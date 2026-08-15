//! Deterministic report models and projections for instrument evidence.
//!
//! A report is a read-only projection: its canonical JSON is the authority for
//! report identity, while Markdown is deliberately rendered from that JSON and
//! carries the same identity and revision fence.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex, ClockReading, StateFence};
use eliot_instrument_api::{
    EvidenceCoverage, EvidenceFreshness, InstrumentInvocation, NormalizedEvidence,
    VerificationOutcome, VerificationRun,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this report surface.
pub const CONTRACT_NAME: &str = "eliot.instrument.reports";
/// Wire revision of the report surface.
pub const CONTRACT_VERSION: &str = "0.29";

/// Report categories emitted by the instrument layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportKind {
    /// A completed or blocked verification task.
    Task,
    /// A health projection over one instrument operation.
    Health,
    /// A failure or dead-letter projection.
    Incident,
}

/// Stable report identity and provenance fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportHeader {
    /// Stable report identifier.
    pub report_id: String,
    /// Projection category.
    pub kind: ReportKind,
    /// Monotonic revision of the source projection.
    pub revision: u64,
    /// Clock captured by the report job.
    pub generated_at: ClockReading,
    /// Policy identity used to interpret the source evidence.
    pub policy_version: String,
    /// Exact durable records read by the report job.
    pub source_record_ids: Vec<String>,
    /// Scope inherited from the instrument invocation.
    pub scope: String,
    /// State fence at which the projection was read.
    pub state_fence: StateFence,
}

/// Canonical report containing only normalized evidence and handles to raw data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentReport {
    /// Report identity and provenance.
    pub header: ReportHeader,
    /// Contract revision producing this shape.
    pub contract_version: String,
    /// Admitted invocation summary and its exact arguments.
    pub invocation: InstrumentInvocation,
    /// Verification observations sorted by run identity when built.
    pub verification_runs: Vec<VerificationRun>,
    /// Normalized evidence sorted by evidence identity when built.
    pub normalized_evidence: Vec<NormalizedEvidence>,
    /// Raw payload handles; bytes are intentionally not copied into reports.
    pub raw_evidence_ids: Vec<String>,
    /// Aggregate semantic result, never a finish decision.
    pub outcome: VerificationOutcome,
    /// Content digest of this report with `report_hash` blank.
    pub report_hash: String,
}

/// Failures while constructing or projecting a report.
#[derive(Debug, Error)]
pub enum ReportError {
    /// A required identity or policy field was invalid.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// Source evidence failed its provider-neutral contract validation.
    #[error("invalid source evidence: {0}")]
    InvalidSource(String),
    /// Canonical JSON could not be produced.
    #[error("canonical report serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn valid_text(value: &str, field: &'static str) -> Result<(), ReportError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ReportError::InvalidText { field })
    } else {
        Ok(())
    }
}

impl InstrumentReport {
    /// Builds a report and computes its deterministic content identity.
    pub fn new(
        header: ReportHeader,
        invocation: InstrumentInvocation,
        mut verification_runs: Vec<VerificationRun>,
        mut normalized_evidence: Vec<NormalizedEvidence>,
        raw_evidence_ids: Vec<String>,
        outcome: VerificationOutcome,
    ) -> Result<Self, ReportError> {
        valid_text(&header.report_id, "report_id")?;
        valid_text(&header.policy_version, "policy_version")?;
        valid_text(&header.scope, "scope")?;
        invocation
            .validate()
            .map_err(|error| ReportError::InvalidSource(error.to_string()))?;
        for run in &verification_runs {
            run.validate()
                .map_err(|error| ReportError::InvalidSource(error.to_string()))?;
        }
        for evidence in &normalized_evidence {
            evidence
                .validate()
                .map_err(|error| ReportError::InvalidSource(error.to_string()))?;
        }
        verification_runs.sort_by_key(|run| run.run_id.to_string());
        normalized_evidence.sort_by_key(|evidence| evidence.evidence_id.to_string());
        let mut report = Self {
            header,
            contract_version: CONTRACT_VERSION.to_owned(),
            invocation,
            verification_runs,
            normalized_evidence,
            raw_evidence_ids,
            outcome,
            report_hash: String::new(),
        };
        report.report_hash = report.content_hash()?;
        Ok(report)
    }

    /// Validates the report and its self-describing deterministic hash.
    pub fn validate(&self) -> Result<(), ReportError> {
        valid_text(&self.header.report_id, "report_id")?;
        valid_text(&self.header.policy_version, "policy_version")?;
        valid_text(&self.header.scope, "scope")?;
        self.invocation
            .validate()
            .map_err(|error| ReportError::InvalidSource(error.to_string()))?;
        for run in &self.verification_runs {
            run.validate()
                .map_err(|error| ReportError::InvalidSource(error.to_string()))?;
        }
        for evidence in &self.normalized_evidence {
            evidence
                .validate()
                .map_err(|error| ReportError::InvalidSource(error.to_string()))?;
        }
        if self.report_hash != self.content_hash()? {
            return Err(ReportError::InvalidSource(
                "report_hash does not match canonical content".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns canonical JSON bytes with recursively sorted object keys.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ReportError> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Renders a stable Markdown projection without reinterpreting evidence.
    pub fn markdown(&self) -> Result<String, ReportError> {
        self.validate()?;
        let mut output = String::new();
        output.push_str("# ELIOT Instrument Report\n\n");
        output.push_str(&format!("- Report: `{}`\n", self.header.report_id));
        output.push_str(&format!(
            "- Kind: `{}`\n",
            serde_json::to_string(&self.header.kind)?.trim_matches('"')
        ));
        output.push_str(&format!("- Revision: `{}`\n", self.header.revision));
        output.push_str(&format!(
            "- Policy: `{}`\n",
            escape_markdown(&self.header.policy_version)
        ));
        output.push_str(&format!("- Outcome: `{}`\n", self.outcome));
        output.push_str(&format!("- Report hash: `{}`\n", self.report_hash));
        output.push_str(&format!(
            "- Source records: `{}`\n\n",
            self.header.source_record_ids.len()
        ));
        output.push_str("## Verification\n\n");
        if self.verification_runs.is_empty() {
            output.push_str("No verification runs were attached.\n");
        } else {
            output.push_str(
                "| Run | Property | Outcome | Coverage | Freshness |\n|---|---|---|---|---|\n",
            );
            for run in &self.verification_runs {
                output.push_str(&format!(
                    "| `{}` | {} | `{}` | `{}` | `{}` |\n",
                    run.run_id,
                    escape_markdown(&run.property),
                    run.outcome,
                    coverage(run.coverage),
                    freshness(run.freshness)
                ));
            }
        }
        output.push_str("\n## Evidence\n\n");
        output.push_str(&format!(
            "Normalized records: `{}`; raw handles: `{}`.\n",
            self.normalized_evidence.len(),
            self.raw_evidence_ids.len()
        ));
        Ok(output)
    }

    fn content_hash(&self) -> Result<String, ReportError> {
        let mut material = self.clone();
        material.report_hash.clear();
        Ok(sha256_hex(&canonical_json_bytes(&material)?))
    }
}

fn escape_markdown(value: &str) -> String {
    value
        .replace('\n', " ")
        .replace('|', "\\|")
        .replace('`', "\\`")
}

fn coverage(value: EvidenceCoverage) -> &'static str {
    match value {
        EvidenceCoverage::CompleteForScope => "COMPLETE_FOR_SCOPE",
        EvidenceCoverage::PartialForScope => "PARTIAL_FOR_SCOPE",
        EvidenceCoverage::NotApplicable => "NOT_APPLICABLE",
        EvidenceCoverage::Unknown => "UNKNOWN",
    }
}

fn freshness(value: EvidenceFreshness) -> &'static str {
    match value {
        EvidenceFreshness::ExactCandidate => "EXACT_CANDIDATE",
        EvidenceFreshness::ExactCommit => "EXACT_COMMIT",
        EvidenceFreshness::ExactQuiescedWorktree => "EXACT_QUIESCED_WORKTREE",
        EvidenceFreshness::KnownOlderSnapshot => "KNOWN_OLDER_SNAPSHOT",
        EvidenceFreshness::Stale => "STALE",
        EvidenceFreshness::Unknown => "UNKNOWN",
    }
}
