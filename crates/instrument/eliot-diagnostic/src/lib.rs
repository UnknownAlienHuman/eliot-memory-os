//! Deterministic owner for diagnostic evidence and diagnostic classification.
//!
//! The owner deliberately keeps the captured observation, its canonical event,
//! and the policy classification separate.  Parsing or classification can
//! therefore fail without turning an incomplete observation into a clean one.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{ArtifactId, ClockReading, ContractVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.instrument.diagnostic";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Errors raised before a diagnostic can become authoritative evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DiagnosticError {
    /// A required text field is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A range is inverted or contains an invalid zero value.
    #[error("{field} is not an ordered range")]
    InvalidRange { field: &'static str },
    /// The captured observation is not valid UTF-8 when text was required.
    #[error("diagnostic output is not valid UTF-8")]
    InvalidUtf8,
    /// A capture clock is not a valid shared clock reading.
    #[error("{field} has an invalid clock reading")]
    InvalidClock { field: &'static str },
    /// The event identity does not match its canonical input.
    #[error("diagnostic id does not match the canonical event identity")]
    IdentityMismatch,
    /// Classification cannot be asserted for an incomplete parse.
    #[error("diagnostic classification is incomplete: {0}")]
    ClassificationIncomplete(String),
}

fn text(value: &str, field: &'static str) -> Result<(), DiagnosticError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(DiagnosticError::InvalidText { field })
    } else {
        Ok(())
    }
}

/// Canonical source location carried by a diagnostic event.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRange {
    /// One-based line or zero-based byte start, according to `unit`.
    pub start: u64,
    /// Exclusive end in the same unit.
    pub end_exclusive: u64,
    /// Coordinate unit for this range.
    pub unit: RangeUnit,
}

impl DiagnosticRange {
    /// Constructs an ordered range.
    pub const fn new(
        start: u64,
        end_exclusive: u64,
        unit: RangeUnit,
    ) -> Result<Self, DiagnosticError> {
        if end_exclusive <= start {
            Err(DiagnosticError::InvalidRange { field: "range" })
        } else {
            Ok(Self {
                start,
                end_exclusive,
                unit,
            })
        }
    }

    fn validate(self) -> Result<(), DiagnosticError> {
        if self.end_exclusive <= self.start {
            Err(DiagnosticError::InvalidRange { field: "range" })
        } else {
            Ok(())
        }
    }
}

/// Coordinate system used by a diagnostic range.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RangeUnit {
    /// Source line coordinates.
    Line,
    /// Raw UTF-8 byte coordinates.
    Byte,
}

/// Canonical diagnostic severity.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Information,
    Hint,
    Unknown,
}

/// Durable lifecycle of a diagnostic observation.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticStatus {
    Active,
    Resolved,
    Stale,
    Suppressed,
}

/// Deterministic semantic class selected by the registered classifier.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticClass {
    BuildFailure,
    TestFailure,
    LintViolation,
    ParseError,
    Configuration,
    Environment,
    ToolFailure,
    Informational,
    Unknown,
}

/// Governed meaning available to a verifier or blocker policy.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticDisposition {
    VerifierFailure,
    Blocker,
    Advisory,
    Suppressed,
    ParseIncomplete,
    Unknown,
}

/// Exact fields supplied by an adapter before normalization.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticInput {
    pub project_id: String,
    pub task_id: Option<String>,
    pub tool_id: String,
    pub tool_version: String,
    pub config_hash: String,
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub file_path: String,
    pub range: Option<DiagnosticRange>,
    pub severity: DiagnosticSeverity,
    pub rule_id: String,
    pub message: String,
    pub raw_observation_ref: ArtifactId,
    pub observed_at: ClockReading,
    pub status: DiagnosticStatus,
}

/// Canonical, deduplicated diagnostic event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEvent {
    pub diagnostic_id: String,
    pub project_id: String,
    pub task_id: Option<String>,
    pub tool_id: String,
    pub tool_version: String,
    pub config_hash: String,
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub file_path: String,
    pub byte_or_line_range: Option<DiagnosticRange>,
    pub severity: DiagnosticSeverity,
    pub rule_id: String,
    pub message: String,
    pub raw_observation_ref: ArtifactId,
    pub observed_at: ClockReading,
    pub status: DiagnosticStatus,
}

impl DiagnosticEvent {
    /// Computes the architecture-defined deduplication identity.
    #[must_use]
    pub fn identity(input: &DiagnosticInput) -> String {
        let range = input.range.map_or_else(String::new, |r| {
            format!(
                "{}:{}:{}",
                match r.unit {
                    RangeUnit::Line => "line",
                    RangeUnit::Byte => "byte",
                },
                r.start,
                r.end_exclusive
            )
        });
        let path = canonical_path(&input.file_path);
        let message = normalize_message(&input.message);
        let fields = [
            input.tool_id.as_str(),
            input.tool_version.as_str(),
            input.config_hash.as_str(),
            input.commit.as_str(),
            input.dirty_state_hash.as_str(),
            path.as_str(),
            range.as_str(),
            input.rule_id.as_str(),
            message.as_str(),
        ];
        let mut hasher = blake3::Hasher::new();
        for field in fields {
            hasher.update(field.as_bytes());
            hasher.update(&[0]);
        }
        format!("diag:{}", hasher.finalize().to_hex())
    }

    /// Normalizes one adapter result without consulting a model or a store.
    pub fn from_input(input: DiagnosticInput) -> Result<Self, DiagnosticError> {
        input.validate()?;
        Ok(Self {
            diagnostic_id: Self::identity(&input),
            project_id: input.project_id,
            task_id: input.task_id,
            tool_id: input.tool_id,
            tool_version: input.tool_version,
            config_hash: input.config_hash,
            branch: input.branch,
            commit: input.commit,
            dirty_state_hash: input.dirty_state_hash,
            file_path: canonical_path(&input.file_path),
            byte_or_line_range: input.range,
            severity: input.severity,
            rule_id: input.rule_id,
            message: normalize_message(&input.message),
            raw_observation_ref: input.raw_observation_ref,
            observed_at: input.observed_at,
            status: input.status,
        })
    }

    /// Validates the event and recomputes its immutable identity.
    pub fn validate(&self) -> Result<(), DiagnosticError> {
        text(&self.project_id, "project_id")?;
        for (value, field) in [
            (&self.tool_id, "tool_id"),
            (&self.tool_version, "tool_version"),
            (&self.config_hash, "config_hash"),
            (&self.branch, "branch"),
            (&self.commit, "commit"),
            (&self.dirty_state_hash, "dirty_state_hash"),
            (&self.file_path, "file_path"),
            (&self.rule_id, "rule_id"),
            (&self.message, "message"),
        ] {
            text(value, field)?;
        }
        if let Some(task_id) = &self.task_id {
            text(task_id, "task_id")?;
        }
        if let Some(range) = self.byte_or_line_range {
            range.validate()?;
        }
        self.observed_at
            .validate()
            .map_err(|_| DiagnosticError::InvalidClock {
                field: "observed_at",
            })?;
        let input = DiagnosticInput {
            project_id: self.project_id.clone(),
            task_id: self.task_id.clone(),
            tool_id: self.tool_id.clone(),
            tool_version: self.tool_version.clone(),
            config_hash: self.config_hash.clone(),
            branch: self.branch.clone(),
            commit: self.commit.clone(),
            dirty_state_hash: self.dirty_state_hash.clone(),
            file_path: self.file_path.clone(),
            range: self.byte_or_line_range,
            severity: self.severity,
            rule_id: self.rule_id.clone(),
            message: self.message.clone(),
            raw_observation_ref: self.raw_observation_ref.clone(),
            observed_at: self.observed_at,
            status: self.status,
        };
        if self.diagnostic_id != Self::identity(&input) {
            return Err(DiagnosticError::IdentityMismatch);
        }
        Ok(())
    }
}

impl DiagnosticInput {
    fn validate(&self) -> Result<(), DiagnosticError> {
        text(&self.project_id, "project_id")?;
        for (value, field) in [
            (&self.tool_id, "tool_id"),
            (&self.tool_version, "tool_version"),
            (&self.config_hash, "config_hash"),
            (&self.branch, "branch"),
            (&self.commit, "commit"),
            (&self.dirty_state_hash, "dirty_state_hash"),
            (&self.file_path, "file_path"),
            (&self.rule_id, "rule_id"),
            (&self.message, "message"),
        ] {
            text(value, field)?;
        }
        if let Some(task_id) = &self.task_id {
            text(task_id, "task_id")?;
        }
        if let Some(range) = self.range {
            range.validate()?;
        }
        self.observed_at
            .validate()
            .map_err(|_| DiagnosticError::InvalidClock {
                field: "observed_at",
            })
    }
}

/// Immutable classification attached to one canonical event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticClassification {
    pub class: DiagnosticClass,
    pub disposition: DiagnosticDisposition,
    pub classifier_version: String,
}

/// Event plus its deterministic policy classification.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEvidence {
    pub event: DiagnosticEvent,
    pub classification: DiagnosticClassification,
}

impl DiagnosticEvidence {
    /// Validates both the canonical observation and its classification.
    pub fn validate(&self) -> Result<(), DiagnosticError> {
        self.event.validate()
    }
}

/// Registered, deterministic diagnostic class owner.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticClassifier {
    rules: BTreeMap<String, DiagnosticClass>,
}

impl DiagnosticClassifier {
    /// Registers an exact rule-id mapping.
    pub fn with_rule(mut self, rule_id: impl Into<String>, class: DiagnosticClass) -> Self {
        self.rules.insert(rule_id.into(), class);
        self
    }

    /// Classifies an event without rewriting its evidence.
    #[must_use]
    pub fn classify(&self, event: &DiagnosticEvent) -> DiagnosticClassification {
        let class = self
            .rules
            .get(&event.rule_id)
            .copied()
            .unwrap_or_else(|| default_class(event));
        let disposition = match event.status {
            DiagnosticStatus::Suppressed => DiagnosticDisposition::Suppressed,
            DiagnosticStatus::Resolved | DiagnosticStatus::Stale => DiagnosticDisposition::Advisory,
            DiagnosticStatus::Active => match class {
                DiagnosticClass::BuildFailure
                | DiagnosticClass::TestFailure
                | DiagnosticClass::LintViolation
                | DiagnosticClass::ParseError => DiagnosticDisposition::VerifierFailure,
                DiagnosticClass::Configuration
                | DiagnosticClass::Environment
                | DiagnosticClass::ToolFailure => DiagnosticDisposition::Blocker,
                DiagnosticClass::Informational => DiagnosticDisposition::Advisory,
                DiagnosticClass::Unknown => DiagnosticDisposition::Unknown,
            },
        };
        DiagnosticClassification {
            class,
            disposition,
            classifier_version: "diagnostic-classifier-v1".to_owned(),
        }
    }

    /// Produces the complete evidence owned by this classifier.
    pub fn admit(&self, event: DiagnosticEvent) -> Result<DiagnosticEvidence, DiagnosticError> {
        event.validate()?;
        Ok(DiagnosticEvidence {
            classification: self.classify(&event),
            event,
        })
    }
}

fn default_class(event: &DiagnosticEvent) -> DiagnosticClass {
    let tool = event.tool_id.to_ascii_lowercase();
    let rule = event.rule_id.to_ascii_lowercase();
    if rule.contains("parse") || rule.contains("syntax") {
        DiagnosticClass::ParseError
    } else if tool.contains("test") || rule.contains("test") {
        DiagnosticClass::TestFailure
    } else if tool.contains("lint") || tool.contains("clippy") || rule.contains("lint") {
        DiagnosticClass::LintViolation
    } else if tool.contains("build") || tool.contains("rustc") || rule.contains("compile") {
        DiagnosticClass::BuildFailure
    } else if matches!(
        event.severity,
        DiagnosticSeverity::Information | DiagnosticSeverity::Hint
    ) {
        DiagnosticClass::Informational
    } else {
        DiagnosticClass::Unknown
    }
}

fn normalize_message(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn canonical_path(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}
