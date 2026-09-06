//! Temporal roles: five distinct times that must never merge.
//!
//! Event, effective, observation, ingestion, and commit times stay separate fields; pipeline order
//! (observation, ingestion, commit) is enforced while event/effective stay unordered. [`TemporalPrecedence`]
//! records bare chronology, which never decodes as causation.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractError, MAX_SHORT_TEXT, validate_bounded_text};

/// The five distinct temporal roles of one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TemporalRole {
    /// When the underlying happening occurred.
    Event,
    /// When the proposition holds.
    Effective,
    /// When the happening was observed.
    Observation,
    /// When the observation entered the pipeline.
    Ingestion,
    /// When the record was committed.
    Commit,
}

/// Five distinct times of one record, in Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemporalRecord {
    /// Event time: when the happening occurred.
    pub event_ms: i64,
    /// Effective time: when the proposition holds.
    pub effective_ms: i64,
    /// Observation time: when the happening was observed.
    pub observation_ms: i64,
    /// Ingestion time: when the observation entered the pipeline.
    pub ingestion_ms: i64,
    /// Commit time: when the record was committed.
    pub commit_ms: i64,
}
impl TemporalRecord {
    /// Constructs a temporal record after validation.
    pub fn new(
        event_ms: i64,
        effective_ms: i64,
        observation_ms: i64,
        ingestion_ms: i64,
        commit_ms: i64,
    ) -> Result<Self, ContractError> {
        let record = Self {
            event_ms,
            effective_ms,
            observation_ms,
            ingestion_ms,
            commit_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the instant attached to one role.
    pub const fn role_time(&self, role: TemporalRole) -> i64 {
        match role {
            TemporalRole::Event => self.event_ms,
            TemporalRole::Effective => self.effective_ms,
            TemporalRole::Observation => self.observation_ms,
            TemporalRole::Ingestion => self.ingestion_ms,
            TemporalRole::Commit => self.commit_ms,
        }
    }

    /// Validates pipeline order: observation, ingestion, then commit.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.ingestion_ms < self.observation_ms || self.commit_ms < self.ingestion_ms {
            return Err(ContractError::InvertedInterval {
                field: "temporal.pipeline",
            });
        }
        Ok(())
    }
}

/// Bare chronological precedence between two instants: navigation evidence
/// only, never promotable into a causal claim by retyping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemporalPrecedence {
    /// Earlier instant in Unix milliseconds.
    pub before_ms: i64,
    /// Later instant in Unix milliseconds.
    pub after_ms: i64,
    /// Bounded basis note for the ordering evidence.
    pub basis: String,
}
impl TemporalPrecedence {
    /// Constructs a precedence record after validation.
    pub fn new(
        before_ms: i64,
        after_ms: i64,
        basis: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let record = Self {
            before_ms,
            after_ms,
            basis: basis.into(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates chronological order and the bounded basis note.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.after_ms < self.before_ms {
            return Err(ContractError::InvertedInterval {
                field: "temporal.precedence",
            });
        }
        validate_bounded_text(&self.basis, "temporal.basis", MAX_SHORT_TEXT)?;
        Ok(())
    }
}
