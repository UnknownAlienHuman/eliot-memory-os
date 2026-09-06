//! Assumption record: an explicit assumption that can never pass as support.
//!
//! An [`AssumptionRecord`] names one assumption an inquiry depends on, with
//! its statement, scope, task binding, and fence. It carries no support
//! result, no evidence handles, and no verdict: there is deliberately no field
//! a reader could mistake for observed support. Assumption identifiers are the
//! same names claim entries list in their `assumptions` sets, so closed
//! validation can prove every named assumption is recorded exactly once.
//! Unknown, assumed, conflicted, and stale stay distinct; an assumption never
//! decodes as a [`SupportRecord`](crate::support::SupportRecord) nor the
//! reverse.

use eliot_contracts::{SourceId, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};

/// Marker proving a document is an assumption record and never support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum AssumptionKind {
    /// The single admitted spelling of an assumption record.
    #[serde(rename = "ASSUMPTION_RECORD")]
    #[schemars(rename = "ASSUMPTION_RECORD")]
    AssumptionRecord,
}

/// One explicit assumption behind an inquiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssumptionRecord {
    /// Marker binding this document to the assumption decoding.
    pub assumption_kind: AssumptionKind,
    /// Stable assumption identity; the name claim entries reference.
    pub assumption_id: String,
    /// Bounded assumed statement, retained as data rather than authority.
    pub statement: String,
    /// Scope the assumption is taken under.
    pub scope: String,
    /// Source holding the assumption.
    pub holder: SourceId,
    /// Task binding of the inquiry the assumption belongs to.
    pub task_id: TaskId,
    /// Fence the assumption was taken under.
    pub fence: StateFence,
    /// Canonical digest of the assumption shape, excluding this field.
    pub digest: String,
}

impl AssumptionRecord {
    /// Constructs an assumption record and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assumption_id: impl Into<String>,
        statement: impl Into<String>,
        scope: impl Into<String>,
        holder: SourceId,
        task_id: TaskId,
        fence: StateFence,
    ) -> Result<Self, ContractError> {
        let mut record = Self {
            assumption_kind: AssumptionKind::AssumptionRecord,
            assumption_id: assumption_id.into(),
            statement: statement.into(),
            scope: scope.into(),
            holder,
            task_id,
            fence,
            digest: String::new(),
        };
        record.validate_shape()?;
        record.digest = record.compute_digest()?;
        Ok(record)
    }

    /// Recomputes the canonical digest of the assumption shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.assumption_kind,
            &self.assumption_id,
            &self.statement,
            &self.scope,
            &self.holder,
            &self.task_id,
            &self.fence,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.assumption_kind != AssumptionKind::AssumptionRecord {
            return Err(ContractError::ImpossibleCombination {
                field: "assumption.assumption_kind",
            });
        }
        validate_bounded_text(
            &self.assumption_id,
            "assumption.assumption_id",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(&self.statement, "assumption.statement", MAX_STATEMENT_TEXT)?;
        validate_bounded_text(&self.scope, "assumption.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "assumption.fence",
            })?;
        Ok(())
    }

    /// Validates the assumption shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "assumption.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "assumption.digest",
            });
        }
        Ok(())
    }
}
