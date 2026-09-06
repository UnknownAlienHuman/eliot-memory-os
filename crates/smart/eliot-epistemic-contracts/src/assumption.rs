//! Assumption record: an explicit assumption that can never pass as support.
//!
//! An [`AssumptionRecord`] names one assumption with origin, necessity, failure mode, and dependents
//! (load-bearing per I12.4, not prose), plus statement, bounds, holder, task, and fence. Withdrawal is
//! mechanical via [`AssumptionRecord::withdraw`]; the record carries no support result, handles, or verdict —
//! nothing a reader could mistake for observed support.
use std::collections::BTreeSet;

use eliot_contracts::{SourceId, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, check_frozen, shape_digest,
    validate_bounded_text, validate_digest,
};
use crate::support::ValidityBounds;

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
    /// Origin that introduced the assumption: route, source, or decision.
    pub origin: String,
    /// Why the inquiry cannot proceed without this assumption.
    pub necessity: String,
    /// What fails, and how dependents fall, when this assumption is refuted.
    pub failure_mode: String,
    /// Dependent assumption or claim names withdrawn when this one fails.
    pub dependents: BTreeSet<String>,
    /// Scope, time, version, and precision bounds the assumption is taken under.
    pub bounds: ValidityBounds,
    /// Scope the assumption is taken under; always equals `bounds.scope`.
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
        origin: impl Into<String>,
        necessity: impl Into<String>,
        failure_mode: impl Into<String>,
        dependents: BTreeSet<String>,
        bounds: ValidityBounds,
        holder: SourceId,
        task_id: TaskId,
        fence: StateFence,
    ) -> Result<Self, ContractError> {
        let scope = bounds.scope.clone();
        let mut record = Self {
            assumption_kind: AssumptionKind::AssumptionRecord,
            assumption_id: assumption_id.into(),
            statement: statement.into(),
            origin: origin.into(),
            necessity: necessity.into(),
            failure_mode: failure_mode.into(),
            dependents,
            bounds,
            scope,
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
            &self.origin,
            &self.necessity,
            &self.failure_mode,
            &self.dependents,
            &self.bounds,
            &self.scope,
            &self.holder,
            &self.task_id,
            &self.fence,
        ))
    }

    /// Mechanically withdraws this assumption: derives a retraction naming
    /// the exact record digest plus the withdrawal context. Dependents fall
    /// by this record, never by rewriting history.
    pub fn withdraw(
        &self,
        reason: impl Into<String>,
    ) -> Result<AssumptionRetraction, ContractError> {
        self.validate()?;
        AssumptionRetraction::new(
            self.digest.clone(),
            self.assumption_id.clone(),
            reason,
            self.scope.clone(),
            self.task_id.clone(),
        )
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
        validate_bounded_text(&self.origin, "assumption.origin", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.necessity, "assumption.necessity", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            &self.failure_mode,
            "assumption.failure_mode",
            MAX_STATEMENT_TEXT,
        )?;
        if self.dependents.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "assumption.dependents",
            });
        }
        for dependent in &self.dependents {
            validate_bounded_text(dependent.as_str(), "assumption.dependents", MAX_SHORT_TEXT)?;
        }
        if self.dependents.contains(&self.assumption_id) {
            return Err(ContractError::SelfReference {
                field: "assumption.dependents",
            });
        }
        self.bounds.validate()?;
        validate_bounded_text(&self.scope, "assumption.scope", MAX_SHORT_TEXT)?;
        if self.bounds.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "assumption.scope",
            });
        }
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
        check_frozen(&self.digest, &self.compute_digest()?, "assumption.digest")
    }

    /// Validates this record against the claiming task, scope, and fence: the same name under another task,
    /// scope, or fence is another context that closed candidate validation rejects.
    pub fn validate_for(
        &self,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if &self.task_id != task_id {
            return Err(ContractError::TaskMismatch {
                field: "assumption.task_id",
            });
        }
        if self.scope != scope {
            return Err(ContractError::ScopeMismatch {
                field: "assumption.scope",
            });
        }
        if !self.fence.is_compatible_with(fence) {
            return Err(ContractError::FenceMismatch {
                field: "assumption.fence",
            });
        }
        Ok(())
    }
}

/// A mechanical withdrawal of one assumption record: it names the exact record digest withdrawn plus the
/// withdrawal context, and carries no replacement content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssumptionRetraction {
    /// Exact digest of the withdrawn assumption record.
    pub assumption_digest: String,
    /// Identity of the withdrawn assumption, for human review only.
    pub assumption_id: String,
    /// Bounded reason for the withdrawal.
    pub reason: String,
    /// Scope withdrawn under.
    pub scope: String,
    /// Task binding withdrawn under.
    pub task_id: TaskId,
    /// Canonical digest of the retraction shape, excluding this field.
    pub digest: String,
}
impl AssumptionRetraction {
    /// Constructs a retraction and freezes its canonical digest.
    pub fn new(
        assumption_digest: impl Into<String>,
        assumption_id: impl Into<String>,
        reason: impl Into<String>,
        scope: impl Into<String>,
        task_id: TaskId,
    ) -> Result<Self, ContractError> {
        let mut retraction = Self {
            assumption_digest: assumption_digest.into(),
            assumption_id: assumption_id.into(),
            reason: reason.into(),
            scope: scope.into(),
            task_id,
            digest: String::new(),
        };
        retraction.validate_shape()?;
        retraction.digest = retraction.compute_digest()?;
        Ok(retraction)
    }

    /// Recomputes the canonical digest of the retraction shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.assumption_digest,
            &self.assumption_id,
            &self.reason,
            &self.scope,
            &self.task_id,
        ))
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_digest(&self.assumption_digest, "assumption.retraction")?;
        validate_bounded_text(
            &self.assumption_id,
            "assumption.retraction_id",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(&self.reason, "assumption.retraction_reason", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "assumption.retraction_scope", MAX_SHORT_TEXT)?;
        Ok(())
    }

    /// Validates the retraction shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(
            &self.digest,
            &self.compute_digest()?,
            "assumption.retraction_digest",
        )
    }
}
