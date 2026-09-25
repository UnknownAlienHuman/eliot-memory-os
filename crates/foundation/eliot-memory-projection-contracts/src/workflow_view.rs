//! Governed workflow state view (I12.35).
//!
//! A [`WorkflowStateView`] is the bounded read shape in which the Governor
//! projection side carries object and workflow continuity: workflow
//! identity, current and previous step with owner, inputs, outputs, pending
//! commitments and external effects, the expected observable with its
//! verifier, the interruption/resume boundary with idempotency, and the
//! artifact lineage with unresolved representation gaps.
//!
//! The view owns no store, ranking, or promotion authority. It only
//! describes the workflow position the projecting owner attests, bound to
//! the same [`TaskId`]/[`WorkScopeId`] triple the projection batch uses, so
//! the Governor provider can admit it against one shared binding.

use eliot_contracts::TaskId;
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::MemoryProjectionError;

/// Maximum inputs, outputs, commitments, effects, or lineage entries per view.
pub const MAX_WORKFLOW_ENTRIES: usize = 64;
/// Maximum unresolved representation gaps carried by one view.
pub const MAX_WORKFLOW_GAPS: usize = 32;

fn text(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MemoryProjectionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn bounded_entries(values: &[String], field: &'static str) -> Result<(), MemoryProjectionError> {
    if values.len() > MAX_WORKFLOW_ENTRIES {
        return Err(MemoryProjectionError::Bounds { field });
    }
    for value in values {
        text(value, field)?;
    }
    Ok(())
}

/// Idempotency posture of a workflow interruption/resume boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowIdempotency {
    /// Resume is idempotent under the named key.
    Idempotent {
        /// Stable idempotency key the resuming owner must reuse.
        key: String,
    },
    /// Resume is not idempotent; effects must be reconciled.
    NonIdempotent,
    /// Idempotency was not established at the boundary.
    Unknown,
}

/// One bounded governed workflow state view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStateView {
    /// Stable workflow identity.
    pub workflow_id: String,
    /// Task the workflow runs under.
    pub task_id: TaskId,
    /// Work scope the workflow runs under.
    pub scope_id: WorkScopeId,
    /// Current workflow step.
    pub current_step: String,
    /// Previous workflow step, when the workflow has advanced.
    pub previous_step: Option<String>,
    /// Owner accountable for the current step.
    pub step_owner: String,
    /// Inputs consumed by the workflow so far.
    pub inputs: Vec<String>,
    /// Outputs produced by the workflow so far.
    pub outputs: Vec<String>,
    /// Commitments made but not yet discharged.
    pub pending_commitments: Vec<String>,
    /// Effects external to the governed record.
    pub external_effects: Vec<String>,
    /// Observable the workflow is expected to produce next.
    pub expected_observable: String,
    /// Verifier competent to confirm the expected observable.
    pub verifier_ref: String,
    /// Boundary at which the workflow may be interrupted and resumed.
    pub resume_boundary: String,
    /// Idempotency posture of that boundary.
    pub idempotency: WorkflowIdempotency,
    /// Artifact lineage the workflow position depends on.
    pub artifact_lineage: Vec<String>,
    /// Representation gaps the view does not resolve.
    pub unresolved_representation_gaps: Vec<String>,
}

impl WorkflowStateView {
    /// Validate the view shape without deciding workflow semantics.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.workflow_id, "workflow_view.workflow_id")?;
        text(&self.current_step, "workflow_view.current_step")?;
        if let Some(previous) = &self.previous_step {
            text(previous, "workflow_view.previous_step")?;
        }
        text(&self.step_owner, "workflow_view.step_owner")?;
        bounded_entries(&self.inputs, "workflow_view.inputs")?;
        bounded_entries(&self.outputs, "workflow_view.outputs")?;
        bounded_entries(
            &self.pending_commitments,
            "workflow_view.pending_commitments",
        )?;
        bounded_entries(&self.external_effects, "workflow_view.external_effects")?;
        text(
            &self.expected_observable,
            "workflow_view.expected_observable",
        )?;
        text(&self.verifier_ref, "workflow_view.verifier_ref")?;
        text(&self.resume_boundary, "workflow_view.resume_boundary")?;
        if let WorkflowIdempotency::Idempotent { key } = &self.idempotency {
            text(key, "workflow_view.idempotency.key")?;
        }
        bounded_entries(&self.artifact_lineage, "workflow_view.artifact_lineage")?;
        if self.unresolved_representation_gaps.len() > MAX_WORKFLOW_GAPS {
            return Err(MemoryProjectionError::Bounds {
                field: "workflow_view.unresolved_representation_gaps",
            });
        }
        for gap in &self.unresolved_representation_gaps {
            text(gap, "workflow_view.unresolved_representation_gaps")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn view() -> Result<WorkflowStateView, Box<dyn std::error::Error>> {
        Ok(WorkflowStateView {
            workflow_id: "workflow:review".to_owned(),
            task_id: "task:review".parse()?,
            scope_id: "scope:review".parse()?,
            current_step: "step:crop".to_owned(),
            previous_step: Some("step:capture".to_owned()),
            step_owner: "owner:operator".to_owned(),
            inputs: vec!["blob:raw".to_owned()],
            outputs: vec!["blob:thumbnail".to_owned()],
            pending_commitments: vec!["commit:verify-hue".to_owned()],
            external_effects: vec!["effect:thumbnail-published".to_owned()],
            expected_observable: "thumbnail at 640x480".to_owned(),
            verifier_ref: "verifier:vision".to_owned(),
            resume_boundary: "boundary:after-crop".to_owned(),
            idempotency: WorkflowIdempotency::Idempotent {
                key: "idempotency:crop-1".to_owned(),
            },
            artifact_lineage: vec!["artifact:panel".to_owned()],
            unresolved_representation_gaps: vec!["sub-pixel hue unmeasured".to_owned()],
        })
    }

    #[test]
    fn workflow_view_round_trips() -> TestResult {
        let full = view()?;
        full.validate()?;
        let encoded = serde_json::to_string(&full)?;
        assert_eq!(serde_json::from_str::<WorkflowStateView>(&encoded)?, full);
        Ok(())
    }

    #[test]
    fn workflow_view_rejects_blank_step() -> TestResult {
        let mut broken = view()?;
        broken.current_step.clear();
        assert!(broken.validate().is_err());
        Ok(())
    }
}
