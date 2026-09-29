//! Binds one admitted operator-intent plan revision to the real durable job
//! execution that answers it.
//!
//! This module joins the candidate/plan contract owned by `operator_intent` to
//! the existing durable-job lifecycle owned by `eliot_protocol::dreamer_job`.
//! It adds no second job lifecycle: the joined [`DurableJobRecord`] is the
//! existing owner's record, validated through that owner's own `validate()`,
//! and its `state` is read directly rather than inferred from the absence of
//! anything.
//!
//! Guarantees this join states, and does not approximate:
//!
//! - The link names the exact plan revision it was authorized for. Validation
//!   compares that revision identity and number against the current plan, so a
//!   delayed confirmation of a predecessor revision cannot execute its
//!   replacement.
//! - The link names the original public request, so an execution is only ever
//!   presented against the message that asked for it.
//! - Job and attempt identity are compared against the record's own
//!   submission.
//! - A verified portion may only claim the exact subset the record's verifier
//!   covers, read from the record's own `VerifierBinding`; the remainder of the
//!   answer is not upgraded.
//! - Effect disposition keeps issued and unknown effects distinct. No variant
//!   promises a rollback, so pause, cancel and escalation stay with their
//!   existing owner.
//!
//! The module owns no durable state, opens no transport, and executes no
//! effect. STITCH is the intended production caller; the link is a pure
//! wire-shaped join validated in memory.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ReceiptId, RequestId, TaskId};
use eliot_protocol::DurableJobRecord;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::operator_intent::{
    OperatorIntentPlan, OperatorIntentPlanRevisionRef, OperatorIntentScope,
};

/// Epistemic status of an answer, kept separate from job completion.
///
/// A `Candidate` or `Advisory` answer says nothing about whether the job
/// finished. `Verified` names only the subset the record's verifier covers; no
/// variant claims the whole answer, and none of them upgrades the durable job
/// state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum OperatorIntentEpistemic {
    /// A proposed answer with no verifier-backed portion.
    Candidate,
    /// An advisory answer with no verifier-backed portion.
    Advisory,
    /// Exactly the verifier-backed subset of the answer. Artifacts outside
    /// `artifact_ids` keep their unverified status.
    Verified { artifact_ids: Vec<ArtifactId> },
}

/// Disposition of a proposed effect after the linked job ran.
///
/// There is deliberately no reversed/rolled-back variant: an issued effect
/// stays issued and an effect of unknown issuance stays unknown, so no
/// disposition here promises a rollback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum OperatorIntentEffectDisposition {
    /// The owner issued this effect and the link carries its receipt.
    Issued { effect_ref: ArtifactId },
    /// The owner cannot say whether this effect was issued.
    IssueUnknown { effect_ref: ArtifactId, reason: String },
}

/// One admitted plan revision joined to the job, attempt and result that
/// answer it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentExecutionLink {
    /// The exact plan revision this link was authorized for.
    pub plan_revision: OperatorIntentPlanRevisionRef,
    /// The original public request that produced the plan.
    pub request_id: RequestId,
    /// The durable job that ran the plan.
    pub job_id: TaskId,
    /// The exact attempt of that job.
    pub attempt_id: ArtifactId,
    /// The existing owner's durable job record, carrying its real state,
    /// checkpoint, cancellation projection and terminal outcome.
    pub record: DurableJobRecord,
    /// Owner receipt for the observed operation, when the owner issued one.
    pub receipt_id: Option<ReceiptId>,
    /// Epistemic status of the answer; never a completion claim.
    pub epistemic: OperatorIntentEpistemic,
    /// Disposition of the proposed effects the plan named.
    pub effects: Vec<OperatorIntentEffectDisposition>,
}

impl OperatorIntentExecutionLink {
    /// Validates the join against the plan revision it claims to execute.
    ///
    /// The plan must be valid, its scope must already be resolved, and the
    /// request, job identity and revision must match. Passing a predecessor
    /// revision returns [`OperatorIntentExecutionError::SupersededRevision`].
    pub fn validate_against_plan(
        &self,
        plan: &OperatorIntentPlan,
    ) -> Result<(), OperatorIntentExecutionError> {
        plan.validate()
            .map_err(|_| OperatorIntentExecutionError::PlanNotAdmissible)?;
        if matches!(plan.scope, OperatorIntentScope::Unresolved { .. }) {
            return Err(OperatorIntentExecutionError::PlanNotAdmissible);
        }
        self.validate()?;
        if self.request_id != plan.identity.message_id {
            return Err(OperatorIntentExecutionError::RequestMismatch);
        }
        if self.plan_revision.revision_id != plan.revision.revision_id
            || self.plan_revision.revision != plan.revision.revision
        {
            return Err(OperatorIntentExecutionError::SupersededRevision);
        }
        Ok(())
    }

    /// Validates the join on its own, without a plan to compare against.
    ///
    /// The record is validated through its own owner's `validate()` rather
    /// than re-deriving the job lifecycle rules here.
    pub fn validate(&self) -> Result<(), OperatorIntentExecutionError> {
        if self.plan_revision.revision == 0 {
            return Err(OperatorIntentExecutionError::InvalidField {
                field: "plan_revision.revision",
            });
        }
        self.record
            .validate()
            .map_err(|_| OperatorIntentExecutionError::JobRecordInvalid)?;
        if self.job_id != self.record.submission.job_id
            || self.attempt_id != self.record.submission.attempt_id
        {
            return Err(OperatorIntentExecutionError::JobIdentityMismatch);
        }
        self.validate_epistemic()?;
        self.validate_effects()
    }

    /// Checks the epistemic status against the record's own verifier.
    fn validate_epistemic(&self) -> Result<(), OperatorIntentExecutionError> {
        let OperatorIntentEpistemic::Verified { artifact_ids } = &self.epistemic else {
            return Ok(());
        };
        if artifact_ids.is_empty() {
            return Err(OperatorIntentExecutionError::InvalidField {
                field: "epistemic.artifact_ids",
            });
        }
        unique(artifact_ids, "epistemic.artifact_ids")?;
        let outcome = self
            .record
            .outcome
            .as_ref()
            .ok_or(OperatorIntentExecutionError::UnverifiedClaim)?;
        let verifier = outcome
            .verifier
            .as_ref()
            .ok_or(OperatorIntentExecutionError::UnverifiedClaim)?;
        if artifact_ids.iter().any(|id| !verifier.artifact_ids.contains(id)) {
            return Err(OperatorIntentExecutionError::UnverifiedClaim);
        }
        Ok(())
    }

    /// Checks each effect disposition against the owner receipt the link
    /// carries and the reason an unknown issuance must state.
    fn validate_effects(&self) -> Result<(), OperatorIntentExecutionError> {
        let mut seen = BTreeSet::new();
        for disposition in &self.effects {
            let effect_ref = match disposition {
                OperatorIntentEffectDisposition::Issued { effect_ref }
                | OperatorIntentEffectDisposition::IssueUnknown { effect_ref, .. } => effect_ref,
            };
            if !seen.insert(effect_ref) {
                return Err(OperatorIntentExecutionError::InvalidField {
                    field: "effects.effect_ref",
                });
            }
            match disposition {
                OperatorIntentEffectDisposition::Issued { .. } if self.receipt_id.is_none() => {
                    return Err(OperatorIntentExecutionError::UnevidencedIssuance);
                }
                OperatorIntentEffectDisposition::IssueUnknown { reason, .. } => {
                    required_text(reason, "effects.reason")?;
                }
                OperatorIntentEffectDisposition::Issued { .. } => {}
            }
        }
        Ok(())
    }
}

/// Failure reasons for the plan-to-execution join.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OperatorIntentExecutionError {
    /// The plan is structurally invalid or still requires a selection.
    #[error("operator intent execution: the plan is not admissible")]
    PlanNotAdmissible,
    /// The durable job record failed its own owner's validation.
    #[error("operator intent execution: the durable job record is invalid")]
    JobRecordInvalid,
    /// The link names a job or attempt other than the record's own.
    #[error("operator intent execution: job or attempt identity does not match the record")]
    JobIdentityMismatch,
    /// The link is bound to a request other than the plan's public message.
    #[error("operator intent execution: request identity does not match the plan")]
    RequestMismatch,
    /// The link authorizes a plan revision other than the current one.
    #[error("operator intent execution: the authorized plan revision is superseded")]
    SupersededRevision,
    /// A verified portion claims artifacts the record's verifier does not cover.
    #[error("operator intent execution: the verified portion is not verifier-backed")]
    UnverifiedClaim,
    /// An issued effect is presented without the owner receipt that evidences it.
    #[error("operator intent execution: an issued effect carries no owner receipt")]
    UnevidencedIssuance,
    /// A field is blank, duplicated, or malformed.
    #[error("operator intent execution: field is invalid: {field}")]
    InvalidField { field: &'static str },
}

fn required_text(value: &str, field: &'static str) -> Result<(), OperatorIntentExecutionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(OperatorIntentExecutionError::InvalidField { field });
    }
    Ok(())
}

fn unique<T: Ord>(values: &[T], field: &'static str) -> Result<(), OperatorIntentExecutionError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(OperatorIntentExecutionError::InvalidField { field });
    }
    Ok(())
}
