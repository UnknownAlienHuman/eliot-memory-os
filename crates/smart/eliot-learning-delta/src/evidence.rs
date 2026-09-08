//! Exact semantic evidence and evaluator attribution checks.

use eliot_contracts::{ArtifactId, StateFence};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness,
};
use eliot_learning_contracts::AgentAttemptId;
use eliot_learning_contracts::{ContractBinding, TargetId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{LearningDeltaError, policy::DerivationPolicy};

/// Semantic result categories remain distinct from causal attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticOutcome {
    /// The declared observable improved within its semantic contract.
    Benefit,
    /// The observable worsened or a protected regression occurred.
    Harm,
    /// No event was observed.
    NoEvent,
    /// The evaluator measured the fixed prediction unchanged.
    MeasuredUnchanged,
    /// A semantic result was observed but remains inconclusive.
    Inconclusive,
    /// The semantic result is unknown under the declared instrumentation.
    Unknown,
    /// Evidence contains materially mixed outcomes that cannot be collapsed.
    Mixed,
    /// A required semantic value was absent from the evaluated scope.
    Missing,
}

/// Role of an evidence record at the derivation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceKind {
    /// Immutable raw attempt observation.
    Observation,
    /// Independent evaluator result.
    Evaluator,
    /// A worker/model narrative, which is not semantic evidence.
    SelfReport,
    /// Tool/process response, which is not semantic evidence.
    ToolResponse,
    /// Delivery acknowledgement, which is not semantic evidence.
    DeliveryAcknowledgement,
}

/// One bounded semantic evidence envelope bound to the exact attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReceipt {
    /// Stable evidence identity retained in the A32 result.
    pub id: ArtifactId,
    /// Shared request/task/scope/fence binding.
    pub binding: ContractBinding,
    /// Attempt to which the evidence belongs.
    pub attempt_id: AgentAttemptId,
    /// Target whose outcome is measured.
    pub target: TargetId,
    /// Exact fence captured with the evidence.
    pub state_fence: StateFence,
    /// Metric identity, checked against policy.
    pub metric: String,
    /// Metric unit, checked against policy.
    pub unit: String,
    /// Population identity, checked against policy.
    pub population: String,
    /// Evaluation window identity, checked against policy.
    pub window: String,
    /// Source revision used for the semantic observation.
    pub source_revision: String,
    /// Source content digest used for the semantic observation.
    pub source_digest: String,
    /// Bounded source/evaluator units charged against policy.
    pub source_units: u32,
    /// Evidence role.
    pub kind: EvidenceKind,
    /// Semantic result, kept separate from causal interpretation.
    pub outcome: SemanticOutcome,
    /// Exact normalized evidence envelope owned by the evidence layer.
    pub envelope: EvidenceEnvelope,
}

impl EvidenceReceipt {
    /// Validate exact identity, source, metric and semantic-role binding.
    pub fn validate_for(
        &self,
        input: &crate::input::AttemptEvidence,
        policy: &DerivationPolicy,
    ) -> Result<(), LearningDeltaError> {
        validate_identity(self, input)?;
        validate_source_lineage(self)?;
        if self.metric != policy.metric
            || self.unit != policy.unit
            || self.population != policy.population
            || self.window != policy.window
        {
            return Err(LearningDeltaError::InsufficientEvidence { field: "metric" });
        }
        if self.source_units == 0 {
            return Err(LearningDeltaError::InsufficientEvidence {
                field: "source_units",
            });
        }
        self.envelope
            .validate()
            .map_err(|_| LearningDeltaError::EvidenceBinding { field: "envelope" })?;
        if self.envelope.state_fence != input.binding.state_fence
            || self.envelope.provenance.scope != input.binding.scope.as_str()
            || self.envelope.provenance.revision.as_deref() != Some(self.source_revision.as_str())
        {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "envelope.lineage",
            });
        }
        if !matches!(
            self.envelope.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        ) || self.envelope.coverage != EvidenceCoverage::CompleteForScope
        {
            return Err(LearningDeltaError::InsufficientEvidence { field: "coverage" });
        }
        if matches!(
            self.kind,
            EvidenceKind::SelfReport
                | EvidenceKind::ToolResponse
                | EvidenceKind::DeliveryAcknowledgement
        ) || matches!(
            self.envelope.authority,
            EvidenceAuthority::ModelInterpretation
        ) {
            return Err(LearningDeltaError::NonSemanticEvidence);
        }
        if matches!(
            self.outcome,
            SemanticOutcome::Inconclusive
                | SemanticOutcome::Unknown
                | SemanticOutcome::Mixed
                | SemanticOutcome::Missing
        ) || self.envelope.status == EpistemicStatus::Unknown
            || self.envelope.assertability == Assertability::AbstainOrFence
        {
            return Err(LearningDeltaError::InsufficientEvidence { field: "outcome" });
        }
        if self.kind == EvidenceKind::Evaluator
            && (self.envelope.status != EpistemicStatus::Verified
                || self.envelope.verification.is_none())
        {
            return Err(LearningDeltaError::MissingEvaluator);
        }
        if self.kind == EvidenceKind::Observation
            && self.envelope.status == EpistemicStatus::Verified
        {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "observation.status",
            });
        }
        if self.kind == EvidenceKind::Evaluator {
            let Some(expected) = input.evaluator_binding.as_ref() else {
                return Err(LearningDeltaError::MissingEvaluator);
            };
            let Some(actual) = self.envelope.verification.as_ref() else {
                return Err(LearningDeltaError::MissingEvaluator);
            };
            if actual.contract_id != expected.contract_id
                || actual.run_id.as_str() != expected.run_id.as_str()
                || actual.revision != expected.revision
            {
                return Err(LearningDeltaError::EvidenceBinding {
                    field: "evaluator.verification",
                });
            }
        }
        Ok(())
    }
}

fn validate_identity(
    receipt: &EvidenceReceipt,
    input: &crate::input::AttemptEvidence,
) -> Result<(), LearningDeltaError> {
    if receipt.id.as_str().trim().is_empty()
        || receipt.binding.schema_version != input.binding.schema_version
        || receipt.binding.policy_revision != input.binding.policy_revision
        || receipt.binding.request_id != input.binding.request_id
        || receipt.binding.operation_id != input.binding.operation_id
        || receipt.binding.product_id != input.binding.product_id
        || receipt.binding.task_id != input.binding.task_id
        || receipt.binding.scope != input.binding.scope
        || receipt.binding.state_fence != input.binding.state_fence
        || receipt.binding.proof_ceiling != input.binding.proof_ceiling
        || receipt.attempt_id != input.attempt_id
        || receipt.target != input.target
        || receipt.state_fence != input.binding.state_fence
    {
        return Err(LearningDeltaError::EvidenceBinding { field: "identity" });
    }
    Ok(())
}

fn validate_source_lineage(receipt: &EvidenceReceipt) -> Result<(), LearningDeltaError> {
    if receipt.source_revision.trim().is_empty()
        || receipt.source_digest.len() != 64
        || !receipt
            .source_digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || receipt.envelope.provenance.revision.as_deref() != Some(receipt.source_revision.as_str())
        || receipt.envelope.provenance.raw_handle.as_deref() != Some(receipt.id.as_str())
        || receipt
            .envelope
            .provenance
            .source_id
            .as_str()
            .trim()
            .is_empty()
    {
        return Err(LearningDeltaError::EvidenceBinding { field: "source" });
    }
    Ok(())
}
