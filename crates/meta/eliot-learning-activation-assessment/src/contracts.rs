//! Local parameter and result containers over canonical A-32 records.

use eliot_contracts::ArtifactId;
use eliot_learning_contracts::{
    AssessmentDimension, AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate,
    CampaignLearningStateView, CausalCeiling, ContractBinding, DimensionAssessment,
    HarnessActivationReceiptCandidate, LearningAssessmentCandidate, LearningStateViewRecipe,
    LifecycleStage, MetricObservation, SourceDenominator, StageObservation,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum bytes accepted from one assessment input.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bytes retained in one assessment result.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum lifecycle observations in one call.
pub const MAX_STAGES: usize = 64;
/// Maximum independent dimensions in one call.
pub const MAX_DIMENSIONS: usize = 32;
/// Maximum metrics in one call.
pub const MAX_METRICS: usize = 64;
/// Maximum references in one call.
pub const MAX_REFERENCES: usize = 256;

/// Caller-supplied finite requirements; this is not an authority policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentPolicy {
    /// Version of this local parameter shape.
    pub schema_version: u16,
    /// Expected lifecycle stages.
    pub required_stages: Vec<LifecycleStage>,
    /// Expected independent dimensions.
    pub required_dimensions: Vec<AssessmentDimension>,
    /// Denominator retained for missing stage observations.
    pub stage_denominator: SourceDenominator,
    /// Denominator retained for missing dimensions.
    pub dimension_denominator: SourceDenominator,
    /// Maximum serialized input accepted by this call.
    pub max_input_bytes: usize,
    /// Maximum serialized result accepted by this call.
    pub max_output_bytes: usize,
}

impl AssessmentPolicy {
    /// Current local parameter revision.
    pub const SCHEMA_VERSION: u16 = 1;

    /// Validate finite policy shape and bounds.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err("policy.schema_version");
        }
        if self.required_stages.is_empty() || self.required_stages.len() > MAX_STAGES {
            return Err("policy.required_stages");
        }
        let mut stages = BTreeSet::new();
        for stage in &self.required_stages {
            if !stages.insert(*stage) {
                return Err("policy.required_stages");
            }
        }
        if self.required_dimensions.is_empty() || self.required_dimensions.len() > MAX_DIMENSIONS {
            return Err("policy.required_dimensions");
        }
        let mut dimensions = BTreeSet::new();
        for dimension in &self.required_dimensions {
            if !dimensions.insert(*dimension) {
                return Err("policy.required_dimensions");
            }
        }
        if dimensions.len() != 13 {
            return Err("policy.required_dimensions");
        }
        if self.stage_denominator.declared == 0
            || self.dimension_denominator.declared == 0
            || self.stage_denominator.observed > self.stage_denominator.declared
            || self.dimension_denominator.observed > self.dimension_denominator.declared
        {
            return Err("policy.denominator");
        }
        if self.max_input_bytes == 0
            || self.max_input_bytes > MAX_INPUT_BYTES
            || self.max_output_bytes == 0
            || self.max_output_bytes > MAX_OUTPUT_BYTES
        {
            return Err("policy.byte_limit");
        }
        Ok(())
    }
}

/// Complete bounded input retained so output cannot outlive its evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentInputSnapshot {
    /// Exact recipe and immutable state view.
    pub recipe: LearningStateViewRecipe,
    pub view: CampaignLearningStateView,
    /// Exact attempt and overlay lineage.
    pub delta: AttemptLearningDeltaCandidate,
    pub overlay: CampaignHarnessOverlayCandidate,
    /// Request identity and local requirements.
    pub binding: ContractBinding,
    pub target: eliot_learning_contracts::TargetId,
    pub policy: AssessmentPolicy,
    /// Supplied candidate/owner identities.
    pub activation_id: Option<ArtifactId>,
    pub admission_receipt: Option<ArtifactId>,
    pub activation_request_receipt: Option<ArtifactId>,
    pub assessment_receipt: Option<ArtifactId>,
    /// Supplied immutable owner evidence.
    pub stages: Vec<StageObservation>,
    pub metrics: Vec<MetricObservation>,
    pub attrition: Vec<ArtifactId>,
    pub confounders: Vec<ArtifactId>,
    pub independent_evaluator_receipt: Option<ArtifactId>,
    pub dimensions: Vec<DimensionAssessment>,
    pub external_review_refs: Vec<ArtifactId>,
    /// Digest over all fields above, excluding this field.
    pub input_digest: String,
}

impl AssessmentInputSnapshot {
    /// Populate the receipt-excluded complete input digest.
    pub fn seal(&mut self) -> Result<(), crate::ActivationAssessmentError> {
        crate::bounds::bounded_serialized_len(
            self,
            self.policy.max_input_bytes.min(MAX_INPUT_BYTES),
            "input",
        )?;
        self.input_digest =
            eliot_learning_contracts::identity::digest_without_field(self, "input_digest")
                .map_err(|_| crate::ActivationAssessmentError::Canonicalization)?;
        Ok(())
    }
}

/// Exact missing canonical evidence required to construct a candidate.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissingAssessmentField {
    /// Stable activation candidate identity.
    ActivationId,
    /// External admission receipt identity.
    AdmissionReceipt,
    /// External activation request receipt identity.
    ActivationRequestReceipt,
    /// Assessment owner receipt identity.
    AssessmentReceipt,
}

/// Candidate-only result retaining both canonical A-32 records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentResult {
    /// Complete bounded source input retained for reconciliation.
    pub input: AssessmentInputSnapshot,
    /// Constructed activation lifecycle candidate.
    pub activation: HarnessActivationReceiptCandidate,
    /// Constructed independent-dimension assessment candidate.
    pub assessment: LearningAssessmentCandidate,
    /// Canonical local result digest, excluding this field.
    pub canonical_digest: String,
}

impl AssessmentResult {
    /// Seal this composition without adding semantic authority.
    pub fn seal(&mut self) -> Result<(), crate::ActivationAssessmentError> {
        crate::bounds::bounded_serialized_len(
            self,
            self.input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
            "result",
        )?;
        self.canonical_digest =
            eliot_learning_contracts::identity::digest_without_field(self, "canonical_digest")
                .map_err(|_| crate::ActivationAssessmentError::Canonicalization)?;
        Ok(())
    }

    /// Validate both canonical owner records and the local digest.
    pub fn validate(&self) -> Result<(), crate::ActivationAssessmentError> {
        crate::bounds::bounded_serialized_len(
            self,
            self.input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
            "result",
        )?;
        self.input
            .policy
            .validate_shape()
            .map_err(|field| crate::ActivationAssessmentError::Bound { field })?;
        crate::assessment::validate_supplied_evidence(
            &self.input.metrics,
            &self.input.stages,
            &self.input.dimensions,
        )?;
        let expected_input =
            eliot_learning_contracts::identity::digest_without_field(&self.input, "input_digest")
                .map_err(|_| crate::ActivationAssessmentError::Canonicalization)?;
        if expected_input != self.input.input_digest {
            return Err(crate::ActivationAssessmentError::LineageMismatch {
                field: "result.input_digest",
            });
        }
        if self.activation.binding != self.input.binding
            || self.activation.target != self.input.target
            || self.activation.view_digest != self.input.view.canonical_digest
            || self.activation.delta_id != self.input.delta.delta_id
            || self.activation.overlay_id != self.input.overlay.overlay_id
            || self.assessment.binding != self.input.binding
            || self.assessment.target != self.input.target
            || self.assessment.overlay_id != self.input.overlay.overlay_id
            || self.input.recipe.binding != self.input.binding
        {
            return Err(crate::ActivationAssessmentError::LineageMismatch {
                field: "result.input_binding",
            });
        }
        if self.input.activation_id.as_ref() != Some(&self.activation.activation_id)
            || self.input.admission_receipt.as_ref() != Some(&self.activation.admission_receipt)
            || self.input.activation_request_receipt.as_ref()
                != Some(&self.activation.activation_request_receipt)
            || self.input.assessment_receipt.as_ref() != Some(&self.assessment.assessment_receipt)
            || self.activation.member_denominator != self.input.view.denominator
            || self.activation.metrics != self.input.metrics
            || self.activation.attrition != self.input.attrition
            || self.activation.confounders != self.input.confounders
            || self.activation.independent_evaluator_receipt
                != self.input.independent_evaluator_receipt
            || self.assessment.external_review_refs != self.input.external_review_refs
            || self.assessment.activation_digest != self.activation.canonical_digest
        {
            return Err(crate::ActivationAssessmentError::LineageMismatch {
                field: "result.retained_evidence",
            });
        }
        let expected_stages =
            crate::assessment::expected_stages(&self.input.stages, &self.input.policy)?;
        let expected_dimensions =
            crate::assessment::expected_dimensions(&self.input.dimensions, &self.input.policy)?;
        if self.activation.stages != expected_stages
            || self.assessment.dimensions != expected_dimensions
        {
            return Err(crate::ActivationAssessmentError::LineageMismatch {
                field: "result.reconciled_evidence",
            });
        }
        self.input
            .view
            .validate_against(&self.input.recipe)
            .map_err(|error| crate::ActivationAssessmentError::contract("input.view", error))?;
        self.input
            .delta
            .validate_against_view(&self.input.view)
            .map_err(|error| crate::ActivationAssessmentError::contract("input.delta", error))?;
        self.input
            .overlay
            .validate_against_view_and_deltas(
                &self.input.view,
                std::slice::from_ref(&self.input.delta),
            )
            .map_err(|error| crate::ActivationAssessmentError::contract("input.overlay", error))?;
        self.activation
            .validate_against_lineage(&self.input.view, &self.input.delta, &self.input.overlay)
            .map_err(|error| crate::ActivationAssessmentError::contract("activation", error))?;
        self.assessment
            .validate_against_activation(&self.activation)
            .map_err(|error| crate::ActivationAssessmentError::contract("assessment", error))?;
        if self.assessment.causal_ceiling != CausalCeiling::Observational {
            return Err(crate::ActivationAssessmentError::LineageMismatch {
                field: "assessment.causal_ceiling",
            });
        }
        let expected =
            eliot_learning_contracts::identity::digest_without_field(self, "canonical_digest")
                .map_err(|_| crate::ActivationAssessmentError::Canonicalization)?;
        if expected != self.canonical_digest {
            return Err(crate::ActivationAssessmentError::LineageMismatch {
                field: "result.canonical_digest",
            });
        }
        Ok(())
    }
}

/// Explicit incomplete outcome; no placeholder receipt IDs are minted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IncompleteAssessment {
    /// Complete bounded source input retained for reconciliation.
    pub input: AssessmentInputSnapshot,
    /// Original binding retained for caller reconciliation.
    pub binding: ContractBinding,
    /// Original activation target.
    pub target: eliot_learning_contracts::TargetId,
    /// Exact missing requirements.
    pub missing: Vec<MissingAssessmentField>,
    /// Supplied stage observations retained exactly.
    pub supplied_stages: Vec<StageObservation>,
    /// Supplied dimensions retained exactly.
    pub supplied_dimensions: Vec<DimensionAssessment>,
    /// Parent candidate identity, when available.
    pub activation_id: Option<ArtifactId>,
}
