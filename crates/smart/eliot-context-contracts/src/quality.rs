//! Independent normative quality dimensions.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, MeasurementRef};

/// The twelve exact I12.13 quality dimensions.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityDimension {
    AcceptanceDecisionCoverage,
    CausalOperationalSufficiency,
    ExactAnchorProvenanceCoverage,
    FreshnessStateFenceCoherence,
    RivalsConflictsUnknownsVisibility,
    NegativeMemoryInvariantCoverage,
    VerifierActionReadiness,
    RouteAccessibilityLayoutRisk,
    InstructionSufficiency,
    PayloadHandleReconstructionCost,
    KnownOmissionsExpansionPaths,
    TelemetryMeasurementCostCoverage,
}

/// One independent dimension result. There is no aggregate scalar.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityDimensionResult {
    pub dimension: QualityDimension,
    pub passed: bool,
    pub evidence: Vec<ArtifactId>,
    pub measurements: Vec<MeasurementRef>,
    pub failed_invariant: Option<ArtifactId>,
    pub unknown_evidence: Vec<ArtifactId>,
    pub proof_ceiling: ProofCeiling,
    pub invalidation: Option<ArtifactId>,
    pub binding: ContextBinding,
}

/// Closed twelve-axis quality scorecard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityScorecard {
    pub binding: ContextBinding,
    pub results: Vec<QualityDimensionResult>,
}

impl QualityScorecard {
    /// Validate exact closure and independent evidence for every dimension.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        let mut seen = BTreeSet::new();
        for result in &self.results {
            if result.binding != self.binding || !seen.insert(result.dimension) {
                return Err(ContextError::QualityIncomplete);
            }
            if result.passed
                && (result.evidence.is_empty()
                    || result.failed_invariant.is_some()
                    || !result.unknown_evidence.is_empty())
            {
                return Err(ContextError::QualityIncomplete);
            }
            if !result.passed
                && result.failed_invariant.is_none()
                && result.unknown_evidence.is_empty()
            {
                return Err(ContextError::QualityIncomplete);
            }
            for measurement in &result.measurements {
                measurement.validate()?;
            }
        }
        if seen.len() != 12 {
            return Err(ContextError::QualityIncomplete);
        }
        Ok(())
    }

    /// A complete scorecard is valid only when every mandatory dimension passes.
    pub fn all_pass(&self) -> Result<bool, ContextError> {
        self.validate()?;
        Ok(self.results.iter().all(|result| result.passed))
    }
}
