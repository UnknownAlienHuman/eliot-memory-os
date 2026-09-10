//! Typed probe objectives. These are declarations, not planner decisions.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ContractId, SourceId};
use eliot_epistemic_contracts::{CoverageDenominator, InvestigationRequirement, ValidityBounds};
use eliot_evaluation_contracts::PlannedVerifierRef;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractViolation,
    rival::{ConditionAssumptionRef, MaterialClaimRef, RivalPredictionRef},
};

use super::{
    bounds::{MAX_PROBE_ITEMS, PROBE_OBJECTIVE_SCHEMA_VERSION, check_sequence},
    validation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeObjectiveOrigin {
    RivalPredictionDifference,
    EvidenceCoverageGap,
    FalsifiableLoadBearingAssumption,
    SuppliedDiscriminator,
    MissingVerifier,
}

/// Typed owner reference for a required follow-up, never an authority claim.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeOwnerRef {
    Source { owner: SourceId },
    Verifier { verifier_id: ContractId },
    Unavailable { reason: String },
}

impl ProbeOwnerRef {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Source { owner } => validation::text(owner.as_str(), "probe.owner.source")?,
            Self::Verifier { verifier_id } => {
                validation::text(verifier_id.as_str(), "probe.owner.verifier")?
            }
            Self::Unavailable { reason } => validation::text(reason, "probe.owner.reason")?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeObjectiveTarget {
    RivalPredictions {
        left: RivalPredictionRef,
        right: RivalPredictionRef,
    },
    EvidenceGap {
        claim: MaterialClaimRef,
        denominator: Option<Box<CoverageDenominator>>,
    },
    Assumption {
        assumption: ConditionAssumptionRef,
        claim: Option<MaterialClaimRef>,
    },
    Discriminator {
        requirement: Box<InvestigationRequirement>,
    },
    Verifier {
        verifier: Box<PlannedVerifierRef>,
    },
}

/// Digest-pinned identity used when a result branch updates an objective gap.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeObjectiveRef {
    pub objective_id: ArtifactId,
    pub objective_digest: String,
}

impl ProbeObjectiveRef {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(
            self.objective_id.as_str(),
            "probe.objective_ref.objective_id",
        )?;
        validation::digest(
            &self.objective_digest,
            "probe.objective_ref.objective_digest",
        )
    }
}

impl ProbeObjectiveTarget {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::RivalPredictions { left, right } => {
                left.validate()?;
                right.validate()?;
                if left.prediction_id == right.prediction_id {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe.objective.target.rival_predictions",
                        reason: "rival prediction endpoints must be distinct".to_owned(),
                    });
                }
            }
            Self::EvidenceGap { claim, denominator } => {
                claim.validate()?;
                if let Some(denominator) = denominator {
                    denominator
                        .validate()
                        .map_err(|error| ContractViolation::BindingMismatch {
                            field: "probe.objective.target.denominator",
                            reason: error.to_string(),
                        })?;
                }
            }
            Self::Assumption { assumption, claim } => {
                assumption.validate()?;
                if let Some(claim) = claim {
                    claim.validate()?;
                }
            }
            Self::Discriminator { requirement } => {
                requirement
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "probe.objective.target.requirement",
                        reason: error.to_string(),
                    })?
            }
            Self::Verifier { verifier } => {
                verifier
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "probe.objective.target.verifier",
                        reason: error.to_string(),
                    })?
            }
        }
        Ok(())
    }
}

fn origin_matches_target(origin: ProbeObjectiveOrigin, target: &ProbeObjectiveTarget) -> bool {
    matches!(
        (origin, target),
        (
            ProbeObjectiveOrigin::RivalPredictionDifference,
            ProbeObjectiveTarget::RivalPredictions { .. }
        ) | (
            ProbeObjectiveOrigin::EvidenceCoverageGap,
            ProbeObjectiveTarget::EvidenceGap { .. }
        ) | (
            ProbeObjectiveOrigin::FalsifiableLoadBearingAssumption,
            ProbeObjectiveTarget::Assumption { .. }
        ) | (
            ProbeObjectiveOrigin::SuppliedDiscriminator,
            ProbeObjectiveTarget::Discriminator { .. }
        ) | (
            ProbeObjectiveOrigin::MissingVerifier,
            ProbeObjectiveTarget::Verifier { .. }
        )
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeObjective {
    pub schema_version: u32,
    pub objective_id: ArtifactId,
    pub origin: ProbeObjectiveOrigin,
    pub target: ProbeObjectiveTarget,
    pub applicability: ValidityBounds,
    pub materiality_rationale: String,
    pub source_refs: BTreeSet<ArtifactId>,
    pub invalidation_conditions: Vec<ConditionAssumptionRef>,
    pub required_owner: ProbeOwnerRef,
    pub digest: String,
}

impl ProbeObjective {
    pub fn new(
        objective_id: ArtifactId,
        origin: ProbeObjectiveOrigin,
        target: ProbeObjectiveTarget,
        applicability: ValidityBounds,
        materiality_rationale: String,
        source_refs: BTreeSet<ArtifactId>,
        invalidation_conditions: Vec<ConditionAssumptionRef>,
        required_owner: ProbeOwnerRef,
    ) -> Result<Self, ContractViolation> {
        let mut objective = Self {
            schema_version: PROBE_OBJECTIVE_SCHEMA_VERSION,
            objective_id,
            origin,
            target,
            applicability,
            materiality_rationale,
            source_refs,
            invalidation_conditions,
            required_owner,
            digest: String::new(),
        };
        validation::preflight(&objective)?;
        objective.validate_shape()?;
        objective.digest = objective.compute_digest()?;
        Ok(objective)
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.objective.digest")?;
        let expected = self.compute_digest()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.objective.digest",
                reason: "objective digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&(
            self.schema_version,
            &self.objective_id,
            self.origin,
            &self.target,
            &self.applicability,
            &self.materiality_rationale,
            &self.source_refs,
            &self.invalidation_conditions,
            &self.required_owner,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != PROBE_OBJECTIVE_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.objective.schema_version",
                reason: "unsupported objective schema".to_owned(),
            });
        }
        validation::text(self.objective_id.as_str(), "probe.objective.objective_id")?;
        validation::text(
            &self.materiality_rationale,
            "probe.objective.materiality_rationale",
        )?;
        self.required_owner.validate()?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.objective.applicability",
                reason: error.to_string(),
            })?;
        if !origin_matches_target(self.origin, &self.target) {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.objective.target",
                reason: "objective origin and target kind differ".to_owned(),
            });
        }
        self.target.validate()?;
        if self.source_refs.len() > MAX_PROBE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.objective.source_refs",
                min: 0,
                max: MAX_PROBE_ITEMS as i64,
                got: self.source_refs.len() as i64,
            });
        }
        for source in &self.source_refs {
            validation::text(source.as_str(), "probe.objective.source_ref")?;
        }
        check_sequence(
            self.invalidation_conditions.len(),
            "probe.objective.invalidation_conditions",
        )?;
        let mut seen = BTreeSet::new();
        for condition in &self.invalidation_conditions {
            condition.validate()?;
            if !seen.insert(condition.assumption_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.objective.invalidation_conditions",
                    reason: "duplicate assumption identity".to_owned(),
                });
            }
        }
        Ok(())
    }
}
