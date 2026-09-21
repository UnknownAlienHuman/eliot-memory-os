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

/// Materiality of an objective supplied by its owning contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeObjectiveMateriality {
    Material { rationale: String },
    NonMaterial { reason: String },
    Unknown { reason: String },
}

impl ProbeObjectiveMateriality {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Material { rationale } => {
                validation::text(rationale, "probe.objective.materiality")
            }
            Self::NonMaterial { reason } | Self::Unknown { reason } => {
                validation::text(reason, "probe.objective.materiality")
            }
        }
    }

    pub fn is_material(&self) -> bool {
        matches!(self, Self::Material { .. })
    }
}

/// Resolution state of an objective before a probe is planned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeObjectiveResolution {
    Open,
    Resolved { basis: String },
    Invalidated { reason: String },
    Unknown { reason: String },
}

impl ProbeObjectiveResolution {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Open => Ok(()),
            Self::Resolved { basis } => validation::text(basis, "probe.objective.resolution"),
            Self::Invalidated { reason } | Self::Unknown { reason } => {
                validation::text(reason, "probe.objective.resolution")
            }
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }
}

/// Exact causal controls, confounders, and rival endpoints required by a
/// causal probe. These are references only; no intervention is performed.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalProbeRequirements {
    pub controls: BTreeSet<ArtifactId>,
    pub confounders: BTreeSet<ArtifactId>,
    pub rival_predictions: BTreeSet<RivalPredictionRef>,
}

impl CausalProbeRequirements {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        check_sequence(self.controls.len(), "probe.objective.causal.controls")?;
        check_sequence(self.confounders.len(), "probe.objective.causal.confounders")?;
        check_sequence(
            self.rival_predictions.len(),
            "probe.objective.causal.rival_predictions",
        )?;
        for control in &self.controls {
            validation::text(control.as_str(), "probe.objective.causal.control")?;
        }
        for confounder in &self.confounders {
            validation::text(confounder.as_str(), "probe.objective.causal.confounder")?;
        }
        for prediction in &self.rival_predictions {
            prediction.validate()?;
        }
        if self.controls.is_empty()
            && self.confounders.is_empty()
            && self.rival_predictions.is_empty()
        {
            return Err(ContractViolation::MissingField(
                "probe.objective.causal.requirements",
            ));
        }
        Ok(())
    }
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
                validation::text(verifier_id.as_str(), "probe.owner.verifier")?;
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

/// Exact objective semantics attached to an affordance or result matrix.
///
/// The claim/assumption fields prevent a gap proxy from being treated as the
/// objective it happens to mention. This binding grants no authority and
/// performs no resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeObjectiveBinding {
    pub objective: ProbeObjectiveRef,
    pub claim: Option<MaterialClaimRef>,
    pub assumption: Option<ConditionAssumptionRef>,
    pub materiality: ProbeObjectiveMateriality,
    pub resolution: ProbeObjectiveResolution,
    pub denominator: Option<Box<CoverageDenominator>>,
    pub causal_requirements: Option<CausalProbeRequirements>,
}

impl ProbeObjectiveBinding {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.objective.validate()?;
        if let Some(claim) = &self.claim {
            claim.validate()?;
        }
        if let Some(assumption) = &self.assumption {
            assumption.validate()?;
        }
        self.materiality.validate()?;
        self.resolution.validate()?;
        if let Some(denominator) = &self.denominator {
            denominator
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "probe.objective.binding.denominator",
                    reason: error.to_string(),
                })?;
        }
        if let Some(causal) = &self.causal_requirements {
            causal.validate()?;
        }
        Ok(())
    }

    pub fn ready_for_planning(&self) -> bool {
        self.materiality.is_material() && self.resolution.is_open()
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
                    })?;
            }
            Self::Verifier { verifier } => {
                verifier
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "probe.objective.target.verifier",
                        reason: error.to_string(),
                    })?;
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
    pub materiality: ProbeObjectiveMateriality,
    pub resolution: ProbeObjectiveResolution,
    pub denominator: Option<Box<CoverageDenominator>>,
    pub causal_requirements: Option<CausalProbeRequirements>,
    pub source_refs: BTreeSet<ArtifactId>,
    pub invalidation_conditions: Vec<ConditionAssumptionRef>,
    pub required_owner: ProbeOwnerRef,
    pub digest: String,
}

impl ProbeObjective {
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the complete canonical objective declaration"
    )]
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
        let denominator = match &target {
            ProbeObjectiveTarget::EvidenceGap { denominator, .. } => denominator.clone(),
            _ => None,
        };
        let mut objective = Self {
            schema_version: PROBE_OBJECTIVE_SCHEMA_VERSION,
            objective_id,
            origin,
            target,
            applicability,
            materiality_rationale,
            materiality: ProbeObjectiveMateriality::Material {
                rationale: "declared by objective owner".to_owned(),
            },
            resolution: ProbeObjectiveResolution::Open,
            denominator,
            causal_requirements: None,
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

    /// Replaces owner-supplied readiness semantics and reseals the objective.
    pub fn with_semantics(
        mut self,
        materiality: ProbeObjectiveMateriality,
        resolution: ProbeObjectiveResolution,
        denominator: Option<Box<CoverageDenominator>>,
        causal_requirements: Option<CausalProbeRequirements>,
    ) -> Result<Self, ContractViolation> {
        self.materiality = materiality;
        self.resolution = resolution;
        self.denominator = denominator;
        self.causal_requirements = causal_requirements;
        self.validate_shape()?;
        self.digest = self.compute_digest()?;
        Ok(self)
    }

    /// Produces the exact binding carried into a planner affordance.
    pub fn binding(&self) -> Result<ProbeObjectiveBinding, ContractViolation> {
        self.validate()?;
        let (claim, assumption) = match &self.target {
            ProbeObjectiveTarget::EvidenceGap { claim, .. } => (Some(claim.clone()), None),
            ProbeObjectiveTarget::Assumption { assumption, claim } => {
                (claim.clone(), Some(assumption.clone()))
            }
            _ => (None, None),
        };
        let binding = ProbeObjectiveBinding {
            objective: ProbeObjectiveRef {
                objective_id: self.objective_id.clone(),
                objective_digest: self.digest.clone(),
            },
            claim,
            assumption,
            materiality: self.materiality.clone(),
            resolution: self.resolution.clone(),
            denominator: self.denominator.clone(),
            causal_requirements: self.causal_requirements.clone(),
        };
        binding.validate()?;
        Ok(binding)
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
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::canonical_digest(&(
            self.schema_version,
            &self.objective_id,
            self.origin,
            &self.target,
            &self.applicability,
            &self.materiality_rationale,
            &self.materiality,
            &self.resolution,
            &self.denominator,
            &self.causal_requirements,
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
        self.materiality.validate()?;
        self.resolution.validate()?;
        if let Some(denominator) = &self.denominator {
            denominator
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "probe.objective.denominator",
                    reason: error.to_string(),
                })?;
        }
        if let Some(causal) = &self.causal_requirements {
            causal.validate()?;
        }
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
                max: crate::error::len_i64(MAX_PROBE_ITEMS),
                got: crate::error::len_i64(self.source_refs.len()),
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
