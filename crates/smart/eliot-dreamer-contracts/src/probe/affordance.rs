//! Owner-neutral inquiry-affordance declarations for the pure probe planner.
//!
//! These records describe externally owned opportunities. They never reserve
//! capacity, grant authority, execute a provider, or attest an observation.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::ValidityBounds;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractViolation, rival::ConditionAssumptionRef};

use super::{
    bounds::{MAX_PROBE_ITEMS, check_sequence},
    objective::{ProbeObjectiveOrigin, ProbeOwnerRef},
    result::PossibleResultSchema,
    validation,
};

/// Wire revision for one inquiry-affordance descriptor.
pub const INQUIRY_AFFORDANCE_SCHEMA_VERSION: u32 = 1;
/// Wire revision for one complete inquiry-affordance set.
pub const INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION: u32 = 1;

/// One independently interpreted non-negative planning dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeEstimate {
    Known { units: u64 },
    Unknown { reason: String },
    NotApplicable { reason: String },
}

impl ProbeEstimate {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        match self {
            Self::Known { .. } => Ok(()),
            Self::Unknown { reason } | Self::NotApplicable { reason } => {
                validation::text(reason, field)
            }
        }
    }

    pub fn known_units(&self) -> Option<u64> {
        match self {
            Self::Known { units } => Some(*units),
            Self::Unknown { .. } | Self::NotApplicable { .. } => None,
        }
    }
}

/// Independent permission or protection state for one affordance dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeRequirementState {
    NotRequired,
    Satisfied { evidence: ArtifactId },
    Required { owner: ProbeOwnerRef, reason: String },
    Unknown { reason: String },
    Failed { reason: String },
}

impl ProbeRequirementState {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        match self {
            Self::NotRequired => Ok(()),
            Self::Satisfied { evidence } => validation::text(evidence.as_str(), field),
            Self::Required { owner, reason } => {
                validate_owner(owner)?;
                validation::text(reason, field)
            }
            Self::Unknown { reason } | Self::Failed { reason } => {
                validation::text(reason, field)
            }
        }
    }

    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::NotRequired | Self::Satisfied { .. })
    }
}

/// External-effect ceiling declared by the affordance owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeEffectClass {
    None,
    ReadOnly,
    ReversibleExternal,
    IrreversibleExternal,
    Unknown,
}

/// Reversibility declaration; never an applied rollback receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeReversibility {
    NotApplicable,
    Reversible { inverse: ArtifactId },
    Compensatable { compensation: ArtifactId },
    Irreversible { reason: String },
    Unknown { reason: String },
}

impl ProbeReversibility {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::NotApplicable => Ok(()),
            Self::Reversible { inverse } => validation::text(
                inverse.as_str(),
                "probe.affordance.reversibility.inverse",
            ),
            Self::Compensatable { compensation } => validation::text(
                compensation.as_str(),
                "probe.affordance.reversibility.compensation",
            ),
            Self::Irreversible { reason } | Self::Unknown { reason } => {
                validation::text(reason, "probe.affordance.reversibility.reason")
            }
        }
    }
}

/// Descriptive availability. Availability never implies permission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeFeasibility {
    Available,
    Unavailable { reason: String },
    Unknown { reason: String },
}

impl ProbeFeasibility {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Available => Ok(()),
            Self::Unavailable { reason } | Self::Unknown { reason } => {
                validation::text(reason, "probe.affordance.feasibility.reason")
            }
        }
    }
}

/// One immutable, inert inquiry affordance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryAffordanceDescriptor {
    pub schema_version: u32,
    pub affordance_id: ArtifactId,
    pub revision: u64,
    /// Unique canonical-order objective kinds this affordance can address.
    pub objective_origins: Vec<ProbeObjectiveOrigin>,
    pub owner: ProbeOwnerRef,
    pub applicability: ValidityBounds,
    pub result_schema: PossibleResultSchema,
    pub information_gain: ProbeEstimate,
    pub cost: ProbeEstimate,
    pub latency: ProbeEstimate,
    pub context: ProbeEstimate,
    pub resources: ProbeEstimate,
    pub privacy: ProbeRequirementState,
    pub consent: ProbeRequirementState,
    pub authority: ProbeRequirementState,
    pub effects: ProbeEffectClass,
    pub reversibility: ProbeReversibility,
    pub feasibility: ProbeFeasibility,
    pub human_attention: ProbeEstimate,
    pub source_refs: BTreeSet<ArtifactId>,
    pub invalidation_conditions: Vec<ConditionAssumptionRef>,
    pub digest: String,
}

impl InquiryAffordanceDescriptor {
    #[allow(clippy::too_many_arguments, reason = "mirrors independent planning dimensions")]
    pub fn new(
        affordance_id: ArtifactId,
        revision: u64,
        objective_origins: Vec<ProbeObjectiveOrigin>,
        owner: ProbeOwnerRef,
        applicability: ValidityBounds,
        result_schema: PossibleResultSchema,
        information_gain: ProbeEstimate,
        cost: ProbeEstimate,
        latency: ProbeEstimate,
        context: ProbeEstimate,
        resources: ProbeEstimate,
        privacy: ProbeRequirementState,
        consent: ProbeRequirementState,
        authority: ProbeRequirementState,
        effects: ProbeEffectClass,
        reversibility: ProbeReversibility,
        feasibility: ProbeFeasibility,
        human_attention: ProbeEstimate,
        source_refs: BTreeSet<ArtifactId>,
        invalidation_conditions: Vec<ConditionAssumptionRef>,
    ) -> Result<Self, ContractViolation> {
        let mut value = Self {
            schema_version: INQUIRY_AFFORDANCE_SCHEMA_VERSION,
            affordance_id,
            revision,
            objective_origins,
            owner,
            applicability,
            result_schema,
            information_gain,
            cost,
            latency,
            context,
            resources,
            privacy,
            consent,
            authority,
            effects,
            reversibility,
            feasibility,
            human_attention,
            source_refs,
            invalidation_conditions,
            digest: String::new(),
        };
        value.validate_shape()?;
        value.digest = value.compute_digest()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.affordance.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance.digest",
                reason: "digest does not match the affordance declaration".to_owned(),
            });
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&(
            self.schema_version,
            &self.affordance_id,
            self.revision,
            &self.objective_origins,
            &self.owner,
            &self.applicability,
            &self.result_schema,
            &self.information_gain,
            &self.cost,
            &self.latency,
            &self.context,
            &self.resources,
            &self.privacy,
            &self.consent,
            &self.authority,
            self.effects,
            &self.reversibility,
            &self.feasibility,
            &self.human_attention,
            &self.source_refs,
            &self.invalidation_conditions,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != INQUIRY_AFFORDANCE_SCHEMA_VERSION {
            return binding("probe.affordance.schema_version", "unsupported schema version");
        }
        validation::text(self.affordance_id.as_str(), "probe.affordance.affordance_id")?;
        if self.revision == 0 {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.affordance.revision",
                min: 1,
                max: i64::MAX,
                got: 0,
            });
        }
        if self.objective_origins.is_empty() || self.objective_origins.len() > MAX_PROBE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.affordance.objective_origins",
                min: 1,
                max: crate::error::len_i64(MAX_PROBE_ITEMS),
                got: crate::error::len_i64(self.objective_origins.len()),
            });
        }
        let mut prior_rank = None;
        for origin in &self.objective_origins {
            let rank = origin_rank(*origin);
            if prior_rank.is_some_and(|prior| prior >= rank) {
                return binding(
                    "probe.affordance.objective_origins",
                    "origins must be unique and canonically ordered",
                );
            }
            prior_rank = Some(rank);
        }
        validate_owner(&self.owner)?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.affordance.applicability",
                reason: error.to_string(),
            })?;
        self.result_schema.validate()?;
        self.information_gain.validate("probe.affordance.information_gain")?;
        self.cost.validate("probe.affordance.cost")?;
        self.latency.validate("probe.affordance.latency")?;
        self.context.validate("probe.affordance.context")?;
        self.resources.validate("probe.affordance.resources")?;
        self.privacy.validate("probe.affordance.privacy")?;
        self.consent.validate("probe.affordance.consent")?;
        self.authority.validate("probe.affordance.authority")?;
        self.reversibility.validate()?;
        self.feasibility.validate()?;
        self.human_attention.validate("probe.affordance.human_attention")?;
        validate_effect_reversibility(self.effects, &self.reversibility)?;
        if self.source_refs.len() > MAX_PROBE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.affordance.source_refs",
                min: 0,
                max: crate::error::len_i64(MAX_PROBE_ITEMS),
                got: crate::error::len_i64(self.source_refs.len()),
            });
        }
        for source in &self.source_refs {
            validation::text(source.as_str(), "probe.affordance.source_ref")?;
        }
        check_sequence(
            self.invalidation_conditions.len(),
            "probe.affordance.invalidation_conditions",
        )?;
        let mut assumptions = BTreeSet::new();
        for condition in &self.invalidation_conditions {
            condition.validate()?;
            if !assumptions.insert(condition.assumption_id.clone()) {
                return binding(
                    "probe.affordance.invalidation_conditions",
                    "duplicate assumption identity",
                );
            }
        }
        Ok(())
    }
}

/// Completeness of the externally supplied affordance denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AffordanceSetStatus {
    Complete,
    Partial,
    Unknown,
}

/// Exact immutable set supplied to the probe planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryAffordanceSet {
    pub schema_version: u32,
    pub set_id: ArtifactId,
    pub task_id: TaskId,
    pub scope: String,
    pub state_fence: StateFence,
    pub descriptors: Vec<InquiryAffordanceDescriptor>,
    pub status: AffordanceSetStatus,
    pub omissions: Vec<String>,
    pub digest: String,
}

impl InquiryAffordanceSet {
    pub fn new(
        set_id: ArtifactId,
        task_id: TaskId,
        scope: String,
        state_fence: StateFence,
        mut descriptors: Vec<InquiryAffordanceDescriptor>,
        status: AffordanceSetStatus,
        mut omissions: Vec<String>,
    ) -> Result<Self, ContractViolation> {
        descriptors.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
        omissions.sort();
        let mut value = Self {
            schema_version: INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION,
            set_id,
            task_id,
            scope,
            state_fence,
            descriptors,
            status,
            omissions,
            digest: String::new(),
        };
        value.validate_shape()?;
        value.digest = value.compute_digest()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.affordance_set.digest")?;
        if self.digest != self.compute_digest()? {
            return binding(
                "probe.affordance_set.digest",
                "digest does not match the affordance set",
            );
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&(
            self.schema_version,
            &self.set_id,
            &self.task_id,
            &self.scope,
            &self.state_fence,
            &self.descriptors,
            self.status,
            &self.omissions,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION {
            return binding(
                "probe.affordance_set.schema_version",
                "unsupported schema version",
            );
        }
        validation::text(self.set_id.as_str(), "probe.affordance_set.set_id")?;
        validation::text(self.task_id.as_str(), "probe.affordance_set.task_id")?;
        validation::text(&self.scope, "probe.affordance_set.scope")?;
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.affordance_set.state_fence",
                reason: error.to_string(),
            })?;
        check_sequence(self.descriptors.len(), "probe.affordance_set.descriptors")?;
        let mut previous_id: Option<&ArtifactId> = None;
        for descriptor in &self.descriptors {
            descriptor.validate()?;
            if previous_id.is_some_and(|prior| prior >= &descriptor.affordance_id) {
                return binding(
                    "probe.affordance_set.descriptors",
                    "descriptor identities must be unique and canonically ordered",
                );
            }
            previous_id = Some(&descriptor.affordance_id);
        }
        if self.omissions.len() > MAX_PROBE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.affordance_set.omissions",
                min: 0,
                max: crate::error::len_i64(MAX_PROBE_ITEMS),
                got: crate::error::len_i64(self.omissions.len()),
            });
        }
        let mut previous_omission: Option<&String> = None;
        for omission in &self.omissions {
            validation::text(omission, "probe.affordance_set.omission")?;
            if previous_omission.is_some_and(|prior| prior >= omission) {
                return binding(
                    "probe.affordance_set.omissions",
                    "omissions must be unique and canonically ordered",
                );
            }
            previous_omission = Some(omission);
        }
        if matches!(self.status, AffordanceSetStatus::Complete) && !self.omissions.is_empty() {
            return binding(
                "probe.affordance_set.status",
                "a complete set cannot retain omissions",
            );
        }
        Ok(())
    }
}

fn validate_owner(owner: &ProbeOwnerRef) -> Result<(), ContractViolation> {
    match owner {
        ProbeOwnerRef::Source { owner } => {
            validation::text(owner.as_str(), "probe.owner.source")
        }
        ProbeOwnerRef::Verifier { verifier_id } => {
            validation::text(verifier_id.as_str(), "probe.owner.verifier")
        }
        ProbeOwnerRef::Unavailable { reason } => {
            validation::text(reason, "probe.owner.reason")
        }
    }
}

fn origin_rank(origin: ProbeObjectiveOrigin) -> u8 {
    match origin {
        ProbeObjectiveOrigin::RivalPredictionDifference => 0,
        ProbeObjectiveOrigin::EvidenceCoverageGap => 1,
        ProbeObjectiveOrigin::FalsifiableLoadBearingAssumption => 2,
        ProbeObjectiveOrigin::SuppliedDiscriminator => 3,
        ProbeObjectiveOrigin::MissingVerifier => 4,
    }
}

fn validate_effect_reversibility(
    effects: ProbeEffectClass,
    reversibility: &ProbeReversibility,
) -> Result<(), ContractViolation> {
    if matches!(
        (effects, reversibility),
        (
            ProbeEffectClass::None | ProbeEffectClass::ReadOnly,
            ProbeReversibility::NotApplicable
        ) | (
            ProbeEffectClass::ReversibleExternal,
            ProbeReversibility::Reversible { .. } | ProbeReversibility::Compensatable { .. }
        ) | (
            ProbeEffectClass::IrreversibleExternal,
            ProbeReversibility::Irreversible { .. }
        ) | (ProbeEffectClass::Unknown, ProbeReversibility::Unknown { .. })
    ) {
        Ok(())
    } else {
        binding(
            "probe.affordance.effect_reversibility",
            "effect class and reversibility declaration differ",
        )
    }
}

fn binding<T>(field: &'static str, reason: &str) -> Result<T, ContractViolation> {
    Err(ContractViolation::BindingMismatch {
        field,
        reason: reason.to_owned(),
    })
}
