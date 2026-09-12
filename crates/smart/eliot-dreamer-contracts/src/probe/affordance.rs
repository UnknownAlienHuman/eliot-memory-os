//! Owner-neutral inquiry affordance declarations consumed by the pure probe planner.
//!
//! These records describe what an external owner could make available. They do
//! not reserve capacity, authorize an effect, execute a provider, or attest that
//! the declared result schema will be observed.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::ValidityBounds;
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
/// Wire revision for one complete affordance-set carrier.
pub const INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION: u32 = 1;

/// One bounded quantitative planning dimension.
///
/// Units are dimension-owned and compared only with the same field. `Unknown`
/// is never interpreted as zero, free, immediate, or safe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeEstimate {
    /// Exact non-negative owner-supplied quantity.
    Known { units: u64 },
    /// The quantity is relevant but unavailable.
    Unknown { reason: String },
    /// The quantity does not apply to this affordance.
    NotApplicable { reason: String },
}

impl ProbeEstimate {
    /// Validates the closed estimate without interpreting its units.
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        match self {
            Self::Known { .. } => Ok(()),
            Self::Unknown { reason } | Self::NotApplicable { reason } => {
                validation::text(reason, field)
            }
        }
    }

    /// Returns the exact quantity only when the owner supplied one.
    pub fn known_units(&self) -> Option<u64> {
        match self {
            Self::Known { units } => Some(*units),
            Self::Unknown { .. } | Self::NotApplicable { .. } => None,
        }
    }
}

/// Independent permission or protection state for one affordance dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeRequirementState {
    /// No external grant is required for this exact dimension.
    NotRequired,
    /// An external owner supplied an immutable evidence handle.
    Satisfied { evidence: ArtifactId },
    /// The dimension requires an external decision that has not been supplied.
    Required { owner: ProbeOwnerRef, reason: String },
    /// Required state could not be established.
    Unknown { reason: String },
    /// The owner explicitly refused or invalidated this dimension.
    Failed { reason: String },
}

impl ProbeRequirementState {
    /// Validates shape only; it does not authenticate the evidence owner.
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        match self {
            Self::NotRequired => Ok(()),
            Self::Satisfied { evidence } => validation::text(evidence.as_str(), field),
            Self::Required { owner, reason } => {
                owner.validate()?;
                validation::text(reason, field)
            }
            Self::Unknown { reason } | Self::Failed { reason } => {
                validation::text(reason, field)
            }
        }
    }

    /// Whether the exact requirement is already satisfied for planning.
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::NotRequired | Self::Satisfied { .. })
    }
}

/// External-effect ceiling declared by an affordance owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeEffectClass {
    None,
    ReadOnly,
    ReversibleExternal,
    IrreversibleExternal,
    Unknown,
}

/// Reversibility of the described effect. This is not a rollback receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// Descriptive availability of the affordance. It carries no permission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// One immutable inquiry affordance. It is descriptive and inert.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InquiryAffordanceDescriptor {
    pub schema_version: u32,
    pub affordance_id: ArtifactId,
    pub revision: u64,
    /// Canonically ordered objective origins this affordance can address.
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
    /// Constructs and canonically seals one affordance descriptor.
    #[allow(clippy::too_many_arguments, reason = "constructor mirrors independent planning dimensions")]
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
        let mut descriptor = Self {
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
        descriptor.validate_shape()?;
        descriptor.digest = descriptor.compute_digest()?;
        Ok(descriptor)
    }

    /// Validates shape, internal consistency, and canonical digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.affordance.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance.digest",
                reason: "affordance digest does not match its declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest excluding the digest field itself.
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
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance.schema_version",
                reason: "unsupported affordance schema".to_owned(),
            });
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
        let mut previous = None;
        for origin in &self.objective_origins {
            let rank = origin_rank(*origin);
            if previous.is_some_and(|prior| prior >= rank) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.affordance.objective_origins",
                    reason: "origins must be unique and canonically ordered".to_owned(),
                });
            }
            previous = Some(rank);
        }
        self.owner.validate()?;
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
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.affordance.invalidation_conditions",
                    reason: "duplicate assumption identity".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Completeness of the externally supplied affordance denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AffordanceSetStatus {
    Complete,
    Partial,
    Unknown,
}

/// Exact immutable set supplied to the probe planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    /// Constructs a canonically ordered set. Descriptor order is by stable ID.
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
        let mut set = Self {
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
        set.validate_shape()?;
        set.digest = set.compute_digest()?;
        Ok(set)
    }

    /// Validates the complete set and canonical digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.affordance_set.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance_set.digest",
                reason: "affordance-set digest does not match its declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest excluding the digest field.
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
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance_set.schema_version",
                reason: "unsupported affordance-set schema".to_owned(),
            });
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
        check_sequence(
            self.descriptors.len(),
            "probe.affordance_set.descriptors",
        )?;
        let mut previous = None;
        for descriptor in &self.descriptors {
            descriptor.validate()?;
            if previous.as_ref().is_some_and(|prior| prior >= &descriptor.affordance_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.affordance_set.descriptors",
                    reason: "descriptor identities must be unique and canonically ordered".to_owned(),
                });
            }
            previous = Some(descriptor.affordance_id.clone());
        }
        if self.omissions.len() > MAX_PROBE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.affordance_set.omissions",
                min: 0,
                max: crate::error::len_i64(MAX_PROBE_ITEMS),
                got: crate::error::len_i64(self.omissions.len()),
            });
        }
        let mut prior = None;
        for omission in &self.omissions {
            validation::text(omission, "probe.affordance_set.omission")?;
            if prior.as_ref().is_some_and(|value| value >= omission) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.affordance_set.omissions",
                    reason: "omissions must be unique and canonically ordered".to_owned(),
                });
            }
            prior = Some(omission.clone());
        }
        if matches!(self.status, AffordanceSetStatus::Complete) && !self.omissions.is_empty() {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance_set.status",
                reason: "a complete set cannot retain omissions".to_owned(),
            });
        }
        Ok(())
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
    let valid = matches!(
        (effects, reversibility),
        (ProbeEffectClass::None | ProbeEffectClass::ReadOnly, ProbeReversibility::NotApplicable)
            | (ProbeEffectClass::ReversibleExternal, ProbeReversibility::Reversible { .. })
            | (ProbeEffectClass::ReversibleExternal, ProbeReversibility::Compensatable { .. })
            | (ProbeEffectClass::IrreversibleExternal, ProbeReversibility::Irreversible { .. })
            | (ProbeEffectClass::Unknown, ProbeReversibility::Unknown { .. })
    );
    if valid {
        Ok(())
    } else {
        Err(ContractViolation::BindingMismatch {
            field: "probe.affordance.effect_reversibility",
            reason: "effect class and reversibility declaration differ".to_owned(),
        })
    }
}
