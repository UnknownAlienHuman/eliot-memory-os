//! Closed inquiry-affordance descriptors consumed by the bounded probe planner.
//!
//! Cell `smart.dreamer.contracts`. This module owns the contract half of issue
//! #1236: an immutable [`InquiryAffordanceDescriptor`] carrying a closed kind,
//! a digest-pinned target, shared applicability, a typed owner, one finite
//! [`PossibleResultSchema`], and twelve independent planning dimensions, plus
//! the immutable [`InquiryAffordanceSet`] that closes a complete denominator
//! of descriptors with a canonical digest.
//!
//! Descriptors are descriptive only. They never authorize, permit, or carry
//! out any inquiry: effectful or irreversible outcomes stay representable, but
//! no descriptor grants execution authority and no descriptor exposes an
//! execution handle or API. Availability and feasibility stay descriptive;
//! permission, authority, and consent are separate dimensions. Every dimension
//! keeps `Unknown` and `Unavailable` explicit and incomparable: there is no
//! ordering over dimensions, no `Default`, and no positive reading (safe,
//! cheap, feasible, permitted, granted) holds for an unknown dimension.

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::ValidityBounds;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::ContractViolation,
    rival::{ConditionAssumptionRef, MaterialClaimRef, RivalPredictionRef},
};

use super::{
    bounds::check_sequence,
    objective::{ProbeObjectiveRef, ProbeOwnerRef},
    result::PossibleResultSchema,
    validation,
};

/// Wire revision for one inquiry-affordance descriptor.
pub const INQUIRY_AFFORDANCE_SCHEMA_VERSION: u32 = 1;
/// Wire revision for one closed inquiry-affordance set.
pub const INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION: u32 = 1;

/// Descriptive information-gain planning dimension.
///
/// `Unknown`/`Unavailable` are explicit and incomparable: they carry no gain
/// expectation and [`InformationDimension::has_expected_gain`] is false for them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum InformationDimension {
    High { detail: String },
    Moderate { detail: String },
    Low { detail: String },
    NoGain { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl InformationDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::High { detail } | Self::Moderate { detail } | Self::Low { detail } => {
                validation::text(detail, "probe.affordance.information.detail")
            }
            Self::NoGain { reason } | Self::Unknown { reason } | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.information.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration expects an information gain. Unknown dimensions
    /// never read as gainful.
    pub fn has_expected_gain(&self) -> bool {
        matches!(
            self,
            Self::High { .. } | Self::Moderate { .. } | Self::Low { .. }
        )
    }
}

/// Descriptive cost planning dimension.
///
/// `Unknown`/`Unavailable` never read as negligible or cheap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CostDimension {
    Negligible { detail: String },
    Low { detail: String },
    Moderate { detail: String },
    High { detail: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl CostDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Negligible { detail }
            | Self::Low { detail }
            | Self::Moderate { detail }
            | Self::High { detail } => validation::text(detail, "probe.affordance.cost.detail"),
            Self::Unknown { reason } | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.cost.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration is negligible-cost. Unknown cost never reads as
    /// negligible or zero.
    pub fn is_negligible(&self) -> bool {
        matches!(self, Self::Negligible { .. })
    }
}

/// Descriptive latency planning dimension.
///
/// `Unknown`/`Unavailable` never read as immediate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum LatencyDimension {
    Immediate { detail: String },
    Interactive { detail: String },
    Deferred { detail: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl LatencyDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Immediate { detail }
            | Self::Interactive { detail }
            | Self::Deferred { detail } => {
                validation::text(detail, "probe.affordance.latency.detail")
            }
            Self::Unknown { reason } | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.latency.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration is immediate. Unknown latency never reads as
    /// immediate.
    pub fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate { .. })
    }
}

/// Descriptive surrounding-context planning dimension.
///
/// `NotApplicable` is an explicit determination that no surrounding context is
/// needed; it is known but never reads as self-contained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ContextDimension {
    SelfContained { detail: String },
    Narrow { detail: String },
    Broad { detail: String },
    NotApplicable { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl ContextDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::SelfContained { detail } | Self::Narrow { detail } | Self::Broad { detail } => {
                validation::text(detail, "probe.affordance.context.detail")
            }
            Self::NotApplicable { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.context.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration needs no surrounding context.
    pub fn is_self_contained(&self) -> bool {
        matches!(self, Self::SelfContained { .. })
    }
}

/// Descriptive resource planning dimension.
///
/// `NotApplicable` is an explicit determination that no resource beyond the
/// planner is needed; it is known but never reads as trivial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResourceDimension {
    Trivial { detail: String },
    Bounded { detail: String },
    Heavy { detail: String },
    NotApplicable { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl ResourceDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Trivial { detail } | Self::Bounded { detail } | Self::Heavy { detail } => {
                validation::text(detail, "probe.affordance.resource.detail")
            }
            Self::NotApplicable { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.resource.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration needs only trivial resources.
    pub fn is_trivial(&self) -> bool {
        matches!(self, Self::Trivial { .. })
    }
}

/// Descriptive privacy planning dimension.
///
/// `Unknown`/`Unavailable` never read as contained or safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PrivacyDimension {
    Contained { detail: String },
    Elevated { reason: String },
    NotApplicable { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl PrivacyDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Contained { detail } => {
                validation::text(detail, "probe.affordance.privacy.detail")
            }
            Self::Elevated { reason }
            | Self::NotApplicable { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.privacy.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration is privacy-contained. Unknown handling never
    /// reads as contained or safe.
    pub fn is_contained(&self) -> bool {
        matches!(self, Self::Contained { .. })
    }
}

/// Descriptive consent planning dimension.
///
/// Separate from authority and feasibility: a granted consent declaration
/// describes supplied consent state and never permits execution by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ConsentDimension {
    Granted { detail: String },
    RequiresGrant { reason: String },
    Denied { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl ConsentDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Granted { detail } => validation::text(detail, "probe.affordance.consent.detail"),
            Self::RequiresGrant { reason }
            | Self::Denied { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.consent.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether consent is declared granted. Unknown consent never reads as
    /// granted, and a grant never permits execution.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

/// Descriptive authority planning dimension.
///
/// Separate from availability and feasibility: feasible and available never
/// imply permitted, and a permitted declaration describes supplied standing
/// without granting execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AuthorityDimension {
    Permitted { detail: String },
    RequiresApproval { reason: String },
    Denied { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl AuthorityDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Permitted { detail } => {
                validation::text(detail, "probe.affordance.authority.detail")
            }
            Self::RequiresApproval { reason }
            | Self::Denied { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.authority.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether standing is declared permitted. Unknown standing never reads as
    /// permitted or authorized, and permission never grants execution.
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted { .. })
    }
}

/// Descriptive effect planning dimension.
///
/// Effectful outcomes stay representable but never grant execution authority:
/// there is no execution handle or API anywhere in this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum EffectDimension {
    SideEffectFree { detail: String },
    ObservableOnly { detail: String },
    StateChanging { detail: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl EffectDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::SideEffectFree { detail }
            | Self::ObservableOnly { detail }
            | Self::StateChanging { detail } => {
                validation::text(detail, "probe.affordance.effect.detail")
            }
            Self::Unknown { reason } | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.effect.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration is side-effect free. Unknown effect never reads
    /// as side-effect free.
    pub fn is_side_effect_free(&self) -> bool {
        matches!(self, Self::SideEffectFree { .. })
    }
}

/// Descriptive reversibility planning dimension.
///
/// Irreversible outcomes stay representable but never grant execution
/// authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ReversibilityDimension {
    Reversible { detail: String },
    Irreversible { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl ReversibilityDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Reversible { detail } => {
                validation::text(detail, "probe.affordance.reversibility.detail")
            }
            Self::Irreversible { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.reversibility.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration is reversible. Unknown reversibility never
    /// reads as reversible.
    pub fn is_reversible(&self) -> bool {
        matches!(self, Self::Reversible { .. })
    }
}

/// Descriptive feasibility planning dimension.
///
/// Separate from permission: feasible never implies permitted, and unknown
/// feasibility never reads as feasible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum FeasibilityDimension {
    Feasible { detail: String },
    Infeasible { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl FeasibilityDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Feasible { detail } => {
                validation::text(detail, "probe.affordance.feasibility.detail")
            }
            Self::Infeasible { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.feasibility.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration is feasible. Unknown feasibility never reads as
    /// feasible, and feasibility never implies permission.
    pub fn is_feasible(&self) -> bool {
        matches!(self, Self::Feasible { .. })
    }
}

/// Descriptive Human-attention planning dimension.
///
/// `NotApplicable` is an explicit determination that no Human attention
/// applies; it is known but never reads as needing a Human.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HumanAttentionDimension {
    Unneeded { detail: String },
    Brief { detail: String },
    Sustained { detail: String },
    NotApplicable { reason: String },
    Unknown { reason: String },
    Unavailable { reason: String },
}

impl HumanAttentionDimension {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Unneeded { detail } | Self::Brief { detail } | Self::Sustained { detail } => {
                validation::text(detail, "probe.affordance.attention.detail")
            }
            Self::NotApplicable { reason }
            | Self::Unknown { reason }
            | Self::Unavailable { reason } => {
                validation::text(reason, "probe.affordance.attention.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. } | Self::Unavailable { .. })
    }

    /// Whether the declaration needs Human attention. Unknown attention needs
    /// never read as unneeded or as dominant.
    pub fn needs_human(&self) -> bool {
        matches!(self, Self::Brief { .. } | Self::Sustained { .. })
    }
}

/// Closed inquiry channel label. Labels are descriptive only: they select no
/// transport, open no channel, and grant no execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AffordanceKind {
    EvidenceInspection,
    RecordLookup,
    ConsistencyCheck,
    HumanConsultation,
    CrossReference,
}

/// Digest-pinned inquiry target with exact source identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AffordanceTarget {
    RivalPredictions {
        left: RivalPredictionRef,
        right: RivalPredictionRef,
    },
    EvidenceGap {
        claim: MaterialClaimRef,
    },
    Assumption {
        assumption: ConditionAssumptionRef,
        claim: Option<MaterialClaimRef>,
    },
    Objective {
        objective: ProbeObjectiveRef,
    },
}

impl AffordanceTarget {
    /// Validates digest-pinned target identity without resolving payloads.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::RivalPredictions { left, right } => {
                left.validate()?;
                right.validate()?;
                if left.prediction_id == right.prediction_id {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe.affordance.target.rival_predictions",
                        reason: "rival prediction endpoints must be distinct".to_owned(),
                    });
                }
            }
            Self::EvidenceGap { claim } => {
                claim.validate()?;
            }
            Self::Assumption { assumption, claim } => {
                assumption.validate()?;
                if let Some(claim) = claim {
                    claim.validate()?;
                }
            }
            Self::Objective { objective } => {
                objective.validate()?;
            }
        }
        Ok(())
    }
}

fn validate_owner(owner: &ProbeOwnerRef) -> Result<(), ContractViolation> {
    match owner {
        ProbeOwnerRef::Source { owner } => {
            validation::text(owner.as_str(), "probe.affordance.owner.source")
        }
        ProbeOwnerRef::Verifier { verifier_id } => {
            validation::text(verifier_id.as_str(), "probe.affordance.owner.verifier")
        }
        ProbeOwnerRef::Unavailable { reason } => {
            validation::text(reason, "probe.affordance.owner.reason")
        }
    }
}

/// One closed immutable inquiry-affordance descriptor.
///
/// Binds a closed kind, a digest-pinned target, shared applicability, a typed
/// owner (never an authority claim), one finite [`PossibleResultSchema`], and
/// the twelve independent planning dimensions, with a frozen canonical digest.
/// Descriptors carry no execution API: an effectful or irreversible descriptor
/// describes a possible inquiry without permitting it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryAffordanceDescriptor {
    /// Wire revision; always [`INQUIRY_AFFORDANCE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable identity of this descriptor within its set.
    pub affordance_id: ArtifactId,
    /// Closed descriptive channel label.
    pub kind: AffordanceKind,
    /// Digest-pinned inquiry target.
    pub target: AffordanceTarget,
    /// Shared applicability shared by the descriptor.
    pub applicability: ValidityBounds,
    /// Typed owner reference; never an authority claim.
    pub owner: ProbeOwnerRef,
    /// Finite possible-result schema with exact branch cover.
    pub result_schema: PossibleResultSchema,
    /// Descriptive information-gain dimension.
    pub information: InformationDimension,
    /// Descriptive cost dimension.
    pub cost: CostDimension,
    /// Descriptive latency dimension.
    pub latency: LatencyDimension,
    /// Descriptive surrounding-context dimension.
    pub context: ContextDimension,
    /// Descriptive resource dimension.
    pub resource: ResourceDimension,
    /// Descriptive privacy dimension.
    pub privacy: PrivacyDimension,
    /// Descriptive consent dimension, separate from authority.
    pub consent: ConsentDimension,
    /// Descriptive authority dimension, separate from availability.
    pub authority: AuthorityDimension,
    /// Descriptive effect dimension; never grants execution.
    pub effect: EffectDimension,
    /// Descriptive reversibility dimension.
    pub reversibility: ReversibilityDimension,
    /// Descriptive feasibility dimension, separate from permission.
    pub feasibility: FeasibilityDimension,
    /// Descriptive Human-attention dimension.
    pub attention: HumanAttentionDimension,
    /// Frozen canonical digest of the preimage above, excluding itself.
    pub digest: String,
}

/// Constructor data for [`InquiryAffordanceDescriptor`]; `schema_version` and
/// `digest` are assigned by [`InquiryAffordanceDescriptor::new`].
#[derive(Clone, Debug)]
pub struct InquiryAffordanceDescriptorParams {
    /// Stable identity of this descriptor within its set.
    pub affordance_id: ArtifactId,
    /// Closed descriptive channel label.
    pub kind: AffordanceKind,
    /// Digest-pinned inquiry target.
    pub target: AffordanceTarget,
    /// Shared applicability shared by the descriptor.
    pub applicability: ValidityBounds,
    /// Typed owner reference; never an authority claim.
    pub owner: ProbeOwnerRef,
    /// Finite possible-result schema with exact branch cover.
    pub result_schema: PossibleResultSchema,
    /// Descriptive information-gain dimension.
    pub information: InformationDimension,
    /// Descriptive cost dimension.
    pub cost: CostDimension,
    /// Descriptive latency dimension.
    pub latency: LatencyDimension,
    /// Descriptive surrounding-context dimension.
    pub context: ContextDimension,
    /// Descriptive resource dimension.
    pub resource: ResourceDimension,
    /// Descriptive privacy dimension.
    pub privacy: PrivacyDimension,
    /// Descriptive consent dimension, separate from authority.
    pub consent: ConsentDimension,
    /// Descriptive authority dimension, separate from availability.
    pub authority: AuthorityDimension,
    /// Descriptive effect dimension; never grants execution.
    pub effect: EffectDimension,
    /// Descriptive reversibility dimension.
    pub reversibility: ReversibilityDimension,
    /// Descriptive feasibility dimension, separate from permission.
    pub feasibility: FeasibilityDimension,
    /// Descriptive Human-attention dimension.
    pub attention: HumanAttentionDimension,
}

impl InquiryAffordanceDescriptor {
    /// Constructs a canonical descriptor with a frozen digest.
    pub fn new(params: InquiryAffordanceDescriptorParams) -> Result<Self, ContractViolation> {
        let mut descriptor = Self {
            schema_version: INQUIRY_AFFORDANCE_SCHEMA_VERSION,
            affordance_id: params.affordance_id,
            kind: params.kind,
            target: params.target,
            applicability: params.applicability,
            owner: params.owner,
            result_schema: params.result_schema,
            information: params.information,
            cost: params.cost,
            latency: params.latency,
            context: params.context,
            resource: params.resource,
            privacy: params.privacy,
            consent: params.consent,
            authority: params.authority,
            effect: params.effect,
            reversibility: params.reversibility,
            feasibility: params.feasibility,
            attention: params.attention,
            digest: String::new(),
        };
        validation::preflight(&descriptor)?;
        descriptor.validate_shape()?;
        descriptor.digest = descriptor.compute_digest_unchecked()?;
        validation::preflight(&descriptor)?;
        Ok(descriptor)
    }

    /// Validates the descriptor shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.affordance.digest")?;
        let expected = self.compute_digest_unchecked()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance.digest",
                reason: "affordance digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest after validating the descriptor shape.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            affordance_id: &'a ArtifactId,
            kind: AffordanceKind,
            target: &'a AffordanceTarget,
            applicability: &'a ValidityBounds,
            owner: &'a ProbeOwnerRef,
            result_schema: &'a PossibleResultSchema,
            information: &'a InformationDimension,
            cost: &'a CostDimension,
            latency: &'a LatencyDimension,
            context: &'a ContextDimension,
            resource: &'a ResourceDimension,
            privacy: &'a PrivacyDimension,
            consent: &'a ConsentDimension,
            authority: &'a AuthorityDimension,
            effect: &'a EffectDimension,
            reversibility: &'a ReversibilityDimension,
            feasibility: &'a FeasibilityDimension,
            attention: &'a HumanAttentionDimension,
        }
        validation::canonical_digest(&Preimage {
            schema_version: self.schema_version,
            affordance_id: &self.affordance_id,
            kind: self.kind,
            target: &self.target,
            applicability: &self.applicability,
            owner: &self.owner,
            result_schema: &self.result_schema,
            information: &self.information,
            cost: &self.cost,
            latency: &self.latency,
            context: &self.context,
            resource: &self.resource,
            privacy: &self.privacy,
            consent: &self.consent,
            authority: &self.authority,
            effect: &self.effect,
            reversibility: &self.reversibility,
            feasibility: &self.feasibility,
            attention: &self.attention,
        })
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != INQUIRY_AFFORDANCE_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance.schema_version",
                reason: "unsupported affordance schema".to_owned(),
            });
        }
        validation::text(
            self.affordance_id.as_str(),
            "probe.affordance.affordance_id",
        )?;
        self.target.validate()?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.affordance.applicability",
                reason: error.to_string(),
            })?;
        validate_owner(&self.owner)?;
        self.result_schema.validate()?;
        self.information.validate()?;
        self.cost.validate()?;
        self.latency.validate()?;
        self.context.validate()?;
        self.resource.validate()?;
        self.privacy.validate()?;
        self.consent.validate()?;
        self.authority.validate()?;
        self.effect.validate()?;
        self.reversibility.validate()?;
        self.feasibility.validate()?;
        self.attention.validate()?;
        Ok(())
    }
}

/// Closed immutable set of inquiry-affordance descriptors.
///
/// Descriptors form a true set: construction sorts them by `affordance_id`,
/// so set-only permutations preserve the digest. The embedded
/// [`PossibleResultSchema`] branch order stays semantic: reordering branches
/// changes the schema digest and therefore the descriptor and set digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InquiryAffordanceSet {
    /// Wire revision; always [`INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable identity of this set.
    pub set_id: ArtifactId,
    /// Task identity copied exactly from the bound input.
    pub task_id: TaskId,
    /// Scope copied exactly from the bound input.
    pub scope: String,
    /// State fence copied exactly from the bound input.
    pub state_fence: StateFence,
    /// Closed descriptors in canonical `affordance_id` order.
    pub descriptors: Vec<InquiryAffordanceDescriptor>,
    /// Frozen canonical digest of the preimage above, excluding itself.
    pub digest: String,
}

/// Constructor data for [`InquiryAffordanceSet`]; `schema_version` and
/// `digest` are assigned by [`InquiryAffordanceSet::new`].
#[derive(Clone, Debug)]
pub struct InquiryAffordanceSetParams {
    /// Stable identity of this set.
    pub set_id: ArtifactId,
    /// Task identity copied exactly from the bound input.
    pub task_id: TaskId,
    /// Scope copied exactly from the bound input.
    pub scope: String,
    /// State fence copied exactly from the bound input.
    pub state_fence: StateFence,
    /// Closed descriptors; canonicalized by construction.
    pub descriptors: Vec<InquiryAffordanceDescriptor>,
}

impl InquiryAffordanceSet {
    /// Constructs a canonical set, sorting descriptors by `affordance_id`.
    pub fn new(params: InquiryAffordanceSetParams) -> Result<Self, ContractViolation> {
        let mut set = Self {
            schema_version: INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION,
            set_id: params.set_id,
            task_id: params.task_id,
            scope: params.scope,
            state_fence: params.state_fence,
            descriptors: params.descriptors,
            digest: String::new(),
        };
        validation::preflight(&set)?;
        set.validate_shape(false)?;
        set.descriptors
            .sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
        validation::preflight(&set)?;
        set.validate_shape(true)?;
        set.digest = set.compute_digest_unchecked()?;
        validation::preflight(&set)?;
        Ok(set)
    }

    /// Validates identity, descriptors, canonical order, and the frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape(true)?;
        validation::digest(&self.digest, "probe.affordance_set.digest")?;
        let expected = self.compute_digest_unchecked()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance_set.digest",
                reason: "affordance set digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest after validating the set content.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape(true)?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&(
            self.schema_version,
            &self.set_id,
            &self.task_id,
            &self.scope,
            &self.state_fence,
            &self.descriptors,
        ))
    }

    fn validate_shape(&self, require_canonical_order: bool) -> Result<(), ContractViolation> {
        if self.schema_version != INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.affordance_set.schema_version",
                reason: "unsupported affordance set schema".to_owned(),
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
        check_sequence(self.descriptors.len(), "probe.affordance_set.descriptors")?;
        for descriptor in &self.descriptors {
            descriptor.validate()?;
        }
        if require_canonical_order {
            check_descriptor_table(&self.descriptors)?;
        }
        Ok(())
    }
}

fn check_descriptor_table(
    entries: &[InquiryAffordanceDescriptor],
) -> Result<(), ContractViolation> {
    for pair in entries.windows(2) {
        match pair[0].affordance_id.cmp(&pair[1].affordance_id) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                if pair[0] == pair[1] {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe.affordance_set.descriptors",
                        reason: "duplicate affordance descriptor".to_owned(),
                    });
                }
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.affordance_set.descriptors",
                    reason: "one affordance identity maps to changed meaning".to_owned(),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.affordance_set.descriptors",
                    reason: "table is not in canonical affordance identity order".to_owned(),
                });
            }
        }
    }
    Ok(())
}
