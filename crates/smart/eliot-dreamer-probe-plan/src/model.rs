//! Closed probe-plan vocabulary: targets, dimension vectors, proposals,
//! omissions, and the frozen [`ProbePlan`].
//!
//! Every probe names the disagreement or unknown it discriminates through a
//! [`ProbeTarget`] projected 1:1 from its source [`AffordanceTarget`]. Ranking
//! is vector-preserving: each probe and omission carries the full twelve
//! planning dimensions verbatim, and ordering is a lexicographic per-dimension
//! rank with no scalar score, so no cost, risk, or authority failure is ever
//! hidden inside one number.

use std::collections::BTreeSet;

use eliot_dreamer_contracts::{
    AffordanceKind, AffordanceTarget, AuthorityDimension, BudgetLimits, ConditionAssumptionRef,
    ConsentDimension, ContextDimension, ContractViolation, CostDimension, DreamInputBundle,
    EffectDimension, FeasibilityDimension, HumanAttentionDimension, InformationDimension,
    InquiryAffordanceSet, LatencyDimension, MaterialClaimRef, PossibleResultSchema,
    PrivacyDimension, ProbeAffordanceRef, ProbeObjectiveRef, ResourceDimension,
    ReversibilityDimension, RivalModelSet, RivalPredictionRef, ValidatedDreamDraft,
    error::len_i64,
    grounding::canonical::{ArtifactId, StateFence, TaskId},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bounds::{self, PROBE_PLAN_SCHEMA_VERSION, preflight};

/// Closed per-probe target naming the disagreement or unknown it
/// discriminates, projected 1:1 from [`AffordanceTarget`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeTarget {
    /// Two rival predictions whose observable declarations disagree.
    RivalDisagreement {
        left: RivalPredictionRef,
        right: RivalPredictionRef,
    },
    /// An evidence gap for one material claim.
    EvidenceUnknown { claim: MaterialClaimRef },
    /// An unresolved assumption, optionally tied to one claim.
    AssumptionUnknown {
        assumption: ConditionAssumptionRef,
        claim: Option<MaterialClaimRef>,
    },
    /// An unresolved probe objective.
    ObjectiveUnknown { objective: ProbeObjectiveRef },
}

impl ProbeTarget {
    /// Projects an affordance target into plan vocabulary without resolving it.
    pub(crate) fn from_affordance(target: &AffordanceTarget) -> Self {
        match target {
            AffordanceTarget::RivalPredictions { left, right } => Self::RivalDisagreement {
                left: left.clone(),
                right: right.clone(),
            },
            AffordanceTarget::EvidenceGap { claim } => Self::EvidenceUnknown {
                claim: claim.clone(),
            },
            AffordanceTarget::Assumption { assumption, claim } => Self::AssumptionUnknown {
                assumption: assumption.clone(),
                claim: claim.clone(),
            },
            AffordanceTarget::Objective { objective } => Self::ObjectiveUnknown {
                objective: objective.clone(),
            },
        }
    }

    /// Validates the named target identity without resolving payloads.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight(self)?;
        match self {
            Self::RivalDisagreement { left, right } => {
                left.validate()?;
                right.validate()?;
                if left.prediction_id == right.prediction_id {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe_plan.target.rival_disagreement",
                        reason: "rival prediction endpoints must be distinct".to_owned(),
                    });
                }
            }
            Self::EvidenceUnknown { claim } => {
                claim.validate()?;
            }
            Self::AssumptionUnknown { assumption, claim } => {
                assumption.validate()?;
                if let Some(claim) = claim {
                    claim.validate()?;
                }
            }
            Self::ObjectiveUnknown { objective } => {
                objective.validate()?;
            }
        }
        Ok(())
    }

    /// Derives the bounded discrimination statement from real target identity.
    pub(crate) fn discrimination(&self) -> String {
        match self {
            Self::RivalDisagreement { left, right } => format!(
                "discriminate rival predictions {} vs {}",
                left.prediction_id.as_str(),
                right.prediction_id.as_str()
            ),
            Self::EvidenceUnknown { claim } => {
                format!("resolve evidence gap for claim {}", claim.claim_id)
            }
            Self::AssumptionUnknown { assumption, claim } => match claim {
                Some(claim) => format!(
                    "test assumption {} for claim {}",
                    assumption.assumption_id, claim.claim_id
                ),
                None => format!("test assumption {}", assumption.assumption_id),
            },
            Self::ObjectiveUnknown { objective } => {
                format!(
                    "address probe objective {}",
                    objective.objective_id.as_str()
                )
            }
        }
    }
}

/// The preserved twelve-dimension planning vector.
///
/// Every dimension keeps its `Unknown` and `Unavailable` spellings explicit:
/// there is no ordering across dimensions and no cross-dimension score.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeDimensions {
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

impl ProbeDimensions {
    /// Validates every preserved dimension declaration.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight(self)?;
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

    /// Lexicographic per-dimension rank: information first, then cost,
    /// latency, resource, attention, effect, reversibility, privacy, context,
    /// and consent. Unknown and unavailable sort after every known
    /// determination inside their own dimension only; ranks never combine
    /// into a scalar.
    pub(crate) fn order_key(&self) -> [u8; 10] {
        [
            match &self.information {
                InformationDimension::High { .. } => 0,
                InformationDimension::Moderate { .. } => 1,
                InformationDimension::Low { .. } => 2,
                InformationDimension::Unknown { .. }
                | InformationDimension::NoGain { .. }
                | InformationDimension::Unavailable { .. } => 3,
            },
            match &self.cost {
                CostDimension::Negligible { .. } => 0,
                CostDimension::Low { .. } => 1,
                CostDimension::Moderate { .. } => 2,
                CostDimension::High { .. } => 3,
                CostDimension::Unknown { .. } | CostDimension::Unavailable { .. } => 4,
            },
            match &self.latency {
                LatencyDimension::Immediate { .. } => 0,
                LatencyDimension::Interactive { .. } => 1,
                LatencyDimension::Deferred { .. } => 2,
                LatencyDimension::Unknown { .. } | LatencyDimension::Unavailable { .. } => 3,
            },
            match &self.resource {
                ResourceDimension::Trivial { .. } => 0,
                ResourceDimension::NotApplicable { .. } => 1,
                ResourceDimension::Bounded { .. } => 2,
                ResourceDimension::Heavy { .. } => 3,
                ResourceDimension::Unknown { .. } | ResourceDimension::Unavailable { .. } => 4,
            },
            match &self.attention {
                HumanAttentionDimension::Unneeded { .. } => 0,
                HumanAttentionDimension::NotApplicable { .. } => 1,
                HumanAttentionDimension::Brief { .. } => 2,
                HumanAttentionDimension::Sustained { .. } => 3,
                HumanAttentionDimension::Unknown { .. }
                | HumanAttentionDimension::Unavailable { .. } => 4,
            },
            match &self.effect {
                EffectDimension::SideEffectFree { .. } => 0,
                EffectDimension::ObservableOnly { .. } => 1,
                EffectDimension::StateChanging { .. } => 2,
                EffectDimension::Unknown { .. } | EffectDimension::Unavailable { .. } => 3,
            },
            match &self.reversibility {
                ReversibilityDimension::Reversible { .. } => 0,
                ReversibilityDimension::Irreversible { .. } => 1,
                ReversibilityDimension::Unknown { .. }
                | ReversibilityDimension::Unavailable { .. } => 2,
            },
            match &self.privacy {
                PrivacyDimension::Contained { .. } => 0,
                PrivacyDimension::NotApplicable { .. } => 1,
                PrivacyDimension::Elevated { .. } => 2,
                PrivacyDimension::Unknown { .. } | PrivacyDimension::Unavailable { .. } => 3,
            },
            match &self.context {
                ContextDimension::SelfContained { .. } => 0,
                ContextDimension::Narrow { .. } => 1,
                ContextDimension::Broad { .. } => 2,
                ContextDimension::NotApplicable { .. } => 3,
                ContextDimension::Unknown { .. } | ContextDimension::Unavailable { .. } => 4,
            },
            match &self.consent {
                ConsentDimension::Granted { .. } => 0,
                ConsentDimension::RequiresGrant { .. } => 1,
                ConsentDimension::Denied { .. } => 2,
                ConsentDimension::Unknown { .. } | ConsentDimension::Unavailable { .. } => 3,
            },
        ]
    }
}

/// One ranked candidate probe proposal.
///
/// Candidate-only: the proposal carries no execution handle, reserves no
/// route or budget, and grants no authority. Cost, risk, and authority state
/// stay visible inside [`ProbeDimensions`]; [`ProbeProposal::rank`] records
/// the lexicographic plan position and nothing else.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeProposal {
    /// Plan-scoped probe identity, always the primary affordance identity.
    pub probe_id: ArtifactId,
    /// Zero-based position in plan order; must equal the vector index.
    pub rank: u32,
    /// Closed descriptive channel label copied from the descriptor.
    pub kind: AffordanceKind,
    /// The disagreement or unknown this probe discriminates.
    pub target: ProbeTarget,
    /// Binding to the primary source descriptor.
    pub affordance: ProbeAffordanceRef,
    /// Collapsed duplicate affordance identities, excluding the primary.
    pub merged_affordances: BTreeSet<ArtifactId>,
    /// Bounded discrimination statement derived from target identity.
    pub expected_discrimination: String,
    /// Finite possible-result schema with exact branch cover.
    pub result_schema: PossibleResultSchema,
    /// Preserved planning dimensions, never scalar-hidden.
    pub dimensions: ProbeDimensions,
}

impl ProbeProposal {
    /// Validates the proposal shape without re-running planning.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight(self)?;
        bounds::text(self.probe_id.as_str(), "probe_plan.probe.probe_id")?;
        self.target.validate()?;
        self.affordance.validate()?;
        if self.probe_id != self.affordance.affordance_id {
            return Err(ContractViolation::BindingMismatch {
                field: "probe_plan.probe.probe_id",
                reason: "probe identity must equal its primary affordance identity".to_owned(),
            });
        }
        bounds::sequence(
            self.merged_affordances.len(),
            "probe_plan.probe.merged_affordances",
        )?;
        for merged in &self.merged_affordances {
            bounds::text(merged.as_str(), "probe_plan.probe.merged_affordance")?;
            if *merged == self.probe_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe_plan.probe.merged_affordances",
                    reason: "merged identity must differ from the primary identity".to_owned(),
                });
            }
        }
        bounds::text(
            &self.expected_discrimination,
            "probe_plan.probe.expected_discrimination",
        )?;
        self.result_schema.validate()?;
        self.dimensions.validate()?;
        Ok(())
    }
}

/// Total plan order key for one probe: the preserved-dimension rank with the
/// probe identity as the final tiebreak.
pub(crate) fn probe_order_key(probe: &ProbeProposal) -> ([u8; 10], &str) {
    (probe.dimensions.order_key(), probe.probe_id.as_str())
}

/// Closed omission class: every gap is explicit and carries no fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OmissionKind {
    /// No feasible or discriminative inquiry exists for the target.
    Unprobeable,
    /// A ranked proposal does not fit the admitted candidate bound.
    OverBudget,
    /// Standing is not permitted or consent is denied for the target.
    AuthorityBlocked,
}

impl OmissionKind {
    /// Canonical gap order rank: unprobeable first, then over-budget, then
    /// authority-blocked. The rank orders gaps only; it never outranks a probe.
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Unprobeable => 0,
            Self::OverBudget => 1,
            Self::AuthorityBlocked => 2,
        }
    }
}

/// One explicit gap: the named target, its source binding, the closed reason,
/// and the preserved dimensions. Omissions propose nothing and launch no
/// fallback action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeOmission {
    /// Closed gap class.
    pub kind: OmissionKind,
    /// The disagreement or unknown left without a probe.
    pub target: ProbeTarget,
    /// Binding to the primary source descriptor.
    pub affordance: ProbeAffordanceRef,
    /// Collapsed duplicate affordance identities, excluding the primary.
    pub merged_affordances: BTreeSet<ArtifactId>,
    /// Bounded reason citing the blocking dimension or bound.
    pub reason: String,
    /// Preserved planning dimensions, never scalar-hidden.
    pub dimensions: ProbeDimensions,
}

impl ProbeOmission {
    /// Validates the omission shape without re-running planning.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight(self)?;
        self.target.validate()?;
        self.affordance.validate()?;
        bounds::sequence(
            self.merged_affordances.len(),
            "probe_plan.omission.merged_affordances",
        )?;
        for merged in &self.merged_affordances {
            bounds::text(merged.as_str(), "probe_plan.omission.merged_affordance")?;
            if *merged == self.affordance.affordance_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe_plan.omission.merged_affordances",
                    reason: "merged identity must differ from the primary identity".to_owned(),
                });
            }
        }
        bounds::text(&self.reason, "probe_plan.omission.reason")?;
        self.dimensions.validate()?;
        Ok(())
    }
}

/// Total canonical gap order key: gap class rank, then affordance identity.
pub(crate) fn omission_order_key(omission: &ProbeOmission) -> (u8, &str) {
    (
        omission.kind.rank(),
        omission.affordance.affordance_id.as_str(),
    )
}

/// Constructor data for [`ProbePlan`]; `schema_version` and `digest` are
/// assigned by [`ProbePlan::new`], which runs the bounded planner.
#[derive(Clone, Debug)]
pub struct ProbePlanParams<'a> {
    /// Plan-scoped stable identity supplied by the calling owner.
    pub plan_id: ArtifactId,
    /// Grounded input bundle the plan is bound to.
    pub bundle: &'a DreamInputBundle,
    /// Validator-bound draft the plan is bound to.
    pub draft: &'a ValidatedDreamDraft,
    /// Rival-model projection the plan discriminates.
    pub rivals: &'a RivalModelSet,
    /// Closed inquiry-affordance denominator the plan selects from.
    pub affordances: &'a InquiryAffordanceSet,
    /// Independent per-dimension budget limits bounding admission.
    pub limits: &'a BudgetLimits,
}

/// Bounded immutable discriminative probe plan with a frozen canonical digest.
///
/// `probes` are ranked candidate-only proposals in total plan order;
/// `omissions` are the explicit unprobeable, over-budget, and
/// authority-blocked gaps. Construction sorts both tables canonically, so
/// set-only input permutations preserve the digest while any content change
/// alters it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbePlan {
    /// Wire revision; always [`PROBE_PLAN_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Plan-scoped stable identity.
    pub plan_id: ArtifactId,
    /// Task identity copied exactly from every bound input.
    pub task_id: TaskId,
    /// Scope copied exactly from every bound input.
    pub scope: String,
    /// State fence copied exactly from every bound input.
    pub state_fence: StateFence,
    /// Lineage digest of the bound validated draft.
    pub draft_digest: String,
    /// Frozen canonical digest of the bound rival projection.
    pub rival_digest: String,
    /// Frozen canonical digest of the bound affordance set.
    pub affordance_digest: String,
    /// Digest of the frozen source manifest.
    pub manifest_digest: String,
    /// Ranked candidate probes in total plan order.
    pub probes: Vec<ProbeProposal>,
    /// Explicit gaps in canonical gap order.
    pub omissions: Vec<ProbeOmission>,
    /// Frozen canonical digest of the preimage above, excluding itself.
    pub digest: String,
}

impl ProbePlan {
    /// Runs the bounded discriminative planner and freezes the plan digest.
    ///
    /// Validates every input, requires exact task, scope, and fence agreement
    /// across all bound inputs, classifies each descriptor, collapses
    /// duplicate probes, ranks the survivors with the vector-preserving order,
    /// admits them against the candidate bound, and records every remainder
    /// as an explicit gap. Any bounds, binding, or digest failure fails
    /// closed; no fallback probe is ever synthesized.
    pub fn new(params: ProbePlanParams<'_>) -> Result<Self, ContractViolation> {
        crate::plan::build_plan(params)
    }

    /// Validates identity, tables, canonical order, and the frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight(self)?;
        self.validate_shape()?;
        bounds::digest(&self.digest, "probe_plan.digest")?;
        let expected = self.compute_digest_unchecked()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "probe_plan.digest",
                reason: "probe plan digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest after validating the plan shape.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        preflight(self)?;
        self.validate_shape()?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        bounds::canonical_digest(&(
            self.schema_version,
            &self.plan_id,
            &self.task_id,
            &self.scope,
            &self.state_fence,
            &self.draft_digest,
            &self.rival_digest,
            &self.affordance_digest,
            &self.manifest_digest,
            &self.probes,
            &self.omissions,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != PROBE_PLAN_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe_plan.schema_version",
                reason: "unsupported probe plan schema".to_owned(),
            });
        }
        bounds::text(self.plan_id.as_str(), "probe_plan.plan_id")?;
        bounds::text(self.task_id.as_str(), "probe_plan.task_id")?;
        bounds::text(&self.scope, "probe_plan.scope")?;
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe_plan.state_fence",
                reason: error.to_string(),
            })?;
        bounds::digest(&self.draft_digest, "probe_plan.draft_digest")?;
        bounds::digest(&self.rival_digest, "probe_plan.rival_digest")?;
        bounds::digest(&self.affordance_digest, "probe_plan.affordance_digest")?;
        bounds::digest(&self.manifest_digest, "probe_plan.manifest_digest")?;
        bounds::sequence(self.probes.len(), "probe_plan.probes")?;
        bounds::sequence(self.omissions.len(), "probe_plan.omissions")?;
        self.validate_probe_table()?;
        self.validate_omission_table()?;
        self.validate_partition()?;
        Ok(())
    }

    fn validate_probe_table(&self) -> Result<(), ContractViolation> {
        for (index, probe) in self.probes.iter().enumerate() {
            probe.validate()?;
            let rank = u32::try_from(index).map_err(|_| ContractViolation::OutOfBounds {
                field: "probe_plan.probes",
                min: 0,
                max: i64::from(u32::MAX),
                got: len_i64(index),
            })?;
            if probe.rank != rank {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe_plan.probes",
                    reason: "probe rank must equal its plan position".to_owned(),
                });
            }
        }
        for pair in self.probes.windows(2) {
            if probe_order_key(&pair[0]) >= probe_order_key(&pair[1]) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe_plan.probes",
                    reason: "probes are not in total plan order".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_omission_table(&self) -> Result<(), ContractViolation> {
        for omission in &self.omissions {
            omission.validate()?;
        }
        for pair in self.omissions.windows(2) {
            if omission_order_key(&pair[0]) >= omission_order_key(&pair[1]) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe_plan.omissions",
                    reason: "omissions are not in canonical gap order".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Probes and omissions partition the source descriptors: no affordance
    /// identity, primary or merged, may appear twice.
    fn validate_partition(&self) -> Result<(), ContractViolation> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for probe in &self.probes {
            // `ProbeProposal::validate` already requires
            // `probe_id == affordance.affordance_id`, so one claim covers both.
            Self::claim_identity(&mut seen, probe.probe_id.as_str())?;
            for merged in &probe.merged_affordances {
                Self::claim_identity(&mut seen, merged.as_str())?;
            }
        }
        for omission in &self.omissions {
            Self::claim_identity(&mut seen, omission.affordance.affordance_id.as_str())?;
            for merged in &omission.merged_affordances {
                Self::claim_identity(&mut seen, merged.as_str())?;
            }
        }
        Ok(())
    }

    fn claim_identity<'a>(
        seen: &mut BTreeSet<&'a str>,
        identity: &'a str,
    ) -> Result<(), ContractViolation> {
        if seen.insert(identity) {
            Ok(())
        } else {
            Err(ContractViolation::BindingMismatch {
                field: "probe_plan.partition",
                reason: "one affordance identity maps to two plan entries".to_owned(),
            })
        }
    }
}
