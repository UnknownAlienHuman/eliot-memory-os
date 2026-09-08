//! Canonical, provider-neutral inputs for deterministic Context admission.
//!
//! This module describes the complete immutable input closure consumed by an
//! admission algorithm.  It deliberately contains no ranking, selection,
//! tokenization, provider access, or mutable state.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ContractVersion};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDisposition, AdmissionRecord, CONTEXT_CONTRACT_VERSION, CapacityLimits,
    ContextBinding, ContextCandidate, ContextCandidateSet, ContextEconomyReceipt, ContextError,
    ContextOutcome, ContextRecipe, DecisionContextIncomplete, DecisionRevision,
    DecisionSafetyFloor, ExpansionHandle, LossPolicy, NonRecoverableReason, OmissionRecord,
    RepresentationKind, StuEstimate, TokenizerObservation, canonical_digest, validate_digest,
    validate_text,
};

/// Closed unit used by an admission cost.  A unit is never inferred from a
/// route or from the magnitude of a number.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementUnit {
    /// Exact UTF-8 bytes of the serialized representation.
    Utf8Bytes,
    /// Conservative Source Token Units; these are planning evidence only.
    Stu,
    /// Exact tokens observed from the selected route tokenizer.
    TokenizerTokens,
}

/// Exact, conservative, or unavailable cost for one atom representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum AdmissionMeasuredCost {
    /// Exact serialized UTF-8 byte count.
    #[serde(rename = "EXACT_UTF8_BYTES")]
    ExactUtf8Bytes { value: u64 },
    /// Conservative estimate with its empirical qualification state.
    #[serde(rename = "CONSERVATIVE_STU")]
    ConservativeStu { estimate: StuEstimate },
    /// Exact tokenizer observation for the bound route.
    #[serde(rename = "EXACT_TOKENIZER")]
    ExactTokenizer { observation: TokenizerObservation },
    /// No measurement is available; this is not zero.
    #[serde(rename = "UNKNOWN")]
    Unknown,
    /// The measurement owner could not provide an observation.
    #[serde(rename = "UNAVAILABLE")]
    Unavailable,
}

/// Qualification for combining per-unit costs. Token counts are not
/// additive by default because framing and tokenizer position can change.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementAggregationMode {
    /// The serializer explicitly measured independent UTF-8 contributions.
    QualifiedUtf8Contribution,
    /// The observations describe a whole context and cannot be summed here.
    WholeContextObservation,
}

/// Closed serializer/route profile that qualifies additive cost accounting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeasurementCompositionProfile {
    pub profile_id: ArtifactId,
    pub schema_version: ContractVersion,
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    pub route_id: String,
    pub model_id: String,
    pub unit: MeasurementUnit,
    pub aggregation: MeasurementAggregationMode,
    pub qualification: ArtifactId,
    pub capacity: CapacityLimits,
}

impl MeasurementCompositionProfile {
    /// Validate the one currently supported additive profile.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != CONTEXT_CONTRACT_VERSION {
            return Err(ContextError::InvalidField(
                "measurement_profile.schema_version",
            ));
        }
        validate_text(&self.serializer_id, "measurement_profile.serializer_id")?;
        validate_text(
            &self.serializer_version,
            "measurement_profile.serializer_version",
        )?;
        validate_digest(
            &self.serializer_options_digest,
            "measurement_profile.serializer_options_digest",
        )?;
        validate_text(&self.route_id, "measurement_profile.route_id")?;
        validate_text(&self.model_id, "measurement_profile.model_id")?;
        self.capacity.validate()?;
        if self.unit != MeasurementUnit::Utf8Bytes
            || self.aggregation != MeasurementAggregationMode::QualifiedUtf8Contribution
        {
            return Err(ContextError::UnknownMeasurement);
        }
        Ok(())
    }

    /// Compute a stable identity for this exact profile.
    pub fn canonical_digest(&self) -> Result<String, ContextError> {
        self.validate()?;
        canonical_digest(self)
    }
}

impl AdmissionMeasuredCost {
    /// Return the explicitly declared unit, when this cost has one.
    #[must_use]
    pub const fn unit(&self) -> Option<MeasurementUnit> {
        match self {
            Self::ExactUtf8Bytes { .. } => Some(MeasurementUnit::Utf8Bytes),
            Self::ConservativeStu { .. } => Some(MeasurementUnit::Stu),
            Self::ExactTokenizer { .. } => Some(MeasurementUnit::TokenizerTokens),
            Self::Unknown | Self::Unavailable => None,
        }
    }

    /// Validate bounds and the closed cost payload.
    pub fn validate(&self) -> Result<(), ContextError> {
        if let Self::ExactTokenizer { observation } = self {
            validate_text(
                &observation.tokenizer_id,
                "admission_measurement.tokenizer_id",
            )?;
            validate_text(
                &observation.tokenizer_version,
                "admission_measurement.tokenizer_version",
            )?;
            validate_digest(
                &observation.tokenizer_hash,
                "admission_measurement.tokenizer_hash",
            )?;
        }
        Ok(())
    }
}

/// Serializer, route, schema and Context identity for one atom measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionMeasurementBinding {
    /// Context task, attempt, scope, fence and decision identity.
    pub context: ContextBinding,
    /// Closed schema revision of the serialized representation.
    pub schema_version: ContractVersion,
    /// Canonical digest of the candidate subject measured by this record.
    pub subject_digest: String,
    /// Digest carried by the candidate's `MeasurementRef`.
    pub input_digest: String,
    /// Digest of the measured serialized representation.
    pub output_digest: String,
    /// Serializer implementation and options identity.
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    /// Route and model that establish the capacity profile.
    pub route_id: String,
    pub model_id: String,
}

impl AdmissionMeasurementBinding {
    /// Validate all load-bearing measurement bindings.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.context.validate()?;
        if self.schema_version != CONTEXT_CONTRACT_VERSION {
            return Err(ContextError::InvalidField(
                "admission_measurement.schema_version",
            ));
        }
        validate_digest(&self.input_digest, "admission_measurement.input_digest")?;
        validate_digest(&self.subject_digest, "admission_measurement.subject_digest")?;
        validate_digest(&self.output_digest, "admission_measurement.output_digest")?;
        validate_text(&self.serializer_id, "admission_measurement.serializer_id")?;
        validate_text(
            &self.serializer_version,
            "admission_measurement.serializer_version",
        )?;
        validate_digest(
            &self.serializer_options_digest,
            "admission_measurement.serializer_options_digest",
        )?;
        validate_text(&self.route_id, "admission_measurement.route_id")?;
        validate_text(&self.model_id, "admission_measurement.model_id")
    }
}

/// One measured cost for one exact candidate atom/representation pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionMeasurement {
    pub measurement_id: ArtifactId,
    pub atom_id: ArtifactId,
    pub representation: RepresentationKind,
    pub unit: MeasurementUnit,
    pub binding: AdmissionMeasurementBinding,
    pub cost: AdmissionMeasuredCost,
    /// Optional unqualified observation retained for diagnostics. It never
    /// authorizes additive fit when it is STU or tokenizer based.
    pub observation: Option<AdmissionMeasuredCost>,
}

impl AdmissionMeasurement {
    /// Validate the binding and cost without estimating or measuring anything.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.cost.validate()?;
        if let Some(observation) = &self.observation {
            observation.validate()?;
        }
        Ok(())
    }

    fn key(&self) -> (ArtifactId, RepresentationKind) {
        (self.atom_id.clone(), self.representation)
    }
}

/// Stable declared priority class for optional allocation.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionPriorityClass {
    Protected,
    Required,
    High,
    Normal,
    Low,
}

/// One candidate's immutable priority declaration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidatePriority {
    pub atom_id: ArtifactId,
    pub class: AdmissionPriorityClass,
    /// Meaningful recipe order, with atom identity as the deterministic tie-break.
    pub ordinal: u32,
}

/// Identity of the priority policy used by an admission run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PriorityPolicyIdentity {
    pub policy_id: ArtifactId,
    pub decision: DecisionRevision,
    pub priorities: Vec<CandidatePriority>,
}

impl PriorityPolicyIdentity {
    /// Validate exact identity and one declaration per candidate.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.decision.validate()?;
        if self.priorities.is_empty() || self.priorities.len() > 4096 {
            return Err(ContextError::MissingField("admission.priority"));
        }
        let mut ids = BTreeSet::new();
        for priority in &self.priorities {
            if !ids.insert(priority.atom_id.clone()) {
                return Err(ContextError::Duplicate("admission.priority.atom_id"));
            }
        }
        Ok(())
    }
}

/// Immutable identity of the exact Safety Floor used by this run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SafetyFloorIdentity {
    pub floor_id: ArtifactId,
    pub decision: DecisionRevision,
    pub floor: DecisionSafetyFloor,
}

impl SafetyFloorIdentity {
    /// Validate the floor and keep its decision identity explicit.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.decision.validate()?;
        self.floor.validate()
    }
}

/// Immutable identity of the admission rule and policy revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRuleIdentity {
    pub rule_id: ArtifactId,
    pub decision: DecisionRevision,
    pub rule_sha256: String,
}

impl AdmissionRuleIdentity {
    /// Validate identity without interpreting the rule or selecting anything.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.decision.validate()?;
        validate_digest(&self.rule_sha256, "admission.rule_sha256")
    }
}

/// A supplied, policy-bound way to account for an omitted candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuppliedOmissionBinding {
    pub atom_id: ArtifactId,
    pub policy: LossPolicy,
    pub expansion: Option<ExpansionHandle>,
    pub non_recoverable_reason: Option<NonRecoverableReason>,
    pub authorization_requirement: String,
    pub privacy_requirement: String,
    pub proof_requirement: String,
    pub expires: Option<ArtifactId>,
    pub invalidation: Option<ArtifactId>,
}

impl SuppliedOmissionBinding {
    /// Validate that omission recovery was supplied by the owner.
    pub fn validate(&self, context: &ContextBinding) -> Result<(), ContextError> {
        if context.state_fence.task_revision.is_none() {
            return Err(ContextError::OmissionHandleInvalid);
        }
        validate_text(
            &self.authorization_requirement,
            "admission.supplied_omission.authorization_requirement",
        )?;
        validate_text(
            &self.privacy_requirement,
            "admission.supplied_omission.privacy_requirement",
        )?;
        validate_text(
            &self.proof_requirement,
            "admission.supplied_omission.proof_requirement",
        )?;
        match (&self.expansion, &self.non_recoverable_reason) {
            (Some(handle), None) => {
                handle.validate()?;
                if handle.context != *context
                    || handle.atom_id != self.atom_id
                    || handle.policy != self.policy
                    || handle.expires != self.expires
                    || handle.invalidation != self.invalidation
                {
                    return Err(ContextError::OmissionHandleInvalid);
                }
            }
            (None, Some(_)) => {}
            _ => return Err(ContextError::OmissionHandleInvalid),
        }
        Ok(())
    }
}

/// Complete decision evidence for every candidate, including explicit omissions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecisionEvidence {
    pub binding: ContextBinding,
    pub decisions: Vec<AdmissionRecord>,
    pub omissions: Vec<OmissionRecord>,
    pub supplied_omissions: Vec<SuppliedOmissionBinding>,
    pub incomplete: Option<DecisionContextIncomplete>,
    pub economy: Option<ContextEconomyReceipt>,
    pub proof_ceiling: ProofCeiling,
}

impl AdmissionDecisionEvidence {
    /// Validate one disposition per candidate and conserve omission evidence.
    pub fn validate_for(&self, candidates: &ContextCandidateSet) -> Result<(), ContextError> {
        self.binding.validate()?;
        candidates.validate_for_admission()?;
        if candidates.binding != self.binding {
            return Err(ContextError::InvalidFence);
        }
        if self.decisions.len() != candidates.candidates.len() {
            return Err(ContextError::DenominatorMismatch);
        }
        let expected: std::collections::BTreeMap<_, _> = candidates
            .candidates
            .iter()
            .map(|candidate| (candidate.atom_id.clone(), candidate.provider_role.clone()))
            .collect();
        let mut seen = BTreeSet::new();
        for decision in &self.decisions {
            if !seen.insert(decision.atom_id.clone()) {
                return Err(ContextError::Duplicate("admission.decisions.atom_id"));
            }
            let role = expected
                .get(&decision.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if role != &decision.provider_role {
                return Err(ContextError::IdentityConflict);
            }
        }
        if seen.len() != expected.len() {
            return Err(ContextError::DenominatorMismatch);
        }
        let mut omission_ids = BTreeSet::new();
        for omission in &self.omissions {
            omission.validate(&self.binding)?;
            if !omission_ids.insert(omission.atom_id.clone()) {
                return Err(ContextError::Duplicate("admission.omissions.atom_id"));
            }
            let decision = self
                .decisions
                .iter()
                .find(|item| item.atom_id == omission.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if matches!(
                decision.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            ) {
                return Err(ContextError::EconomyMismatch);
            }
        }
        let mut supplied_ids = BTreeSet::new();
        for supplied in &self.supplied_omissions {
            supplied.validate(&self.binding)?;
            if !supplied_ids.insert(supplied.atom_id.clone()) {
                return Err(ContextError::Duplicate(
                    "admission.supplied_omissions.atom_id",
                ));
            }
            let omission = self
                .omissions
                .iter()
                .find(|item| item.atom_id == supplied.atom_id)
                .ok_or(ContextError::OmissionHandleInvalid)?;
            if omission.allowed_representation != supplied.policy
                || omission.expansion != supplied.expansion
                || omission.non_recoverable_reason != supplied.non_recoverable_reason
                || omission.authorization_requirement != supplied.authorization_requirement
                || omission.privacy_requirement != supplied.privacy_requirement
                || omission.proof_requirement != supplied.proof_requirement
                || omission.expires != supplied.expires
                || omission.invalidation != supplied.invalidation
            {
                return Err(ContextError::OmissionHandleInvalid);
            }
        }
        if supplied_ids != omission_ids {
            return Err(ContextError::OmissionHandleInvalid);
        }
        if let Some(incomplete) = &self.incomplete {
            incomplete.validate()?;
        }
        if let Some(economy) = &self.economy {
            economy.validate()?;
            if economy.binding != self.binding {
                return Err(ContextError::InvalidFence);
            }
            let economy_omissions: BTreeSet<_> = economy
                .omissions
                .iter()
                .map(|item| item.atom_id.clone())
                .collect();
            if economy_omissions != omission_ids {
                return Err(ContextError::EconomyMismatch);
            }
        } else if !omission_ids.is_empty() && self.incomplete.is_none() {
            return Err(ContextError::EconomyMismatch);
        }
        Ok(())
    }
}

/// Complete immutable input closure for a pure admission implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionInput {
    pub schema_version: ContractVersion,
    pub binding: ContextBinding,
    pub recipe: ContextRecipe,
    pub candidates: ContextCandidateSet,
    pub floor: SafetyFloorIdentity,
    pub priority: PriorityPolicyIdentity,
    pub rule: AdmissionRuleIdentity,
    pub measurement_profile: MeasurementCompositionProfile,
    pub supplied_omissions: Vec<SuppliedOmissionBinding>,
    pub measurements: Vec<AdmissionMeasurement>,
}

impl AdmissionInput {
    /// Validate the complete identity, denominator and measurement closure.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.validate_contract()?;
        let candidates: std::collections::BTreeMap<_, _> = self
            .candidates
            .candidates
            .iter()
            .map(|candidate| (candidate.atom_id.clone(), candidate))
            .collect();
        self.validate_floor_bindings(&candidates)?;
        self.validate_measurement_closure(&candidates)?;
        self.validate_priority_and_omission_closure(&candidates)?;
        Ok(())
    }

    fn validate_contract(&self) -> Result<(), ContextError> {
        if self.candidates.candidates.len() > 4096
            || self.measurements.len() > 4096
            || self.priority.priorities.len() > 4096
            || self.supplied_omissions.len() > 4096
            || (self.candidates.candidates.is_empty()
                && (!self.measurements.is_empty() || !self.priority.priorities.is_empty()))
            || (!self.candidates.candidates.is_empty()
                && (self.measurements.is_empty() || self.priority.priorities.is_empty()))
        {
            return Err(ContextError::Bounds {
                field: "admission.input",
            });
        }
        if self.schema_version != CONTEXT_CONTRACT_VERSION {
            return Err(ContextError::InvalidField("admission.schema_version"));
        }
        self.binding.validate()?;
        self.recipe.validate()?;
        self.candidates.validate_for_admission()?;
        self.floor.validate()?;
        self.priority.decision.validate()?;
        if !self.priority.priorities.is_empty() {
            self.priority.validate()?;
        }
        self.rule.validate()?;
        self.measurement_profile.validate()?;
        if self.recipe.binding != self.binding
            || self.candidates.binding != self.binding
            || self.floor.floor.binding != self.binding
            || self.floor.decision != self.recipe.decision
            || self.priority.decision != self.recipe.decision
            || self.rule.decision != self.recipe.decision
            || self.measurement_profile.capacity != self.recipe.capacity
        {
            return Err(ContextError::IdentityConflict);
        }
        if self.floor.floor.capacity != self.recipe.capacity {
            return Err(ContextError::IdentityConflict);
        }
        if matches!(
            self.measurement_profile.aggregation,
            MeasurementAggregationMode::WholeContextObservation
        ) {
            return Err(ContextError::UnknownMeasurement);
        }
        Ok(())
    }

    fn validate_floor_bindings(
        &self,
        candidates: &std::collections::BTreeMap<ArtifactId, &ContextCandidate>,
    ) -> Result<(), ContextError> {
        for provider in &self.floor.floor.providers.requested {
            if !self
                .candidates
                .denominator
                .requested
                .iter()
                .any(|candidate_provider| candidate_provider == provider)
            {
                return Err(ContextError::DenominatorMismatch);
            }
        }
        for member in &self.floor.floor.members {
            let Some(candidate) = candidates.get(&member.atom_id) else {
                continue;
            };
            let floor_provider = self
                .floor
                .floor
                .providers
                .dispositions
                .iter()
                .find(|disposition| disposition.slot == candidate.provider_role)
                .ok_or(ContextError::DenominatorMismatch)?;
            let candidate_provider = self
                .candidates
                .denominator
                .dispositions
                .iter()
                .find(|disposition| disposition.slot == candidate.provider_role)
                .ok_or(ContextError::DenominatorMismatch)?;
            let measurement_matches = member
                .measurement
                .as_ref()
                .is_none_or(|measurement| measurement == &candidate.measurement);
            if candidate.provider_role.role != member.role
                || candidate.availability != member.availability
                || floor_provider.state != candidate_provider.state
                || candidate.availability != floor_provider.state
                || (member.availability == crate::AtomAvailability::PresentCurrent
                    && !measurement_matches)
                || (member.measurement.is_some() && !measurement_matches)
                || candidate.dependencies.iter().collect::<BTreeSet<_>>()
                    != member.required_dependencies.iter().collect::<BTreeSet<_>>()
            {
                return Err(ContextError::IdentityConflict);
            }
        }
        Ok(())
    }

    fn validate_measurement_closure(
        &self,
        candidates: &std::collections::BTreeMap<ArtifactId, &ContextCandidate>,
    ) -> Result<(), ContextError> {
        let mut seen = BTreeSet::new();
        for measurement in &self.measurements {
            measurement.validate()?;
            if !seen.insert(measurement.key()) {
                return Err(ContextError::Duplicate(
                    "admission.measurements.atom_representation",
                ));
            }
            if measurement.binding.context != self.binding {
                return Err(ContextError::InvalidFence);
            }
            if measurement.unit != self.measurement_profile.unit
                || measurement
                    .cost
                    .unit()
                    .is_some_and(|unit| unit != measurement.unit)
                || measurement.binding.schema_version != self.measurement_profile.schema_version
                || measurement.binding.serializer_id != self.measurement_profile.serializer_id
                || measurement.binding.serializer_version
                    != self.measurement_profile.serializer_version
                || measurement.binding.serializer_options_digest
                    != self.measurement_profile.serializer_options_digest
                || measurement.binding.route_id != self.measurement_profile.route_id
                || measurement.binding.model_id != self.measurement_profile.model_id
            {
                return Err(ContextError::IdentityConflict);
            }
            let candidate = candidates
                .get(&measurement.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if candidate.representation.kind() != measurement.representation
                || candidate.measurement.digest != measurement.binding.input_digest
                || candidate.measurement.serializer != measurement.binding.serializer_id
                || canonical_digest(candidate)? != measurement.binding.subject_digest
            {
                return Err(ContextError::IdentityConflict);
            }
        }
        let expected: BTreeSet<_> = self
            .candidates
            .candidates
            .iter()
            .map(|candidate| (candidate.atom_id.clone(), candidate.representation.kind()))
            .collect();
        if seen != expected {
            return Err(ContextError::DenominatorMismatch);
        }
        Ok(())
    }

    fn validate_priority_and_omission_closure(
        &self,
        candidates: &std::collections::BTreeMap<ArtifactId, &ContextCandidate>,
    ) -> Result<(), ContextError> {
        let priority_ids: BTreeSet<_> = self
            .priority
            .priorities
            .iter()
            .map(|priority| priority.atom_id.clone())
            .collect();
        let candidate_ids: BTreeSet<_> = candidates.keys().cloned().collect();
        if priority_ids != candidate_ids {
            return Err(ContextError::DenominatorMismatch);
        }
        let mut supplied_ids = BTreeSet::new();
        for supplied in &self.supplied_omissions {
            supplied.validate(&self.binding)?;
            if !supplied_ids.insert(supplied.atom_id.clone()) {
                return Err(ContextError::Duplicate(
                    "admission.supplied_omissions.atom_id",
                ));
            }
            let candidate = candidates
                .get(&supplied.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if candidate.loss_policy != supplied.policy {
                return Err(ContextError::OmissionHandleInvalid);
            }
            if let Some(handle) = &supplied.expansion
                && (handle.decision != self.recipe.decision
                    || handle.source_id.as_str() != candidate.source.source_id.as_str()
                    || handle.provider_role != candidate.provider_role)
            {
                return Err(ContextError::OmissionHandleInvalid);
            }
        }
        if !supplied_ids.is_subset(&candidate_ids) {
            return Err(ContextError::DenominatorMismatch);
        }
        let floor_ids: BTreeSet<_> = self
            .floor
            .floor
            .members
            .iter()
            .map(|member| member.atom_id.clone())
            .collect();
        if candidates
            .keys()
            .any(|atom_id| !floor_ids.contains(atom_id) && !supplied_ids.contains(atom_id))
        {
            return Err(ContextError::OmissionHandleInvalid);
        }
        Ok(())
    }

    /// Check whether all available observations can participate in a byte
    /// contribution sum. Unknown and unavailable members remain explicit and
    /// cause a typed incomplete result at the admission boundary.
    pub fn validate_additive_measurements(&self) -> Result<(), ContextError> {
        self.validate()?;
        for measurement in &self.measurements {
            if !matches!(
                measurement.cost,
                AdmissionMeasuredCost::ExactUtf8Bytes { .. }
                    | AdmissionMeasuredCost::Unknown
                    | AdmissionMeasuredCost::Unavailable
            ) {
                return Err(ContextError::UnknownMeasurement);
            }
            if let Some(observation) = &measurement.observation
                && !matches!(observation, AdmissionMeasuredCost::ExactUtf8Bytes { .. })
            {
                return Err(ContextError::UnknownMeasurement);
            }
        }
        Ok(())
    }

    /// Compute a deterministic digest for the complete immutable input.
    pub fn canonical_digest(&self) -> Result<String, ContextError> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.recipe.mandatory_roles.sort();
        canonical.recipe.denominator.requested.sort();
        canonical
            .recipe
            .denominator
            .dispositions
            .sort_by(|left, right| left.slot.cmp(&right.slot));
        for role_policy in &mut canonical.recipe.role_policies {
            role_policy.allowed_representations.sort();
        }
        canonical
            .recipe
            .role_policies
            .sort_by_key(|role_policy| role_policy.role);
        canonical
            .candidates
            .candidates
            .sort_by_key(|candidate| candidate.atom_id.clone());
        canonical.candidates.denominator.requested.sort();
        canonical
            .candidates
            .denominator
            .dispositions
            .sort_by(|left, right| left.slot.cmp(&right.slot));
        canonical.floor.floor.mandatory_atoms.sort();
        canonical.floor.floor.mandatory_roles.sort();
        canonical
            .floor
            .floor
            .members
            .sort_by_key(|member| member.atom_id.clone());
        canonical.floor.floor.interpretation_dependencies.sort();
        canonical.floor.floor.providers.requested.sort();
        canonical
            .floor
            .floor
            .providers
            .dispositions
            .sort_by(|left, right| left.slot.cmp(&right.slot));
        for member in &mut canonical.floor.floor.members {
            member.required_dependencies.sort();
        }
        canonical
            .priority
            .priorities
            .sort_by_key(|priority| priority.atom_id.clone());
        canonical
            .measurements
            .sort_by_key(AdmissionMeasurement::key);
        canonical
            .supplied_omissions
            .sort_by_key(|binding| binding.atom_id.clone());
        canonical_digest(&canonical)
    }

    /// Return a candidate by its stable atom identity.
    #[must_use]
    pub fn candidate(&self, atom_id: &ArtifactId) -> Option<&ContextCandidate> {
        self.candidates
            .candidates
            .iter()
            .find(|candidate| &candidate.atom_id == atom_id)
    }

    /// Return the exact measured pair for a candidate.
    #[must_use]
    pub fn measurement(
        &self,
        atom_id: &ArtifactId,
        representation: RepresentationKind,
    ) -> Option<&AdmissionMeasurement> {
        self.measurements.iter().find(|measurement| {
            measurement.atom_id == *atom_id && measurement.representation == representation
        })
    }
}

/// Result envelope for the admission owner’s complete or incomplete outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionResult {
    pub schema_version: ContractVersion,
    pub binding: ContextBinding,
    pub input_digest: String,
    pub recipe_digest: String,
    pub profile_digest: String,
    pub floor_id: ArtifactId,
    pub outcome: ContextOutcome<crate::AdmittedContextSet>,
    pub evidence: AdmissionDecisionEvidence,
    pub selection_digest: String,
    pub result_digest: String,
}

impl AdmissionResult {
    /// Validate complete conservation or an explicit incomplete outcome.
    pub fn validate_for(&self, input: &AdmissionInput) -> Result<(), ContextError> {
        self.validate_input_contract(input)?;
        self.evidence.validate_for(&input.candidates)?;
        self.validate_omissions(input)?;
        match &self.outcome {
            ContextOutcome::Complete(admitted) => {
                self.validate_complete_economy(input, admitted)?;
                self.validate_complete_selection(input, admitted)?;
            }
            ContextOutcome::Incomplete(incomplete) => {
                self.validate_incomplete_outcome(incomplete)?;
            }
        }
        let mut unsigned = self.clone();
        unsigned.result_digest = "0".repeat(64);
        if self.result_digest != canonical_digest(&unsigned)? {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_input_contract(&self, input: &AdmissionInput) -> Result<(), ContextError> {
        input.validate_additive_measurements()?;
        if self.schema_version != CONTEXT_CONTRACT_VERSION || self.binding != input.binding {
            return Err(ContextError::IdentityConflict);
        }
        if self.input_digest != input.canonical_digest()?
            || self.recipe_digest != input.recipe.recipe_sha256
            || self.floor_id != input.floor.floor_id
            || self.profile_digest != input.measurement_profile.canonical_digest()?
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_omissions(&self, input: &AdmissionInput) -> Result<(), ContextError> {
        for omission in &self.evidence.omissions {
            let candidate = input
                .candidate(&omission.atom_id)
                .ok_or(ContextError::DenominatorMismatch)?;
            if candidate.source.source_id.as_str() != omission.source_id.as_str()
                || candidate.provider_role != omission.provider_role
                || omission.decision != input.recipe.decision
            {
                return Err(ContextError::IdentityConflict);
            }
            let supplied = input
                .supplied_omissions
                .iter()
                .find(|binding| binding.atom_id == omission.atom_id)
                .ok_or(ContextError::OmissionHandleInvalid)?;
            if omission.allowed_representation != supplied.policy
                || omission.expansion != supplied.expansion
                || omission.non_recoverable_reason != supplied.non_recoverable_reason
                || omission.authorization_requirement != supplied.authorization_requirement
                || omission.privacy_requirement != supplied.privacy_requirement
                || omission.proof_requirement != supplied.proof_requirement
                || omission.expires != supplied.expires
                || omission.invalidation != supplied.invalidation
            {
                return Err(ContextError::OmissionHandleInvalid);
            }
            let measurement = input
                .measurement(&candidate.atom_id, candidate.representation.kind())
                .ok_or(ContextError::DenominatorMismatch)?;
            match &measurement.cost {
                AdmissionMeasuredCost::ExactUtf8Bytes { value }
                    if omission.measured_cost == Some(*value) => {}
                AdmissionMeasuredCost::Unknown | AdmissionMeasuredCost::Unavailable
                    if omission.measured_cost.is_none() => {}
                AdmissionMeasuredCost::ExactUtf8Bytes { .. }
                | AdmissionMeasuredCost::Unknown
                | AdmissionMeasuredCost::Unavailable => {
                    return Err(ContextError::EconomyMismatch);
                }
                AdmissionMeasuredCost::ConservativeStu { .. }
                | AdmissionMeasuredCost::ExactTokenizer { .. } => {
                    return Err(ContextError::UnknownMeasurement);
                }
            }
        }
        Ok(())
    }

    fn validate_complete_economy(
        &self,
        input: &AdmissionInput,
        admitted: &crate::AdmittedContextSet,
    ) -> Result<(), ContextError> {
        if self.evidence.incomplete.is_some() {
            return Err(ContextError::DenominatorMismatch);
        }
        if input.floor.floor.incomplete()?.is_some() {
            return Err(ContextError::MissingFloor);
        }
        admitted.validate()?;
        if admitted.binding != self.binding
            || admitted.floor != input.floor.floor
            || self.evidence.economy.as_ref() != Some(&admitted.economy)
            || admitted.economy.measurement.digest != admitted.canonical_payload_digest()?
            || admitted.economy.measurement.serializer != input.measurement_profile.serializer_id
        {
            return Err(ContextError::IdentityConflict);
        }
        if admitted.economy.omissions.len() != self.evidence.omissions.len()
            || admitted.economy.omissions.iter().any(|economy_omission| {
                self.evidence
                    .omissions
                    .iter()
                    .find(|evidence_omission| evidence_omission.atom_id == economy_omission.atom_id)
                    != Some(economy_omission)
            })
        {
            return Err(ContextError::EconomyMismatch);
        }
        let capacity = &input.recipe.capacity;
        let allocations = &admitted.economy.allocations;
        if allocations.route_capacity != capacity.route_capacity
            || allocations.fixed_overhead != capacity.fixed_overhead
            || allocations.output_reserve != capacity.output_reserve
            || allocations.review_reserve != capacity.review_reserve
        {
            return Err(ContextError::EconomyMismatch);
        }
        let mut admitted_cost = 0_u64;
        for record in &admitted.records {
            let measurement = input
                .measurement(
                    &record.candidate.atom_id,
                    record.candidate.representation.kind(),
                )
                .ok_or(ContextError::DenominatorMismatch)?;
            let AdmissionMeasuredCost::ExactUtf8Bytes { value } = &measurement.cost else {
                return Err(ContextError::UnknownMeasurement);
            };
            admitted_cost = admitted_cost
                .checked_add(*value)
                .ok_or(ContextError::Overflow)?;
        }
        let allocated_admitted = allocations
            .admitted_required
            .checked_add(allocations.admitted_optional)
            .ok_or(ContextError::Overflow)?;
        if admitted_cost != allocated_admitted {
            return Err(ContextError::EconomyMismatch);
        }
        Ok(())
    }

    fn validate_complete_selection(
        &self,
        input: &AdmissionInput,
        admitted: &crate::AdmittedContextSet,
    ) -> Result<(), ContextError> {
        for admission in &admitted.admissions {
            if !self.evidence.decisions.iter().any(|decision| {
                decision.atom_id == admission.atom_id
                    && decision.provider_role == admission.provider_role
                    && decision.disposition == admission.disposition
                    && decision.rule_evidence == admission.rule_evidence
            }) {
                return Err(ContextError::SelectionIntegrityMismatch);
            }
        }
        for record in &admitted.records {
            if input.candidate(&record.candidate.atom_id) != Some(&record.candidate) {
                return Err(ContextError::SelectionIntegrityMismatch);
            }
        }
        let admitted_ids: BTreeSet<_> = admitted
            .records
            .iter()
            .map(|record| record.candidate.atom_id.clone())
            .collect();
        let omission_ids: BTreeSet<_> = self
            .evidence
            .omissions
            .iter()
            .map(|omission| omission.atom_id.clone())
            .collect();
        for decision in &self.evidence.decisions {
            let expected_admitted = matches!(
                decision.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            );
            if expected_admitted != admitted_ids.contains(&decision.atom_id)
                || (!expected_admitted && !omission_ids.contains(&decision.atom_id))
            {
                return Err(ContextError::SelectionIntegrityMismatch);
            }
        }
        let admitted_digest = admitted.canonical_payload_digest()?;
        if self.selection_digest != admitted_digest {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        Ok(())
    }

    fn validate_incomplete_outcome(
        &self,
        incomplete: &DecisionContextIncomplete,
    ) -> Result<(), ContextError> {
        if self.evidence.incomplete.as_ref() != Some(incomplete)
            || self.evidence.economy.is_some()
            || self.evidence.decisions.iter().any(|decision| {
                matches!(
                    decision.disposition,
                    AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
                )
            })
        {
            return Err(ContextError::DenominatorMismatch);
        }
        if self.selection_digest != canonical_digest(incomplete)? {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        Ok(())
    }
}
