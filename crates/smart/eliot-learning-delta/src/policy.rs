//! Immutable policy and explicit bounds for the pure derivation.

use std::collections::BTreeMap;

use eliot_contracts::PolicyRevision;
use eliot_learning_contracts::{
    ChangeSurface, MemberId, NoChangeReason, OwnerId, SlotId, TargetId,
    identity::{validate_digest, validate_external_id},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{LearningDeltaError, SemanticOutcome};

/// Closed reasons that can authorize a materially equivalent controlled retry.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RetryReason {
    /// Repeat to estimate noise around the same mechanism.
    Replication,
    /// Repeat to estimate measurement noise.
    NoiseEstimation,
    /// Repeat as a controlled comparison.
    ControlledComparison,
    /// Repeat an exact reproduction.
    ExactReproduction,
    /// Repeat to prove recovery of a known failure.
    RecoveryProof,
    /// Repeat to calibrate the verifier.
    VerifierCalibration,
}

/// Exact verifier property and semantic witness frozen for one no-change reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoChangeWitness {
    /// Verifier identity required for the witness.
    pub verifier: eliot_contracts::ContractId,
    /// Property which must have been evaluated.
    pub property: String,
    /// Revision of the evaluated property.
    pub revision: String,
    /// Mapped semantic outcome required for this reason.
    pub outcome: SemanticOutcome,
}

/// One exact mutable surface permitted by a policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurfacePermission {
    /// Recipe slot identity.
    pub slot_id: SlotId,
    /// Exact target identity.
    pub target: TargetId,
    /// Exact owner identity.
    pub owner: OwnerId,
    /// Exact member identity, when the slot is member-backed.
    pub member_id: Option<MemberId>,
    /// Permitted closed change surface.
    pub surface: ChangeSurface,
    /// Accepted typed value label.
    pub accepted_type: String,
    /// Accepted schema digest.
    pub schema_digest: String,
}

/// Versioned, side-effect-free limits used by every derivation phase.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DerivationPolicy {
    /// Policy revision bound to the input contract.
    pub revision: PolicyRevision,
    /// Maximum evidence records consumed by one derivation.
    pub max_evidence: u32,
    /// Maximum dependency/reference identities retained in one result.
    pub max_references: u32,
    /// Maximum serialized input/output work budget.
    pub max_work_units: u32,
    /// Maximum encoded input size checked before full validation.
    pub max_input_bytes: u32,
    /// Maximum encoded output size checked before returning a result.
    pub max_output_bytes: u32,
    /// Maximum source evidence units consumed by one derivation.
    pub max_source_units: u32,
    /// Maximum measured source-token units; no inference from bytes is allowed.
    pub max_stu: u32,
    /// Maximum measured cost units.
    pub max_cost_units: u32,
    /// Maximum measured output units.
    pub max_output_units: u32,
    /// Exact metric identity expected from semantic evaluator evidence.
    pub metric: String,
    /// Exact unit identity expected from semantic evaluator evidence.
    pub unit: String,
    /// Exact population identity expected from semantic evaluator evidence.
    pub population: String,
    /// Exact evaluation window identity expected from semantic evaluator evidence.
    pub window: String,
    /// Frozen evaluator contract selected by this policy.
    pub evaluator_contract: Option<eliot_contracts::ContractId>,
    /// Frozen verifier identity selected by this policy.
    pub evaluator_verifier: Option<eliot_contracts::ContractId>,
    /// Frozen verifier property selected by this policy.
    pub evaluator_property: String,
    /// Frozen evaluated revision selected by this policy.
    pub evaluator_revision: String,
    /// Semantic mapping for a passing verifier run.
    pub evaluator_pass_outcome: SemanticOutcome,
    /// Semantic mapping for a failing verifier run.
    pub evaluator_fail_outcome: SemanticOutcome,
    /// Frozen affirmative semantic outcomes for each closed no-change reason.
    pub no_change_witnesses: BTreeMap<String, NoChangeWitness>,
    /// Structural surfaces permitted by this policy snapshot.
    pub allowed_surfaces: Vec<ChangeSurface>,
    /// Exact slot/target/owner/member/surface permission rows.
    pub surface_permissions: Vec<SurfacePermission>,
}

impl Default for DerivationPolicy {
    fn default() -> Self {
        Self {
            revision: PolicyRevision::genesis(),
            max_evidence: 64,
            max_references: 128,
            max_work_units: 4096,
            max_input_bytes: 1_048_576,
            max_output_bytes: 1_048_576,
            max_source_units: 8192,
            max_stu: 8192,
            max_cost_units: 8192,
            max_output_units: 8192,
            metric: "outcome".to_owned(),
            unit: "categorical".to_owned(),
            population: "declared-attempt".to_owned(),
            window: "attempt".to_owned(),
            evaluator_contract: None,
            evaluator_verifier: None,
            evaluator_property: "learning-outcome".to_owned(),
            evaluator_revision: "1".to_owned(),
            evaluator_pass_outcome: SemanticOutcome::Benefit,
            evaluator_fail_outcome: SemanticOutcome::Harm,
            no_change_witnesses: BTreeMap::new(),
            allowed_surfaces: Vec::new(),
            surface_permissions: Vec::new(),
        }
    }
}

impl DerivationPolicy {
    /// Validate finite policy dimensions before reading large collections.
    pub fn validate(&self) -> Result<(), LearningDeltaError> {
        if self.max_evidence == 0
            || self.max_references == 0
            || self.max_work_units == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_source_units == 0
            || self.max_stu == 0
            || self.max_cost_units == 0
            || self.max_output_units == 0
        {
            return Err(LearningDeltaError::Bound { field: "policy" });
        }
        if self.max_evidence > 128
            || self.max_references > 256
            || self.max_work_units > 16_384
            || self.max_input_bytes > 4_194_304
            || self.max_output_bytes > 4_194_304
            || self.max_source_units > 65_536
            || self.max_stu > 65_536
            || self.max_cost_units > 65_536
            || self.max_output_units > 65_536
        {
            return Err(LearningDeltaError::Bound { field: "policy" });
        }
        for (value, field) in [
            (&self.metric, "policy.metric"),
            (&self.unit, "policy.unit"),
            (&self.population, "policy.population"),
            (&self.window, "policy.window"),
        ] {
            validate_external_id(value, field)
                .map_err(|_| LearningDeltaError::InvalidInput { field })?;
        }
        let evaluator_contract =
            self.evaluator_contract
                .as_ref()
                .ok_or(LearningDeltaError::InvalidInput {
                    field: "policy.evaluator_contract",
                })?;
        let evaluator_verifier =
            self.evaluator_verifier
                .as_ref()
                .ok_or(LearningDeltaError::InvalidInput {
                    field: "policy.evaluator_verifier",
                })?;
        for (value, field) in [
            (evaluator_contract.as_str(), "policy.evaluator_contract"),
            (evaluator_verifier.as_str(), "policy.evaluator_verifier"),
            (&self.evaluator_property, "policy.evaluator_property"),
            (&self.evaluator_revision, "policy.evaluator_revision"),
        ] {
            validate_external_id(value, field)
                .map_err(|_| LearningDeltaError::InvalidInput { field })?;
        }
        for (count, field) in [
            (self.no_change_witnesses.len(), "policy.no_change_witnesses"),
            (self.allowed_surfaces.len(), "policy.allowed_surfaces"),
            (self.surface_permissions.len(), "policy.surface_permissions"),
        ] {
            if u32::try_from(count).map_err(|_| LearningDeltaError::Bound { field })?
                > self.max_references
            {
                return Err(LearningDeltaError::Bound { field });
            }
        }
        for witness in self.no_change_witnesses.values() {
            for (value, field) in [
                (witness.verifier.as_str(), "policy.witness.verifier"),
                (witness.property.as_str(), "policy.witness.property"),
                (witness.revision.as_str(), "policy.witness.revision"),
            ] {
                validate_external_id(value, field)
                    .map_err(|_| LearningDeltaError::InvalidInput { field })?;
            }
        }
        for permission in &self.surface_permissions {
            permission.slot_id.validate()?;
            permission.owner.validate()?;
            validate_external_id(permission.target.as_str(), "policy.permission.target").map_err(
                |_| LearningDeltaError::InvalidInput {
                    field: "policy.permission.target",
                },
            )?;
            if let Some(member) = &permission.member_id {
                member.validate()?;
            }
            if permission.accepted_type.trim().is_empty() {
                return Err(LearningDeltaError::InvalidInput {
                    field: "policy.permission.accepted_type",
                });
            }
            validate_digest(&permission.schema_digest, "policy.permission.schema_digest").map_err(
                |_| LearningDeltaError::InvalidInput {
                    field: "policy.permission.schema_digest",
                },
            )?;
        }
        Ok(())
    }

    /// Check the policy-owned affirmative semantic witness for a no-change reason.
    pub fn allows_no_change(
        &self,
        reason: NoChangeReason,
        verifier: &eliot_contracts::ContractId,
        property: &str,
        revision: &str,
        outcome: SemanticOutcome,
    ) -> bool {
        let key = no_change_key(reason);
        self.no_change_witnesses.get(key).is_some_and(|witness| {
            &witness.verifier == verifier
                && witness.property == property
                && witness.revision == revision
                && witness.outcome == outcome
        })
    }

    /// Check an exact mutable surface permission row.
    pub fn allows_surface(&self, request: &crate::ChangeRequest) -> bool {
        self.allowed_surfaces.contains(&request.surface)
            && self.surface_permissions.iter().any(|permission| {
                permission.slot_id == request.slot_id
                    && permission.target == request.target
                    && permission.owner == request.owner
                    && permission.member_id == request.member_id
                    && permission.surface == request.surface
                    && permission.accepted_type == request.accepted_type
                    && permission.schema_digest == request.schema_digest
            })
    }
}

fn no_change_key(reason: NoChangeReason) -> &'static str {
    match reason {
        NoChangeReason::ConfirmedFixedPrediction => "confirmed_fixed_prediction",
        NoChangeReason::ControlledReplicationNeeded => "controlled_replication_needed",
        NoChangeReason::ProtectedConstraint => "protected_constraint",
        NoChangeReason::ProvenNonApplicability => "proven_non_applicability",
        NoChangeReason::Contradicted => "contradicted",
        NoChangeReason::UnsafeCandidate => "unsafe_candidate",
        NoChangeReason::OwnerBlocked => "owner_blocked",
        NoChangeReason::ExternalReviewRequired => "external_review_required",
    }
}
