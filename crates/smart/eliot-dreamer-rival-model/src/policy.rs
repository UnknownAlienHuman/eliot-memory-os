//! Local, explicit bounds for rival structuring.

use crate::bounds::MAX_RIVAL_WIRE_BYTES;
use crate::error::RivalModelError;
use eliot_dreamer_contracts::{BudgetUsage, canonical_bytes, digest_hex, is_hex64_lower};
use serde::{Deserialize, Serialize};

/// Wire version for the local rival policy.
pub const RIVAL_POLICY_SCHEMA_VERSION: u32 = 1;

/// Bounded structural limits for one rival-model operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalPolicyLimits {
    /// Maximum retained model declarations.
    pub max_models: u32,
    /// Minimum distinct retained models required for comparison.
    pub min_models: u32,
    /// Maximum serialized output bytes.
    pub max_output_bytes: u64,
    /// Maximum deterministic work units.
    pub max_work_units: u64,
    /// Maximum elapsed wall time.
    pub max_elapsed_ms: u64,
    /// Maximum synthetic throttle units.
    pub max_stu: u64,
    /// Maximum inert discriminators.
    pub max_discriminators: u32,
    /// Minimum output capacity reserved for explicit unknown/omitted data.
    pub reserved_unknown_slots: u32,
    /// Maximum material entries.
    pub max_material_items: u32,
    /// Maximum reference entries.
    pub max_reference_items: u32,
    /// Maximum evidence entries.
    pub max_evidence_items: u32,
    /// Maximum conflict entries.
    pub max_conflict_items: u32,
}

/// Explicit deterministic operation observations supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalOperationObservation {
    /// Observed operation time in Unix milliseconds, if supplied.
    pub observation_time_ms: Option<u64>,
    /// Observed elapsed operation time.
    pub elapsed_ms: u64,
    /// Cancellation observation captured by the caller.
    pub cancellation_requested: bool,
    /// Observed synthetic throttle usage.
    pub stu_used: u64,
    /// Current handler increment added to the prior A05 usage for job limits.
    /// Its wall and STU fields must equal `elapsed_ms` and `stu_used`.
    pub current_usage: BudgetUsage,
}

/// Deterministic caller-supplied limits; no execution or selection semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalPolicy {
    /// Policy wire version.
    pub schema_version: u32,
    /// Stable policy identity.
    pub policy_id: String,
    /// Positive policy revision.
    pub policy_revision: u64,
    /// Maximum retained rival model declarations.
    pub max_models: u32,
    /// Minimum retained rival declarations reserved for a comparison.
    pub min_models: u32,
    /// Maximum serialized output bytes.
    pub max_output_bytes: u64,
    /// Maximum deterministic work units.
    pub max_work_units: u64,
    /// Maximum inert discriminators reserved for later analysis.
    pub max_discriminators: u32,
    /// Minimum output slots reserved for explicit unknown/omitted data; this
    /// does not reject an input with more unknown declarations.
    pub reserved_unknown_slots: u32,
    /// Independent material-entry bound.
    pub max_material_items: u32,
    /// Independent reference-entry bound.
    pub max_reference_items: u32,
    /// Independent evidence-entry bound.
    pub max_evidence_items: u32,
    /// Independent conflict-entry bound.
    pub max_conflict_items: u32,
    /// Optional caller-supplied operation deadline in milliseconds.
    pub deadline_ms: Option<u64>,
    /// Explicit operation-time observation supplied by the caller.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation observation supplied by the caller.
    pub cancellation_requested: bool,
    /// Maximum elapsed wall time admitted for this operation.
    pub max_elapsed_ms: u64,
    /// Maximum synthetic throttle units admitted for this operation.
    pub max_stu: u64,
    /// Observed elapsed operation time supplied by the caller.
    pub observed_elapsed_ms: u64,
    /// Observed synthetic throttle usage supplied by the caller.
    pub observed_stu_used: u64,
    /// Current handler increment added to the prior A05 usage for job limits.
    pub current_usage: BudgetUsage,
    /// Canonical policy digest, empty only before sealing.
    pub digest: String,
}

impl RivalPolicy {
    /// Creates an unsealed policy with the supplied limits.
    pub fn new(
        policy_id: String,
        policy_revision: u64,
        limits: RivalPolicyLimits,
        observation: RivalOperationObservation,
        deadline_ms: Option<u64>,
    ) -> Self {
        Self {
            schema_version: RIVAL_POLICY_SCHEMA_VERSION,
            policy_id,
            policy_revision,
            max_models: limits.max_models,
            min_models: limits.min_models,
            max_output_bytes: limits.max_output_bytes,
            max_work_units: limits.max_work_units,
            max_elapsed_ms: limits.max_elapsed_ms,
            max_stu: limits.max_stu,
            max_discriminators: limits.max_discriminators,
            reserved_unknown_slots: limits.reserved_unknown_slots,
            max_material_items: limits.max_material_items,
            max_reference_items: limits.max_reference_items,
            max_evidence_items: limits.max_evidence_items,
            max_conflict_items: limits.max_conflict_items,
            deadline_ms,
            observation_time_ms: observation.observation_time_ms,
            cancellation_requested: observation.cancellation_requested,
            observed_elapsed_ms: observation.elapsed_ms,
            observed_stu_used: observation.stu_used,
            current_usage: observation.current_usage,
            digest: String::new(),
        }
    }

    /// Computes and stores the canonical policy digest.
    pub fn seal(mut self) -> Result<Self, RivalModelError> {
        self.validate_shape()?;
        self.digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the policy and its frozen digest.
    pub fn validate(&self) -> Result<(), RivalModelError> {
        self.validate_shape()?;
        if self.digest.len() != 64 || !is_hex64_lower(&self.digest) {
            return Err(RivalModelError::InvalidContract("rival_policy.digest"));
        }
        if self.compute_digest()? != self.digest {
            return Err(RivalModelError::InvalidContract("rival_policy.digest"));
        }
        Ok(())
    }

    pub(crate) fn max_output_bytes_as_usize(&self) -> Result<usize, RivalModelError> {
        usize::try_from(self.max_output_bytes).map_err(|_| RivalModelError::Bound {
            field: "policy.max_output_bytes",
            maximum: usize::MAX,
            actual: usize::MAX,
        })
    }

    fn validate_shape(&self) -> Result<(), RivalModelError> {
        if self.schema_version != RIVAL_POLICY_SCHEMA_VERSION
            || self.policy_id.len() > 4096
            || self.policy_id.trim().is_empty()
            || self.policy_revision == 0
            || self.max_models == 0
            || self.max_models > 256
            || self.min_models == 0
            || self.min_models > 256
            || self.min_models > self.max_models
            || self.max_work_units == 0
            || self.max_work_units > 4096
            || self.max_discriminators == 0
            || self.max_discriminators > 256
            || self.max_material_items == 0
            || self.max_reference_items == 0
            || self.max_evidence_items == 0
            || self.max_conflict_items == 0
            || self.max_material_items > 4096
            || self.max_reference_items > 4096
            || self.max_evidence_items > 4096
            || self.max_conflict_items > 4096
            || self.reserved_unknown_slots > 4096
            || self.max_output_bytes == 0
            || self.max_elapsed_ms == 0
            || self.max_elapsed_ms > 600_000
            || self.max_stu > 10_000
            || self.observed_elapsed_ms > self.max_elapsed_ms
            || self.observed_stu_used > self.max_stu
            || self.current_usage.wall_ms != self.observed_elapsed_ms
            || self.current_usage.stu_used != self.observed_stu_used
            || usize::try_from(self.max_output_bytes).unwrap_or(usize::MAX) > MAX_RIVAL_WIRE_BYTES
        {
            return Err(RivalModelError::InvalidContract("rival_policy"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, RivalModelError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            policy_id: &'a str,
            policy_revision: u64,
            max_models: u32,
            min_models: u32,
            max_output_bytes: u64,
            max_work_units: u64,
            max_elapsed_ms: u64,
            max_stu: u64,
            max_discriminators: u32,
            reserved_unknown_slots: u32,
            max_material_items: u32,
            max_reference_items: u32,
            max_evidence_items: u32,
            max_conflict_items: u32,
            deadline_ms: Option<u64>,
            observation_time_ms: Option<u64>,
            cancellation_requested: bool,
            observed_elapsed_ms: u64,
            observed_stu_used: u64,
            current_usage: &'a BudgetUsage,
        }
        let bytes = canonical_bytes(&Preimage {
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            max_models: self.max_models,
            min_models: self.min_models,
            max_output_bytes: self.max_output_bytes,
            max_work_units: self.max_work_units,
            max_elapsed_ms: self.max_elapsed_ms,
            max_stu: self.max_stu,
            max_discriminators: self.max_discriminators,
            reserved_unknown_slots: self.reserved_unknown_slots,
            max_material_items: self.max_material_items,
            max_reference_items: self.max_reference_items,
            max_evidence_items: self.max_evidence_items,
            max_conflict_items: self.max_conflict_items,
            deadline_ms: self.deadline_ms,
            observation_time_ms: self.observation_time_ms,
            cancellation_requested: self.cancellation_requested,
            observed_elapsed_ms: self.observed_elapsed_ms,
            observed_stu_used: self.observed_stu_used,
            current_usage: &self.current_usage,
        })
        .map_err(|_| RivalModelError::InvalidContract("rival_policy.preimage"))?;
        Ok(digest_hex(&bytes))
    }
}
