//! Versioned lexicographic policy identity for probe presentation.

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractViolation;

use super::validation;

/// Stable policy wire revision.
pub const PROBE_ORDERING_POLICY_SCHEMA_VERSION: u32 = 1;

/// Closed dimensions accepted by the pure planner's lexicographic policy.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeOrderingDimension {
    Information,
    Cost,
    Latency,
    Context,
    Resource,
    Privacy,
    Consent,
    Authority,
    Effect,
    Reversibility,
    Feasibility,
    HumanAttention,
}

/// Stable final tie-break. It changes presentation only; it never grants
/// execution priority or semantic authority.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeOrderingTieBreak {
    AffordanceId,
}

/// Explicit, digest-bound ordering policy consumed by the planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeOrderingPolicy {
    pub schema_version: u32,
    pub policy_id: ArtifactId,
    pub revision: u32,
    pub dimensions: Vec<ProbeOrderingDimension>,
    pub tie_break: ProbeOrderingTieBreak,
    pub digest: String,
}

impl ProbeOrderingPolicy {
    /// Constructs the current explicit v1 policy.
    pub fn v1() -> Result<Self, ContractViolation> {
        let policy_id =
            ArtifactId::new("probe-ordering-v1").map_err(|error| ContractViolation::Malformed {
                field: "probe.policy.policy_id",
                reason: error.to_string(),
            })?;
        let mut policy = Self {
            schema_version: PROBE_ORDERING_POLICY_SCHEMA_VERSION,
            policy_id,
            revision: 1,
            dimensions: vec![
                ProbeOrderingDimension::Information,
                ProbeOrderingDimension::Cost,
                ProbeOrderingDimension::Latency,
                ProbeOrderingDimension::Context,
                ProbeOrderingDimension::Resource,
                ProbeOrderingDimension::Privacy,
                ProbeOrderingDimension::Consent,
                ProbeOrderingDimension::Authority,
                ProbeOrderingDimension::Effect,
                ProbeOrderingDimension::Reversibility,
                ProbeOrderingDimension::Feasibility,
                ProbeOrderingDimension::HumanAttention,
            ],
            tie_break: ProbeOrderingTieBreak::AffordanceId,
            digest: String::new(),
        };
        policy.validate_shape()?;
        policy.digest = policy.compute_digest_unchecked()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.policy.digest")?;
        if self.digest != self.compute_digest_unchecked()? {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.policy.digest",
                reason: "ordering policy digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&(
            self.schema_version,
            &self.policy_id,
            self.revision,
            &self.dimensions,
            self.tie_break,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != PROBE_ORDERING_POLICY_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.policy.schema_version",
                reason: "unsupported ordering policy schema".to_owned(),
            });
        }
        validation::text(self.policy_id.as_str(), "probe.policy.policy_id")?;
        if self.revision == 0 {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.policy.revision",
                min: 1,
                max: i64::MAX,
                got: 0,
            });
        }
        if self.dimensions.len() != 12 {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.policy.dimensions",
                reason: "ordering policy must name all twelve dimensions exactly once".to_owned(),
            });
        }
        let mut sorted = self.dimensions.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != 12 {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.policy.dimensions",
                reason: "ordering policy dimensions must be unique".to_owned(),
            });
        }
        Ok(())
    }
}
