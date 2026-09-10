//! Typed non-authoritative portions of the A9.5 Architecture result.

use eliot_dreamer_contracts::{BudgetLimits, BudgetUsage, GroundedDreamDraft, ModelDraft};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ArchitectureBriefError;

/// Availability marker for a field that is absent from the A-03 v1 closure.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DataAvailability {
    /// A-03 v1 does not carry this value.
    NotRetainedByV1,
}

/// Exact model-authored and grounded drafts, retained outside constitutional
/// Architecture statements. Neither value can establish source authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSynthesis {
    pub model: ModelDraft,
    pub grounded: GroundedDreamDraft,
}

impl ModelSynthesis {
    pub(crate) fn validate(&self) -> Result<(), ArchitectureBriefError> {
        self.model
            .validate()
            .map_err(|_| ArchitectureBriefError::BindingMismatch {
                field: "projection.model_synthesis.model",
            })?;
        self.grounded
            .validate()
            .map_err(|_| ArchitectureBriefError::BindingMismatch {
                field: "projection.model_synthesis.grounded",
            })?;
        Ok(())
    }
}

/// Rival-model data is deliberately separate from model counterevidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalModels {
    /// A-03 v1 carries counterevidence, but no rival-model records.
    pub availability: DataAvailability,
}

/// Typed availability marker for admitted model routes.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteAvailability {
    /// A-03 v1 does not carry allowed model-route records.
    NotRetainedByV1,
}

/// Typed availability marker for monetary model cost.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MonetaryCostAvailability {
    /// A-03 v1 carries resource usage, not money or provider pricing.
    NotRetainedByV1,
}

/// A9.5 route/cost envelope with resource usage kept distinct from money.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCostEnvelope {
    pub routes: RouteAvailability,
    pub monetary_cost: MonetaryCostAvailability,
    /// Original upstream ceilings are retained losslessly.
    pub budget_limits: BudgetLimits,
    /// A-05 usage retained separately from this projection's own usage.
    pub upstream_usage: BudgetUsage,
    /// Measured projection resource usage; this is not monetary cost and is
    /// not the total serialized wrapper size.
    pub projection_usage: BudgetUsage,
}
