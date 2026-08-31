use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model_control::{
    AttemptHealthProjection, AttemptTelemetryInput, HumanModelPreferencePolicy,
    ModelCatalogueEntry, ModelCatalogueSnapshot, ModelControlError, ModelQueryReceipt, ModelRole,
    ModelSelectionReceipt, ZeroModelExecutionCounters,
};

/// Stable schema identity for the ControlBoard-consumable Swarm read model.
pub const SWARM_CONTROLBOARD_PROJECTION_VERSION: &str =
    "eliot.agent-swarm-controlboard-projection/v1";

pub(super) const MAX_ATTEMPTS: usize = 4096;

/// Composition-owned inputs. `None` means that the provider was unavailable;
/// an empty collection means that the provider answered with an empty current
/// denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmControlBoardProjectionInput {
    pub catalogue: Option<ModelCatalogueSnapshot>,
    pub preferences: Option<HumanModelPreferencePolicy>,
    pub attempt_telemetry: Option<Vec<SwarmAttemptTelemetryInput>>,
}

/// Attempt telemetry bound to the exact A-02 model-selection receipt that was
/// used before dispatch. The receipt remains candidate-only and grants no
/// process or route authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmAttemptTelemetryInput {
    pub selection: ModelSelectionReceipt,
    pub telemetry: AttemptTelemetryInput,
}

/// Provider whose absence must remain an explicit plan gap.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmProjectionProvider {
    ModelCatalogue,
    HumanPreferences,
    AttemptTelemetry,
}

/// Missing or empty coverage that a surface must not render as healthy state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum SwarmProjectionGap {
    ProviderUnavailable { provider: SwarmProjectionProvider },
    CatalogueEmpty,
}

/// Account-scoped catalogue projection with exact source identity and query
/// receipt. Non-dispatchable rows remain present with typed blockers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmCatalogueProjection {
    pub snapshot_id: String,
    pub account_scope: String,
    pub collector_identity: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub current: bool,
    pub query: ModelQueryReceipt,
}

/// Relationship between an attempt's exact selection receipt and the current
/// catalogue and Human policy providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmAttemptSelectionBinding {
    ExactCurrent,
    CatalogueUnavailable,
    PreferencesUnavailable,
    StaleOrMismatched,
}

/// ControlBoard-consumable attempt row with exact selection and health identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmAttemptProjection {
    pub selection_id: String,
    pub selection_digest: String,
    pub account_scope: String,
    pub role: ModelRole,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub preference_policy_digest: String,
    pub selected: ModelCatalogueEntry,
    pub selection_binding: SwarmAttemptSelectionBinding,
    pub health: AttemptHealthProjection,
}

/// Maximum interpretation permitted for this A-02 projection.
///
/// The only v1 value means that A-08 has not authenticated the viewer, filtered
/// the rows by role/privacy, admitted a route, granted process control, approved
/// redispatch, completed a task, or decided finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmProjectionAuthorityCeiling {
    UnfilteredReadModelOnly,
}

/// One deterministic, bounded operator read model. A-08 may render this value
/// only after its own authenticated role/privacy filtering and command checks;
/// this A-02 contract does not authenticate a Human or forward commands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmControlBoardProjection {
    pub schema_version: String,
    pub observed_at_unix_ms: u64,
    pub catalogue: Option<SwarmCatalogueProjection>,
    pub preferences: Option<HumanModelPreferencePolicy>,
    pub attempts: Vec<SwarmAttemptProjection>,
    pub gaps: Vec<SwarmProjectionGap>,
    pub execution: ZeroModelExecutionCounters,
    pub authority_ceiling: SwarmProjectionAuthorityCeiling,
}

/// Fail-closed projection errors. Provider absence is represented in the view,
/// while malformed or cross-scope provider state is rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SwarmControlBoardProjectionError {
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
    #[error("invalid Swarm ControlBoard projection field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate Swarm ControlBoard projection identity: {0}")]
    DuplicateIdentity(&'static str),
}
