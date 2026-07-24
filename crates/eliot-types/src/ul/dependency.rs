use crate::{ProjectId, PyramidTargetKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UlDependencyKind {
    File,
    Claim,
    Decision,
    Edge,
    Report,
}

#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct UlDependencyRef {
    pub kind: UlDependencyKind,
    pub key: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlReverseDependencyRow {
    pub project_id: ProjectId,
    pub dependency: UlDependencyRef,
    pub target_kind: PyramidTargetKind,
    pub target_id: String,
    pub build_id: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UlDirtyReason {
    pub dependency: UlDependencyRef,
    pub expected_fingerprint: Option<String>,
    pub observed_fingerprint: Option<String>,
    pub event_ref: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlArtifactDirtyState {
    pub project_id: ProjectId,
    pub target_kind: PyramidTargetKind,
    pub target_id: String,
    pub build_id: String,
    pub dirty: bool,
    pub reasons: Vec<UlDirtyReason>,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub first_dirty_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlDependencyRebuildReport {
    pub project_id: ProjectId,
    pub artifacts_indexed: u32,
    pub dependencies_indexed: u32,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlMaintenanceReport {
    pub project_id: ProjectId,
    pub requested: u16,
    pub rebuilt: Vec<String>,
    pub failed: Vec<String>,
    pub remaining_dirty: u32,
}
