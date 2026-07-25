use crate::{CoChangeEdge, ProjectId, SessionId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const ACTIVATION_SCALE: u16 = 1000;
pub const ACTIVATION_THRESHOLD: u16 = 350;

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ActivationEdgeKind {
    CardCovers,
    CapsuleCovers,
    ConceptImplementedBy,
    CoChange,
    StaticDependency,
    ConceptDependsOn,
    Supports,
    VerifiedBy,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ActivationNode {
    pub node_ref: String,
    pub score_milli: u16,
    pub depth: u8,
    pub via: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SuppressedActivation {
    pub node_ref: String,
    pub score_milli: u16,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ActivationTrace {
    pub trace_id: String,
    pub project_id: ProjectId,
    pub session_id: SessionId,
    pub task_id: Option<TaskId>,
    pub seed_refs: Vec<String>,
    pub enabled_edge_count: u32,
    pub depth_limit: u8,
    pub fanout_cap: u8,
    pub threshold_milli: u16,
    pub activated: Vec<ActivationNode>,
    pub suppressed: Vec<SuppressedActivation>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlActivationGraphEdge {
    pub from_ref: String,
    pub to_ref: String,
    pub kind: ActivationEdgeKind,
}

#[derive(Clone, Debug, Default, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlActivationGraphRows {
    #[serde(default)]
    pub co_change: Vec<CoChangeEdge>,
    #[serde(default)]
    pub relations: Vec<UlActivationGraphEdge>,
}
