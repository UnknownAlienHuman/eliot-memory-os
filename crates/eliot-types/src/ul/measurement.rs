use crate::{ProjectId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlTaskLedger {
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub injected_tokens: u64,
    pub read_tool_input_bytes: u64,
    pub read_tool_output_bytes: u64,
    pub expanded_injected_handles: u32,
    pub acknowledged_items: u32,
    pub first_mutation_seen: bool,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlUseReport {
    pub project_id: ProjectId,
    pub tasks: u32,
    pub injected_tokens: u64,
    pub exploration_tokens: u64,
    pub acknowledged_fraction: f64,
    pub expanded_after_injection_fraction: f64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct UlLedgerDelta {
    pub injected_tokens: u64,
    pub read_tool_input_bytes: u64,
    pub read_tool_output_bytes: u64,
    pub expanded_injected_handles: u32,
    pub acknowledged_items: u32,
    pub first_mutation_seen: bool,
}
