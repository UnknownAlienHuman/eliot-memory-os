use crate::{CompilePacketL3Request, MaterialPacketFrame, MemoryExposureMode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CompilePacketToolInput {
    #[serde(flatten)]
    pub request: CompilePacketL3Request,
    #[serde(default)]
    pub material_frame: Option<MaterialPacketFrame>,
    #[serde(default)]
    pub memory_mode: Option<MemoryExposureMode>,
}

#[allow(clippy::expect_used)]
pub fn compile_packet_input_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(CompilePacketToolInput))
        .expect("CompilePacketToolInput schema must serialize")
}

pub fn compile_packet_minimal_example() -> Value {
    json!({
        "project_id": "00000000-0000-7000-8000-000000000001",
        "task_id": "task-example",
        "goal": "Describe the required change",
        "candidate_handles": [],
        "max_tokens": 1200,
        "memory_mode": "include_case_candidates",
        "material_frame": {
            "acceptance_items": [],
            "environment": [],
            "active_plan": [],
            "completed_work": [],
            "killed_paths": [],
            "causal_bridge": [],
            "negative_memory_checked": false,
            "exact_load_bearing_atoms": [],
            "cheapest_discriminative_probes": [],
            "responsibility_contour_route_refs": [],
            "next_allowed_action": "inspect the responsible boundary",
            "expected_observable": "replace with a machine-checkable observation",
            "verifier": "replace with a registered verifier",
            "stop_condition": "stop on verifier failure",
            "tool_schema_bytes_visible": 0,
            "instruction_hotset_size": 0
        }
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvalidField {
    pub field: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolInputErrorData {
    pub code: String,
    pub missing: Vec<String>,
    pub invalid: Vec<InvalidField>,
    pub minimal_valid_example: Value,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid tool input")]
pub struct ToolInputError {
    pub data: ToolInputErrorData,
}
