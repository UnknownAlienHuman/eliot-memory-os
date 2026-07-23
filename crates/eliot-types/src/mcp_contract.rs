use crate::{CompilePacketL3Request, CueBinding, MaterialPacketFrame, MemoryExposureMode};
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

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCandidateSubmitInput {
    pub project_id: String,
    pub task_id: String,
    pub write_id: String,
    pub topic: String,
    pub statement: String,
    #[serde(default)]
    pub where_applicable: Vec<String>,
    #[serde(default)]
    pub where_not_applicable: Vec<String>,
    #[serde(default)]
    pub negative_constraints: Vec<String>,
    pub provenance_refs: Vec<String>,
    pub freshness_rule: String,
    #[serde(default)]
    pub cue_bindings: Vec<CueBinding>,
    #[serde(default)]
    pub auto_bind: Option<bool>,
    pub expected_reuse_note: String,
    #[serde(default)]
    pub curation: Option<AgentCandidateCurationInput>,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AgentCandidateCurationInput {
    pub handle: String,
    #[serde(default)]
    pub duplicate_of: Option<String>,
    #[serde(default)]
    pub semantic_duplicate_of: Option<String>,
    #[serde(default)]
    pub semantic_equivalence_verified: bool,
    #[serde(default)]
    pub scope_match: Option<bool>,
    #[serde(default)]
    pub wrong_scope_for: Vec<String>,
    #[serde(default)]
    pub utility_score: Option<u8>,
    #[serde(default)]
    pub utility_delta: Option<i16>,
    #[serde(default)]
    pub repeat_count: Option<u16>,
    #[serde(default)]
    pub repeated_with: Vec<String>,
    #[serde(default)]
    pub evidence_sufficient: Option<bool>,
    #[serde(default)]
    pub superseded_by: Option<String>,
    #[serde(default)]
    pub stale_reason_ref: Option<String>,
    #[serde(default)]
    pub protected: bool,
    #[serde(default)]
    pub current_truth: bool,
    #[serde(default)]
    pub audit_required: bool,
    #[serde(default)]
    pub reopen_condition_met: Option<bool>,
    #[serde(default)]
    pub unsafe_instruction: bool,
    #[serde(default)]
    pub unsafe_evidence_refs: Vec<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub lifecycle: Option<String>,
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub counterevidence_refs: Vec<String>,
}

#[allow(clippy::expect_used)]
pub fn agent_candidate_input_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(AgentCandidateSubmitInput))
        .expect("AgentCandidateSubmitInput schema must serialize")
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
