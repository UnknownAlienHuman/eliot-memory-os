use crate::{CompilePacketL3Request, CueBinding, MaterialPacketFrame, MemoryExposureMode};
use schemars::JsonSchema;
use serde::{
    Deserialize, Serialize,
    de::{Error as _, MapAccess, Visitor},
};
use serde_json::{Map, Value, json};
use std::fmt;

/// Wire/schema revision for the capture-first `eliot.observe` surface.
///
/// This is deliberately separate from the legacy candidate-submit schema. The
/// legacy payload and its cue-page inputs remain v1-compatible, including
/// `AgentCandidateSubmitInput.expected_reuse_note: String` and the page-id
/// hash material for old `Some(note)` cue bindings.
pub const OBSERVE_INPUT_SCHEMA_VERSION: &str = "eliot.observe-v1";

#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct CompilePacketToolInput {
    #[serde(flatten)]
    pub request: CompilePacketL3Request,
    #[serde(default)]
    pub material_frame: Option<MaterialPacketFrame>,
    #[serde(default)]
    pub memory_mode: Option<MemoryExposureMode>,
}

// Explicit decoder for the one permitted flat wire shape: the wrapper keys
// plus the flattened `CompilePacketL3Request` keys, with no nested `request`
// object and no new discriminator. A derived `flatten` decoder buffers the
// remaining keys into a map and would silently keep the last duplicate, so
// this decoder rejects duplicate keys while reading the raw map, before any
// insertion, and rejects unknown keys before typed output. Request keys
// mirror `CompilePacketL3Request` (`memory.rs`, #937-owned); a shape change
// there invalidates this decoder. Serialization and the published schema
// still derive from the declaration above.
//
// The prose here is deliberately a plain comment: this type derives
// `JsonSchema`, and a doc comment would become the published schema
// `description`, which the wire compatibility boundary must not change.
impl<'de> Deserialize<'de> for CompilePacketToolInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CompilePacketToolInputVisitor)
    }
}

struct CompilePacketToolInputVisitor;

const COMPILE_PACKET_TOOL_FIELDS: &[&str] = &[
    "project_id",
    "task_id",
    "goal",
    "candidate_handles",
    "max_tokens",
    "material_frame",
    "memory_mode",
];

impl<'de> Visitor<'de> for CompilePacketToolInputVisitor {
    type Value = CompilePacketToolInput;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a flat compile-packet tool object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut request_keys = Map::new();
        let mut material_frame: Option<MaterialPacketFrame> = None;
        let mut memory_mode: Option<MemoryExposureMode> = None;
        let mut material_frame_seen = false;
        let mut memory_mode_seen = false;
        let mut project_id_seen = false;
        let mut task_id_seen = false;
        let mut goal_seen = false;
        let mut candidate_handles_seen = false;
        let mut max_tokens_seen = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "material_frame" => {
                    if material_frame_seen {
                        return Err(A::Error::duplicate_field("material_frame"));
                    }
                    material_frame_seen = true;
                    material_frame = map.next_value()?;
                }
                "memory_mode" => {
                    if memory_mode_seen {
                        return Err(A::Error::duplicate_field("memory_mode"));
                    }
                    memory_mode_seen = true;
                    memory_mode = map.next_value()?;
                }
                "project_id" => {
                    if project_id_seen {
                        return Err(A::Error::duplicate_field("project_id"));
                    }
                    project_id_seen = true;
                    request_keys.insert(key, map.next_value()?);
                }
                "task_id" => {
                    if task_id_seen {
                        return Err(A::Error::duplicate_field("task_id"));
                    }
                    task_id_seen = true;
                    request_keys.insert(key, map.next_value()?);
                }
                "goal" => {
                    if goal_seen {
                        return Err(A::Error::duplicate_field("goal"));
                    }
                    goal_seen = true;
                    request_keys.insert(key, map.next_value()?);
                }
                "candidate_handles" => {
                    if candidate_handles_seen {
                        return Err(A::Error::duplicate_field("candidate_handles"));
                    }
                    candidate_handles_seen = true;
                    request_keys.insert(key, map.next_value()?);
                }
                "max_tokens" => {
                    if max_tokens_seen {
                        return Err(A::Error::duplicate_field("max_tokens"));
                    }
                    max_tokens_seen = true;
                    request_keys.insert(key, map.next_value()?);
                }
                _ => {
                    return Err(A::Error::unknown_field(&key, COMPILE_PACKET_TOOL_FIELDS));
                }
            }
        }
        let request = CompilePacketL3Request::deserialize(Value::Object(request_keys))
            .map_err(A::Error::custom)?;
        Ok(CompilePacketToolInput {
            request,
            material_frame,
            memory_mode,
        })
    }
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
            "expected_observable": "verifier:cargo test --workspace=pass",
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
    let mut schema = serde_json::to_value(schemars::schema_for!(AgentCandidateSubmitInput))
        .expect("AgentCandidateSubmitInput schema must serialize");
    // CueBinding is optional-note for capture-first pages, but the legacy
    // candidate-submit wire remains strict and requires a semantic note.
    for definitions_key in ["$defs", "definitions"] {
        let Some(definitions) = schema
            .get_mut(definitions_key)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let Some(cue_binding) = definitions
            .get_mut("CueBinding")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let required = cue_binding
            .entry("required")
            .or_insert_with(|| json!([]))
            .as_array_mut();
        if let Some(required) = required
            && !required.iter().any(|value| value == "expected_reuse_note")
        {
            required.push(json!("expected_reuse_note"));
        }
    }
    schema
}

/// Capture-first observation input. The server supplies the trusted session,
/// project and task context; callers cannot select an arbitrary project.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveInput {
    /// Natural language or structured JSON observation content.
    pub text_or_structured_payload: Value,
    /// Optional first-pass classification hint. Classification never grants
    /// promotion or task authority.
    #[serde(default, alias = "kind")]
    pub hint: ObserveHint,
    /// Optional task selector. An absent task keeps the capture cold.
    #[serde(default)]
    pub task_id: Option<String>,
    /// Paths/entities affected by the observation.
    #[serde(default)]
    pub affected_resources: Vec<String>,
    /// Exact source/evidence handles, when available.
    #[serde(default)]
    pub source_handles: Vec<String>,
    /// Optional agent-supplied reuse guidance. Automatically generated cue
    /// bindings retain `None` when this is omitted.
    #[serde(default)]
    pub expected_reuse_note: Option<String>,
    /// Optional retry identity. When omitted, the server allocates one.
    #[serde(default)]
    pub write_id: Option<String>,
    /// Explicit schema revision for callers that pin the wire shape.
    #[serde(default = "default_observe_schema_version")]
    pub schema_version: String,
}

fn default_observe_schema_version() -> String {
    OBSERVE_INPUT_SCHEMA_VERSION.to_owned()
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserveHint {
    Observation,
    Decision,
    Failure,
    Outcome,
    Unknown,
    ReuseCandidate,
    #[default]
    Auto,
}

#[allow(clippy::expect_used)]
pub fn observe_input_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(ObserveInput))
        .expect("ObserveInput schema must serialize")
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
