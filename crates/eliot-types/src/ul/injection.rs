use crate::{CueKind, MemoryInfluenceClass, SessionId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ObservedCue {
    pub kind: CueKind,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingInjectionItem {
    pub item_ref: String,
    pub record_kind: String,
    pub preview: String,
    pub payload: Option<Value>,
    pub source_fingerprint: String,
    pub fired_cues: Vec<ObservedCue>,
    pub negative_memory: bool,
    pub invariant: bool,
    pub token_estimate: u32,
    #[serde(default)]
    pub activation_trace_ref: Option<String>,
    #[serde(default)]
    pub activation_score_milli: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UlFiredBlock {
    pub items: Vec<UlFiredItem>,
    pub overflow: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UlFiredItem {
    pub item_ref: String,
    pub kind: String,
    pub line: String,
    pub uri: String,
    pub payload: Option<Value>,
    #[serde(default)]
    pub activation_trace_ref: Option<String>,
    #[serde(default)]
    pub activation_score_milli: Option<u16>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct InjectionReceipt {
    pub injection_id: String,
    pub session_id: SessionId,
    pub task_id: Option<TaskId>,
    pub surface: String,
    pub item_ref: String,
    pub render_form: String,
    pub fired_cues: Vec<ObservedCue>,
    pub token_cost: u32,
    pub source_fingerprint: String,
    pub outcome: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct MemoryInfluenceAckInput {
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub write_id: Option<String>,
    pub memory_handle: String,
    pub influence_class: MemoryInfluenceClass,
    #[serde(default)]
    pub downstream_outcome_ref: Option<String>,
}
