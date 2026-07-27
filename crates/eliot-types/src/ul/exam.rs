use crate::{AgentHostId, ProjectId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UlExamQuestionKind {
    Blast,
    Invariant,
    Entrypoint,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlExamQuestion {
    pub question_id: String,
    pub project_id: ProjectId,
    pub subsystem_concept_id: String,
    pub kind: UlExamQuestionKind,
    pub prompt: String,
    pub ground_truth_refs: Vec<String>,
    pub ground_truth_values: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlExamAnswer {
    pub question_id: String,
    pub answer_values: Vec<String>,
    pub cited_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlExamGrade {
    pub question_id: String,
    pub precision_num: u32,
    pub precision_den: u32,
    pub recall_num: u32,
    pub recall_den: u32,
    pub f1_milli: u16,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlExamRecord {
    pub exam_id: String,
    pub project_id: ProjectId,
    pub route: String,
    pub cold_input_refs: Vec<String>,
    pub questions: Vec<UlExamQuestion>,
    pub answers: Vec<UlExamAnswer>,
    pub grades: Vec<UlExamGrade>,
    pub subsystem_scores_milli: Vec<(String, u16)>,
    pub dirty_capsule_refs: Vec<String>,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UlReasoningRoute {
    Claude,
    Antigravity,
}

impl UlReasoningRoute {
    #[must_use]
    pub const fn host(self) -> AgentHostId {
        match self {
            Self::Claude => AgentHostId::Claude,
            Self::Antigravity => AgentHostId::Antigravity,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Antigravity => "antigravity",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlReasoningRequest {
    pub idempotency_key: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub route: UlReasoningRoute,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub prompt: String,
    pub output_schema: Value,
    pub max_input_bytes: u32,
    pub max_output_units: u32,
    pub timeout_seconds: u64,
}
