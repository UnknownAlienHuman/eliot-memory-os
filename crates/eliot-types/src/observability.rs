//! Durable non-truth observability contracts.

use crate::{MemoryInfluenceTrace, ProjectId, SessionId, TaskId, WriteId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

pub const OBSERVABILITY_SCHEMA_VERSION: &str = "eliot-observability-v1";

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityKind {
    MemoryInfluenceTrace,
    InjectionReceipt,
    ActivationTrace,
    PredictionRecord,
    ExamRecord,
}

impl ObservabilityKind {
    pub const fn table_name(self) -> &'static str {
        match self {
            Self::MemoryInfluenceTrace => "memory_influence_trace",
            Self::InjectionReceipt => "injection_receipt",
            Self::ActivationTrace => "activation_trace",
            Self::PredictionRecord => "prediction_record",
            Self::ExamRecord => "exam_record",
        }
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct ObservabilityWriteEnvelope {
    pub schema_version: String,
    pub write_id: WriteId,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
    pub kind: ObservabilityKind,
    pub record_id: String,
    pub payload: Value,
    pub input_hash: String,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityWriteStatus {
    Committed,
    IdempotentReplay,
    Rejected,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct ObservabilityWriteReceipt {
    pub write_id: WriteId,
    pub record_id: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub kind: ObservabilityKind,
    pub input_hash: String,
    pub status: ObservabilityWriteStatus,
    pub rejected_reason: Option<String>,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceTraceWriteInput {
    pub project_id: String,
    pub write_id: String,
    pub trace: MemoryInfluenceTrace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryInfluenceTraceWriteResult {
    pub trace: MemoryInfluenceTrace,
    pub observability_receipt: ObservabilityWriteReceipt,
}

#[allow(clippy::expect_used)]
pub fn memory_influence_trace_write_input_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(MemoryInfluenceTraceWriteInput))
        .expect("MemoryInfluenceTraceWriteInput schema must serialize")
}
