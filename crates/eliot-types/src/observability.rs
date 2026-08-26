//! Durable non-truth observability contracts.

use crate::{
    MemoryInfluenceAckInput, MemoryInfluenceTrace, MemoryRevision, ProjectId, SessionId, TaskId,
    WriteId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

pub const OBSERVABILITY_SCHEMA_VERSION: &str = "eliot-observability-v1";
pub const MEMORY_DELIVERY_GRANT_SCHEMA_VERSION: &str = "eliot-memory-delivery-grant-v1";

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityKind {
    MemoryInfluenceTrace,
    InjectionReceipt,
    MemoryGrantOffer,
    ActivationTrace,
    PredictionRecord,
    ExamRecord,
}

impl ObservabilityKind {
    pub const fn table_name(self) -> &'static str {
        match self {
            Self::MemoryInfluenceTrace => "memory_influence_trace",
            Self::InjectionReceipt => "injection_receipt",
            Self::MemoryGrantOffer => "memory_grant_offer",
            Self::ActivationTrace => "activation_trace",
            Self::PredictionRecord => "prediction_record",
            Self::ExamRecord => "exam_record",
        }
    }
}

/// Private durable authority behind a public opaque memory-grant token.
///
/// The public token contains only a random grant id, expiry, and MAC. The
/// prior fingerprint and guidance digest stay in the canonical store so an
/// agent never needs an exact source handle to cite the offered lesson.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryGrantOfferRecord {
    pub schema_version: String,
    pub grant_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub packet_id: String,
    #[schemars(with = "u64")]
    pub packet_revision_fence: MemoryRevision,
    #[schemars(with = "u64")]
    pub task_memory_revision: MemoryRevision,
    pub task_contract_ref: String,
    pub auth_generation: String,
    pub prior_fingerprint: String,
    pub guidance_hash: String,
    pub offer_write_id: WriteId,
    pub token_hash: String,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub offered_at: OffsetDateTime,
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

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MemoryInfluenceToolInput {
    Full(MemoryInfluenceTraceWriteInput),
    Ack(MemoryInfluenceAckInput),
}

#[allow(clippy::expect_used)]
pub fn memory_influence_trace_write_input_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(MemoryInfluenceToolInput))
        .expect("MemoryInfluenceToolInput schema must serialize");
    schema
        .as_object_mut()
        .expect("MemoryInfluenceToolInput schema root must be an object")
        .insert("type".to_owned(), Value::String("object".to_owned()));
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_influence_tool_schema_has_mcp_object_root() {
        let schema = memory_influence_trace_write_input_schema();
        assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
        assert!(
            schema.get("anyOf").and_then(Value::as_array).is_some(),
            "the full and acknowledgement input variants must remain represented"
        );
    }
}
