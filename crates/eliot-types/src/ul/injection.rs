use crate::{CueKind, MemoryInfluenceClass, ProjectId, SessionId, TaskId, WriteId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

pub const PENDING_INJECTION_BATCH_SCHEMA_VERSION: &str = "eliot-pending-injection-batch-v1";
pub const MAX_DURABLE_PENDING_INJECTIONS_PER_SESSION: usize = 256;

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

/// Stable identity for one exact pending-delivery item. The same identity is
/// used by enqueue persistence and receipt cleanup, so receipt replay can
/// remove only the item it actually delivered.
#[must_use]
pub fn pending_injection_write_id(
    project_id: ProjectId,
    session_id: SessionId,
    item_ref: &str,
    source_fingerprint: &str,
) -> WriteId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"eliot-pending-injection-v1");
    for part in [
        project_id.as_uuid().as_bytes().as_slice(),
        session_id.as_uuid().as_bytes().as_slice(),
        item_ref.as_bytes(),
        source_fingerprint.as_bytes(),
    ] {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingInjectionBatch {
    pub schema_version: String,
    pub write_id: WriteId,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub session_id: SessionId,
    pub items: Vec<PendingInjectionItem>,
    pub input_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl PendingInjectionBatch {
    pub fn new(
        project_id: ProjectId,
        task_id: Option<TaskId>,
        session_id: SessionId,
        items: Vec<PendingInjectionItem>,
        created_at: OffsetDateTime,
    ) -> Result<Self, serde_json::Error> {
        let identity = serde_json::to_vec(&(
            PENDING_INJECTION_BATCH_SCHEMA_VERSION,
            project_id,
            task_id,
            session_id,
            &items,
        ))?;
        let input_hash = blake3::hash(&identity).to_hex().to_string();
        let write_id = pending_injection_batch_write_id(project_id, session_id, &input_hash);
        Ok(Self {
            schema_version: PENDING_INJECTION_BATCH_SCHEMA_VERSION.to_owned(),
            write_id,
            project_id,
            task_id,
            session_id,
            items,
            input_hash,
            created_at,
        })
    }
}

#[must_use]
pub fn pending_injection_batch_write_id(
    project_id: ProjectId,
    session_id: SessionId,
    input_hash: &str,
) -> WriteId {
    pending_injection_write_id(
        project_id,
        session_id,
        "pending-injection-batch",
        input_hash,
    )
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
    #[serde(default)]
    pub policy_reason: Option<String>,
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
