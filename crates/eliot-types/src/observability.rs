//! Durable non-truth observability contracts.

use crate::{
    MemoryInfluenceAckInput, MemoryInfluenceClass, MemoryInfluenceTrace, MemoryRevision, ProjectId,
    SessionId, TaskId, WriteId,
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

// Durable non-truth observability write envelope.
//
// The envelope fields are closed: an unknown envelope key cannot ride along
// with an accepted observability write. `payload` itself is a protected typed
// payload whose owner re-decodes it into the exact record kind named by
// `kind` (`MemoryGrantOfferRecord`, `InjectionReceipt`,
// `MemoryInfluenceTrace`); it is not inert data, and a `Value` intermediate
// cannot prove the absence of duplicate keys in the original bytes.
//
// The prose here is deliberately a plain comment: this type derives
// `JsonSchema`, and a doc comment would become the published schema
// `description`, which the wire compatibility boundary must not change.
#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityWriteEnvelope {
    #[serde(deserialize_with = "deserialize_observability_schema_version")]
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

/// Bounded refusal for an observability envelope schema version this build
/// does not own. The message is fixed and never echoes the received value.
fn unsupported_observability_schema_version<E>(expected: &str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

fn deserialize_observability_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == OBSERVABILITY_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_observability_schema_version(
            OBSERVABILITY_SCHEMA_VERSION,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityWriteStatus {
    Committed,
    IdempotentReplay,
    Rejected,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceTraceWriteResult {
    pub trace: MemoryInfluenceTrace,
    pub observability_receipt: ObservabilityWriteReceipt,
}

// Accepted `memory_influence_trace` tool argument union.
//
// The wire shape is unchanged: it stays an untagged two-variant object union
// and the published MCP schema is still generated from this declaration, so
// no public tag is introduced. Only *decoding* changes. The derived untagged
// form used to try `Full`, then silently retry `Ack` after a lossy failure,
// so an argument object that carried both shapes — including one whose
// `trace` was malformed — decoded as an accepted acknowledgement and dropped
// the full influence trace. This decoder instead inspects the exact key set
// once: `trace` marks the full shape, `memory_handle` marks the
// acknowledgement shape, and both or neither is a mixed/ambiguous argument
// object that is refused.
//
// The prose here is deliberately a plain comment: this type derives
// `JsonSchema`, and a doc comment would become the published MCP schema
// `description`, which the wire compatibility boundary must not change.
#[derive(Clone, Debug, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum MemoryInfluenceToolInput {
    Full(MemoryInfluenceTraceWriteInput),
    Ack(MemoryInfluenceAckInput),
}

impl<'de> Deserialize<'de> for MemoryInfluenceToolInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(MemoryInfluenceToolInputVisitor)
    }
}

/// Single-pass decoder for [`MemoryInfluenceToolInput`].
///
/// A repeated key is refused before any value is stored, and a key outside the
/// selected variant is refused before the typed union is returned. The two
/// accepted shapes keep their own per-variant key policy: the full shape is
/// closed (`MemoryInfluenceTraceWriteInput::deny_unknown_fields`), while the
/// acknowledgement shape keeps the open key set its owner
/// `crates/eliot-types/src/ul/injection.rs::MemoryInfluenceAckInput` declares.
struct MemoryInfluenceToolInputVisitor;

impl<'de> serde::de::Visitor<'de> for MemoryInfluenceToolInputVisitor {
    type Value = MemoryInfluenceToolInput;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a memory influence trace write or acknowledgement object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut project_id: Option<String> = None;
        let mut write_id: Option<String> = None;
        let mut trace: Option<MemoryInfluenceTrace> = None;
        let mut memory_handle: Option<String> = None;
        let mut influence_class: Option<MemoryInfluenceClass> = None;
        let mut downstream_outcome_ref: Option<String> = None;
        let mut saw_acknowledgement_key = false;
        let mut saw_foreign_key = false;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "project_id" => set_once(&mut project_id, map.next_value()?, "project_id")?,
                "write_id" => set_once(&mut write_id, map.next_value()?, "write_id")?,
                "trace" => set_once(&mut trace, map.next_value()?, "trace")?,
                "memory_handle" => {
                    set_once(&mut memory_handle, map.next_value()?, "memory_handle")?;
                    saw_acknowledgement_key = true;
                }
                "influence_class" => {
                    set_once(&mut influence_class, map.next_value()?, "influence_class")?;
                    saw_acknowledgement_key = true;
                }
                "downstream_outcome_ref" => {
                    set_once(
                        &mut downstream_outcome_ref,
                        map.next_value()?,
                        "downstream_outcome_ref",
                    )?;
                    saw_acknowledgement_key = true;
                }
                _ => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    saw_foreign_key = true;
                }
            }
        }

        let acknowledgement_shape = memory_handle.is_some() || saw_acknowledgement_key;
        match (trace.is_some(), acknowledgement_shape) {
            (true, true) => Err(serde::de::Error::custom(
                "ambiguous memory influence argument: it carries both the full trace shape and the acknowledgement shape",
            )),
            (false, false) => Err(serde::de::Error::custom(
                "unrecognised memory influence argument: it carries neither the full trace shape nor the acknowledgement shape",
            )),
            (true, false) => {
                if saw_foreign_key {
                    return Err(serde::de::Error::custom(
                        "unknown field in the full memory influence trace write argument",
                    ));
                }
                Ok(MemoryInfluenceToolInput::Full(
                    MemoryInfluenceTraceWriteInput {
                        project_id: required(project_id, "project_id")?,
                        write_id: required(write_id, "write_id")?,
                        trace: required(trace, "trace")?,
                    },
                ))
            }
            (false, true) => Ok(MemoryInfluenceToolInput::Ack(MemoryInfluenceAckInput {
                project_id,
                write_id,
                memory_handle: required(memory_handle, "memory_handle")?,
                influence_class: required(influence_class, "influence_class")?,
                downstream_outcome_ref,
            })),
        }
    }
}

/// Store a decoded field exactly once, refusing a repeated key first.
fn set_once<T, E>(slot: &mut Option<T>, value: T, key: &'static str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if slot.is_some() {
        return Err(E::duplicate_field(key));
    }
    *slot = Some(value);
    Ok(())
}

fn required<T, E>(value: Option<T>, field: &'static str) -> Result<T, E>
where
    E: serde::de::Error,
{
    value.ok_or_else(|| E::missing_field(field))
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
