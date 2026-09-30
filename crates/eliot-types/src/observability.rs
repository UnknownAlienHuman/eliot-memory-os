//! Durable non-truth observability contracts.

use crate::{
    ActivationTrace, InjectionReceipt, MemoryInfluenceAckInput, MemoryInfluenceClass,
    MemoryInfluenceTrace, MemoryRevision, PredictionRecord, ProjectId, SessionId, TaskId,
    UlExamRecord, WriteId, ul::injection::MEMORY_INFLUENCE_ACK_FIELDS,
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
// with an accepted observability write, and a repeated key is refused before
// any value is stored. `payload` is a protected typed payload under its actual
// owner, not inert data. The decoder reads the whole envelope once and then
// re-decodes `payload` through the owner type that `kind` names — the record
// type the store itself later persists — so an observation that does not carry
// its record kind is refused here rather than reaching the store as an untyped
// blob. The published field stays the `Value` it has always been, so the wire
// spelling and the `input_hash` digest material are byte-identical.
//
// The prose here is deliberately a plain comment: this type derives
// `JsonSchema`, and a doc comment would become the published schema
// `description`, which the wire compatibility boundary must not change.
#[derive(Clone, Debug, JsonSchema, Serialize)]
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

/// The exact declared field set of [`ObservabilityWriteEnvelope`], reused as the
/// `deserialize_struct` hint so a refusal names the owning contract rather than
/// a second, drifting list of field names.
const OBSERVABILITY_WRITE_ENVELOPE_FIELDS: &[&str] = &[
    "schema_version",
    "write_id",
    "project_id",
    "task_id",
    "session_id",
    "kind",
    "record_id",
    "payload",
    "input_hash",
    "created_at",
];

impl<'de> Deserialize<'de> for ObservabilityWriteEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "ObservabilityWriteEnvelope",
            OBSERVABILITY_WRITE_ENVELOPE_FIELDS,
            ObservabilityWriteEnvelopeVisitor,
        )
    }
}

/// Single-pass decoder for [`ObservabilityWriteEnvelope`].
///
/// A repeated key is refused before any value is stored, an unrecognised key is
/// refused against the declared field set before the typed envelope is
/// returned, and `payload` is refused unless the record kind the envelope names
/// actually accepts it.
struct ObservabilityWriteEnvelopeVisitor;

impl<'de> serde::de::Visitor<'de> for ObservabilityWriteEnvelopeVisitor {
    type Value = ObservabilityWriteEnvelope;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a durable observability write envelope")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut schema_version: Option<String> = None;
        let mut write_id: Option<WriteId> = None;
        let mut project_id: Option<ProjectId> = None;
        let mut task_id: Option<Option<TaskId>> = None;
        let mut session_id: Option<Option<SessionId>> = None;
        let mut kind: Option<ObservabilityKind> = None;
        let mut record_id: Option<String> = None;
        let mut payload: Option<Value> = None;
        let mut input_hash: Option<String> = None;
        let mut created_at: Option<OffsetDateTime> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "schema_version" => {
                    let value = map.next_value::<String>()?;
                    check_observability_schema_version(&value)?;
                    set_once(&mut schema_version, value, "schema_version")?;
                }
                "write_id" => set_once(&mut write_id, map.next_value()?, "write_id")?,
                "project_id" => set_once(&mut project_id, map.next_value()?, "project_id")?,
                "task_id" => set_once(&mut task_id, map.next_value()?, "task_id")?,
                "session_id" => set_once(&mut session_id, map.next_value()?, "session_id")?,
                "kind" => set_once(&mut kind, map.next_value()?, "kind")?,
                "record_id" => set_once(&mut record_id, map.next_value()?, "record_id")?,
                "payload" => set_once(&mut payload, map.next_value()?, "payload")?,
                "input_hash" => set_once(&mut input_hash, map.next_value()?, "input_hash")?,
                "created_at" => {
                    let value = map.next_value::<String>()?;
                    let parsed = OffsetDateTime::parse(
                        &value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_err(serde::de::Error::custom)?;
                    set_once(&mut created_at, parsed, "created_at")?;
                }
                _ => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    return Err(serde::de::Error::unknown_field(
                        key.as_str(),
                        OBSERVABILITY_WRITE_ENVELOPE_FIELDS,
                    ));
                }
            }
        }

        let envelope = ObservabilityWriteEnvelope {
            schema_version: required(schema_version, "schema_version")?,
            write_id: required(write_id, "write_id")?,
            project_id: required(project_id, "project_id")?,
            task_id: task_id.unwrap_or_default(),
            session_id: session_id.unwrap_or_default(),
            kind: required(kind, "kind")?,
            record_id: required(record_id, "record_id")?,
            payload: required(payload, "payload")?,
            input_hash: required(input_hash, "input_hash")?,
            created_at: required(created_at, "created_at")?,
        };

        bind_observability_payload(envelope.kind, &envelope.payload)
            .map_err(serde::de::Error::custom)?;

        Ok(envelope)
    }
}

/// Refuse a payload that is not the record type its envelope's `kind` names.
///
/// This is the owner binding, not a shape approximation: each arm is the owning
/// record type's own `Deserialize`, so an unknown key, a duplicate key, a wrong
/// variant or a missing protected field inside the payload is refused by the
/// owner that defines it. The six kinds resolve to six existing owner decoders —
/// no new record type and no new decoder framework is introduced here, and
/// `MemoryGrantOfferRecord` keeps its grant/token semantics untouched.
///
/// Residual, owned by the producers rather than by this leaf: the published
/// `payload` field is still the `Value` every producer constructs through
/// `serde_json::to_value`, because re-typing it would change the `input_hash`
/// digest material and force a matching change in the six
/// `submit_observability` producers outside this file. Binding therefore happens
/// where bytes enter, at `deserialize`, not where the struct literal is built.
fn bind_observability_payload(
    kind: ObservabilityKind,
    payload: &Value,
) -> Result<(), serde_json::Error> {
    match kind {
        ObservabilityKind::MemoryGrantOffer => {
            serde_json::from_value::<MemoryGrantOfferRecord>(payload.clone()).map(|_owner| ())
        }
        ObservabilityKind::InjectionReceipt => {
            serde_json::from_value::<InjectionReceipt>(payload.clone()).map(|_owner| ())
        }
        ObservabilityKind::MemoryInfluenceTrace => {
            serde_json::from_value::<MemoryInfluenceTrace>(payload.clone()).map(|_owner| ())
        }
        ObservabilityKind::ActivationTrace => {
            serde_json::from_value::<ActivationTrace>(payload.clone()).map(|_owner| ())
        }
        ObservabilityKind::PredictionRecord => {
            serde_json::from_value::<PredictionRecord>(payload.clone()).map(|_owner| ())
        }
        ObservabilityKind::ExamRecord => {
            serde_json::from_value::<UlExamRecord>(payload.clone()).map(|_owner| ())
        }
    }
}

/// Bounded refusal for an observability envelope schema version this build
/// does not own. The message is fixed and never echoes the received value.
fn unsupported_observability_schema_version<E>(expected: &str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

/// Refuse an envelope whose `schema_version` is not the one this build owns.
///
/// This keeps the bound the field's former `deserialize_with` enforced. The
/// accepted spelling is unchanged — exactly one version value decodes — but note
/// that the refusal is now raised as soon as the key is read rather than after
/// the whole map has been consumed.
fn check_observability_schema_version<E>(value: &str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if value == OBSERVABILITY_SCHEMA_VERSION {
        Ok(())
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
/// selected variant is refused before the typed union is returned. Both
/// accepted shapes are closed, so this composition accepts no argument object
/// that the stricter owning contract refuses: the full shape is closed here
/// against the same three keys the owning `MemoryInfluenceTraceWriteInput`
/// closes with its `deny_unknown_fields` attribute, and the acknowledgement
/// shape is closed here against the exact declared field set
/// its owner `crates/eliot-types/src/ul/injection.rs::MemoryInfluenceAckInput`
/// publishes as `MEMORY_INFLUENCE_ACK_FIELDS` and refuses in
/// `MemoryInfluenceAckInputVisitor::visit_map`.
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
        // The first unrecognised key name, kept so the refusal can name it and
        // the owning acknowledgement field set rather than a second list.
        let mut foreign_key: Option<String> = None;

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
                    foreign_key.get_or_insert(key);
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
                if foreign_key.is_some() {
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
            (false, true) => {
                // The composed union is at least as strict as its strictest
                // branch: an argument object carrying a key outside the owning
                // acknowledgement contract is refused here exactly as
                // `MemoryInfluenceAckInputVisitor` refuses it, rather than
                // being accepted with the key dropped.
                if let Some(unknown) = foreign_key {
                    return Err(serde::de::Error::unknown_field(
                        unknown.as_str(),
                        MEMORY_INFLUENCE_ACK_FIELDS,
                    ));
                }
                Ok(MemoryInfluenceToolInput::Ack(MemoryInfluenceAckInput {
                    project_id,
                    write_id,
                    memory_handle: required(memory_handle, "memory_handle")?,
                    influence_class: required(influence_class, "influence_class")?,
                    downstream_outcome_ref,
                }))
            }
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
