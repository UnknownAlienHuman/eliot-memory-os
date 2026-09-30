use crate::{LegacyCueKindV1, MemoryInfluenceClass, SessionId, TaskId};
use schemars::JsonSchema;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ObservedCue {
    pub kind: LegacyCueKindV1,
    pub value: String,
}

impl<'de> Deserialize<'de> for ObservedCue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ObservedCueVisitor {
            allow_legacy_metadata: true,
        })
    }
}

/// Single-pass decoder for the direct legacy cue boundary.
///
/// The direct legacy mode accepts the historical record plus exactly two inert
/// metadata keys pinned by the #831/8 compatibility oracle. Those keys are
/// dropped and never re-serialized. Strict nested mode accepts only `kind` and
/// `value`; `StrictObservedCueInput` selects it for `PendingInjectionItem` and
/// `InjectionReceipt.fired_cues`, including receipts decoded by
/// `CanonicalStore::apply_observability`. Both modes reject unknown keys and
/// reject repeated keys before decoding their values.
struct ObservedCueVisitor {
    allow_legacy_metadata: bool,
}

impl<'de> serde::de::Visitor<'de> for ObservedCueVisitor {
    type Value = ObservedCue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a legacy observed cue")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let allow_legacy_metadata = self.allow_legacy_metadata;
        let mut kind: Option<LegacyCueKindV1> = None;
        let mut value: Option<String> = None;
        // The two inert metadata keys are decoded and dropped, never stored.
        let mut version: Option<IgnoredAny> = None;
        let mut schema_version: Option<IgnoredAny> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "kind" => next_once(&mut map, &mut kind, "kind")?,
                "value" => next_once(&mut map, &mut value, "value")?,
                "version" if allow_legacy_metadata => {
                    next_once(&mut map, &mut version, "version")?;
                }
                "schema_version" if allow_legacy_metadata => {
                    next_once(&mut map, &mut schema_version, "schema_version")?;
                }
                _ => {
                    let fields = if allow_legacy_metadata {
                        &["kind", "value", "version", "schema_version"][..]
                    } else {
                        &["kind", "value"][..]
                    };
                    return Err(serde::de::Error::unknown_field(key.as_str(), fields));
                }
            }
        }

        Ok(ObservedCue {
            kind: required(kind, "kind")?,
            value: required(value, "value")?,
        })
    }
}

/// Decode a map value only after confirming its key has not appeared before.
fn next_once<'de, A, T>(
    map: &mut A,
    slot: &mut Option<T>,
    key: &'static str,
) -> Result<(), A::Error>
where
    A: serde::de::MapAccess<'de>,
    T: Deserialize<'de>,
{
    if slot.is_some() {
        return Err(serde::de::Error::duplicate_field(key));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}

fn required<T, E>(value: Option<T>, field: &'static str) -> Result<T, E>
where
    E: serde::de::Error,
{
    value.ok_or_else(|| E::missing_field(field))
}

struct StrictObservedCueInput(ObservedCue);

impl<'de> Deserialize<'de> for StrictObservedCueInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer
            .deserialize_map(ObservedCueVisitor {
                allow_legacy_metadata: false,
            })
            .map(Self)
    }
}

fn deserialize_strict_observed_cues<'de, D>(deserializer: D) -> Result<Vec<ObservedCue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let cues = Vec::<StrictObservedCueInput>::deserialize(deserializer)?;
    Ok(cues.into_iter().map(|cue| cue.0).collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInjectionItem {
    pub item_ref: String,
    pub record_kind: String,
    pub preview: String,
    pub payload: Option<Value>,
    pub source_fingerprint: String,
    #[serde(deserialize_with = "deserialize_strict_observed_cues")]
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
#[serde(deny_unknown_fields)]
pub struct UlFiredBlock {
    pub items: Vec<UlFiredItem>,
    pub overflow: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct InjectionReceipt {
    pub injection_id: String,
    pub session_id: SessionId,
    pub task_id: Option<TaskId>,
    pub surface: String,
    pub item_ref: String,
    pub render_form: String,
    #[serde(deserialize_with = "deserialize_strict_observed_cues")]
    pub fired_cues: Vec<ObservedCue>,
    pub token_cost: u32,
    pub source_fingerprint: String,
    pub outcome: String,
    #[serde(default)]
    pub policy_reason: Option<String>,
}

#[derive(Clone, Debug, JsonSchema, Serialize)]
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

pub(crate) const MEMORY_INFLUENCE_ACK_FIELDS: &[&str] = &[
    "project_id",
    "write_id",
    "memory_handle",
    "influence_class",
    "downstream_outcome_ref",
];

impl<'de> Deserialize<'de> for MemoryInfluenceAckInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "MemoryInfluenceAckInput",
            MEMORY_INFLUENCE_ACK_FIELDS,
            MemoryInfluenceAckInputVisitor,
        )
    }
}

struct MemoryInfluenceAckInputVisitor;

impl<'de> serde::de::Visitor<'de> for MemoryInfluenceAckInputVisitor {
    type Value = MemoryInfluenceAckInput;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a memory influence acknowledgement input")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut project_id: Option<Option<String>> = None;
        let mut write_id: Option<Option<String>> = None;
        let mut memory_handle: Option<String> = None;
        let mut influence_class: Option<MemoryInfluenceClass> = None;
        let mut downstream_outcome_ref: Option<Option<String>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "project_id" => next_once(&mut map, &mut project_id, "project_id")?,
                "write_id" => next_once(&mut map, &mut write_id, "write_id")?,
                "memory_handle" => next_once(&mut map, &mut memory_handle, "memory_handle")?,
                "influence_class" => {
                    next_once(&mut map, &mut influence_class, "influence_class")?;
                }
                "downstream_outcome_ref" => {
                    next_once(
                        &mut map,
                        &mut downstream_outcome_ref,
                        "downstream_outcome_ref",
                    )?;
                }
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        key.as_str(),
                        MEMORY_INFLUENCE_ACK_FIELDS,
                    ));
                }
            }
        }

        Ok(MemoryInfluenceAckInput {
            project_id: project_id.unwrap_or_default(),
            write_id: write_id.unwrap_or_default(),
            memory_handle: required(memory_handle, "memory_handle")?,
            influence_class: required(influence_class, "influence_class")?,
            downstream_outcome_ref: downstream_outcome_ref.unwrap_or_default(),
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let project_id = seq.next_element::<Option<String>>()?.unwrap_or_default();
        let write_id = seq.next_element::<Option<String>>()?.unwrap_or_default();
        let memory_handle = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
        let influence_class = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
        let downstream_outcome_ref = seq.next_element::<Option<String>>()?.unwrap_or_default();

        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(6, &self));
        }

        Ok(MemoryInfluenceAckInput {
            project_id,
            write_id,
            memory_handle,
            influence_class,
            downstream_outcome_ref,
        })
    }
}
