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
        deserializer.deserialize_map(ObservedCueVisitor)
    }
}

/// Single-pass decoder for the direct legacy cue boundary.
///
/// The accepted key set is enumerated rather than derived, and it is the
/// historical record plus exactly two inert metadata keys pinned by the #831/8
/// compatibility oracle. Those two are read and dropped: they are never stored
/// and never re-serialized, so a versioned trial decode cannot be absorbed by
/// them, and the re-serialized cue keeps the exact two-key record. Every other
/// key is refused, and a repeated key is refused before its value is stored, so
/// a lexical duplicate cannot overwrite an accepted one.
struct ObservedCueVisitor;

impl<'de> serde::de::Visitor<'de> for ObservedCueVisitor {
    type Value = ObservedCue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a legacy observed cue")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut kind: Option<LegacyCueKindV1> = None;
        let mut value: Option<String> = None;
        // The two inert metadata keys are decoded and dropped, never stored.
        let mut version: Option<IgnoredAny> = None;
        let mut schema_version: Option<IgnoredAny> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "kind" => set_once(&mut kind, map.next_value()?, "kind")?,
                "value" => set_once(&mut value, map.next_value()?, "value")?,
                "version" => {
                    set_once(&mut version, map.next_value::<IgnoredAny>()?, "version")?;
                }
                "schema_version" => {
                    set_once(
                        &mut schema_version,
                        map.next_value::<IgnoredAny>()?,
                        "schema_version",
                    )?;
                }
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        key.as_str(),
                        &["kind", "value", "version", "schema_version"],
                    ));
                }
            }
        }

        Ok(ObservedCue {
            kind: required(kind, "kind")?,
            value: required(value, "value")?,
        })
    }
}

/// Cue adapter for cues nested inside a protected injection record.
///
/// A nested cue carries no legacy compatibility: the exact historical key set
/// is the whole key set, so the inert metadata pair the direct legacy decode
/// tolerates is refused here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictObservedCueInput {
    kind: LegacyCueKindV1,
    value: String,
}

fn deserialize_strict_observed_cues<'de, D>(deserializer: D) -> Result<Vec<ObservedCue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let cues = Vec::<StrictObservedCueInput>::deserialize(deserializer)?;
    Ok(cues
        .into_iter()
        .map(|cue| ObservedCue {
            kind: cue.kind,
            value: cue.value,
        })
        .collect())
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
