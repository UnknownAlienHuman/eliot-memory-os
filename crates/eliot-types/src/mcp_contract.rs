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
    /// Field-specific, caller-evidenced retention (#708).
    ///
    /// These six defaulted fields are retained deliberately and are NOT counted
    /// as fixed. Exact current caller evidence that each is a genuine optional
    /// agent choice on this specific wire, not a general exemption:
    ///
    /// - `where_applicable` / `where_not_applicable` / `negative_constraints`:
    ///   the scope delimiters of a candidate statement. An omitted key here is a
    ///   deliberate "this candidate states no boundary", which is a coherent
    ///   answer; the current producer
    ///   (`crates/eliot-app/tests/ul_cue_candidate.rs:31`) writes them
    ///   explicitly, and `crates/eliot-types/tests/ul_cue_normalize.rs::t03_candidate_schema_roundtrip`
    ///   round-trips the exact declared shape.
    /// - `cue_bindings`: retained capture-first optionality. The published
    ///   `agent_candidate_input_schema` deliberately keeps `cue_bindings` OUT of
    ///   `required` and only force-inserts `expected_reuse_note` into the nested
    ///   `CueBinding` definition (`agent_candidate_input_schema`, :262-289); the
    ///   existing test asserts exactly that (`t03` asserts
    ///   `!required.contains("cue_bindings")`). Removing the default would move
    ///   that published required set — a wire change owned outside this file.
    /// - `auto_bind` / `curation`: genuinely optional enrichment requests whose
    ///   absence means "do not auto-bind" and "no curation attached".
    ///
    /// These are per-field exemptions, invalidated by any producer or schema
    /// change, and none of them crosses or influences a protected boundary by
    /// omission: the retained keys cannot create a grant, a scope, an effect or
    /// a receipt. They are also NOT part of W2: none of the six is
    /// authority-, scope-, effect- or receipt-bearing in the retained direction.
    /// `deny_unknown_fields` remains, and the typed error owner remains serde's
    /// `missing_field` for every non-retained key.
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

/// Field-specific retention, one row per field (#708).
///
/// `AgentCandidateCurationInput` is the only curation payload on the legacy
/// candidate-submit wire, and it is `Option`-wrapped at the submission level,
/// so its *whole* presence is already explicit. The remaining question for each
/// field is whether an omitted key may be read as "not stated" or as a stated
/// value. For every field in this struct the retained reading is the safe one,
/// with exact caller evidence:
///
/// - `duplicate_of` / `semantic_duplicate_of` / `superseded_by` /
///   `stale_reason_ref`: relation/provenance references. `None` means "no such
///   relation was asserted", and asserting one is the only way to change it, so
///   omission cannot manufacture a retention or erasure effect.
/// - `semantic_equivalence_verified` / `protected` / `current_truth` /
///   `audit_required` / `unsafe_instruction`: boolean curation judgements whose
///   retained default is `false`. These are *fail-closed* on the two that
///   matter for safety: an omitted `protected` is not "protected" and an
///   omitted `unsafe_instruction` is not "flagged unsafe", so no omission can
///   grant protection or suppress a safety flag. (The inverse defect —
///   defaulting an unsafe/protected flag to `true` — would be an escalation and
///   is not what this code does.)
/// - `scope_match` / `evidence_sufficient` / `reopen_condition_met`: tri-state
///   judgements where `None` (unknown) is materially different from either
///   boolean. Retaining `default` here is therefore the W3-correct choice, not a
///   tolerance: the three-way absent / present-empty / value distinction is
///   preserved by the `Option`, and the `#[serde(default)]` only supplies `None`
///   for a key the producer never wrote.
/// - `wrong_scope_for` / `repeated_with` / `unsafe_evidence_refs` /
///   `evidence_refs` / `counterevidence_refs`: evidence vectors, where an
///   explicitly empty set is a real answer ("no counterevidence was recorded")
///   and must not be banned generically.
/// - `utility_score` / `utility_delta` / `repeat_count` / `role` / `lifecycle` /
///   `authority`: advisory metadata, `None` = not stated.
///
/// Field-specific and invalidated by any producer/caller change; never
/// package-wide or file-wide. `deny_unknown_fields` remains, so an unknown key
/// is refused rather than defaulted. No alias, `untagged` or default helper
/// re-accepts any removed layout (W4).
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
///
/// `hint` and `schema_version` keep their existing decoder state in this
/// increment, and that is a recorded decision, not a default:
///
/// - `schema_version` is contract-required and `dispatch_observe` already pins
///   `OBSERVE_INPUT_SCHEMA_VERSION`, rejecting anything else. Removing the
///   default would move that check earlier (absent key = typed missing-field
///   failure rather than a silent promotion to current) and invents no version
///   field — `schema_version` and its constant already exist on this wire.
///   BLOCKED-BY: the *contract* is generated from this type, and
///   `eliot.observe` is published in the MCP tool catalogue whose
///   `inputSchema` and its required-key set are the agent-visible wire. Making a
///   previously omittable key required changes `tools/list` output bytes for
///   every connected agent, which is a major incompatibility under APPENDIX-P
///   and needs the catalogue owner, not this crate's file scope.
/// - `hint`'s `alias = "kind"` is a genuine W4 defect: the current decoder
///   trial-accepts the same closed control variant under two names, which
///   APPENDIX-P line 13 ("closed control variants fail when unknown") forbids.
///   NO named legacy boundary accepts `kind` for this shape anywhere in the
///   workspace — no versioned type, no migration descriptor wired into a
///   decoder, no legacy reader — so the alias is the only way that spelling
///   decodes: an unsanctioned trial-accept, not a retained compatibility row.
///   Owner: the generated inventory row, `eliot-app` coordinating; the field
///   doc below names the real decoder, publisher and inventory owner.
///
/// The remaining `#[serde(default)]` fields stay: `task_id`,
/// `expected_reuse_note` and `write_id` are genuinely optional agent choices,
/// and `affected_resources` / `source_handles` are explicit no-authority sets
/// whose empty value is a real answer, not an inferred one.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveInput {
    /// Natural language or structured JSON observation content.
    pub text_or_structured_payload: Value,
    /// Optional first-pass classification hint. Classification never grants
    /// promotion or task authority.
    ///
    /// W4 DEFECT, unchanged in this increment and recorded here so it is not mistaken for an intentional compatibility alias.
    /// `alias = "kind"` makes the *current* decoder trial-accept the same closed control variant under two names, while APPENDIX-P line 13
    /// requires the current decoder to fail closed on a closed control variant and admits aliases only at a named migration/compatibility
    /// boundary. No such boundary exists for this shape anywhere in the workspace — no versioned type, no migration descriptor wired into a
    /// decoder, no legacy reader — so the alias is the ONLY way that spelling decodes: an unsanctioned trial-accept, not a retained
    /// compatibility row. `deny_unknown_fields` still refuses every other unknown key, so unknown key/refuse stays distinct.
    ///
    /// The owner this record previously named is wrong and could not be the owner: `crates/surfaces/eliot-mcp/Cargo.toml` does not depend on
    /// `eliot-types`; `decode_protected_request_bytes` is `crates/surfaces/eliot-mcp/src/contract.rs:953`, not `src/core.rs`; and that crate's own
    /// `ObserveInput` (`contract.rs:330`) is a different, kind-tagged type that refuses `{"kind":"reuse_candidate"}` (`tests/contract.rs:664`).
    /// Real decoder of THIS type: `crates/eliot-app/src/mcp_stdio/verification.rs:26` (`serde_json::from_value::<ObserveInput>`), reached from
    /// `crates/eliot-app/src/mcp_stdio/dispatch.rs:910`. Real schema publisher: `crates/eliot-app/src/mcp_stdio/catalog.rs:1180` →
    /// `crates/eliot-app/src/mcp_stdio/protocol_support.rs::observe_schema` (:111), a bare `inputSchema` with no schema digest and no external
    /// required-key binding. No in-tree producer sends the legacy spelling: the only writer of that key emits canonical `"hint"`
    /// (`verification.rs:86`), and `schemars` never reads `alias`, so the generated JSON Schema bytes are identical with or without it.
    ///
    /// Real owner: the generated inventory row (`crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`, `owner = "#692"`,
    /// `repair_child = "#933"`, `has_alias = true`), with `eliot-app` coordinating; that inventory row is the only artefact needing regeneration.
    /// Retained verbatim because #708 does not correct it in this increment, and no second alias, `untagged` or default is added. Proof ceiling:
    /// source-attested only, no executed test in this lane.
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
    ///
    /// BLOCKED-BY, unchanged in this increment and recorded here so the field is
    /// not mistaken for a retained internal default. `schema_version` is
    /// contract-required, and `dispatch_observe`
    /// (`crates/eliot-app/src/mcp_stdio/verification.rs::dispatch_observe`, :27)
    /// already pins `OBSERVE_INPUT_SCHEMA_VERSION` and rejects every other
    /// value, so the wire version is enforced — just later than a required key
    /// would be. The `default = "default_observe_schema_version"` helper is what
    /// this issue's field inventory calls the *helper* default form, and it is
    /// the one genuine remaining trial-accept path here: an omitted key is
    /// silently promoted to the current version.
    ///
    /// Why it cannot be corrected in this issue's file scope: the JSON Schema
    /// for `eliot.observe` is generated from this type
    /// (`crates/eliot-app/src/mcp_stdio/protocol_support.rs::observe_schema` →
    /// `eliot_types::observe_input_schema`, :112). Making a previously
    /// omittable key required moves the published schema and therefore the
    /// `inputSchema` `required` set every connected agent sees through `tools/list`
    /// (`crates/eliot-app/src/mcp_stdio/dispatch.rs:226`, from `catalog.rs:1180`).
    /// `crates/surfaces/eliot-mcp/src/schema.rs` does not publish THIS type: its
    /// `descriptor::<ObserveInput>("eliot.observe", ..)` at `:72` describes eliot-mcp's own
    /// kind-tagged type, and no `schema_sha256` reaches the eliot-app catalogue. A
    /// requiredness change is still an APPENDIX-P major incompatibility owned by `eliot-app`, not this crate's file scope.
    ///
    /// W4 disposition: NOT a compatible requiredness correction, and NOT an
    /// isolated old-version representation either. No `schema_version` field is
    /// invented, and no alias/`untagged`/helper-default compensation is added;
    /// the version field already exists on this wire and the current version is
    /// already rejected by `dispatch_observe`. Required owner is the generated
    /// inventory row (`owner = "#692"`, `repair_child = "#933"`) with the
    /// `eliot-app` `eliot.observe` catalogue as coordinating surface. Base SHA of
    /// this branch's merge-base with `origin/main` is recorded in the #708
    /// report.
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
