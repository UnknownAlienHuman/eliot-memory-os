#![forbid(unsafe_code)]

//! Candidate-only ingress validation for the `OpenCode` `ActionGate` payload.
//!
//! The plugin (`integrations/opencode/plugins/eliot.js`) produces a gate
//! payload whose decision must bind to one specific action: the typed
//! `effect_descriptor` plus its SHA-256 `effect_digest`. This module is the
//! narrow consumer-side check for that binding. It is pure (no I/O, no
//! server, no store) and fail-closed: any unknown tool, version drift,
//! bound violation, shape drift, or digest mismatch is rejected.
//!
//! Canonicalization mirrors `eliot.js` `appendCanonicalValue` for the
//! descriptor shape only (plain objects with sorted keys, string arrays,
//! strings). Strings encode as `s{utf16_len}:` followed by one lowercase
//! 4-digit hex unit per UTF-16 code unit, exactly as the plugin's
//! `appendCanonicalString` does.

use serde_json::Value;
use thiserror::Error;

/// Single-source tool-identity version pinned in
/// `integrations/opencode/plugin-bridge-contract.json`.
pub const OPENCODE_TOOL_IDENTITY_VERSION: &str = "eliot.opencode.tools.v1";
/// Effect schema version minted by the plugin (`EFFECT_SCHEMA_VERSION`).
pub const OPENCODE_EFFECT_SCHEMA_VERSION: &str = "eliot.opencode.effect.v1";
/// Argument normalization version minted by the plugin
/// (`ARGUMENT_NORMALIZATION_VERSION`).
pub const OPENCODE_ARGUMENT_NORMALIZATION_VERSION: &str = "eliot.opencode.arguments.v1";
/// Maximum argument keys, mirroring `MAX_ARGUMENT_KEYS` in the plugin.
pub const OPENCODE_MAX_ARGUMENT_KEYS: usize = 64;
/// Maximum UTF-16 length of one argument key, mirroring the plugin bound.
pub const OPENCODE_MAX_ARGUMENT_KEY_LENGTH: usize = 128;
/// Maximum canonical descriptor bytes, mirroring
/// `MAX_EFFECT_DESCRIPTOR_BYTES` in the plugin.
pub const OPENCODE_MAX_EFFECT_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// Exact case-sensitive mutating tools, mirroring `MUTATING_TOOLS`.
pub const OPENCODE_MUTATING_TOOLS: [&str; 4] = ["bash", "edit", "write", "patch"];
/// Exact case-sensitive read-only tools, mirroring `READ_ONLY_TOOLS`.
pub const OPENCODE_READ_ONLY_TOOLS: [&str; 8] = [
    "read",
    "grep",
    "glob",
    "list",
    "webfetch",
    "websearch",
    "lsp",
    "codesearch",
];

/// Allowlisted gate-payload fields, mirroring
/// `plugin-bridge-contract.json` `payload.allowlisted_fields`.
pub const OPENCODE_GATE_PAYLOAD_FIELDS: [&str; 14] = [
    "event_id",
    "sequence",
    "emitted_at",
    "event_kind",
    "vendor_event_kind",
    "host_session_id",
    "task_id",
    "work_item_id",
    "tool",
    "changed_path",
    "argument_keys",
    "attached_task",
    "effect_descriptor",
    "effect_digest",
];

/// Mutation-gate event identity produced by the plugin.
pub const OPENCODE_GATE_EVENT_KIND: &str = "tool.execute.before";
/// Read-only skipped-observation event identity produced by the plugin.
pub const OPENCODE_SKIPPED_EVENT_KIND: &str = "tool.execute.skipped";

/// Tool class derived from the single-source identity sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateToolClass {
    Mutating,
    ReadOnly,
}

/// Classify one `OpenCode` tool name with an exact case-sensitive lookup.
///
/// Returns `None` for aliases, unknown names, and anything outside the two
/// allowlists. The boolean comes from a real set comparison, never a
/// constant.
#[must_use]
pub fn classify_opencode_tool(tool: &str) -> Option<GateToolClass> {
    if OPENCODE_MUTATING_TOOLS.contains(&tool) {
        Some(GateToolClass::Mutating)
    } else if OPENCODE_READ_ONLY_TOOLS.contains(&tool) {
        Some(GateToolClass::ReadOnly)
    } else {
        None
    }
}

/// Fail-closed rejection reasons for gate ingress validation.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum GateValidationError {
    #[error("gate payload must be a JSON object")]
    NotAnObject,
    #[error("gate payload shape differs from the contract allowlist")]
    ShapeMismatch,
    #[error("gate payload field is missing or mistyped: {0}")]
    Field(&'static str),
    #[error("gate payload is not attached to a task")]
    NotAttached,
    #[error("tool identity is not an exact allowlist member")]
    UnknownTool,
    #[error("read-only tool cannot authorize a mutation gate")]
    ReadOnlyToolForGate,
    #[error("mutating tool cannot produce a skipped receipt")]
    MutatingToolForSkipped,
    #[error("effect schema version is unsupported")]
    UnsupportedSchemaVersion,
    #[error("argument normalization version is unsupported")]
    UnsupportedNormalizationVersion,
    #[error("argument key count exceeds its bounded contract")]
    TooManyArgumentKeys,
    #[error("argument key exceeds its bounded contract")]
    ArgumentKeyTooLong,
    #[error("argument keys are not sorted and unique")]
    ArgumentKeysUnsorted,
    #[error("payload argument keys differ from the effect descriptor")]
    ArgumentKeysMismatch,
    #[error("payload tool differs from the effect descriptor")]
    ToolMismatch,
    #[error("digest is not lowercase SHA-256 hex")]
    InvalidDigest,
    #[error("effect digest does not recompute from the descriptor")]
    DigestMismatch,
    #[error("effect descriptor exceeds its bounded contract")]
    DescriptorTooLarge,
    #[error("gate event kind is not the mutation gate")]
    UnexpectedEventKind,
}

/// Validated mutation-gate admission candidate (no authority granted).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMutationGate {
    /// Exact mutating tool identity.
    pub tool: String,
    /// Sorted argument names bound by the digest.
    pub argument_keys: Vec<String>,
    /// Recomputed effect digest the decision must bind to.
    pub effect_digest: String,
    /// Gate event identity.
    pub event_id: String,
}

/// Validated read-only skipped observation (no authority granted).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSkippedReceipt {
    /// Exact read-only tool identity.
    pub tool: String,
    /// Sorted argument names bound by the digest.
    pub argument_keys: Vec<String>,
    /// Recomputed effect digest carried by the observation.
    pub effect_digest: String,
    /// Observation event identity.
    pub event_id: String,
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

struct CanonicalState {
    bytes: usize,
    parts: Vec<String>,
}

impl CanonicalState {
    fn new() -> Self {
        Self {
            bytes: 0,
            parts: Vec::new(),
        }
    }

    fn push(&mut self, piece: &str) -> Result<(), GateValidationError> {
        self.bytes = self.bytes.saturating_add(piece.len());
        if self.bytes > OPENCODE_MAX_EFFECT_DESCRIPTOR_BYTES {
            return Err(GateValidationError::DescriptorTooLarge);
        }
        self.parts.push(piece.to_owned());
        Ok(())
    }

    fn push_string(&mut self, value: &str) -> Result<(), GateValidationError> {
        let units: Vec<u16> = value.encode_utf16().collect();
        self.push(&format!("s{}:", units.len()))?;
        for unit in units {
            self.push(&format!("{unit:04x}"))?;
        }
        Ok(())
    }

    fn finish(self) -> String {
        self.parts.join("")
    }
}

/// Recompute the effect digest from typed descriptor fields.
///
/// The canonical form emits the descriptor object with keys sorted
/// (`argument_digest`, `argument_keys`, `normalization_version`,
/// `schema_version`, `tool`), matching the plugin's `plainObjectEntries`
/// sort for this shape. The digest is SHA-256 hex of
/// `{schema_version}:effect:{canonical}`. Every boolean here derives from a
/// real byte comparison; nothing is echoed.
pub fn recompute_effect_digest(
    tool: &str,
    argument_keys: &[String],
    argument_digest: &str,
    schema_version: &str,
    normalization_version: &str,
) -> Result<String, GateValidationError> {
    let mut state = CanonicalState::new();
    state.push("object5{")?;
    // argument_digest
    state.push_string("argument_digest")?;
    state.push_string(argument_digest)?;
    // argument_keys
    state.push_string("argument_keys")?;
    state.push(&format!("array{}[", argument_keys.len()))?;
    for key in argument_keys {
        state.push_string(key)?;
    }
    state.push("]")?;
    // normalization_version
    state.push_string("normalization_version")?;
    state.push_string(normalization_version)?;
    // schema_version
    state.push_string("schema_version")?;
    state.push_string(schema_version)?;
    // tool
    state.push_string("tool")?;
    state.push_string(tool)?;
    state.push("}")?;
    let canonical = state.finish();
    let preimage = format!("{schema_version}:effect:{canonical}");
    Ok(eliot_contracts::sha256_hex(preimage.as_bytes()))
}

fn check_argument_keys(keys: &[String]) -> Result<(), GateValidationError> {
    if keys.len() > OPENCODE_MAX_ARGUMENT_KEYS {
        return Err(GateValidationError::TooManyArgumentKeys);
    }
    for key in keys {
        if utf16_len(key) > OPENCODE_MAX_ARGUMENT_KEY_LENGTH {
            return Err(GateValidationError::ArgumentKeyTooLong);
        }
    }
    let mut sorted = keys.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != keys.len() || sorted != keys {
        return Err(GateValidationError::ArgumentKeysUnsorted);
    }
    Ok(())
}

fn object_fields(value: &Value) -> Result<&serde_json::Map<String, Value>, GateValidationError> {
    value
        .as_object()
        .ok_or(GateValidationError::NotAnObject)
}

fn require_shape(object: &serde_json::Map<String, Value>) -> Result<(), GateValidationError> {
    if object.len() != OPENCODE_GATE_PAYLOAD_FIELDS.len() {
        return Err(GateValidationError::ShapeMismatch);
    }
    for key in object.keys() {
        if !OPENCODE_GATE_PAYLOAD_FIELDS.contains(&key.as_str()) {
            return Err(GateValidationError::ShapeMismatch);
        }
    }
    for field in OPENCODE_GATE_PAYLOAD_FIELDS {
        if !object.contains_key(field) {
            return Err(GateValidationError::ShapeMismatch);
        }
    }
    Ok(())
}

fn require_non_empty_string(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, GateValidationError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(GateValidationError::Field(field))
}

fn require_optional_string(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(), GateValidationError> {
    match object.get(field) {
        Some(Value::Null | Value::String(_)) => Ok(()),
        _ => Err(GateValidationError::Field(field)),
    }
}

fn require_string_list(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, GateValidationError> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(GateValidationError::Field(field))?;
    let mut keys = Vec::with_capacity(values.len());
    for value in values {
        let key = value
            .as_str()
            .ok_or(GateValidationError::Field(field))?;
        keys.push(key.to_owned());
    }
    Ok(keys)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedBinding {
    tool: String,
    argument_keys: Vec<String>,
    effect_digest: String,
    event_id: String,
}

fn validate_envelope(
    object: &serde_json::Map<String, Value>,
    expected_event_kind: &str,
    required_class: GateToolClass,
) -> Result<(String, String, Vec<String>), GateValidationError> {
    require_shape(object)?;
    let event_id = require_non_empty_string(object, "event_id")?;
    let event_kind = require_non_empty_string(object, "event_kind")?;
    let vendor_event_kind = require_non_empty_string(object, "vendor_event_kind")?;
    if event_kind != expected_event_kind || vendor_event_kind != expected_event_kind {
        return Err(GateValidationError::UnexpectedEventKind);
    }
    require_non_empty_string(object, "emitted_at")?;
    require_optional_string(object, "host_session_id")?;
    require_optional_string(object, "task_id")?;
    require_optional_string(object, "work_item_id")?;
    require_optional_string(object, "changed_path")?;
    let sequence = object
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or(GateValidationError::Field("sequence"))?;
    if sequence == 0 {
        return Err(GateValidationError::Field("sequence"));
    }
    let attached = object
        .get("attached_task")
        .and_then(Value::as_bool)
        .ok_or(GateValidationError::Field("attached_task"))?;
    if !attached {
        return Err(GateValidationError::NotAttached);
    }
    let tool = require_non_empty_string(object, "tool")?;
    let class = classify_opencode_tool(&tool).ok_or(GateValidationError::UnknownTool)?;
    if class != required_class {
        return if required_class == GateToolClass::Mutating {
            Err(GateValidationError::ReadOnlyToolForGate)
        } else {
            Err(GateValidationError::MutatingToolForSkipped)
        };
    }
    let payload_keys = require_string_list(object, "argument_keys")?;
    check_argument_keys(&payload_keys)?;
    Ok((event_id, tool, payload_keys))
}

struct DescriptorBinding {
    schema_version: String,
    normalization_version: String,
    descriptor_keys: Vec<String>,
    argument_digest: String,
}

fn validate_descriptor(
    object: &serde_json::Map<String, Value>,
    tool: &str,
    payload_keys: &[String],
) -> Result<DescriptorBinding, GateValidationError> {
    let descriptor_value = object
        .get("effect_descriptor")
        .ok_or(GateValidationError::Field("effect_descriptor"))?;
    let descriptor = object_fields(descriptor_value)?;
    let schema_version = descriptor
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or(GateValidationError::Field("effect_descriptor"))?;
    if schema_version != OPENCODE_EFFECT_SCHEMA_VERSION {
        return Err(GateValidationError::UnsupportedSchemaVersion);
    }
    let normalization_version = descriptor
        .get("normalization_version")
        .and_then(Value::as_str)
        .ok_or(GateValidationError::Field("effect_descriptor"))?;
    if normalization_version != OPENCODE_ARGUMENT_NORMALIZATION_VERSION {
        return Err(GateValidationError::UnsupportedNormalizationVersion);
    }
    let descriptor_tool = descriptor
        .get("tool")
        .and_then(Value::as_str)
        .ok_or(GateValidationError::Field("effect_descriptor"))?;
    if descriptor_tool != tool {
        return Err(GateValidationError::ToolMismatch);
    }
    let descriptor_keys_value = descriptor
        .get("argument_keys")
        .and_then(Value::as_array)
        .ok_or(GateValidationError::Field("effect_descriptor"))?;
    let mut descriptor_keys = Vec::with_capacity(descriptor_keys_value.len());
    for value in descriptor_keys_value {
        descriptor_keys.push(
            value
                .as_str()
                .ok_or(GateValidationError::Field("effect_descriptor"))?
                .to_owned(),
        );
    }
    check_argument_keys(&descriptor_keys)?;
    if descriptor_keys != payload_keys {
        return Err(GateValidationError::ArgumentKeysMismatch);
    }
    let argument_digest = descriptor
        .get("argument_digest")
        .and_then(Value::as_str)
        .ok_or(GateValidationError::Field("effect_descriptor"))?;
    if !is_lowercase_sha256_hex(argument_digest) {
        return Err(GateValidationError::InvalidDigest);
    }
    Ok(DescriptorBinding {
        schema_version: schema_version.to_owned(),
        normalization_version: normalization_version.to_owned(),
        descriptor_keys,
        argument_digest: argument_digest.to_owned(),
    })
}

fn validate_binding(
    object: &serde_json::Map<String, Value>,
    expected_event_kind: &str,
    required_class: GateToolClass,
) -> Result<ValidatedBinding, GateValidationError> {
    let (event_id, tool, payload_keys) =
        validate_envelope(object, expected_event_kind, required_class)?;
    let binding = validate_descriptor(object, &tool, &payload_keys)?;
    let effect_digest = object
        .get("effect_digest")
        .and_then(Value::as_str)
        .ok_or(GateValidationError::Field("effect_digest"))?;
    if !is_lowercase_sha256_hex(effect_digest) {
        return Err(GateValidationError::InvalidDigest);
    }
    let recomputed = recompute_effect_digest(
        &tool,
        &binding.descriptor_keys,
        &binding.argument_digest,
        &binding.schema_version,
        &binding.normalization_version,
    )?;
    if recomputed != effect_digest {
        return Err(GateValidationError::DigestMismatch);
    }
    Ok(ValidatedBinding {
        tool,
        argument_keys: binding.descriptor_keys,
        effect_digest: effect_digest.to_owned(),
        event_id,
    })
}

/// Validate one mutation-gate payload (`tool.execute.before`).
///
/// Accepts only exact mutating tools with an attached task, an exact
/// 14-field contract shape, sorted bounded argument keys identical between
/// payload and descriptor, pinned versions, and an effect digest that
/// recomputes from the descriptor. Anything else fails closed.
pub fn validate_mutation_gate_payload(
    payload: &Value,
) -> Result<ValidatedMutationGate, GateValidationError> {
    let object = object_fields(payload)?;
    let binding = validate_binding(object, OPENCODE_GATE_EVENT_KIND, GateToolClass::Mutating)?;
    Ok(ValidatedMutationGate {
        tool: binding.tool,
        argument_keys: binding.argument_keys,
        effect_digest: binding.effect_digest,
        event_id: binding.event_id,
    })
}

/// Validate one read-only skipped observation (`tool.execute.skipped`).
///
/// Same binding rules as the mutation gate, but the tool must be an exact
/// read-only member. Unknown tools, aliases, and mutating tools fail closed.
pub fn validate_skipped_tool_receipt(
    payload: &Value,
) -> Result<ValidatedSkippedReceipt, GateValidationError> {
    let object = object_fields(payload)?;
    let binding = validate_binding(
        object,
        OPENCODE_SKIPPED_EVENT_KIND,
        GateToolClass::ReadOnly,
    )?;
    Ok(ValidatedSkippedReceipt {
        tool: binding.tool,
        argument_keys: binding.argument_keys,
        effect_digest: binding.effect_digest,
        event_id: binding.event_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gate_fixture() -> Value {
        json!({
            "event_id": "opencode:effect:64d799a6061269b3080cecc529e34d127f492cf794910767c03afd923fee853b:call-1",
            "sequence": 1,
            "emitted_at": "2026-09-15T18:14:45.835Z",
            "event_kind": "tool.execute.before",
            "vendor_event_kind": "tool.execute.before",
            "host_session_id": null,
            "task_id": "task-1",
            "work_item_id": null,
            "tool": "bash",
            "changed_path": null,
            "argument_keys": ["command"],
            "attached_task": true,
            "effect_descriptor": {
                "schema_version": "eliot.opencode.effect.v1",
                "normalization_version": "eliot.opencode.arguments.v1",
                "tool": "bash",
                "argument_keys": ["command"],
                "argument_digest": "c0a81a95602d7ae3abbc9f673b3716a22969188b16657bf0429daea2dcb05b00"
            },
            "effect_digest": "64d799a6061269b3080cecc529e34d127f492cf794910767c03afd923fee853b"
        })
    }

    #[test]
    fn mutation_gate_accepts_plugin_vector_and_binds_tool_to_digest(
    ) -> Result<(), GateValidationError> {
        let payload = gate_fixture();
        let validated = validate_mutation_gate_payload(&payload)?;
        assert_eq!(validated.tool, "bash");
        assert_eq!(validated.argument_keys, vec!["command".to_owned()]);
        assert_eq!(
            validated.effect_digest,
            "64d799a6061269b3080cecc529e34d127f492cf794910767c03afd923fee853b"
        );

        let tampered = json!({
            "event_id": payload["event_id"],
            "sequence": 1,
            "emitted_at": "2026-09-15T18:14:45.835Z",
            "event_kind": "tool.execute.before",
            "vendor_event_kind": "tool.execute.before",
            "host_session_id": null,
            "task_id": "task-1",
            "work_item_id": null,
            "tool": "write",
            "changed_path": null,
            "argument_keys": ["command"],
            "attached_task": true,
            "effect_descriptor": payload["effect_descriptor"],
            "effect_digest": payload["effect_digest"]
        });
        assert_eq!(
            validate_mutation_gate_payload(&tampered),
            Err(GateValidationError::ToolMismatch)
        );
        Ok(())
    }

    #[test]
    fn mutation_gate_rejects_unknown_tool_and_tampered_digest() {
        let mut unknown = gate_fixture();
        unknown["tool"] = json!("unknown_tool");
        assert_eq!(
            validate_mutation_gate_payload(&unknown),
            Err(GateValidationError::UnknownTool)
        );

        let mut tampered = gate_fixture();
        tampered["effect_digest"] =
            json!("0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(
            validate_mutation_gate_payload(&tampered),
            Err(GateValidationError::DigestMismatch)
        );
    }
}
