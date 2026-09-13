//! Authoritative lossless representation for arbitrary JSON payloads.
//!
//! Issue #10: vendor and RPC layers below this boundary (notably SurrealDB
//! record coercion and JSON-RPC `Value` variables) can silently narrow or
//! reinterpret JSON that has already collapsed into
//! [`serde_json::Value`]. This module provides the single authoritative
//! representation that must be parsed from raw ingress bytes **before** any
//! `Value` collapse:
//!
//! - [`ExactJsonBytes`] keeps the exact UTF-8 bytes, a versioned
//!   digest binding over `version || encoding || bytes`, a length bound, and a
//!   vendor-neutral provenance label. It is the authority; every `Value`
//!   projection derived from it (including [`CanonicalJson`]) is explicitly a
//!   derivative and must never silently replace the authority.
//! - Duplicate object keys are rejected fail-closed before map collapse, so no
//!   first-wins or last-wins interpretation can hide.
//! - Wide numbers are preserved lexically in the authority bytes. Any
//!   derivation that would narrow a number through `f64` fails closed before
//!   admission instead of silently changing precision.
//! - `null`, absent, `false`, `0`, `""`, `[]`, and `{}` stay distinct because
//!   the authority is opaque bytes: `null` is a four-byte payload, absent
//!   means no authority or no member at all.
//! - Payload bytes cannot override control fields (operation, session, fence,
//!   authority, receipt, or idempotency identity) via
//!   [`CONTROL_FIELD_DENYLIST`] enforcement on the decode path.
//!
//! This module creates no second payload owner: it only represents bytes that
//! Governor/Kernel admission already authorized. The store persists the
//! authority opaquely and binds plan/receipt digests to it; it never invents
//! semantic content.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{StoreError, canonical_json_bytes};

/// Version of the [`ExactJsonBytes`] digest binding. Bumped only with a
/// contract change; old versions fail closed in [`ExactJsonBytes::validate`].
pub const PAYLOAD_AUTHORITY_VERSION: u16 = 1;

/// Maximum exact payload size of one authoritative JSON value (1 MiB).
/// Bounds memory before parsing and matches the Wave-B length-bound rule.
pub const MAX_EXACT_JSON_BYTES: usize = 1_048_576;

/// Maximum object/array nesting accepted by the duplicate-key scanner.
/// `serde_json` already enforces its own recursion limit during the
/// pre-scan parse; this is a defensive second bound, not a new allowance.
const MAX_PAYLOAD_SCAN_DEPTH: usize = 256;

/// Control fields that payload bytes can never override. A decoded
/// named-operation parameter carrying one of these names is rejected
/// fail-closed instead of being merged into control identity.
pub const CONTROL_FIELD_DENYLIST: &[&str] = &[
    "operation",
    "operation_id",
    "operation_kind",
    "operation_manifest_digest",
    "session",
    "session_id",
    "state_fence",
    "authority",
    "authority_epoch",
    "resource_generation",
    "receipt",
    "receipt_body",
    "receipt_body_json_b64",
    "envelope",
    "idempotency_key",
    "canonical_request_hash",
    "transition_class",
    "requested_effect_ceiling",
    "admission_contract_set_digest",
    "task_id",
    "scope_id",
    "ordering_scopes",
    "ordering_sequences",
    "security",
    "principal",
    "identity",
    "context",
    "fence",
    "manifest",
    "event_projection_relation_intents",
    "required_proof_and_approval_refs",
    "revision_before_after",
    "applied_command_ids",
    "emitted_event_ids",
    "projection_refs",
    "outbox_refs",
    "commit_id",
    "committed_at",
];

/// Byte encoding of [`ExactJsonBytes`]. Only UTF-8 JSON exists today; the
/// code byte participates in the digest so a future encoding is explicit.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    Utf8Json,
}

impl PayloadEncoding {
    /// Digest code byte for this encoding.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Utf8Json => 0,
        }
    }

    /// Vendor-neutral encoding mnemonic used in persisted bindings.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Utf8Json => "utf8_json",
        }
    }
}

/// Provenance of the raw bytes. A label only: it never enters the digest, so
/// provenance can never alias two different byte strings to one identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadSource {
    NamedOperationParameter,
    DirectIngest,
    MigrationReplay,
}

/// Authoritative lossless representation of one arbitrary JSON payload.
///
/// Parsed from raw bytes before any `serde_json::Value` collapse. The
/// `digest` binds `version (u16 little-endian) || encoding code || bytes`
/// with SHA-256 and is verified on every decode path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactJsonBytes {
    pub version: u16,
    pub encoding: PayloadEncoding,
    pub bytes: Vec<u8>,
    #[serde(with = "digest_hex_serde")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
    pub source: PayloadSource,
}

impl ExactJsonBytes {
    /// Parses and binds one authoritative payload from raw ingress bytes.
    ///
    /// Fails closed on empty input, oversize input, non-UTF-8 bytes, input
    /// that is not exactly one JSON value, or duplicate object keys at any
    /// nesting level. Wide numbers are preserved lexically; they are only
    /// rejected later on paths that would collapse them through `f64`.
    pub fn parse(source: PayloadSource, raw: &[u8]) -> Result<Self, StoreError> {
        if raw.is_empty() {
            return Err(StoreError::Empty {
                field: "payload.bytes",
            });
        }
        if raw.len() > MAX_EXACT_JSON_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        let text = std::str::from_utf8(raw).map_err(|_| StoreError::InvalidField {
            field: "payload.bytes",
            reason: "payload authority bytes are not UTF-8 JSON",
        })?;
        // Exactly one JSON value: `serde_json` rejects trailing bytes here,
        // so no second value can hide behind the first.
        let _: Value = serde_json::from_slice(raw)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        reject_duplicate_object_keys(text)?;
        Ok(Self {
            version: PAYLOAD_AUTHORITY_VERSION,
            encoding: PayloadEncoding::Utf8Json,
            bytes: raw.to_vec(),
            digest: Self::compute_digest(PAYLOAD_AUTHORITY_VERSION, PayloadEncoding::Utf8Json, raw),
            source,
        })
    }

    /// Revalidates version, bounds, single-value shape, duplicate-key
    /// freedom, and the digest binding. Anything constructed outside
    /// [`Self::parse`] (for example via deserialization) must pass here
    /// before it is trusted.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != PAYLOAD_AUTHORITY_VERSION {
            return Err(StoreError::InvalidField {
                field: "payload.version",
                reason: "unsupported payload authority version",
            });
        }
        if self.bytes.is_empty() {
            return Err(StoreError::Empty {
                field: "payload.bytes",
            });
        }
        if self.bytes.len() > MAX_EXACT_JSON_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        let text = std::str::from_utf8(&self.bytes).map_err(|_| StoreError::InvalidField {
            field: "payload.bytes",
            reason: "payload authority bytes are not UTF-8 JSON",
        })?;
        let _: Value = serde_json::from_slice(&self.bytes)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        reject_duplicate_object_keys(text)?;
        self.verify_digest()
    }

    /// Computes the SHA-256 binding over `version || encoding || bytes`.
    #[must_use]
    pub fn compute_digest(version: u16, encoding: PayloadEncoding, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(version.to_le_bytes());
        hasher.update([encoding.code()]);
        hasher.update(bytes);
        let finished = hasher.finalize();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&finished);
        digest
    }

    /// Verifies the stored digest against the current version, encoding,
    /// and bytes. Any mismatch is corruption or substitution, never a
    /// fallback case.
    pub fn verify_digest(&self) -> Result<(), StoreError> {
        let expected = Self::compute_digest(self.version, self.encoding, &self.bytes);
        if expected != self.digest {
            return Err(StoreError::InvalidField {
                field: "payload.digest",
                reason: "payload authority digest does not bind version, encoding and bytes",
            });
        }
        Ok(())
    }

    /// Lowercase hex rendering of the digest binding.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex_encode_32(&self.digest)
    }

    /// Exact byte length of the authority payload.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Views the authority bytes as JSON text. Validated UTF-8 by
    /// construction; rechecked here for values that bypassed
    /// [`Self::parse`].
    pub fn as_json_str(&self) -> Result<&str, StoreError> {
        std::str::from_utf8(&self.bytes).map_err(|_| StoreError::InvalidField {
            field: "payload.bytes",
            reason: "payload authority bytes are not UTF-8 JSON",
        })
    }

    /// Derives the queryable `Value` projection. This is explicitly a
    /// lossy-capable derivative: any number whose lexical form would narrow
    /// through `f64` fails closed here so callers must use the authority
    /// bytes instead of silently losing precision.
    pub fn projection_value(&self) -> Result<Value, StoreError> {
        let text = self.as_json_str()?;
        let value: Value = serde_json::from_str(text)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        for token in collect_number_tokens(text)? {
            if number_token_would_narrow(&token) {
                return Err(StoreError::InvalidField {
                    field: "payload.number",
                    reason: "wide number would narrow through f64; use payload authority bytes",
                });
            }
        }
        Ok(value)
    }

    /// Decodes a top-level object authority into the legacy named-operation
    /// parameter shape without silent loss: control-field names and
    /// narrowing numbers fail closed, and duplicate keys were already
    /// rejected at parse time so the map collapse is exact.
    pub fn decode_object_parameters(&self) -> Result<BTreeMap<String, Value>, StoreError> {
        let value = self.projection_value()?;
        let Value::Object(object) = value else {
            return Err(StoreError::InvalidField {
                field: "payload.shape",
                reason: "named-operation parameters require a top-level JSON object",
            });
        };
        for name in object.keys() {
            reject_control_parameter_name(name)?;
            if name.trim().is_empty() || name.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter_name",
                    reason: "blank or control character",
                });
            }
        }
        Ok(object.into_iter().collect())
    }

    /// Derives the canonical (sorted-key) projection bound to this
    /// authority. The result is a derivative for comparison and digest
    /// purposes, never a replacement for [`Self::bytes`].
    pub fn canonical_projection(&self) -> Result<CanonicalJson, StoreError> {
        CanonicalJson::from_authority(self)
    }
}

/// Canonical sorted-key view derived from an [`ExactJsonBytes`] authority.
///
/// Carries the authority digest it was derived from so verifiers can prove
/// the projection matches the exact bytes instead of trusting a detached
/// canonical blob.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalJson {
    pub version: u16,
    pub source_digest_hex: String,
    pub bytes: Vec<u8>,
}

impl CanonicalJson {
    /// Derives the canonical projection. Fails closed exactly where
    /// [`ExactJsonBytes::projection_value`] does: narrowing numbers and
    /// control-field-free shape violations never become silent canonical
    /// bytes.
    pub fn from_authority(authority: &ExactJsonBytes) -> Result<Self, StoreError> {
        authority.validate()?;
        let value = authority.projection_value()?;
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(Self {
            version: PAYLOAD_AUTHORITY_VERSION,
            source_digest_hex: authority.digest_hex(),
            bytes,
        })
    }

    /// Proves this projection is a derivative of the given authority by
    /// re-deriving and comparing. A mismatch is a corrupt or substituted
    /// projection, reported as a typed error rather than a silent fallback.
    pub fn verify_against(&self, authority: &ExactJsonBytes) -> Result<(), StoreError> {
        if self.version != PAYLOAD_AUTHORITY_VERSION {
            return Err(StoreError::InvalidField {
                field: "payload.projection_version",
                reason: "unsupported payload projection version",
            });
        }
        let expected = Self::from_authority(authority)?;
        if self.bytes != expected.bytes || self.source_digest_hex != expected.source_digest_hex {
            return Err(StoreError::InvalidField {
                field: "payload.projection",
                reason: "queryable projection is not a derivative of the payload authority",
            });
        }
        Ok(())
    }
}

/// Rejects one decoded parameter name that would override operation,
/// session, fence, authority, receipt, or idempotency control identity.
pub fn reject_control_parameter_name(name: &str) -> Result<(), StoreError> {
    if CONTROL_FIELD_DENYLIST.contains(&name) {
        return Err(StoreError::InvalidField {
            field: "payload.control_field",
            reason: "payload must not override a control field",
        });
    }
    Ok(())
}

/// Reports whether a lexical JSON number token would lose information by
/// passing through `f64`.
///
/// Integers that fit `i64`/`u64` are preserved exactly by `serde_json` and
/// never narrow. Anything else narrows unless its lexical form already
/// equals the shortest `f64` round-trip rendering.
#[must_use]
pub fn number_token_would_narrow(token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    let is_float = token
        .bytes()
        .any(|byte| byte == b'.' || byte == b'e' || byte == b'E');
    if !is_float {
        if token.parse::<i64>().is_ok() {
            return false;
        }
        if !token.starts_with('-') && token.parse::<u64>().is_ok() {
            return false;
        }
        return true;
    }
    match token.parse::<f64>() {
        Ok(value) if value.is_finite() => format!("{value}") != token,
        _ => true,
    }
}

/// Distinguishes the JSON shape of a decoded value for typed diagnostics.
/// The authority itself never needs this: opaque bytes already keep `null`,
/// `false`, `0`, `""`, `[]`, and `{}` distinct without interpretation.
#[must_use]
pub fn json_shape_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn hex_encode_32(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode_32(text: &str) -> Result<[u8; 32], ()> {
    if text.len() != 64 {
        return Err(());
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

mod digest_hex_serde {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    use super::hex_decode_32;
    use super::hex_encode_32;

    pub(super) fn serialize<S>(digest: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode_32(digest))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        hex_decode_32(&text)
            .map_err(|()| D::Error::custom("payload digest must be lowercase SHA-256 hex"))
    }
}

/// Rejects duplicate object keys at any nesting level, comparing keys by
/// decoded value so `"a"` and `"\u0061"` count as the same key.
///
/// The input already passed `serde_json`, so this scanner assumes valid
/// syntax and fails closed on anything it cannot structurally account for.
fn reject_duplicate_object_keys(text: &str) -> Result<(), StoreError> {
    let mut cursor = KeyCursor::new(text);
    cursor.skip_ws();
    cursor.parse_value()?;
    cursor.skip_ws();
    if cursor.peek().is_some() {
        return Err(StoreError::InvalidField {
            field: "payload.bytes",
            reason: "payload authority bytes are not a single JSON value",
        });
    }
    Ok(())
}

struct KeyCursor<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> KeyCursor<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos += 1;
    }

    fn fail(&self) -> StoreError {
        StoreError::InvalidField {
            field: "payload.bytes",
            reason: "payload authority bytes are not a single JSON value",
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), StoreError> {
        if self.peek() == Some(byte) {
            self.bump();
            Ok(())
        } else {
            Err(self.fail())
        }
    }

    fn enter(&mut self) -> Result<(), StoreError> {
        self.depth += 1;
        if self.depth > MAX_PAYLOAD_SCAN_DEPTH {
            return Err(StoreError::PayloadTooLarge);
        }
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<(), StoreError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(_) => self.parse_scalar(),
            None => Err(self.fail()),
        }
    }

    fn parse_object(&mut self) -> Result<(), StoreError> {
        self.enter()?;
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            self.exit();
            return Ok(());
        }
        let mut keys = BTreeSet::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.fail());
            }
            let key = self.parse_string()?;
            if !keys.insert(key) {
                return Err(StoreError::Duplicate {
                    field: "payload.object_key",
                });
            }
            self.skip_ws();
            self.expect(b':')?;
            self.parse_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    self.exit();
                    return Ok(());
                }
                _ => return Err(self.fail()),
            }
        }
    }

    fn parse_array(&mut self) -> Result<(), StoreError> {
        self.enter()?;
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            self.exit();
            return Ok(());
        }
        loop {
            self.parse_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    self.exit();
                    return Ok(());
                }
                _ => return Err(self.fail()),
            }
        }
    }

    fn parse_scalar(&mut self) -> Result<(), StoreError> {
        match self.peek() {
            Some(b't') => self.parse_keyword("true"),
            Some(b'f') => self.parse_keyword("false"),
            Some(b'n') => self.parse_keyword("null"),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(self.fail()),
        }
    }

    fn parse_keyword(&mut self, keyword: &str) -> Result<(), StoreError> {
        if self.bytes.get(self.pos..self.pos + keyword.len()) == Some(keyword.as_bytes()) {
            self.pos += keyword.len();
            Ok(())
        } else {
            Err(self.fail())
        }
    }

    fn parse_number(&mut self) -> Result<(), StoreError> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E') {
                self.bump();
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.fail());
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, StoreError> {
        self.expect(b'"')?;
        let mut decoded = String::new();
        let mut run_start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.fail()),
                Some(b'"') => {
                    decoded.push_str(&self.text[run_start..self.pos]);
                    self.bump();
                    return Ok(decoded);
                }
                Some(b'\\') => {
                    decoded.push_str(&self.text[run_start..self.pos]);
                    self.bump();
                    let escape = self.peek().ok_or_else(|| self.fail())?;
                    self.bump();
                    match escape {
                        b'"' => decoded.push('"'),
                        b'\\' => decoded.push('\\'),
                        b'/' => decoded.push('/'),
                        b'b' => decoded.push('\u{0008}'),
                        b'f' => decoded.push('\u{000C}'),
                        b'n' => decoded.push('\n'),
                        b'r' => decoded.push('\r'),
                        b't' => decoded.push('\t'),
                        b'u' => decoded.push(self.parse_unicode_escape()?),
                        _ => return Err(self.fail()),
                    }
                    run_start = self.pos;
                }
                Some(byte) if byte < 0x80 => self.bump(),
                Some(_) => self.advance_char()?,
            }
        }
    }

    fn advance_char(&mut self) -> Result<(), StoreError> {
        let lead = self.peek().ok_or_else(|| self.fail())?;
        let width = if lead >= 0xF0 {
            4
        } else if lead >= 0xE0 {
            3
        } else if lead >= 0xC0 {
            2
        } else {
            return Err(self.fail());
        };
        if self.pos + width > self.bytes.len() {
            return Err(self.fail());
        }
        self.pos += width;
        Ok(())
    }

    fn parse_unicode_escape(&mut self) -> Result<char, StoreError> {
        let high = self.parse_hex4()?;
        if (0xD800..0xDC00).contains(&high) {
            if self.peek() == Some(b'\\') {
                self.bump();
                if self.peek() == Some(b'u') {
                    self.bump();
                    let low = self.parse_hex4()?;
                    if (0xDC00..0xE000).contains(&low) {
                        let scalar =
                            0x1_0000 + (u32::from(high - 0xD800) << 10) + u32::from(low - 0xDC00);
                        return char::from_u32(scalar).ok_or_else(|| self.fail());
                    }
                }
            }
            return Err(self.fail());
        }
        if (0xDC00..0xE000).contains(&high) {
            return Err(self.fail());
        }
        char::from_u32(u32::from(high)).ok_or_else(|| self.fail())
    }

    fn parse_hex4(&mut self) -> Result<u16, StoreError> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let byte = self.peek().ok_or_else(|| self.fail())?;
            let nibble = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a') + 10,
                b'A'..=b'F' => u16::from(byte - b'A') + 10,
                _ => return Err(self.fail()),
            };
            value = value.saturating_mul(16).saturating_add(nibble);
            self.bump();
        }
        Ok(value)
    }
}

/// Collects the lexical number tokens of one validated JSON text, skipping
/// string contents (including record-like strings such as
/// `"observation:01234567-..."`) so textual identifiers are never mistaken
/// for numbers.
fn collect_number_tokens(text: &str) -> Result<Vec<String>, StoreError> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
        } else if byte == b'"' {
            in_string = true;
            index += 1;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit()
                    || matches!(bytes[index], b'+' | b'-' | b'.' | b'e' | b'E'))
            {
                index += 1;
            }
            tokens.push(text[start..index].to_owned());
        } else {
            index += 1;
        }
    }
    if in_string {
        return Err(StoreError::InvalidField {
            field: "payload.bytes",
            reason: "payload authority bytes are not a single JSON value",
        });
    }
    Ok(tokens)
}
