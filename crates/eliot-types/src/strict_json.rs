//! Duplicate-rejecting raw JSON ingress for one bounded, untrusted byte slice.
//!
//! `serde_json::Map` is a `BTreeMap` unless the workspace enables the
//! `serde_json` `preserve_order` feature, so a repeated JSON object member is
//! collapsed to last-wins the instant raw bytes become a `serde_json::Value`.
//! Every later consumer of that value — a `#[serde(deny_unknown_fields)]` DTO,
//! a custom duplicate-rejecting field deserializer, or a JSON Schema validator
//! — then sees only the collapsed projection and cannot distinguish a duplicate
//! document from its last-wins equivalent.
//!
//! This module owns the single shared lexical decoder. It observes object
//! members through `MapAccess` before `serde_json::Value` construction, so a
//! duplicate member is a hard error at every object depth, including top-level
//! identity/version/discriminator fields and nested objects inside arrays.
//! Member names are compared as fully decoded `String`s, so escape-equivalent
//! spellings of one key collide while case-different names stay distinct.
//! Arrays are traversed, but repeated array elements are ordinary domain data
//! and are never treated as object-key duplicates.
//!
//! Malformed JSON, malformed UTF-8 and trailing non-whitespace data are
//! rejected by the serde JSON document decoder itself; there is no hand-rolled
//! pre-scan. This cell owns lexical JSON integrity only: no domain schema, no
//! provider policy, no authority, no persistence, and no secret vocabulary.
//! For every accepted document the returned value is identical to
//! `serde_json::from_slice`, so accepted bytes keep their existing downstream
//! result and no wire or schema version changes.

use std::collections::HashSet;
use std::fmt;

use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Internal marker used to classify a duplicate member inside the serde JSON
/// decoder's own error. It is never returned to a caller: the decoder
/// re-emits it as `StrictJsonErrorKind::DuplicateKey` and otherwise reports a
/// bounded, redacted reason.
const DUPLICATE_MEMBER_MARKER: &str = "strict json: duplicate object member";

/// Internal, bounded, non-content-bearing rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictJsonErrorKind {
    /// The input exceeded the caller-supplied maximum byte length.
    TooLarge,
    /// Malformed UTF-8, malformed JSON, or trailing non-whitespace data.
    Malformed,
    /// A repeated object member at any depth, compared on the decoded name.
    DuplicateKey,
}

impl StrictJsonErrorKind {
    /// Stable, redacted, caller-safe reason string.
    ///
    /// Never contains input bytes, an offset, or the duplicate member value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "strict json: document exceeds byte ceiling",
            Self::Malformed => "strict json: malformed or trailing JSON document",
            Self::DuplicateKey => DUPLICATE_MEMBER_MARKER,
        }
    }
}

/// Bounded, redacted lexical rejection. It carries a category only: no input
/// bytes, no offset, and no duplicate member value ever reach the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictJsonError {
    /// Which lexical failure class was detected.
    pub kind: StrictJsonErrorKind,
}

impl StrictJsonError {
    const fn new(kind: StrictJsonErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.as_str())
    }
}

impl std::error::Error for StrictJsonError {}

/// Decodes exactly one bounded JSON document into a duplicate-clean
/// `serde_json::Value`.
///
/// Rejects an input longer than `max_bytes` before parsing, a repeated object
/// member at any depth, and any malformed or trailing document. The returned
/// value is the same value `serde_json::from_slice` would produce for an
/// accepted document, so callers may hand that one value to every downstream
/// validator without a second read of the bytes.
pub fn strict_json_value(bytes: &[u8], max_bytes: usize) -> Result<Value, StrictJsonError> {
    if bytes.len() > max_bytes {
        return Err(StrictJsonError::new(StrictJsonErrorKind::TooLarge));
    }
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|strict| strict.0)
        .map_err(|error| {
            StrictJsonError::new(if error.to_string().starts_with(DUPLICATE_MEMBER_MARKER) {
                StrictJsonErrorKind::DuplicateKey
            } else {
                StrictJsonErrorKind::Malformed
            })
        })
}

/// Validates that one JSON document has no duplicate object member and then
/// discards the decoded value.
///
/// This is the validate-only entry point for callers that decode the document a
/// second time through their own typed deserializer. It applies no byte
/// ceiling: the caller owns its own size bound, and a caller that has none must
/// establish one before treating unbounded bytes as bounded input.
pub fn strict_json_has_no_duplicate_members(bytes: &[u8]) -> Result<(), StrictJsonError> {
    strict_json_value(bytes, bytes.len()).map(|_| ())
}

/// Strict JSON value that rejects an object duplicate at every depth.
struct StrictValue(Value);

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON value without duplicate object members")
    }

    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        StrictValue::deserialize(deserializer)
    }

    fn visit_bool<E: DeError>(self, v: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_i64<E: DeError>(self, v: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(v.into())))
    }

    fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(v.into())))
    }

    fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
        let number = serde_json::Number::from_f64(v)
            .ok_or_else(|| E::custom("strict json: unrepresentable JSON number"))?;
        Ok(StrictValue(Value::Number(number)))
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v.to_owned())))
    }

    fn visit_borrowed_str<E: DeError>(self, v: &'de str) -> Result<Self::Value, E> {
        self.visit_str(v)
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v)))
    }

    fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
        let text = std::str::from_utf8(v)
            .map_err(|_| E::custom("strict json: invalid UTF-8 document bytes"))?;
        self.visit_str(text)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(elem) = seq.next_element::<StrictValue>()? {
            items.push(elem.0);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = serde_json::Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(DUPLICATE_MEMBER_MARKER));
            }
            let nested: StrictValue = map.next_value()?;
            object.insert(key, nested.0);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}
