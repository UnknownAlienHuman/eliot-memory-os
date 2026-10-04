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
    /// Every byte is lowercase ASCII, a space or a colon, so the string cannot
    /// carry a mixed-case member name out of the document it rejected.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "strict json: document exceeds byte ceiling",
            Self::Malformed => "strict json: malformed or trailing json document",
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

#[cfg(test)]
mod tests {
    use super::{StrictJsonErrorKind, strict_json_value};
    use serde_json::Value;

    #[test]
    fn rejects_duplicate_members_at_top_level() -> Result<(), &'static str> {
        let bytes = br#"{"scope":1,"scope":2}"#;
        let Err(error) = strict_json_value(bytes, bytes.len()) else {
            return Err("a top-level duplicate member was unexpectedly accepted");
        };
        assert_eq!(error.kind, StrictJsonErrorKind::DuplicateKey);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_members_at_nested_object_depth() -> Result<(), &'static str> {
        let bytes = br#"{"outer":{"inner":{"leaf":1,"leaf":2}}}"#;
        let Err(error) = strict_json_value(bytes, bytes.len()) else {
            return Err("a duplicate member at nested depth was unexpectedly accepted");
        };
        assert_eq!(error.kind, StrictJsonErrorKind::DuplicateKey);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_members_inside_array_elements() -> Result<(), &'static str> {
        let bytes = br#"[{"scope":1},{"scope":2,"scope":3}]"#;
        let Err(error) = strict_json_value(bytes, bytes.len()) else {
            return Err("a duplicate member inside an array element was unexpectedly accepted");
        };
        assert_eq!(error.kind, StrictJsonErrorKind::DuplicateKey);
        Ok(())
    }

    #[test]
    fn rejects_equal_duplicate_values_with_the_duplicate_kind() -> Result<(), &'static str> {
        let bytes = br#"{"scope":"same","scope":"same"}"#;
        let Err(error) = strict_json_value(bytes, bytes.len()) else {
            return Err("an equal duplicate value was unexpectedly accepted");
        };
        assert_eq!(error.kind, StrictJsonErrorKind::DuplicateKey);
        assert_ne!(error.kind, StrictJsonErrorKind::Malformed);
        Ok(())
    }

    #[test]
    fn escape_equivalent_spellings_collide_as_duplicates() -> Result<(), &'static str> {
        let bytes = br#"{"scope":1,"\u0073cope":2}"#;
        assert!(
            serde_json::from_slice::<Value>(bytes).is_ok(),
            "serde_json must collapse this document, otherwise the fixture proves nothing"
        );
        let Err(error) = strict_json_value(bytes, bytes.len()) else {
            return Err("escape-equivalent member spellings were unexpectedly accepted");
        };
        assert_eq!(error.kind, StrictJsonErrorKind::DuplicateKey);
        Ok(())
    }

    #[test]
    fn case_different_member_names_stay_distinct() -> Result<(), &'static str> {
        let bytes = br#"{"Scope":1,"scope":2}"#;
        let Ok(value) = strict_json_value(bytes, bytes.len()) else {
            return Err("case-different member names were unexpectedly rejected");
        };
        let Some(object) = value.as_object() else {
            return Err("the accepted value was not a JSON object");
        };
        assert_eq!(object.len(), 2);
        assert_eq!(object.get("Scope").and_then(Value::as_i64), Some(1));
        assert_eq!(object.get("scope").and_then(Value::as_i64), Some(2));
        Ok(())
    }

    #[test]
    fn repeated_array_elements_remain_accepted_domain_data() -> Result<(), &'static str> {
        let numbers = b"[1,1,1]";
        let Ok(repeated_numbers) = strict_json_value(numbers, numbers.len()) else {
            return Err("repeated array elements were unexpectedly rejected");
        };
        assert_eq!(
            repeated_numbers,
            Value::Array(vec![Value::from(1), Value::from(1), Value::from(1)])
        );
        let Some(number_items) = repeated_numbers.as_array() else {
            return Err("the accepted number array was not a JSON array");
        };
        assert_eq!(number_items.len(), 3);

        let strings = br#"["a","a"]"#;
        let Ok(repeated_strings) = strict_json_value(strings, strings.len()) else {
            return Err("repeated string elements were unexpectedly rejected");
        };
        assert_eq!(
            repeated_strings,
            Value::Array(vec![
                Value::String("a".to_owned()),
                Value::String("a".to_owned()),
            ])
        );
        let Some(string_items) = repeated_strings.as_array() else {
            return Err("the accepted string array was not a JSON array");
        };
        assert_eq!(string_items.len(), 2);
        Ok(())
    }

    #[test]
    fn malformed_utf8_is_rejected_as_malformed() -> Result<(), &'static str> {
        let bytes = b"{\"scope\":\"\xff\"}";
        let Err(error) = strict_json_value(bytes, bytes.len()) else {
            return Err("malformed UTF-8 was unexpectedly accepted");
        };
        assert_eq!(error.kind, StrictJsonErrorKind::Malformed);
        Ok(())
    }

    #[test]
    fn trailing_non_whitespace_bytes_are_rejected_as_malformed() -> Result<(), &'static str> {
        for bytes in [&b"{} {}"[..], &b"{}x"[..]] {
            let Err(error) = strict_json_value(bytes, bytes.len()) else {
                return Err("a document with trailing bytes was unexpectedly accepted");
            };
            assert_eq!(error.kind, StrictJsonErrorKind::Malformed);
        }
        let whitespace_only = b"{} \n\t";
        let Ok(value) = strict_json_value(whitespace_only, whitespace_only.len()) else {
            return Err("trailing whitespace was unexpectedly rejected");
        };
        assert_eq!(value, Value::Object(serde_json::Map::new()));
        Ok(())
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() -> Result<(), &'static str> {
        let malformed = b"{\"scope\":";
        let Err(malformed_error) = strict_json_value(malformed, malformed.len() - 1) else {
            return Err("an oversized malformed document was unexpectedly accepted");
        };
        assert_eq!(malformed_error.kind, StrictJsonErrorKind::TooLarge);

        let duplicate = b"{\"scope\":1,\"scope\":2}";
        let Err(duplicate_error) = strict_json_value(duplicate, duplicate.len() - 1) else {
            return Err("an oversized duplicate document was unexpectedly accepted");
        };
        assert_eq!(duplicate_error.kind, StrictJsonErrorKind::TooLarge);

        let at_ceiling = b"{\"scope\":1}";
        let Ok(value) = strict_json_value(at_ceiling, at_ceiling.len()) else {
            return Err("a document exactly at the byte ceiling was unexpectedly rejected");
        };
        assert_eq!(value.get("scope").and_then(Value::as_i64), Some(1));
        Ok(())
    }

    #[test]
    fn rejection_reasons_leak_neither_input_bytes_nor_member_names() -> Result<(), &'static str> {
        const KEY: &str = "memberNameThatMustNeverLeak";
        const PAYLOAD: &str = "payloadValueThatMustNeverLeak";

        let duplicate = format!(r#"{{"{KEY}":"{PAYLOAD}","{KEY}":"{PAYLOAD}"}}"#);
        let Err(duplicate_error) = strict_json_value(duplicate.as_bytes(), duplicate.len()) else {
            return Err("the duplicate fixture was unexpectedly accepted");
        };
        let malformed = r#"{"memberNameThatMustNeverLeak":"payloadValueThatMustNeverLeak""#;
        let malformed_bytes = malformed.as_bytes();
        let Err(malformed_error) = strict_json_value(malformed_bytes, malformed_bytes.len()) else {
            return Err("the truncated fixture was unexpectedly accepted");
        };
        let Err(oversized_error) = strict_json_value(malformed_bytes, malformed_bytes.len() - 1)
        else {
            return Err("the oversized fixture was unexpectedly accepted");
        };

        for error in [duplicate_error, malformed_error, oversized_error] {
            let reason = error.kind.as_str();
            assert!(
                !reason.contains(KEY),
                "the duplicate member name leaked into {reason:?}"
            );
            assert!(
                !reason.contains(PAYLOAD),
                "input bytes leaked into {reason:?}"
            );
            for byte in reason.bytes() {
                assert!(
                    byte.is_ascii_lowercase() || byte == b' ' || byte == b':',
                    "the rejection reason leaked an unexpected byte {byte:?} in {reason:?}"
                );
            }
            assert_eq!(error.to_string(), reason);
        }
        Ok(())
    }

    #[test]
    fn accepted_document_equals_serde_json_from_slice() -> Result<(), &'static str> {
        let document = r#"{"scope":1,"Scope":2,"nested":{"a":true,"b":null,"deep":{"k":"v"}},"array":[1,1,"a"],"float":1.5,"esc":"cope"}"#;
        let bytes = document.as_bytes();
        let Ok(strict) = strict_json_value(bytes, bytes.len()) else {
            return Err("a duplicate-free document was unexpectedly rejected");
        };
        let Ok(reference) = serde_json::from_slice::<Value>(bytes) else {
            return Err("serde_json rejected the duplicate-free reference document");
        };
        assert_eq!(strict, reference);
        Ok(())
    }
}
