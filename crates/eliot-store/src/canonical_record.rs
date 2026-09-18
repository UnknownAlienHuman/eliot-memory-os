//! Canonical-record wire/deserialization cell — read-only lossless projection.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for canonical records. It decodes the canonical wire losslessly (prefers `receipt_body_json_b64` `STANDARD_NO_PAD` bytes, falls back to legacy `receipt_body`) without acquiring canonical authority, lifecycle, frozen/Luna/Dreamer, write ownership, or provider semantics.
//! This is a read-only lossless wire projection with no canonical authority. It excludes `CanonicalLifecycleView`, `CanonicalReplayView`, `CanonicalSleepView`, `CanonicalAutonomyRunView`, `SleepCandidatesResponse`, `CanonicalTruncation` and any cognitive/replay/sleep/write-ownership semantics. Mechanical split only.
//! F-DENY-LS-RECORD (#976, child of #710, rows owned by #929): the manual
//! envelope decoder denies unknown envelope fields and duplicate envelope keys
//! (including JSON escape-equivalent names) before a trusted record escapes.
//! The two supported wire forms are preserved: `receipt_body_json_b64`
//! (`STANDARD_NO_PAD`) preferred when present, else legacy `receipt_body`.
//! Invalid base64 or invalid selected JSON never falls back to legacy.
//! Duplicate evidence inside the legacy body is preserved through a
//! duplicate-sensitive capture until selection has run; base64-decoded bodies
//! receive the same duplicate/trailing-data treatment plus actual generic-`T`
//! validation. Input already supplied as `serde_json::Value` has lost its
//! lexical duplicate history, so this decoder cannot credit it with a
//! raw-ingress duplicate guarantee; that weaker provenance requires a distinct
//! upstream #929 row and concrete owner. Diagnostics are redacted and
//! non-authoritative.

use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use eliot_types::{MemoryRevision, ProjectId, ProjectSequence, TaskId, WriteReceiptRef};
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize)]
pub struct CanonicalRecord<T> {
    pub record_id: String,
    pub receipt_kind: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub subject_ref: String,
    pub receipt_body: T,
    pub canonical_receipt: WriteReceiptRef,
    pub memory_revision: Option<MemoryRevision>,
    pub project_sequence: Option<ProjectSequence>,
}

impl<T: fmt::Debug> fmt::Debug for CanonicalRecord<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalRecord")
            .field("record_id", &self.record_id)
            .field("receipt_kind", &self.receipt_kind)
            .field("project_id", &self.project_id)
            .field("task_id", &self.task_id)
            .field("subject_ref", &self.subject_ref)
            .field("receipt_body", &"[redacted]")
            .field("canonical_receipt", &self.canonical_receipt)
            .field("memory_revision", &self.memory_revision)
            .field("project_sequence", &self.project_sequence)
            .finish()
    }
}

/// Duplicate-sensitive capture for the legacy body path.
///
/// The capture observes every object key through `MapAccess` (so JSON escape
/// equivalents collapse to the same `String` and count as duplicates) and
/// records whether any object at any depth repeated a key. It defers the
/// failure until envelope selection has run, so a valid `receipt_body_json_b64`
/// record keeps its established precedence even when the ignored legacy field
/// differs. Last-wins `Value` semantics are used only after the duplicate flag
/// has been checked; an unchecked `Value` is never the duplicate proof.
struct LegacyBodyCapture {
    value: Value,
    had_duplicates: bool,
}

impl LegacyBodyCapture {
    fn null() -> Self {
        Self {
            value: Value::Null,
            had_duplicates: false,
        }
    }
}

struct LegacyCaptureVisitor;

impl<'de> Visitor<'de> for LegacyCaptureVisitor {
    type Value = LegacyBodyCapture;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON body value")
    }

    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture::null())
    }

    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture::null())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        LegacyBodyCapture::deserialize(deserializer)
    }

    fn visit_bool<E: DeError>(self, v: bool) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture {
            value: Value::Bool(v),
            had_duplicates: false,
        })
    }

    fn visit_i64<E: DeError>(self, v: i64) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture {
            value: Value::Number(v.into()),
            had_duplicates: false,
        })
    }

    fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture {
            value: Value::Number(v.into()),
            had_duplicates: false,
        })
    }

    fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
        let number = serde_json::Number::from_f64(v)
            .ok_or_else(|| E::custom("canonical record: invalid number"))?;
        Ok(LegacyBodyCapture {
            value: Value::Number(number),
            had_duplicates: false,
        })
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture {
            value: Value::String(v.to_owned()),
            had_duplicates: false,
        })
    }

    fn visit_borrowed_str<E: DeError>(self, v: &'de str) -> Result<Self::Value, E> {
        self.visit_str(v)
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        Ok(LegacyBodyCapture {
            value: Value::String(v),
            had_duplicates: false,
        })
    }

    fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
        let text = std::str::from_utf8(v)
            .map_err(|_| E::custom("canonical record: invalid body bytes"))?;
        self.visit_str(text)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        let mut had_duplicates = false;
        while let Some(elem) = seq.next_element::<LegacyBodyCapture>()? {
            had_duplicates = had_duplicates || elem.had_duplicates;
            items.push(elem.value);
        }
        Ok(LegacyBodyCapture {
            value: Value::Array(items),
            had_duplicates,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = serde_json::Map::new();
        let mut seen = HashSet::new();
        let mut had_duplicates = false;
        while let Some(key) = map.next_key::<String>()? {
            let nested: LegacyBodyCapture = map.next_value()?;
            if !seen.insert(key.clone()) {
                had_duplicates = true;
            }
            had_duplicates = had_duplicates || nested.had_duplicates;
            object.insert(key, nested.value);
        }
        Ok(LegacyBodyCapture {
            value: Value::Object(object),
            had_duplicates,
        })
    }
}

impl<'de> Deserialize<'de> for LegacyBodyCapture {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LegacyCaptureVisitor)
    }
}

/// Strict JSON value used to validate base64-decoded bodies.
///
/// Unlike `serde_json::Value`, object duplicates at any depth are a hard
/// error here, so a `Value`-shaped protected body cannot smuggle a duplicate
/// past the decoder. Errors are redacted and never echo input.
struct StrictValue(Value);

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON body value without duplicate keys")
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
            .ok_or_else(|| E::custom("canonical record: invalid number"))?;
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
            .map_err(|_| E::custom("canonical record: invalid body bytes"))?;
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
                return Err(A::Error::custom("canonical record: duplicate body field"));
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

fn strict_body_has_no_duplicates<E: DeError>(bytes: &[u8]) -> Result<(), E> {
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|_| ())
        .map_err(|_| E::custom("canonical record: invalid protected body"))?;
    Ok(())
}

struct EnvelopeAcc {
    seen: HashSet<String>,
    record_id: Option<String>,
    receipt_kind: Option<String>,
    project_id: Option<ProjectId>,
    task_id: Option<TaskId>,
    subject_ref: Option<String>,
    receipt_body: Option<LegacyBodyCapture>,
    b64: Option<String>,
    canonical_receipt: Option<WriteReceiptRef>,
    memory_revision: Option<MemoryRevision>,
    project_sequence: Option<ProjectSequence>,
}

impl EnvelopeAcc {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            record_id: None,
            receipt_kind: None,
            project_id: None,
            task_id: None,
            subject_ref: None,
            receipt_body: None,
            b64: None,
            canonical_receipt: None,
            memory_revision: None,
            project_sequence: None,
        }
    }

    fn mark<'de, A: MapAccess<'de>>(&mut self, key: &str) -> Result<(), A::Error> {
        if !self.seen.insert(key.to_owned()) {
            return Err(A::Error::custom(
                "canonical record: duplicate envelope field",
            ));
        }
        Ok(())
    }

    fn take_record_id<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("record_id")?;
        self.record_id = Some(map.next_value()?);
        Ok(())
    }

    fn take_receipt_kind<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("receipt_kind")?;
        self.receipt_kind = Some(map.next_value()?);
        Ok(())
    }

    fn take_project_id<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("project_id")?;
        self.project_id = Some(map.next_value()?);
        Ok(())
    }

    fn take_task_id<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("task_id")?;
        self.task_id = map.next_value()?;
        Ok(())
    }

    fn take_subject_ref<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("subject_ref")?;
        self.subject_ref = Some(map.next_value()?);
        Ok(())
    }

    fn take_body<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("receipt_body")?;
        self.receipt_body = Some(map.next_value()?);
        Ok(())
    }

    fn take_b64<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error> {
        self.mark::<A>("receipt_body_json_b64")?;
        self.b64 = map.next_value()?;
        Ok(())
    }

    fn take_canonical_receipt<'de, A: MapAccess<'de>>(
        &mut self,
        map: &mut A,
    ) -> Result<(), A::Error> {
        self.mark::<A>("canonical_receipt")?;
        self.canonical_receipt = Some(map.next_value()?);
        Ok(())
    }

    fn take_memory_revision<'de, A: MapAccess<'de>>(
        &mut self,
        map: &mut A,
    ) -> Result<(), A::Error> {
        self.mark::<A>("memory_revision")?;
        self.memory_revision = map.next_value()?;
        Ok(())
    }

    fn take_project_sequence<'de, A: MapAccess<'de>>(
        &mut self,
        map: &mut A,
    ) -> Result<(), A::Error> {
        self.mark::<A>("project_sequence")?;
        self.project_sequence = map.next_value()?;
        Ok(())
    }
}

struct EnvelopeVisitor<T>(PhantomData<T>);

impl<'de, T: DeserializeOwned> Visitor<'de> for EnvelopeVisitor<T> {
    type Value = CanonicalRecord<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("canonical record envelope without unknown or duplicate fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut acc = EnvelopeAcc::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "record_id" => acc.take_record_id(&mut map)?,
                "receipt_kind" => acc.take_receipt_kind(&mut map)?,
                "project_id" => acc.take_project_id(&mut map)?,
                "task_id" => acc.take_task_id(&mut map)?,
                "subject_ref" => acc.take_subject_ref(&mut map)?,
                "receipt_body" => acc.take_body(&mut map)?,
                "receipt_body_json_b64" => acc.take_b64(&mut map)?,
                "canonical_receipt" => acc.take_canonical_receipt(&mut map)?,
                "memory_revision" => acc.take_memory_revision(&mut map)?,
                "project_sequence" => acc.take_project_sequence(&mut map)?,
                _ => return Err(A::Error::custom("canonical record: unknown envelope field")),
            }
        }
        finish_envelope(acc)
    }
}

fn finish_envelope<T: DeserializeOwned, E: DeError>(
    acc: EnvelopeAcc,
) -> Result<CanonicalRecord<T>, E> {
    let record_id = acc.record_id.ok_or_else(|| E::missing_field("record_id"))?;
    let receipt_kind = acc
        .receipt_kind
        .ok_or_else(|| E::missing_field("receipt_kind"))?;
    let Some(project_id) = acc.project_id else {
        return Err(E::missing_field("project_id"));
    };
    let Some(subject_ref) = acc.subject_ref else {
        return Err(E::missing_field("subject_ref"));
    };
    let Some(canonical_receipt) = acc.canonical_receipt else {
        return Err(E::missing_field("canonical_receipt"));
    };
    let receipt_body = if let Some(encoded) = acc.b64 {
        let bytes = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| E::custom("canonical record: invalid protected body"))?;
        strict_body_has_no_duplicates::<E>(&bytes)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| E::custom("canonical record: invalid protected body"))?
    } else {
        let capture = acc.receipt_body.unwrap_or_else(LegacyBodyCapture::null);
        if capture.had_duplicates {
            return Err(E::custom("canonical record: duplicate body field"));
        }
        serde_json::from_value(capture.value)
            .map_err(|_| E::custom("canonical record: invalid protected body"))?
    };
    Ok(CanonicalRecord {
        record_id,
        receipt_kind,
        project_id,
        task_id: acc.task_id,
        subject_ref,
        receipt_body,
        canonical_receipt,
        memory_revision: acc.memory_revision,
        project_sequence: acc.project_sequence,
    })
}

impl<'de, T> Deserialize<'de> for CanonicalRecord<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(EnvelopeVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::CanonicalRecord;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use eliot_types::{ProjectId, ReceiptId, WriteId};
    use serde_json::{Value, json};

    fn wire_record(receipt_body: &Value) -> Value {
        json!({
            "record_id": WriteId::new_v7().to_string(),
            "receipt_kind": "autonomy_budget_ledger",
            "project_id": ProjectId::new_v7(),
            "task_id": null,
            "subject_ref": "autonomy:operator-runtime-proof",
            "receipt_body": receipt_body,
            "canonical_receipt": {
                "receipt_id": ReceiptId::new_v7(),
                "write_id": WriteId::new_v7(),
            },
            "memory_revision": 1,
            "project_sequence": 1,
        })
    }

    #[test]
    fn canonical_record_prefers_lossless_json_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let expected = json!({"target_ref": "memory:operator-runtime-proof"});
        let mut wire = wire_record(&json!({"target_ref": "memory:operator"}));
        wire["receipt_body_json_b64"] =
            Value::String(STANDARD_NO_PAD.encode(serde_json::to_vec(&expected)?));

        let record: CanonicalRecord<Value> = serde_json::from_value(wire)?;
        assert_eq!(record.receipt_body, expected);
        Ok(())
    }

    #[test]
    fn canonical_record_reads_legacy_receipt_body_without_lossless_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let legacy = json!({"state": "active"});
        let record: CanonicalRecord<Value> = serde_json::from_value(wire_record(&legacy))?;

        assert_eq!(record.receipt_body, legacy);
        Ok(())
    }
}
