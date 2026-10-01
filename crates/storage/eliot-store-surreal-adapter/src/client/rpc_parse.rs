//! Pure `SurrealDB` JSON-RPC/provider-version parsing cell extracted from `client.rs`.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I5.1, I5.9, I5.22, I2.23.
//! Ownership: pure `RpcResponse` envelope and `surrealdb-3.1`/`3.2` `ProviderVersion` parsing only, plus the ELIOT-owned [`ResponseCeiling`] a bounded capture carries into the transport (issue #951); no transport, auth, handshake, process-spawn, or lifecycle ownership (see `crates/storage/eliot-store-surreal-adapter/src/client.rs`).

use std::cell::Cell;
use std::fmt;

use serde::Deserialize;
use serde::de::{
    DeserializeSeed, Deserializer, Error as SerdeError, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde_json::Value;

use eliot_store_api::StoreError;

use crate::error::AdapterError;

#[derive(Debug, Deserialize)]
pub(super) struct RpcResponse {
    pub(super) id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
    data: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderVersion {
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) patch: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderVersionObject {
    version: String,
    build: String,
    timestamp: String,
}

pub(crate) fn provider_version_from_rpc(value: &Value) -> Result<ProviderVersion, AdapterError> {
    match value {
        Value::String(version) => {
            let numeric = version
                .strip_prefix("surrealdb-")
                .ok_or_else(|| invalid_provider_version("legacy string lacks surrealdb- prefix"))?;
            let parsed = parse_provider_semver(numeric)?;
            if parsed.major != 3 || parsed.minor != 1 {
                return Err(invalid_provider_version(
                    "legacy string is only valid for the documented 3.1 response",
                ));
            }
            Ok(parsed)
        }
        Value::Object(_) => {
            let response: ProviderVersionObject = serde_json::from_value(value.clone())
                .map_err(|_| invalid_provider_version("3.2 object shape is invalid"))?;
            if response.build.trim().is_empty()
                || response.timestamp.trim().is_empty()
                || response.build.chars().any(char::is_control)
                || response.timestamp.chars().any(char::is_control)
            {
                return Err(invalid_provider_version(
                    "3.2 object build and timestamp must be non-empty text",
                ));
            }
            let parsed = parse_provider_semver(&response.version)?;
            if parsed.major != 3 || parsed.minor != 2 {
                return Err(invalid_provider_version(
                    "object response is only valid for the documented 3.2 response",
                ));
            }
            Ok(parsed)
        }
        _ => Err(invalid_provider_version(
            "result is neither the 3.1 string nor the 3.2 object",
        )),
    }
}

fn parse_provider_semver(value: &str) -> Result<ProviderVersion, AdapterError> {
    let mut parts = value.split('.');
    let major = parse_version_component(parts.next(), "major")?;
    let minor = parse_version_component(parts.next(), "minor")?;
    let patch = parse_version_component(parts.next(), "patch")?;
    if parts.next().is_some() {
        return Err(invalid_provider_version("version has extra components"));
    }
    Ok(ProviderVersion {
        major,
        minor,
        patch,
    })
}

fn parse_version_component(value: Option<&str>, field: &str) -> Result<u16, AdapterError> {
    let value = value.ok_or_else(|| invalid_provider_version(&format!("missing {field}")))?;
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid_provider_version(&format!(
            "{field} component is not canonical decimal"
        )));
    }
    value
        .parse::<u16>()
        .map_err(|_| invalid_provider_version(&format!("{field} component is out of range")))
}

fn invalid_provider_version(reason: &str) -> AdapterError {
    AdapterError::Config(format!(
        "SurrealDB version RPC returned an incompatible fail-closed response: {reason}"
    ))
}

pub(super) fn parse_response(text: &str) -> Result<RpcResponse, AdapterError> {
    serde_json::from_str(text).map_err(|error| AdapterError::Serialization(error.to_string()))
}

/// The ELIOT-owned response ceiling carried into the RPC transport (issue #951).
///
/// A provider response is unbounded input until this owner says otherwise. A
/// third-party WebSocket default frame/message limit is that library's
/// incidental behaviour, not this bridge's snapshot contract, so the admitted
/// bound is issued here and travels with the admitted capture.
///
/// The value is derived, never chosen: it is the capture's own admitted
/// aggregate byte budget — the `bounds.max_bytes` that
/// [`eliot_store_api::SnapshotBounds::validate`] has already proved non-zero and
/// no stronger than [`eliot_store_api::MAX_SNAPSHOT_BYTES`] — plus
/// [`SNAPSHOT_PROTOCOL_ENVELOPE_BYTES`]. It is therefore never weaker than the
/// admitted `max_bytes`, and a smaller admitted budget yields a smaller, never a
/// laxer, ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseCeiling {
    max_bytes: u64,
}

impl ResponseCeiling {
    /// Issues the transport ceiling for one admitted capture byte budget.
    ///
    /// A zero budget cannot carry a protocol envelope, so it is refused with the
    /// same typed bounded refusal an oversize response gets. Overflow of the
    /// envelope addition is refused for the same reason rather than saturating
    /// to a value that would silently stop bounding anything.
    pub(crate) fn for_admitted_capture(aggregate_bytes: u64) -> Result<Self, AdapterError> {
        if aggregate_bytes == 0 {
            // An admitted budget of zero cannot carry a protocol envelope, and
            // accepting one here would hand the transport a ceiling that no
            // admitted capture ever justified.
            return Err(response_ceiling_refusal());
        }
        let max_bytes = aggregate_bytes
            .checked_add(SNAPSHOT_PROTOCOL_ENVELOPE_BYTES)
            .ok_or_else(response_ceiling_refusal)?;
        Ok(Self { max_bytes })
    }

    /// Largest provider frame, in bytes, this ceiling admits.
    pub(crate) const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    /// Refuses a frame whose length is not admitted.
    ///
    /// Called at the transport boundary before UTF-8 conversion and before any
    /// `Value` construction, which is the only position where an oversize
    /// response can be rejected without materializing it.
    pub(crate) fn admit_frame(self, frame_bytes: usize) -> Result<(), AdapterError> {
        let observed = u64::try_from(frame_bytes).map_err(|_| response_ceiling_refusal())?;
        if observed > self.max_bytes {
            return Err(response_ceiling_refusal());
        }
        Ok(())
    }
}

/// The one typed refusal an unbounded provider response gets.
///
/// It is the existing bounded-store refusal this crate already returns for an
/// over-budget decoded payload ([`StoreError::PayloadTooLarge`]), reused so a
/// refusal before the decode and a refusal after it are one typed outcome
/// rather than two. It is never [`AdapterError::ProviderUnavailable`]: an
/// oversize response observed a source that answered, and reporting it as a
/// provider that is gone would let a bounded refusal masquerade as a
/// retryable transport loss.
fn response_ceiling_refusal() -> AdapterError {
    AdapterError::Store(StoreError::PayloadTooLarge)
}

/// Bytes the pinned JSON-RPC framing spends around one capture's decoded rows.
///
/// **No document names this value.** It is derived from the fixed shapes this
/// crate itself emits and decodes:
///
/// * the request id [`RPC_PROTOCOL_VERSION`](super::RPC_PROTOCOL_VERSION)
///   mints for every named operation, its two separators and its canonical
///   36-character UUID text — bounded, because the operation label is a closed
///   `&'static str` of this registry and the UUID is the only variable part;
/// * the pinned member batch's fixed statement count: the retained
///   `BEGIN TRANSACTION` result, the two capture-point reads, one read per
///   admitted canonical source class, and the `COMMIT TRANSACTION` result, each
///   wrapped in its `{"status":…,"result":…,"time":…}` member set with its
///   separators;
/// * the per-row one-over accounting headroom the member batch's row limit keeps
///   ([`crate::client::MEMBER_CLASS_ROW_LIMIT`](super::MEMBER_CLASS_ROW_LIMIT)
///   rows plus the one extra the statement admits, per captured class), so a
///   class that arrives at exactly the admitted rows plus one is still inside the
///   frame the ceiling allows.
///
/// The envelope is a *charge*, not a heap measurement: it bounds the framing and
/// the one-over accounting slack, not the row content, which the admitted
/// `max_bytes` bounds separately. It is rounded up generously on purpose — a
/// ceiling that is too tight would refuse an admissible capture, while one that
/// is too generous still cannot admit an unbounded response, because the frame
/// itself is charged against the total.
const SNAPSHOT_PROTOCOL_ENVELOPE_BYTES: u64 = 64 * 1024;

/// Static text the bounded reader stops on when a response crosses the
/// admitted aggregate byte budget.
///
/// The bounded reader reports the crossing through a serde error so the parse
/// unwinds immediately and the remainder of an oversize response is never
/// materialized. The text never crosses the crate boundary: the caller maps it
/// back to [`StoreError::PayloadTooLarge`], so a caller still receives the
/// existing typed refusal and never provider prose.
const RESPONSE_BYTE_BUDGET_REFUSAL: &str = "provider response exceeded the admitted byte budget";

/// Decodes one bounded provider response from a borrowed frame.
///
/// This is the read path the transport uses for every bounded capture
/// response. The frame is charged against the ELIOT-owned [`ResponseCeiling`]
/// *before* any UTF-8 conversion and before `serde_json` constructs a single
/// `Value`, so an oversize response is refused without materializing it at all —
/// the binary arm in particular never copies the frame into a second buffer. A
/// frame inside the ceiling is then decoded through a body reader that walks the
/// statement list one statement at a time and stops the moment the response's
/// byte budget is spent, so the remainder of an over-budget response is never
/// decoded into `Value`s.
///
/// Both refusals are the same typed [`StoreError::PayloadTooLarge`].
pub(super) fn parse_response_bounded(
    frame: &[u8],
    ceiling: ResponseCeiling,
) -> Result<RpcResponse, AdapterError> {
    ceiling.admit_frame(frame.len())?;
    let budget_exceeded = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(frame);
    let response = BoundedResponseSeed {
        ceiling,
        budget_exceeded: &budget_exceeded,
    }
    .deserialize(&mut deserializer);
    // A budget crossing is reported by the bounded reader rather than inferred
    // from a serde message, so the exact typed refusal cannot be confused with
    // a malformed response.
    if budget_exceeded.get() {
        return Err(response_ceiling_refusal());
    }
    let response = response.map_err(|error| AdapterError::Serialization(error.to_string()))?;
    // Trailing bytes are still a malformed response, exactly as the unbounded
    // read reports them; bounding the response never loosens its shape.
    deserializer
        .end()
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(response)
}

/// Seed that decodes one response envelope under an admitted byte ceiling.
struct BoundedResponseSeed<'budget> {
    ceiling: ResponseCeiling,
    budget_exceeded: &'budget Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for BoundedResponseSeed<'_> {
    type Value = RpcResponse;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(BoundedResponseVisitor {
            id: None,
            result: None,
            error: None,
            ceiling: self.ceiling,
            budget_exceeded: self.budget_exceeded,
        })
    }
}

/// Map visitor that keeps the envelope fields apart so `result` can be decoded
/// through the bounded body reader.
struct BoundedResponseVisitor<'budget> {
    id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcErrorBody>,
    ceiling: ResponseCeiling,
    budget_exceeded: &'budget Cell<bool>,
}

impl<'de> Visitor<'de> for BoundedResponseVisitor<'_> {
    type Value = RpcResponse;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON-RPC response envelope")
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut access: A) -> Result<Self::Value, A::Error> {
        while let Some(key) = access.next_key::<String>()? {
            match key.as_str() {
                "id" => {
                    self.id = Some(access.next_value()?);
                }
                "result" => {
                    self.result = Some(access.next_value_seed(BoundedResultSeed {
                        ceiling: self.ceiling,
                        budget_exceeded: self.budget_exceeded,
                    })?);
                }
                "error" => {
                    self.error = Some(access.next_value()?);
                }
                _ => {
                    // An envelope member this contract does not read is skipped
                    // by value, not dropped without a decode, so a provider
                    // extension cannot smuggle an unbounded value past the
                    // admitted ceiling through an unread member.
                    access.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(RpcResponse {
            id: self.id,
            result: self.result,
            error: self.error,
        })
    }
}

/// Seed for the response's statement list, decoded incrementally.
struct BoundedResultSeed<'budget> {
    ceiling: ResponseCeiling,
    budget_exceeded: &'budget Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for BoundedResultSeed<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_option(BoundedResultVisitor {
            statements: Vec::new(),
            remaining_bytes: self.ceiling.max_bytes(),
            budget_exceeded: self.budget_exceeded,
        })
    }
}

/// Sequence visitor that charges each decoded statement and stops the decode
/// the moment the response's byte budget is spent.
///
/// The budget charged here is the same admitted ceiling the frame was admitted
/// against — the capture's admitted `max_bytes` plus the fixed registry's
/// bounded protocol envelope — not a second, invented number. A statement can
/// never exceed the frame it arrived in, so this line can only refuse a response
/// whose *decoded* statements cost more than its own frame budget; the frame
/// check above is what refuses a response that is too large to arrive.
struct BoundedResultVisitor<'budget> {
    statements: Vec<Value>,
    remaining_bytes: u64,
    budget_exceeded: &'budget Cell<bool>,
}

impl<'de> Visitor<'de> for BoundedResultVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded provider statement list")
    }

    fn visit_unit<E: SerdeError>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: SerdeError>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut access: A) -> Result<Self::Value, A::Error> {
        while let Some(statement) = access.next_element::<Value>()? {
            // One statement can hold an arbitrarily large schemaless value, so
            // it is charged against the remaining budget *before* it is kept:
            // once that budget is spent the next statement is never decoded and
            // the remainder of the response is left undecoded.
            self.remaining_bytes = self
                .remaining_bytes
                .saturating_sub(statement_charge_bytes(&statement));
            if self.remaining_bytes == 0 {
                self.budget_exceeded.set(true);
                return Err(<A::Error as SerdeError>::custom(
                    RESPONSE_BYTE_BUDGET_REFUSAL,
                ));
            }
            self.statements.push(statement);
        }
        Ok(Value::Array(self.statements))
    }
}

/// Charges one decoded provider statement against the admitted byte budget.
///
/// The same *charge* the capture owner charges a decoded class result for
/// (`backup_snapshot::decoded_class_bytes`): the statement is re-encoded from
/// the value the reader already holds, so key ordering can only move the
/// number and the claim stays a bounded charge of observed statements. A
/// statement that cannot be re-encoded is charged out rather than free.
fn statement_charge_bytes(statement: &Value) -> u64 {
    match serde_json::to_string(statement) {
        Ok(encoded) => u64::try_from(encoded.len()).unwrap_or(u64::MAX),
        Err(_) => u64::MAX,
    }
}

pub(super) fn rpc_result(response: RpcResponse) -> Result<Value, AdapterError> {
    if let Some(error) = response.error {
        let _ = (error.code, error.message, error.data);
        return Err(AdapterError::ProviderUnavailable);
    }
    Ok(response.result.unwrap_or(Value::Null))
}

#[cfg(test)]
mod bounded_response_tests {
    #![allow(clippy::expect_used)]

    use serde_json::json;

    use super::*;
    use crate::client::snapshot_response_ceiling;

    /// The admitted budget these cases use. Chosen inside the closed
    /// [`eliot_store_api::SnapshotBounds`] range so it is a value the existing
    /// `SnapshotBounds::validate` admits, not a shape the API would refuse.
    const ADMITTED_MAX_BYTES: u64 = 4_096;

    fn ceiling() -> ResponseCeiling {
        snapshot_response_ceiling(ADMITTED_MAX_BYTES).expect("admitted response ceiling")
    }

    /// Builds one `snapshot.members` response frame holding exactly one
    /// whole-record canonical row, padded with JSON whitespace to exactly
    /// `target_bytes`.
    ///
    /// JSON whitespace between tokens is ignored by the decoder, so padding
    /// grows the frame — and therefore the transport allocation a ceiling has to
    /// bound — without changing the decoded value at all. A hand-built
    /// `Vec<Map<String, Value>>` could not express this: the defect the ceiling
    /// repairs happens before any row value exists.
    fn one_row_response(target_bytes: usize) -> Vec<u8> {
        let canonical = serde_json::to_string(&json!({
            "id": "eliot.s03.rpc.v1:snapshot.members:00000000-0000-0000-0000-000000000000",
            "result": [{
                "status": "OK",
                "result": [{ "event_id": "one-row", "operation_id": "op-951" }],
                "time": "1.5ms",
            }],
        }))
        .expect("canonical provider response");
        let padding = target_bytes
            .checked_sub(canonical.len())
            .expect("target frame is at least the canonical response");
        let mut frame = String::with_capacity(target_bytes);
        frame.push('{');
        frame.push_str(&" ".repeat(padding));
        frame.push_str(&canonical[1..]);
        assert_eq!(frame.len(), target_bytes, "padded frame has the exact size");
        frame.into_bytes()
    }

    /// A named test at the real RPC parsing boundary for case 13's byte bound
    /// and one-over: one row whose response frame is exactly one byte over the
    /// admitted ceiling is refused with the existing typed
    /// [`StoreError::PayloadTooLarge`] **before** the frame is converted to text
    /// or parsed, while the identical frame one byte smaller decodes.
    ///
    /// This drives [`parse_response_bounded`], the exact function
    /// `client::session::RpcSession::request_payload` calls for both the text and
    /// the binary arm of a bounded capture, and [`snapshot_response_ceiling`],
    /// the exact function `crate::backup_snapshot::capture_response_ceiling`
    /// calls to bind the capture's admitted `bounds.max_bytes` to that ceiling.
    /// The oversize frame is deliberately *not* valid JSON, so a check that ran
    /// after the decode would answer with a serialization failure; receiving the
    /// typed `PayloadTooLarge` is the proof that the byte charge happened first
    /// and that no parse tree was built for it.
    #[test]
    fn bounded_capture_response_one_byte_over_ceiling_is_refused_before_full_decode() {
        let ceiling = ceiling();
        let frame_ceiling =
            usize::try_from(ceiling.max_bytes()).expect("frame ceiling fits a usize");
        assert!(
            ceiling.max_bytes() >= ADMITTED_MAX_BYTES,
            "the effective ceiling is never weaker than the admitted max_bytes"
        );

        let mut one_over = one_row_response(frame_ceiling);
        // One byte over the admitted frame, and not valid JSON at all.
        one_over.push(b'!');
        assert_eq!(one_over.len(), frame_ceiling + 1);
        assert_eq!(
            parse_response_bounded(&one_over, ceiling).expect_err("one byte over is refused"),
            AdapterError::Store(StoreError::PayloadTooLarge),
            "the ceiling is charged before UTF-8 conversion and before any Value"
        );

        // The same response exactly at the ceiling is admitted and decoded.
        let at_ceiling = one_row_response(frame_ceiling);
        parse_response_bounded(&at_ceiling, ceiling).expect("a frame inside the ceiling decodes");
    }

    /// Positive case for the bounded path: a normal bounded response still
    /// decodes and reaches the statement results the capture reads, with the
    /// `status`/`result` shape `crate::client::RpcResults::from_value` — and
    /// therefore `read_enumeration` — consumes.
    #[test]
    fn bounded_capture_response_inside_ceiling_still_reaches_the_statement_results() {
        let ceiling = ceiling();
        let frame_ceiling =
            usize::try_from(ceiling.max_bytes()).expect("frame ceiling fits a usize");
        let frame = one_row_response(frame_ceiling);
        let response = parse_response_bounded(&frame, ceiling).expect("bounded frame decodes");
        let result = rpc_result(response).expect("no provider error");
        let statements = result.as_array().expect("statement list");
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0]["status"].as_str(), Some("OK"));
        let rows = statements[0]["result"]
            .as_array()
            .expect("one whole-record row");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event_id"].as_str(), Some("one-row"));
    }

    /// Refusal case for the bounded path: a well-formed response of exactly the
    /// admitted shape but over the byte ceiling is refused with the typed
    /// `PayloadTooLarge`, which reaches the store boundary unchanged and is never
    /// reported as an unavailable provider or an empty denominator.
    #[test]
    fn oversize_well_formed_capture_response_is_refused_with_the_typed_bounded_refusal() {
        let ceiling = ceiling();
        let frame_ceiling =
            usize::try_from(ceiling.max_bytes()).expect("frame ceiling fits a usize");
        // Right shape, one byte too much: only the byte ceiling can refuse it.
        let oversize = one_row_response(frame_ceiling + 1);
        assert_eq!(
            parse_response_bounded(&oversize, ceiling).expect_err("right shape, too many bytes"),
            AdapterError::Store(StoreError::PayloadTooLarge)
        );
        assert_eq!(
            AdapterError::Store(StoreError::PayloadTooLarge).into_store_error(),
            StoreError::PayloadTooLarge,
            "the refusal reaches the store boundary unchanged"
        );
    }
}
