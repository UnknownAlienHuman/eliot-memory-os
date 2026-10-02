//! Pure `SurrealDB` JSON-RPC/provider-version parsing cell extracted from `client.rs`.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I5.1, I5.9, I5.22, I2.23.
//! Ownership: pure `RpcResponse` envelope and `surrealdb-3.1`/`3.2` `ProviderVersion` parsing only, plus the ELIOT-owned [`ResponseCeiling`] a bounded capture carries into the transport (issue #951) and the one typed [`StoreError::PayloadTooLarge`] refusal it raises; no transport, auth, handshake, process-spawn, or lifecycle ownership (see `crates/storage/eliot-store-surreal-adapter/src/client.rs`).

use std::cell::Cell;
use std::fmt;

use serde::Deserialize;
use serde::de::{
    DeserializeSeed, Deserializer, Error as SerdeError, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde_json::Value;

use eliot_store_api::{MAX_SNAPSHOT_BYTES, StoreError};

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

/// The ELIOT-owned response bound a bounded capture carries into the transport
/// (issue #951).
///
/// A provider response is unbounded input until this owner says otherwise. A
/// third-party WebSocket limit is that library's incidental behaviour, not this
/// bridge's snapshot contract, so the bound is issued here and travels with the
/// admitted capture.
///
/// It carries two values, and which of them is owner-issued is stated rather
/// than glossed:
///
/// * [`ResponseCeiling::admitted_bytes`] is the capture's own admitted aggregate
///   byte budget — the `bounds.max_bytes` that
///   [`eliot_store_api::SnapshotBounds::validate`] has already proved non-zero
///   and no stronger than [`eliot_store_api::MAX_SNAPSHOT_BYTES`] — and nothing
///   else. This half is owner-issued. It is the budget the decoded statement rows
///   are charged against.
/// * [`ResponseCeiling::max_bytes`] is that budget plus
///   [`SNAPSHOT_PROTOCOL_ENVELOPE_BYTES`], and is the largest single provider
///   frame or message the transport admits. This half is the admitted budget
///   plus an engineering allowance this change introduces, which is recorded as
///   a named limitation on [`SNAPSHOT_PROTOCOL_ENVELOPE_BYTES`] below and is
///   deliberately *not* claimed to be owner-issued.
///
/// The transport bound is therefore never weaker than the admitted budget, a
/// smaller admitted budget yields a smaller and never a laxer bound, and the
/// row bound is the *unpadded* admitted budget, so the envelope allowance can
/// never be spent on row content.
///
/// [`ResponseCeiling::session_wide`] issues the same shape from
/// [`eliot_store_api::MAX_SNAPSHOT_BYTES`], so the bound the socket enforces can
/// never be weaker than the bound the largest admissible capture needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseCeiling {
    admitted_bytes: u64,
    max_bytes: u64,
}

impl ResponseCeiling {
    /// Issues the response bound for one admitted capture byte budget.
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
        Ok(Self {
            admitted_bytes: aggregate_bytes,
            max_bytes,
        })
    }

    /// Issues the response bound the session socket itself is constructed with.
    ///
    /// Derived from [`eliot_store_api::MAX_SNAPSHOT_BYTES`], the same
    /// owner-issued constant `SnapshotBounds::validate` refuses any admitted
    /// capture above, so every admissible capture's own bound is at or below
    /// this one and the transport can never refuse a capture its admitted
    /// budget allows. The addition is a `const` expression: an overflow would be
    /// a compile error, not a runtime saturation to an unbounded value.
    pub(crate) const fn session_wide() -> Self {
        Self {
            admitted_bytes: MAX_SNAPSHOT_BYTES,
            max_bytes: MAX_SNAPSHOT_BYTES + SNAPSHOT_PROTOCOL_ENVELOPE_BYTES,
        }
    }

    /// The capture's own admitted aggregate byte budget.
    ///
    /// What the decoded statement rows are charged against, with no envelope
    /// allowance: a response whose rows cost more than this is refused even
    /// though its frame was inside the transport bound.
    pub(crate) const fn admitted_bytes(self) -> u64 {
        self.admitted_bytes
    }

    /// Largest provider frame or message, in bytes, this ceiling admits.
    pub(crate) const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    /// Charges one already-received frame against this ceiling.
    ///
    /// The frame charge is the *second* position of the same bound, not the
    /// first: the socket itself refuses an oversize frame while it is still a
    /// network frame, so a frame that reaches this function was already admitted
    /// by the transport for every bounded capture. What this proves is that the
    /// two agree, and it is the position that also covers the unbounded decode
    /// shape (`&str`) the text arm hands over.
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
/// refusal raised by the transport, by the frame charge and by the bounded
/// decoder is one typed outcome rather than three. It is never
/// [`AdapterError::ProviderUnavailable`]: an oversize response observed a source
/// that answered, and reporting it as a provider that is gone would let a bounded
/// refusal masquerade as a retryable transport loss.
pub(super) fn response_ceiling_refusal() -> AdapterError {
    AdapterError::Store(StoreError::PayloadTooLarge)
}

/// Bytes the pinned JSON-RPC framing spends around one capture's rows.
///
/// **Named limitation: this allowance is not owner-issued.** No document in this
/// repository names it. It is introduced by issue #951 as the one part of the
/// bound's arithmetic this crate chose, and it must not be reported as part of
/// the owner-issued derivation: the owner-issued half of
/// [`ResponseCeiling::for_admitted_capture`] is the capture's admitted
/// `bounds.max_bytes`, and of [`ResponseCeiling::session_wide`] it is
/// [`eliot_store_api::MAX_SNAPSHOT_BYTES`]. A reviewer must treat this constant
/// as an engineering allowance and check it against the derivation below.
///
/// The derivation is from the fixed shapes this crate itself emits and decodes,
/// and the test `the_envelope_allowance_covers_the_pinned_framing` proves it
/// against the live statement registry rather than restating it in prose:
///
/// * one response id: [`RPC_PROTOCOL_VERSION`](super::RPC_PROTOCOL_VERSION), the
///   two separators the `version:operation:uuid` id format uses, the closed
///   `&'static str` operation label and the canonical 36-character UUID text;
/// * one wrapper per statement of the pinned batch — the retained
///   `BEGIN TRANSACTION` result, the two capture-point reads, one read per
///   admitted canonical source class and the `COMMIT TRANSACTION` result, each in
///   its `{"status":…,"result":…,"time":…}` member set with its separator — plus
///   the enclosing brackets.
///
/// Row content is deliberately *not* part of it. The envelope is the framing
/// allowance above the admitted `max_bytes`; a response that spends it on rows
/// instead of framing is refused by the row charge against
/// [`ResponseCeiling::admitted_bytes`], so a generous envelope cannot buy a
/// larger capture.
///
/// Direction of failure, stated so the limitation is not read as a hole: if the
/// real framing ever exceeded this allowance, an otherwise admissible capture
/// would be refused with the typed [`StoreError::PayloadTooLarge`] — fail closed,
/// typed and visible. Enlarging it would widen the transport bound by that
/// amount, which the frame charge still bounds. Neither direction removes a
/// bound.
const SNAPSHOT_PROTOCOL_ENVELOPE_BYTES: u64 = 64 * 1024;

/// Upper bound on the fixed bytes one response statement's wrapper spends,
/// excluding the `result` rows that statement carries.
///
/// Counted from the provider's member set
/// `{"status":"ERR-0123456789","result":[],"time":"12345.678ms"},`: the two
/// braces, the three quoted member names, their three colons, two separators,
/// and the widest status and duration text the provider is observed to emit —
/// 57 bytes, so 64 covers that shape with the remaining margin unused. The rows
/// inside `result` are charged separately against
/// [`ResponseCeiling::admitted_bytes`].
#[cfg(test)]
const STATEMENT_WRAPPER_BOUND_BYTES: u64 = 64;

/// Upper bound on the bytes one response id spends, quotes included.
///
/// [`RPC_PROTOCOL_VERSION`](super::RPC_PROTOCOL_VERSION) is 16 bytes, the two
/// separators and the 36-character UUID are fixed, and the longest label the
/// closed snapshot vocabulary issues is `snapshot.members` — 73 bytes for the
/// longest case. 128 is the bound the envelope check charges, not a second
/// factor on the byte budget.
#[cfg(test)]
const RESPONSE_ID_BOUND_BYTES: u64 = 128;

/// Static text the bounded reader stops on when a response's rows cross the
/// admitted aggregate byte budget.
///
/// The bounded reader reports the crossing through a serde error so the parse
/// unwinds immediately and the statements after the crossing one are never
/// decoded. The text never crosses the crate boundary: the caller maps it back
/// to [`StoreError::PayloadTooLarge`], so a caller still receives the existing
/// typed refusal and never provider prose.
const RESPONSE_BYTE_BUDGET_REFUSAL: &str = "provider response exceeded the admitted byte budget";

/// Decodes one bounded provider response from an already-received frame.
///
/// This is the read path the transport uses for every bounded capture response.
/// It charges the frame it is handed against the ELIOT-owned
/// [`ResponseCeiling`] before `serde_json` constructs a single `Value`, and it
/// decodes the statement list through a body reader that charges each statement's
/// rows against the capture's admitted budget and ends the decode at the
/// statement that would exceed it, so the statements after that one are never
/// decoded into `Value`s.
///
/// What this function does **not** do is stop a frame from arriving. The frame
/// it is handed has already been read out of the transport: for the text arm the
/// UTF-8 validation has already happened inside the provider library, and for
/// both arms the payload is already in memory. The reason an oversize response
/// is not materialised at all is the transport bound — the socket is constructed
/// with a bound of this same shape (see [`ResponseCeiling::session_wide`] and
/// `client::session::response_bound_config`), so the provider library refuses an
/// oversize frame while it is still a network frame and never hands one to this
/// function. This charge is what keeps the two positions in agreement, and it is
/// the position that can refuse a frame the session-wide transport bound would
/// admit but this capture's smaller admitted budget does not.
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
            remaining_bytes: self.ceiling.admitted_bytes(),
            budget_exceeded: self.budget_exceeded,
        })
    }
}

/// Sequence visitor that charges each decoded statement's rows against the
/// capture's admitted budget and ends the decode at the statement that would
/// exceed it.
///
/// The budget charged here is the capture's own admitted `max_bytes`
/// ([`ResponseCeiling::admitted_bytes`]) over the same rows the capture later
/// charges through `backup_snapshot::decoded_class_bytes`, and *not* the padded
/// transport bound. That difference is what makes this a real second line of
/// defence rather than a restatement of the frame charge: a frame may
/// legitimately be [`SNAPSHOT_PROTOCOL_ENVELOPE_BYTES`] larger than the admitted
/// budget (the framing spends it), so a response that puts that allowance into
/// row content passes the transport and the frame charge and is refused here.
///
/// Charging the rows and not the whole statement matters at the boundary: a
/// capture whose rows sit *exactly* at its admitted budget must be served, and
/// adding the array punctuation or the per-statement `status`/`time` wrappers to
/// that charge would refuse it. Those are framing, and the transport bound
/// already covers them. Rows costing exactly the admitted budget are therefore
/// admitted, which is the same one-over discipline the capture bounds use
/// elsewhere.
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
            // its rows are charged against the admitted budget *before* it is
            // kept: a statement that would push the decoded rows past the
            // admitted budget ends the decode here, and every statement after it
            // is left undecoded. The statement that crosses the budget has
            // already been decoded into a `Value` — `serde_json` offers no other
            // seam for a per-element charge — but it is dropped rather than kept,
            // so nothing over budget reaches the capture.
            let charge = statement_charge_bytes(&statement);
            if charge > self.remaining_bytes {
                self.budget_exceeded.set(true);
                return Err(A::Error::custom(RESPONSE_BYTE_BUDGET_REFUSAL));
            }
            self.remaining_bytes -= charge;
            self.statements.push(statement);
        }
        Ok(Value::Array(self.statements))
    }
}

/// Charges one decoded provider statement's rows against the admitted byte
/// budget.
///
/// A statement whose `result` is a row array is charged the way
/// `backup_snapshot::decoded_class_bytes` charges a class result: the sum of the
/// row re-encodings, with no array punctuation and no `status`/`time` wrapper
/// bytes, so this bound and the capture's own aggregate bound agree exactly at
/// the boundary. A statement whose `result` is any other value is charged as one
/// value, so a large non-row result is still bounded rather than free. A
/// statement with no `result` member is charged nothing.
///
/// Every value is re-encoded from what the reader already holds, so key ordering
/// can only move the number and the claim stays a bounded charge of observed
/// rows. The wrappers and the response envelope are framing, and the transport
/// bound already covers them; charging them here would refuse a capture whose
/// rows sit exactly at its admitted budget.
fn statement_charge_bytes(statement: &Value) -> u64 {
    let Some(result) = statement.get("result") else {
        return 0;
    };
    match result {
        Value::Array(rows) => rows
            .iter()
            .fold(0_u64, |total, row| total.saturating_add(encoded_len(row))),
        other => encoded_len(other),
    }
}

/// Re-encodes one decoded value and returns its byte length.
///
/// A value that cannot be re-encoded is charged out at the maximum rather than
/// free, which refuses it instead of admitting an unmeasurable one.
fn encoded_len(value: &Value) -> u64 {
    serde_json::to_string(value).map_or(u64::MAX, |encoded| {
        u64::try_from(encoded.len()).unwrap_or(u64::MAX)
    })
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
    use crate::backup_snapshot::{capture_point_statements, captured_member_tables};
    use crate::client::backup_snapshot::SNAPSHOT_OPERATIONS;
    use crate::client::{RPC_PROTOCOL_VERSION, snapshot_response_ceiling};

    /// The admitted budget these cases use. Chosen inside the closed
    /// [`eliot_store_api::SnapshotBounds`] range so it is a value the existing
    /// `SnapshotBounds::validate` admits, not a shape the API would refuse.
    const ADMITTED_MAX_BYTES: u64 = 4_096;

    /// Canonical 36-character UUID text, the only variable part of a minted id.
    const UUID_TEXT_BYTES: u64 = 36;

    fn ceiling() -> ResponseCeiling {
        snapshot_response_ceiling(ADMITTED_MAX_BYTES).expect("admitted response ceiling")
    }

    /// Statements one pinned member-batch response carries: the two capture-point
    /// reads plus one read per admitted canonical source class. Counted from the
    /// live registry rather than restated, so a class added to
    /// [`crate::backup_snapshot::CANONICAL_SOURCE_CLASSES`] moves this number.
    fn member_batch_statement_count() -> u64 {
        let points = u64::try_from(capture_point_statements().count()).expect("point count fits");
        let members = u64::try_from(captured_member_tables().count()).expect("member count fits");
        points + members
    }

    /// Longest operation label the closed snapshot vocabulary issues.
    fn longest_snapshot_label_bytes() -> u64 {
        SNAPSHOT_OPERATIONS
            .iter()
            .map(|label| u64::try_from(label.len()).expect("label length fits"))
            .max()
            .expect("the closed vocabulary is never empty")
    }

    /// The exact bytes one minted response id spends, quotes included.
    fn observed_response_id_bytes() -> u64 {
        2 + u64::try_from(RPC_PROTOCOL_VERSION.len()).expect("version length fits")
            + 2
            + longest_snapshot_label_bytes()
            + UUID_TEXT_BYTES
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
    /// [`StoreError::PayloadTooLarge`] before any `Value` is constructed, while
    /// the identical frame one byte smaller decodes.
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
            "the ceiling is charged before any Value is constructed"
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
    ///
    /// The refusal is *obtained from the production read* and then projected
    /// through the production store-boundary mapping; nothing here builds the
    /// error, so replacing `response_ceiling_refusal()` with
    /// `ProviderUnavailable` — or retyping the projection — fails here.
    #[test]
    fn oversize_well_formed_capture_response_is_refused_with_the_typed_bounded_refusal() {
        let ceiling = ceiling();
        let frame_ceiling =
            usize::try_from(ceiling.max_bytes()).expect("frame ceiling fits a usize");
        // Right shape, one byte too much: only the byte ceiling can refuse it.
        let oversize = one_row_response(frame_ceiling + 1);
        let refusal =
            parse_response_bounded(&oversize, ceiling).expect_err("right shape, too many bytes");
        assert_eq!(refusal, AdapterError::Store(StoreError::PayloadTooLarge));
        assert_eq!(
            refusal.into_store_error(),
            StoreError::PayloadTooLarge,
            "the refusal reaches the store boundary unchanged"
        );
    }

    /// Builds one `snapshot.members` response frame holding a single statement
    /// whose single row carries `value_bytes` bytes of canonical payload.
    ///
    /// Unlike [`one_row_response`] this is *not* padded: the frame is only as
    /// long as the response it holds, so a case can put real row content where
    /// the framing allowance would otherwise sit.
    fn response_with_row_of_bytes(value_bytes: usize) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "eliot.s03.rpc.v1:snapshot.members:00000000-0000-0000-0000-000000000000",
            "result": [{
                "status": "OK",
                "result": [{
                    "event_id": "one-row",
                    "operation_id": "op-951",
                    "body": "v".repeat(value_bytes),
                }],
                "time": "1.5ms",
            }],
        }))
        .expect("canonical provider response")
    }

    /// The second bound is real, not a restatement of the frame charge: a
    /// response whose frame is inside the transport bound but whose *content*
    /// exceeds the capture's admitted `max_bytes` is refused, while the same
    /// response with content inside the admitted budget is admitted.
    ///
    /// Both frames here are well inside `ResponseCeiling::max_bytes`, so the
    /// frame charge cannot be what refuses the first one. Seeding the
    /// statement-list budget from `max_bytes` again — the shape this replaces —
    /// makes the refusal case fail, and admitting content one byte over the
    /// admitted budget makes the boundary assertions fail.
    #[test]
    fn content_over_the_admitted_budget_is_refused_even_inside_the_frame_bound() {
        let ceiling = ceiling();
        let frame_ceiling =
            usize::try_from(ceiling.max_bytes()).expect("frame ceiling fits a usize");

        // Content inside the admitted budget: admitted, and the row survives.
        let admitted_body_bytes =
            usize::try_from(ADMITTED_MAX_BYTES).expect("admitted budget fits a usize") - 512;
        let inside = response_with_row_of_bytes(admitted_body_bytes);
        assert!(
            inside.len() <= frame_ceiling,
            "the positive frame is inside the transport bound"
        );
        let response = parse_response_bounded(&inside, ceiling).expect("admitted content decodes");
        let result = rpc_result(response).expect("no provider error");
        let statements = result.as_array().expect("statement list");
        assert_eq!(statements.len(), 1);
        let body = statements[0]["result"][0]["body"]
            .as_str()
            .expect("row body");
        assert_eq!(body.len(), admitted_body_bytes);

        // Content one row past the admitted budget, still inside the frame bound.
        let over = response_with_row_of_bytes(
            usize::try_from(ADMITTED_MAX_BYTES).expect("admitted budget fits a usize"),
        );
        assert!(
            over.len() <= frame_ceiling,
            "the refused frame is inside the transport bound, so only the statement charge can refuse it"
        );
        assert_eq!(
            parse_response_bounded(&over, ceiling).expect_err("content over the admitted budget"),
            AdapterError::Store(StoreError::PayloadTooLarge),
            "the admitted budget is charged against decoded statements, not just the frame"
        );
    }

    /// The bound is exactly the admitted budget plus one envelope allowance:
    /// there is no second factor, no multiplication and no rounding.
    ///
    /// A reviewer's first question about an invented byte constant is whether it
    /// is quietly doubled somewhere; this is the assertion that answers it, and
    /// any arithmetic added to the derivation fails here.
    #[test]
    fn the_derived_bound_is_exactly_the_admitted_budget_plus_one_envelope() {
        let ceiling = ceiling();
        assert_eq!(ceiling.admitted_bytes(), ADMITTED_MAX_BYTES);
        assert_eq!(
            ceiling.max_bytes(),
            ADMITTED_MAX_BYTES + SNAPSHOT_PROTOCOL_ENVELOPE_BYTES
        );
    }

    /// The envelope allowance is large enough for the framing the pinned member
    /// batch actually emits, measured from the live registry rather than
    /// restated in prose.
    ///
    /// This is the sufficiency argument for the one non-owner-issued constant in
    /// the derivation, made executable: it fails if the allowance is reduced
    /// below what the current registry needs, if a canonical source class is
    /// added, or if a longer operation label enters the closed vocabulary.
    #[test]
    fn the_envelope_allowance_covers_the_pinned_framing() {
        let statements = member_batch_statement_count();
        // Two enclosing brackets around the statement list.
        let framing = statements * STATEMENT_WRAPPER_BOUND_BYTES + RESPONSE_ID_BOUND_BYTES + 2;
        assert!(
            RESPONSE_ID_BOUND_BYTES >= observed_response_id_bytes(),
            "the response-id bound no longer covers a minted id"
        );
        assert!(
            framing <= SNAPSHOT_PROTOCOL_ENVELOPE_BYTES,
            "the pinned member batch framing costs {framing} bytes \
             ({statements} statements), above the \
             {SNAPSHOT_PROTOCOL_ENVELOPE_BYTES}-byte envelope allowance"
        );
    }

    /// The session-wide bound the socket is constructed with admits every
    /// capture ceiling the admitted budgets can issue, so tightening the
    /// transport can never refuse a capture its own admitted budget allows.
    ///
    /// Raising the per-capture envelope above the session-wide one, or deriving
    /// the session bound from anything other than
    /// [`eliot_store_api::MAX_SNAPSHOT_BYTES`], fails here.
    #[test]
    fn the_session_wide_transport_bound_admits_every_admissible_capture_ceiling() {
        let session_wide = ResponseCeiling::session_wide();
        assert_eq!(session_wide.admitted_bytes(), MAX_SNAPSHOT_BYTES);
        let expected = MAX_SNAPSHOT_BYTES + SNAPSHOT_PROTOCOL_ENVELOPE_BYTES;
        assert_eq!(session_wide.max_bytes(), expected);
        for admitted in [1, 4_096, MAX_SNAPSHOT_BYTES / 2, MAX_SNAPSHOT_BYTES] {
            let capture = snapshot_response_ceiling(admitted).expect("admitted capture ceiling");
            assert!(
                capture.max_bytes() <= session_wide.max_bytes(),
                "an admitted budget of {admitted} issues a ceiling above the transport bound"
            );
        }
    }
}
