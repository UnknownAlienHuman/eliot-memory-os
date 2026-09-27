//! Stateless JSON binding codec for the private Surreal query boundary.
//!
//! Surreal 3's JSON RPC decoder interprets string contents as record IDs,
//! UUIDs or datetimes. Send each value as JSON text inside a one-element array
//! (always starting with `[`, never a record-like prefix), then decode it with
//! the RFC 8259 JSON decoder before executing the unchanged named operation.
//! No payload bytes are replaced and no persistent encoding is introduced:
//! `ExactJsonBytes` remains the versioned, digest-bound canonical authority.
//!
//! # W4 determination: the current named-operation path is lossless (issue #10)
//!
//! Issue #10 item 4 asks whether the current named-operation path transports
//! arbitrary payloads losslessly, and requires a refutation recorded with
//! current evidence instead of a workaround when the historical mechanism is
//! absent. Determined on `origin/main` at `c43c5493`, product
//! `eliot-store-surreal` (store bridge) over store generation
//! `SurrealStoreAdapter`/`CanonicalStoreClient`: the mechanism is **present**
//! and **reachable on the production named-operation write and read paths**.
//! Two exact bindings carry the proof.
//!
//! ## Binding 1 - the vendor coercion boundary is structurally unreachable
//!
//! [`encode_bindings`] is applied to *every* bound value of *every* statement
//! on both production query lanes: the facade lane in `client.rs`
//! (`RpcTransport::query_facade` calls `encode_bindings(statement, bindings)`
//! before the `query` RPC) and the pooled lane in `client/session_pool.rs`.
//! The canonical write transaction is submitted as the RPC operation
//! `transaction.apply` (`apply/atomic_write.rs`, facade and pooled-write
//! lanes) and that name is not in `POOL_READ_OPERATIONS` (only `read.*`,
//! `recovery.*` and `backup*`/snapshot names are), so every named-operation
//! write reaches `encode_bindings`.
//!
//! Each binding is replaced by the JSON *text* of a one-element array
//! (`serde_json::to_string(&[value])`) and re-decoded inside `SurrealQL`
//! with `LET $name = encoding::json::decode($name)[0];`. The bytes the Surreal JSON
//! RPC decoder actually inspects therefore always begin with `[`, never with a
//! `prefix:` token. The historical matrix discriminator
//! (`observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240` shortening to
//! `observation:f31e5b3f`, and the same for `memory:operator-runtime-proof` and
//! `sha256:abc-def-0123456789`) is a record-ID interpretation of string
//! *contents*; because no bound value is ever presented in record-shaped form,
//! that causal step has no current path into this boundary. The value written
//! to the store is the RFC 8259 re-decode of the exact text that was sent.
//!
//! ## Binding 2 - the digest-bound exact bytes are written and re-verified
//!
//! `crate::plan::plan_apply_with_payload_authority` always calls
//! `evidence_records`, on both the legacy all-`None` branch and the
//! authority-carrying branch. With no supplied authority that planner derives
//! the exact representation with
//! `ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, canonical_json_bytes(&operation.parameters))`
//! and `apply/atomic_write.rs` persists it verbatim, in the same transaction as
//! the receipt, into `write_receipt.evidence_records` (`bytes_utf8` plus
//! `version`/`encoding`/`digest_hex`/`byte_len`).
//! `apply/read_boundary.rs` then re-derives the digest from the stored bytes
//! and requires `decode_object_parameters() == parameters` in
//! `validate_evidence_record`, on the governed named read
//! `NamedReadOperation::GetEvidencePack`. A coerced or truncated stored payload
//! fails that read closed instead of being served as a projection.
//!
//! ## Recorded limits of this determination
//!
//! - Exactness is relative to the **admitted** `serde_json::Value` of the
//!   named-operation parameters. The caller's original byte stream is not
//!   preserved, because `Frame::payload` is `ProtocolPayload::Json(Value)` and
//!   `wire.rs::decode_request_frame_with_authority` rebuilds the request with
//!   `serde_json::from_value`. Byte-level identity with the caller's own
//!   serialization (key order, number spelling) is therefore **not** claimed;
//!   semantic identity of arbitrary JSON values, including every
//!   record-shaped string in the historical matrix, is.
//! - The `wire.rs` payload-authority channel is a separate anti-substitution
//!   gate and is **not** the losslessness transport. On the current path it
//!   has no production producer; see the refutation recorded on
//!   `wire.rs::request_frame_with_payload_authority`.

use std::fmt::Write;

use serde_json::{Map, Value};

use crate::error::AdapterError;

pub(super) fn encode_bindings(
    statement: &str,
    bindings: Map<String, Value>,
) -> Result<(String, Map<String, Value>, usize), AdapterError> {
    let prefix_len = bindings.len();
    let mut query = String::new();
    let mut encoded = Map::new();
    for (name, value) in bindings {
        // Names come only from private named-operation definitions. Validate
        // before placing them in SQL; values always remain bound parameters.
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || name.as_bytes()[0].is_ascii_digit()
        {
            return Err(AdapterError::Serialization(
                "invalid private query binding name".to_owned(),
            ));
        }
        let text = serde_json::to_string(&[value])
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
        writeln!(query, "LET ${name} = encoding::json::decode(${name})[0];")
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
        encoded.insert(name, Value::String(text));
    }
    query.push_str(statement);
    Ok((query, encoded, prefix_len))
}
