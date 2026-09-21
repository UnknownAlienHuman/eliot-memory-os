//! Canonical reactive-state wire contract (issue #1941 C4, I5/I7.18).
//!
//! This module owns the serialization-only wire boundary for durable
//! reactive delivery records and revisioned resource snapshots: versioned
//! identity, closed parameter declarations support, per-operation
//! completeness validation on raw parameter maps, and request builders.
//! It contains no delivery semantics, no ledger model, and no receipt
//! validation: the bridge ledger (`ReactiveInjectionLedger`,
//! `bins/eliot-agent-bridge`) owns delivery/dedup/stickiness, the
//! I7.18 grammar owner (`eliot-agent-bridge-core`) owns the canonical
//! URI semantics, and the canonical backend drives persistence within
//! its fenced transaction and outbox owner. Wire shapes stay
//! serialization-only and never become a second semantic model.
//!
//! Wire identity: [`REACTIVE_STATE_SCHEMA_V1`]
//! (`eliot.reactive.state.v1`). Ledger mutation operation:
//! `ApplyReactiveInjectionState`. Ledger read operation:
//! `GetReactiveInjectionState`. Snapshot mutation operation:
//! `ApplyResourceSnapshot`. Snapshot read operation:
//! `GetResourceSnapshot`. Transition class: `ReactiveState` with a
//! `ReversibleMutation` ceiling.
//!
//! Ledger bytes are the bridge's `reactive_ledger_snapshot()` output —
//! canonical JSON stamped with [`REACTIVE_LEDGER_CONTRACT_V1`] — carried
//! here as one opaque string so the store preserves them verbatim and a
//! readback is byte-identical to what the bridge wrote. The store
//! validates the contract stamp and bounds structurally; full ledger
//! semantics (`from_json_bytes`/`restore_reactive_ledger`) stay at the
//! bridge endpoints, which already round-trip byte-equal.
//!
//! Resource snapshots carry the exact I7.18 URI, the lowercase SHA-256
//! hex of the content bytes, and the base64 content. The backend
//! re-decodes and re-hashes (never trusting the presented digest) and
//! refuses to rewrite one URI with different bytes, so versioning flows
//! through revision-bearing URI families (`task/<id>/packet/<rev>`,
//! `architecture/<rev>/<anchor>`) exactly as the bridge registry does.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde_json::Value;
use thiserror::Error;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, StateFence, StoreError,
};

/// Versioned wire/schema identity for canonical reactive state.
pub const REACTIVE_STATE_SCHEMA_V1: &str = "eliot.reactive.state.v1";
/// Bridge ledger contract stamp the stored bytes must carry.
///
/// Owned by the bridge ledger (`REACTIVE_INJECTION_CONTRACT` in
/// `bins/eliot-agent-bridge/src/reactive_injection_receipts.rs`); mirrored
/// here as the store-side acceptance string so the persistence boundary
/// stays fail-closed on foreign payloads without depending on the bridge
/// binary crate.
pub const REACTIVE_LEDGER_CONTRACT_V1: &str = "eliot.agent-bridge.reactive-injection-receipts/v1";
/// Closed mutation operation name for reactive-ledger upserts.
pub const REACTIVE_LEDGER_MUTATION_NAME: &str = "ApplyReactiveInjectionState";
/// Closed read operation name for reactive-ledger reads.
pub const REACTIVE_LEDGER_READ_NAME: &str = "GetReactiveInjectionState";
/// Closed mutation operation name for resource-snapshot writes.
pub const RESOURCE_SNAPSHOT_MUTATION_NAME: &str = "ApplyResourceSnapshot";
/// Closed read operation name for resource-snapshot reads.
pub const RESOURCE_SNAPSHOT_READ_NAME: &str = "GetResourceSnapshot";
/// Fixed transition scope for all reactive rows.
pub const REACTIVE_STATE_SCOPE: &str = "reactive-state";
/// Maximum accepted `session_id` length in bytes.
pub const MAX_SESSION_ID_BYTES: usize = 256;
/// Maximum accepted ledger snapshot length in bytes.
///
/// Mirrors the bridge `MAX_LEDGER_JSON_BYTES` (1 MiB): the store never
/// accepts a snapshot the bridge itself could not have produced.
pub const MAX_REACTIVE_LEDGER_BYTES: usize = 1024 * 1024;
/// Maximum accepted resource content length in bytes (decoded).
///
/// Mirrors the bridge `MAX_CONTENT_BYTES` (1 MiB).
pub const MAX_RESOURCE_CONTENT_BYTES: usize = 1024 * 1024;
/// Maximum accepted resource URI length in bytes.
///
/// Mirrors the bridge `MAX_URI_BYTES`.
pub const MAX_RESOURCE_URI_BYTES: usize = 512;
/// `eliot://` URI scheme prefix.
pub const RESOURCE_URI_SCHEME: &str = "eliot://";

/// Mutation session selector (ledger upsert; exact read selector).
pub const REACTIVE_PARAM_SESSION_ID: &str = "session_id";
/// Opaque canonical ledger-snapshot JSON (ledger upsert).
pub const REACTIVE_PARAM_LEDGER_JSON: &str = "ledger_json";
/// Canonical `eliot://` resource identity (snapshot legs; exact read selector).
pub const REACTIVE_PARAM_URI: &str = "uri";
/// Lowercase SHA-256 hex of the exact snapshot bytes (snapshot upsert).
pub const REACTIVE_PARAM_CONTENT_SHA256: &str = "content_sha256";
/// Base64 (standard alphabet) snapshot bytes (snapshot upsert).
pub const REACTIVE_PARAM_CONTENT_BASE64: &str = "content_base64";

/// Read payload field: ledger session identity.
pub const REACTIVE_PAGE_SESSION_ID: &str = "session_id";
/// Read payload field: verbatim ledger snapshot (null when absent).
pub const REACTIVE_PAGE_LEDGER_JSON: &str = "ledger_json";
/// Read payload field: owner revision read at.
pub const REACTIVE_PAGE_REVISION: &str = "revision";
/// Read payload field: projection fence.
pub const REACTIVE_PAGE_STATE_FENCE: &str = "state_fence";
/// Read payload field: snapshot URI.
pub const SNAPSHOT_PAGE_URI: &str = "uri";
/// Read payload field: stored content digest (null when absent).
pub const SNAPSHOT_PAGE_CONTENT_SHA256: &str = "content_sha256";
/// Read payload field: stored base64 bytes (null when absent).
pub const SNAPSHOT_PAGE_CONTENT_BASE64: &str = "content_base64";
/// Read payload field: owner revision read at.
pub const SNAPSHOT_PAGE_REVISION: &str = "revision";
/// Read payload field: projection fence.
pub const SNAPSHOT_PAGE_STATE_FENCE: &str = "state_fence";

/// Fail-closed reactive wire errors before [`StoreError`] projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveContractError {
    /// A field failed bounded validation.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// A required parameter is absent.
    #[error("missing reactive parameter: {0}")]
    MissingParameter(&'static str),
}

impl ReactiveContractError {
    /// Projects the contract error onto the closed store error set.
    #[must_use]
    pub const fn into_store_error(self) -> StoreError {
        match self {
            Self::InvalidField { field, reason } => StoreError::InvalidField { field, reason },
            Self::MissingParameter(name) => StoreError::InvalidField {
                field: name,
                reason: "missing required reactive parameter",
            },
        }
    }
}

/// Raw validated mutation decoded from a mutation parameter map.
///
/// Payloads stay opaque strings: the backend re-validates them against
/// the bridge contracts and drives the row compare-and-set. This enum
/// carries no delivery semantics beyond operation completeness.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedReactiveMutation {
    /// Replace the stored ledger snapshot for one session.
    ApplyLedger {
        /// Kernel-owned activation-sealed session binding.
        session_id: String,
        /// Verbatim canonical ledger-snapshot JSON.
        ledger_json: String,
    },
    /// Create (or convergently re-apply) one immutable resource snapshot.
    ApplySnapshot {
        /// Canonical `eliot://` resource identity.
        uri: String,
        /// Lowercase SHA-256 hex of the exact snapshot bytes.
        content_sha256: String,
        /// Base64 snapshot bytes.
        content_base64: String,
    },
}

/// Builds the closed `ApplyReactiveInjectionState` mutation request.
#[must_use]
pub fn reactive_ledger_mutation_request(
    session_id: String,
    ledger_json: String,
) -> NamedMutationRequest {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        REACTIVE_PARAM_SESSION_ID.to_owned(),
        Value::String(session_id),
    );
    parameters.insert(
        REACTIVE_PARAM_LEDGER_JSON.to_owned(),
        Value::String(ledger_json),
    );
    NamedMutationRequest {
        operation: NamedMutationOperation::ApplyReactiveInjectionState,
        parameters,
    }
}

/// Builds the closed `GetReactiveInjectionState` read request.
pub fn reactive_ledger_read_request(
    session_id: String,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let parameters = BTreeMap::from([(
        REACTIVE_PARAM_SESSION_ID.to_owned(),
        Value::String(session_id),
    )]);
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetReactiveInjectionState,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Builds the closed `ApplyResourceSnapshot` mutation request.
///
/// Content bytes are base64-encoded here so arbitrary snapshot bytes
/// (including non-UTF-8) travel the JSON parameter map without loss; the
/// backend re-decodes and re-hashes before persisting.
pub fn resource_snapshot_mutation_request(
    uri: String,
    content: &[u8],
) -> Result<NamedMutationRequest, StoreError> {
    let content_base64 = encode_resource_content(content)?;
    let content_sha256 = crate::sha256_hex(content);
    let parameters = BTreeMap::from([
        (REACTIVE_PARAM_URI.to_owned(), Value::String(uri)),
        (
            REACTIVE_PARAM_CONTENT_SHA256.to_owned(),
            Value::String(content_sha256),
        ),
        (
            REACTIVE_PARAM_CONTENT_BASE64.to_owned(),
            Value::String(content_base64),
        ),
    ]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::ApplyResourceSnapshot,
        parameters,
    })
}

/// Builds the closed `GetResourceSnapshot` read request.
pub fn resource_snapshot_read_request(
    uri: String,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let parameters = BTreeMap::from([(REACTIVE_PARAM_URI.to_owned(), Value::String(uri))]);
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetResourceSnapshot,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Validates closed mutation parameters for one reactive operation.
///
/// The operation identity is the discriminator: each op declares exactly
/// its required params, and value rules (session bounds, ledger
/// contract/bounds, URI grammar, digest shape, base64/decode/digest
/// agreement) run here so every backend shares one acceptance boundary.
pub fn validate_reactive_mutation_params(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    match operation {
        NamedMutationOperation::ApplyReactiveInjectionState => {
            validate_session_id(text_param(parameters, REACTIVE_PARAM_SESSION_ID)?)?;
            validate_ledger_json(text_param(parameters, REACTIVE_PARAM_LEDGER_JSON)?)?;
            Ok(())
        }
        NamedMutationOperation::ApplyResourceSnapshot => {
            let uri = text_param(parameters, REACTIVE_PARAM_URI)?;
            validate_resource_uri(uri)?;
            let sha = text_param(parameters, REACTIVE_PARAM_CONTENT_SHA256)?;
            validate_sha256_hex(sha, REACTIVE_PARAM_CONTENT_SHA256)?;
            let encoded = text_param(parameters, REACTIVE_PARAM_CONTENT_BASE64)?;
            decode_resource_content(encoded, sha)?;
            Ok(())
        }
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Decodes one validated mutation parameter map into its raw operation.
pub fn decode_reactive_mutation(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedReactiveMutation, StoreError> {
    validate_reactive_mutation_params(operation, parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "reactive parameter must be present",
            })
    };
    match operation {
        NamedMutationOperation::ApplyReactiveInjectionState => {
            Ok(DecodedReactiveMutation::ApplyLedger {
                session_id: text_of(REACTIVE_PARAM_SESSION_ID)?,
                ledger_json: text_of(REACTIVE_PARAM_LEDGER_JSON)?,
            })
        }
        NamedMutationOperation::ApplyResourceSnapshot => {
            Ok(DecodedReactiveMutation::ApplySnapshot {
                uri: text_of(REACTIVE_PARAM_URI)?,
                content_sha256: text_of(REACTIVE_PARAM_CONTENT_SHA256)?,
                content_base64: text_of(REACTIVE_PARAM_CONTENT_BASE64)?,
            })
        }
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Validates the closed ledger-read selectors (exact session only).
pub fn validate_reactive_ledger_read_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<String, StoreError> {
    let session_id = text_param(parameters, REACTIVE_PARAM_SESSION_ID)?;
    validate_session_id(session_id)?;
    Ok(session_id.to_owned())
}

/// Validates the closed snapshot-read selectors (exact URI only).
pub fn validate_resource_snapshot_read_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<String, StoreError> {
    let uri = text_param(parameters, REACTIVE_PARAM_URI)?;
    validate_resource_uri(uri)?;
    Ok(uri.to_owned())
}

fn text_param<'a>(
    parameters: &'a BTreeMap<String, Value>,
    name: &'static str,
) -> Result<&'a str, StoreError> {
    parameters
        .get(name)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: name,
            reason: "reactive parameter must be a string",
        })
}

fn validate_session_id(session_id: &str) -> Result<(), StoreError> {
    if session_id.trim().is_empty() || session_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "reactive.session_id",
            reason: "session must be non-blank text",
        });
    }
    if session_id.len() > MAX_SESSION_ID_BYTES {
        return Err(StoreError::InvalidField {
            field: "reactive.session_id",
            reason: "session exceeds the length bound",
        });
    }
    Ok(())
}

/// Validates opaque ledger bytes structurally: bounded length, valid
/// JSON object, stamped with the bridge ledger contract.
///
/// Full ledger semantics stay with the bridge (`from_json_bytes` before
/// write and after read at the bridge endpoints); this boundary rejects
/// foreign, oversize, or undecodable payloads without interpreting
/// delivery state.
pub fn validate_ledger_json(ledger_json: &str) -> Result<(), StoreError> {
    if ledger_json.is_empty() || ledger_json.len() > MAX_REACTIVE_LEDGER_BYTES {
        return Err(StoreError::InvalidField {
            field: "reactive.ledger_json",
            reason: "ledger snapshot is outside the bounded length",
        });
    }
    let value: Value = serde_json::from_str(ledger_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let contract = value
        .as_object()
        .and_then(|object| object.get("contract"))
        .and_then(Value::as_str);
    if contract != Some(REACTIVE_LEDGER_CONTRACT_V1) {
        return Err(StoreError::InvalidField {
            field: "reactive.ledger_json",
            reason: "ledger snapshot carries the wrong delivery-record contract",
        });
    }
    Ok(())
}

/// Validates a lowercase SHA-256 hex digest string.
pub fn validate_sha256_hex(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "digest must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

/// Encodes snapshot bytes for the wire: bounded length, standard
/// base64 alphabet.
pub fn encode_resource_content(content: &[u8]) -> Result<String, StoreError> {
    if content.is_empty() || content.len() > MAX_RESOURCE_CONTENT_BYTES {
        return Err(StoreError::InvalidField {
            field: "reactive.content",
            reason: "snapshot content is outside the bounded length",
        });
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(content))
}

/// Decodes wire snapshot bytes and proves digest agreement.
///
/// Fails closed on undecodable base64, over-bound content, or a digest
/// that does not name the decoded bytes. Backends run this on every
/// write instead of trusting the presented digest.
pub fn decode_resource_content(
    encoded: &str,
    expected_sha256: &str,
) -> Result<Vec<u8>, StoreError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_RESOURCE_CONTENT_BYTES {
        return Err(StoreError::InvalidField {
            field: "reactive.content",
            reason: "snapshot content is outside the bounded length",
        });
    }
    if crate::sha256_hex(&bytes) != expected_sha256 {
        return Err(StoreError::InvalidField {
            field: "reactive.content_sha256",
            reason: "digest does not name the snapshot bytes",
        });
    }
    Ok(bytes)
}

/// Validates one canonical `eliot://` resource identity.
///
/// String-level mirror of the I7.18 grammar owned by
/// `eliot-agent-bridge-core`: only the ten canonical forms are
/// admissible, with immutable IDs or explicit revisions exactly where
/// the contract demands them. Kept as a mirror (not a dependency) so
/// the store boundary stays vendor- and surface-independent; any
/// grammar change must update both sides together.
pub fn validate_resource_uri(uri: &str) -> Result<(), StoreError> {
    const INVALID: StoreError = StoreError::InvalidField {
        field: "reactive.uri",
        reason: "not a canonical resource identity",
    };
    if uri.trim().is_empty()
        || uri.bytes().any(|byte| byte.is_ascii_control())
        || uri.len() > MAX_RESOURCE_URI_BYTES
    {
        return Err(INVALID);
    }
    let rest = uri.strip_prefix(RESOURCE_URI_SCHEME).ok_or(INVALID)?;
    if rest.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(INVALID);
    }
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|segment| !valid_uri_segment(segment)) {
        return Err(INVALID);
    }
    if canonical_form(&segments) {
        Ok(())
    } else {
        Err(INVALID)
    }
}

/// Reports whether validated segments form one of the ten canonical
/// I7.18 resource shapes.
fn canonical_form(segments: &[&str]) -> bool {
    let head = segments.first().copied().unwrap_or_default();
    match (head, segments.len()) {
        ("scope", 3) => segments[2] == "state",
        ("task", 4) => segments[2] == "packet",
        ("evidence" | "conflict" | "problem" | "report", 2) | ("architecture", 3) => true,
        ("session", 3) => segments[2] == "attention" || segments[2] == "mailbox",
        ("job", 3) => segments[2] == "result",
        _ => false,
    }
}

fn valid_uri_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && segment != "."
        && segment != ".."
        && segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}
