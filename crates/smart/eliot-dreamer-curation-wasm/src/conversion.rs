//! Exhaustive typed conversion between the guest envelope and native A-31.
//!
//! Every native input field, result field and error variant maps through a
//! closed, explicitly enumerated conversion. There is no wildcard, `Other`,
//! `Value` or whole-payload bridge: the single explicitly canonical leaf is
//! the request/response byte envelope at the `handle` boundary, and even that
//! envelope decodes only into the typed [`GuestRequest`]/[`GuestResponse`].
//! The kind-to-family table is never duplicated here: [`family_of`] is the
//! single accepted mapping and this module only calls it.

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{
    CurationFamily, CurationKind, CurationRejectionCode, ScreenBinding, family_of, parse_family,
    parse_kind,
};
use eliot_dreamer_curation::{
    CurationCandidateSet, CurationRoutingError, NativeCurationPortSet, RoutingDisposition,
    RoutingPolicy, ValidatedCurationBatch, route_validated_curation, routing_rejection_hint,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{EXPORT_NAME, GUEST_ABI_VERSION, HANDLER_SUBTYPE, WORLD_NAME};
use crate::static_registry::{missing_static_ports_error, static_registry};

/// Byte ceiling for one canonical guest request envelope.
pub const MAX_GUEST_INPUT_BYTES: u64 = 1_048_576;
/// Byte ceiling for one canonical guest response envelope.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 1_048_576;

/// Typed guest envelope over exactly the native A-31 inputs.
///
/// The registry is deliberately not carried: this component root owns static
/// registration and always routes through [`static_registry`]. Live ports are
/// injected at the typed Rust boundary only; no callable objects cross bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the accepted WIT world name.
    pub world: String,
    /// Must equal `HANDLER_SUBTYPE`.
    pub handler_subtype: String,
    /// Already A-05-validated batch proposed for fan-in dispatch.
    pub batch: ValidatedCurationBatch,
    /// Exact immutable A-19c screen binding the batch was sealed against.
    pub screen: ScreenBinding,
    /// Routing policy bound into the batch input digest.
    pub policy: RoutingPolicy,
}

/// Typed guest response: exactly one of set or error is present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the handler subtype.
    pub handler_subtype: String,
    /// Native candidate set on success; `None` on error.
    pub set: Option<CurationCandidateSet>,
    /// Exhaustive typed error; `None` on success.
    pub error: Option<GuestError>,
    /// Native A-31 calls made by this invocation (0 or 1).
    pub native_calls: u64,
    /// Digest of the static registry this invocation composed (empty only
    /// when static composition itself failed).
    pub static_registry_digest: String,
}

/// Closed guest error: one variant per native [`CurationRoutingError`]
/// variant, plus envelope rejections that never reach native, plus the frozen
/// missing-owner edge for dispatchable envelopes without owner-published
/// live ports.
#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Native `Batch` envelope failure.
    #[error("batch[{field}]: {detail}")]
    Batch {
        /// Closed native field name.
        field: String,
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Binding` disagreement.
    #[error("binding[{field}]: {detail}")]
    Binding {
        /// Closed native binding name.
        field: String,
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Receipt` failure.
    #[error("receipt: {detail}")]
    Receipt {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Screen` failure.
    #[error("screen: {detail}")]
    Screen {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Registry` failure.
    #[error("registry: {detail}")]
    Registry {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Port` failure.
    #[error("port: {detail}")]
    Port {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Policy` failure.
    #[error("policy: {detail}")]
    Policy {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Denominator` failure.
    #[error("denominator: {detail}")]
    Denominator {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Handler` terminal failure.
    #[error("handler[{handler_id}]: {detail}")]
    Handler {
        /// Handler that reported the failure.
        handler_id: String,
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `HandlerPanicked` terminal failure.
    #[error("handler[{handler_id}] panicked: terminal, no alternate handler")]
    HandlerPanicked {
        /// Handler that panicked.
        handler_id: String,
    },
    /// Native `Envelope` drift failure.
    #[error("envelope[{handler_id}]: {detail}")]
    Envelope {
        /// Handler that returned the drifting envelope.
        handler_id: String,
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Atomicity` failure.
    #[error("atomicity: {detail}")]
    Atomicity {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Native `Digest` failure.
    #[error("digest: {detail}")]
    Digest {
        /// Bounded redacted native reason.
        detail: String,
    },
    /// Envelope rejected before native execution: wrong ABI/subtype/world.
    #[error("rejected envelope: {0}")]
    RejectedEnvelope(String),
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {0}")]
    RejectedBytes(String),
    /// Dispatchable envelope without owner-published live ports (frozen).
    #[error("missing static ports: {detail}")]
    MissingStaticPorts {
        /// Frozen missing-owner detail naming absent families and owners.
        detail: String,
        /// Canonical family spellings with no published live handler.
        missing_handlers: Vec<String>,
    },
}

impl From<&CurationRoutingError> for GuestError {
    fn from(error: &CurationRoutingError) -> Self {
        match error {
            CurationRoutingError::Batch { field, detail } => Self::Batch {
                field: (*field).to_owned(),
                detail: detail.clone(),
            },
            CurationRoutingError::Binding { field, detail } => Self::Binding {
                field: (*field).to_owned(),
                detail: detail.clone(),
            },
            CurationRoutingError::Receipt { detail } => Self::Receipt {
                detail: detail.clone(),
            },
            CurationRoutingError::Screen { detail } => Self::Screen {
                detail: detail.clone(),
            },
            CurationRoutingError::Registry { detail } => Self::Registry {
                detail: detail.clone(),
            },
            CurationRoutingError::Port { detail } => Self::Port {
                detail: detail.clone(),
            },
            CurationRoutingError::Policy { detail } => Self::Policy {
                detail: detail.clone(),
            },
            CurationRoutingError::Denominator { detail } => Self::Denominator {
                detail: detail.clone(),
            },
            CurationRoutingError::Handler { handler_id, detail } => Self::Handler {
                handler_id: handler_id.clone(),
                detail: detail.clone(),
            },
            CurationRoutingError::HandlerPanicked { handler_id } => Self::HandlerPanicked {
                handler_id: handler_id.clone(),
            },
            CurationRoutingError::Envelope { handler_id, detail } => Self::Envelope {
                handler_id: handler_id.clone(),
                detail: detail.clone(),
            },
            CurationRoutingError::Atomicity { detail } => Self::Atomicity {
                detail: detail.clone(),
            },
            CurationRoutingError::Digest { detail } => Self::Digest {
                detail: detail.clone(),
            },
        }
    }
}

/// Observes native A-31 fan-in calls for exactly-once proof.
#[derive(Debug, Default)]
pub struct CallLedger {
    calls: AtomicU64,
}

impl CallLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
        }
    }

    /// Returns calls recorded so far.
    #[must_use]
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn record_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// Canonical wire spelling of one native curation kind (closed set of 11).
#[must_use]
pub const fn kind_as_str(kind: CurationKind) -> &'static str {
    kind.as_str()
}

/// Parses a kind wire spelling back to the closed enum.
#[must_use]
pub fn parse_kind_spelling(code: &str) -> Option<CurationKind> {
    parse_kind(code).ok()
}

/// Canonical wire spelling of one native handler family (closed set of 10).
#[must_use]
pub const fn family_as_str(family: CurationFamily) -> &'static str {
    family.as_str()
}

/// Parses a family wire spelling back to the closed enum.
#[must_use]
pub fn parse_family_spelling(code: &str) -> Option<CurationFamily> {
    parse_family(code).ok()
}

/// Canonical wire spelling of every native routing disposition (closed set).
#[must_use]
pub const fn disposition_as_str(disposition: RoutingDisposition) -> &'static str {
    disposition.as_str()
}

/// Parses a disposition wire spelling back to the closed enum.
#[must_use]
pub fn parse_disposition(code: &str) -> Option<RoutingDisposition> {
    match code {
        "candidate" => Some(RoutingDisposition::Candidate),
        "duplicate" => Some(RoutingDisposition::Duplicate),
        "conflict" => Some(RoutingDisposition::Conflict),
        "abstention" => Some(RoutingDisposition::Abstention),
        "partial" => Some(RoutingDisposition::Partial),
        "blocked" => Some(RoutingDisposition::Blocked),
        "unsupported" => Some(RoutingDisposition::Unsupported),
        "internal_defect" => Some(RoutingDisposition::InternalDefect),
        "unprocessed" => Some(RoutingDisposition::Unprocessed),
        _ => None,
    }
}

/// Canonical wire spelling of one routing rejection hint, if any.
#[must_use]
pub const fn rejection_hint_as_str(hint: Option<CurationRejectionCode>) -> Option<&'static str> {
    match hint {
        None => None,
        Some(code) => Some(code.as_str()),
    }
}

/// Resolves one wire kind through the single accepted kind-to-family mapping.
///
/// This is a call, not a table: the guest never duplicates the mapping.
#[must_use]
pub const fn resolve_family(kind: CurationKind) -> CurationFamily {
    family_of(kind)
}

/// Resolves the routing-only rejection hint for one disposition.
#[must_use]
pub const fn resolve_rejection_hint(
    disposition: RoutingDisposition,
) -> Option<CurationRejectionCode> {
    routing_rejection_hint(disposition)
}

/// Conversion failures that cannot occur on well-formed input.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConversionError {
    /// Canonical encoding failed for a stated stage.
    #[error("guest encoding failed for {0}")]
    Encoding(&'static str),
    /// Envelope exceeds the guest byte ceiling.
    #[error("guest envelope exceeds byte ceiling")]
    TooLarge,
}

fn check_envelope(request: &GuestRequest) -> Result<(), GuestError> {
    if request.abi_version != GUEST_ABI_VERSION {
        return Err(GuestError::RejectedEnvelope("abi_version".to_owned()));
    }
    if request.world != WORLD_NAME {
        return Err(GuestError::RejectedEnvelope("world".to_owned()));
    }
    if request.handler_subtype != HANDLER_SUBTYPE {
        return Err(GuestError::RejectedEnvelope("handler_subtype".to_owned()));
    }
    Ok(())
}

/// Encodes a typed request to its canonical byte envelope.
pub fn encode_request(request: &GuestRequest) -> Result<Vec<u8>, ConversionError> {
    let bytes =
        canonical_json_bytes(request).map_err(|_| ConversionError::Encoding("guest request"))?;
    if u64::try_from(bytes.len()).map_err(|_| ConversionError::TooLarge)? > MAX_GUEST_INPUT_BYTES {
        return Err(ConversionError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes canonical bytes into the typed request; unknown fields fail.
pub fn decode_request(bytes: &[u8]) -> Result<GuestRequest, GuestError> {
    if u64::try_from(bytes.len())
        .map_err(|_| GuestError::RejectedBytes("input bytes".to_owned()))?
        > MAX_GUEST_INPUT_BYTES
    {
        return Err(GuestError::RejectedBytes("input bytes".to_owned()));
    }
    serde_json::from_slice(bytes).map_err(|_| GuestError::RejectedBytes("request shape".to_owned()))
}

/// Encodes a typed response to its canonical byte envelope.
pub fn encode_response(response: &GuestResponse) -> Result<Vec<u8>, ConversionError> {
    let bytes =
        canonical_json_bytes(response).map_err(|_| ConversionError::Encoding("guest response"))?;
    if u64::try_from(bytes.len()).map_err(|_| ConversionError::TooLarge)? > MAX_GUEST_OUTPUT_BYTES {
        return Err(ConversionError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes canonical bytes into the typed response; unknown fields fail.
pub fn decode_response(bytes: &[u8]) -> Result<GuestResponse, GuestError> {
    if u64::try_from(bytes.len())
        .map_err(|_| GuestError::RejectedBytes("output bytes".to_owned()))?
        > MAX_GUEST_OUTPUT_BYTES
    {
        return Err(GuestError::RejectedBytes("output bytes".to_owned()));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| GuestError::RejectedBytes("response shape".to_owned()))
}

/// Handles one typed request against the static registry, calling native
/// A-31 at most once.
///
/// Rejected envelopes return before native execution with `native_calls: 0`
/// and an empty registry digest. A valid envelope routes through the static
/// registry exactly once and returns exactly the native semantic candidate
/// set with `native_calls: 1`.
pub fn handle_with_ports(
    request: &GuestRequest,
    ports: &NativeCurationPortSet<'_>,
    ledger: &CallLedger,
) -> GuestResponse {
    let respond = |set: Option<CurationCandidateSet>,
                   error: Option<GuestError>,
                   native_calls: u64,
                   static_registry_digest: String| GuestResponse {
        abi_version: request.abi_version,
        handler_subtype: request.handler_subtype.clone(),
        set,
        error,
        native_calls,
        static_registry_digest,
    };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0, String::new());
    }
    let registry = match static_registry() {
        Ok(registry) => registry,
        Err(error) => return respond(None, Some(error), 0, String::new()),
    };
    let Ok(registry_digest) = registry.digest() else {
        return respond(
            None,
            Some(GuestError::Registry {
                detail: "static registry digest requires closed registry".to_owned(),
            }),
            0,
            String::new(),
        );
    };
    let before = ledger.calls();
    ledger.record_call();
    match route_validated_curation(
        &request.batch,
        &request.screen,
        &registry,
        &request.policy,
        ports,
    ) {
        Ok(set) => respond(Some(set), None, ledger.calls() - before, registry_digest),
        Err(error) => respond(
            None,
            Some(GuestError::from(&error)),
            ledger.calls() - before,
            registry_digest,
        ),
    }
}

/// Handles one typed request with an ephemeral ledger.
pub fn handle_request_typed(
    request: &GuestRequest,
    ports: &NativeCurationPortSet<'_>,
) -> GuestResponse {
    handle_with_ports(request, ports, &CallLedger::new())
}

/// Handles one typed request through static composition only, without live
/// ports and without native execution.
///
/// Preflight rejections return their exact error. A dispatchable envelope
/// proves the static registry constructs closed, then returns the frozen
/// missing-owner error with `native_calls: 0`: no production live-handler
/// binding exists on this base, and none is fabricated.
pub fn handle_static_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let before = ledger.calls();
    let respond = |error: GuestError, static_registry_digest: String| GuestResponse {
        abi_version: request.abi_version,
        handler_subtype: request.handler_subtype.clone(),
        set: None,
        error: Some(error),
        // Static composition never executes A-31: the ledger must be untouched.
        native_calls: 0,
        static_registry_digest,
    };
    if let Err(error) = check_envelope(request) {
        debug_assert_eq!(ledger.calls(), before);
        return respond(error, String::new());
    }
    let registry_digest = match static_registry() {
        Ok(registry) => match registry.digest() {
            Ok(digest) => digest,
            Err(_) => {
                return respond(
                    GuestError::Registry {
                        detail: "static registry digest requires closed registry".to_owned(),
                    },
                    String::new(),
                );
            }
        },
        Err(error) => {
            debug_assert_eq!(ledger.calls(), before);
            return respond(error, String::new());
        }
    };
    debug_assert_eq!(ledger.calls(), before);
    respond(missing_static_ports_error(), registry_digest)
}

/// Name of the WIT export this adapter implements.
#[must_use]
pub const fn wit_export_name() -> &'static str {
    EXPORT_NAME
}

/// SHA-256 of canonical request bytes for capsule/response binding.
#[must_use]
pub fn request_digest(request: &GuestRequest) -> String {
    sha256_hex(&canonical_json_bytes(request).unwrap_or_default())
}
