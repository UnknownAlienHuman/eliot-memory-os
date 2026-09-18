//! Exhaustive typed conversion between the guest envelope and native API.
//!
//! Every native input field, result field and error variant maps through a
//! closed, explicitly enumerated conversion. There is no wildcard, `Other`,
//! `Value` or whole-payload bridge: the single explicitly canonical leaf is
//! the request/response byte envelope at the `run` boundary, and even that
//! envelope decodes only into the typed [`GuestRequest`]/[`GuestResponse`].

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, CurrentEpistemicPositionHandle, OrientationDisposition,
    OrientationError, OrientationPacketCandidate, OrientationPolicy, project_orientation,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{EXPORT_NAME, GUEST_ABI_VERSION, HANDLER_SUBTYPE, WORLD_NAME};

/// Byte ceiling for one canonical guest request envelope.
pub const MAX_GUEST_INPUT_BYTES: u64 = 1_048_576;
/// Byte ceiling for one canonical guest response envelope.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 1_048_576;

/// Typed guest envelope over exactly the five native Orientation inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the accepted WIT world name.
    pub world: String,
    /// Must equal `HANDLER_SUBTYPE`.
    pub handler_subtype: String,
    /// Admitted job: job, frame, evidence and coverage denominator.
    pub admitted: AdmittedOrientationJob,
    /// Supplied bundle; must equal `candidate.bundle`.
    pub bundle: eliot_dreamer_contracts::DreamInputBundle,
    /// A03-validated candidate.
    pub candidate: eliot_dreamer_contracts::ValidatedCandidate,
    /// Current epistemic position handles.
    pub positions: Vec<CurrentEpistemicPositionHandle>,
    /// Explicit per-invocation policy.
    pub policy: OrientationPolicy,
}

/// Typed guest response: exactly one of packet or error is present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the handler subtype.
    pub handler_subtype: String,
    /// Native packet on success; `None` on error.
    pub packet: Option<OrientationPacketCandidate>,
    /// Exhaustive typed error; `None` on success.
    pub error: Option<GuestError>,
    /// Native projector calls made by this invocation (0 or 1).
    pub native_calls: u64,
}

/// Closed guest error: one variant per native [`OrientationError`] variant,
/// plus envelope rejections that never reach native.
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Native `WrongJobClass`.
    #[error("wrong job class")]
    WrongJobClass,
    /// Native `Invalid`.
    #[error("invalid {0}")]
    InvalidField(String),
    /// Native `Unsupported`.
    #[error("unsupported {0}")]
    UnsupportedShape(String),
    /// Native `Binding`.
    #[error("binding mismatch: {0}")]
    BindingMismatch(String),
    /// Native `Bound`.
    #[error("bounded orientation limit exceeded")]
    BoundExceeded,
    /// Native `Bounded`.
    #[error("bounded orientation input exceeds {0} limit")]
    BoundedLimit(String),
    /// Native `RevalidationRequired`.
    #[error("revalidation required: current observation time is unavailable")]
    RevalidationRequired,
    /// Native `Cancelled`.
    #[error("cancelled")]
    Cancelled,
    /// Native `Encoding`.
    #[error("encoding failed for {0}")]
    EncodingFailure(String),
    /// Native `Internal`.
    #[error("internal projector failure")]
    InternalFailure,
    /// Envelope rejected before native execution: wrong ABI/subtype/world.
    #[error("rejected envelope: {0}")]
    RejectedEnvelope(String),
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {0}")]
    RejectedBytes(String),
}

impl From<&OrientationError> for GuestError {
    fn from(error: &OrientationError) -> Self {
        match error {
            OrientationError::WrongJobClass => Self::WrongJobClass,
            OrientationError::Invalid(field) => Self::InvalidField((*field).to_owned()),
            OrientationError::Unsupported(shape) => Self::UnsupportedShape((*shape).to_owned()),
            OrientationError::Binding(binding) => Self::BindingMismatch((*binding).to_owned()),
            OrientationError::Bound => Self::BoundExceeded,
            OrientationError::Bounded(limit) => Self::BoundedLimit((*limit).to_owned()),
            OrientationError::RevalidationRequired => Self::RevalidationRequired,
            OrientationError::Cancelled => Self::Cancelled,
            OrientationError::Encoding(stage) => Self::EncodingFailure((*stage).to_owned()),
            OrientationError::Internal => Self::InternalFailure,
        }
    }
}

/// Observes native projector calls for exactly-once proof.
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

/// Canonical wire spelling of every native disposition (closed set).
#[must_use]
pub const fn disposition_as_str(disposition: OrientationDisposition) -> &'static str {
    match disposition {
        OrientationDisposition::Complete => "complete",
        OrientationDisposition::Partial => "partial",
        OrientationDisposition::Blocked => "blocked",
        OrientationDisposition::RevalidationRequired => "revalidation_required",
        OrientationDisposition::Unsupported => "unsupported",
        OrientationDisposition::Abstention => "abstention",
        OrientationDisposition::Cancelled => "cancelled",
        OrientationDisposition::Bound => "bound",
        OrientationDisposition::Invalid => "invalid",
        OrientationDisposition::Internal => "internal",
    }
}

/// Parses a disposition wire spelling back to the closed enum.
#[must_use]
pub fn parse_disposition(code: &str) -> Option<OrientationDisposition> {
    match code {
        "complete" => Some(OrientationDisposition::Complete),
        "partial" => Some(OrientationDisposition::Partial),
        "blocked" => Some(OrientationDisposition::Blocked),
        "revalidation_required" => Some(OrientationDisposition::RevalidationRequired),
        "unsupported" => Some(OrientationDisposition::Unsupported),
        "abstention" => Some(OrientationDisposition::Abstention),
        "cancelled" => Some(OrientationDisposition::Cancelled),
        "bound" => Some(OrientationDisposition::Bound),
        "invalid" => Some(OrientationDisposition::Invalid),
        "internal" => Some(OrientationDisposition::Internal),
        _ => None,
    }
}

/// Conversion failures that cannot occur on well-formed input.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
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
    if request.bundle != request.candidate.bundle {
        return Err(GuestError::BindingMismatch("supplied bundle".to_owned()));
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

/// Handles one typed request, calling the native projector at most once.
///
/// Rejected envelopes return before native execution with `native_calls: 0`.
/// A valid envelope calls [`project_orientation`] exactly once and returns
/// exactly its semantic result with `native_calls: 1`.
pub fn handle_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let respond = |packet: Option<OrientationPacketCandidate>,
                   error: Option<GuestError>,
                   native_calls: u64| GuestResponse {
        abi_version: request.abi_version,
        handler_subtype: request.handler_subtype.clone(),
        packet,
        error,
        native_calls,
    };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0);
    }
    let before = ledger.calls();
    ledger.record_call();
    match project_orientation(
        &request.admitted,
        &request.bundle,
        &request.candidate,
        &request.positions,
        &request.policy,
    ) {
        Ok(packet) => respond(Some(packet), None, ledger.calls() - before),
        Err(error) => respond(
            None,
            Some(GuestError::from(&error)),
            ledger.calls() - before,
        ),
    }
}

/// Handles one typed request with an ephemeral ledger.
pub fn handle_request_typed(request: &GuestRequest) -> GuestResponse {
    handle_with_ledger(request, &CallLedger::new())
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
