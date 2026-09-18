//! Exhaustive typed conversion between the guest envelope and native A-17a.
//!
//! Every native input field, result field and error variant maps through a
//! closed, explicitly enumerated conversion. There is no wildcard, `Other`,
//! `Value` or whole-payload bridge: the request envelope carries exactly the
//! native [`AdmissionInput`](eliot_context_contracts::AdmissionInput) type,
//! so every candidate atom, provider denominator, representation, loss
//! policy, dependency, scope, capacity, measurement and omission binding is
//! preserved by construction. The response carries exactly the native
//! [`AdmissionResult`](eliot_context_contracts::AdmissionResult), including
//! the first-class [`DecisionContextIncomplete`](eliot_context_contracts::DecisionContextIncomplete)
//! outcome, which stays distinct from malformed-input failure and success.

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_context_admission::admit_context;
use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionResult, AtomAvailability, ContextError,
    LossPolicy, RepresentationKind,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{EXPORT_NAME, GUEST_ABI_VERSION, HANDLER_SUBTYPE, WORLD_NAME};

/// Byte ceiling for one canonical guest request envelope.
pub const MAX_GUEST_INPUT_BYTES: u64 = 1_048_576;
/// Byte ceiling for one canonical guest response envelope.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 4_194_304;
/// Exact external incomplete code; never a success and never a typed error.
pub const INCOMPLETE_CODE: &str = "DECISION_CONTEXT_INCOMPLETE";

/// Typed guest envelope over exactly the native A-17a admission input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the accepted WIT world name (`context-admission`).
    pub world: String,
    /// Must equal `HANDLER_SUBTYPE` (`context-compiler`).
    pub handler_subtype: String,
    /// The exact native admission input; every field preserved verbatim.
    pub input: AdmissionInput,
}

/// Typed guest response: exactly one of result or error is present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the handler subtype.
    pub handler_subtype: String,
    /// Native admission result on success, including first-class incomplete.
    pub result: Option<AdmissionResult>,
    /// Exhaustive typed error; `None` on success (complete or incomplete).
    pub error: Option<GuestError>,
    /// Native A-17a calls made by this invocation (0 or 1).
    pub native_calls: u64,
}

/// Closed guest error: one variant per native [`ContextError`] variant,
/// plus envelope rejections that never reach native.
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Native `MissingField`.
    #[error("missing required field: {0}")]
    MissingField(String),
    /// Native `InvalidField`.
    #[error("invalid field: {0}")]
    InvalidField(String),
    /// Native `Bounds`.
    #[error("field exceeds its bound: {0}")]
    BoundsExceeded(String),
    /// Native `InvalidFence`.
    #[error("invalid State Fence")]
    InvalidFence,
    /// Native `Duplicate`.
    #[error("duplicate identity: {0}")]
    DuplicateIdentity(String),
    /// Native `DenominatorMismatch`.
    #[error("provider/role denominator does not reconcile")]
    DenominatorMismatch,
    /// Native `IdentityConflict`.
    #[error("identity content conflict")]
    IdentityConflict,
    /// Native `WholeUnitRequired`.
    #[error("whole unit representation required")]
    WholeUnitRequired,
    /// Native `MissingFloor`.
    #[error("missing mandatory Safety Floor member")]
    MissingFloor,
    /// Native `StaleFloor`.
    #[error("stale mandatory Safety Floor member")]
    StaleFloor,
    /// Native `BlockedFloor`.
    #[error("blocked mandatory Safety Floor member")]
    BlockedFloor,
    /// Native `OversizedFloor`.
    #[error("Safety Floor exceeds route capacity")]
    OversizedFloor,
    /// Native `Overflow`.
    #[error("capacity arithmetic overflow")]
    CapacityOverflow,
    /// Native `CapacityExceeded`.
    #[error("capacity components exceed route capacity")]
    CapacityExceeded,
    /// Native `UnknownMeasurement`.
    #[error("measurement is unknown or unavailable")]
    UnknownMeasurement,
    /// Native `OmissionHandleInvalid`.
    #[error("omission handle binding is invalid")]
    OmissionHandleInvalid,
    /// Native `EconomyMismatch`.
    #[error("context economy receipt does not reconcile")]
    EconomyMismatch,
    /// Native `QualityIncomplete`.
    #[error("quality scorecard is incomplete")]
    QualityIncomplete,
    /// Native `SelectionIntegrityMismatch`.
    #[error("selection integrity does not match admitted membership")]
    SelectionIntegrityMismatch,
    /// Native `InvalidDigest`.
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    /// Envelope rejected before native execution: wrong ABI/subtype/world.
    #[error("rejected envelope: {0}")]
    RejectedEnvelope(String),
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {0}")]
    RejectedBytes(String),
}

impl From<&ContextError> for GuestError {
    fn from(error: &ContextError) -> Self {
        match error {
            ContextError::MissingField(field) => Self::MissingField((*field).to_owned()),
            ContextError::InvalidField(field) => Self::InvalidField((*field).to_owned()),
            ContextError::Bounds { field } => Self::BoundsExceeded((*field).to_owned()),
            ContextError::InvalidFence => Self::InvalidFence,
            ContextError::Duplicate(field) => Self::DuplicateIdentity((*field).to_owned()),
            ContextError::DenominatorMismatch => Self::DenominatorMismatch,
            ContextError::IdentityConflict => Self::IdentityConflict,
            ContextError::WholeUnitRequired => Self::WholeUnitRequired,
            ContextError::MissingFloor => Self::MissingFloor,
            ContextError::StaleFloor => Self::StaleFloor,
            ContextError::BlockedFloor => Self::BlockedFloor,
            ContextError::OversizedFloor => Self::OversizedFloor,
            ContextError::Overflow => Self::CapacityOverflow,
            ContextError::CapacityExceeded => Self::CapacityExceeded,
            ContextError::UnknownMeasurement => Self::UnknownMeasurement,
            ContextError::OmissionHandleInvalid => Self::OmissionHandleInvalid,
            ContextError::EconomyMismatch => Self::EconomyMismatch,
            ContextError::QualityIncomplete => Self::QualityIncomplete,
            ContextError::SelectionIntegrityMismatch => Self::SelectionIntegrityMismatch,
            ContextError::InvalidDigest(field) => Self::InvalidDigest((*field).to_owned()),
        }
    }
}

/// Observes native A-17a calls for exactly-once proof.
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

/// Canonical wire spelling of every native admission disposition (closed set,
/// kebab-case per the accepted `context-admission` WIT).
#[must_use]
pub const fn admission_disposition_as_str(disposition: AdmissionDisposition) -> &'static str {
    match disposition {
        AdmissionDisposition::Include => "include-member",
        AdmissionDisposition::HandleOnly => "handle-only",
        AdmissionDisposition::Revalidate => "revalidate",
        AdmissionDisposition::Suppress => "suppress",
        AdmissionDisposition::Quarantine => "quarantine",
        AdmissionDisposition::Unavailable => "unavailable",
        AdmissionDisposition::Blocked => "blocked",
        AdmissionDisposition::OverBudget => "over-budget",
    }
}

/// Parses a disposition wire spelling back to the closed enum.
#[must_use]
pub fn parse_admission_disposition(code: &str) -> Option<AdmissionDisposition> {
    match code {
        "include-member" => Some(AdmissionDisposition::Include),
        "handle-only" => Some(AdmissionDisposition::HandleOnly),
        "revalidate" => Some(AdmissionDisposition::Revalidate),
        "suppress" => Some(AdmissionDisposition::Suppress),
        "quarantine" => Some(AdmissionDisposition::Quarantine),
        "unavailable" => Some(AdmissionDisposition::Unavailable),
        "blocked" => Some(AdmissionDisposition::Blocked),
        "over-budget" => Some(AdmissionDisposition::OverBudget),
        _ => None,
    }
}

/// Canonical wire spelling of every native loss policy (closed set of four,
/// kebab-case per the accepted WIT).
#[must_use]
pub const fn loss_policy_as_str(policy: LossPolicy) -> &'static str {
    match policy {
        LossPolicy::NonDroppable => "non-droppable",
        LossPolicy::HandleOnly => "handle-only",
        LossPolicy::Extractive => "extractive",
        LossPolicy::Summarizable => "summarizable",
    }
}

/// Parses a loss-policy wire spelling back to the closed enum.
#[must_use]
pub fn parse_loss_policy(code: &str) -> Option<LossPolicy> {
    match code {
        "non-droppable" => Some(LossPolicy::NonDroppable),
        "handle-only" => Some(LossPolicy::HandleOnly),
        "extractive" => Some(LossPolicy::Extractive),
        "summarizable" => Some(LossPolicy::Summarizable),
        _ => None,
    }
}

/// Canonical wire spelling of every native atom availability (closed set of
/// ten, kebab-case per the accepted WIT).
#[must_use]
pub const fn availability_as_str(state: AtomAvailability) -> &'static str {
    match state {
        AtomAvailability::PresentCurrent => "present-current",
        AtomAvailability::Missing => "missing",
        AtomAvailability::Stale => "stale",
        AtomAvailability::Blocked => "blocked",
        AtomAvailability::Unavailable => "unavailable",
        AtomAvailability::Omitted => "omitted",
        AtomAvailability::Exhausted => "exhausted",
        AtomAvailability::Unknown => "unknown",
        AtomAvailability::KnownEmpty => "known-empty",
        AtomAvailability::Partial => "partial",
    }
}

/// Parses an availability wire spelling back to the closed enum.
#[must_use]
pub fn parse_availability(code: &str) -> Option<AtomAvailability> {
    match code {
        "present-current" => Some(AtomAvailability::PresentCurrent),
        "missing" => Some(AtomAvailability::Missing),
        "stale" => Some(AtomAvailability::Stale),
        "blocked" => Some(AtomAvailability::Blocked),
        "unavailable" => Some(AtomAvailability::Unavailable),
        "omitted" => Some(AtomAvailability::Omitted),
        "exhausted" => Some(AtomAvailability::Exhausted),
        "unknown" => Some(AtomAvailability::Unknown),
        "known-empty" => Some(AtomAvailability::KnownEmpty),
        "partial" => Some(AtomAvailability::Partial),
        _ => None,
    }
}

/// Canonical wire spelling of every native representation kind (closed set of
/// four, kebab-case per the accepted WIT).
#[must_use]
pub const fn representation_kind_as_str(kind: RepresentationKind) -> &'static str {
    match kind {
        RepresentationKind::Whole => "whole",
        RepresentationKind::Handle => "handle",
        RepresentationKind::Extractive => "extractive",
        RepresentationKind::Summary => "summary",
    }
}

/// Parses a representation-kind wire spelling back to the closed enum.
#[must_use]
pub fn parse_representation_kind(code: &str) -> Option<RepresentationKind> {
    match code {
        "whole" => Some(RepresentationKind::Whole),
        "handle" => Some(RepresentationKind::Handle),
        "extractive" => Some(RepresentationKind::Extractive),
        "summary" => Some(RepresentationKind::Summary),
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
        return Err(GuestError::RejectedBytes("response shape".to_owned()));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| GuestError::RejectedBytes("response shape".to_owned()))
}

/// Handles one typed request, calling the native A-17a gate at most once.
///
/// Rejected envelopes return before native execution with `native_calls: 0`.
/// A valid envelope calls [`admit_context`] exactly once and returns exactly
/// its semantic result with `native_calls: 1`: a complete set, a first-class
/// incomplete outcome, or the exact native typed failure.
pub fn handle_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let respond = |result: Option<AdmissionResult>,
                   error: Option<GuestError>,
                   native_calls: u64| GuestResponse {
        abi_version: request.abi_version,
        handler_subtype: request.handler_subtype.clone(),
        result,
        error,
        native_calls,
    };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0);
    }
    let before = ledger.calls();
    ledger.record_call();
    match admit_context(&request.input) {
        Ok(result) => respond(Some(result), None, ledger.calls() - before),
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

/// Name of the byte-transport WIT export this adapter implements.
#[must_use]
pub const fn wit_export_name() -> &'static str {
    EXPORT_NAME
}

/// SHA-256 of canonical request bytes for capsule/response binding.
#[must_use]
pub fn request_digest(request: &GuestRequest) -> String {
    sha256_hex(&canonical_json_bytes(request).unwrap_or_default())
}
