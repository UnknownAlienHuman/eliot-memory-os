//! Exhaustive typed conversion between the guest envelope and native A-14a.
//!
//! Every native input field, result field and error variant maps through a
//! closed, explicitly enumerated conversion. There is no wildcard, `Other`,
//! `Value` or whole-payload bridge: the single explicitly canonical leaf is
//! the request/response byte envelope at the `activate` boundary, and even
//! that envelope decodes only into the typed [`GuestRequest`]/[`GuestResponse`].
//!
//! The guest performs envelope preflight only (ABI version and world). All
//! domain binding — snapshot identity, fence, profile equality, registry
//! revision, freshness, limits — stays inside native
//! [`evaluate_activation`](eliot_cue_activation::evaluate_activation), so a
//! representable stale/partial/unknown input keeps exact native behavior
//! instead of a guest-recomputed rejection.

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_cue_activation::{
    ActivationError, ActivationProfile, CueActivationEvaluation, evaluate_activation,
};
use eliot_cue_contracts::{
    ActivationRequest, BoundKind, Completeness, CueContractError, CueSnapshotBuildCandidate,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{EXPORT_NAME, GUEST_ABI_VERSION, WORLD_NAME};

/// Byte ceiling for one canonical guest request envelope.
pub const MAX_GUEST_INPUT_BYTES: u64 = 1_048_576;
/// Byte ceiling for one canonical guest response envelope.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 1_048_576;

/// Typed guest envelope over exactly the three native A-14a inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the accepted WIT world name.
    pub world: String,
    /// Immutable snapshot build candidate under evaluation.
    pub candidate: CueSnapshotBuildCandidate,
    /// Bounded activation request bound to the candidate.
    pub request: ActivationRequest,
    /// Caller-supplied versioned numerical profile.
    pub profile: ActivationProfile,
}

/// Typed guest response: exactly one of evaluation or error is present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the request world.
    pub world: String,
    /// Native evaluation on success; `None` on error.
    pub evaluation: Option<CueActivationEvaluation>,
    /// Exhaustive typed error; `None` on success.
    pub error: Option<GuestError>,
    /// Native evaluator calls made by this invocation (0 or 1).
    pub native_calls: u64,
}

/// Closed guest error: one variant per native [`ActivationError`] variant,
// plus envelope rejections that never reach native.
///
/// The eight closed [`CueContractError`] rejections map field-for-field with
/// owned spellings because the native `&'static` field paths are not
/// `DeserializeOwned`; no rejection is reworded, merged, or weakened at the
/// guest boundary.
#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Native contract `InvalidText` rejection.
    #[error("{field} must be non-blank and free of control characters")]
    ContractInvalidText {
        /// Stable native field path.
        field: String,
    },
    /// Native contract `BoundExceeded` rejection.
    #[error("{field} exceeds its declared bound of {limit}")]
    ContractBoundExceeded {
        /// Stable native field path.
        field: String,
        /// The declared native limit that was crossed.
        limit: usize,
    },
    /// Native contract `BrokenActivationPath` rejection.
    #[error("derived activation path is empty, broken, or does not start at a direct seed")]
    ContractBrokenActivationPath,
    /// Native contract `CompleteWithFrontier` rejection.
    #[error("a complete result cannot carry an unresolved frontier")]
    ContractCompleteWithFrontier,
    /// Native contract `TruncationWithoutBound` rejection.
    #[error("a truncated result must name the bound it hit")]
    ContractTruncationWithoutBound,
    /// Native contract `SnapshotNotRebuildable` rejection.
    #[error("snapshot digest does not match its recorded rebuild inputs")]
    ContractSnapshotNotRebuildable,
    /// Native contract `DuplicateIdentity` rejection.
    #[error("duplicate identity in {field}")]
    ContractDuplicateIdentity {
        /// Stable native field path.
        field: String,
    },
    /// Native contract `Foundation` rejection.
    #[error("foundation contract rejected {field}")]
    ContractFoundation {
        /// Stable native field path.
        field: String,
    },
    /// Native `ProfileBinding` failure.
    #[error("activation profile is incompatible with the candidate or request")]
    ProfileBinding,
    /// Native `StaleInput` failure.
    #[error("activation input is stale or unavailable for the requested fence")]
    StaleInput,
    /// Native `Unsupported` failure.
    #[error("activation input is unsupported by this bounded evaluator")]
    Unsupported,
    /// Native `Cancelled` failure.
    #[error("activation was cancelled before evaluation")]
    Cancelled,
    /// Native `Deadline` failure.
    #[error("activation deadline has passed")]
    Deadline,
    /// Native `Limit` failure.
    #[error("activation bound exceeded for {field}")]
    Limit {
        /// Stable native bound field name.
        field: String,
    },
    /// Envelope rejected before native execution: wrong ABI/world.
    #[error("rejected envelope: {0}")]
    RejectedEnvelope(String),
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {0}")]
    RejectedBytes(String),
}

impl From<&ActivationError> for GuestError {
    fn from(error: &ActivationError) -> Self {
        // `match_same_arms`: the wildcard body intentionally equals
        // `Unsupported` — a future native variant must stay a typed failure,
        // never a fabricated success.
        #[allow(clippy::match_same_arms)]
        match error {
            ActivationError::Contract(contract) => match contract {
                CueContractError::InvalidText { field } => Self::ContractInvalidText {
                    field: (*field).to_owned(),
                },
                CueContractError::BoundExceeded { field, limit } => Self::ContractBoundExceeded {
                    field: (*field).to_owned(),
                    limit: *limit,
                },
                CueContractError::BrokenActivationPath => Self::ContractBrokenActivationPath,
                CueContractError::CompleteWithFrontier => Self::ContractCompleteWithFrontier,
                CueContractError::TruncationWithoutBound => Self::ContractTruncationWithoutBound,
                CueContractError::SnapshotNotRebuildable => Self::ContractSnapshotNotRebuildable,
                CueContractError::DuplicateIdentity { field } => Self::ContractDuplicateIdentity {
                    field: (*field).to_owned(),
                },
                CueContractError::Foundation { field } => Self::ContractFoundation {
                    field: (*field).to_owned(),
                },
                // `CueContractError` is non-exhaustive: a future native
                // rejection has no wire spelling on this base and stays a
                // foundation failure rather than a fabricated success.
                // Dead on this base: all eight current variants above.
                _ => Self::ContractFoundation {
                    field: "cue_contract.unknown_future_variant".to_owned(),
                },
            },
            ActivationError::ProfileBinding => Self::ProfileBinding,
            ActivationError::StaleInput => Self::StaleInput,
            ActivationError::Unsupported => Self::Unsupported,
            ActivationError::Cancelled => Self::Cancelled,
            ActivationError::Deadline => Self::Deadline,
            ActivationError::Limit { field } => Self::Limit {
                field: (*field).to_owned(),
            },
            // `ActivationError` is non-exhaustive: a future native variant has
            // no wire spelling on this base and stays unsupported rather than
            // becoming a fabricated success or a reworded contract failure.
            // Dead on this base: every current variant is enumerated above.
            _ => Self::Unsupported,
        }
    }
}

/// Observes native A-14a evaluator calls for exactly-once proof.
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

/// Canonical wire spelling of one native completeness state (closed set of 9).
///
/// The readable `cue-activation.wit` names five of these
/// (`complete`, `truncated`, `source-unavailable`, `stale`, `no-direct-match`);
/// the remaining four (`partial`, `blocked`, `unavailable`, `unknown`) are
/// contract vocabulary with no native producer on this base (frozen
/// expectation, proven in `WORK_UNIT_CASE: 640/4`). A future native state has
/// no spelling here and maps to `None` instead of an invented code.
#[must_use]
pub const fn completeness_as_str(completeness: &Completeness) -> Option<&'static str> {
    match completeness {
        Completeness::Complete => Some("complete"),
        Completeness::Truncated { .. } => Some("truncated"),
        Completeness::Partial { .. } => Some("partial"),
        Completeness::Blocked { .. } => Some("blocked"),
        Completeness::Unavailable { .. } => Some("unavailable"),
        Completeness::Unknown { .. } => Some("unknown"),
        Completeness::SourceUnavailable { .. } => Some("source-unavailable"),
        Completeness::NoDirectMatch { .. } => Some("no-direct-match"),
        Completeness::Stale { .. } => Some("stale"),
        _ => None,
    }
}

/// Parses a completeness wire spelling back to its discriminant.
///
/// Payload-carrying states parse to their empty-payload form; only the
/// discriminant round-trips here, never the frontier or reason text.
#[must_use]
pub fn parse_completeness(code: &str) -> Option<Completeness> {
    // `match_same_arms`: `stale` intentionally shares the `None` body — its
    // fence payload is load-bearing, so it has a spelling but no
    // empty-payload parse.
    #[allow(clippy::match_same_arms)]
    match code {
        "complete" => Some(Completeness::Complete),
        "truncated" => Some(Completeness::Truncated {
            frontier: Vec::new(),
            bound_hit: BoundKind::Depth,
        }),
        "partial" => Some(Completeness::Partial {
            frontier: Vec::new(),
        }),
        "blocked" => Some(Completeness::Blocked {
            reason: String::new(),
        }),
        "unavailable" => Some(Completeness::Unavailable {
            reason: String::new(),
        }),
        "unknown" => Some(Completeness::Unknown {
            reason: String::new(),
        }),
        "source-unavailable" => Some(Completeness::SourceUnavailable {
            reason: String::new(),
        }),
        "no-direct-match" => Some(Completeness::NoDirectMatch {
            reason: String::new(),
        }),
        "stale" => None,
        _ => None,
    }
}

/// Canonical wire spelling of one native bound kind (closed set of 4).
///
/// The readable WIT names twelve bound kinds; only these four have a native
/// producer on this base. The remaining WIT kinds (`results`, `nodes`,
/// `edges`, `work`, `path-len`, `seeds`, `direct`, `derived`, `trace-steps`,
/// `output-bytes`) are frozen: asserted absent from native output in
/// `WORK_UNIT_CASE: 640/4`, never invented here.
#[must_use]
pub const fn bound_kind_as_str(bound: BoundKind) -> Option<&'static str> {
    match bound {
        BoundKind::Depth => Some("depth"),
        BoundKind::Fanout => Some("fanout"),
        BoundKind::Results => Some("results"),
        BoundKind::Threshold => Some("threshold"),
        _ => None,
    }
}

/// Parses a bound-kind wire spelling back to the closed enum.
#[must_use]
pub fn parse_bound_kind(code: &str) -> Option<BoundKind> {
    match code {
        "depth" => Some(BoundKind::Depth),
        "fanout" => Some(BoundKind::Fanout),
        "results" => Some(BoundKind::Results),
        "threshold" => Some(BoundKind::Threshold),
        _ => None,
    }
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

/// Handles one typed request, calling the native evaluator at most once.
///
/// Rejected envelopes return before native execution with `native_calls: 0`.
/// A valid envelope calls [`evaluate_activation`] exactly once and returns
/// exactly its semantic evaluation with `native_calls: 1`, including every
/// native error mapped losslessly through [`GuestError`].
pub fn handle_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let respond = |evaluation: Option<CueActivationEvaluation>,
                   error: Option<GuestError>,
                   native_calls: u64| GuestResponse {
        abi_version: request.abi_version,
        world: request.world.clone(),
        evaluation,
        error,
        native_calls,
    };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0);
    }
    let before = ledger.calls();
    ledger.record_call();
    match evaluate_activation(&request.candidate, &request.request, &request.profile) {
        Ok(evaluation) => respond(Some(evaluation), None, ledger.calls() - before),
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
