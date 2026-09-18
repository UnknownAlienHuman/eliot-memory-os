//! Exhaustive typed conversion between the guest envelope and native A-20.
//!
//! Every native input field, result field and error variant maps through a
//! closed, explicitly enumerated conversion. There is no wildcard, `Other`,
//! `Value` or whole-payload bridge: the single explicitly canonical leaf is
//! the request/response byte envelope at the `screen` boundary, and even that
//! envelope decodes only into the typed [`GuestRequest`]/[`GuestResponse`].
//! The transport carries the native [`CurationScreenRequest`],
//! [`SourceSnapshot`] and [`ProtectionEvidence`] verbatim, so the guest adds
//! no screening, protection, eligibility, paging, or handler semantics.
//!
//! The `*_as_str` / `parse_*` helpers are read-only parity projections onto
//! the readable (not accepted) `memory-curation-screen.wit` spellings. Where
//! the WIT world has no counterpart for a native variant they return `None`
//! instead of inventing one; the accepted ABI stays owned by #756 and the
//! native shapes stay owned by #586/#588.

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_memory_curation_contracts::{
    ContractError, CurationScreenRequest, CurationScreenResult, EligibilityStatus, FindingClass,
    FindingProof, MemberDisposition, ProtectionDecision, ProtectionEvidence, ResultState,
    SourceAvailability, SourceSnapshot,
};
use eliot_memory_curation_screen::{CurationScreenError, screen_memory_curation};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{EXPORT_NAME, GUEST_ABI_VERSION, HANDLER_SUBTYPE, WORLD_NAME};

/// Byte ceiling for one canonical guest request envelope.
///
/// Equals the native [`MAX_INPUT_BYTES`](eliot_memory_curation_screen::MAX_INPUT_BYTES)
/// ceiling so native bound errors surface unchanged instead of being
/// pre-empted by the guest.
pub const MAX_GUEST_INPUT_BYTES: u64 = 4 * 1024 * 1024;
/// Byte ceiling for one canonical guest response envelope.
///
/// Equals the native [`MAX_OUTPUT_BYTES`](eliot_memory_curation_screen::MAX_OUTPUT_BYTES)
/// ceiling so native bound errors surface unchanged instead of being
/// pre-empted by the guest.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// Typed guest envelope over exactly the three native A-20 inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the readable WIT world name.
    pub world: String,
    /// Must equal `HANDLER_SUBTYPE`.
    pub handler_subtype: String,
    /// Immutable screen request bound to the source snapshot.
    pub request: CurationScreenRequest,
    /// Immutable finite source snapshot supplied by the canonical owner.
    pub source: SourceSnapshot,
    /// Independently owner-evidenced protection records.
    pub evidence: Vec<ProtectionEvidence>,
}

/// Typed guest response: exactly one of result or error is present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the screen subtype.
    pub handler_subtype: String,
    /// Native screen result on success; `None` on error.
    pub result: Option<CurationScreenResult>,
    /// Exhaustive typed error; `None` on success.
    pub error: Option<GuestError>,
    /// Native A-20 calls made by this invocation (0 or 1).
    pub native_calls: u64,
    /// SHA-256 of the canonical request bytes binding this response.
    pub request_digest: String,
}

/// Closed guest error: one variant per native [`ContractError`] variant plus
/// the native cancellation edge, plus envelope rejections that never reach
/// native.
#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Native `Cancelled`: the caller requested cancellation.
    #[error("screen cancelled before bounded evaluation")]
    Cancelled,
    /// Native `Contract::Blank`.
    #[error("contract blank[{field}]")]
    ContractBlank {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::ControlCharacter`.
    #[error("contract control[{field}]")]
    ContractControl {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::Zero`.
    #[error("contract zero[{field}]")]
    ContractZero {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::Bound`.
    #[error("contract bound[{field}]")]
    ContractBound {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::Duplicate`.
    #[error("contract duplicate[{field}]")]
    ContractDuplicate {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::BindingMismatch`.
    #[error("contract binding[{field}]")]
    ContractBinding {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::ChangedIdentity`.
    #[error("contract changed[{field}]")]
    ContractChanged {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::Unsupported`.
    ///
    /// Continuation cursors, page frontiers, live deadlines and unknown rules
    /// arrive here with their native field intact: the guest preserves the
    /// native outcome (owner #588) instead of implementing paging.
    #[error("contract unsupported[{field}]")]
    ContractUnsupported {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::InvalidDigest`.
    #[error("contract digest[{field}]")]
    ContractDigest {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::Reconciliation`.
    #[error("contract reconciliation[{field}]")]
    ContractReconciliation {
        /// Closed native field name.
        field: String,
    },
    /// Native `Contract::Canonicalization`.
    #[error("contract canonicalization: {detail}")]
    ContractCanonical {
        /// Bounded native reason.
        detail: String,
    },
    /// Envelope rejected before native execution: wrong ABI/subtype/world.
    #[error("rejected envelope: {0}")]
    RejectedEnvelope(String),
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {0}")]
    RejectedBytes(String),
}

impl From<&ContractError> for GuestError {
    fn from(error: &ContractError) -> Self {
        match error {
            ContractError::Blank { field } => Self::ContractBlank {
                field: (*field).to_owned(),
            },
            ContractError::ControlCharacter { field } => Self::ContractControl {
                field: (*field).to_owned(),
            },
            ContractError::Zero { field } => Self::ContractZero {
                field: (*field).to_owned(),
            },
            ContractError::Bound { field } => Self::ContractBound {
                field: (*field).to_owned(),
            },
            ContractError::Duplicate { field } => Self::ContractDuplicate {
                field: (*field).to_owned(),
            },
            ContractError::BindingMismatch { field } => Self::ContractBinding {
                field: (*field).to_owned(),
            },
            ContractError::ChangedIdentity { field } => Self::ContractChanged {
                field: (*field).to_owned(),
            },
            ContractError::Unsupported { field } => Self::ContractUnsupported {
                field: (*field).to_owned(),
            },
            ContractError::InvalidDigest { field } => Self::ContractDigest {
                field: (*field).to_owned(),
            },
            ContractError::Reconciliation { field } => Self::ContractReconciliation {
                field: (*field).to_owned(),
            },
            ContractError::Canonicalization(detail) => Self::ContractCanonical {
                detail: detail.clone(),
            },
        }
    }
}

impl From<&CurationScreenError> for GuestError {
    fn from(error: &CurationScreenError) -> Self {
        match error {
            CurationScreenError::Cancelled => Self::Cancelled,
            CurationScreenError::Contract(error) => Self::from(error),
        }
    }
}

/// Observes native A-20 screen calls for exactly-once proof.
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

/// Read-only WIT projection of one native eligibility status.
///
/// The native `StaleUnavailable` conflates what the readable WIT world splits
/// into `ineligible-stale` / `ineligible-unavailable`, and native
/// `OutsideScope` has no WIT counterpart: the projection uses the documented
/// arms below and the transport still carries the native status verbatim.
/// The accepted spelling stays owned by #756.
#[must_use]
pub const fn eligibility_as_str(status: EligibilityStatus) -> &'static str {
    match status {
        EligibilityStatus::EligibleForSemanticCuration => "eligible-for-semantic-curation",
        EligibilityStatus::Protected => "ineligible-protected",
        EligibilityStatus::Malformed => "ineligible-malformed",
        EligibilityStatus::StaleUnavailable => "ineligible-stale",
        EligibilityStatus::OutsideScope => "ineligible-unavailable",
        EligibilityStatus::IncompleteTruncated => "ineligible-partial",
        EligibilityStatus::UnknownBlocked => "unknown",
    }
}

/// Parses a readable WIT eligibility spelling back to the native status.
#[must_use]
pub fn parse_eligibility(code: &str) -> Option<EligibilityStatus> {
    match code {
        "eligible-for-semantic-curation" => Some(EligibilityStatus::EligibleForSemanticCuration),
        "ineligible-protected" => Some(EligibilityStatus::Protected),
        "ineligible-malformed" => Some(EligibilityStatus::Malformed),
        "ineligible-stale" => Some(EligibilityStatus::StaleUnavailable),
        "ineligible-unavailable" => Some(EligibilityStatus::OutsideScope),
        "ineligible-partial" => Some(EligibilityStatus::IncompleteTruncated),
        "unknown" => Some(EligibilityStatus::UnknownBlocked),
        _ => None,
    }
}

/// Read-only WIT projection of one native protection decision (closed 3↔3).
#[must_use]
pub const fn protection_as_str(decision: ProtectionDecision) -> &'static str {
    match decision {
        ProtectionDecision::Protected => "protected",
        ProtectionDecision::Unprotected => "unprotected",
        ProtectionDecision::Unknown => "protection-unknown",
    }
}

/// Parses a readable WIT protection spelling back to the native decision.
#[must_use]
pub fn parse_protection(code: &str) -> Option<ProtectionDecision> {
    match code {
        "protected" => Some(ProtectionDecision::Protected),
        "unprotected" => Some(ProtectionDecision::Unprotected),
        "protection-unknown" => Some(ProtectionDecision::Unknown),
        _ => None,
    }
}

/// Read-only WIT projection of one native finding class.
///
/// The native screen emits only `ProvenanceGap` and `ConflictAmbiguity`; the
/// remaining native classes have no spelling in the readable WIT world and
/// map to `None` instead of an invented one (owner #756).
#[must_use]
pub const fn finding_class_as_str(class: FindingClass) -> Option<&'static str> {
    match class {
        FindingClass::ProvenanceGap => Some("provenance-gap"),
        FindingClass::ConflictAmbiguity => Some("conflict-ambiguity"),
        FindingClass::Duplicate
        | FindingClass::StaleSuperseded
        | FindingClass::MalformedIncomplete
        | FindingClass::ProtectionGap
        | FindingClass::BoundedOut
        | FindingClass::Unprocessed => None,
    }
}

/// Parses a readable WIT finding-class spelling back to the native class.
#[must_use]
pub fn parse_finding_class(code: &str) -> Option<FindingClass> {
    match code {
        "provenance-gap" => Some(FindingClass::ProvenanceGap),
        "conflict-ambiguity" => Some(FindingClass::ConflictAmbiguity),
        _ => None,
    }
}

/// Read-only WIT projection of one native finding proof.
///
/// The native screen establishes only `Deterministic` proof; the remaining
/// native states have no spelling in the readable WIT world (owner #756).
#[must_use]
pub const fn finding_proof_as_str(proof: FindingProof) -> Option<&'static str> {
    match proof {
        FindingProof::Deterministic => Some("deterministic"),
        FindingProof::Observed | FindingProof::Unknown => None,
    }
}

/// Parses the readable WIT finding-proof spelling back to native proof.
#[must_use]
pub fn parse_finding_proof(code: &str) -> Option<FindingProof> {
    match code {
        "deterministic" => Some(FindingProof::Deterministic),
        _ => None,
    }
}

/// Read-only WIT projection of one native source availability.
///
/// Native `Blocked`, `Malformed` and `Unknown` have no counterpart in the
/// readable WIT world and map to `None` instead of an invented spelling;
/// degraded states still reach native and keep their native outcome.
/// The accepted spelling stays owned by #756.
#[must_use]
pub const fn availability_as_str(availability: SourceAvailability) -> Option<&'static str> {
    match availability {
        SourceAvailability::Available => Some("available"),
        SourceAvailability::Partial => Some("partial"),
        SourceAvailability::Unavailable => Some("unavailable"),
        SourceAvailability::Stale => Some("stale"),
        SourceAvailability::Blocked
        | SourceAvailability::Malformed
        | SourceAvailability::Unknown => None,
    }
}

/// Parses a readable WIT availability spelling back to native availability.
#[must_use]
pub fn parse_availability(code: &str) -> Option<SourceAvailability> {
    match code {
        "available" => Some(SourceAvailability::Available),
        "partial" => Some(SourceAvailability::Partial),
        "unavailable" => Some(SourceAvailability::Unavailable),
        "stale" => Some(SourceAvailability::Stale),
        _ => None,
    }
}

/// Read-only WIT projection of one native result state.
///
/// Native `Blocked` is never projected onto WIT `incomplete`: the guest
/// preserves the native blocked outcome verbatim instead of re-labelling it.
/// The accepted spelling stays owned by #756.
#[must_use]
pub const fn result_state_as_str(state: ResultState) -> Option<&'static str> {
    match state {
        ResultState::Complete => Some("complete"),
        ResultState::Partial => Some("partial"),
        ResultState::Unknown => Some("unknown"),
        ResultState::Blocked => None,
    }
}

/// Parses a readable WIT result-state spelling back to the native state.
#[must_use]
pub fn parse_result_state(code: &str) -> Option<ResultState> {
    match code {
        "complete" => Some(ResultState::Complete),
        "partial" => Some(ResultState::Partial),
        "unknown" => Some(ResultState::Unknown),
        _ => None,
    }
}

/// Guest-local canonical spelling of one native member disposition.
///
/// The readable WIT world defines no disposition type; these spellings are a
/// guest-local parity projection only, never an ABI claim.
#[must_use]
pub const fn disposition_as_str(disposition: MemberDisposition) -> &'static str {
    match disposition {
        MemberDisposition::Eligible => "eligible",
        MemberDisposition::Protected => "protected",
        MemberDisposition::Blocked => "blocked",
        MemberDisposition::PreservedReference => "preserved-reference",
        MemberDisposition::Unprocessed => "unprocessed",
    }
}

/// Parses a guest-local disposition spelling back to the native disposition.
#[must_use]
pub fn parse_disposition(code: &str) -> Option<MemberDisposition> {
    match code {
        "eligible" => Some(MemberDisposition::Eligible),
        "protected" => Some(MemberDisposition::Protected),
        "blocked" => Some(MemberDisposition::Blocked),
        "preserved-reference" => Some(MemberDisposition::PreservedReference),
        "unprocessed" => Some(MemberDisposition::Unprocessed),
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

/// Handles one typed request, calling the native A-20 screen at most once.
///
/// Rejected envelopes return before native execution with `native_calls: 0`.
/// A valid envelope calls [`screen_memory_curation`] exactly once and returns
/// exactly its result with `native_calls: 1` — including the native degraded,
/// blocked, partial, stale, unsupported-continuation and bound outcomes, which
/// are preserved verbatim. Cursor continuation, page frontiers, live
/// deadlines and cancellation grace stay owned by #588: the guest adds no
/// paging, and only the manager may append `cognitive-contract-challenges.toml`
/// (I2.17).
pub fn handle_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let digest = request_digest(request);
    let respond = |result: Option<CurationScreenResult>,
                   error: Option<GuestError>,
                   native_calls: u64| GuestResponse {
        abi_version: request.abi_version,
        handler_subtype: request.handler_subtype.clone(),
        result,
        error,
        native_calls,
        request_digest: digest.clone(),
    };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0);
    }
    let before = ledger.calls();
    ledger.record_call();
    match screen_memory_curation(&request.request, &request.source, &request.evidence) {
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
