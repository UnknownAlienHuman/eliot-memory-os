//! Exhaustive typed conversion between the guest envelope and the native API.
//!
//! Every native transition input field, result field and error variant maps
//! through a closed, explicitly enumerated conversion. There is no wildcard,
//! `Other`, `Value` or whole-payload bridge: the single explicitly canonical
//! leaf is the request/response byte envelope at the `run` boundary, and even
//! that envelope decodes only into the typed [`GuestRequest`]/[`GuestResponse`].

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_cycle::{
    CYCLE_SCHEMA_VERSION, CycleError, CyclePolicy, CycleStep, DreamerCycleState, ObservedOutcome,
    StepDisposition,
    contract::{MAX_RECORDS, MAX_REQUESTS},
    step_dreamer_cycle_at,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{EXPORT_NAME, GUEST_ABI_VERSION, HANDLER_SUBTYPE, WORLD_NAME};

/// Byte ceiling for one canonical guest request envelope.
pub const MAX_GUEST_INPUT_BYTES: u64 = 1_048_576;
/// Byte ceiling for one canonical guest response envelope.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 1_048_576;

/// Typed guest envelope over exactly the native transition inputs: one frozen
/// state, the already-observed owner outcomes, the frozen policy, and the
/// optional injected observation time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the accepted WIT world name.
    pub world: String,
    /// Must equal `HANDLER_SUBTYPE`.
    pub handler_subtype: String,
    /// Frozen controller state consumed by the transition.
    pub state: DreamerCycleState,
    /// Already-observed owner outcomes supplied to the transition.
    pub observed: Vec<ObservedOutcome>,
    /// Frozen policy governing the transition.
    pub policy: CyclePolicy,
    /// Explicitly supplied observation time, if the caller injects one.
    pub observation_time_ms: Option<i64>,
}

/// Typed guest response: exactly one of step or error is present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the handler subtype.
    pub handler_subtype: String,
    /// Native transition candidate on success; `None` on error.
    pub step: Option<CycleStep>,
    /// Exhaustive typed error; `None` on success.
    pub error: Option<GuestError>,
    /// Native transition calls made by this invocation (0 or 1).
    pub native_calls: u64,
}

/// Closed guest error: one variant per native [`CycleError`] variant, plus
/// envelope rejections that never reach native.
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Native `BindingMismatch`.
    #[error("binding mismatch on {field}: {reason}")]
    BindingMismatch {
        /// Binding that failed.
        field: String,
        /// Stable explanation.
        reason: String,
    },
    /// Native `IdentityConflict`.
    #[error("identity conflict for {identity}")]
    IdentityConflict {
        /// Conflicting request, outcome or cycle identity.
        identity: String,
    },
    /// Native `PhaseViolation`.
    #[error("phase transition is invalid: {0}")]
    PhaseViolation(String),
    /// Native `IncompleteOutcome`.
    #[error("outcome is incomplete: {0}")]
    IncompleteOutcome(String),
    /// Native `Bound`.
    #[error("input bound exceeded on {field}: maximum {maximum}")]
    BoundExceeded {
        /// Bounded field.
        field: String,
        /// Inclusive maximum.
        maximum: usize,
    },
    /// Native `BudgetBlocked`.
    #[error("budget or cancellation policy blocked the transition")]
    BudgetBlocked,
    /// Native `Contract`.
    #[error("contract violation: {0}")]
    ContractViolation(String),
    /// Native `Receipt`.
    #[error("receipt violation: {0}")]
    ReceiptViolation(String),
    /// Native `Encoding`.
    #[error("canonical encoding failed: {0}")]
    EncodingFailure(String),
    /// Envelope rejected before native execution: wrong ABI/subtype/world,
    /// unsupported native schema, or an outer collection bound.
    #[error("rejected envelope: {0}")]
    RejectedEnvelope(String),
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {0}")]
    RejectedBytes(String),
}

impl From<&CycleError> for GuestError {
    fn from(error: &CycleError) -> Self {
        match error {
            CycleError::BindingMismatch { field, reason } => Self::BindingMismatch {
                field: (*field).to_owned(),
                reason: (*reason).to_owned(),
            },
            CycleError::IdentityConflict { identity } => Self::IdentityConflict {
                identity: identity.clone(),
            },
            CycleError::PhaseViolation(reason) => Self::PhaseViolation((*reason).to_owned()),
            CycleError::IncompleteOutcome(reason) => Self::IncompleteOutcome((*reason).to_owned()),
            CycleError::Bound { field, maximum } => Self::BoundExceeded {
                field: (*field).to_owned(),
                maximum: *maximum,
            },
            CycleError::BudgetBlocked => Self::BudgetBlocked,
            CycleError::Contract(detail) => Self::ContractViolation(detail.clone()),
            CycleError::Receipt(detail) => Self::ReceiptViolation(detail.clone()),
            CycleError::Encoding(detail) => Self::EncodingFailure(detail.clone()),
        }
    }
}

/// Observes native transition calls for exactly-once proof.
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

/// Canonical wire spelling of every native step disposition (closed set).
#[must_use]
pub const fn disposition_as_str(disposition: StepDisposition) -> &'static str {
    match disposition {
        StepDisposition::Advanced => "advanced",
        StepDisposition::Replayed => "replayed",
        StepDisposition::ReconciliationRequired => "reconciliation_required",
        StepDisposition::Blocked => "blocked",
        StepDisposition::Terminal => "terminal",
    }
}

/// Parses a disposition wire spelling back to the closed enum.
#[must_use]
pub fn parse_disposition(code: &str) -> Option<StepDisposition> {
    match code {
        "advanced" => Some(StepDisposition::Advanced),
        "replayed" => Some(StepDisposition::Replayed),
        "reconciliation_required" => Some(StepDisposition::ReconciliationRequired),
        "blocked" => Some(StepDisposition::Blocked),
        "terminal" => Some(StepDisposition::Terminal),
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
    if request.state.schema_version != CYCLE_SCHEMA_VERSION {
        return Err(GuestError::RejectedEnvelope(
            "state.schema_version".to_owned(),
        ));
    }
    if request.policy.schema_version != CYCLE_SCHEMA_VERSION {
        return Err(GuestError::RejectedEnvelope(
            "policy.schema_version".to_owned(),
        ));
    }
    if request.observed.len() > MAX_RECORDS {
        return Err(GuestError::RejectedEnvelope(
            "observed_external_outcomes".to_owned(),
        ));
    }
    if request.state.pending.len() > MAX_RECORDS
        || request.state.outcomes.len() > MAX_RECORDS
        || request.state.frontier.len() > MAX_RECORDS
    {
        return Err(GuestError::RejectedEnvelope("state.records".to_owned()));
    }
    if request.state.proposed_requests.len() > MAX_REQUESTS {
        return Err(GuestError::RejectedEnvelope(
            "state.proposed_requests".to_owned(),
        ));
    }
    if request.policy.phase_rules.len() > MAX_RECORDS {
        return Err(GuestError::RejectedEnvelope(
            "policy.phase_rules".to_owned(),
        ));
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

/// Handles one typed request, calling the native transition at most once.
///
/// Rejected envelopes return before native execution with `native_calls: 0`.
/// A valid envelope calls [`step_dreamer_cycle_at`] exactly once and returns
/// exactly its semantic result with `native_calls: 1`.
pub fn handle_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let respond =
        |step: Option<CycleStep>, error: Option<GuestError>, native_calls: u64| GuestResponse {
            abi_version: request.abi_version,
            handler_subtype: request.handler_subtype.clone(),
            step,
            error,
            native_calls,
        };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0);
    }
    let before = ledger.calls();
    ledger.record_call();
    match step_dreamer_cycle_at(
        &request.state,
        &request.observed,
        &request.policy,
        request.observation_time_ms,
    ) {
        Ok(step) => respond(Some(step), None, ledger.calls() - before),
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
