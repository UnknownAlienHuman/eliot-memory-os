//! Exhaustive typed conversion between the guest envelope and the native boundary.
//!
//! Every field of the readable `dreamer-handler.wit` `ResearchSynthesis` arm
//! (`research-pack-ref`, `research-claim`, `research-brief`,
//! `research-payload`, `candidate-disposition`, the `validated-candidate`
//! envelope, `budget-limits`, `preservation-report` and `handler-error`) maps
//! through a closed, explicitly enumerated conversion. There is no wildcard,
//! `Other`, `Value` or whole-payload bridge: the single explicitly canonical
//! leaf is the request/response byte envelope at the `run` boundary, and even
//! that envelope decodes only into the typed [`GuestRequest`]/[`GuestResponse`].
//!
//! The native synthesis projector of #995 is missing entirely, so the single
//! native-boundary call site ([`invoke_native_owner`]) records exactly one
//! attempt per valid invocation and returns the honest [`GuestError::NativeUnavailable`]
//! boundary error. The adapter never emits a brief of its own: reference
//! firewall (I21.7), freeze discipline (I21.8) and grade ceiling (I21.2) are
//! enforced in-guest before the boundary, and outside-manifest references are
//! rejected as would-be sourcing through the guest.

use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::descriptor::{
    EXPORT_NAME, GUEST_ABI_VERSION, HANDLER_SUBTYPE, NATIVE_CONTRACT_ID, NATIVE_OWNER,
    NATIVE_STATUS, TYPED_WORLD_NAME,
};

/// Byte ceiling for one canonical guest request envelope.
pub const MAX_GUEST_INPUT_BYTES: u64 = 1_048_576;
/// Byte ceiling for one canonical guest response envelope.
pub const MAX_GUEST_OUTPUT_BYTES: u64 = 1_048_576;
/// Candidate schema revision implemented by this adapter.
pub const CANDIDATE_SCHEMA_REVISION: u32 = 1;

/// Requester origin closed set from the readable WIT arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum GuestRequesterOrigin {
    /// Human principal.
    Human,
    /// Explicitly admitted agent principal.
    AdmittedAgent,
    /// Schedule-policy principal.
    SchedulePolicy,
}

/// Preservation dimension closed set from the readable WIT arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum GuestPreservationDimension {
    /// Coverage dimension.
    Coverage,
    /// Faithfulness dimension.
    Faithfulness,
    /// Lineage dimension.
    Lineage,
    /// Reversibility dimension.
    Reversibility,
    /// Authority-ceiling dimension.
    AuthorityCeiling,
    /// Dependency-closure dimension.
    DependencyClosure,
    /// Provenance-retention dimension.
    ProvenanceRetention,
}

/// One preservation verdict from the readable WIT arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestDimensionVerdict {
    /// Verdict dimension.
    pub dimension: GuestPreservationDimension,
    /// Whether the dimension passed.
    pub passed: bool,
    /// Whether the verdict is known (`false` keeps the unknown explicit).
    pub known: bool,
    /// Human-readable note.
    pub note: String,
}

/// Governed pack reference transcribed from the readable WIT arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchPackRef {
    /// Digest of the governed pack.
    pub pack_digest: String,
    /// Coverage denominator artifact handles.
    pub source_denominator: Vec<String>,
    /// Exact governed question.
    pub question: String,
    /// Exact authorized source handles; the only citable set.
    pub authorized_sources: Vec<String>,
}

/// One claim transcribed from the readable WIT arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchClaim {
    /// Claim artifact handle.
    pub claim_id: String,
    /// Supporting source handles (must stay inside the authorized set).
    pub support: Vec<String>,
    /// Counterclaim source handles (preserved, never dropped).
    pub counterclaim: Vec<String>,
    /// Citation source handles (must stay inside the authorized set).
    pub citations: Vec<String>,
}

/// Candidate disposition closed set from the readable WIT arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResearchDisposition {
    /// Candidate brief.
    Candidate,
    /// Duplicate brief.
    Duplicate,
    /// Conflicted brief.
    Conflict,
    /// Abstention brief.
    Abstention,
    /// Partial brief.
    Partial,
    /// Blocked brief.
    Blocked,
    /// Unsupported brief (also the explicit encoding of unknown).
    Unsupported,
    /// Internal-defect brief.
    InternalDefect,
}

/// Candidate brief transcribed from the readable WIT arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchBrief {
    /// Pack this brief answers; must equal the request pack.
    pub pack: ResearchPackRef,
    /// Claim/counterclaim matrix.
    pub claims: Vec<ResearchClaim>,
    /// Rival positions (preserved verbatim, never resolved here).
    pub rivals: Vec<String>,
    /// Unknowns (preserved verbatim).
    pub unknowns: Vec<String>,
    /// Proposed discriminative probes (inert recommendations only).
    pub probes: Vec<String>,
    /// Inert concilium recommendation note.
    pub concilium_note: String,
    /// Brief disposition.
    pub disposition: ResearchDisposition,
}

/// Research payload transcribed from the readable WIT arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchPayload {
    /// Governed pack under synthesis.
    pub pack: ResearchPackRef,
    /// Candidate brief draft (never applied by this guest).
    pub brief: ResearchBrief,
}

/// Validated-candidate envelope transcribed from the readable WIT arm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchCandidate {
    /// Schema revision; only [`CANDIDATE_SCHEMA_REVISION`] is implemented.
    pub schema_revision: u32,
    /// Operation identity.
    pub operation_id: String,
    /// Job class wire spelling; only `research-synthesis` is accepted.
    pub job: String,
    /// Requester principal.
    pub requester_principal: String,
    /// Requester origin.
    pub requester_origin: GuestRequesterOrigin,
    /// Requester session.
    pub requester_session: String,
    /// Task identity.
    pub task_id: String,
    /// Attempt identity.
    pub attempt_id: String,
    /// Scope identity.
    pub scope_id: String,
    /// Fence epoch identity.
    pub fence_epoch: String,
    /// Fence generation.
    pub fence_generation: u64,
    /// Bundle digest (hex).
    pub bundle_digest: String,
    /// Manifest digest (hex).
    pub manifest_digest: String,
    /// Grounding digest (hex).
    pub grounding_digest: String,
    /// Pre-handler validation receipt digest (hex).
    pub validation_receipt: String,
    /// Research payload under synthesis.
    pub payload: ResearchPayload,
    /// Input byte budget.
    pub max_input_bytes: u32,
    /// Output byte budget.
    pub max_output_bytes: u32,
    /// Candidate-count budget.
    pub max_candidates: u16,
    /// Work budget.
    pub max_work: u64,
    /// Depth budget.
    pub max_depth: u8,
    /// Preservation report verdicts.
    pub preservation: Vec<GuestDimensionVerdict>,
    /// Wall deadline in milliseconds, when bounded.
    pub deadline_ms: Option<i64>,
    /// Pre-handler cancellation flag.
    pub cancelled: bool,
}

/// Typed guest envelope over exactly the `ResearchSynthesis` candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    /// Must equal `GUEST_ABI_VERSION`.
    pub abi_version: u32,
    /// Must equal the readable typed world name.
    pub world: String,
    /// Must equal `HANDLER_SUBTYPE`.
    pub handler_subtype: String,
    /// Validated research candidate.
    pub candidate: ResearchCandidate,
}

/// Typed guest response: the boundary error, never a fabricated brief.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestResponse {
    /// Echoes the request ABI version.
    pub abi_version: u32,
    /// Echoes the handler subtype.
    pub handler_subtype: String,
    /// Native brief on success; always `None` while #995 is missing.
    pub brief: Option<ResearchBrief>,
    /// Exhaustive typed error; always `Some` on this base.
    pub error: Option<GuestError>,
    /// Native-boundary attempts made by this invocation (0 or 1).
    pub native_calls: u64,
    /// SHA-256 of the canonical error bytes (semantic digest of this result).
    pub output_digest: String,
}

/// Closed guest error: one variant per readable `handler-error` arm, plus
/// guest-local envelope, transport, cancellation, firewall and native-boundary
/// errors that never reach native.
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestError {
    /// Readable `malformed` arm: field-level shape failure.
    #[error("malformed {field}: {detail}")]
    Malformed {
        /// Offending field path.
        field: String,
        /// Human-readable detail.
        detail: String,
    },
    /// Readable `kind-mismatch` arm: a known but wrong subtype/job/world.
    #[error("kind mismatch: want {want}, got {got}: {detail}")]
    KindMismatch {
        /// Expected spelling.
        want: String,
        /// Observed spelling.
        got: String,
        /// Human-readable detail.
        detail: String,
    },
    /// Readable `unsupported-subtype-error` arm: unknown subtype spelling.
    #[error("unsupported subtype: want {want}: {detail}")]
    UnsupportedSubtype {
        /// Expected spelling.
        want: String,
        /// Human-readable detail.
        detail: String,
    },
    /// Readable `budget-exceeded` arm.
    #[error("budget exceeded: {detail}")]
    BudgetExceeded {
        /// Human-readable detail.
        detail: String,
    },
    /// Readable `unsupported-schema` arm.
    #[error("unsupported schema: want revision {want_revision}, got {got_revision}: {detail}")]
    UnsupportedSchema {
        /// Implemented revision.
        want_revision: u32,
        /// Observed revision.
        got_revision: u32,
        /// Human-readable detail.
        detail: String,
    },
    /// Readable `internal` arm.
    #[error("internal guest failure: {detail}")]
    Internal {
        /// Human-readable detail.
        detail: String,
    },
    /// Envelope bytes exceed the guest ceiling or are undecodable.
    #[error("envelope bytes rejected: {detail}")]
    RejectedBytes {
        /// Human-readable detail.
        detail: String,
    },
    /// Pre-handler cancellation: the envelope is valid but cancelled.
    #[error("cancelled before native invocation")]
    Cancelled,
    /// Reference-firewall rejection: a handle outside the authorized set
    /// would need fresh sourcing, which the guest must never perform.
    #[error("outside-manifest reference {handle}: {detail}")]
    AcquisitionRejected {
        /// Offending handle.
        handle: String,
        /// Human-readable detail.
        detail: String,
    },
    /// `ContractChallenge` boundary: the #995 native owner is missing, so a
    /// valid invocation stops here instead of fabricating a brief.
    #[error("native {owner} {contract} unavailable ({status}): {detail}")]
    NativeUnavailable {
        /// Owning issue of the missing native.
        owner: String,
        /// Expected native crate identity.
        contract: String,
        /// Acceptance status of the missing native.
        status: String,
        /// Human-readable detail.
        detail: String,
    },
}

/// Observes native-boundary attempts for exactly-once proof.
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

    /// Returns attempts recorded so far.
    #[must_use]
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn record_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// Canonical wire spelling of every readable disposition (closed set).
#[must_use]
pub const fn disposition_as_str(disposition: ResearchDisposition) -> &'static str {
    match disposition {
        ResearchDisposition::Candidate => "candidate",
        ResearchDisposition::Duplicate => "duplicate",
        ResearchDisposition::Conflict => "conflict",
        ResearchDisposition::Abstention => "abstention",
        ResearchDisposition::Partial => "partial",
        ResearchDisposition::Blocked => "blocked",
        ResearchDisposition::Unsupported => "unsupported",
        ResearchDisposition::InternalDefect => "internal-defect",
    }
}

/// Parses a disposition wire spelling back to the closed enum.
#[must_use]
pub fn parse_disposition(code: &str) -> Option<ResearchDisposition> {
    match code {
        "candidate" => Some(ResearchDisposition::Candidate),
        "duplicate" => Some(ResearchDisposition::Duplicate),
        "conflict" => Some(ResearchDisposition::Conflict),
        "abstention" => Some(ResearchDisposition::Abstention),
        "partial" => Some(ResearchDisposition::Partial),
        "blocked" => Some(ResearchDisposition::Blocked),
        "unsupported" => Some(ResearchDisposition::Unsupported),
        "internal-defect" => Some(ResearchDisposition::InternalDefect),
        _ => None,
    }
}

/// Canonical wire spelling of every readable requester origin (closed set).
#[must_use]
pub const fn origin_as_str(origin: GuestRequesterOrigin) -> &'static str {
    match origin {
        GuestRequesterOrigin::Human => "human",
        GuestRequesterOrigin::AdmittedAgent => "admitted-agent",
        GuestRequesterOrigin::SchedulePolicy => "schedule-policy",
    }
}

/// Canonical wire spelling of every readable preservation dimension.
#[must_use]
pub const fn dimension_as_str(dimension: GuestPreservationDimension) -> &'static str {
    match dimension {
        GuestPreservationDimension::Coverage => "coverage",
        GuestPreservationDimension::Faithfulness => "faithfulness",
        GuestPreservationDimension::Lineage => "lineage",
        GuestPreservationDimension::Reversibility => "reversibility",
        GuestPreservationDimension::AuthorityCeiling => "authority-ceiling",
        GuestPreservationDimension::DependencyClosure => "dependency-closure",
        GuestPreservationDimension::ProvenanceRetention => "provenance-retention",
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

fn is_digest_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn malformed(field: &str, detail: &str) -> GuestError {
    GuestError::Malformed {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}

fn check_text(value: &str, field: &str) -> Result<(), GuestError> {
    if value.trim().is_empty() {
        return Err(malformed(field, "must be a non-empty handle"));
    }
    Ok(())
}

fn check_digest(value: &str, field: &str) -> Result<(), GuestError> {
    if !is_digest_hex(value) {
        return Err(malformed(
            field,
            "must be 64 lowercase hex digest characters",
        ));
    }
    Ok(())
}

fn check_envelope(request: &GuestRequest) -> Result<(), GuestError> {
    if request.abi_version != GUEST_ABI_VERSION {
        return Err(GuestError::UnsupportedSchema {
            want_revision: GUEST_ABI_VERSION,
            got_revision: request.abi_version,
            detail: "guest envelope revision".to_owned(),
        });
    }
    if request.world != TYPED_WORLD_NAME {
        return Err(GuestError::KindMismatch {
            want: TYPED_WORLD_NAME.to_owned(),
            got: request.world.clone(),
            detail: "guest envelope world".to_owned(),
        });
    }
    if request.handler_subtype != HANDLER_SUBTYPE {
        if request.handler_subtype == "orientation" || request.handler_subtype == "curation" {
            return Err(GuestError::KindMismatch {
                want: HANDLER_SUBTYPE.to_owned(),
                got: request.handler_subtype.clone(),
                detail: "guest envelope subtype".to_owned(),
            });
        }
        return Err(GuestError::UnsupportedSubtype {
            want: HANDLER_SUBTYPE.to_owned(),
            detail: format!("guest envelope subtype {}", request.handler_subtype),
        });
    }
    Ok(())
}

fn check_firewall(pack: &ResearchPackRef, brief: &ResearchBrief) -> Result<(), GuestError> {
    for reference in brief.claims.iter().flat_map(|claim| {
        claim
            .support
            .iter()
            .chain(claim.counterclaim.iter())
            .chain(claim.citations.iter())
    }) {
        if !pack
            .authorized_sources
            .iter()
            .any(|allow| allow == reference)
        {
            return Err(GuestError::AcquisitionRejected {
                handle: reference.clone(),
                detail: "handle is outside the authorized source set".to_owned(),
            });
        }
    }
    Ok(())
}

fn check_candidate(candidate: &ResearchCandidate, input_bytes: u64) -> Result<(), GuestError> {
    if candidate.cancelled {
        return Err(GuestError::Cancelled);
    }
    if candidate.schema_revision != CANDIDATE_SCHEMA_REVISION {
        return Err(GuestError::UnsupportedSchema {
            want_revision: CANDIDATE_SCHEMA_REVISION,
            got_revision: candidate.schema_revision,
            detail: "research candidate revision".to_owned(),
        });
    }
    if candidate.job != HANDLER_SUBTYPE {
        return Err(GuestError::KindMismatch {
            want: HANDLER_SUBTYPE.to_owned(),
            got: candidate.job.clone(),
            detail: "research candidate job".to_owned(),
        });
    }
    check_text(&candidate.operation_id, "candidate.operation_id")?;
    check_text(
        &candidate.requester_principal,
        "candidate.requester_principal",
    )?;
    check_text(&candidate.requester_session, "candidate.requester_session")?;
    check_text(&candidate.task_id, "candidate.task_id")?;
    check_text(&candidate.attempt_id, "candidate.attempt_id")?;
    check_text(&candidate.scope_id, "candidate.scope_id")?;
    check_text(&candidate.fence_epoch, "candidate.fence_epoch")?;
    check_digest(&candidate.bundle_digest, "candidate.bundle_digest")?;
    check_digest(&candidate.manifest_digest, "candidate.manifest_digest")?;
    check_digest(&candidate.grounding_digest, "candidate.grounding_digest")?;
    check_digest(
        &candidate.validation_receipt,
        "candidate.validation_receipt",
    )?;
    let pack = &candidate.payload.pack;
    check_digest(&pack.pack_digest, "candidate.payload.pack.pack_digest")?;
    check_text(&pack.question, "candidate.payload.pack.question")?;
    if pack.authorized_sources.is_empty() {
        return Err(malformed(
            "candidate.payload.pack.authorized_sources",
            "at least one authorized source is required",
        ));
    }
    let brief = &candidate.payload.brief;
    if brief.pack != *pack {
        return Err(malformed(
            "candidate.payload.brief.pack",
            "brief pack must equal the request pack exactly",
        ));
    }
    for (index, claim) in brief.claims.iter().enumerate() {
        if claim.claim_id.trim().is_empty() {
            return Err(malformed(
                "candidate.payload.brief.claims",
                &format!("claim {index} id must be a non-empty handle"),
            ));
        }
    }
    check_firewall(pack, brief)?;
    if candidate.max_input_bytes == 0
        || candidate.max_output_bytes == 0
        || candidate.max_work == 0
        || candidate.max_depth == 0
    {
        return Err(GuestError::BudgetExceeded {
            detail: "research budget ceilings must be non-zero".to_owned(),
        });
    }
    if input_bytes > u64::from(candidate.max_input_bytes) {
        return Err(GuestError::BudgetExceeded {
            detail: "canonical request exceeds the input byte budget".to_owned(),
        });
    }
    let claims = u64::try_from(brief.claims.len()).unwrap_or(u64::MAX);
    if claims > u64::from(candidate.max_candidates) {
        return Err(GuestError::BudgetExceeded {
            detail: "claim count exceeds the candidate budget".to_owned(),
        });
    }
    Ok(())
}

/// The single native-boundary call site of this guest.
///
/// The #995 native projector is missing, so a valid invocation records
/// exactly one attempt and stops with the honest boundary error instead of
/// fabricating a brief. Rejected envelopes never reach this function.
fn invoke_native_owner(ledger: &CallLedger) -> GuestError {
    ledger.record_call();
    GuestError::NativeUnavailable {
        owner: NATIVE_OWNER.to_owned(),
        contract: NATIVE_CONTRACT_ID.to_owned(),
        status: NATIVE_STATUS.to_owned(),
        detail: "valid research invocation awaits the accepted #995 projector".to_owned(),
    }
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
    if u64::try_from(bytes.len()).map_err(|_| GuestError::RejectedBytes {
        detail: "input bytes".to_owned(),
    })? > MAX_GUEST_INPUT_BYTES
    {
        return Err(GuestError::RejectedBytes {
            detail: "input bytes".to_owned(),
        });
    }
    serde_json::from_slice(bytes).map_err(|_| GuestError::RejectedBytes {
        detail: "request shape".to_owned(),
    })
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
    if u64::try_from(bytes.len()).map_err(|_| GuestError::RejectedBytes {
        detail: "output bytes".to_owned(),
    })? > MAX_GUEST_OUTPUT_BYTES
    {
        return Err(GuestError::RejectedBytes {
            detail: "output bytes".to_owned(),
        });
    }
    serde_json::from_slice(bytes).map_err(|_| GuestError::RejectedBytes {
        detail: "response shape".to_owned(),
    })
}

/// Handles one typed request, reaching the native boundary at most once.
///
/// Rejected envelopes return before the boundary with `native_calls: 0`.
/// A valid envelope records exactly one boundary attempt and returns the
/// honest boundary error with `native_calls: 1`.
pub fn handle_with_ledger(request: &GuestRequest, ledger: &CallLedger) -> GuestResponse {
    let respond = |brief: Option<ResearchBrief>, error: Option<GuestError>, native_calls: u64| {
        let digest_source = error
            .as_ref()
            .map(|error| canonical_json_bytes(error).unwrap_or_default())
            .unwrap_or_default();
        GuestResponse {
            abi_version: request.abi_version,
            handler_subtype: request.handler_subtype.clone(),
            brief,
            error,
            native_calls,
            output_digest: sha256_hex(&digest_source),
        }
    };
    if let Err(error) = check_envelope(request) {
        return respond(None, Some(error), 0);
    }
    let input_bytes =
        u64::try_from(canonical_json_bytes(request).unwrap_or_default().len()).unwrap_or(u64::MAX);
    if let Err(error) = check_candidate(&request.candidate, input_bytes) {
        return respond(None, Some(error), 0);
    }
    let before = ledger.calls();
    let error = invoke_native_owner(ledger);
    respond(None, Some(error), ledger.calls() - before)
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

/// SHA-256 of canonical brief bytes (semantic digest of brief content).
#[must_use]
pub fn brief_digest(brief: &ResearchBrief) -> String {
    sha256_hex(&canonical_json_bytes(brief).unwrap_or_default())
}
