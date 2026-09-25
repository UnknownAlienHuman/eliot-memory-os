//! Pure request validation, normalization, forwarding, and response bounding.

use std::collections::BTreeSet;

use eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
use eliot_receipts::{ArtifactBinding, ProofCeiling, SessionBinding};
use eliot_source_assurance::{
    AdmissionOutcome, AssuranceFinding, OwnerSourceEvidence, SourceAssurance, SourceAssuranceError,
    canonical_digest,
};
use eliot_types::RecallDisposition;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ApplicationRequest, ContractViolation, LEGACY_FINISH_INPUT_REJECTED, McpProtocolVersion,
    QueryInput, QueryIntent, QueryMode, ToolRequest, TypedRejection, decode_protected_request_bytes,
    validate_proof_ceiling,
};

/// Default and optional local transport profiles. This is validation only.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportProfile {
    /// Default near-stateless stdio shim.
    #[default]
    Stdio,
    /// Optional loopback-only Streamable HTTP profile.
    LoopbackHttp(LoopbackProfile),
}

impl TransportProfile {
    /// Validates the bounded profile without opening a socket.
    pub fn validate(&self) -> Result<(), BridgeError> {
        match self {
            Self::Stdio => Ok(()),
            Self::LoopbackHttp(profile) => profile.validate(),
        }
    }
}

/// Untrusted per-request transport facts presented to the injected resolver.
///
/// These values never become authority by themselves. Both stdio and loopback
/// calls must carry them, and the trusted port must resolve them to a current
/// [`ActiveSessionBinding`] before semantic dispatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRequestContext {
    /// Validated local transport profile.
    pub profile: TransportProfile,
    /// Identity of this concrete transport connection.
    pub connection_id: String,
    /// Opaque reference to a scoped short-lived local credential.
    pub scoped_credential_ref: String,
    /// Exact live transport generation.
    pub transport_generation: u64,
}

impl TransportRequestContext {
    fn validate(&self) -> Result<(), BridgeError> {
        self.profile.validate()?;
        if self.connection_id.trim().is_empty() {
            return Err(BridgeError::invalid(
                "transport.connection_id",
                "must be non-blank",
            ));
        }
        if self.scoped_credential_ref.trim().is_empty() {
            return Err(BridgeError::invalid(
                "transport.scoped_credential_ref",
                "must be non-blank",
            ));
        }
        if self.transport_generation == 0 {
            return Err(BridgeError::invalid(
                "transport.transport_generation",
                "must be greater than zero",
            ));
        }
        if let TransportProfile::LoopbackHttp(profile) = &self.profile
            && profile.credential_ref != self.scoped_credential_ref
        {
            return Err(BridgeError::invalid(
                "transport.scoped_credential_ref",
                "must exactly match the loopback profile credential reference",
            ));
        }
        Ok(())
    }
}

/// Loopback-only HTTP validation inputs. Credentials are opaque references.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopbackProfile {
    /// Exact bind literal: `127.0.0.1` or `::1`.
    pub bind_address: String,
    /// Exact validated HTTP Host, including the selected port.
    pub host: String,
    /// Browser Origin, when browser-originated access is admitted.
    pub browser_origin: Option<String>,
    /// Reference to a scoped short-lived local credential, never raw secret data.
    pub credential_ref: String,
}

impl LoopbackProfile {
    fn validate(&self) -> Result<(), BridgeError> {
        if self.bind_address != "127.0.0.1" && self.bind_address != "::1" {
            return Err(BridgeError::invalid(
                "transport.bind_address",
                "must be the literal 127.0.0.1 or ::1",
            ));
        }
        let port = if self.bind_address == "::1" {
            self.host.strip_prefix("[::1]:")
        } else {
            self.host.strip_prefix("127.0.0.1:")
        };
        if !port.is_some_and(valid_port) {
            return Err(BridgeError::invalid(
                "transport.host",
                "must use the exact loopback literal and an explicit nonzero port",
            ));
        }
        if self.credential_ref.trim().is_empty() {
            return Err(BridgeError::invalid(
                "transport.credential_ref",
                "must reference a scoped local credential",
            ));
        }
        if let Some(origin) = &self.browser_origin {
            let expected = format!("http://{}", self.host);
            if origin != &expected {
                return Err(BridgeError::invalid(
                    "transport.browser_origin",
                    "must exactly match the admitted loopback Host",
                ));
            }
        }
        Ok(())
    }
}

fn valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok_and(|value| value > 0)
}

/// Initialize input. It intentionally contains no ELIOT session/task/authority fields.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeRequest {
    /// Requested MCP profile.
    pub protocol_version: McpProtocolVersion,
    /// Presentation-only capability advertisement.
    #[serde(default)]
    pub capabilities: crate::ClientCapabilities,
}

/// Initialize projection. It creates no application identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeResponse {
    /// Selected supported profile.
    pub protocol_version: McpProtocolVersion,
    /// Exact canonical tool count.
    pub canonical_tool_count: usize,
    /// Hard encoded structured-response limit.
    pub structured_response_limit_bytes: usize,
    /// Explicit statement that initialize did not create application identity.
    pub application_binding_created: bool,
}

/// Immutable forwarded request passed to the injected semantic owner.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedRequest {
    /// Validated request in its canonical tool form.
    pub request: ApplicationRequest,
    /// SHA-256 over canonical serialized request bytes, including identity.
    pub canonical_request_sha256: String,
    /// Trusted current operational binding resolved for this exact request.
    pub active_session_binding: ActiveSessionBinding,
    /// Owner-authenticated source evidence required by every semantic handoff.
    pub source_assurance: ForwardedSourceAssurance,
}

/// Immutable source-assurance envelope attached immediately before semantic
/// dispatch. Its owner identity is checked against the active binding.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedSourceAssurance {
    pub owner_principal_ref: String,
    pub evidence_ref: String,
    pub request_id: String,
    /// Exact typed request identity.
    pub original_request_sha256: String,
    pub idempotency_key: String,
    pub cancellation_id: String,
    pub session_id: String,
    pub state_fence_digest: String,
    pub canonical_request_sha256: String,
    pub verifier_ref: Option<String>,
    pub assurance: SourceAssurance,
    pub policy: eliot_source_assurance::SourceAssurancePolicy,
    pub assurance_digest: String,
}

/// Request sent to the trusted operational-binding resolver.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingResolutionRequest {
    /// Untrusted local transport facts to authenticate and resolve.
    pub transport: TransportRequestContext,
    /// Caller-claimed application Session to match, never to trust directly.
    pub claimed_session: SessionBinding,
    /// Exact request identity.
    pub request_id: String,
    pub original_request_sha256: String,
    /// Exact retry identity.
    pub idempotency_key: String,
    /// Exact cancellation identity.
    pub cancellation_id: String,
    /// Exact canonical request digest.
    pub canonical_request_sha256: String,
    /// Absolute request deadline.
    pub deadline_unix_ms: u64,
}

/// Kernel-owned operational Session binding for one exact request.
///
/// It is evidence returned by the injected trusted port. It is not accepted as
/// public tool input and it owns no durable Session or authority state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveSessionBinding {
    /// Opaque live binding identity assigned by the resolver.
    pub binding_id: String,
    /// Authenticated local principal identity.
    pub principal_ref: String,
    /// Resolved durable application Session, authority epoch, and State Fence.
    pub session: SessionBinding,
    /// Resolved connection, credential, profile, and transport generation.
    pub transport: TransportRequestContext,
    /// Exact request correlation.
    pub request_id: String,
    /// Exact idempotency correlation.
    pub idempotency_key: String,
    /// Exact cancellation correlation.
    pub cancellation_id: String,
    /// Exact request-byte correlation.
    pub canonical_request_sha256: String,
    /// Resolver observation time in Unix milliseconds.
    pub resolved_at_unix_ms: u64,
    /// Expiry of this scoped operational binding in Unix milliseconds.
    pub valid_until_unix_ms: u64,
}

/// Kernel/Governor semantic port. The MCP crate provides no implementation state.
pub trait KernelGovernorPort {
    /// Authenticate transport facts and resolve a current operational binding.
    fn resolve_active_session(
        &self,
        request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure>;

    /// Resolve owner-authenticated source evidence for this exact binding.
    /// The safe default is an explicit plan gap; callers cannot receive a
    /// synthesized trusted envelope.
    fn resolve_source_assurance(
        &self,
        _request: &BindingResolutionRequest,
        _binding: &ActiveSessionBinding,
    ) -> Result<OwnerSourceEvidence, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: "source-assurance-owner-evidence".to_owned(),
            reason: "owner-authenticated source evidence is not injected".to_owned(),
        })
    }

    /// Evaluate one validated and explicitly bound request.
    fn dispatch(&self, request: &ForwardedRequest) -> Result<PortProjection, PortFailure>;
}

/// Maximum exact evidence-pack record count accepted by this surface.
pub const EVIDENCE_PACK_MAX_RECORDS: u32 = eliot_store_api::EVIDENCE_PACK_MAX_RECORDS;

/// Version of the opaque Store evidence-pack payload consumed by this surface.
///
/// The Store keeps candidate captures opaque; this is the existing payload
/// shape and does not carry semantic admission or disposition.
pub const EVIDENCE_PACK_PROJECTION_VERSION: u32 = 1;

/// Closed T11.1 evidence-pack query plan derived from an explicit-intent
/// `eliot.query`.
///
/// This is the pure planning half of the `KernelGovernorPort::dispatch` seam
/// for `ToolRequest::Query`: it maps a validated `QueryInput` with explicit
/// read intent into the Store catalogue's closed selectors
/// (`subject`/`max_records` for `GetEvidencePack`) without importing Store
/// operation/request types. The Store catalogue remains the authority; its
/// shared payload-version constant is used only to validate the returned
/// evidence pack. Free-text `query` is intent data, never a selector: T11.1
/// requires the exact form `subject:<exact-subject>`; anything else fails
/// closed instead of becoming a substring search or a forwarded `query`
/// parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidencePackQueryPlan {
    /// Exact captured-observation subject (never a substring, never blank).
    pub subject: String,
    /// Explicit `max_records` bound carried as its decimal string.
    pub max_records: String,
    /// Exact scope the read is bound to.
    pub scope_id: String,
}

impl EvidencePackQueryPlan {
    /// Closed operation name this plan executes.
    #[must_use]
    pub const fn operation_name() -> &'static str {
        "GetEvidencePack"
    }
}

/// Plans one closed `GetEvidencePack` read from an explicit-intent query.
///
/// `scope_id` comes from the trusted active session binding (never from MCP
/// arguments alone) and `max_records` is the caller's explicit decimal bound;
/// the store enforces the catalogue `EVIDENCE_PACK_MAX_RECORDS` cap. Fails
/// closed when the intent is `CurrentPosition` (which never admits
/// `GetEvidencePack`), when `exact_resource_uri` is present (exact expansion
/// uses the resource path, not a query), or when `query` is not the exact
/// `subject:<exact-subject>` selector form.
pub fn plan_evidence_pack_query(
    input: &QueryInput,
    scope_id: &str,
    max_records: &str,
) -> Result<EvidencePackQueryPlan, BridgeError> {
    if matches!(input.intent.mode, QueryMode::CurrentPosition) {
        return Err(BridgeError::Port(PortFailure::Unsupported {
            capability: "GetEvidencePack".to_owned(),
            reason: "CurrentPosition intent never admits GetEvidencePack".to_owned(),
        }));
    }
    if input.exact_resource_uri.is_some() {
        return Err(BridgeError::invalid(
            "query.exact_resource_uri",
            "exact resource expansion uses the resource path, not eliot.query",
        ));
    }
    if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            "query.scope_id",
            "must be non-blank and contain no control characters",
        ));
    }
    if max_records.trim().is_empty() || max_records.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            "query.max_records",
            "must be a non-blank decimal bound",
        ));
    }
    let bound: u32 = max_records.trim().parse().map_err(|_| {
        BridgeError::invalid("query.max_records", "must be a positive decimal bound")
    })?;
    if bound == 0 {
        return Err(BridgeError::invalid(
            "query.max_records",
            "must be a positive decimal bound",
        ));
    }
    let subject = input
        .query
        .strip_prefix("subject:")
        .map(str::trim)
        .filter(|subject| !subject.is_empty() && !subject.chars().any(char::is_control))
        .ok_or_else(|| {
            BridgeError::invalid(
                "query.query",
                "T11.1 requires the exact form `subject:<exact-subject>`; free-text search is not an exact selector",
            )
        })?;
    Ok(EvidencePackQueryPlan {
        subject: subject.to_owned(),
        max_records: max_records.trim().to_owned(),
        scope_id: scope_id.trim().to_owned(),
    })
}

/// Projects a successful evidence-pack payload into a bounded `Projection`.
///
/// Kind is always `Projection` (read-only owner state, never a candidate);
/// proof ceiling is `ScopedVerification` (the strongest ceiling MCP
/// projections may claim); no `CurrentPosition` claim is expressed. The exact
/// Store payload crosses unchanged under `evidence_pack` with its
/// subject/scope identity. The response owner derives the typed disposition
/// from the available observations; this function never reads admission meaning
/// from the opaque Store payload.
#[allow(
    clippy::needless_pass_by_value,
    reason = "payload moves into the JSON projection; clippy cannot see through json!"
)]
pub fn project_evidence_pack_projection(
    plan: &EvidencePackQueryPlan,
    payload: Value,
) -> Result<PortProjection, BridgeError> {
    let content = json!({
        "operation": EvidencePackQueryPlan::operation_name(),
        "subject": plan.subject,
        "scope_id": plan.scope_id,
        "evidence_pack": payload,
    });
    let expected_max_records = plan.max_records.parse::<u64>().map_err(|_| {
        BridgeError::Serialization("evidence-pack plan has an invalid max_records bound".to_owned())
    })?;
    let projected_max_records = content
        .pointer("/evidence_pack/provenance/max_records")
        .and_then(Value::as_u64);
    if projected_max_records != Some(expected_max_records) {
        return Err(BridgeError::Serialization(
            "evidence_pack max_records does not match the admitted query".to_owned(),
        ));
    }
    let recall_disposition = parse_projected_recall_disposition("eliot.query", &content)?;
    Ok(PortProjection {
        kind: ProjectionKind::Projection,
        content,
        recall_disposition,
        artifacts: Vec::new(),
        proof_ceiling: ProofCeiling::ScopedVerification,
        resource: None,
        durable_job: None,
    })
}

fn validate_projected_evidence_records(
    records: &[Value],
    expected_subject: &str,
) -> Result<(), BridgeError> {
    let malformed = |reason: &str| BridgeError::Serialization(reason.to_owned());
    let mut capture_indices = BTreeSet::new();
    for record in records {
        let record = record
            .as_object()
            .ok_or_else(|| malformed("evidence_pack records must contain canonical objects"))?;
        let Some(capture_index) = record.get("capture_index").and_then(Value::as_u64) else {
            return Err(malformed("evidence_pack record is missing capture_index"));
        };
        if !capture_indices.insert(capture_index) {
            return Err(malformed("evidence_pack capture indices must be unique"));
        }
        if record.get("operation").and_then(Value::as_str) != Some("CaptureObservation")
            || record
                .get("parameters")
                .and_then(Value::as_object)
                .is_none()
            || record
                .get("parameters")
                .and_then(|parameters| parameters.get("subject"))
                .and_then(Value::as_str)
                != Some(expected_subject)
        {
            return Err(malformed(
                "evidence_pack record does not match the admitted exact subject",
            ));
        }
    }
    Ok(())
}

/// Parses and validates the response-owned disposition on an MCP projection.
///
/// The Store payload remains an opaque version-1 candidate-capture pack. This
/// function validates that shape and derives the P1 result from what the
/// response owner actually observed. Candidate count is not admission evidence,
/// so the only honest result on this route is `INCOMPLETE_COVERAGE`.
pub fn parse_projected_recall_disposition(
    canonical_tool_name: &str,
    content: &Value,
) -> Result<Option<RecallDisposition>, BridgeError> {
    let malformed = |reason: &str| BridgeError::Serialization(reason.to_owned());
    let operation = content.get("operation").and_then(Value::as_str);
    let Some(evidence_pack) = content.get("evidence_pack") else {
        if operation == Some("GetEvidencePack") {
            return Err(malformed(
                "GetEvidencePack projection is missing its evidence_pack payload",
            ));
        }
        return Ok(None);
    };

    if canonical_tool_name != "eliot.query" {
        return Err(malformed(
            "only eliot.query may expose an evidence_pack projection",
        ));
    }
    if operation != Some("GetEvidencePack") {
        return Err(malformed(
            "evidence_pack projection must use the GetEvidencePack operation",
        ));
    }
    let subject = content
        .get("subject")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("evidence_pack projection is missing subject"))?;
    let scope_id = content
        .get("scope_id")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("evidence_pack projection is missing scope_id"))?;
    if subject.trim().is_empty()
        || subject.chars().any(char::is_control)
        || scope_id.trim().is_empty()
        || scope_id.chars().any(char::is_control)
    {
        return Err(malformed(
            "evidence_pack projection identity must be exact and non-blank",
        ));
    }

    let pack = evidence_pack
        .as_object()
        .ok_or_else(|| malformed("evidence_pack must be an object"))?;
    if pack.get("version").and_then(Value::as_u64)
        != Some(u64::from(EVIDENCE_PACK_PROJECTION_VERSION))
    {
        return Err(malformed("evidence_pack version is unsupported"));
    }
    if pack.get("subject").and_then(Value::as_str) != Some(subject)
        || pack.get("scope_id").and_then(Value::as_str) != Some(scope_id)
    {
        return Err(malformed(
            "evidence_pack identity does not match the admitted query",
        ));
    }
    let records = pack
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("evidence_pack records must be an array"))?;
    validate_projected_evidence_records(records, subject)?;
    let provenance = pack
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("evidence_pack provenance must be an object"))?;
    validate_projected_state_fence(evidence_pack)?;
    let matched_total = provenance
        .get("matched_total")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("evidence_pack matched_total must be unsigned"))?;
    let returned_u64 = provenance
        .get("returned")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("evidence_pack returned must be unsigned"))?;
    let max_records = provenance
        .get("max_records")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("evidence_pack max_records must be unsigned"))?;
    let truncated = provenance
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed("evidence_pack truncated must be boolean"))?;
    let returned = usize::try_from(returned_u64)
        .map_err(|_| malformed("evidence_pack returned count exceeds usize"))?;
    if max_records == 0
        || max_records > u64::from(EVIDENCE_PACK_MAX_RECORDS)
        || returned_u64 != matched_total.min(max_records)
        || records.len() != returned
        || truncated != (matched_total > max_records)
    {
        return Err(malformed(
            "evidence_pack record and provenance counts are inconsistent",
        ));
    }
    // Do not read a disposition from the Store payload, even if an older or
    // substituted producer added one. The response owner has no admission,
    // corpus, score, conflict, or selected-tier observation on this route.
    Ok(Some(RecallDisposition::IncompleteCoverage))
}

fn validate_projected_state_fence(evidence_pack: &Value) -> Result<(), BridgeError> {
    let value = evidence_pack
        .pointer("/provenance/state_fence")
        .cloned()
        .ok_or_else(|| {
            BridgeError::Serialization(
                "evidence_pack provenance is missing its State Fence".to_owned(),
            )
        })?;
    let fence: eliot_store_api::StateFence = serde_json::from_value(value).map_err(|error| {
        BridgeError::Serialization(format!("evidence_pack State Fence is invalid: {error}"))
    })?;
    fence.validate().map_err(|error| {
        BridgeError::Serialization(format!("evidence_pack State Fence is invalid: {error}"))
    })?;
    Ok(())
}

fn validate_projected_revision_heads(
    content: &Value,
    expected_scope_id: &str,
    expected_fence: &eliot_store_api::StateFence,
) -> Result<(), BridgeError> {
    let heads = content
        .get("revision_heads")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            BridgeError::Serialization(
                "evidence-pack response is missing its revision heads".to_owned(),
            )
        })?;
    let scope_key = format!("scope:{expected_scope_id}");
    let mut keys = BTreeSet::new();
    let mut scope_heads = 0usize;
    for value in heads {
        let head: eliot_store_api::RevisionHead =
            serde_json::from_value(value.clone()).map_err(|error| {
                BridgeError::Serialization(format!(
                    "evidence-pack revision head is invalid: {error}"
                ))
            })?;
        head.validate().map_err(|error| {
            BridgeError::Serialization(format!("evidence-pack revision head is invalid: {error}"))
        })?;
        if !keys.insert(head.key.as_str().to_owned()) {
            return Err(BridgeError::Serialization(
                "evidence-pack revision heads must have unique keys".to_owned(),
            ));
        }
        if head.key.as_str() == scope_key {
            scope_heads += 1;
            if head.state_fence != *expected_fence {
                return Err(BridgeError::Serialization(
                    "evidence-pack scope revision head State Fence does not match the request"
                        .to_owned(),
                ));
            }
        }
    }
    if scope_heads != 1 {
        return Err(BridgeError::Serialization(
            "evidence-pack response must carry exactly one admitted scope revision head".to_owned(),
        ));
    }
    Ok(())
}

/// Classifies a typed negative response for downstream rejection mapping.
///
/// Candidate and projection responses are positive answers. Plan-gap and
/// unsupported responses preserve their typed owner failure instead of being
/// surfaced as successful responses.
pub fn classify_response_failure(
    response: &McpResponse,
) -> Result<Option<PortFailure>, BridgeError> {
    let text = |field: &str| {
        response
            .content
            .as_object()
            .and_then(|object| object.get(field))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
            .map(str::to_owned)
            .ok_or_else(|| BridgeError::Serialization(format!("typed response is missing {field}")))
    };
    match response.kind {
        ResponseKind::Candidate | ResponseKind::Projection => Ok(None),
        ResponseKind::PlanGap => {
            if response.recall_disposition.is_some() {
                return Err(BridgeError::Serialization(
                    "plan-gap response must not carry a recall disposition".to_owned(),
                ));
            }
            let content = response.content.as_object().ok_or_else(|| {
                BridgeError::Serialization("plan-gap response content must be an object".to_owned())
            })?;
            if content.get("code").and_then(Value::as_str) != Some("PLAN_GAP") {
                return Err(BridgeError::Serialization(
                    "plan-gap response code does not match its kind".to_owned(),
                ));
            }
            Ok(Some(PortFailure::PlanGap {
                missing_capability: text("missing_capability")?,
                reason: text("reason")?,
            }))
        }
        ResponseKind::Unsupported => {
            if response.recall_disposition.is_some() {
                return Err(BridgeError::Serialization(
                    "unsupported response must not carry a recall disposition".to_owned(),
                ));
            }
            let content = response.content.as_object().ok_or_else(|| {
                BridgeError::Serialization(
                    "unsupported response content must be an object".to_owned(),
                )
            })?;
            if content.get("code").and_then(Value::as_str) != Some("UNSUPPORTED") {
                return Err(BridgeError::Serialization(
                    "unsupported response code does not match its kind".to_owned(),
                ));
            }
            Ok(Some(PortFailure::Unsupported {
                capability: text("capability")?,
                reason: text("reason")?,
            }))
        }
    }
}

/// Exact request facts that an evidence-pack response must bind at a response
/// owner or an untrusted replay boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidencePackResponseExpectation {
    /// Exact response request identity.
    pub request_id: String,
    /// Exact response idempotency identity.
    pub idempotency_key: String,
    /// Digest defined by the response owner for the admitted request. For a
    /// local-read envelope this is the envelope/request/idempotency tuple;
    /// direct MCP requests use their separate application-request hash.
    pub canonical_request_sha256: String,
    /// Exact subject selector admitted by the request.
    pub subject: String,
    /// Exact trusted scope admitted by the request.
    pub scope_id: String,
    /// Exact bounded record count admitted by the request.
    pub max_records: u64,
    /// Canonical State Fence expected in the evidence-pack provenance.
    pub state_fence: Value,
}

/// Returns whether a tool is the exact subject evidence query that must carry
/// a disposition and an evidence-pack projection.
#[must_use]
pub fn requires_evidence_pack_response(tool: &ToolRequest) -> bool {
    let ToolRequest::Query(input) = tool else {
        return false;
    };
    if input.exact_resource_uri.is_some() || matches!(input.intent.mode, QueryMode::CurrentPosition)
    {
        return false;
    }
    input
        .query
        .strip_prefix("subject:")
        .map(str::trim)
        .is_some_and(|subject| !subject.is_empty() && !subject.chars().any(char::is_control))
}

fn validate_projection_content_for_tool(
    tool: &ToolRequest,
    content: &Value,
    disposition: Option<RecallDisposition>,
) -> Result<(), BridgeError> {
    let parsed = parse_projected_recall_disposition(tool.canonical_name(), content)?;
    if requires_evidence_pack_response(tool) {
        let subject = tool.query_subject().ok_or_else(|| {
            BridgeError::Serialization("exact evidence subject is missing".to_owned())
        })?;
        if content.get("subject").and_then(Value::as_str) != Some(subject) {
            return Err(BridgeError::Serialization(
                "evidence-pack subject does not match the admitted query".to_owned(),
            ));
        }
        if parsed.is_none() {
            return Err(BridgeError::Serialization(
                "exact eliot.query response is missing its evidence pack".to_owned(),
            ));
        }
    } else if parsed.is_some() {
        return Err(BridgeError::Serialization(
            "unrelated query response must not expose an evidence pack".to_owned(),
        ));
    }
    if parsed != disposition {
        return Err(BridgeError::Serialization(
            "response recall_disposition does not match the response-owner evidence projection"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Validates a decoded MCP response against the exact tool request before a
/// gateway or bridge replays it.
pub fn validate_mcp_response_for_tool(
    tool: &ToolRequest,
    response: &McpResponse,
) -> Result<(), BridgeError> {
    if response.canonical_tool_name != tool.canonical_name() {
        return Err(BridgeError::Serialization(
            "response tool does not match the requested tool".to_owned(),
        ));
    }
    if !is_sha256(&response.canonical_request_sha256) {
        return Err(BridgeError::Serialization(
            "response canonical request digest is invalid".to_owned(),
        ));
    }
    if matches!(
        response.kind,
        ResponseKind::PlanGap | ResponseKind::Unsupported
    ) {
        if response.recall_disposition.is_some() {
            return Err(BridgeError::Serialization(
                "negative response must not carry a recall disposition".to_owned(),
            ));
        }
        if response.proof_ceiling != ProofCeiling::Observation
            || !response.artifacts.is_empty()
            || response.resource.is_some()
            || response.job.is_some()
        {
            return Err(BridgeError::Serialization(
                "negative response has an invalid proof or resource envelope".to_owned(),
            ));
        }
        classify_response_failure(response)?;
        let encoded = serde_json::to_vec(response)
            .map_err(|error| BridgeError::Serialization(error.to_string()))?;
        if encoded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
            return Err(BridgeError::Serialization(
                "negative response exceeds the structured response ceiling".to_owned(),
            ));
        }
        return Ok(());
    }
    if requires_evidence_pack_response(tool) {
        if response.kind != ResponseKind::Projection {
            return Err(BridgeError::Serialization(
                "exact evidence response must be a read-only projection".to_owned(),
            ));
        }
        if response.proof_ceiling != ProofCeiling::ScopedVerification
            || !response.artifacts.is_empty()
            || response.resource.is_some()
            || response.job.is_some()
        {
            return Err(BridgeError::Serialization(
                "exact evidence response has an invalid proof or resource envelope".to_owned(),
            ));
        }
    }
    validate_projection_content_for_tool(tool, &response.content, response.recall_disposition)
}

/// Joins an exact evidence-pack projection to the direct MCP request.
///
/// The direct MCP path has no local-read envelope tuple. It still has an
/// authenticated source-assurance scope and an owner-resolved State Fence, so
/// the response owner must bind the exact subject, scope, catalogue bound,
/// request digest, and fence before the response leaves the core. The bridge
/// and local-read replay paths repeat the corresponding checks at their
/// untrusted boundaries.
fn validate_direct_evidence_pack_response(
    request: &ForwardedRequest,
    response: &McpResponse,
) -> Result<(), BridgeError> {
    if !requires_evidence_pack_response(&request.request.tool) {
        return Ok(());
    }
    let subject = request.request.tool.query_subject().ok_or_else(|| {
        BridgeError::Serialization("exact evidence subject is missing".to_owned())
    })?;
    let state_fence = serde_json::to_value(&request.active_session_binding.session.state_fence)
        .map_err(|error| {
            BridgeError::Serialization(format!(
                "request State Fence cannot be canonicalized: {error}"
            ))
        })?;
    validate_evidence_pack_response(
        response,
        &EvidencePackResponseExpectation {
            request_id: request.active_session_binding.request_id.clone(),
            idempotency_key: request.active_session_binding.idempotency_key.clone(),
            canonical_request_sha256: request.canonical_request_sha256.clone(),
            subject: subject.to_owned(),
            scope_id: request
                .source_assurance
                .assurance
                .scope
                .expected_scope
                .clone(),
            max_records: u64::from(EVIDENCE_PACK_MAX_RECORDS),
            state_fence,
        },
    )
}

/// Validates an exact evidence-pack response and all request/fence joins that
/// a response owner or replay boundary can know.
pub fn validate_evidence_pack_response(
    response: &McpResponse,
    expected: &EvidencePackResponseExpectation,
) -> Result<(), BridgeError> {
    if expected.request_id.trim().is_empty()
        || expected.request_id.chars().any(char::is_control)
        || expected.idempotency_key.trim().is_empty()
        || expected.idempotency_key.chars().any(char::is_control)
        || expected.subject.trim().is_empty()
        || expected.subject.chars().any(char::is_control)
        || expected.scope_id.trim().is_empty()
        || expected.scope_id.chars().any(char::is_control)
        || !is_sha256(&expected.canonical_request_sha256)
    {
        return Err(BridgeError::Serialization(
            "evidence-pack response expectation is malformed".to_owned(),
        ));
    }
    let expected_fence: eliot_store_api::StateFence =
        serde_json::from_value(expected.state_fence.clone()).map_err(|error| {
            BridgeError::Serialization(format!("expected evidence State Fence is invalid: {error}"))
        })?;
    expected_fence.validate().map_err(|error| {
        BridgeError::Serialization(format!("expected evidence State Fence is invalid: {error}"))
    })?;
    validate_mcp_response_for_tool(
        &ToolRequest::Query(QueryInput {
            intent: QueryIntent {
                mode: QueryMode::Verification,
                time_scope: "response-owner".to_owned(),
                branch_environment_scope: "response-owner".to_owned(),
                freshness_policy: "exact captured records only".to_owned(),
                required_assurance: "response-owner validation".to_owned(),
            },
            query: format!("subject:{}", expected.subject),
            exact_resource_uri: None,
        }),
        response,
    )?;
    if response.request_id != expected.request_id
        || response.idempotency_key != expected.idempotency_key
        || response.canonical_request_sha256 != expected.canonical_request_sha256
    {
        return Err(BridgeError::Serialization(
            "evidence-pack response does not bind the admitted request identity".to_owned(),
        ));
    }
    if response.kind != ResponseKind::Projection {
        return Err(BridgeError::Serialization(
            "evidence-pack response must be a read-only projection".to_owned(),
        ));
    }
    if response.proof_ceiling != ProofCeiling::ScopedVerification
        || !response.artifacts.is_empty()
        || response.resource.is_some()
        || response.job.is_some()
    {
        return Err(BridgeError::Serialization(
            "evidence-pack response has an invalid proof or resource envelope".to_owned(),
        ));
    }
    if expected.max_records == 0 || expected.max_records > u64::from(EVIDENCE_PACK_MAX_RECORDS) {
        return Err(BridgeError::Serialization(
            "evidence-pack expected max_records is outside the catalogue bound".to_owned(),
        ));
    }
    if response.content.get("subject").and_then(Value::as_str) != Some(expected.subject.as_str())
        || response.content.get("scope_id").and_then(Value::as_str)
            != Some(expected.scope_id.as_str())
        || response.content.get("operation").and_then(Value::as_str) != Some("GetEvidencePack")
    {
        return Err(BridgeError::Serialization(
            "evidence-pack response does not bind the admitted subject and scope".to_owned(),
        ));
    }
    if response
        .content
        .pointer("/evidence_pack/provenance/max_records")
        .and_then(Value::as_u64)
        != Some(expected.max_records)
    {
        return Err(BridgeError::Serialization(
            "evidence-pack response does not bind max_records".to_owned(),
        ));
    }
    if response
        .content
        .pointer("/evidence_pack/provenance/state_fence")
        != Some(&expected.state_fence)
    {
        return Err(BridgeError::Serialization(
            "evidence-pack response does not bind the admitted State Fence".to_owned(),
        ));
    }
    validate_projected_revision_heads(
        &response.content,
        expected.scope_id.as_str(),
        &expected_fence,
    )?;
    if response.recall_disposition != Some(RecallDisposition::IncompleteCoverage) {
        return Err(BridgeError::Serialization(
            "candidate-only evidence must fail closed to INCOMPLETE_COVERAGE".to_owned(),
        ));
    }
    Ok(())
}

impl ToolRequest {
    fn query_subject(&self) -> Option<&str> {
        let Self::Query(input) = self else {
            return None;
        };
        input
            .query
            .strip_prefix("subject:")
            .map(str::trim)
            .filter(|subject| !subject.is_empty() && !subject.chars().any(char::is_control))
    }
}

/// Closed T11.3 reconstruction query plan derived from an explicit-intent
/// `eliot.query` with `ContextReconstruction` mode.
///
/// This is the pure planning half of the `KernelGovernorPort::dispatch` seam
/// for `ToolRequest::Query`: it carries only validated strings (task-bound
/// scope, exact task selector, evidence selectors, position selector) without
/// importing store types, so this crate stays transport-only and the store
/// catalogue remains the authority. Free-text `query` is intent data, never a
/// selector: T11.3 requires the exact form `task:<exact-task-id>`; anything
/// else fails closed instead of becoming a substring search or a forwarded
/// `query` parameter. The Governor reconstruction composition behind
/// `KernelGovernorPort` binds these selectors to the six
/// ContextReconstruction-admitted named reads; the seven provider-role
/// dispositions return through
/// [`project_context_reconstruction_projection`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextReconstructionQueryPlan {
    /// Exact task-bound scope (from the trusted active session binding, never
    /// from MCP arguments alone).
    pub scope_id: String,
    /// Exact task identity (never a substring, never blank).
    pub task_id: String,
    /// Exact captured-observation subject for the evidence role.
    pub evidence_subject: String,
    /// Explicit evidence `max_records` bound carried as its decimal string.
    pub evidence_max_records: String,
    /// Exact position selector for the activation-evidence role.
    pub position: String,
}

impl ContextReconstructionQueryPlan {
    /// Closed intent name this plan executes.
    #[must_use]
    pub const fn operation_name() -> &'static str {
        "ContextReconstruction"
    }

    /// Closed named-read operation names bound by this plan, in canonical
    /// role order. Spellings match the store catalogue's `PascalCase` wire
    /// form; the catalogue — not this crate — admits them for execution.
    #[must_use]
    pub const fn role_operation_names() -> [&'static str; 6] {
        [
            "GetTaskState",
            "GetAttentionAndProblems",
            "GetCurrentEpistemicPosition",
            "GetUnderstandingProjectionInputs",
            "GetEvidencePack",
            "GetCapabilityEvidenceState",
        ]
    }
}

/// Plans one closed reconstruction closure from an explicit-intent query.
///
/// Only the `ContextReconstruction` intent plans here (any other mode fails
/// closed as unsupported instead of borrowing the reconstruction closure);
/// `exact_resource_uri` fails closed because exact expansion uses the
/// resource path, not a query; `query` must be the exact
/// `task:<exact-task-id>` selector form. `scope_id` comes from the trusted
/// active session binding and the store enforces the catalogue
/// `EVIDENCE_PACK_MAX_RECORDS` cap on the carried bound.
pub fn plan_context_reconstruction_query(
    input: &QueryInput,
    scope_id: &str,
    evidence_subject: &str,
    evidence_max_records: &str,
    position: &str,
) -> Result<ContextReconstructionQueryPlan, BridgeError> {
    if !matches!(input.intent.mode, QueryMode::ContextReconstruction) {
        return Err(BridgeError::Port(PortFailure::Unsupported {
            capability: "ContextReconstruction".to_owned(),
            reason: "the reconstruction closure admits only the ContextReconstruction intent"
                .to_owned(),
        }));
    }
    if input.exact_resource_uri.is_some() {
        return Err(BridgeError::invalid(
            "query.exact_resource_uri",
            "exact resource expansion uses the resource path, not eliot.query",
        ));
    }
    if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            "query.scope_id",
            "must be non-blank and contain no control characters",
        ));
    }
    let task_id = input
        .query
        .strip_prefix("task:")
        .map(str::trim)
        .filter(|task| !task.is_empty() && !task.chars().any(char::is_control))
        .ok_or_else(|| {
            BridgeError::invalid(
                "query.query",
                "T11.3 requires the exact form `task:<exact-task-id>`; free-text search is not an exact selector",
            )
        })?;
    if evidence_subject.trim().is_empty() || evidence_subject.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            "query.evidence_subject",
            "must be non-blank and contain no control characters",
        ));
    }
    if evidence_max_records.trim().is_empty() || evidence_max_records.chars().any(char::is_control)
    {
        return Err(BridgeError::invalid(
            "query.evidence_max_records",
            "must be a non-blank decimal bound",
        ));
    }
    let bound: u32 = evidence_max_records.trim().parse().map_err(|_| {
        BridgeError::invalid(
            "query.evidence_max_records",
            "must be a positive decimal bound",
        )
    })?;
    if bound == 0 {
        return Err(BridgeError::invalid(
            "query.evidence_max_records",
            "must be a positive decimal bound",
        ));
    }
    if position.trim().is_empty() || position.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            "query.position",
            "must be non-blank and contain no control characters",
        ));
    }
    Ok(ContextReconstructionQueryPlan {
        scope_id: scope_id.trim().to_owned(),
        task_id: task_id.to_owned(),
        evidence_subject: evidence_subject.trim().to_owned(),
        evidence_max_records: evidence_max_records.trim().to_owned(),
        position: position.trim().to_owned(),
    })
}

/// Projects a successful reconstruction payload into a bounded `Projection`.
///
/// Kind is always `Projection` (read-only owner state, never a candidate);
/// proof ceiling is `ScopedVerification` (the strongest ceiling MCP
/// projections may claim); no `CurrentPosition` claim is expressed. The exact
/// owner payload — the seven role dispositions with their fence identity —
/// crosses unchanged under `context_reconstruction` with its task/scope
/// identity.
#[must_use]
#[allow(
    clippy::needless_pass_by_value,
    reason = "payload moves into the JSON projection; clippy cannot see through json!"
)]
pub fn project_context_reconstruction_projection(
    plan: &ContextReconstructionQueryPlan,
    payload: Value,
) -> PortProjection {
    PortProjection {
        kind: ProjectionKind::Projection,
        content: json!({
            "operation": ContextReconstructionQueryPlan::operation_name(),
            "task_id": plan.task_id,
            "scope_id": plan.scope_id,
            "context_reconstruction": payload,
        }),
        recall_disposition: None,
        artifacts: Vec::new(),
        proof_ceiling: ProofCeiling::ScopedVerification,
        resource: None,
        durable_job: None,
    }
}

/// Closed non-authoritative projection classes returned by the injected port.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionKind {
    /// Candidate content awaiting admission/verification.
    Candidate,
    /// Read-only projection of owner state.
    Projection,
}

/// A semantic owner result that still cannot express finish/admission authority.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortProjection {
    /// Candidate/projection class only.
    pub kind: ProjectionKind,
    /// Structured content.
    pub content: Value,
    /// Response-owner disposition for an exact evidence-pack projection.
    /// Other projections omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_disposition: Option<RecallDisposition>,
    /// Exact immutable artifacts referenced by the projection.
    #[serde(default)]
    pub artifacts: Vec<ArtifactBinding>,
    /// Strongest interpretation permitted for this projection.
    pub proof_ceiling: ProofCeiling,
    /// Immutable resource handle for large content.
    pub resource: Option<ResourceHandle>,
    /// Durable long-operation handle, if one was started by the real owner.
    pub durable_job: Option<DurableJobHandle>,
}

/// Typed negative outcomes from a real or absent semantic provider.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PortFailure {
    /// Required G-12/Q-01 or another semantic provider is absent/unadmitted.
    #[error("PLAN_GAP: {reason}")]
    PlanGap {
        /// Exact missing provider/capability.
        missing_capability: String,
        /// Public recovery reason.
        reason: String,
    },
    /// The selected provider does not implement the requested semantic contract.
    #[error("UNSUPPORTED: {reason}")]
    Unsupported {
        /// Unsupported contract/capability.
        capability: String,
        /// Public reason.
        reason: String,
    },
    /// Same idempotency identity was bound to different request bytes.
    #[error("IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    /// Request deadline was reached by the semantic owner.
    #[error("DEADLINE_EXCEEDED")]
    DeadlineExceeded,
    /// Request was cancelled by its canonical cancellation identity.
    #[error("CANCELLED")]
    Cancelled,
    /// Owner rejected a stale or mismatched state fence.
    #[error("FENCE_MISMATCH")]
    FenceMismatch,
    /// Scoped credential or operational transport binding was rejected.
    #[error("TRANSPORT_BINDING_REJECTED: {reason}")]
    TransportBindingRejected {
        /// Public bounded rejection reason.
        reason: String,
    },
}

/// Immutable large-data handle. Bytes stay outside the structured response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceHandle {
    /// Immutable `eliot://resource/...` URI.
    pub uri: String,
    /// Exact artifact/digest identity of the resource bytes.
    pub artifact: ArtifactBinding,
    /// Media type of the resource bytes.
    pub media_type: String,
    /// Exact byte size.
    pub size_bytes: u64,
    /// Session/fence scope in which the resource was produced.
    pub session: SessionBinding,
}

/// Provider-neutral durable job handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJobHandle {
    /// Durable ELIOT job identity.
    pub job_id: String,
    /// Stable resource used for poll/subscription.
    pub resource_uri: String,
    /// Current job revision.
    pub revision: u64,
    /// Explicit application Session/fence scope.
    pub session: SessionBinding,
}

/// Presentation of one identical durable handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum JobPresentation {
    /// MCP Tasks presentation when advertised.
    McpTask { handle: DurableJobHandle },
    /// Native `DurableJob` presentation otherwise.
    DurableJob { handle: DurableJobHandle },
}

impl JobPresentation {
    /// Returns the semantically identical underlying handle.
    #[must_use]
    pub const fn handle(&self) -> &DurableJobHandle {
        match self {
            Self::McpTask { handle } | Self::DurableJob { handle } => handle,
        }
    }
}

/// Closed MCP response classes. There is deliberately no `SUCCESS` verdict.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseKind {
    /// Candidate content.
    Candidate,
    /// Read-only projection.
    Projection,
    /// Required real provider is absent.
    PlanGap,
    /// Provider contract is not supported.
    Unsupported,
}

/// Bounded, correlated, non-authoritative MCP response.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResponse {
    /// Exact request identity echoed for correlation.
    pub request_id: String,
    /// Exact idempotency identity echoed for retry correlation.
    pub idempotency_key: String,
    /// SHA-256 of canonical request bytes.
    pub canonical_request_sha256: String,
    /// Candidate/projection/typed-gap class.
    pub kind: ResponseKind,
    /// Canonical tool name.
    pub canonical_tool_name: String,
    /// Response-owner closed recall result for an exact evidence-pack query.
    /// Other projections and all negative responses omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_disposition: Option<RecallDisposition>,
    /// Structured bounded content or a resource pointer.
    pub content: Value,
    /// Immutable artifacts referenced by the content.
    pub artifacts: Vec<ArtifactBinding>,
    /// Explicit proof ceiling; never a finish decision.
    pub proof_ceiling: ProofCeiling,
    /// Large-data resource handle, when used.
    pub resource: Option<ResourceHandle>,
    /// Long-operation presentation.
    pub job: Option<JobPresentation>,
}

/// Immutable identity binding one bounded MCP response to its request.
///
/// Built once at server receive from the validated request identity and
/// carried end-to-end through the host gateway to the bridge stdio span, so a
/// completed response is never mistaken for a timeout when host/UI
/// observability is missing. It carries correlation only; it mints no
/// principal, Session, task, fence, or authority identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCorrelation {
    /// Exact request identity echoed for correlation.
    pub request_id: String,
    /// Exact idempotency identity echoed for retry correlation.
    pub idempotency_key: String,
    /// SHA-256 of canonical request bytes.
    pub canonical_request_sha256: String,
}

impl McpResponse {
    /// Returns the immutable request binding echoed by this response.
    #[must_use]
    pub fn correlation(&self) -> RequestCorrelation {
        RequestCorrelation {
            request_id: self.request_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            canonical_request_sha256: self.canonical_request_sha256.clone(),
        }
    }
}

/// Pure stateless MCP core. It stores neither a port nor application state.
#[derive(Clone, Copy, Debug, Default)]
pub struct McpCore;

impl McpCore {
    /// Returns a non-binding initialize projection.
    ///
    /// The advertised tool count is derived from the single versioned semantic
    /// owner (one registered profile per method identity and version), never
    /// from a name list: a method without a profile is absent from the
    /// advertised surface, so the count follows the owner.
    #[must_use]
    pub fn initialize(request: InitializeRequest) -> InitializeResponse {
        InitializeResponse {
            protocol_version: request.protocol_version,
            canonical_tool_count: canonical_tool_count(),
            structured_response_limit_bytes: HARD_STRUCTURED_RESPONSE_BYTES,
            application_binding_created: false,
        }
    }

    /// Validates and dispatches a primary-profile request.
    pub fn execute<P: KernelGovernorPort + ?Sized>(
        &self,
        port: &P,
        transport: TransportRequestContext,
        request: ApplicationRequest,
    ) -> Result<McpResponse, BridgeError> {
        if request.protocol_version != McpProtocolVersion::Final2026_07_28 {
            return Err(BridgeError::invalid(
                "protocol_version",
                "the primary entrypoint admits only 2026-07-28",
            ));
        }
        Self::execute_inner(port, transport, request)
    }

    /// Validates raw request bytes through the protected decoder before any
    /// trusted construction or semantic dispatch.
    ///
    /// Raw duplicate protected keys (including escape-equivalent forms) and
    /// unknown protected variants fail here with zero port calls; no trial
    /// decoding is performed.
    pub fn execute_raw<P: KernelGovernorPort + ?Sized>(
        &self,
        port: &P,
        transport: TransportRequestContext,
        request_bytes: &[u8],
    ) -> Result<McpResponse, BridgeError> {
        let request =
            decode_protected_request_bytes(request_bytes).map_err(raw_rejection_to_bridge)?;
        self.execute(port, transport, request)
    }

    #[allow(clippy::too_many_lines)]
    fn execute_inner<P: KernelGovernorPort + ?Sized>(
        port: &P,
        transport: TransportRequestContext,
        request: ApplicationRequest,
    ) -> Result<McpResponse, BridgeError> {
        transport.validate()?;
        validate_application_request(&request)?;
        let correlation = RequestCorrelation {
            request_id: request
                .identity
                .request
                .metadata
                .request_id
                .as_str()
                .to_owned(),
            idempotency_key: request.identity.idempotency_key.clone(),
            canonical_request_sha256: canonical_sha256(&request)?,
        };
        let canonical_tool_name = request.tool.canonical_name().to_owned();
        let client_capabilities = request.client_capabilities;
        let resolution_request = BindingResolutionRequest {
            transport,
            claimed_session: request.session.clone(),
            request_id: correlation.request_id.clone(),
            original_request_sha256: correlation.canonical_request_sha256.clone(),
            idempotency_key: correlation.idempotency_key.clone(),
            cancellation_id: request.identity.cancellation_id.clone(),
            canonical_request_sha256: correlation.canonical_request_sha256.clone(),
            deadline_unix_ms: request.identity.deadline_unix_ms,
        };
        let active_session_binding = match port.resolve_active_session(&resolution_request) {
            Ok(binding) => binding,
            Err(failure @ (PortFailure::PlanGap { .. } | PortFailure::Unsupported { .. })) => {
                return negative_response(
                    &correlation.request_id,
                    &correlation.idempotency_key,
                    &correlation.canonical_request_sha256,
                    &canonical_tool_name,
                    failure,
                );
            }
            Err(other) => return Err(BridgeError::Port(other)),
        };
        validate_active_session_binding(&resolution_request, &active_session_binding)?;
        let owner_evidence =
            match port.resolve_source_assurance(&resolution_request, &active_session_binding) {
                Ok(evidence) => evidence,
                Err(failure @ (PortFailure::PlanGap { .. } | PortFailure::Unsupported { .. })) => {
                    return negative_response(
                        &correlation.request_id,
                        &correlation.idempotency_key,
                        &correlation.canonical_request_sha256,
                        &canonical_tool_name,
                        failure,
                    );
                }
                Err(other) => return Err(BridgeError::Port(other)),
            };
        let source_assurance = validate_owner_evidence(
            &owner_evidence,
            &resolution_request,
            &active_session_binding,
        )?;
        let forwarded = ForwardedRequest {
            request,
            canonical_request_sha256: correlation.canonical_request_sha256.clone(),
            active_session_binding,
            source_assurance,
        };
        let projection = match port.dispatch(&forwarded) {
            Ok(value) => value,
            Err(failure @ (PortFailure::PlanGap { .. } | PortFailure::Unsupported { .. })) => {
                return negative_response(
                    &correlation.request_id,
                    &correlation.idempotency_key,
                    &correlation.canonical_request_sha256,
                    &canonical_tool_name,
                    failure,
                );
            }
            Err(other) => return Err(BridgeError::Port(other)),
        };
        validate_projection(&forwarded.request.session, &projection)?;
        validate_projection_content_for_tool(
            &forwarded.request.tool,
            &projection.content,
            projection.recall_disposition,
        )?;
        let recall_disposition = projection.recall_disposition;
        let kind = match projection.kind {
            ProjectionKind::Candidate => ResponseKind::Candidate,
            ProjectionKind::Projection => ResponseKind::Projection,
        };
        let job = projection.durable_job.map(|handle| {
            if client_capabilities.tasks {
                JobPresentation::McpTask { handle }
            } else {
                JobPresentation::DurableJob { handle }
            }
        });
        let response = McpResponse {
            request_id: correlation.request_id.clone(),
            idempotency_key: correlation.idempotency_key.clone(),
            canonical_request_sha256: correlation.canonical_request_sha256.clone(),
            kind,
            canonical_tool_name,
            recall_disposition,
            content: projection.content,
            artifacts: projection.artifacts,
            proof_ceiling: projection.proof_ceiling,
            resource: projection.resource,
            job,
        };
        validate_mcp_response_for_tool(&forwarded.request.tool, &response)?;
        validate_direct_evidence_pack_response(&forwarded, &response)?;
        bounded_response(response)
    }
}

/// Provider used when no real Kernel/Governor semantic provider is admitted.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProviderPort;

impl KernelGovernorPort for NoProviderPort {
    fn resolve_active_session(
        &self,
        _request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: "active-session-binding-resolver".to_owned(),
            reason: "no admitted Kernel/Governor provider is injected".to_owned(),
        })
    }

    fn dispatch(&self, request: &ForwardedRequest) -> Result<PortProjection, PortFailure> {
        Err(PortFailure::PlanGap {
            missing_capability: request.request.tool.canonical_name().to_owned(),
            reason: "no admitted Kernel/Governor provider is injected".to_owned(),
        })
    }
}

fn validate_negative_text(field: &'static str, value: &str) -> Result<(), BridgeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            field,
            "typed negative response text must be non-blank and contain no control characters",
        ));
    }
    Ok(())
}

fn negative_response(
    request_id: &str,
    idempotency_key: &str,
    canonical_request_sha256: &str,
    canonical_tool_name: &str,
    failure: PortFailure,
) -> Result<McpResponse, BridgeError> {
    let (kind, content) = match failure {
        PortFailure::PlanGap {
            missing_capability,
            reason,
        } => {
            validate_negative_text("response.content.missing_capability", &missing_capability)?;
            validate_negative_text("response.content.reason", &reason)?;
            (
                ResponseKind::PlanGap,
                json!({
                    "code": "PLAN_GAP",
                    "missing_capability": missing_capability,
                    "reason": reason,
                }),
            )
        }
        PortFailure::Unsupported { capability, reason } => {
            validate_negative_text("response.content.capability", &capability)?;
            validate_negative_text("response.content.reason", &reason)?;
            (
                ResponseKind::Unsupported,
                json!({
                    "code": "UNSUPPORTED",
                    "capability": capability,
                    "reason": reason,
                }),
            )
        }
        other => return Err(BridgeError::Port(other)),
    };
    bounded_response(McpResponse {
        request_id: request_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        canonical_request_sha256: canonical_request_sha256.to_owned(),
        kind,
        canonical_tool_name: canonical_tool_name.to_owned(),
        recall_disposition: None,
        content,
        artifacts: Vec::new(),
        proof_ceiling: ProofCeiling::Observation,
        resource: None,
        job: None,
    })
}

/// Bounded typed recovery code for source-assurance admission failures.
///
/// `Rejected` covers conflicting or policy-rejected evidence,
/// `Quarantined` covers quarantined sources, `Incomplete` covers missing or
/// incomplete evidence, `Stale` covers needs-revalidation, and
/// `InternalDefect` covers encoding defects that are never caller recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceRecoveryCode {
    /// Conflicting, wrong-scope, or policy-rejected evidence.
    Rejected,
    /// Quarantined source; retained as evidence but excluded from admission.
    Quarantined,
    /// Missing or incomplete evidence.
    Incomplete,
    /// Stale snapshot/frontier/scope requiring revalidation.
    Stale,
    /// Internal encoding defect, not caller recovery.
    InternalDefect,
}

/// Pure bridge validation/forwarding failure.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Input contract violation.
    #[error("INVALID_ARGUMENT at {field}: {reason}")]
    InvalidArgument {
        /// Stable field path.
        field: &'static str,
        /// Public reason.
        reason: String,
    },
    /// Semantic owner negative outcome that is not a typed plan gap.
    #[error("semantic provider: {0}")]
    Port(#[from] PortFailure),
    /// Serialization/schema failure.
    #[error("contract serialization failed: {0}")]
    Serialization(String),
    /// Structured output exceeded the hard limit without a valid resource route.
    #[error("RESOURCE_REQUIRED: structured response is {actual} bytes; maximum is {maximum}")]
    ResourceRequired {
        /// Encoded response size.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// A resource handle did not bind the exact canonical inline content.
    #[error("RESOURCE_BINDING_MISMATCH: resource does not bind canonical content bytes")]
    ResourceBindingMismatch,
    /// Owner source evidence was absent, invalid, stale, or policy-rejected.
    #[error("SOURCE_ASSURANCE_REJECTED: {reason}")]
    SourceAssuranceRejected { reason: String },
}

impl BridgeError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidArgument {
            field,
            reason: reason.into(),
        }
    }
}

fn validate_application_request(request: &ApplicationRequest) -> Result<(), BridgeError> {
    request
        .identity
        .validate()
        .map_err(|error| BridgeError::invalid("identity", error.to_string()))?;
    request
        .session
        .state_fence
        .validate()
        .map_err(|error| BridgeError::invalid("session.state_fence", error.to_string()))?;
    if request.session.authority_epoch != request.session.state_fence.authority_epoch {
        return Err(BridgeError::invalid(
            "session.authority_epoch",
            "must match session.state_fence.authority_epoch",
        ));
    }
    if request.session.state_fence != request.identity.request.state_fence {
        return Err(BridgeError::invalid(
            "identity.request.state_fence",
            "must exactly match the application Session state fence",
        ));
    }
    if request.identity.request.metadata.session_id.as_ref() != Some(&request.session.session_id) {
        return Err(BridgeError::invalid(
            "identity.request.metadata.session_id",
            "must exactly match the explicit application Session",
        ));
    }
    if request
        .identity
        .request
        .metadata
        .clock
        .known_time_ms
        .and_then(|value| u64::try_from(value).ok())
        .is_some_and(|known_time_ms| request.identity.deadline_unix_ms <= known_time_ms)
    {
        return Err(BridgeError::invalid(
            "identity.deadline_unix_ms",
            "must be later than the request known-time observation",
        ));
    }
    request.tool.validate().map_err(contract_violation)?;
    validate_tool_semantic_owner(&request.tool)?;
    if let ToolRequest::Finish(draft) = &request.tool {
        let metadata_task = request.identity.request.metadata.task_id.as_ref();
        if !matches!(metadata_task, Some(value) if value.as_str() == draft.task_id.as_str()) {
            return Err(BridgeError::invalid(
                "finish.task_id",
                "must exactly match request metadata task_id",
            ));
        }
        if !matches!(
            request.identity.request.state_fence.task_revision,
            Some(value) if value.value() == draft.expected_task_revision
        ) {
            return Err(BridgeError::invalid(
                "finish.expected_task_revision",
                "must exactly match the request State Fence task revision",
            ));
        }
    }
    Ok(())
}

fn contract_violation(value: ContractViolation) -> BridgeError {
    match value {
        ContractViolation::InvalidField { field, reason } => BridgeError::invalid(field, reason),
    }
}

/// Number of methods owned by the single versioned semantic registry.
///
/// Fails closed to zero when the canonical owner cannot be built (unreachable
/// for the literal canonical data; any build failure is a code defect, and a
/// defect must never advertise tools).
fn canonical_tool_count() -> usize {
    crate::canonical_known_tools().map_or(0, |tools| tools.len())
}

/// Resolves the single versioned semantic owner for the requested tool on the
/// normal admission path (I7.24).
///
/// Every admitted request joins its method identity and version to exactly one
/// registered [`crate::ToolSemanticProfile`] before any port call; a method
/// with no owner fails closed here. Routing behavior is read from the profile
/// by downstream consumers, never inferred from the tool name.
fn validate_tool_semantic_owner(tool: &ToolRequest) -> Result<(), BridgeError> {
    crate::validate_tool_request_owner(tool).map_err(|error| {
        BridgeError::invalid(
            "tool.name",
            format!("no registered semantic owner: {error}"),
        )
    })?;
    Ok(())
}

fn validate_active_session_binding(
    resolution: &BindingResolutionRequest,
    binding: &ActiveSessionBinding,
) -> Result<(), BridgeError> {
    if binding.binding_id.trim().is_empty() || binding.principal_ref.trim().is_empty() {
        return Err(BridgeError::invalid(
            "active_session_binding",
            "must identify both the live binding and authenticated principal",
        ));
    }
    binding.transport.validate()?;
    if binding.session != resolution.claimed_session {
        return Err(BridgeError::invalid(
            "active_session_binding.session",
            "must exactly match the caller claim after trusted resolution",
        ));
    }
    if binding.transport != resolution.transport {
        return Err(BridgeError::invalid(
            "active_session_binding.transport",
            "must exactly match the resolved credential, connection, profile, and generation",
        ));
    }
    if binding.request_id != resolution.request_id
        || binding.idempotency_key != resolution.idempotency_key
        || binding.cancellation_id != resolution.cancellation_id
        || binding.canonical_request_sha256 != resolution.canonical_request_sha256
    {
        return Err(BridgeError::invalid(
            "active_session_binding.request_correlation",
            "must bind the exact request, idempotency, cancellation, and canonical bytes",
        ));
    }
    if binding.resolved_at_unix_ms == 0
        || binding.resolved_at_unix_ms > resolution.deadline_unix_ms
        || binding.valid_until_unix_ms < resolution.deadline_unix_ms
        || binding.valid_until_unix_ms <= binding.resolved_at_unix_ms
    {
        return Err(BridgeError::invalid(
            "active_session_binding.validity",
            "must be current and remain valid through the exact request deadline",
        ));
    }
    Ok(())
}

fn validate_owner_evidence(
    evidence: &OwnerSourceEvidence,
    resolution: &BindingResolutionRequest,
    binding: &ActiveSessionBinding,
) -> Result<ForwardedSourceAssurance, BridgeError> {
    evidence.validate().map_err(|error| {
        assurance_rejection(
            assurance_error_code(&error),
            &safe_assurance_error_reason(&error),
        )
    })?;
    if evidence.owner_principal_ref != binding.principal_ref {
        return Err(assurance_rejection(
            AssuranceRecoveryCode::Rejected,
            "owner evidence principal must match the authenticated active binding",
        ));
    }
    let state_fence_digest =
        canonical_digest(&resolution.claimed_session.state_fence).map_err(|error| {
            assurance_rejection(
                assurance_error_code(&error),
                &safe_assurance_error_reason(&error),
            )
        })?;
    if evidence.request_id != resolution.request_id
        || evidence.original_request_sha256 != resolution.original_request_sha256
        || evidence.idempotency_key != resolution.idempotency_key
        || evidence.cancellation_id != resolution.cancellation_id
        || evidence.session_id != resolution.claimed_session.session_id.to_string()
        || evidence.state_fence_digest != state_fence_digest
        || evidence.canonical_request_sha256 != resolution.canonical_request_sha256
    {
        return Err(assurance_rejection(
            AssuranceRecoveryCode::Rejected,
            "owner evidence must bind the resolver's exact canonical request",
        ));
    }
    let outcome = evidence
        .assurance
        .admit_with_policy(&evidence.policy)
        .map_err(|error| {
            assurance_rejection(
                assurance_error_code(&error),
                &safe_assurance_error_reason(&error),
            )
        })?;
    let AdmissionOutcome::Admitted { assurance_digest } = outcome else {
        let (_, reason, _) = admission_outcome_recovery(&outcome);
        return Err(BridgeError::SourceAssuranceRejected {
            reason: reason.to_owned(),
        });
    };
    if evidence.verifier_ref != evidence.policy.required_verifier {
        return Err(assurance_rejection(
            AssuranceRecoveryCode::Rejected,
            "owner evidence does not satisfy the policy verifier requirement",
        ));
    }
    Ok(ForwardedSourceAssurance {
        owner_principal_ref: evidence.owner_principal_ref.clone(),
        evidence_ref: evidence.evidence_ref.clone(),
        request_id: evidence.request_id.clone(),
        original_request_sha256: evidence.original_request_sha256.clone(),
        idempotency_key: evidence.idempotency_key.clone(),
        cancellation_id: evidence.cancellation_id.clone(),
        session_id: evidence.session_id.clone(),
        state_fence_digest: evidence.state_fence_digest.clone(),
        canonical_request_sha256: evidence.canonical_request_sha256.clone(),
        verifier_ref: evidence.verifier_ref.clone(),
        assurance: evidence.assurance.clone(),
        policy: evidence.policy.clone(),
        assurance_digest,
    })
}

fn admission_outcome_reason(outcome: &AdmissionOutcome) -> &'static str {
    match outcome {
        AdmissionOutcome::Admitted { .. } => "REJECTED: source assurance admitted",
        AdmissionOutcome::NeedsRevalidation { .. } => "STALE: source assurance needs revalidation",
        AdmissionOutcome::Missing { .. } => "INCOMPLETE: source assurance is incomplete",
        AdmissionOutcome::Conflicted { .. } => {
            "REJECTED: source assurance has conflicting identities"
        }
        AdmissionOutcome::WrongScope { .. } => "REJECTED: source assurance scope does not match",
        AdmissionOutcome::Quarantined { .. } => "QUARANTINED: source assurance is quarantined",
    }
}

/// Maps a non-admitted outcome to its bounded recovery code, redacted reason,
/// and preserved evaluator findings.
///
/// The error itself carries only the distinct single-field reason below; the
/// returned findings vec preserves the full typed evaluator detail without
/// protected bodies for callers that need it. Diagnostics never echo
/// protected bodies.
#[must_use]
pub fn admission_outcome_recovery(
    outcome: &AdmissionOutcome,
) -> (AssuranceRecoveryCode, &'static str, Vec<AssuranceFinding>) {
    match outcome {
        AdmissionOutcome::Admitted { .. } => (
            AssuranceRecoveryCode::Rejected,
            admission_outcome_reason(outcome),
            Vec::new(),
        ),
        AdmissionOutcome::NeedsRevalidation { findings } => (
            AssuranceRecoveryCode::Stale,
            admission_outcome_reason(outcome),
            findings.clone(),
        ),
        AdmissionOutcome::Missing { findings } => (
            AssuranceRecoveryCode::Incomplete,
            admission_outcome_reason(outcome),
            findings.clone(),
        ),
        AdmissionOutcome::Conflicted { findings } | AdmissionOutcome::WrongScope { findings } => (
            AssuranceRecoveryCode::Rejected,
            admission_outcome_reason(outcome),
            findings.clone(),
        ),
        AdmissionOutcome::Quarantined { findings } => (
            AssuranceRecoveryCode::Quarantined,
            admission_outcome_reason(outcome),
            findings.clone(),
        ),
    }
}

fn assurance_error_code(error: &SourceAssuranceError) -> AssuranceRecoveryCode {
    match error {
        SourceAssuranceError::MissingField(_) => AssuranceRecoveryCode::Incomplete,
        SourceAssuranceError::Json(_) => AssuranceRecoveryCode::InternalDefect,
        SourceAssuranceError::InvalidDigest(_)
        | SourceAssuranceError::DuplicateSourceId(_)
        | SourceAssuranceError::NonCanonicalSourceSet
        | SourceAssuranceError::UnsupportedSchema(_) => AssuranceRecoveryCode::Rejected,
    }
}

fn safe_assurance_error_reason(error: &SourceAssuranceError) -> String {
    match error {
        SourceAssuranceError::MissingField(field) => {
            format!("required assurance field missing: {field}")
        }
        SourceAssuranceError::InvalidDigest(field) => format!("assurance digest invalid: {field}"),
        SourceAssuranceError::DuplicateSourceId(_) => "duplicate source identity".to_owned(),
        SourceAssuranceError::NonCanonicalSourceSet => "source set is not canonical".to_owned(),
        SourceAssuranceError::UnsupportedSchema(_) => "unsupported assurance schema".to_owned(),
        SourceAssuranceError::Json(_) => "assurance encoding failed".to_owned(),
    }
}

/// Builds the single-field assurance rejection with the recovery-code name
/// embedded as a `CODE: detail` prefix, keeping stale, incomplete, rejected,
/// quarantined, and internal-defect outcomes distinct without structured
/// fields. `detail` is already redacted; protected bodies are never echoed.
fn assurance_rejection(code: AssuranceRecoveryCode, detail: &str) -> BridgeError {
    let prefix = match code {
        AssuranceRecoveryCode::Rejected => "REJECTED",
        AssuranceRecoveryCode::Quarantined => "QUARANTINED",
        AssuranceRecoveryCode::Incomplete => "INCOMPLETE",
        AssuranceRecoveryCode::Stale => "STALE",
        AssuranceRecoveryCode::InternalDefect => "INTERNAL_DEFECT",
    };
    BridgeError::SourceAssuranceRejected {
        reason: format!("{prefix}: {detail}"),
    }
}

/// Maps a raw protected rejection to a redacted bridge error.
///
/// Only bounded control names and static reasons are echoed; raw bodies,
/// secrets, and protected payloads are never included.
fn raw_rejection_to_bridge(rejection: TypedRejection) -> BridgeError {
    match rejection {
        TypedRejection::DuplicateKey { key } => {
            BridgeError::invalid("request", format!("duplicate protected key: {key}"))
        }
        TypedRejection::UnknownVariant { variant } => {
            BridgeError::invalid("tool.name", format!("unsupported tool variant: {variant}"))
        }
        TypedRejection::LegacyFinishProof { member } => BridgeError::invalid(
            "tool.arguments",
            format!(
                "{LEGACY_FINISH_INPUT_REJECTED}: caller-supplied finish proof member `{member}` is not accepted; submit only the strict FinishAttemptDraft fields"
            ),
        ),
        TypedRejection::Malformed { reason } => BridgeError::invalid("request", reason),
        TypedRejection::Oversized { actual, maximum } => {
            BridgeError::ResourceRequired { actual, maximum }
        }
    }
}

/// Trusted routing authority taken strictly from the envelope, the active
/// binding, and owner evidence. Nested JSON/XML/YAML/Markdown/code payloads,
/// encoded strings, and bidi/zero-width text remain inert data: this struct
/// never reads selector, identity, policy, authority, effect-ceiling, or
/// `Finish` routing from data prose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeAuthority {
    /// Canonical tool selector from the typed envelope.
    pub selector: String,
    /// Exact request identity from the envelope.
    pub request_id: String,
    /// Exact retry identity from the envelope.
    pub idempotency_key: String,
    /// Exact cancellation identity from the envelope.
    pub cancellation_id: String,
    /// Exact session identity from the envelope and binding.
    pub session_id: String,
    /// Authenticated principal from the active binding.
    pub principal_ref: String,
    /// Owner policy version from the assurance envelope.
    pub policy_version: String,
    /// Required verifier from the owner policy, when present.
    pub verifier_ref: Option<String>,
    /// Canonical assurance digest from the forwarding envelope.
    pub assurance_digest: String,
}

/// Extracts the trusted routing authority strictly from the envelope,
/// binding, and assurance. Data payloads are never consulted.
#[must_use]
pub fn envelope_authority(
    request: &ApplicationRequest,
    binding: &ActiveSessionBinding,
    assurance: &ForwardedSourceAssurance,
) -> EnvelopeAuthority {
    EnvelopeAuthority {
        selector: request.tool.canonical_name().to_owned(),
        request_id: request
            .identity
            .request
            .metadata
            .request_id
            .as_str()
            .to_owned(),
        idempotency_key: request.identity.idempotency_key.clone(),
        cancellation_id: request.identity.cancellation_id.clone(),
        session_id: request.session.session_id.to_string(),
        principal_ref: binding.principal_ref.clone(),
        policy_version: assurance.policy.policy_version.clone(),
        verifier_ref: assurance.verifier_ref.clone(),
        assurance_digest: assurance.assurance_digest.clone(),
    }
}

/// How a candidate forwarded request relates to an original under one retry
/// identity. Pure comparison over `ForwardedRequest` fields and the
/// assurance digest; no store and no I/O.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayConflictKind {
    /// Canonical payload or request bytes changed.
    PayloadChanged,
    /// Owner source evidence or assurance digest changed.
    SourceChanged,
    /// Owner policy changed.
    PolicyChanged,
    /// Active session binding changed.
    BindingChanged,
}

/// Replay disposition for two forwarded requests sharing a retry identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayDisposition {
    /// Every digest, binding, source, and policy field matches.
    ExactReplay,
    /// Same retry identity but a protected field changed.
    Conflict(ReplayConflictKind),
    /// Different retry identities; not a replay comparison.
    DifferentIdentity,
}

/// Compares two forwarded requests for exact replay or invalidation.
///
/// Exact replay requires identical retry identity plus identical canonical
/// request digests, active binding, source assurance (including the assurance
/// digest), and policy. Any protected change under one identity conflicts and
/// invalidates reuse.
#[must_use]
pub fn replay_disposition(
    original: &ForwardedRequest,
    candidate: &ForwardedRequest,
) -> ReplayDisposition {
    if original.source_assurance.idempotency_key != candidate.source_assurance.idempotency_key
        || original.request.identity.idempotency_key != candidate.request.identity.idempotency_key
    {
        return ReplayDisposition::DifferentIdentity;
    }
    if original.canonical_request_sha256 != candidate.canonical_request_sha256
        || original.request != candidate.request
    {
        return ReplayDisposition::Conflict(ReplayConflictKind::PayloadChanged);
    }
    if original.source_assurance.assurance_digest != candidate.source_assurance.assurance_digest
        || original.source_assurance.assurance != candidate.source_assurance.assurance
        || original.source_assurance.evidence_ref != candidate.source_assurance.evidence_ref
        || original.source_assurance.owner_principal_ref
            != candidate.source_assurance.owner_principal_ref
    {
        return ReplayDisposition::Conflict(ReplayConflictKind::SourceChanged);
    }
    if original.source_assurance.policy != candidate.source_assurance.policy {
        return ReplayDisposition::Conflict(ReplayConflictKind::PolicyChanged);
    }
    if original.active_session_binding != candidate.active_session_binding
        || original.source_assurance.session_id != candidate.source_assurance.session_id
        || original.source_assurance.state_fence_digest
            != candidate.source_assurance.state_fence_digest
        || original.source_assurance.canonical_request_sha256
            != candidate.source_assurance.canonical_request_sha256
    {
        return ReplayDisposition::Conflict(ReplayConflictKind::BindingChanged);
    }
    ReplayDisposition::ExactReplay
}

/// Returns true only for a deterministic exact replay.
#[must_use]
pub fn is_exact_replay(original: &ForwardedRequest, candidate: &ForwardedRequest) -> bool {
    matches!(
        replay_disposition(original, candidate),
        ReplayDisposition::ExactReplay
    )
}

/// Lineage derived by a transformation. The original digest is preserved
/// unchanged; the derived digest adds provenance for the transform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransformedLineage {
    /// Original lineage digest, preserved exactly.
    pub original_lineage_digest: String,
    /// Bounded transform reference that produced the derivation.
    pub transform_ref: String,
    /// Canonical digest over the original digest plus the transform.
    pub derived_digest: String,
}

/// Derives transformed lineage while preserving the original digest.
///
/// The derived digest is computed through the assurance crate's canonical
/// `blake3` helper (`canonical_digest`), not by duplicating digest logic.
/// No store and no I/O are performed.
pub fn derive_transformed_lineage(
    original_lineage_digest: &str,
    transform_ref: &str,
) -> Result<TransformedLineage, BridgeError> {
    if !is_sha256(original_lineage_digest) {
        return Err(BridgeError::invalid(
            "provenance.lineage_digest",
            "must be a lowercase hex digest",
        ));
    }
    if transform_ref.trim().is_empty() || transform_ref.chars().any(char::is_control) {
        return Err(BridgeError::invalid(
            "provenance.transform_ref",
            "must be non-blank and contain no control characters",
        ));
    }
    let derived_digest =
        canonical_digest(&(original_lineage_digest, transform_ref)).map_err(|error| {
            assurance_rejection(
                assurance_error_code(&error),
                &safe_assurance_error_reason(&error),
            )
        })?;
    Ok(TransformedLineage {
        original_lineage_digest: original_lineage_digest.to_owned(),
        transform_ref: transform_ref.to_owned(),
        derived_digest,
    })
}

fn validate_projection(
    request_session: &SessionBinding,
    projection: &PortProjection,
) -> Result<(), BridgeError> {
    validate_proof_ceiling(projection.proof_ceiling).map_err(contract_violation)?;
    let mut artifacts = BTreeSet::new();
    for artifact in &projection.artifacts {
        if !is_sha256(&artifact.sha256) {
            return Err(BridgeError::invalid(
                "response.artifacts.sha256",
                "must be a lowercase SHA-256 digest",
            ));
        }
        if artifact
            .source_revision
            .as_ref()
            .is_some_and(|revision| revision.trim().is_empty())
        {
            return Err(BridgeError::invalid(
                "response.artifacts.source_revision",
                "must be non-blank when present",
            ));
        }
        if !artifacts.insert(artifact.artifact_id.as_str()) {
            return Err(BridgeError::invalid(
                "response.artifacts",
                "must not contain duplicate artifact identities",
            ));
        }
    }
    if let Some(resource) = &projection.resource {
        validate_resource(request_session, resource)?;
        if projection
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == resource.artifact.artifact_id)
            != Some(&resource.artifact)
        {
            return Err(BridgeError::invalid(
                "response.resource.artifact",
                "must exactly match its full binding in response.artifacts",
            ));
        }
    }
    if let Some(job) = &projection.durable_job {
        validate_job(request_session, job)?;
    }
    Ok(())
}

fn validate_resource(
    request_session: &SessionBinding,
    resource: &ResourceHandle,
) -> Result<(), BridgeError> {
    if !resource.uri.starts_with("eliot://resource/") {
        return Err(BridgeError::invalid(
            "response.resource.uri",
            "must be an immutable eliot://resource/ URI",
        ));
    }
    if resource.media_type.trim().is_empty() || resource.size_bytes == 0 {
        return Err(BridgeError::invalid(
            "response.resource",
            "must have a media type and nonzero exact size",
        ));
    }
    if !is_sha256(&resource.artifact.sha256) {
        return Err(BridgeError::invalid(
            "response.resource.artifact.sha256",
            "must be a lowercase SHA-256 digest",
        ));
    }
    if &resource.session != request_session {
        return Err(BridgeError::invalid(
            "response.resource.session",
            "must exactly match the request Session and State Fence",
        ));
    }
    Ok(())
}

fn validate_job(
    request_session: &SessionBinding,
    job: &DurableJobHandle,
) -> Result<(), BridgeError> {
    if job.job_id.trim().is_empty()
        || !job.resource_uri.starts_with("eliot://job/")
        || job.revision == 0
    {
        return Err(BridgeError::invalid(
            "response.durable_job",
            "must have a non-blank identity, immutable job URI, and nonzero revision",
        ));
    }
    if &job.session != request_session {
        return Err(BridgeError::invalid(
            "response.durable_job.session",
            "must exactly match the request Session and State Fence",
        ));
    }
    Ok(())
}

fn bounded_response(mut response: McpResponse) -> Result<McpResponse, BridgeError> {
    let encoded = serde_json::to_vec(&response)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    if encoded.len() <= HARD_STRUCTURED_RESPONSE_BYTES {
        return Ok(response);
    }
    let Some(resource) = response.resource.as_ref() else {
        return Err(BridgeError::ResourceRequired {
            actual: encoded.len(),
            maximum: HARD_STRUCTURED_RESPONSE_BYTES,
        });
    };
    let canonical_content = canonicalize(response.content.clone());
    let canonical_content_bytes = serde_json::to_vec(&canonical_content)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    let content_size = u64::try_from(canonical_content_bytes.len())
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    let content_sha256 = hex_digest(&Sha256::digest(&canonical_content_bytes));
    if resource.media_type != "application/json"
        || resource.size_bytes != content_size
        || resource.artifact.sha256 != content_sha256
    {
        return Err(BridgeError::ResourceBindingMismatch);
    }
    response.content = json!({
        "resource_uri": resource.uri,
        "artifact_id": resource.artifact.artifact_id,
        "sha256": resource.artifact.sha256,
        "size_bytes": resource.size_bytes,
    });
    let bounded = serde_json::to_vec(&response)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    if bounded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(BridgeError::ResourceRequired {
            actual: bounded.len(),
            maximum: HARD_STRUCTURED_RESPONSE_BYTES,
        });
    }
    Ok(response)
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, BridgeError> {
    let value = serde_json::to_value(value)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| BridgeError::Serialization(error.to_string()))?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut keys = values.into_iter().collect::<Vec<_>>();
            keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                keys.into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        other => other,
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "T11.1 planning tests: every asserted subject, bound, scope, intent gate, and projection value is derived from the test inputs; nothing is canned"
)]
mod evidence_pack_query_plan_tests {
    //! T11.1 `eliot.query` planning tests at the MCP dispatch seam.
    //!
    //! The planner maps explicit-intent `QueryInput` to the store catalogue's
    //! closed `subject`/`max_records` selectors without ever forwarding free
    //! text. Every asserted subject, bound, scope, intent gate, and projection
    //! shape is derived from the test inputs; nothing is canned.

    use super::*;
    use crate::{QueryInput, QueryIntent};

    fn verification_intent(mode: QueryMode) -> QueryIntent {
        QueryIntent {
            mode,
            time_scope: "evidence window for verification".to_owned(),
            branch_environment_scope: "test branch and environment".to_owned(),
            freshness_policy: "exact captured records only".to_owned(),
            required_assurance: "verifier evidence read".to_owned(),
        }
    }

    fn input(mode: QueryMode, query: &str) -> QueryInput {
        QueryInput {
            intent: verification_intent(mode),
            query: query.to_owned(),
            exact_resource_uri: None,
        }
    }

    #[test]
    fn plans_exact_subject_with_explicit_bound_and_scope() {
        let plan = plan_evidence_pack_query(
            &input(QueryMode::Verification, "subject:evidence-alpha"),
            "scope-evidence",
            "10",
        )
        .expect("exact selector plans");
        assert_eq!(plan.subject, "evidence-alpha");
        assert_eq!(plan.max_records, "10");
        assert_eq!(plan.scope_id, "scope-evidence");
        assert_eq!(EvidencePackQueryPlan::operation_name(), "GetEvidencePack");
    }

    #[test]
    fn verification_family_intents_plan_but_current_position_never_does() {
        for mode in [
            QueryMode::HistoricalReconstruction,
            QueryMode::Provenance,
            QueryMode::Navigation,
            QueryMode::Verification,
            QueryMode::ChangeImpact,
            QueryMode::ContextReconstruction,
        ] {
            plan_evidence_pack_query(
                &input(mode, "subject:evidence-alpha"),
                "scope-evidence",
                "8",
            )
            .expect("verification family admits GetEvidencePack");
        }
        match plan_evidence_pack_query(
            &input(QueryMode::CurrentPosition, "subject:evidence-alpha"),
            "scope-evidence",
            "8",
        ) {
            Err(BridgeError::Port(PortFailure::Unsupported { capability, .. })) => {
                assert_eq!(capability, "GetEvidencePack");
            }
            other => panic!("CurrentPosition must never admit GetEvidencePack: {other:?}"),
        }
    }

    #[test]
    fn rejects_free_text_resource_uri_and_bad_bounds() {
        // Free text without the exact `subject:` form is not a selector.
        assert!(matches!(
            plan_evidence_pack_query(
                &input(QueryMode::Verification, "retrieve the exact evidence"),
                "scope-evidence",
                "8",
            ),
            Err(BridgeError::InvalidArgument { field, .. }) if field == "query.query"
        ));
        // Exact expansion uses the resource path, not a query.
        let mut with_uri = input(QueryMode::Verification, "subject:evidence-alpha");
        with_uri.exact_resource_uri = Some("eliot://resource/evidence-1".to_owned());
        assert!(matches!(
            plan_evidence_pack_query(&with_uri, "scope-evidence", "8"),
            Err(BridgeError::InvalidArgument { field, .. })
                if field == "query.exact_resource_uri"
        ));
        // Zero, non-numeric, and blank bounds fail closed before transport.
        for bound in ["0", "ten", "  "] {
            assert!(
                plan_evidence_pack_query(
                    &input(QueryMode::Verification, "subject:evidence-alpha"),
                    "scope-evidence",
                    bound,
                )
                .is_err(),
                "bound {bound:?} must fail closed"
            );
        }
        assert!(matches!(
            plan_evidence_pack_query(
                &input(QueryMode::Verification, "subject:evidence-alpha"),
                "  ",
                "8",
            ),
            Err(BridgeError::InvalidArgument { field, .. }) if field == "query.scope_id"
        ));
    }

    #[test]
    fn projects_bounded_projection_without_current_position_claim() {
        let plan = plan_evidence_pack_query(
            &input(QueryMode::Verification, "subject:evidence-alpha"),
            "scope-evidence",
            "8",
        )
        .expect("exact selector plans");
        let payload = json!({
            "version": EVIDENCE_PACK_PROJECTION_VERSION,
            "subject": "evidence-alpha",
            "scope_id": "scope-evidence",
            "records": [],
            "provenance": {
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 1,
                    },
                    "resource_generation": 1,
                },
                "matched_total": 0,
                "returned": 0,
                "max_records": 8,
                "truncated": false,
            },
        });
        let projection = project_evidence_pack_projection(&plan, payload.clone())
            .expect("opaque evidence pack projects");
        assert_eq!(projection.kind, ProjectionKind::Projection);
        assert_eq!(projection.proof_ceiling, ProofCeiling::ScopedVerification);
        assert!(
            projection
                .proof_ceiling
                .is_at_most(ProofCeiling::ScopedVerification)
        );
        assert_eq!(projection.content["operation"], "GetEvidencePack");
        assert_eq!(projection.content["subject"], "evidence-alpha");
        assert_eq!(projection.content["scope_id"], "scope-evidence");
        assert_eq!(projection.content["evidence_pack"], payload);
        assert!(projection.artifacts.is_empty());
        assert!(projection.resource.is_none());
        assert!(projection.durable_job.is_none());
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "T11.3 planning tests: every asserted task, bound, scope, intent gate, and projection value is derived from the test inputs; nothing is canned"
)]
mod context_reconstruction_query_plan_tests {
    //! T11.3 `eliot.query` planning tests at the MCP dispatch seam.
    //!
    //! The planner maps an explicit-intent `QueryInput` with
    //! `ContextReconstruction` mode to the closed task/evidence/position
    //! selectors without ever forwarding free text. Every asserted task,
    //! bound, scope, intent gate, and projection shape is derived from the
    //! test inputs; nothing is canned.

    use super::*;
    use crate::{QueryInput, QueryIntent};

    fn reconstruction_intent(mode: QueryMode) -> QueryIntent {
        QueryIntent {
            mode,
            time_scope: "task window for reconstruction".to_owned(),
            branch_environment_scope: "test branch and environment".to_owned(),
            freshness_policy: "exact admitted generation only".to_owned(),
            required_assurance: "reconstruction input read".to_owned(),
        }
    }

    fn input(mode: QueryMode, query: &str) -> QueryInput {
        QueryInput {
            intent: reconstruction_intent(mode),
            query: query.to_owned(),
            exact_resource_uri: None,
        }
    }

    fn plan(query: &str) -> Result<ContextReconstructionQueryPlan, BridgeError> {
        plan_context_reconstruction_query(
            &input(QueryMode::ContextReconstruction, query),
            "scope-task",
            "evidence-alpha",
            "8",
            "position-one",
        )
    }

    #[test]
    fn plans_exact_task_with_explicit_selectors_and_scope() {
        let plan = plan("task:task-7").expect("exact selector plans");
        assert_eq!(plan.task_id, "task-7");
        assert_eq!(plan.scope_id, "scope-task");
        assert_eq!(plan.evidence_subject, "evidence-alpha");
        assert_eq!(plan.evidence_max_records, "8");
        assert_eq!(plan.position, "position-one");
        assert_eq!(
            ContextReconstructionQueryPlan::operation_name(),
            "ContextReconstruction"
        );
        assert_eq!(
            ContextReconstructionQueryPlan::role_operation_names(),
            [
                "GetTaskState",
                "GetAttentionAndProblems",
                "GetCurrentEpistemicPosition",
                "GetUnderstandingProjectionInputs",
                "GetEvidencePack",
                "GetCapabilityEvidenceState",
            ]
        );
    }

    #[test]
    fn only_context_reconstruction_intent_plans() {
        for mode in [
            QueryMode::CurrentPosition,
            QueryMode::HistoricalReconstruction,
            QueryMode::Provenance,
            QueryMode::Navigation,
            QueryMode::Verification,
            QueryMode::ChangeImpact,
        ] {
            match plan_context_reconstruction_query(
                &input(mode, "task:task-7"),
                "scope-task",
                "evidence-alpha",
                "8",
                "position-one",
            ) {
                Err(BridgeError::Port(PortFailure::Unsupported { capability, .. })) => {
                    assert_eq!(capability, "ContextReconstruction");
                }
                other => panic!("non-reconstruction intent must fail closed: {other:?}"),
            }
        }
        plan("task:task-7").expect("ContextReconstruction intent plans");
    }

    #[test]
    fn rejects_free_text_resource_uri_and_bad_selectors() {
        // Free text without the exact `task:` form is not a selector.
        assert!(matches!(
            plan("retrieve the task context"),
            Err(BridgeError::InvalidArgument { field, .. }) if field == "query.query"
        ));
        // Exact expansion uses the resource path, not a query.
        let mut with_uri = input(QueryMode::ContextReconstruction, "task:task-7");
        with_uri.exact_resource_uri = Some("eliot://resource/task-7".to_owned());
        assert!(matches!(
            plan_context_reconstruction_query(
                &with_uri,
                "scope-task",
                "evidence-alpha",
                "8",
                "position-one",
            ),
            Err(BridgeError::InvalidArgument { field, .. })
                if field == "query.exact_resource_uri"
        ));
        // Zero, non-numeric, and blank evidence bounds fail closed.
        for bound in ["0", "ten", "  "] {
            assert!(
                plan_context_reconstruction_query(
                    &input(QueryMode::ContextReconstruction, "task:task-7"),
                    "scope-task",
                    "evidence-alpha",
                    bound,
                    "position-one",
                )
                .is_err(),
                "bound {bound:?} must fail closed"
            );
        }
        // Blank scope, subject, and position fail closed before transport.
        assert!(matches!(
            plan_context_reconstruction_query(
                &input(QueryMode::ContextReconstruction, "task:task-7"),
                "  ",
                "evidence-alpha",
                "8",
                "position-one",
            ),
            Err(BridgeError::InvalidArgument { field, .. }) if field == "query.scope_id"
        ));
        assert!(matches!(
            plan_context_reconstruction_query(
                &input(QueryMode::ContextReconstruction, "task:task-7"),
                "scope-task",
                "  ",
                "8",
                "position-one",
            ),
            Err(BridgeError::InvalidArgument { field, .. })
                if field == "query.evidence_subject"
        ));
        assert!(matches!(
            plan_context_reconstruction_query(
                &input(QueryMode::ContextReconstruction, "task:task-7"),
                "scope-task",
                "evidence-alpha",
                "8",
                "  ",
            ),
            Err(BridgeError::InvalidArgument { field, .. }) if field == "query.position"
        ));
    }

    #[test]
    fn projects_bounded_projection_without_current_position_claim() {
        let plan = plan("task:task-7").expect("exact selector plans");
        let payload = json!({"roles": [], "state_fence": "fence-1"});
        let projection = project_context_reconstruction_projection(&plan, payload.clone());
        assert_eq!(projection.kind, ProjectionKind::Projection);
        assert_eq!(projection.proof_ceiling, ProofCeiling::ScopedVerification);
        assert!(
            projection
                .proof_ceiling
                .is_at_most(ProofCeiling::ScopedVerification)
        );
        assert_eq!(projection.content["operation"], "ContextReconstruction");
        assert_eq!(projection.content["task_id"], "task-7");
        assert_eq!(projection.content["scope_id"], "scope-task");
        assert_eq!(projection.content["context_reconstruction"], payload);
        assert!(projection.artifacts.is_empty());
        assert!(projection.resource.is_none());
        assert!(projection.durable_job.is_none());
    }
}
