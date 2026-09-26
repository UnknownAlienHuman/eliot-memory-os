//! Governor local read serving adapter (HANDOFF-LRR-GOV, #18).
//!
//! Per-call factory over [`DaemonComposition::context_read_client`]:
//! builds the `KernelContextReadClient` for the caller-held
//! [`DaemonKernelClient`], wraps it in the Governor `ReadService`, and
//! answers through [`LocalReadPort`]. The composition retains no client and
//! no thread, so a Governor refresh surfaces as an exact fence mismatch
//! instead of silent divergence.
//!
//! Caller chain: MGR01 kernel caller -> this factory -> `ReadService` over
//! `KernelContextReadClient` -> store-backed `QueryResult` consumer
//! (projection via `eliot-mcp`, persistence via the existing ORS result
//! path).
//!
//! Production edges out of this module:
//! [`forward_admitted_local_read`] forwards one admitted `eliot.query` pair
//! to the Kernel `local_read` leg over the retained authenticated session
//! and returns the persisted result body. `eliot.packet` follows the same
//! claim/result lifecycle but is served by the production campaign compiler;
//! [`serve_admitted_local_read`] remains the query-only local twin
//! ([`KernelContextReadClient::execute_local_read`] over
//! [`LocalReadPort::evidence_query`]) and returns the exact evidence record.
//!
//! Query is fully live (`Verification` + `GetEvidencePack`); projection
//! inputs stay port-shape fail-closed `Unavailable` until MGR04 (#19)
//! activates the storage operation.
//!
//! Context reconstruction (#2857): the third local-serving edge. One admitted
//! `eliot.query` pair whose `arguments.intent.mode` is exactly
//! [`CONTEXT_RECONSTRUCTION_QUERY_MODE`] is served HERE instead of forwarded
//! on the Kernel `local_read` leg, because that leg answers exactly one
//! bounded `GetEvidencePack` and cannot answer the seven-role closure.
//! [`serve_context_reconstruction`] builds the exact
//! [`ContextReconstructionRequest`] from the ADMITTED envelope plus the
//! admitted tool bytes ([`context_reconstruction_request`]), calls
//! [`eliot_governor::GovernorContextInputs::reconstruct`] through the
//! Governor `ReadService` over the same `KernelContextReadClient`
//! ([`reconstruct_context_inputs`]), and publishes the bounded seven-role
//! projection ([`project_context_reconstruction`]). The reconstruction
//! ALGORITHM stays in `eliot-governor`: this module resolves identity, binds
//! the result body, and refuses; it plans no read and judges no page.
//!
//! Authority discipline on this route:
//!
//! * scope comes from `envelope.identity` (the trusted `WorkScope`, else the
//!   durable `Session`), never from the tool body — the same resolution the
//!   Kernel admission mirror and the read client's own
//!   `KernelContextReadClient::check_local_read_capability` gate use;
//! * the state fence comes from the admitted envelope;
//! * the task identity comes from `envelope.identity.task_id`, the
//!   authenticated task the Kernel validated at admission. It is never taken
//!   from the tool body, and a pair whose envelope claims no task is refused
//!   rather than given a fabricated `TaskFrame` selector;
//! * the tool bytes are proven to be the admitted bytes before any selector is
//!   read from them (`HostRequestInvokeReadPayload::validate` binds the
//!   canonical tool digest to `envelope.identity.payload_sha256`);
//! * every remaining selector, every per-role bound and the dependency-head
//!   map is an EXPLICIT argument in the closed
//!   `context_reconstruction` selector object. Missing, extra, blank,
//!   wildcard, mistyped or over-bound members are a typed refusal, never a
//!   default, a fabricated `all` selector, or an empty page.

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{
    ClockReading, ProductId, RequestMetadata, SessionId, SourceId, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_governor::{
    ContextReconstructionRequest, GovernorContextInputs, KernelPortError, ROLE_AFFORDANCES,
    ROLE_ATTENTION_CONFLICT, ROLE_CUE_ACTIVATION, ROLE_EPISTEMIC_POSITION, ROLE_EVIDENCE_ASSURANCE,
    ROLE_NEGATIVE_MEMORY, ROLE_TASK_FRAME, RoleAcquisition, SevenRoleInputs,
};
use eliot_protocol::{
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope,
    HostRequestInvokeReadPayload, HostRequestResultBody, LocalReadAttempt,
};
use eliot_read::{LocalReadPort, QueryResult, ReadError, ReadService, StoreReadFailure};
use eliot_store_api::{EVIDENCE_PACK_MAX_RECORDS, RevisionKey, ScopeId};
use serde::Serialize;
use serde_json::{Map, Value};

use super::{DaemonComposition, DaemonKernelClient, KernelContextReadClient, SERVICE_NAME};

/// Forwards one admitted `eliot.query` pair to the Kernel `local_read` leg.
///
/// Production kernel-caller bridge over the retained authenticated session:
/// the pair proves its closed linkage and fence binding inside
/// [`DaemonKernelClient::local_read_async`], travels as the `"local_read"`
/// operation with the Kernel-issued attempt capability, and the persisted
/// result body behind the admitted receipt+record returns carrying that same
/// attempt for the submit leg. Kernel remains the admission and persistence
/// authority; this function performs no admission decision and no consistency
/// algorithm. A wrong fence or malformed pair fails closed before any
/// transport. A packet is dispatched by the campaign poller after its exact
/// owner-read and Context-compiler work, then uses this same result-submit
/// contract.
pub async fn forward_admitted_local_read(
    kernel: &DaemonKernelClient,
    envelope: HostRequestEnvelope,
    tool: serde_json::Value,
    attempt: LocalReadAttempt,
) -> Result<HostRequestResultBody, KernelPortError> {
    kernel.local_read_async(envelope, tool, attempt).await
}

/// Serves one admitted `eliot.query` pair through the Governor read port.
///
/// Production local-serving edge twinning the Kernel admission mirror: the
/// closed capability gate runs before any read, the envelope fence must equal
/// the caller-observed admitted fence, and the closed selectors serve exactly
/// one bounded [`LocalReadPort::evidence_query`] whose answer must echo the
/// evidence operation and the admitted fence. Returns the exact evidence
/// record, never a bare admission. `eliot.packet` is dispatched by the
/// production campaign compiler rather than this query-only twin; a wrong
/// fence or substituted answer fails closed, never `Ok`-empty.
///
/// The port and the fence stay per-call parameters (rather than retained
/// state) so the composition retains no client and no thread.
pub async fn serve_admitted_local_read(
    reads: &impl LocalReadPort,
    admitted_fence: &StateFence,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<QueryResult, ReadError> {
    KernelContextReadClient::execute_local_read(reads, admitted_fence, envelope, tool).await
}

/// Answers one bounded Governor evidence query through the local read port.
///
/// Threads the admitted fence via `ctx`, the explicit trusted `scope`, the
/// exact `subject`, and the explicit `max_records` bound. Returns the exact
/// record/provenance on success; a wrong fence or an over-bound request is
/// refused fail-closed.
pub async fn answer_evidence_query(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    subject: String,
    max_records: u32,
) -> Result<QueryResult, ReadError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|_| ReadError::Store(StoreReadFailure::Unavailable))?;
    let service = ReadService::new(client);
    service
        .evidence_query(ctx, scope, subject, max_records)
        .await
}

/// Answers one Governor projection-inputs read (port-shape only).
///
/// Validates `packet_ref` / `material_refs` and the facade request shape,
/// then fails closed with a typed `Unavailable` store error until MGR04
/// (#19) activates the storage operation. Never `Ok`-empty, never canned.
pub async fn answer_projection_inputs(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    packet_ref: Option<String>,
    material_refs: Vec<String>,
) -> Result<QueryResult, ReadError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|_| ReadError::Store(StoreReadFailure::Unavailable))?;
    let service = ReadService::new(client);
    service
        .projection_inputs(ctx, scope, packet_ref, material_refs)
        .await
}

/// The one `eliot.query` intent mode this route serves locally.
///
/// The Kernel's local-read admission mirror already admits this mode for the
/// bounded evidence read (`LOCAL_READ_QUERY_MODES` in the read client); this
/// constant is the discriminator the daemon poller uses to hand the
/// seven-role closure to [`serve_context_reconstruction`] instead.
pub const CONTEXT_RECONSTRUCTION_QUERY_MODE: &str = "context_reconstruction";

/// The admitted query capability, the only capability whose pairs this poller
/// ever claims (`host_request_route::KernelComposition::claim_local_read_pair`).
const ADMITTED_QUERY_CAPABILITY: &str = "eliot.query";

/// The closed `eliot.query` argument set this route reads.
///
/// `intent`, `query` and `exact_resource_uri` are the MCP `QueryInput`
/// members every `eliot.query` pair carries; `context_reconstruction` is the
/// one member this mode adds, holding the owner-resolved selector set. Any
/// other member is a typed refusal, so this route can never be handed a
/// widened argument vocabulary by a later surface.
const RECONSTRUCTION_QUERY_ARGUMENTS: [&str; 4] = [
    "intent",
    "query",
    "exact_resource_uri",
    "context_reconstruction",
];

/// The member carrying the closed reconstruction selector set.
const RECONSTRUCTION_SELECTOR_KEY: &str = "context_reconstruction";

/// The closed member set a reconstruction request must state explicitly.
///
/// Every member maps 1:1 onto a member of
/// [`ContextReconstructionRequest`] or onto one of the store catalogue's
/// declared selectors for a role read. `task_id` is deliberately absent: it is
/// the authenticated envelope identity, never a tool-body member. A member
/// that is not required and not one of the optional members below is refused,
/// so a widened or duplicated selector can never travel.
const RECONSTRUCTION_REQUIRED_MEMBERS: [&str; 12] = [
    "affordance_max_records",
    "affordance_skill_id",
    "attention_max_records",
    "dependency_revisions",
    "epistemic_position",
    "evidence_max_records",
    "evidence_subject",
    "negative_memory_max_records",
    "negative_memory_selector",
    "projection_max_records",
    "projection_selector",
    "task_max_records",
];

/// The only optional reconstruction member.
///
/// `None` (key absent) is the declared "no specific problem is requested"
/// contract option of `GetAttentionAndProblems`, which the owner handler
/// answers with its own exact null; a PRESENT key must still be one exact
/// non-blank identity, and a JSON `null` is refused rather than carried as a
/// substituted selector.
const RECONSTRUCTION_OPTIONAL_MEMBERS: [&str; 1] = ["attention_problem_id"];

/// Selector spellings refused because they mean "every source" rather than
/// one exact owner-resolved identity.
///
/// The store owner still decides what a selector matches; this is the daemon
/// route's own narrowing of the issue's "no fabricated `all`/empty selector"
/// rule, kept as a closed list rather than a prefix or pattern test so no new
/// spelling can be waved through.
const RECONSTRUCTION_WILDCARD_SELECTORS: [&str; 2] = ["all", "*"];

/// Bound on one refusal reason. Reasons are bounded role metadata; the full
/// provider or contract error stays in the read path.
const MAX_RECONSTRUCTION_REASON_BYTES: usize = 240;

/// Fail-closed, typed outcome vocabulary for one local reconstruction request.
///
/// Every variant is terminal for the claimed pair: the request is refused, a
/// result body still settles that pair through the existing idempotent submit
/// leg, and no empty, partial or substituted reconstruction is ever published
/// in place of the refusal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContextReconstructionRefusal {
    /// The admitted pair does not resolve the exact owner-resolved selector
    /// set: a missing, extra, blank, wildcard, mistyped or over-bound argument,
    /// a task-less envelope, or an evidence subject that is not the exact
    /// `subject:` selector the Kernel admitted for this pair.
    RequestInvalid {
        /// Bounded verbatim reason.
        reason: String,
    },
    /// The read client could not be built at the admitted fence, so no
    /// reconstruction could be attempted at all.
    CompositionUnavailable {
        /// Bounded verbatim reason.
        reason: String,
    },
    /// The Governor reconstruction refused: a malformed request, a missing
    /// dependency closure, or source heads that moved during acquisition.
    /// Never downgraded to a partial or empty seven-role view.
    ReconstructionRefused {
        /// Bounded verbatim reason.
        reason: String,
    },
    /// The bounded projection could not be bound into the response object.
    ProjectionInvalid {
        /// Bounded verbatim reason.
        reason: String,
    },
    /// The result body could not be bound. The pair still settles: the refusal
    /// itself is re-bound as a bounded `ResultBodyInvalid` answer.
    ResultBodyInvalid {
        /// Bounded verbatim reason.
        reason: String,
    },
}

/// The complete admitted parent-request identity one answer is bound to.
///
/// This is the parent identity #2563 item 4 asks for: the authenticated
/// request/session/task/`WorkScope` the Kernel admitted, the capability it
/// validated, the operation handle and envelope digest the submitted body
/// binds, the Kernel-minted attempt, and the exact scope every role projection
/// was read under. `scope_id` is `None` only when the envelope resolved no
/// trusted scope and the request was refused before any read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextReconstructionBinding {
    /// Admitted request identity from the Kernel-minted envelope.
    pub request_id: String,
    /// The capability the Kernel admitted and validated for this pair.
    pub capability: String,
    /// Deterministic operation handle the submitted result body binds.
    pub operation_id: String,
    /// Admitted envelope digest, which the submitted body binds as its
    /// `request_sha256`.
    pub envelope_sha256: String,
    /// Kernel-minted fenced attempt the submitted body binds.
    pub attempt_id: String,
    /// Authenticated durable Session the envelope claimed, when it claims one.
    pub session_id: Option<String>,
    /// Authenticated Governor task the envelope claimed, when it claims one.
    pub task_id: Option<String>,
    /// Authenticated `WorkScope` the envelope claimed, when it claims one.
    pub work_scope_id: Option<String>,
    /// The exact scope every role projection was read under, when the request
    /// resolved one.
    pub scope_id: Option<String>,
}

/// The wire answer for one local `context_reconstruction` pair.
///
/// Either the finished seven-role projection with the exact selector set and
/// bound parent identity it answers, or the typed refusal with the same bound
/// identity. There is no third shape: a route that cannot finish reports the
/// refusal, never a truncated success.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ContextReconstructionOutcome {
    /// The declared closure finished and all seven role slots are reported.
    Reconstructed {
        /// The admitted parent-request identity this answer is bound to.
        identity: ContextReconstructionBinding,
        /// The exact owner-resolved selector set and per-role bounds the
        /// reconstruction was asked for, echoed unchanged.
        request: Value,
        /// The bounded seven-role projection.
        inputs: Value,
    },
    /// The request was refused fail-closed.
    Refused {
        /// The admitted parent-request identity this refusal is bound to.
        identity: ContextReconstructionBinding,
        /// The typed refusal.
        refusal: ContextReconstructionRefusal,
    },
}

/// Reports whether one claimed pair is the local context-reconstruction query.
///
/// Narrow by construction, in the same shape as
/// [`is_controlboard_read_tool`](crate::is_controlboard_read_tool): the Kernel
/// only ever queues and claims pairs whose `envelope.identity.capability` and
/// `tool.name` are both `eliot.query`
/// (`host_request_route::{local_read_selectors_from_tool,
/// KernelComposition::claim_local_read_pair}`), and this predicate adds the one
/// intent mode that selects the seven-role closure. Every other mode, and
/// `eliot.packet`, keeps the existing Kernel `local_read` forward path
/// byte-identically.
#[must_use]
pub fn is_context_reconstruction_query(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> bool {
    if envelope.identity.capability != ADMITTED_QUERY_CAPABILITY {
        return false;
    }
    let Some(arguments) = tool
        .as_object()
        .filter(|object| {
            object
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == ADMITTED_QUERY_CAPABILITY)
        })
        .and_then(|object| object.get("arguments"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    arguments
        .get("intent")
        .and_then(Value::as_object)
        .and_then(|intent| intent.get("mode"))
        .and_then(Value::as_str)
        .is_some_and(|mode| mode == CONTEXT_RECONSTRUCTION_QUERY_MODE)
}

/// Resolves the trusted scope of one admitted pair.
///
/// The single scope source for this route: the envelope's `WorkScope` identity,
/// else its durable `Session` identity, and never a tool-body member. This is
/// the same resolution `host_request_route::trusted_local_read_scope` and the
/// read client's own `KernelContextReadClient::check_local_read_capability`
/// gate apply, so the reconstruction reads exactly the scope the Kernel
/// admitted the pair under and a caller-selected scope is structurally
/// impossible.
fn reconstruction_scope(
    envelope: &HostRequestEnvelope,
) -> Result<ScopeId, ContextReconstructionRefusal> {
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
        })
        .ok_or_else(|| {
            request_invalid(
                "context reconstruction requires one exact trusted envelope scope; the tool body never supplies it",
            )
        })?;
    ScopeId::new(scope_text).map_err(|error| {
        request_invalid(format!(
            "context reconstruction envelope scope is not a valid scope: {error}"
        ))
    })
}

/// Builds the exact [`ContextReconstructionRequest`] for one admitted pair.
///
/// The envelope is the only authority for scope, fence and task identity; the
/// admitted tool bytes are the only source for the remaining owner-resolved
/// selectors, and those bytes are proven to be the admitted bytes first
/// ([`HostRequestInvokeReadPayload::validate`] binds the canonical tool digest
/// to `envelope.identity.payload_sha256`). Every selector, every per-role
/// bound and the dependency-head map must be stated explicitly: a missing,
/// extra, blank, wildcard, mistyped or over-bound member is
/// [`ContextReconstructionRefusal::RequestInvalid`], never a default, a
/// fabricated `all` selector, or an empty dependency set. The assembled
/// request is then validated by its own owner
/// ([`ContextReconstructionRequest::validate`]) and that verdict is propagated,
/// so this constructor can neither widen nor relax the request contract.
pub fn context_reconstruction_request(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<ContextReconstructionRequest, ContextReconstructionRefusal> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|error| {
        request_invalid(format!(
            "context reconstruction requires the exact admitted tool bytes: {error}"
        ))
    })?;
    let arguments = reconstruction_arguments(tool)?;
    let selectors = arguments
        .get(RECONSTRUCTION_SELECTOR_KEY)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            request_invalid(format!(
                "context reconstruction requires its closed {RECONSTRUCTION_SELECTOR_KEY} selector object"
            ))
        })?;
    for member in RECONSTRUCTION_REQUIRED_MEMBERS {
        if !selectors.contains_key(member) {
            return Err(request_invalid(format!(
                "context reconstruction requires its explicit {member} member"
            )));
        }
    }
    for member in selectors.keys() {
        if !RECONSTRUCTION_REQUIRED_MEMBERS.contains(&member.as_str())
            && !RECONSTRUCTION_OPTIONAL_MEMBERS.contains(&member.as_str())
        {
            return Err(request_invalid(format!(
                "context reconstruction member {member:?} is outside the closed selector set"
            )));
        }
    }
    let evidence_subject = reconstruction_selector(selectors, "evidence_subject")?;
    if evidence_subject != admitted_query_subject(arguments)? {
        return Err(request_invalid(
            "context reconstruction evidence_subject must be the exact subject: selector the Kernel admitted for this pair",
        ));
    }
    let attention_problem_id = match selectors.get("attention_problem_id") {
        None => None,
        Some(value) => Some(reconstruction_selector_text(value, "attention_problem_id")?),
    };
    let request = ContextReconstructionRequest {
        scope_id: reconstruction_scope(envelope)?,
        dependency_revisions: reconstruction_dependency_revisions(selectors)?,
        epistemic_position: reconstruction_selector(selectors, "epistemic_position")?,
        evidence_subject,
        evidence_max_records: reconstruction_bound(selectors, "evidence_max_records")?,
        task_id: reconstruction_task_id(envelope)?,
        task_max_records: reconstruction_bound(selectors, "task_max_records")?,
        attention_problem_id,
        attention_max_records: reconstruction_bound(selectors, "attention_max_records")?,
        projection_selector: reconstruction_selector(selectors, "projection_selector")?,
        projection_max_records: reconstruction_bound(selectors, "projection_max_records")?,
        negative_memory_selector: reconstruction_selector(selectors, "negative_memory_selector")?,
        negative_memory_max_records: reconstruction_bound(
            selectors,
            "negative_memory_max_records",
        )?,
        affordance_skill_id: reconstruction_selector(selectors, "affordance_skill_id")?,
        affordance_max_records: reconstruction_bound(selectors, "affordance_max_records")?,
    };
    request.validate().map_err(|error| {
        request_invalid(format!(
            "context reconstruction request is not owner-valid: {error}"
        ))
    })?;
    Ok(request)
}

/// Reads and closes the `eliot.query` argument object for this mode.
fn reconstruction_arguments(
    tool: &serde_json::Value,
) -> Result<&Map<String, Value>, ContextReconstructionRefusal> {
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .and_then(Value::as_object)
        .ok_or_else(|| request_invalid("eliot.query arguments must be a JSON object"))?;
    for key in arguments.keys() {
        if !RECONSTRUCTION_QUERY_ARGUMENTS.contains(&key.as_str()) {
            return Err(request_invalid(format!(
                "eliot.query argument {key:?} is outside the context_reconstruction argument set"
            )));
        }
    }
    let mode = arguments
        .get("intent")
        .and_then(Value::as_object)
        .and_then(|intent| intent.get("mode"))
        .and_then(Value::as_str)
        .ok_or_else(|| request_invalid("query intent mode must be one exact string"))?;
    if mode != CONTEXT_RECONSTRUCTION_QUERY_MODE {
        return Err(request_invalid(format!(
            "query intent mode {mode:?} is not the context reconstruction mode"
        )));
    }
    if arguments
        .get("exact_resource_uri")
        .is_some_and(|value| !value.is_null())
    {
        return Err(request_invalid(
            "exact resource reads use the resource path, not a query",
        ));
    }
    Ok(arguments)
}

/// Returns the exact `subject:` selector the Kernel admitted for this pair.
///
/// The Kernel only enqueues and claims an `eliot.query` pair whose `query` is
/// one exact `subject:` selector
/// (`host_request_route::local_read_selectors_from_tool`), so this reads the
/// same member the admission mirror reads and refuses a substituted or
/// free-text form rather than adopting a second query language.
fn admitted_query_subject(
    arguments: &Map<String, Value>,
) -> Result<String, ContextReconstructionRefusal> {
    arguments
        .get("query")
        .and_then(Value::as_str)
        .and_then(|query| query.strip_prefix("subject:"))
        .map(str::trim)
        .filter(|subject| !subject.is_empty() && !subject.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| {
            request_invalid("query must be the one exact subject: selector the Kernel admitted")
        })
}

/// Returns the authenticated task identity the reconstruction binds.
///
/// The `TaskFrame` role reads `GetTaskState` for one exact `task_id`, so the
/// only acceptable source is the envelope identity the Kernel validated at
/// admission. A pair whose envelope claims no task is refused: the route never
/// invents a task id, and never reads the task from the tool body, whose
/// `query` member is the Kernel's evidence `subject:` selector.
fn reconstruction_task_id(
    envelope: &HostRequestEnvelope,
) -> Result<String, ContextReconstructionRefusal> {
    envelope
        .identity
        .task_id
        .as_deref()
        .filter(|task| !task.trim().is_empty() && !task.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| {
            request_invalid(
                "context reconstruction requires the authenticated envelope task identity; the task-frame role is never given a fabricated task id",
            )
        })
}

/// Reads one required, exact owner-resolved selector member.
fn reconstruction_selector(
    selectors: &Map<String, Value>,
    member: &'static str,
) -> Result<String, ContextReconstructionRefusal> {
    let value = selectors.get(member).ok_or_else(|| {
        request_invalid(format!(
            "context reconstruction requires its explicit {member} selector"
        ))
    })?;
    reconstruction_selector_text(value, member)
}

/// Reads one exact, non-blank, wildcard-free owner-resolved selector.
fn reconstruction_selector_text(
    value: &Value,
    member: &'static str,
) -> Result<String, ContextReconstructionRefusal> {
    let text = value.as_str().ok_or_else(|| {
        request_invalid(format!(
            "context reconstruction {member} must be one exact string"
        ))
    })?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(request_invalid(format!(
            "context reconstruction {member} must be non-blank text with no control characters"
        )));
    }
    if RECONSTRUCTION_WILDCARD_SELECTORS.contains(&text) {
        return Err(request_invalid(format!(
            "context reconstruction {member} must name one exact source, never {text:?}"
        )));
    }
    Ok(text.to_owned())
}

/// Reads one explicit per-role bound.
///
/// The bound travels as a decimal STRING, mirroring the store catalogue's
/// declared `Subject` shape for `max_records` (`NamedReadRequest` refuses a
/// JSON number there), so exactly one spelling of an explicit bound exists on
/// this route end to end. Zero, a sign, whitespace, and anything outside
/// `1..=EVIDENCE_PACK_MAX_RECORDS` are refused.
fn reconstruction_bound(
    selectors: &Map<String, Value>,
    member: &'static str,
) -> Result<u32, ContextReconstructionRefusal> {
    let raw = selectors
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            request_invalid(format!(
                "context reconstruction requires its explicit decimal {member} bound"
            ))
        })?;
    if !is_exact_decimal(raw) {
        return Err(request_invalid(format!(
            "context reconstruction {member} must be one positive decimal bound"
        )));
    }
    let bound = raw.parse::<u32>().map_err(|error| {
        request_invalid(format!(
            "context reconstruction {member} must be one positive decimal bound: {error}"
        ))
    })?;
    if bound == 0 || bound > EVIDENCE_PACK_MAX_RECORDS {
        return Err(request_invalid(format!(
            "context reconstruction {member} must be within 1..=EVIDENCE_PACK_MAX_RECORDS"
        )));
    }
    Ok(bound)
}

/// Reads the explicit non-empty dependency-head map the exact-fence reads
/// bind.
///
/// Exact-fence consistency requires at least one declared dependency revision
/// ([`eliot_read::ReadError::MissingDependencies`]), so an absent or empty map
/// is refused here rather than reaching the read owner. Every revision is an
/// exact decimal and non-zero: a zero revision is a fabricated minimum, which
/// the owner would otherwise accept as "no dependency observed".
fn reconstruction_dependency_revisions(
    selectors: &Map<String, Value>,
) -> Result<BTreeMap<RevisionKey, u64>, ContextReconstructionRefusal> {
    let declared = selectors
        .get("dependency_revisions")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            request_invalid(
                "context reconstruction requires an explicit dependency_revisions object",
            )
        })?;
    if declared.is_empty() {
        return Err(request_invalid(
            "context reconstruction requires at least one dependency revision for exact-fence reads",
        ));
    }
    let mut revisions = BTreeMap::new();
    for (key, value) in declared {
        let raw = value.as_str().ok_or_else(|| {
            request_invalid(format!(
                "context reconstruction dependency revision {key:?} must be one decimal string"
            ))
        })?;
        if !is_exact_decimal(raw) {
            return Err(request_invalid(format!(
                "context reconstruction dependency revision {key:?} must be one exact decimal"
            )));
        }
        let revision = raw.parse::<u64>().map_err(|error| {
            request_invalid(format!(
                "context reconstruction dependency revision {key:?} is not a revision: {error}"
            ))
        })?;
        if revision == 0 {
            return Err(request_invalid(format!(
                "context reconstruction dependency revision {key:?} must be non-zero"
            )));
        }
        revisions.insert(
            RevisionKey::new(key.as_str()).map_err(|error| {
                request_invalid(format!(
                    "context reconstruction dependency key {key:?} is not a revision key: {error}"
                ))
            })?,
            revision,
        );
    }
    Ok(revisions)
}

/// Reports whether one token is an exact unsigned decimal literal.
///
/// Rejects every other spelling — an empty string, a sign, whitespace, a
/// fraction, an exponent — so one bound or revision has exactly one accepted
/// wire form.
fn is_exact_decimal(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit())
}

/// Builds the read metadata for one local reconstruction.
///
/// Same fence-bound shape as the local-read serving edge's `local_read_context`
/// helper inside `KernelContextReadClient::execute_local_read` (that helper is
/// module-private to the read client), with the admitted parent identity bound
/// in place of a fixed label so every read the reconstruction issues carries
/// the request, session and task that asked for it:
///
/// * `request_id`, `session_id` and `task_id` are the envelope's own admitted
///   identities, so the whole closure is attributable to one admitted pair;
/// * `state_fence` is the ADMITTED envelope fence, so a Governor refresh
///   between claim and read surfaces as an exact fence mismatch rather than a
///   previous generation served as current;
/// * `product_id` / `source_id` are the daemon service identity and `clock`
///   carries no observation, exactly as the twin does.
fn reconstruction_request_context(
    envelope: &HostRequestEnvelope,
) -> Result<RequestMetadata, ContextReconstructionRefusal> {
    let context = RequestMetadata {
        request_id: envelope.identity.request_id.clone(),
        session_id: envelope
            .identity
            .session_id
            .as_deref()
            .map(SessionId::new)
            .transpose()
            .map_err(|error| {
                request_invalid(format!(
                    "admitted envelope session identity is not usable: {error}"
                ))
            })?,
        task_id: envelope
            .identity
            .task_id
            .as_deref()
            .map(TaskId::new)
            .transpose()
            .map_err(|error| {
                request_invalid(format!(
                    "admitted envelope task identity is not usable: {error}"
                ))
            })?,
        product_id: ProductId::new(SERVICE_NAME).map_err(|error| {
            request_invalid(format!("daemon product identity is not usable: {error}"))
        })?,
        source_id: SourceId::new(SERVICE_NAME).map_err(|error| {
            request_invalid(format!("daemon source identity is not usable: {error}"))
        })?,
        state_fence: envelope.state_fence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    context.validate().map_err(|error| {
        request_invalid(format!(
            "reconstruction read metadata is not contract-valid: {error}"
        ))
    })?;
    Ok(context)
}

/// Reconstructs the seven role slots on the live daemon read route.
///
/// Resolves the read client from the composition, builds the Governor
/// [`ReadService`] over it, and calls
/// [`eliot_governor::GovernorContextInputs::reconstruct`] — the ALGORITHM stays
/// in `eliot-governor`, including the before/after source-head closure, the
/// six-or-seven physical reads over seven role slots, the per-role disposition
/// classification and the shared role-page provenance rule. This function adds
/// no plan, no consistency step and no page judgement of its own.
///
/// A read failure that the Governor classifies per role stays a role
/// disposition. A composition failure, a bad request, a missing closure or
/// observed head churn fails the WHOLE call closed as a typed refusal: it never
/// becomes an empty or partial seven-role result.
pub async fn reconstruct_context_inputs(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    request: &ContextReconstructionRequest,
) -> Result<SevenRoleInputs, ContextReconstructionRefusal> {
    let client = composition.context_read_client(kernel).map_err(|error| {
        ContextReconstructionRefusal::CompositionUnavailable {
            reason: bounded_reason(&error.to_string()),
        }
    })?;
    let service = ReadService::new(client);
    // #2857: `reconstruct` is one bounded closure over six or seven reads, so
    // its state machine is far past the `large_futures` ceiling. Boxing the
    // inner future keeps THIS route's future small without splitting the
    // Governor's algorithm and without an `#[allow]`: the closure still runs
    // exactly once, with no retry and no continuation field.
    Box::pin(GovernorContextInputs::borrow(&service).reconstruct(ctx, request))
        .await
        .map_err(
            |error| ContextReconstructionRefusal::ReconstructionRefused {
                reason: bounded_reason(&error.to_string()),
            },
        )
}

/// The seven role slots in the same order as
/// [`SevenRoleInputs::role_states`], built from the same owner role labels.
///
/// The projection iterates this beside `role_states()` and cross-checks the
/// two label sequences, so the daemon cannot publish a different role
/// denominator, a missing slot, a duplicate slot, or a relabelled role than
/// the one the Governor reconstruction produced.
fn reconstruction_role_slots(inputs: &SevenRoleInputs) -> [(&'static str, &RoleAcquisition); 7] {
    [
        (ROLE_TASK_FRAME, &inputs.task_frame),
        (ROLE_ATTENTION_CONFLICT, &inputs.attention),
        (ROLE_EPISTEMIC_POSITION, &inputs.epistemic),
        (ROLE_CUE_ACTIVATION, &inputs.cue),
        (ROLE_NEGATIVE_MEMORY, &inputs.negative_memory),
        (ROLE_EVIDENCE_ASSURANCE, &inputs.evidence),
        (ROLE_AFFORDANCES, &inputs.affordances),
    ]
}

/// Projects the reconstructed seven-role closure into the bounded response.
///
/// Every slot crosses under its owner role label with the EXACT
/// `ProjectionState` disposition the Governor classifier produced, its exact
/// named-read operation, its exact observed revision heads and its exact owner
/// payload. A role with no payload carries a typed `detail` — the disposition
/// itself, plus its own reason when the disposition declares one — and never a
/// `null`, an empty object, or a substituted previous generation. The
/// before/after dependency heads, the fence, the scope, the epistemic readback
/// and the unsupported-role list cross unchanged, so a consumer can tell an
/// authoritative `KnownEmpty` from an unreadable source.
pub fn project_context_reconstruction(
    inputs: &SevenRoleInputs,
) -> Result<Value, ContextReconstructionRefusal> {
    let mut roles = Map::with_capacity(inputs.role_states().len());
    for ((state_role, state), (role, acquisition)) in inputs
        .role_states()
        .into_iter()
        .zip(reconstruction_role_slots(inputs))
    {
        if state_role != role || *state != acquisition.state {
            return Err(projection_invalid(
                "the seven-role denominator and the role slots disagree on slot order or disposition",
            ));
        }
        roles.insert(role.to_owned(), project_role(role, acquisition)?);
    }
    let mut object = Map::with_capacity(9);
    object.insert(
        "operation".to_owned(),
        Value::String("ContextReconstruction".to_owned()),
    );
    object.insert(
        "intent_mode".to_owned(),
        Value::String(CONTEXT_RECONSTRUCTION_QUERY_MODE.to_owned()),
    );
    object.insert(
        "scope_id".to_owned(),
        Value::String(inputs.scope_id.as_str().to_owned()),
    );
    object.insert(
        "state_fence".to_owned(),
        encode_member("state_fence", &inputs.state_fence)?,
    );
    object.insert(
        "heads_before".to_owned(),
        encode_member("heads_before", &inputs.heads_before)?,
    );
    object.insert(
        "heads_after".to_owned(),
        encode_member("heads_after", &inputs.heads_after)?,
    );
    object.insert(
        "epistemic_readback".to_owned(),
        encode_member("epistemic_readback", &inputs.epistemic_readback)?,
    );
    object.insert(
        "unsupported_roles".to_owned(),
        Value::Array(
            inputs
                .unsupported_role_names()
                .into_iter()
                .map(|role| Value::String(role.to_owned()))
                .collect(),
        ),
    );
    object.insert("roles".to_owned(), Value::Object(roles));
    Ok(Value::Object(object))
}

/// Projects one role slot under its owner label.
///
/// The exact [`RoleAcquisition`] crosses unchanged — including its declared
/// `state`, which is the Governor's own `ProjectionState` encoding and
/// therefore the single page-provenance rule's verdict, not a second mapping —
/// except that a role with no payload drops its `null` payload member and
/// carries a typed `detail` instead.
fn project_role(
    role: &str,
    acquisition: &RoleAcquisition,
) -> Result<Value, ContextReconstructionRefusal> {
    let Value::Object(members) = encode_member(role, acquisition)? else {
        return Err(projection_invalid(format!(
            "role {role} does not encode as a JSON object"
        )));
    };
    let mut object = Map::with_capacity(members.len() + 2);
    object.insert("role".to_owned(), Value::String(role.to_owned()));
    let mut detail = None;
    for (member, value) in members {
        if member == "payload" && value.is_null() {
            detail = Some(role_detail(acquisition)?);
            continue;
        }
        object.insert(member, value);
    }
    if let Some(detail) = detail {
        object.insert("detail".to_owned(), detail);
    }
    Ok(Value::Object(object))
}

/// The typed detail a role with no payload carries.
///
/// The disposition is read off the role's own encoded `ProjectionState`, so it
/// is exactly the vocabulary the Governor classifier produced. `COMPLETE`,
/// `KNOWN_EMPTY` and `MISSING` declare no reason; the detail then names the
/// disposition alone, which is still a typed statement and never an empty or
/// substituted payload.
fn role_detail(acquisition: &RoleAcquisition) -> Result<Value, ContextReconstructionRefusal> {
    let state = encode_member("state", &acquisition.state)?;
    let disposition = state
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| projection_invalid("a role disposition did not carry its own state tag"))?;
    let mut detail = Map::with_capacity(2);
    detail.insert(
        "disposition".to_owned(),
        Value::String(disposition.to_owned()),
    );
    if let Some(reason) = state.get("reason").and_then(Value::as_str) {
        detail.insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    Ok(Value::Object(detail))
}

/// Binds the complete admitted parent-request identity of one answer.
fn context_reconstruction_identity(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    scope: Option<&str>,
) -> ContextReconstructionBinding {
    ContextReconstructionBinding {
        request_id: envelope.identity.request_id.as_str().to_owned(),
        capability: envelope.identity.capability.clone(),
        operation_id: attempt.operation_id.clone(),
        envelope_sha256: envelope.envelope_sha256.clone(),
        attempt_id: attempt.attempt_id.clone(),
        session_id: envelope.identity.session_id.clone(),
        task_id: envelope.identity.task_id.clone(),
        work_scope_id: envelope.identity.work_scope_id.clone(),
        scope_id: scope.map(str::to_owned),
    }
}

/// Binds one reconstruction outcome into the submit-leg result body.
///
/// The body is the exact shape the Kernel submit leg validates first: the
/// Kernel-issued operation handle, the admitted envelope digest as
/// `request_sha256`, a `result_digest` taken over the
/// [`canonical_json_bytes`] of this exact response, and the current attempt.
/// [`HostRequestResultBody::validate`] is run, not assumed, because an
/// unvalidated body is a dropped pair.
pub fn context_reconstruction_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    outcome: &ContextReconstructionOutcome,
) -> Result<HostRequestResultBody, ContextReconstructionRefusal> {
    let response = serde_json::to_value(outcome)
        .map_err(|error| result_body_invalid(format!("outcome encoding: {error}")))?;
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| result_body_invalid(format!("outcome digest: {error}")))?;
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&bytes),
        response,
        attempt: Some(attempt.clone()),
    };
    body.validate()
        .map_err(|error| result_body_invalid(format!("result body shape: {error}")))?;
    Ok(body)
}

/// Serves one admitted `context_reconstruction` pair and returns its body.
///
/// The single production entry of this route: resolve the request, reconstruct
/// the seven roles over the composition's read client, project the bounded
/// answer, and bind it to the submit-leg result body. Every failure path ends
/// in a typed refusal that STILL settles the claimed pair — no refusal is ever
/// turned into a dropped pair, and no refusal is ever published as an empty or
/// partial reconstruction.
///
/// Bounded by construction: exactly one request, one `reconstruct` call (one
/// read per role slot, no retry loop, no continuation field) and one body. When
/// the projection does not fit the bounded structured-response ceiling, the
/// whole answer becomes a typed refusal rather than a truncated success; the
/// per-role partial/unknown coverage that the closure DID observe is already
/// carried explicitly by each role's own disposition.
pub async fn serve_context_reconstruction(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> HostRequestResultBody {
    let reconstructed = Box::pin(reconstruction_outcome(
        composition,
        kernel,
        envelope,
        tool,
        attempt,
    ))
    .await;
    let outcome = match reconstructed {
        Ok(outcome) => outcome,
        Err(refusal) => ContextReconstructionOutcome::Refused {
            // The same single scope source is re-read here so a refused
            // answer is still bound to the scope the envelope resolved. It is
            // the same private resolver the constructor uses, not a second
            // scope authority.
            identity: context_reconstruction_identity(
                envelope,
                attempt,
                reconstruction_scope(envelope)
                    .ok()
                    .map(|scope| scope.as_str().to_owned())
                    .as_deref(),
            ),
            refusal,
        },
    };
    context_reconstruction_result_body(envelope, attempt, &outcome).unwrap_or_else(|error| {
        // A refusal that cannot be bound is itself the bound answer: the pair
        // still settles with the exact typed refusal, and the shape gate runs
        // on the body that actually leaves. The Kernel submit leg
        // (`submit_local_read_result_async`) runs
        // [`HostRequestResultBody::validate`] as its first act and is the final
        // authority over a result body, so this arm settles rather than drops
        // the pair or forges a valid one.
        let refused = ContextReconstructionOutcome::Refused {
            identity: context_reconstruction_identity(envelope, attempt, None),
            refusal: error,
        };
        context_reconstruction_result_body(envelope, attempt, &refused)
            .unwrap_or_else(|_| unbound_reconstruction_body(envelope, attempt, &refused))
    })
}

/// Runs the whole route once, or returns the typed refusal that stopped it.
async fn reconstruction_outcome(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<ContextReconstructionOutcome, ContextReconstructionRefusal> {
    let request = context_reconstruction_request(envelope, tool)?;
    let identity =
        context_reconstruction_identity(envelope, attempt, Some(request.scope_id.as_str()));
    let context = reconstruction_request_context(envelope)?;
    let inputs = Box::pin(reconstruct_context_inputs(
        composition,
        kernel,
        &context,
        &request,
    ))
    .await?;
    let projection = project_context_reconstruction(&inputs)?;
    let selectors = serde_json::to_value(&request)
        .map_err(|error| projection_invalid(format!("reconstruction request encoding: {error}")))?;
    Ok(ContextReconstructionOutcome::Reconstructed {
        identity,
        request: selectors,
        inputs: projection,
    })
}

/// Emits the bound refusal when even that refusal cannot be bound.
///
/// The arm exists for one case, and the case is not the response: the refusal
/// is a tagged enum of bounded plain strings, so it is already encoded and
/// digested. Nothing here may be invented to change the verdict, and a claimed
/// pair must still settle, so the same refused bytes are emitted once more —
/// with `result_digest` again taken over the exact canonical bytes of the exact
/// response emitted — and the same shape gate is run on the body that leaves.
fn unbound_reconstruction_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    outcome: &ContextReconstructionOutcome,
) -> HostRequestResultBody {
    let response = serde_json::to_value(outcome).unwrap_or(Value::Null);
    let result_digest =
        sha256_hex(&canonical_json_bytes(&response).unwrap_or_else(|_| b"null".to_vec()));
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest,
        response,
        attempt: Some(attempt.clone()),
    };
    let _shape_gate = body.validate();
    body
}

/// Encodes one projection member, refusing rather than substituting.
fn encode_member<T: Serialize>(
    member: &str,
    value: &T,
) -> Result<Value, ContextReconstructionRefusal> {
    serde_json::to_value(value)
        .map_err(|error| projection_invalid(format!("{member} encoding: {error}")))
}

/// Builds a bounded request refusal from one reason.
fn request_invalid(detail: impl std::fmt::Display) -> ContextReconstructionRefusal {
    ContextReconstructionRefusal::RequestInvalid {
        reason: bounded_reason(&detail.to_string()),
    }
}

/// Builds a bounded projection refusal from one reason.
fn projection_invalid(detail: impl std::fmt::Display) -> ContextReconstructionRefusal {
    ContextReconstructionRefusal::ProjectionInvalid {
        reason: bounded_reason(&detail.to_string()),
    }
}

/// Builds a bounded result-body refusal from one reason.
fn result_body_invalid(detail: impl std::fmt::Display) -> ContextReconstructionRefusal {
    ContextReconstructionRefusal::ResultBodyInvalid {
        reason: bounded_reason(&detail.to_string()),
    }
}

/// Renders one bounded, control-character-free refusal reason.
///
/// Argument keys and provider errors are data, so a reason is stripped of
/// control characters and truncated on a character boundary; the full detail
/// stays in the read path. A reason that is empty after stripping names itself
/// rather than crossing the wire as an empty string.
fn bounded_reason(detail: &str) -> String {
    let stripped: String = detail
        .chars()
        .map(|cell| if cell.is_control() { ' ' } else { cell })
        .collect();
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return "no further detail".to_owned();
    }
    if trimmed.len() <= MAX_RECONSTRUCTION_REASON_BYTES {
        return trimmed.to_owned();
    }
    let mut end = MAX_RECONSTRUCTION_REASON_BYTES;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_owned()
}
