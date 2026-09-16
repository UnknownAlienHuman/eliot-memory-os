//! Governed Claude Agent SDK sidecar execution behind the existing contracts.
//!
//! [`prepare`] admits one exact attempt from frozen inputs only: the X4
//! [`ProviderExecutionBinding`](eliot_agent_api::ProviderExecutionBinding)
//! attempt projection, the admitted
//! [`AgentAttempt`](eliot_agent_api::AgentAttempt), the current fence and
//! runtime generation, an exact [`ClaudeAdapterDescriptor`], the inert
//! [`ClaudeSidecarRequest`](crate::ClaudeSidecarRequest), the sealed X2
//! [`ProcessRequest`](eliot_process::ProcessRequest), a credential
//! [`SecretRef`](eliot_process::SecretRef) reference (never a raw secret),
//! the prior idempotency record, and the [`UnknownOutcomeGate`](crate::UnknownOutcomeGate).
//! Every rejection happens before any process or credential acquisition.
//!
//! [`ClaudeSidecarFactory`] then drives exactly one immutable sidecar
//! generation through the shared
//! [`ProcessExecutor`](eliot_process::ProcessExecutor) contour: single-take
//! [`ClaudeSidecarFactory::launch`], bounded
//! [`ClaudeRunningSidecar::ingest_line`] streaming with raw-evidence lineage,
//! [`ClaudeRunningSidecar::complete_terminal`] candidate extraction with
//! recomputed output digests, [`translate_candidate_result`] into
//! candidate-only [`AgentResult`](eliot_agent_api::AgentResult) records,
//! [`ClaudeSidecarFactory::cancel_running`] wired to the real
//! `cancel(operation_id)` plus deadline and [`CleanupState`](crate::CleanupState)
//! semantics, and [`ClaudeSidecarFactory::reconcile_same_operation`] which
//! admits a retry only on the digest derived from the exact reconcile
//! evidence. No second sidecar, route, or attempt is ever launched to escape
//! uncertainty, and [`try_promote_to_finish`](crate::try_promote_to_finish)
//! still proves no promotion path exists.

use std::sync::Arc;

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentAttempt, AgentResult, CancellationState, ClockReading,
    ContractError as AgentContractError, EffectCeiling, EventCursor, ExecutionOutcome,
    LowercaseSha256, PhysicalRouteObservationReceipt, ProviderExecutionBinding, ResourceGeneration,
    ResultDisposition, RouteFingerprint, RouteObservationState, StateFence, UsageReceipt,
    validate_execution_binding,
};
use eliot_process::{
    CancellationReceipt, CancellationStatus, OperationId, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessLifecycle, ProcessRequest,
    SecretRef,
};

use crate::{
    CLAUDE_SIDECAR_ADAPTER_ID, CLAUDE_SIDECAR_HOST_FAMILY, CLAUDE_SIDECAR_PROTOCOL_VERSION,
    CLAUDE_SIDECAR_TRANSPORT, CancellationEnvelope, ClaudeCandidateDisposition,
    ClaudeCandidateResult, ClaudeRequestKind, ClaudeResponseKind, ClaudeSidecarError,
    ClaudeSidecarRequest, ClaudeSidecarResponse, IdempotencyDecision, IdempotencyKey,
    MAX_FRAME_BYTES, MAX_WALL_TIME_MS, MIN_WALL_TIME_MS, NormalizedClaudeEvent, PreservedOrOmitted,
    StoredIdempotencyKey, UnknownOutcomeGate, acknowledge, claude_local_digest_256_hex,
    decide_idempotency, idempotency_key_for_request, normalize_event, preserve_or_omit,
    request_cancel, terminate, validate_monotonic,
};

// ---------------------------------------------------------------------------
// Adapter identity
// ---------------------------------------------------------------------------

/// Execution-unit namespace bound by [`validate_binding_for_claude`]. A
/// foreign-family binding quarantines as a binding mismatch, never as
/// attributed Claude output.
pub const CLAUDE_EXECUTION_UNIT_NAMESPACE: &str = "claude";

/// Current Claude-side factory revision checked by
/// [`ClaudeAdapterDescriptor::validate_for`]. Any other revision is stale and
/// rejected before any process or credential acquisition.
pub const CLAUDE_SIDECAR_FACTORY_REVISION: u64 = 1;

/// Event cursor stamped on translated candidate results.
pub const CLAUDE_RESULT_EVENT_CURSOR: &str = "claude-result";

/// Explicit reason recorded when the physical route could not be observed.
/// Absence is never synthesized from the requested route.
pub const CLAUDE_UNOBSERVED_ROUTE_REASON: &str =
    "claude physical route not separately observed; requested retained without synthesis";

// ---------------------------------------------------------------------------
// Error mapping (typed, no secret or provider-body material)
// ---------------------------------------------------------------------------

fn map_agent_contract(error: AgentContractError) -> ClaudeSidecarError {
    ClaudeSidecarError::BindingMismatch(error.to_string())
}

fn map_process_contract(error: eliot_process::ContractError) -> ClaudeSidecarError {
    ClaudeSidecarError::ExecutorRejected(error.to_string())
}

fn map_executor(error: ProcessExecutionError, attempt_id: &str) -> ClaudeSidecarError {
    match error {
        ProcessExecutionError::Contract(contract) => map_process_contract(contract),
        ProcessExecutionError::NotFound => ClaudeSidecarError::OperationNotFound,
        ProcessExecutionError::Unavailable(detail) => {
            ClaudeSidecarError::ExecutorUnavailable(detail)
        }
        ProcessExecutionError::EvidenceSink(sink) => {
            ClaudeSidecarError::ExecutorRejected(sink.message)
        }
        ProcessExecutionError::UnknownOutcome => {
            ClaudeSidecarError::UnknownOutcomeRequiresReconcile {
                attempt_id: attempt_id.to_owned(),
            }
        }
    }
}

fn typed_digest(hex: String) -> Result<LowercaseSha256, ClaudeSidecarError> {
    serde_json::from_value::<LowercaseSha256>(serde_json::Value::String(hex))
        .map_err(|_| ClaudeSidecarError::BindingMismatch("digest is not canonical".to_owned()))
}

// ---------------------------------------------------------------------------
// Binding / route validation (Claude family mirror of the Codex precedent)
// ---------------------------------------------------------------------------

/// Validate that a route fingerprint is exactly the local Claude sidecar
/// route. Shape first, then exact host family / adapter / transport identity.
pub fn validate_claude_route(route: &RouteFingerprint) -> Result<(), ClaudeSidecarError> {
    route.validate().map_err(map_agent_contract)?;
    if route.host_family != CLAUDE_SIDECAR_HOST_FAMILY
        || route.adapter != CLAUDE_SIDECAR_ADAPTER_ID
        || route.protocol_transport != CLAUDE_SIDECAR_TRANSPORT
    {
        return Err(ClaudeSidecarError::DescriptorMismatch(
            "route is not the local Claude sidecar route".to_owned(),
        ));
    }
    Ok(())
}

/// Validate that a recorded binding belongs to the Claude adapter family
/// before use: binding shape, exact Claude route, and the Claude execution
/// namespace. A foreign-family binding fails closed here, never as
/// attributed output.
pub fn validate_binding_for_claude(
    binding: &ProviderExecutionBinding,
) -> Result<(), ClaudeSidecarError> {
    binding.validate_internal().map_err(map_agent_contract)?;
    validate_claude_route(&binding.route)?;
    if binding.execution_unit.namespace != CLAUDE_EXECUTION_UNIT_NAMESPACE {
        return Err(ClaudeSidecarError::BindingMismatch(
            "execution unit is not in the claude namespace".to_owned(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Adapter descriptor (exact revision gate for the future #874 registry)
// ---------------------------------------------------------------------------

/// Exact adapter identity the factory was constructed for. The #874 registry
/// supplies this alongside the admitted input; any deviation in adapter id,
/// factory revision, or route fails before any process or credential
/// acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeAdapterDescriptor {
    /// Must equal [`CLAUDE_SIDECAR_ADAPTER_ID`](crate::CLAUDE_SIDECAR_ADAPTER_ID).
    pub adapter_id: String,
    /// Must equal [`CLAUDE_SIDECAR_FACTORY_REVISION`].
    pub factory_revision: u64,
    /// Must equal the bound [`RouteFingerprint`] by typed `==`.
    pub route: RouteFingerprint,
}

impl ClaudeAdapterDescriptor {
    /// Build the current descriptor for one exact route.
    pub fn current(route: RouteFingerprint) -> Self {
        Self {
            adapter_id: CLAUDE_SIDECAR_ADAPTER_ID.to_owned(),
            factory_revision: CLAUDE_SIDECAR_FACTORY_REVISION,
            route,
        }
    }

    /// Check exact descriptor identity against a recorded binding.
    pub fn validate_for(
        &self,
        binding: &ProviderExecutionBinding,
    ) -> Result<(), ClaudeSidecarError> {
        if self.adapter_id != CLAUDE_SIDECAR_ADAPTER_ID {
            return Err(ClaudeSidecarError::DescriptorMismatch(
                "adapter id is not the Claude sidecar adapter".to_owned(),
            ));
        }
        if self.factory_revision != CLAUDE_SIDECAR_FACTORY_REVISION {
            return Err(ClaudeSidecarError::DescriptorMismatch(
                "stale adapter factory revision".to_owned(),
            ));
        }
        if self.route != binding.route {
            return Err(ClaudeSidecarError::DescriptorMismatch(
                "descriptor route differs from the bound route".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Factory input / prepared attempt
// ---------------------------------------------------------------------------

/// Frozen factory inputs. Everything is supplied by composition; nothing is
/// minted here. `credential` is a provider/key reference only and is never
/// resolved, logged, or forwarded by this package.
pub struct ClaudeFactoryInput {
    /// Exact X4 attempt projection.
    pub binding: ProviderExecutionBinding,
    /// Admitted attempt the binding must agree with.
    pub admitted: AgentAttempt,
    /// Current fence for freshness (complete `==`, never compatibility).
    pub current_fence: StateFence,
    /// Current runtime generation for freshness (typed `==`).
    pub runtime_generation: ResourceGeneration,
    /// Exact adapter/factory/route revision expectation.
    pub descriptor: ClaudeAdapterDescriptor,
    /// Inert NDJSON request projection (query only).
    pub request: ClaudeSidecarRequest,
    /// Sealed X2 process binding; executable identity comes from admission.
    pub process_request: ProcessRequest,
    /// Credential reference only; never raw secret material.
    pub credential: SecretRef,
    /// Prior idempotency record for duplicate/conflict detection.
    pub prior: Option<StoredIdempotencyKey>,
    /// Unknown-outcome gate. `None` when no unknown outcome is on record for
    /// this attempt (fresh launch); `Some` after an unknown outcome was
    /// recorded, in which case preparation blocks until that exact gate is
    /// reconciled.
    pub gate: Option<UnknownOutcomeGate>,
}

impl std::fmt::Debug for ClaudeFactoryInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeFactoryInput")
            .field("binding", &self.binding)
            .field("admitted", &self.admitted)
            .field("current_fence", &self.current_fence)
            .field("runtime_generation", &self.runtime_generation)
            .field("descriptor", &self.descriptor)
            .field("request", &self.request)
            .field("process_request", &self.process_request)
            .field("credential", &"[redacted credential reference]")
            .field("prior", &self.prior)
            .field("gate", &self.gate)
            .finish()
    }
}

/// One admitted attempt ready to launch. Holds the single-take process
/// binding: the first [`ClaudeSidecarFactory::launch`] consumes it and any
/// further launch fails with [`ClaudeSidecarError::ProcessAlreadyStarted`].
pub struct ClaudePreparedAttempt {
    binding: ProviderExecutionBinding,
    request: ClaudeSidecarRequest,
    plan_digest: String,
    idempotency_key: IdempotencyKey,
    credential: SecretRef,
    gate: Option<UnknownOutcomeGate>,
    wall_time_ms: u64,
    process_request: Option<ProcessRequest>,
}

impl std::fmt::Debug for ClaudePreparedAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudePreparedAttempt")
            .field("binding", &self.binding)
            .field("request", &self.request)
            .field("plan_digest", &self.plan_digest)
            .field("idempotency_key", &self.idempotency_key)
            .field("credential", &"[redacted credential reference]")
            .field("gate", &self.gate)
            .field("wall_time_ms", &self.wall_time_ms)
            .field("process_request_present", &self.process_request.is_some())
            .finish()
    }
}

impl ClaudePreparedAttempt {
    /// The exact bound attempt projection.
    pub const fn binding(&self) -> &ProviderExecutionBinding {
        &self.binding
    }

    /// The admitted NDJSON request projection.
    pub const fn request(&self) -> &ClaudeSidecarRequest {
        &self.request
    }

    /// Correlation id shared by the request, stream frames, and terminal.
    pub fn request_id(&self) -> &str {
        self.request.request_id.as_str()
    }

    /// Digest of the canonical launch-plan JSON admitted for this attempt.
    pub fn plan_digest(&self) -> &str {
        self.plan_digest.as_str()
    }

    /// Idempotency key presented at preparation.
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Credential reference (opaque provider/key, never secret material).
    pub const fn credential(&self) -> &SecretRef {
        &self.credential
    }

    /// Unknown-outcome gate carried with this attempt, when any was on
    /// record at preparation.
    pub const fn gate(&self) -> Option<&UnknownOutcomeGate> {
        self.gate.as_ref()
    }

    /// Wall-time ceiling in milliseconds taken from the admitted plan.
    pub const fn wall_time_ms(&self) -> u64 {
        self.wall_time_ms
    }

    /// Whether the single-take process binding is still unconsumed.
    pub const fn has_process_request(&self) -> bool {
        self.process_request.is_some()
    }
}

/// Factory outcome: either a prepared attempt ready for one launch, or an
/// exact-replay duplicate that consumed no process and acquired no
/// credential. The replay path returns the unconsumed process binding to
/// composition.
#[derive(Debug)]
pub enum ClaudeFactoryOutcome {
    /// Admitted; exactly one launch may follow. Boxed: the prepared attempt
    /// carries the full frozen input snapshot.
    Prepared(Box<ClaudePreparedAttempt>),
    /// Exact replay of a prior attempt; no sidecar was started.
    ReplayDuplicate {
        /// Result digest stored for the prior attempt.
        prior_result_digest: String,
        /// Unconsumed process binding returned to composition. Boxed: the
        /// sealed request is large and replay must stay a small outcome.
        process_request: Box<ProcessRequest>,
    },
}

/// Admit one exact attempt from frozen inputs. Order is load-bearing: request
/// shape, Claude family, attempt/lease/fence/generation agreement, exact
/// descriptor revision, sealed process binding, idempotency, and the
/// unknown-outcome gate are all decided before anything is acquired. This
/// function cannot contact an executor: preparation starts no process.
pub fn prepare(input: ClaudeFactoryInput) -> Result<ClaudeFactoryOutcome, ClaudeSidecarError> {
    if input.request.kind != ClaudeRequestKind::Query {
        return Err(ClaudeSidecarError::MalformedFrame(
            "factory admits query requests only",
        ));
    }
    input.request.validate()?;
    validate_binding_for_claude(&input.binding)?;
    validate_execution_binding(
        &input.binding,
        &input.admitted,
        &input.current_fence,
        input.runtime_generation,
    )
    .map_err(map_agent_contract)?;
    input.admitted.validate().map_err(map_agent_contract)?;
    input.descriptor.validate_for(&input.binding)?;
    input
        .process_request
        .validate()
        .map_err(map_process_contract)?;
    let (prompt, plan) = match (&input.request.prompt, &input.request.launch_plan) {
        (Some(prompt), Some(plan)) => (prompt.as_str(), plan),
        (None, _) | (_, None) => {
            return Err(ClaudeSidecarError::EmptyField("prompt/launch_plan"));
        }
    };
    if let Some(stored) = input.prior.as_ref() {
        stored.validate()?;
    }
    let presented = idempotency_key_for_request(&input.request.request_id, prompt, plan)?;
    if let Some(stored) = input.prior.as_ref()
        && let IdempotencyDecision::Replay { prior_digest } =
            decide_idempotency(Some(stored), &presented)
    {
        return Ok(ClaudeFactoryOutcome::ReplayDuplicate {
            prior_result_digest: prior_digest,
            process_request: Box::new(input.process_request),
        });
    }
    if let Some(stored) = input.prior.as_ref()
        && let IdempotencyDecision::Conflict { changed_fields } =
            decide_idempotency(Some(stored), &presented)
    {
        return Err(ClaudeSidecarError::IdempotencyConflict(
            changed_fields.join(","),
        ));
    }
    if let Some(gate) = input.gate.as_ref() {
        gate.validate()?;
        if gate.attempt_id != input.binding.attempt_id.as_str() {
            return Err(ClaudeSidecarError::BindingMismatch(
                "unknown-outcome gate addresses another attempt".to_owned(),
            ));
        }
        gate.block_retry_or_route_switch()?;
    }
    let canonical = serde_json::to_string(plan)
        .map_err(|_| ClaudeSidecarError::MalformedFrame("plan not serializable"))?;
    let plan_digest = claude_local_digest_256_hex(canonical.as_bytes());
    let wall_time_ms = plan.wall_time_ms;
    Ok(ClaudeFactoryOutcome::Prepared(Box::new(
        ClaudePreparedAttempt {
            binding: input.binding,
            request: input.request,
            plan_digest,
            idempotency_key: presented,
            credential: input.credential,
            gate: input.gate,
            wall_time_ms,
            process_request: Some(input.process_request),
        },
    )))
}

/// Render the exact NDJSON stdin line for a prepared attempt. The line is
/// re-validated and bounded here; it carries no secret material because the
/// request projection never holds any.
pub fn sidecar_stdin_line(prepared: &ClaudePreparedAttempt) -> Result<String, ClaudeSidecarError> {
    prepared.request.validate()?;
    prepared
        .request
        .to_ndjson_line()
        .map_err(|_| ClaudeSidecarError::MalformedFrame("request not serializable"))
}

// ---------------------------------------------------------------------------
// Running sidecar: bounded streaming with raw lineage
// ---------------------------------------------------------------------------

/// One launched sidecar generation. Tracks the exact operation, the stream
/// cursor, the deadline, and whether the terminal frame was seen. The
/// executable, working root, and ceilings in force are the admitted ones
/// recorded in the process binding, never caller-selected paths.
#[derive(Clone, Debug)]
pub struct ClaudeRunningSidecar {
    operation_id: OperationId,
    invocation_digest: String,
    attempt_id: String,
    request_id: String,
    plan_digest: String,
    prev_sequence: Option<u64>,
    frames_ingested: u64,
    deadline_ms: u64,
    terminal_seen: bool,
}

impl ClaudeRunningSidecar {
    /// Exact process operation started for this attempt.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Sealed invocation digest quoted from the start receipt.
    pub fn invocation_digest(&self) -> &str {
        self.invocation_digest.as_str()
    }

    /// Attempt this sidecar executes for.
    pub fn attempt_id(&self) -> &str {
        self.attempt_id.as_str()
    }

    /// Request correlation enforced on every stream frame.
    pub fn request_id(&self) -> &str {
        self.request_id.as_str()
    }

    /// Digest of the canonical launch plan admitted for this attempt.
    pub fn plan_digest(&self) -> &str {
        self.plan_digest.as_str()
    }

    /// Absolute deadline in milliseconds (`started_at_ms + wall_time_ms`).
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Number of stream frames ingested so far.
    pub const fn frames_ingested(&self) -> u64 {
        self.frames_ingested
    }

    /// Whether the terminal `Result` frame was already ingested.
    pub const fn terminal_seen(&self) -> bool {
        self.terminal_seen
    }

    /// Ingest one raw NDJSON stdout line. Enforces, in order: deadline (no
    /// work past it), single terminal (no frames after `Result`), frame size
    /// and version bounds before parsing, exact request correlation, strict
    /// monotonic order, raw-evidence preservation, then normalization. The
    /// normalized event links the raw digest and preserves the source kind;
    /// progress or completion is never manufactured.
    pub fn ingest_line(
        &mut self,
        raw_line: &str,
        now_ms: u64,
    ) -> Result<ClaudeStreamEvent, ClaudeSidecarError> {
        if now_ms > self.deadline_ms {
            return Err(ClaudeSidecarError::DeadlineExceeded {
                deadline_ms: self.deadline_ms,
                observed_ms: now_ms,
            });
        }
        if self.terminal_seen {
            return Err(ClaudeSidecarError::MalformedFrame(
                "stream already terminated",
            ));
        }
        let frame = ClaudeSidecarResponse::from_ndjson_line(raw_line)?;
        if frame.request_id != self.request_id {
            return Err(ClaudeSidecarError::WrongRequest {
                expected: self.request_id.clone(),
                observed: frame.request_id.clone(),
            });
        }
        let actual = match frame.sequence {
            Some(sequence) => sequence,
            None if self.prev_sequence.is_none() => 0,
            None => {
                return Err(ClaudeSidecarError::MalformedFrame(
                    "governed stream requires explicit sequences after the first frame",
                ));
            }
        };
        validate_monotonic(self.prev_sequence, actual)?;
        let raw = preserve_or_omit(raw_line, MAX_FRAME_BYTES)?;
        let normalized = normalize_event(&frame, raw_line)?;
        let is_terminal = frame.kind == ClaudeResponseKind::Result;
        if is_terminal {
            self.terminal_seen = true;
        }
        self.prev_sequence = Some(actual);
        self.frames_ingested += 1;
        Ok(ClaudeStreamEvent {
            sequence: actual,
            is_terminal,
            raw,
            normalized,
        })
    }

    /// Extract the terminal candidate bound to this running sidecar. The
    /// claimed output digest is recomputed over the exact output bytes and
    /// must match; a mismatch fails closed. The returned record carries the
    /// request and plan linkage of this sidecar.
    pub fn complete_terminal(
        &self,
        candidate: &ClaudeCandidateResult,
        raw_line: &str,
    ) -> Result<ClaudeTerminalCandidate, ClaudeSidecarError> {
        candidate.validate()?;
        let recomputed = claude_local_digest_256_hex(candidate.output.as_bytes());
        if recomputed != candidate.output_digest {
            return Err(ClaudeSidecarError::BadDigest(
                "candidate output digest does not match output bytes".to_owned(),
            ));
        }
        let raw = preserve_or_omit(raw_line, MAX_FRAME_BYTES)?;
        Ok(ClaudeTerminalCandidate {
            candidate: candidate.clone(),
            raw,
            request_id: self.request_id.clone(),
            plan_digest: self.plan_digest.clone(),
        })
    }
}

/// True when `now_ms` is past the sidecar deadline. The caller must cancel;
/// [`ClaudeRunningSidecar::ingest_line`] additionally refuses late frames.
pub const fn sidecar_expired(running: &ClaudeRunningSidecar, now_ms: u64) -> bool {
    now_ms > running.deadline_ms
}

/// One ingested stream event: the normalized view plus its immutable raw
/// lineage handle. `is_terminal` marks the `Result` frame; no other frame
/// carries candidate output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeStreamEvent {
    /// Accepted stream sequence.
    pub sequence: u64,
    /// True only for the terminal `Result` frame.
    pub is_terminal: bool,
    /// Raw-line lineage handle (preserved digest, never raw bytes).
    pub raw: PreservedOrOmitted,
    /// Normalized event linked to the raw digest.
    pub normalized: NormalizedClaudeEvent,
}

/// Terminal candidate bound to one running sidecar. Candidate-only: see
/// [`try_promote_to_finish`](crate::try_promote_to_finish), which always
/// fails with `NotAuthority`.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaudeTerminalCandidate {
    candidate: ClaudeCandidateResult,
    raw: PreservedOrOmitted,
    request_id: String,
    plan_digest: String,
}

impl std::fmt::Debug for ClaudeTerminalCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeTerminalCandidate")
            .field("output_digest", &self.candidate.output_digest)
            .field("disposition", &self.candidate.disposition)
            .field("truncated", &self.candidate.truncated)
            .field("raw", &self.raw)
            .field("request_id", &self.request_id)
            .field("plan_digest", &self.plan_digest)
            .finish()
    }
}

impl ClaudeTerminalCandidate {
    /// The verified terminal candidate.
    pub const fn candidate(&self) -> &ClaudeCandidateResult {
        &self.candidate
    }

    /// Raw lineage handle for the terminal bytes.
    pub const fn raw(&self) -> &PreservedOrOmitted {
        &self.raw
    }

    /// Request correlation of the sidecar that produced this candidate.
    pub fn request_id(&self) -> &str {
        self.request_id.as_str()
    }

    /// Plan digest of the sidecar that produced this candidate.
    pub fn plan_digest(&self) -> &str {
        self.plan_digest.as_str()
    }
}

// ---------------------------------------------------------------------------
// Candidate-only result translation (Codex translate_result precedent)
// ---------------------------------------------------------------------------

/// Input to candidate translation. `terminal` is `None` exactly when delivery
/// was lost; that path yields `UnknownOutcome` with a recovery handle and an
/// explicit reason, never a manufactured result.
#[derive(Clone, Debug)]
pub struct ClaudeResultInput {
    /// Terminal candidate when delivery succeeded.
    pub terminal: Option<ClaudeTerminalCandidate>,
    /// Observed usage facts (unknown values stay typed).
    pub usage: UsageReceipt,
    /// True when the sidecar was cancelled; observed cancellation wins over
    /// any terminal text.
    pub cancelled: bool,
    /// Required exactly for `UnknownOutcome`; passed through otherwise.
    pub unknown_reason: Option<String>,
}

/// Translate terminal output into the provider-neutral candidate result
/// contract. Attempt identity comes from the recorded binding; the physical
/// route is always `UNOBSERVED` with an explicit reason because this adapter
/// records no separate physical route observation; cancellation carries
/// observed cancellation and every other non-terminal outcome stays
/// `UNKNOWN_OUTCOME` with a recovery handle. The result is validated against
/// the live binding, admission, and effect ceiling before return, and can
/// never express task finish.
pub fn translate_candidate_result(
    input: ClaudeResultInput,
    binding: &ProviderExecutionBinding,
    admission: &AdmittedRouteReceipt,
    ceiling: &EffectCeiling,
) -> Result<AgentResult, ClaudeSidecarError> {
    validate_binding_for_claude(binding)?;
    let disposition = if input.cancelled {
        ResultDisposition::CancelledObserved
    } else {
        match input
            .terminal
            .as_ref()
            .map(|item| &item.candidate.disposition)
        {
            Some(ClaudeCandidateDisposition::CandidateReady) => {
                ResultDisposition::CandidateSucceeded
            }
            Some(ClaudeCandidateDisposition::CandidatePartial) => ResultDisposition::Partial,
            Some(ClaudeCandidateDisposition::CandidateFailed) => {
                ResultDisposition::FailedVerification
            }
            None => ResultDisposition::UnknownOutcome,
        }
    };
    if disposition == ResultDisposition::UnknownOutcome
        && input.unknown_reason.as_deref().is_none_or(str::is_empty)
    {
        return Err(ClaudeSidecarError::MissingUnknownReason);
    }
    let mut evidence_refs = Vec::new();
    if let Some(terminal) = input.terminal.as_ref() {
        evidence_refs.push(format!(
            "claude-output:{}",
            terminal.candidate.output_digest
        ));
        match &terminal.raw {
            PreservedOrOmitted::Preserved(handle) => {
                evidence_refs.push(format!("claude-raw:{}", handle.digest));
            }
            PreservedOrOmitted::Omitted(omission) => {
                evidence_refs.push(format!("claude-omitted:{}", omission.manifest_digest));
            }
        }
    }
    let (execution_outcome, cancellation, recovery_ref) = if input.cancelled {
        (
            ExecutionOutcome::Observed,
            Some(CancellationState::Acknowledged),
            None,
        )
    } else if input.terminal.is_some() {
        let handle = format!("claude-terminal:{}", binding.start_request_id.as_str());
        (ExecutionOutcome::UnknownOutcome, None, Some(handle))
    } else {
        let reason = input
            .unknown_reason
            .clone()
            .unwrap_or_else(|| "terminal candidate absent".to_owned());
        (
            ExecutionOutcome::UnknownOutcome,
            None,
            Some(format!("claude-recovery:{reason}")),
        )
    };
    if recovery_ref.is_none() && disposition == ResultDisposition::UnknownOutcome {
        return Err(ClaudeSidecarError::MissingUnknownReason);
    }
    if let Some(handle) = recovery_ref.as_ref() {
        evidence_refs.push(handle.clone());
    }
    let request_digest = typed_digest(claude_local_digest_256_hex(
        binding.start_request_sha256.as_bytes(),
    ))?;
    let translation_digest = input
        .terminal
        .as_ref()
        .map(|terminal| {
            serde_json::to_vec(&terminal.candidate)
                .map_err(|_| {
                    ClaudeSidecarError::MalformedFrame("candidate result not serializable")
                })
                .and_then(|bytes| typed_digest(claude_local_digest_256_hex(&bytes)))
        })
        .transpose()?;
    let (raw_evidence_digest, raw_evidence_ref) =
        match input.terminal.as_ref().map(|item| &item.raw) {
            Some(PreservedOrOmitted::Preserved(handle)) => (
                Some(typed_digest(handle.digest.clone())?),
                Some(format!("claude-raw:{}", handle.digest)),
            ),
            Some(PreservedOrOmitted::Omitted(omission)) => (
                Some(typed_digest(omission.manifest_digest.clone())?),
                Some(format!("claude-omitted:{}", omission.manifest_digest)),
            ),
            None => (None, None),
        };
    let cursor = EventCursor::new(CLAUDE_RESULT_EVENT_CURSOR).map_err(map_agent_contract)?;
    let mut actual_route = PhysicalRouteObservationReceipt {
        schema_version: eliot_agent_api::CONTRACT_VERSION.to_owned(),
        attempt_id: binding.attempt_id.clone(),
        state_fence: binding.state_fence.clone(),
        runtime_generation: binding.runtime_generation,
        admitted_route_digest: admission.self_digest.clone(),
        binding: binding.clone(),
        requested_route: binding.route.clone(),
        observed_route: None,
        route_state: RouteObservationState::Unobserved,
        diverged_fields: Vec::new(),
        execution_outcome,
        request_digest,
        translation_digest,
        raw_evidence_digest,
        raw_evidence_ref,
        usage: input.usage.clone(),
        started: ClockReading::default(),
        first_byte: ClockReading::default(),
        first_semantic: ClockReading::default(),
        terminal: ClockReading::default(),
        event_cursor: cursor,
        event_sequence: 1,
        cancellation,
        unobserved_reason: Some(CLAUDE_UNOBSERVED_ROUTE_REASON.to_owned()),
        recovery_ref,
        safe_public_error: None,
        restricted_raw_error_ref: None,
        self_digest: typed_digest(claude_local_digest_256_hex(
            CLAUDE_SIDECAR_PROTOCOL_VERSION.as_bytes(),
        ))?,
    };
    actual_route.self_digest = actual_route
        .compute_digest()
        .map_err(|_| ClaudeSidecarError::BindingMismatch("route observation digest".to_owned()))?;
    let result = AgentResult {
        attempt_id: binding.attempt_id.clone(),
        disposition,
        artifacts: Vec::new(),
        evidence_refs,
        proposed_effects: Vec::new(),
        unresolved_questions: Vec::new(),
        usage: input.usage,
        actual_route,
        unknown_reason: input.unknown_reason,
    };
    result
        .validate_for_binding(binding, admission, ceiling)
        .map_err(map_agent_contract)?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Cancellation record
// ---------------------------------------------------------------------------

/// Observed cancellation outcome for one operation. `descendants_complete`
/// is `None` while cleanup is still in progress (honest pending, never a
/// manufactured closure claim); composition polls until closure is proven.
#[derive(Clone, Debug)]
pub struct ClaudeCancelRecord {
    operation_id: OperationId,
    status: CancellationStatus,
    lifecycle: ProcessLifecycle,
    no_effect_proven: bool,
    descendants_complete: Option<bool>,
    cleanup: crate::CleanupState,
}

impl ClaudeCancelRecord {
    /// Exact operation that was cancelled.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Cancellation progress reported by the executor.
    pub const fn status(&self) -> CancellationStatus {
        self.status
    }

    /// Process lifecycle observed with the cancellation.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Whether the executor proved no physical effect happened.
    pub const fn no_effect_proven(&self) -> bool {
        self.no_effect_proven
    }

    /// Descendant-closure evidence when the executor reported any.
    pub const fn descendants_complete(&self) -> Option<bool> {
        self.descendants_complete
    }

    /// Local cleanup-machine state after this cancellation.
    pub const fn cleanup(&self) -> crate::CleanupState {
        self.cleanup
    }
}

// ---------------------------------------------------------------------------
// Same-operation reconciliation record
// ---------------------------------------------------------------------------

/// Reconciliation of the same operation after lost delivery. Carries the
/// exact evidence digest admitted into the gate; it grants no new launch.
#[derive(Clone, Debug)]
pub struct ClaudeReconciled {
    operation_id: OperationId,
    evidence_digest: String,
    stdout_present: bool,
    stderr_present: bool,
}

impl ClaudeReconciled {
    /// Operation that was reconciled (never a new one).
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Digest derived from the exact reconcile evidence bytes.
    pub fn evidence_digest(&self) -> &str {
        self.evidence_digest.as_str()
    }

    /// Whether the reconcile evidence carried stdout lineage.
    pub const fn stdout_present(&self) -> bool {
        self.stdout_present
    }

    /// Whether the reconcile evidence carried stderr lineage.
    pub const fn stderr_present(&self) -> bool {
        self.stderr_present
    }
}

// ---------------------------------------------------------------------------
// Factory: the first Claude-side adapter behind the shared contour
// ---------------------------------------------------------------------------

/// Stateless Claude sidecar adapter facade. The executor is injected and
/// therefore remains the process lifecycle owner; this type stores no mutable
/// session, attempt, or credential state. A future #874 registry composes
/// this factory by importing it from this package.
pub struct ClaudeSidecarFactory<E> {
    executor: Arc<E>,
}

impl<E> ClaudeSidecarFactory<E> {
    /// Inject the governed executor. No admission is checked here; every
    /// operation revalidates its own binding.
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> ClaudeSidecarFactory<E> {
    /// Launch one prepared attempt through the shared executor. Consumes the
    /// single-take process binding, then checks the start receipt against the
    /// exact admitted operation and generation. A stale or foreign receipt
    /// fails closed and the attempt must be reconciled, never retried blind.
    pub async fn launch(
        &self,
        prepared: &mut ClaudePreparedAttempt,
        sink: Arc<dyn ProcessEvidenceSink>,
        started_at_ms: u64,
    ) -> Result<ClaudeRunningSidecar, ClaudeSidecarError> {
        if started_at_ms == 0 {
            return Err(ClaudeSidecarError::ZeroField("started_at_ms"));
        }
        let process_request = prepared
            .process_request
            .take()
            .ok_or(ClaudeSidecarError::ProcessAlreadyStarted)?;
        let expected_operation = process_request.operation_id().clone();
        let expected_generation = process_request.generation();
        let attempt_id = prepared.binding.attempt_id.as_str().to_owned();
        let request_id = prepared.request_id().to_owned();
        let plan_digest = prepared.plan_digest.clone();
        let wall_time_ms = prepared.wall_time_ms;
        let receipt = self
            .executor
            .start(process_request, sink)
            .await
            .map_err(|error| map_executor(error, &attempt_id))?;
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation() != expected_generation
        {
            return Err(ClaudeSidecarError::OperationMismatch {
                expected: expected_operation.as_str().to_owned(),
                observed: receipt.operation_id().as_str().to_owned(),
            });
        }
        let deadline_ms =
            started_at_ms
                .checked_add(wall_time_ms)
                .ok_or(ClaudeSidecarError::TimeOutOfRange(
                    started_at_ms,
                    MIN_WALL_TIME_MS,
                    MAX_WALL_TIME_MS,
                ))?;
        Ok(ClaudeRunningSidecar {
            operation_id: expected_operation,
            invocation_digest: receipt.request_digest().to_owned(),
            attempt_id,
            request_id,
            plan_digest,
            prev_sequence: None,
            frames_ingested: 0,
            deadline_ms,
            terminal_seen: false,
        })
    }

    /// Inspect one running sidecar through the executor. Returns the
    /// executor-owned view after checking it addresses the exact running
    /// operation; interpretation stays with composition.
    pub async fn inspect_operation(
        &self,
        running: &ClaudeRunningSidecar,
    ) -> Result<ProcessExecutionView, ClaudeSidecarError> {
        let view = self
            .executor
            .inspect(running.operation_id.clone())
            .await
            .map_err(|error| map_executor(error, &running.attempt_id))?;
        if view.operation_id() != &running.operation_id {
            return Err(ClaudeSidecarError::OperationMismatch {
                expected: running.operation_id.as_str().to_owned(),
                observed: view.operation_id().as_str().to_owned(),
            });
        }
        Ok(view)
    }

    /// Cancel one running sidecar through the real `cancel(operation_id)`.
    /// The validated envelope must address the exact running attempt. The
    /// [`CleanupState`](crate::CleanupState) machine advances from the
    /// observed receipt: terminal lifecycles terminate, anything else stays
    /// acknowledged as pending cleanup. No descendant closure is
    /// manufactured: `descendants_complete` is `None` until the executor
    /// reports tree evidence.
    pub async fn cancel_running(
        &self,
        running: &ClaudeRunningSidecar,
        envelope: &CancellationEnvelope,
    ) -> Result<ClaudeCancelRecord, ClaudeSidecarError> {
        envelope.validate()?;
        if envelope.attempt_id != running.attempt_id {
            return Err(ClaudeSidecarError::BindingMismatch(
                "cancellation envelope addresses another attempt".to_owned(),
            ));
        }
        let requested = request_cancel(envelope);
        let receipt: CancellationReceipt = self
            .executor
            .cancel(running.operation_id.clone())
            .await
            .map_err(|error| map_executor(error, &running.attempt_id))?;
        let acknowledged = acknowledge(requested);
        let cleanup = if receipt.lifecycle().is_terminal() {
            terminate(acknowledged)
        } else {
            acknowledged
        };
        Ok(ClaudeCancelRecord {
            operation_id: running.operation_id.clone(),
            status: receipt.status(),
            lifecycle: receipt.lifecycle(),
            no_effect_proven: receipt.no_effect_proven(),
            descendants_complete: receipt
                .descendants()
                .map(|descendants| descendants.complete() && descendants.tree_terminated()),
            cleanup,
        })
    }

    /// Reconcile the same operation after lost delivery. Calls the exact
    /// `reconcile(operation_id)`, checks the evidence addresses that same
    /// operation, digests the canonical evidence bytes, and admits the gate
    /// retry with that derived digest only. No caller-supplied digest is
    /// accepted, and no second sidecar, route, or attempt is launched: this
    /// method takes no process binding and holds no launch capability.
    pub async fn reconcile_same_operation(
        &self,
        operation: &OperationId,
        attempt_id: &str,
        gate: &mut UnknownOutcomeGate,
    ) -> Result<ClaudeReconciled, ClaudeSidecarError> {
        gate.validate()?;
        if gate.attempt_id != attempt_id {
            return Err(ClaudeSidecarError::BindingMismatch(
                "reconciliation gate addresses another attempt".to_owned(),
            ));
        }
        let evidence: ProcessEvidence = self
            .executor
            .reconcile(operation.clone())
            .await
            .map_err(|error| map_executor(error, attempt_id))?;
        if evidence.operation_id() != operation {
            return Err(ClaudeSidecarError::OperationMismatch {
                expected: operation.as_str().to_owned(),
                observed: evidence.operation_id().as_str().to_owned(),
            });
        }
        let bytes = serde_json::to_vec(&evidence).map_err(|_| {
            ClaudeSidecarError::ExecutorRejected("reconcile evidence not serializable".to_owned())
        })?;
        let digest = claude_local_digest_256_hex(&bytes);
        gate.admit_retry(&digest)?;
        Ok(ClaudeReconciled {
            operation_id: operation.clone(),
            evidence_digest: digest,
            stdout_present: evidence.stdout().is_some(),
            stderr_present: evidence.stderr().is_some(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests: governed execution behind the port contour
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::num::NonZeroU64;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use eliot_agent_api::{
        AgentAttempt, AgentWorkUnitBrief, AttemptId, AttemptState, AuthorityEnvelope,
        BudgetEnvelope, CandidateSelectionDisposition, ContinuityKind, EffectCeiling, EffectKind,
        EpochId, LaunchRequestId, NativeSession, NativeSessionLocator, PolicyRevision,
        ProofCeiling, QuotaKnowledge, RouteSelectionCandidate, TaskId, UsageReceipt, WorkLeaseId,
        WorkUnitId, candidate_digest_for,
    };
    use eliot_contracts::EpochLineageId;
    use eliot_process::{
        ActionLeaseRef, CancellationRequest, DispatchAuthorityId, DispatchPermitAuthority,
        DispatchValidationContext, EnvironmentInheritance, EnvironmentProjection, FencingToken,
        Generation, ImageId, JobId, KernelDispatchKey, PermitIssuance, PhysicalProcessBinding,
        ProcessHealth, ProcessHealthStatus, ProcessId, ProcessIntent, ProcessState, ProcessTreeId,
        ResourceLimits, SessionId as ProcessSessionId, SuspendedProcessIdentity,
    };

    use crate::{
        AdmittedHandle, ClaudeAllowedTool, ClaudeArgv, ClaudeEnvAllowlist, ClaudeLaunchPort,
        ClaudePermissionMode, ClaudeRequestKind, ClaudeResponseKind, ClaudeSidecarLaunchPlan,
        ClaudeSidecarRequest, ClaudeSidecarResponse, MAX_OUTPUT_BYTES, MAX_PROMPT_BYTES,
        admit_with_port, is_valid_64_hex_digest, on_ack_timeout, try_promote_to_finish,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440001";
    const CANARY: &str = "sk-ant-CANARY-0000-ffff-secret-material";

    fn test_epoch(lineage: &str) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(7).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fixture_digest(seed: &str) -> LowercaseSha256 {
        serde_json::from_value(serde_json::json!(eliot_contracts::sha256_hex(
            format!("claude-fixture-{seed}").as_bytes()
        )))
        .expect("valid fixture digest")
    }

    fn claude_route() -> RouteFingerprint {
        RouteFingerprint {
            host_family: "claude".into(),
            adapter: CLAUDE_SIDECAR_ADAPTER_ID.into(),
            protocol_transport: CLAUDE_SIDECAR_TRANSPORT.into(),
            runtime_hash: fixture_digest("runtime"),
            adapter_hash: fixture_digest("adapter"),
            provider: "test-provider".into(),
            model: "test-model".into(),
            auth_billing: "test-subscription".into(),
            serializer_hash: fixture_digest("serializer"),
            tool_semantics_hash: fixture_digest("tools"),
            reasoning_mode: "default".into(),
            continuation_behavior: "fresh".into(),
            feature_flags_hash: fixture_digest("features"),
        }
    }

    fn lease_fixture(value: &str) -> TestResult<WorkLeaseId> {
        Ok(serde_json::from_value(serde_json::json!({
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": value,
        }))?)
    }

    fn binding_fixture() -> TestResult<ProviderExecutionBinding> {
        Ok(ProviderExecutionBinding {
            attempt_id: AttemptId::new("attempt-claude-1")?,
            lease_id: lease_fixture("lease-claude-1")?,
            state_fence: StateFence::new(
                test_epoch(TEST_LINEAGE),
                eliot_agent_api::ResourceGeneration::new(1)?,
            ),
            runtime_generation: eliot_agent_api::ResourceGeneration::new(1)?,
            route: claude_route(),
            session_id: None,
            provider_scope_ref: "scope-claude-1".into(),
            native_session: NativeSession::Native(NativeSessionLocator::new("claude-thread-1")?),
            execution_unit: eliot_agent_api::ExecutionUnit::new("claude", "claude-turn-1")?,
            start_request_id: eliot_agent_api::RequestId::new("req-claude-1")?,
            start_request_sha256: eliot_contracts::sha256_hex(b"req-claude-1"),
        })
    }

    fn budget_fixture() -> BudgetEnvelope {
        BudgetEnvelope {
            context_tokens: 10_000,
            wall_time_ms: 60_000,
            output_bytes: 1_000_000,
            cost_microunits: 1_000,
            max_depth: 2,
            max_descendants: 4,
        }
    }

    fn ceiling_fixture() -> EffectCeiling {
        EffectCeiling {
            scope_ref: "scope-claude-1".into(),
            allowed: BTreeSet::from([EffectKind::Observe]),
            max_external_effects: 0,
        }
    }

    fn admitted_fixture(binding: &ProviderExecutionBinding) -> TestResult<AgentAttempt> {
        Ok(AgentAttempt {
            id: binding.attempt_id.clone(),
            launch_request_id: LaunchRequestId::new("launch-claude-1")?,
            task_id: TaskId::new("task-claude-1")?,
            parent_attempt: None,
            work_unit: AgentWorkUnitBrief {
                id: WorkUnitId::new("unit-claude-1")?,
                objective: "observe".into(),
                causal_property: "claude sidecar".into(),
                scope_ref: "scope-claude-1".into(),
                expected_outputs: vec!["candidate".into()],
                source_refs: vec!["architecture".into()],
                verifier_ref: "test".into(),
                integration_owner: "owner".into(),
                contract_revision: "v1".into(),
                budget: budget_fixture(),
                effect_ceiling: ceiling_fixture(),
                stop_condition: "test".into(),
            },
            session: None,
            lease: binding.lease_id.clone(),
            state: AttemptState::Admitted,
            continuity: ContinuityKind::Fresh,
            route: binding.route.clone(),
            budget: budget_fixture(),
            authority: AuthorityEnvelope {
                epoch: test_epoch(TEST_LINEAGE),
                scope_ref: "scope-claude-1".into(),
                effect_ceiling: ceiling_fixture(),
                lease: binding.lease_id.clone(),
                state_fence: binding.state_fence.clone(),
                valid_until: "2099-01-01T00:00:00Z".into(),
            },
            cancellation: CancellationState::NotRequested,
            event_cursor: None,
            continuation: None,
            provider_binding: Some(binding.clone()),
        })
    }

    fn admission_fixture(binding: &ProviderExecutionBinding) -> TestResult<AdmittedRouteReceipt> {
        let candidate = RouteSelectionCandidate {
            capability: "claude".to_owned(),
            query_intent: "test-intent".to_owned(),
            scope_ref: "scope-claude-1".to_owned(),
            policy_revision: PolicyRevision::new(3)?,
            candidates: vec![binding.route.clone()],
            selected: Some(binding.route.clone()),
            rejected: Vec::new(),
            selection: CandidateSelectionDisposition::Selected,
            evidence_refs: vec!["evidence-1".to_owned()],
        };
        candidate.validate()?;
        let zero: LowercaseSha256 = serde_json::from_value(serde_json::json!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))?;
        let mut receipt = AdmittedRouteReceipt {
            schema_version: eliot_agent_api::CONTRACT_VERSION.to_owned(),
            decision_id: eliot_contracts::DecisionId::new("decision-claude-1")?,
            candidate_digest: candidate_digest_for(&candidate)?,
            attempt_id: binding.attempt_id.clone(),
            lease_id: binding.lease_id.clone(),
            state_fence: binding.state_fence.clone(),
            runtime_generation: binding.runtime_generation,
            policy_revision: PolicyRevision::new(3)?,
            requested_route: binding.route.clone(),
            selected_route: Some(binding.route.clone()),
            no_route: None,
            evidence_refs: vec!["evidence-1".to_owned()],
            proof_ceiling: ProofCeiling::CandidateArtifact,
            self_digest: zero,
        };
        receipt.self_digest = receipt.compute_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn plan_fixture() -> ClaudeSidecarLaunchPlan {
        ClaudeSidecarLaunchPlan {
            argv: ClaudeArgv {
                program: "eliot-claude-sidecar".into(),
                argv: vec!["--stdio".into()],
            },
            working_directory: "C:\\workspace".into(),
            env: ClaudeEnvAllowlist {
                vars: vec![("PATH".into(), "/usr/bin".into())],
            },
            wall_time_ms: 30_000,
            max_output_bytes: 64 * 1024,
            permission_mode: ClaudePermissionMode::Default,
            allowed_tools: vec![ClaudeAllowedTool::Read, ClaudeAllowedTool::Grep],
        }
    }

    fn request_fixture() -> ClaudeSidecarRequest {
        ClaudeSidecarRequest {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-claude-1".into(),
            kind: ClaudeRequestKind::Query,
            prompt: Some("summarize the workspace".into()),
            launch_plan: Some(plan_fixture()),
            sequence: None,
        }
    }

    fn process_request_fixture() -> TestResult<ProcessRequest> {
        let generation = Generation::new(1)?;
        let intent = ProcessIntent::new(
            eliot_process::OperationId::new("op-claude-1")?,
            ProcessTreeId::new("tree-claude-1")?,
            JobId::new("job-claude-1")?,
            ImageId::new("image-claude-1")?,
            ProcessSessionId::new("session-claude-1")?,
            generation,
            "claude-sidecar-admitted",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            vec!["--stdio".into()],
            "C:\\workspace",
            EnvironmentProjection::new(
                BTreeMap::from([("PATH".to_owned(), "/usr/bin".to_owned())]),
                vec![eliot_process::SecretRef::new(
                    "test-broker",
                    "claude-api-key",
                )?],
                EnvironmentInheritance::None,
            )?,
            ResourceLimits::new(1_000, None, None, 10_000, 10_000, 1)?,
        )?;
        let fence = FencingToken::new(test_epoch(TEST_LINEAGE), generation, "nonce-claude")?;
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("claude-test-authority")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new(
                ActionLeaseRef::new("claude-test-lease")?,
                fence,
                BTreeMap::from([
                    ("authority".to_owned(), "a".repeat(64)),
                    ("state".to_owned(), "b".repeat(64)),
                ]),
                100,
                10_000,
                "claude-nonce-1",
            )?,
        )?;
        Ok(ProcessRequest::new(intent, permit)?)
    }

    fn input_fixture(
        binding: ProviderExecutionBinding,
        admitted: AgentAttempt,
        request: ClaudeSidecarRequest,
        process_request: ProcessRequest,
        prior: Option<StoredIdempotencyKey>,
        gate: Option<UnknownOutcomeGate>,
    ) -> ClaudeFactoryInput {
        let route = binding.route.clone();
        let fence = binding.state_fence.clone();
        let generation = binding.runtime_generation;
        ClaudeFactoryInput {
            binding,
            admitted,
            current_fence: fence,
            runtime_generation: generation,
            descriptor: ClaudeAdapterDescriptor::current(route),
            request,
            process_request,
            credential: eliot_process::SecretRef::new("test-broker", "claude-api-key")
                .expect("valid test credential reference"),
            prior,
            gate,
        }
    }

    fn fresh_input() -> TestResult<ClaudeFactoryInput> {
        let binding = binding_fixture()?;
        let admitted = admitted_fixture(&binding)?;
        Ok(input_fixture(
            binding,
            admitted,
            request_fixture(),
            process_request_fixture()?,
            None,
            None,
        ))
    }

    fn usage_fixture() -> UsageReceipt {
        UsageReceipt {
            input_tokens: None,
            output_tokens: None,
            cost_microunits: None,
            quota: QuotaKnowledge::Unknown,
        }
    }

    fn candidate_fixture() -> ClaudeCandidateResult {
        let output = "candidate summary".to_owned();
        let output_digest = claude_local_digest_256_hex(output.as_bytes());
        ClaudeCandidateResult {
            attempt_id: "attempt-claude-1".into(),
            disposition: ClaudeCandidateDisposition::CandidateReady,
            output,
            output_digest,
            truncated: false,
        }
    }

    fn response_line(kind: ClaudeResponseKind, sequence: u64) -> String {
        let candidate = if kind == ClaudeResponseKind::Result {
            Some(candidate_fixture())
        } else {
            None
        };
        let payload = if kind == ClaudeResponseKind::Event {
            Some("delta".to_owned())
        } else {
            None
        };
        let error = if kind == ClaudeResponseKind::Error {
            Some("sidecar failed".to_owned())
        } else {
            None
        };
        ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-claude-1".into(),
            kind,
            payload,
            candidate_result: candidate,
            error,
            sequence: Some(sequence),
        }
        .to_ndjson_line()
        .expect("valid test response line")
    }

    struct RecordingSink;
    impl ProcessEvidenceSink for RecordingSink {
        fn record(
            &self,
            _evidence: ProcessEvidence,
        ) -> Result<(), eliot_process::EvidenceSinkError> {
            Ok(())
        }
    }

    /// Deterministic executor double: drives the real P-03 state machine for
    /// start/cancel and returns real views/evidence for inspect/reconcile.
    /// Only the OS spawn is absent; every contract transition is genuine.
    struct StubExecutor {
        starts: AtomicUsize,
        cancels: AtomicUsize,
        states: Mutex<HashMap<String, ProcessState>>,
    }

    impl StubExecutor {
        fn new() -> Self {
            Self {
                starts: AtomicUsize::new(0),
                cancels: AtomicUsize::new(0),
                states: Mutex::new(HashMap::new()),
            }
        }

        fn lock_states(
            &self,
        ) -> Result<std::sync::MutexGuard<'_, HashMap<String, ProcessState>>, ProcessExecutionError>
        {
            self.states
                .lock()
                .map_err(|_| ProcessExecutionError::Unavailable("fixture lock".to_owned()))
        }
    }

    fn validated_process_state(
        request: ProcessRequest,
    ) -> Result<ProcessState, ProcessExecutionError> {
        let intent = request.intent().clone();
        let fence = request.fence().clone();
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("claude-test-authority")?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let _permit = authority
            .issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("claude-test-lease")?,
                    fence.clone(),
                    BTreeMap::from([
                        ("authority".to_owned(), "a".repeat(64)),
                        ("state".to_owned(), "b".repeat(64)),
                    ]),
                    100,
                    10_000,
                    "claude-nonce-1",
                )
                .map_err(ProcessExecutionError::from)?,
            )
            .map_err(ProcessExecutionError::from)?;
        let observed = SuspendedProcessIdentity::new(
            ProcessId::new("process-claude-1").map_err(ProcessExecutionError::from)?,
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            intent.generation(),
            PhysicalProcessBinding::new(4242, 11, intent.executable(), "Local\\Eliot-Claude-Test")
                .map_err(ProcessExecutionError::from)?,
            120,
            intent.executable_sha256(),
        )
        .map_err(ProcessExecutionError::from)?;
        let clock = serde_json::from_value(serde_json::json!({
            "valid_time_ms": 150,
            "known_time_ms": 150,
            "transaction_sequence": null,
            "monotonic_ns": 1
        }))
        .map_err(|_| ProcessExecutionError::Unavailable("fixture clock".to_owned()))?;
        let context = DispatchValidationContext::new(
            clock,
            fence,
            test_epoch(TEST_LINEAGE),
            BTreeMap::from([
                ("authority".to_owned(), "a".repeat(64)),
                ("state".to_owned(), "b".repeat(64)),
            ]),
            41,
        )
        .map_err(ProcessExecutionError::from)?;
        let validated = authority
            .validate_and_consume(request, observed, &context)
            .map_err(ProcessExecutionError::from)?;
        let mut state = ProcessState::from_validated(&validated);
        state
            .mark_resumed(
                151,
                ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)
                    .map_err(ProcessExecutionError::from)?,
            )
            .map_err(ProcessExecutionError::from)?;
        Ok(state)
    }

    impl ProcessExecutor for StubExecutor {
        async fn start(
            &self,
            request: ProcessRequest,
            _sink: Arc<dyn ProcessEvidenceSink>,
        ) -> Result<eliot_process::ProcessStartReceipt, ProcessExecutionError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let key = request.operation_id().as_str().to_owned();
            let state = validated_process_state(request)?;
            let receipt = eliot_process::ProcessStartReceipt::new(&state)
                .map_err(ProcessExecutionError::from)?;
            self.lock_states()?.insert(key, state);
            Ok(receipt)
        }

        async fn inspect(
            &self,
            operation_id: eliot_process::OperationId,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            let states = self.lock_states()?;
            let state = states
                .get(operation_id.as_str())
                .ok_or(ProcessExecutionError::NotFound)?;
            Ok(state.view())
        }

        async fn cancel(
            &self,
            operation_id: eliot_process::OperationId,
        ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
            self.cancels.fetch_add(1, Ordering::SeqCst);
            let mut states = self.lock_states()?;
            let state = states
                .get_mut(operation_id.as_str())
                .ok_or(ProcessExecutionError::NotFound)?;
            let binding = state.binding().clone();
            state
                .cancel(&CancellationRequest::new(binding))
                .map_err(ProcessExecutionError::from)
        }

        async fn reconcile(
            &self,
            operation_id: eliot_process::OperationId,
        ) -> Result<ProcessEvidence, ProcessExecutionError> {
            let states = self.lock_states()?;
            let state = states
                .get(operation_id.as_str())
                .ok_or(ProcessExecutionError::NotFound)?;
            ProcessEvidence::new(
                state.view(),
                None,
                None,
                eliot_instrument_api::EvidenceAxes::observed(),
            )
            .map_err(ProcessExecutionError::from)
        }
    }

    fn factory() -> (Arc<StubExecutor>, ClaudeSidecarFactory<StubExecutor>) {
        let executor = Arc::new(StubExecutor::new());
        let stu = Arc::clone(&executor);
        (executor, ClaudeSidecarFactory::new(stu))
    }

    async fn launched(
        factory: &ClaudeSidecarFactory<StubExecutor>,
        prepared: &mut ClaudePreparedAttempt,
    ) -> TestResult<ClaudeRunningSidecar> {
        Ok(factory
            .launch(prepared, Arc::new(RecordingSink), 1_000)
            .await?)
    }

    fn prepared_fixture() -> TestResult<ClaudePreparedAttempt> {
        match prepare(fresh_input()?)? {
            ClaudeFactoryOutcome::Prepared(prepared) => Ok(*prepared),
            ClaudeFactoryOutcome::ReplayDuplicate { .. } => {
                panic!("fresh input must prepare, not replay")
            }
        }
    }

    #[test]
    fn credential_reference_is_redacted_in_debug() -> TestResult {
        // The factory carries a broker/key reference only; raw secret material
        // never enters this package (`SecretRef` holds provider/key ids, and
        // its constructor takes no secret bytes). The factory's own
        // credential field must render as the redaction marker instead of the
        // reference. (The sealed `ProcessRequest` projection keeps its
        // kernel-owned `SecretRef` list under the kernel's Debug; those ids
        // are likewise non-secret references.)
        let input = fresh_input()?;
        assert_eq!(input.credential.provider(), "test-broker");
        assert_eq!(input.credential.key(), "claude-api-key");
        let rendered = format!("{input:?}");
        assert!(rendered.contains("credential: \"[redacted credential reference]\""));
        let prepared = prepared_fixture()?;
        assert_eq!(prepared.credential().provider(), "test-broker");
        let rendered = format!("{prepared:?}");
        assert!(rendered.contains("credential: \"[redacted credential reference]\""));
        Ok(())
    }

    // -- preparation -------------------------------------------------------

    #[test]
    fn prepare_accepts_exact_admitted_attempt() -> TestResult {
        let prepared = prepared_fixture()?;
        assert_eq!(prepared.request_id(), "req-claude-1");
        assert!(is_valid_64_hex_digest(prepared.plan_digest()));
        assert_eq!(prepared.wall_time_ms(), 30_000);
        assert!(prepared.has_process_request());
        assert_eq!(prepared.credential().provider(), "test-broker");
        assert_eq!(prepared.credential().key(), "claude-api-key");
        assert_eq!(prepared.binding().attempt_id.as_str(), "attempt-claude-1");
        assert!(prepared.gate().is_none());
        let line = sidecar_stdin_line(&prepared)?;
        assert!(line.ends_with('\n'));
        assert_eq!(
            ClaudeSidecarRequest::from_ndjson_line(&line)?,
            request_fixture()
        );
        Ok(())
    }

    #[test]
    fn prepare_rejects_foreign_stale_incompatible_input() -> TestResult {
        // Foreign execution namespace.
        let mut input = fresh_input()?;
        input.binding.execution_unit = eliot_agent_api::ExecutionUnit::new("codex", "turn-9")?;
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::BindingMismatch(_))
        ));

        // Non-sidecar route.
        let mut input = fresh_input()?;
        input.binding.route.adapter = "other-adapter".into();
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::DescriptorMismatch(_))
        ));

        // Stale fence against the current runtime context.
        let mut input = fresh_input()?;
        input.current_fence = StateFence::new(
            test_epoch(OTHER_LINEAGE),
            eliot_agent_api::ResourceGeneration::new(1)?,
        );
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::BindingMismatch(_))
        ));

        // Stale factory revision.
        let mut input = fresh_input()?;
        input.descriptor.factory_revision = 0;
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::DescriptorMismatch(_))
        ));

        // Descriptor route differs from the bound route.
        let mut input = fresh_input()?;
        input.descriptor.route.model = "other-model".into();
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::DescriptorMismatch(_))
        ));

        // Close requests carry no work.
        let mut input = fresh_input()?;
        input.request = ClaudeSidecarRequest {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-claude-1".into(),
            kind: ClaudeRequestKind::Close,
            prompt: None,
            launch_plan: None,
            sequence: None,
        };
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::MalformedFrame(_))
        ));
        Ok(())
    }

    #[test]
    fn exact_replay_is_idempotent_and_conflict_fails() -> TestResult {
        let binding = binding_fixture()?;
        let admitted = admitted_fixture(&binding)?;
        let request = request_fixture();
        let presented = idempotency_key_for_request(
            &request.request_id,
            request.prompt.as_deref().unwrap_or_default(),
            request.launch_plan.as_ref().expect("fixture plan"),
        )?;
        let stored = StoredIdempotencyKey {
            key: presented,
            result_digest: "c".repeat(64),
        };
        // Exact replay returns the unconsumed binding and starts nothing.
        match prepare(input_fixture(
            binding.clone(),
            admitted.clone(),
            request.clone(),
            process_request_fixture()?,
            Some(stored),
            Some(UnknownOutcomeGate::new("attempt-claude-1".to_owned())),
        ))? {
            ClaudeFactoryOutcome::ReplayDuplicate {
                prior_result_digest,
                process_request,
            } => {
                assert_eq!(prior_result_digest, "c".repeat(64));
                assert_eq!(process_request.operation_id().as_str(), "op-claude-1");
            }
            ClaudeFactoryOutcome::Prepared(_) => panic!("exact replay must not prepare"),
        }
        // Same identity with a changed prompt conflicts.
        let mut changed = request.clone();
        changed.prompt = Some("a different prompt".into());
        let conflict_key = idempotency_key_for_request(
            &request.request_id,
            request.prompt.as_deref().unwrap_or_default(),
            request.launch_plan.as_ref().expect("fixture plan"),
        )?;
        let outcome = prepare(input_fixture(
            binding,
            admitted,
            changed,
            process_request_fixture()?,
            Some(StoredIdempotencyKey {
                key: conflict_key,
                result_digest: "c".repeat(64),
            }),
            Some(UnknownOutcomeGate::new("attempt-claude-1".to_owned())),
        ));
        assert!(matches!(
            outcome,
            Err(ClaudeSidecarError::IdempotencyConflict(_))
        ));
        Ok(())
    }

    #[test]
    fn unreconciled_gate_blocks_preparation() -> TestResult {
        // No unknown outcome on record: fresh preparation proceeds.
        assert!(fresh_input()?.gate.is_none());
        prepared_fixture()?;
        // A recorded unknown outcome blocks preparation until reconciled.
        let mut input = fresh_input()?;
        input.gate = Some(UnknownOutcomeGate::new("attempt-claude-1".to_owned()));
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::UnknownOutcomeRequiresReconcile { .. })
        ));
        // A gate bound to another attempt fails closed as well.
        let mut input = fresh_input()?;
        input.gate = Some(UnknownOutcomeGate::new("attempt-other".to_owned()));
        assert!(matches!(
            prepare(input),
            Err(ClaudeSidecarError::BindingMismatch(_))
        ));
        Ok(())
    }

    // -- launch: exactly one generation ------------------------------------

    #[tokio::test]
    async fn launch_starts_exactly_one_generation() -> TestResult {
        let (executor, factory) = factory();
        let mut prepared = prepared_fixture()?;
        let running = launched(&factory, &mut prepared).await?;
        assert_eq!(running.operation_id().as_str(), "op-claude-1");
        assert!(!running.invocation_digest().is_empty());
        assert_eq!(running.attempt_id(), "attempt-claude-1");
        assert_eq!(running.request_id(), "req-claude-1");
        assert_eq!(running.deadline_ms(), 31_000);
        assert_eq!(running.frames_ingested(), 0);
        assert!(!running.terminal_seen());
        assert!(!prepared.has_process_request());
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        // A second launch on the same attempt cannot start another sidecar.
        let second = factory
            .launch(&mut prepared, Arc::new(RecordingSink), 1_000)
            .await;
        assert!(matches!(
            second,
            Err(ClaudeSidecarError::ProcessAlreadyStarted)
        ));
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        // Inspection addresses the exact running operation.
        let view = factory.inspect_operation(&running).await?;
        assert_eq!(view.operation_id().as_str(), "op-claude-1");
        Ok(())
    }

    // -- streaming: bounded IO with lineage --------------------------------

    #[tokio::test]
    async fn stream_ingest_validates_frames_with_lineage() -> TestResult {
        let (_, factory) = factory();
        let mut prepared = prepared_fixture()?;
        let mut running = launched(&factory, &mut prepared).await?;

        let started = response_line(ClaudeResponseKind::Started, 0);
        let event = running.ingest_line(&started, 1_000)?;
        assert_eq!(event.sequence, 0);
        assert!(!event.is_terminal);
        assert_eq!(event.normalized.kind, ClaudeResponseKind::Started);
        assert_eq!(
            event.normalized.raw_digest,
            claude_local_digest_256_hex(started.as_bytes())
        );

        let delta = response_line(ClaudeResponseKind::Event, 1);
        let event = running.ingest_line(&delta, 2_000)?;
        assert_eq!(event.sequence, 1);
        assert!(!event.is_terminal);
        assert_eq!(event.normalized.payload.as_deref(), Some("delta"));
        assert_eq!(running.frames_ingested(), 2);

        let terminal = response_line(ClaudeResponseKind::Result, 2);
        let event = running.ingest_line(&terminal, 3_000)?;
        assert!(event.is_terminal);
        assert!(running.terminal_seen());
        // No frames are accepted after the terminal frame.
        assert!(matches!(
            running.ingest_line(&started, 3_000),
            Err(ClaudeSidecarError::MalformedFrame(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn stream_rejects_malformed_oversize_out_of_order_frames() -> TestResult {
        let (_, factory) = factory();
        let mut prepared = prepared_fixture()?;
        let mut running = launched(&factory, &mut prepared).await?;

        // Malformed JSON fails before semantic work.
        assert!(matches!(
            running.ingest_line("{not json}\n", 1_000),
            Err(ClaudeSidecarError::MalformedFrame(_))
        ));
        // Oversize frames fail before parsing.
        let oversized = "x".repeat(MAX_FRAME_BYTES + 1) + "\n";
        assert!(matches!(
            running.ingest_line(&oversized, 1_000),
            Err(ClaudeSidecarError::FrameTooLarge { .. })
        ));
        // Oversize payloads fail on validation.
        let big = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-claude-1".into(),
            kind: ClaudeResponseKind::Event,
            payload: Some("o".repeat(MAX_OUTPUT_BYTES + 1)),
            candidate_result: None,
            error: None,
            sequence: Some(0),
        };
        let big_line = big.to_ndjson_line().expect("oversize test line");
        // The 1 MiB payload also breaches the 256 KiB frame bound, which
        // trips first by design (size before parse).
        assert!(matches!(
            running.ingest_line(&big_line, 1_000),
            Err(ClaudeSidecarError::FrameTooLarge { .. })
        ));
        // A skipped sequence is out of order.
        assert!(matches!(
            running.ingest_line(&response_line(ClaudeResponseKind::Started, 1), 1_000),
            Err(ClaudeSidecarError::OutOfOrder { .. })
        ));
        // The first frame is accepted, then a replay is out of order.
        running.ingest_line(&response_line(ClaudeResponseKind::Started, 0), 1_000)?;
        assert!(matches!(
            running.ingest_line(&response_line(ClaudeResponseKind::Event, 0), 1_000),
            Err(ClaudeSidecarError::OutOfOrder { .. })
        ));
        // A frame for another request is rejected.
        let mut foreign: ClaudeSidecarResponse =
            serde_json::from_str(response_line(ClaudeResponseKind::Event, 1).trim_end())?;
        foreign.request_id = "req-other".into();
        let foreign_line = foreign.to_ndjson_line().expect("foreign test line");
        assert!(matches!(
            running.ingest_line(&foreign_line, 1_000),
            Err(ClaudeSidecarError::WrongRequest { .. })
        ));
        // Late frames past the deadline are refused.
        assert!(matches!(
            running.ingest_line(&response_line(ClaudeResponseKind::Event, 1), 31_001),
            Err(ClaudeSidecarError::DeadlineExceeded { .. })
        ));
        Ok(())
    }

    // -- terminal candidate + provider-neutral translation -----------------

    #[tokio::test]
    async fn terminal_candidate_translates_to_candidate_only_result() -> TestResult {
        let (_, factory) = factory();
        let mut prepared = prepared_fixture()?;
        let running = launched(&factory, &mut prepared).await?;
        let binding = binding_fixture()?;
        let admission = admission_fixture(&binding)?;
        let ceiling = ceiling_fixture();

        let candidate = candidate_fixture();
        let terminal_line = response_line(ClaudeResponseKind::Result, 2);
        let terminal = running.complete_terminal(&candidate, &terminal_line)?;
        assert_eq!(terminal.request_id(), "req-claude-1");
        assert!(is_valid_64_hex_digest(terminal.plan_digest()));
        // Tampered digests fail closed.
        let mut tampered = candidate.clone();
        tampered.output_digest = "d".repeat(64);
        assert!(matches!(
            running.complete_terminal(&tampered, &terminal_line),
            Err(ClaudeSidecarError::BadDigest(_))
        ));
        // The candidate can never become a finish decision.
        assert!(try_promote_to_finish(terminal.candidate()).is_err());

        let result = translate_candidate_result(
            ClaudeResultInput {
                terminal: Some(terminal),
                usage: usage_fixture(),
                cancelled: false,
                unknown_reason: None,
            },
            &binding,
            &admission,
            &ceiling,
        )?;
        assert_eq!(
            result.disposition,
            eliot_agent_api::ResultDisposition::CandidateSucceeded
        );
        assert_eq!(result.attempt_id.as_str(), "attempt-claude-1");
        let expected_ref = format!("claude-output:{}", candidate.output_digest);
        assert_eq!(
            result.evidence_refs.first().map(String::as_str),
            Some(expected_ref.as_str())
        );
        // Linkage was enforced inside translation (binding/admission/ceiling).
        result.validate_for_binding(&binding, &admission, &ceiling)?;
        Ok(())
    }

    // -- unknown outcome + same-operation reconciliation --------------------

    #[tokio::test]
    async fn lost_delivery_blocks_retry_until_same_operation_reconciles() -> TestResult {
        let (executor, factory) = factory();
        let mut prepared = prepared_fixture()?;
        let running = launched(&factory, &mut prepared).await?;
        let operation = running.operation_id().clone();
        let binding = binding_fixture()?;
        let admission = admission_fixture(&binding)?;
        let ceiling = ceiling_fixture();

        // Delivery loss yields an unknown outcome with a recovery handle.
        let result = translate_candidate_result(
            ClaudeResultInput {
                terminal: None,
                usage: usage_fixture(),
                cancelled: false,
                unknown_reason: Some("sidecar output delivery lost".into()),
            },
            &binding,
            &admission,
            &ceiling,
        )?;
        assert_eq!(
            result.disposition,
            eliot_agent_api::ResultDisposition::UnknownOutcome
        );
        assert!(result.unknown_reason.is_some());

        // The gate blocks a blind retry of the same attempt.
        let mut gate = UnknownOutcomeGate::new("attempt-claude-1".to_owned());
        let blocked = prepare(input_fixture(
            binding.clone(),
            admitted_fixture(&binding)?,
            request_fixture(),
            process_request_fixture()?,
            None,
            Some(gate.clone()),
        ));
        assert!(matches!(
            blocked,
            Err(ClaudeSidecarError::UnknownOutcomeRequiresReconcile { .. })
        ));

        // Reconciliation touches the same operation only: no new sidecar.
        let reconciled = factory
            .reconcile_same_operation(&operation, "attempt-claude-1", &mut gate)
            .await?;
        assert_eq!(reconciled.operation_id().as_str(), "op-claude-1");
        assert!(is_valid_64_hex_digest(reconciled.evidence_digest()));
        assert!(gate.block_retry_or_route_switch().is_ok());
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);

        // After exact reconciliation the same attempt may be prepared again,
        // still without launching a second generation here.
        match prepare(input_fixture(
            binding.clone(),
            admitted_fixture(&binding)?,
            request_fixture(),
            process_request_fixture()?,
            None,
            Some(gate),
        ))? {
            ClaudeFactoryOutcome::Prepared(_) => {}
            ClaudeFactoryOutcome::ReplayDuplicate { .. } => panic!("fresh key must prepare"),
        }
        assert_eq!(executor.starts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    // -- cancellation + deadline -------------------------------------------

    #[tokio::test]
    async fn cancel_wires_real_operation_cancel_and_cleanup() -> TestResult {
        let (executor, factory) = factory();
        let mut prepared = prepared_fixture()?;
        let running = launched(&factory, &mut prepared).await?;
        let envelope = crate::CancellationEnvelope {
            attempt_id: "attempt-claude-1".into(),
            reason: "test timeout".into(),
            observed_at_ms: 5_000,
        };
        let record = factory.cancel_running(&running, &envelope).await?;
        assert_eq!(record.operation_id().as_str(), "op-claude-1");
        assert_eq!(
            record.status(),
            eliot_process::CancellationStatus::InProgress
        );
        assert_eq!(
            record.lifecycle(),
            eliot_process::ProcessLifecycle::Cancelling
        );
        assert_eq!(record.cleanup(), crate::CleanupState::Acknowledged);
        assert_eq!(record.descendants_complete(), None);
        assert!(!record.no_effect_proven());
        assert_eq!(executor.cancels.load(Ordering::SeqCst), 1);

        // An envelope for another attempt is rejected before executor contact.
        let foreign = crate::CancellationEnvelope {
            attempt_id: "attempt-other".into(),
            reason: "test timeout".into(),
            observed_at_ms: 5_000,
        };
        assert!(matches!(
            factory.cancel_running(&running, &foreign).await,
            Err(ClaudeSidecarError::BindingMismatch(_))
        ));
        assert_eq!(executor.cancels.load(Ordering::SeqCst), 1);

        // Cancelling an unknown operation surfaces the executor truth.
        let missing_running = ClaudeRunningSidecar {
            operation_id: eliot_process::OperationId::new("op-missing")?,
            invocation_digest: String::new(),
            attempt_id: "attempt-claude-1".into(),
            request_id: "req-claude-1".into(),
            plan_digest: "p".repeat(64),
            prev_sequence: None,
            frames_ingested: 0,
            deadline_ms: 31_000,
            terminal_seen: false,
        };
        assert!(matches!(
            factory.cancel_running(&missing_running, &envelope).await,
            Err(ClaudeSidecarError::OperationNotFound)
        ));
        Ok(())
    }

    #[test]
    fn deadline_is_enforced_purely() {
        let running = ClaudeRunningSidecar {
            operation_id: eliot_process::OperationId::new("op-claude-1").expect("valid op"),
            invocation_digest: String::new(),
            attempt_id: "attempt-claude-1".into(),
            request_id: "req-claude-1".into(),
            plan_digest: "p".repeat(64),
            prev_sequence: None,
            frames_ingested: 0,
            deadline_ms: 31_000,
            terminal_seen: false,
        };
        assert!(!sidecar_expired(&running, 31_000));
        assert!(sidecar_expired(&running, 31_001));
    }

    // -- credential redaction ----------------------------------------------

    #[test]
    fn no_secret_material_reaches_adapter_surfaces() -> TestResult {
        let prepared = prepared_fixture()?;
        let line = sidecar_stdin_line(&prepared)?;
        let process_request = process_request_fixture()?;
        let argv = process_request.argv().join(" ");
        let env_debug = format!("{:?}", process_request.environment());
        let prepared_debug = format!("{prepared:?}");
        let terminal = ClaudeTerminalCandidate {
            candidate: candidate_fixture(),
            raw: crate::preserve_or_omit(&line, MAX_FRAME_BYTES)?,
            request_id: "req-claude-1".into(),
            plan_digest: prepared.plan_digest().to_owned(),
        };
        let terminal_debug = format!("{terminal:?}");
        let candidate_json = serde_json::to_string(terminal.candidate())?;
        for surface in [
            &line,
            &argv,
            &env_debug,
            &prepared_debug,
            &terminal_debug,
            &candidate_json,
        ] {
            assert!(
                !surface.contains(CANARY),
                "secret canary leaked into adapter surface"
            );
        }
        // References flow; values never exist in this package.
        assert!(prepared_debug.contains("redacted"));
        assert!(!prepared_debug.contains("claude-api-key"));
        // The admitted executable wins; the inert plan program is never used.
        assert_eq!(process_request.executable(), "claude-sidecar-admitted");
        assert_ne!(process_request.executable(), "eliot-claude-sidecar");
        Ok(())
    }

    // -- previously-unwired pure functions ---------------------------------

    #[test]
    fn monotonic_order_edges() {
        assert!(validate_monotonic(None, 0).is_ok());
        assert!(validate_monotonic(Some(4), 5).is_ok());
        assert!(validate_monotonic(None, 1).is_err());
        assert!(validate_monotonic(Some(4), 4).is_err());
        assert!(validate_monotonic(Some(4), 6).is_err());
        assert!(validate_monotonic(Some(u64::MAX), 0).is_err());
        assert!(validate_monotonic(Some(u64::MAX), u64::MAX).is_err());
    }

    #[test]
    fn preserve_or_omit_paths() -> TestResult {
        match crate::preserve_or_omit("small", 100)? {
            PreservedOrOmitted::Preserved(handle) => {
                assert_eq!(handle.digest, claude_local_digest_256_hex(b"small"));
                assert_eq!(handle.byte_len, 5);
                assert!(!handle.truncated);
                handle.validate()?;
            }
            PreservedOrOmitted::Omitted(_) => panic!("small output must be preserved"),
        }
        match crate::preserve_or_omit(&"x".repeat(101), 100)? {
            PreservedOrOmitted::Omitted(omission) => {
                assert!(!omission.reason.trim().is_empty());
                omission.validate()?;
            }
            PreservedOrOmitted::Preserved(_) => panic!("oversize output must be omitted"),
        }
        Ok(())
    }

    #[test]
    fn cleanup_state_machine() {
        let envelope = crate::CancellationEnvelope {
            attempt_id: "attempt-claude-1".into(),
            reason: "test".into(),
            observed_at_ms: 1,
        };
        assert_eq!(request_cancel(&envelope), crate::CleanupState::Requested);
        assert_eq!(
            acknowledge(crate::CleanupState::Requested),
            crate::CleanupState::Acknowledged
        );
        assert_eq!(
            acknowledge(crate::CleanupState::Acknowledged),
            crate::CleanupState::Acknowledged
        );
        assert_eq!(
            terminate(crate::CleanupState::Acknowledged),
            crate::CleanupState::Terminated
        );
        assert_eq!(
            on_ack_timeout(crate::CleanupState::Acknowledged),
            crate::CleanupState::UnknownOutcome
        );
        assert_eq!(
            on_ack_timeout(crate::CleanupState::Terminated),
            crate::CleanupState::Terminated
        );
    }

    #[test]
    fn idempotency_and_gate_decisions() -> TestResult {
        let plan = plan_fixture();
        let key = idempotency_key_for_request("req-1", "prompt", &plan)?;
        key.validate()?;
        // No prior record is new.
        assert!(matches!(
            decide_idempotency(None, &key),
            IdempotencyDecision::New
        ));
        let stored = StoredIdempotencyKey {
            key: key.clone(),
            result_digest: "d".repeat(64),
        };
        stored.validate()?;
        // Exact replay returns the prior digest.
        assert!(matches!(
            decide_idempotency(Some(&stored), &key),
            IdempotencyDecision::Replay { .. }
        ));
        // A changed prompt conflicts and names the field.
        let changed = idempotency_key_for_request("req-1", "other prompt", &plan)?;
        match decide_idempotency(Some(&stored), &changed) {
            IdempotencyDecision::Conflict { changed_fields } => {
                assert!(changed_fields.contains(&"prompt_digest".to_owned()));
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        // The gate blocks until exact reconciliation.
        let mut gate = UnknownOutcomeGate::new("attempt-1".to_owned());
        gate.validate()?;
        assert!(gate.block_retry_or_route_switch().is_err());
        assert!(gate.admit_retry("not-hex").is_err());
        gate.admit_retry(&"e".repeat(64))?;
        assert!(gate.block_retry_or_route_switch().is_ok());
        Ok(())
    }

    #[test]
    fn normalize_event_keeps_raw_lineage() -> TestResult {
        let response = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-claude-1".into(),
            kind: ClaudeResponseKind::Event,
            payload: Some("delta".into()),
            candidate_result: None,
            error: None,
            sequence: Some(3),
        };
        let line = response.to_ndjson_line()?;
        let normalized = normalize_event(&response, &line)?;
        normalized.validate()?;
        assert_eq!(normalized.sequence, 3);
        assert_eq!(normalized.kind, ClaudeResponseKind::Event);
        assert_eq!(
            normalized.raw_digest,
            claude_local_digest_256_hex(line.as_bytes())
        );
        assert_eq!(
            normalized.normalizer_version,
            crate::CLAUDE_EVENT_NORMALIZER_VERSION
        );
        // Oversize raw lines fail before normalization.
        let oversized = "z".repeat(MAX_FRAME_BYTES + 1);
        assert!(matches!(
            normalize_event(&response, &oversized),
            Err(ClaudeSidecarError::FrameTooLarge { .. })
        ));
        // Invalid source frames fail instead of normalizing.
        let bad = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-claude-1".into(),
            kind: ClaudeResponseKind::Result,
            payload: None,
            candidate_result: None,
            error: None,
            sequence: None,
        };
        let bad_line = serde_json::to_string(&bad)? + "\n";
        assert!(normalize_event(&bad, &bad_line).is_err());
        Ok(())
    }

    struct AllowPort;
    struct DenyPort;

    impl ClaudeLaunchPort for AllowPort {
        fn check_admission(
            &self,
            request_id: &str,
            plan_digest: &str,
        ) -> Result<AdmittedHandle, ClaudeSidecarError> {
            Ok(AdmittedHandle {
                request_id: request_id.to_owned(),
                plan_digest: plan_digest.to_owned(),
            })
        }
    }

    impl ClaudeLaunchPort for DenyPort {
        fn check_admission(
            &self,
            _request_id: &str,
            _plan_digest: &str,
        ) -> Result<AdmittedHandle, ClaudeSidecarError> {
            Err(ClaudeSidecarError::AdmissionDenied("test deny".into()))
        }
    }

    #[test]
    fn admit_with_port_delegates_after_validation() -> TestResult {
        let handle = admit_with_port(&AllowPort, &request_fixture())?;
        handle.validate()?;
        assert_eq!(handle.request_id, "req-claude-1");
        assert!(is_valid_64_hex_digest(&handle.plan_digest));
        // Denials surface typed.
        assert!(matches!(
            admit_with_port(&DenyPort, &request_fixture()),
            Err(ClaudeSidecarError::AdmissionDenied(_))
        ));
        // Request validation precedes delegation.
        let mut bad = request_fixture();
        bad.protocol_version = "v0".into();
        assert!(matches!(
            admit_with_port(&DenyPort, &bad),
            Err(ClaudeSidecarError::UnsupportedVersion(_))
        ));
        // Oversize prompts never reach the port.
        let mut big = request_fixture();
        big.prompt = Some("p".repeat(MAX_PROMPT_BYTES + 1));
        assert!(matches!(
            admit_with_port(&AllowPort, &big),
            Err(ClaudeSidecarError::PromptTooLarge { .. })
        ));
        Ok(())
    }
}
