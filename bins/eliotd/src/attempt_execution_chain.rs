//! Daemon production chain for one execution unit: attach → admission →
//! supplier bind → coordinator bind → matched attestation (issue #1942 lane
//! O1).
//!
//! Owner wiring: the Codex adapter owns attach admission
//! ([`CodexAttachReceipt`]), the coordinator owns attempt admission and the
//! provider-execution bind, and this daemon module owns only the sequencing
//! between them. It mints no session, fence, task, authority, grant, or
//! idempotency identity; every load-bearing value arrives as a typed
//! owner artifact and every agreement is checked with typed equality.
//!
//! Chain order with live checks before authoritative use:
//!
//! 1. `attached` (live daemon attach admission: launch, authority, route,
//!    session validated together by the adapter `attach`) is checked against
//!    the freshly read live triple: receipt session equals `live_session`,
//!    receipt launch task equals `live_task`. A superseded attach fails here.
//! 2. The admission `context` fence must match `live_fence` exactly under the
//!    normative [`fences_match_exact`] (bidirectional; revision wildcards
//!    rejected), proving the admission is current before anything executes.
//! 3. [`bind_execution_unit`] builds the binding with the session sourced
//!    exclusively from the admitted receipt (never thread input).
//! 4. [`AgentCoordinator::bind_provider_execution`] records it through the
//!    sealed-verifier S1/S2 path (T1/T5 session admission).
//! 5. The recorded attestation is re-read from the live registry and matched
//!    with [`verify_session_binding`] against the same live triple before it
//!    is returned for authoritative use (dispatch, receipts, or the session
//!    snapshot's `snapshot.attempt_id` via the M2 join).
//!
//! Principal/task/attempt/fence/generation coverage: principal is
//! single-owner bridge state and arrives with the live triple from the same
//! attach read (no cross-owner match required); task is matched exactly;
//! attempt identity is the canonical `AgentAttemptId` passed through
//! unchanged (never re-derived from text); fence is matched with the
//! normative exact comparator; generation agreement was enforced by S1 at
//! bind (`binding.runtime_generation == fence.resource_generation`) and the
//! snapshot's authoritative generation comes from the Kernel activation
//! receipt. Nothing is hashed, parsed, or minted for authority anywhere in
//! this chain.
//!
//! Invocation note: this module is the compiled chain interface. It is
//! called by the actual binary execution path that holds the live attach
//! triple — no other runtime join may invoke the supplier path, and no
//! speculative loop is wired here.

use eliot_agent_api::{
    AgentLaunchRequest, AuthorityEnvelope, ExecutionUnit, NativeSession, ProviderExecutionBinding,
    RequestId, RouteFingerprint,
};
use eliot_agent_codex::{
    CodexAdapterError, CodexAttachInput, CodexAttachReceipt, CodexBindExecutionInput,
    CodexSessionBinding, attach, bind_execution_unit,
};
use eliot_agent_coordinator::{
    AgentCoordinator, CoordinatedAttemptState, CoordinatorError, ExecutionContext,
    ProviderAdmissionReceipt, ProviderExecutionBindingSubmission, ProviderIdentity,
    SessionAttemptError, SessionMatchError, VerifiedSessionBinding, produce_session_bound_attempts,
    verify_session_binding,
};
use eliot_contracts::{SessionId, StateFence, TaskId, WorkLeaseId, fences_match_exact};
use eliot_process::ProcessRequest;
use eliot_source_assurance::{AdmissionExpectation, SourceAssurance};
use thiserror::Error;

/// Typed inputs for dispatching one execution unit through the chain.
///
/// Owner artifacts only: the admitted attach receipt, the coordinator plus
/// its admission context, coordinator-admitted attempt/lease identity, the
/// freshly read live attach triple, execution-observed facts, and the
/// provider-start correlation. There is no session, task, or fence text
/// anywhere in this struct.
pub struct ExecutionDispatchInput<'a> {
    /// Live daemon attach admission (session, route, launch, authority).
    pub attached: &'a CodexAttachReceipt,
    /// Coordinator holding the admitted attempt.
    pub coordinator: &'a mut AgentCoordinator,
    /// Admission context (fence, epoch, lease agreement).
    pub context: ExecutionContext,
    /// Coordinator-admitted attempt identity.
    pub attempt_id: eliot_agent_api::AttemptId,
    /// Coordinator-admitted lease identity.
    pub lease_id: WorkLeaseId,
    /// Freshly read live attach session the dispatch serves.
    pub live_session: &'a SessionId,
    /// Freshly read live attach fence the dispatch serves under.
    pub live_fence: &'a StateFence,
    /// Freshly read live attach task the dispatch serves.
    pub live_task: &'a TaskId,
    /// Authenticated provider scope the execution runs under.
    pub provider_scope_ref: String,
    /// Observed native thread locator (execution evidence only).
    pub native_session: NativeSession,
    /// Execution-unit identity for this turn.
    pub execution_unit: ExecutionUnit,
    /// Start-request identity.
    pub start_request_id: RequestId,
    /// Canonical start-request bytes (digest computed inside the supplier).
    pub start_request_bytes: &'a [u8],
    /// Provider identity for the start correlation.
    pub provider_identity: ProviderIdentity,
    /// Provider start-receipt reference for the start correlation.
    pub provider_start_receipt_ref: String,
}

/// The dispatched execution: the bound unit plus its matched attestation.
///
/// `verified` is the only value in this struct cleared for authoritative
/// use; `binding` is the exact bound unit retained for attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchedExecution {
    /// The bound provider execution unit.
    pub binding: ProviderExecutionBinding,
    /// The recorded attestation matched against the live triple.
    pub verified: VerifiedSessionBinding,
}

/// Fail-closed execution-chain errors.
#[derive(Debug, Error)]
pub enum ExecutionChainError {
    /// The live attach receipt disagrees with the freshly read live triple:
    /// the attach is stale or belongs to another session/task.
    #[error("live attach receipt disagrees with the live triple at {field}")]
    LiveAttachMismatch {
        /// Receipt field that disagrees (`attach.session` or `attach.task`).
        field: &'static str,
    },
    /// The admission fence is not current against the live fence.
    #[error("admission fence is not current against the live fence")]
    StaleAdmissionFence,
    /// The adapter supplier rejected the bind inputs.
    #[error("execution-unit supplier rejected: {0}")]
    Supplier(#[from] CodexAdapterError),
    /// The coordinator rejected the bind.
    #[error("coordinator bind rejected: {0}")]
    Coordinator(#[from] CoordinatorError),
    /// No live session-bound attempt was recorded.
    #[error("no live session-bound attempt recorded: {0}")]
    NoAttestation(#[from] SessionAttemptError),
    /// The recorded attestation failed its live-triple match, or the bound
    /// attempt is not the dispatched one.
    #[error("recorded attestation failed its live-triple match: {0}")]
    Match(#[from] SessionMatchError),
    /// The recorded attestation names another attempt than the dispatched
    /// one.
    #[error("recorded attestation names another attempt than dispatched")]
    AttemptMismatch,
    /// No admitted lane carries the attach route, or several do: the launch
    /// cannot select a single lane without a caller choice.
    #[error("admitted lanes do not select exactly one lane for the attach route")]
    LaneSelection,
    /// The admitted attempt is not in a dispatchable state (neither
    /// `Admitted` nor `Running`).
    #[error("admitted attempt is not in a dispatchable state")]
    AttemptNotDispatchable,
}

/// Dispatch one execution unit through the full production chain.
///
/// Runs attach→admission→supplier→bind→match in order, checking the live
/// triple before authoritative use. Deterministic and side-effect free
/// except for the coordinator bind it sequences (idempotent under the
/// coordinator's canonical-input replay).
pub fn dispatch_execution_unit(
    input: ExecutionDispatchInput,
) -> Result<DispatchedExecution, ExecutionChainError> {
    // 1. Live attach checks: the receipt the daemon serves must be the live
    //    attach. Exact typed equality, no hashes, no text.
    if input.attached.session().session_id != *input.live_session {
        return Err(ExecutionChainError::LiveAttachMismatch {
            field: "attach.session",
        });
    }
    if input.attached.launch().task_id != *input.live_task {
        return Err(ExecutionChainError::LiveAttachMismatch {
            field: "attach.task",
        });
    }
    // 2. Admission currency: the admission fence must exactly match the live
    //    fence under the normative bidirectional comparator.
    if !fences_match_exact(&input.context.state_fence, input.live_fence) {
        return Err(ExecutionChainError::StaleAdmissionFence);
    }
    // 3. Supplier bind: session sourced exclusively from the admitted
    //    receipt, route from the admitted route, shape-checked inside.
    let binding = bind_execution_unit(CodexBindExecutionInput {
        attached: input.attached,
        attempt_id: input.attempt_id.clone(),
        lease_id: input.lease_id.clone(),
        state_fence: input.context.state_fence.clone(),
        runtime_generation: input.context.state_fence.resource_generation,
        provider_scope_ref: input.provider_scope_ref,
        native_session: input.native_session,
        execution_unit: input.execution_unit,
        start_request_id: input.start_request_id,
        start_request_bytes: input.start_request_bytes,
    })?;
    // 4. Coordinator bind through the sealed-verifier S1/S2 path; records
    //    the session (T1/T5 admission).
    let submission = ProviderExecutionBindingSubmission {
        binding: binding.clone(),
        provider_identity: input.provider_identity,
        provider_start_receipt_ref: input.provider_start_receipt_ref,
    };
    let bound = input
        .coordinator
        .bind_provider_execution(input.context, submission)?;
    // 5. Re-read the recorded attestation and match it against the same
    //    live triple before authoritative use.
    let recorded = produce_session_bound_attempts(input.coordinator)?
        .into_iter()
        .find(|facts| facts.attempt_id == bound.attempt_id)
        .ok_or(ExecutionChainError::AttemptMismatch)?;
    let verified = verify_session_binding(
        &recorded,
        input.live_session,
        input.live_fence,
        input.live_task,
    )?;
    Ok(DispatchedExecution {
        binding: bound,
        verified,
    })
}

/// Typed inputs for launching one execution unit through the full chain.
///
/// Owner artifacts only, grouped by the owner that issued them: the Task
/// Controller frozen launch, the Governor grant envelope and provider
/// admission receipt, the Q-01 source admission, the P-03 process binding,
/// the daemon-held live attach session binding and live triple, and the
/// execution-observed facts plus provider-start correlation. No identity,
/// fence, task, or receipt text appears anywhere here; every field is a
/// validated owner type.
pub struct LaunchExecutionInput<'a> {
    /// Frozen Task-Controller launch request.
    pub launch: AgentLaunchRequest,
    /// Governor grant envelope bounding the launch.
    pub authority: AuthorityEnvelope,
    /// Admitted route this launch serves.
    pub route: RouteFingerprint,
    /// Daemon-held live attach session binding.
    pub session: CodexSessionBinding,
    /// P-03 process-request binding for the execution.
    pub process_request: ProcessRequest,
    /// Q-01 source assurance for the launch source.
    pub source_assurance: SourceAssurance,
    /// Q-01 admission expectation for the launch source.
    pub source_expectation: AdmissionExpectation,
    /// Coordinator holding the admission.
    pub coordinator: &'a mut AgentCoordinator,
    /// Governor/provider admission receipt for the staffed candidate.
    pub admission: ProviderAdmissionReceipt,
    /// Freshly read live attach session the launch serves.
    pub live_session: &'a SessionId,
    /// Freshly read live attach fence the launch serves under.
    pub live_fence: &'a StateFence,
    /// Freshly read live attach task the launch serves.
    pub live_task: &'a TaskId,
    /// Authenticated provider scope the execution runs under.
    pub provider_scope_ref: String,
    /// Observed native thread locator (execution evidence only).
    pub native_session: NativeSession,
    /// Execution-unit identity for this turn.
    pub execution_unit: ExecutionUnit,
    /// Start-request identity.
    pub start_request_id: RequestId,
    /// Canonical start-request bytes (digest computed inside the supplier).
    pub start_request_bytes: &'a [u8],
    /// Provider identity for the start correlation.
    pub provider_identity: ProviderIdentity,
    /// Provider start-receipt reference for the start correlation.
    pub provider_start_receipt_ref: String,
}

/// Launch one execution unit through the complete production chain.
///
/// Order with attach-first validation: the adapter `attach` runs before any
/// coordinator mutation, so a rejected launch/authority/route/session,
/// process request, or source admission fails here and no admission, start,
/// or bind authority ever flows. The coordinator `admit` then stages the
/// Governor/provider receipt; exactly one admitted lane may carry the attach
/// route; the attempt starts unless already running; and the remainder runs
/// through [`dispatch_execution_unit`], which re-checks the live triple
/// before authoritative use. Deterministic; the coordinator bind stays
/// idempotent under its canonical-input replay.
pub fn launch_execution_unit(
    input: LaunchExecutionInput,
) -> Result<DispatchedExecution, ExecutionChainError> {
    // 1. Attach first: validates launch, authority, route, session, process
    //    request, and source admission together. Nothing below runs unless
    //    the daemon admission accepts all of them.
    let attached = attach(CodexAttachInput {
        launch: input.launch,
        authority: input.authority,
        route: input.route.clone(),
        session: input.session,
        process_request: input.process_request,
        source_assurance: input.source_assurance,
        source_expectation: input.source_expectation,
    })?;
    // 2. Stage the Governor/provider admission receipt (sealed verifier).
    let receipt = input.coordinator.admit(input.admission)?;
    // 3. The admission must serve the attached launch task.
    if receipt.task_id != attached.launch().task_id {
        return Err(ExecutionChainError::LiveAttachMismatch {
            field: "admission.task",
        });
    }
    // 4. Select exactly one admitted lane by the attach route (exact typed
    //    equality; lanes arrive sorted from `admit`, so selection is
    //    deterministic).
    let mut lanes = receipt
        .admitted_lanes
        .iter()
        .filter(|lane| lane.route == input.route);
    let lane = lanes.next().ok_or(ExecutionChainError::LaneSelection)?;
    if lanes.next().is_some() {
        return Err(ExecutionChainError::LaneSelection);
    }
    let context = ExecutionContext::from(&receipt);
    // 5. Start unless already running; anything else is not dispatchable.
    //    Owner state is read first — a cached state assumption never starts
    //    or skips here.
    let record = input
        .coordinator
        .attempt(&lane.attempt_id)
        .ok_or(ExecutionChainError::AttemptMismatch)?;
    match record.state {
        CoordinatedAttemptState::Admitted => {
            input
                .coordinator
                .start_attempt(context.clone(), lane.attempt_id.clone())?;
        }
        CoordinatedAttemptState::Running => {}
        _ => return Err(ExecutionChainError::AttemptNotDispatchable),
    }
    // 6. Remainder runs through the verified dispatch chain, which re-checks
    //    the live triple before authoritative use.
    dispatch_execution_unit(ExecutionDispatchInput {
        attached: &attached,
        coordinator: input.coordinator,
        context,
        attempt_id: lane.attempt_id.clone(),
        lease_id: lane.lease_id.clone(),
        live_session: input.live_session,
        live_fence: input.live_fence,
        live_task: input.live_task,
        provider_scope_ref: input.provider_scope_ref,
        native_session: input.native_session,
        execution_unit: input.execution_unit,
        start_request_id: input.start_request_id,
        start_request_bytes: input.start_request_bytes,
        provider_identity: input.provider_identity,
        provider_start_receipt_ref: input.provider_start_receipt_ref,
    })
}
