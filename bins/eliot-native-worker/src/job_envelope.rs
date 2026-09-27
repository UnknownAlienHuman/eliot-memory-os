//! Explicit job envelope for the production native-worker lifecycle.
//!
//! Issue #1912 (I14.1/A12.2/A12.3/A12.6/A14.7): the admitted
//! registration/claim/hello halves already bind principal, session,
//! `WorkScope`, Authority Epoch, State Fence, route class, task/job budget,
//! deadline, and cancellation, but no single contour value names them at
//! each boundary. This module projects those halves into one explicit
//! [`JobEnvelope`] and refuses fail-closed when any bound dimension is
//! missing or disagrees. It mints no authority: every check re-proves
//! admitted values, and cost accounting stays Governor-side (A14.7).

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{EpochId, SessionId, StateFence, TaskId};
use eliot_native_worker_core::{
    AttemptId, BudgetEnvelope, NativeClaimId, NativeWorkerClaim, NativeWorkerReadiness,
    ReadinessSubmission, WorkerLifecycle,
};
use eliot_process::OperationId;

use crate::NativeWorkerError;
use crate::admitted_material::ValidatedAdmittedMaterial;
use crate::governed_action::FinishState;

/// Maximum length for one opaque provider/tool/receipt reference.
pub const MAX_ATTRIBUTION_REF_LEN: usize = 256;

/// Explicit job envelope projected from admitted material.
///
/// Every field echoes an admitted half: principal/session from the
/// registration, `WorkScope`/route/budget/deadline/cancellation/task/job
/// from the claim, allowed effects (requested capabilities) plus the
/// handshake deadline/route from the hello, and the Authority Epoch plus
/// State Fence agreed across all three. Visibility, privacy class, and the
/// swarm leg of the budget have no typed field on the admitted halves, so
/// they are not projected here (see the issue record).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobEnvelope {
    /// Authenticated principal reference from the registration.
    pub principal_ref: String,
    /// Semantic session from the registration.
    pub session_id: SessionId,
    /// Task `WorkScope` identity from the claim.
    pub work_scope_id: String,
    /// Current authority epoch agreed across halves.
    pub authority_epoch: EpochId,
    /// Exact immutable fence agreed across halves.
    pub state_fence: StateFence,
    /// Allowed effects: capabilities the handshake requests.
    pub requested_capabilities: BTreeSet<String>,
    /// Admitted route/provider class label from the claim.
    pub route_class: String,
    /// Full canonical route label from the handshake.
    pub route_ref: String,
    /// Governed task identity from the claim.
    pub task_id: TaskId,
    /// Kernel-owned parent Durable Job identity from the claim.
    pub parent_job_id: String,
    /// Resource and context ceilings from the claim.
    pub budget: BudgetEnvelope,
    /// Claim deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Handshake deadline in Unix milliseconds.
    pub hello_deadline_unix_ms: u64,
    /// Cancellation policy governing the unit, from the claim.
    pub cancellation_policy_id: String,
    /// Distinct claim operation identity.
    pub claim_id: NativeClaimId,
    /// Attempt identity bound to the claim.
    pub attempt_id: AttemptId,
    /// Exact external-effect operation identity.
    pub operation_id: OperationId,
    /// Predecessor revision the claim continues from.
    pub predecessor_revision: String,
    /// Replay stream identity bound to the claim generation, when the v2
    /// executable join carries one.
    pub replay_stream_id: Option<String>,
}

/// Requires the explicit job envelope for one admitted presentation.
///
/// Runs the production registration/claim binding validation, then binds
/// the handshake to the claim (epoch, fence, generation, handshake deadline
/// bounded and inside the claim window, non-empty requested capabilities,
/// join route when a v2 join is present). Any disagreement is a refused presentation before any
/// lifecycle submit or process start. Pure projection otherwise.
///
/// # Errors
///
/// Returns the underlying binding failure or
/// [`NativeWorkerError::KernelAdmissionRequired`] for a handshake that
/// does not answer the admitted claim.
pub fn require_job_envelope(
    material: &ValidatedAdmittedMaterial,
) -> Result<JobEnvelope, NativeWorkerError> {
    material
        .admission
        .validate_binding()
        .map_err(NativeWorkerError::from)?;
    let registration = material.admission.registration();
    let claim = material.admission.claim();
    let hello = &material.hello;
    if !hello
        .authority_epoch
        .is_same_authority(&claim.authority_epoch)
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope epoch disagrees: the hello authority epoch is not the admitted claim epoch"
                .to_owned(),
        ));
    }
    if hello.state_fence != claim.state_fence {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope fence disagrees: the hello state fence is not the admitted claim fence"
                .to_owned(),
        ));
    }
    if hello.worker_generation != claim.worker_generation {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope generation disagrees: the hello worker generation is not the admitted claim generation"
                .to_owned(),
        ));
    }
    if hello.deadline_unix_ms == 0 {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope deadline missing: the hello carries no bounded deadline".to_owned(),
        ));
    }
    // The worker-originated handshake deadline sits strictly inside the
    // claim window (the kernel-file reader caps it there): a hello that
    // outlives the admitted claim could complete after the unit expired,
    // so the presentation is refused before any lifecycle submit.
    if hello.deadline_unix_ms > claim.deadline_unix_ms {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope deadline disagrees: the hello handshake deadline outlives the admitted claim window"
                .to_owned(),
        ));
    }
    if hello.requested_capabilities.is_empty() {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope allowed effects missing: the hello requests no capabilities".to_owned(),
        ));
    }
    if let Some(join) = claim.executable_binding.as_ref()
        && join.route_ref != hello.route_ref
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "job envelope route disagrees: the executable join route does not bind the presented hello"
                .to_owned(),
        ));
    }
    Ok(JobEnvelope {
        principal_ref: registration.principal_ref.clone(),
        session_id: registration.session_id.clone(),
        work_scope_id: claim.work_scope_id.clone(),
        authority_epoch: claim.authority_epoch.clone(),
        state_fence: claim.state_fence.clone(),
        requested_capabilities: hello.requested_capabilities.clone(),
        route_class: claim.route_class.clone(),
        route_ref: hello.route_ref.clone(),
        task_id: claim.task_id.clone(),
        parent_job_id: claim.parent_job_id.clone(),
        budget: claim.budget.clone(),
        deadline_unix_ms: claim.deadline_unix_ms,
        hello_deadline_unix_ms: hello.deadline_unix_ms,
        cancellation_policy_id: claim.cancellation_policy_id.clone(),
        claim_id: claim.claim_id.clone(),
        attempt_id: claim.attempt_id.clone(),
        operation_id: claim.operation_id.clone(),
        predecessor_revision: claim.predecessor_revision.clone(),
        replay_stream_id: claim
            .executable_binding
            .as_ref()
            .map(|join| join.replay_stream_id.clone()),
    })
}

/// Requires the owner's ready verdict before any paid start (issue #1912).
///
/// A `Blocked` verdict names the dimension refusing the unit; starting a
/// process against it would spend budget the owner already refused. The
/// refusal names the dimension plus the claim/task/job identities so
/// supervision sees what was preserved. A `Ready` verdict passes through.
///
/// # Errors
///
/// Returns [`NativeWorkerError::KernelAdmissionRequired`] when the
/// verdict is `Blocked`.
pub fn require_paid_start_eligible(
    readiness: &ReadinessSubmission,
) -> Result<(), NativeWorkerError> {
    match readiness.readiness() {
        NativeWorkerReadiness::Ready(_) => Ok(()),
        NativeWorkerReadiness::Blocked(report) => {
            let claim = readiness.claim();
            Err(NativeWorkerError::KernelAdmissionRequired(format!(
                "job cannot start paid work: owner verdict is BLOCKED on dimension {:?} for claim '{}' task '{}' job '{}'; no adapter invoked, no process started, prior state unchanged",
                report.dimension,
                claim.claim_id.as_str(),
                claim.task_id.as_str(),
                claim.parent_job_id,
            )))
        }
    }
}

/// Provider/tool consumption receipt bound to its originating task/job.
///
/// Opaque bounded references only (`provider_ref`, `tool_ref`,
/// `receipt_ref` carry no meter values and grant nothing); the typed
/// task/job/claim/attempt/operation identities must equal the admitted
/// claim's. Cost accounting stays Governor-side (A14.7): this record is
/// the attribution binding, never a ledger. No swarm identity exists on
/// the admitted claim, so the swarm leg is not bound here (see the issue
/// record).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumptionAttribution {
    /// Opaque provider reference from the consumption receipt.
    pub provider_ref: String,
    /// Opaque tool reference from the consumption receipt.
    pub tool_ref: String,
    /// Opaque provider/tool receipt reference.
    pub receipt_ref: String,
    /// Governed task identity the receipt is attributed to.
    pub task_id: TaskId,
    /// Kernel-owned parent Durable Job identity the receipt is attributed to.
    pub parent_job_id: String,
    /// Claimed unit the receipt is attributed to.
    pub claim_id: NativeClaimId,
    /// Attempt identity the receipt is attributed to.
    pub attempt_id: AttemptId,
    /// Exact external-effect operation identity the receipt is attributed to.
    pub operation_id: OperationId,
}

/// Requires one consumption receipt to bind its originating task/job.
///
/// Validates the opaque reference shapes, then requires the typed
/// task/job/claim/attempt/operation identities to equal the admitted
/// claim's. A foreign receipt is refused before any result submit.
///
/// # Errors
///
/// Returns [`NativeWorkerError::KernelAdmissionRequired`] for a malformed
/// reference or an identity that does not answer the admitted claim.
pub fn require_consumption_attribution(
    claim: &NativeWorkerClaim,
    attribution: &ConsumptionAttribution,
) -> Result<(), NativeWorkerError> {
    for (field, value) in [
        ("provider_ref", attribution.provider_ref.as_str()),
        ("tool_ref", attribution.tool_ref.as_str()),
        ("receipt_ref", attribution.receipt_ref.as_str()),
    ] {
        if value.trim().is_empty()
            || value.len() > MAX_ATTRIBUTION_REF_LEN
            || value.chars().any(char::is_control)
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(format!(
                "consumption attribution field '{field}' is missing, oversized, or malformed"
            )));
        }
    }
    if attribution.task_id != claim.task_id
        || attribution.parent_job_id != claim.parent_job_id
        || attribution.claim_id != claim.claim_id
        || attribution.attempt_id != claim.attempt_id
        || attribution.operation_id != claim.operation_id
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "consumption receipt does not bind the originating task/job/claim/attempt/operation"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Visible coverage-gap disposition for a terminally incomplete serve.
///
/// Emitted when the stdio loop ends with the worker cancelled or holding
/// an unknown outcome: verified partial output stays under the original
/// claim for reconciliation (durable replay/checkpoint retention), and
/// this record keeps the gap visible instead of silently lost. The
/// `finish` word uses the honest A10.8 vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageGap {
    /// Claimed unit the gap belongs to.
    pub claim_id: String,
    /// Governed task identity the gap belongs to.
    pub task_id: String,
    /// Kernel-owned parent Durable Job identity the gap belongs to.
    pub parent_job_id: String,
    /// Attempt identity the gap belongs to.
    pub attempt_id: String,
    /// Exact external-effect operation identity the gap belongs to.
    pub operation_id: String,
    /// Honest finish word for the incomplete serve.
    pub finish: FinishState,
    /// Durable retention locator: the claim-bound replay stream, or the
    /// claim identity when no v2 join names a stream.
    pub retention_ref: String,
    /// Bounded reason naming what was preserved and what stays open.
    pub reason: String,
}

impl CoverageGap {
    /// Builds the coverage-gap record for a terminally incomplete serve.
    ///
    /// Returns `Some` when `lifecycle` is `Cancelling`, `Cancelled`, or
    /// `UnknownOutcome`; any other lifecycle served to its own terminal
    /// state and carries no worker-visible gap. Pure projection.
    #[must_use]
    pub fn for_job_envelope(envelope: &JobEnvelope, lifecycle: WorkerLifecycle) -> Option<Self> {
        let (finish, reason) = match lifecycle {
            WorkerLifecycle::Cancelling | WorkerLifecycle::Cancelled => (
                FinishState::Cancelled,
                "cancellation observed: verified partial output stays under the original claim for reconciliation; no further paid starts under this attempt",
            ),
            WorkerLifecycle::UnknownOutcome => (
                FinishState::Partial,
                "unknown outcome: the retained attempt reconciles under the original claim; the coverage gap stays visible until the reconcile verdict",
            ),
            _ => return None,
        };
        Some(Self {
            claim_id: envelope.claim_id.as_str().to_owned(),
            task_id: envelope.task_id.as_str().to_owned(),
            parent_job_id: envelope.parent_job_id.clone(),
            attempt_id: envelope.attempt_id.as_str().to_owned(),
            operation_id: envelope.operation_id.as_str().to_owned(),
            finish,
            retention_ref: envelope
                .replay_stream_id
                .clone()
                .unwrap_or_else(|| envelope.claim_id.as_str().to_owned()),
            reason: reason.to_owned(),
        })
    }
}
