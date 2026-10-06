//! A-13's provider-neutral isolated native-worker protocol core.
//!
//! A-13 owns the worker protocol and lifecycle. G-01-facing admission,
//! P-03 process execution, and durable replay/cursor storage are injected.
//! This crate never starts a process directly, opens a database, persists a
//! private journal, or converts a public request into authority.

#![forbid(unsafe_code)]

mod action_envelope;
mod generated {
    include!(concat!(env!("OUT_DIR"), "/native_worker_facets_v1.rs"));
}
mod ports;
mod protocol;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Constituent envelope types of the public claim protocol, re-exported so
/// composition roots (which must not depend on the agent plane directly) can
/// build and inspect claims through this crate's API.
pub use action_envelope::{
    ActionEnvelopeCarrier, ActionEnvelopeCarrierError, MAX_ACTION_ENVELOPE_BYTES,
    MAX_ACTION_ENVELOPE_OP_LEN,
};
pub use eliot_agent_api::{
    AttemptId, AuthorityEnvelope, BudgetEnvelope, EffectCeiling, EffectKind,
};
use eliot_agent_api::{AuthorizedEffect, ProposedEffect};
use eliot_contracts::{EpochId, RequestId, ResourceGeneration};
use eliot_process::{
    CancellationStatus, EvidenceSinkError, FencingToken, OperationId,
    PROCESS_CONTRACT_SCHEMA_VERSION, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessLifecycle, ProcessRequest, ProcessStartReceipt,
};
use eliot_receipts::{ProofCeiling, ReceiptDisposition};
use eliot_runtime_contracts::{CapacityBottleneck, CapacityPermitBinding, CapacityRequest};
pub use generated::{
    NativeWorkerExecuteEbpCallV1, NativeWorkerFacetStubError, compile_native_worker_execute_call_v1,
};
use thiserror::Error;

pub use eliot_protocol::AckPhase;
use ports::{AdmissionLiveness, CapabilityGrant, EffectAdmissionGrant, ProcessBindingSnapshot};
pub use ports::{
    AdmissionLivenessFacts, AdmissionLivenessOutcome, CapabilityAdmissionFacts,
    CapabilityAdmissionOutcome, CapabilityAdmissionPort, CapabilityAdmissionRequest,
    CapabilityLivenessRequest, CheckpointProviderOutcome, CheckpointReceiptFacts,
    ClaimAdmissionRequest, DurableCheckpointPort, DurableCheckpointRequest, DurableReplayPort,
    DurableRequestDecision, EffectAdmissionFacts, EffectAdmissionOutcome, EffectAdmissionRequest,
    ProviderFailure, ReadinessSubmission,
};
pub use protocol::{
    CancelRequest, CheckpointRequest, ClaimBindingDecision, ClaimConflict, DeliveryClass,
    EXECUTION_UNIT_SCHEMA_VERSION, EventAckReceipt, JSON_ENCODING_PROFILE, MAX_CLAIM_TEXT_LEN,
    MAX_CREDENTIAL_REFERENCES, MAX_INVALIDATION_ENTRIES, MAX_OPERATION_IDENTITY_LEN,
    NATIVE_WORKER_CLAIM_WIRE_VERSION, NATIVE_WORKER_CLAIM_WIRE_VERSION_V1,
    NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION, NativeAckId, NativeAckRecord,
    NativeBlockedReport, NativeCancellationEnvelope, NativeCancellationId,
    NativeCheckpointEnvelope, NativeCheckpointId, NativeClaimId, NativeHeartbeatEnvelope,
    NativeHeartbeatId, NativeLifecycleBinding, NativeReadyId, NativeReadyReport,
    NativeRegistrationId, NativeRenewalId, NativeResultEnvelope, NativeResultId, NativeWorkerClaim,
    NativeWorkerExecutableBinding, NativeWorkerExecutableExpectation, NativeWorkerReadiness,
    NativeWorkerRegistration, PROTOCOL_VERSION, ReadinessBlockDimension, ReconnectRequest,
    WorkerEventDraft, WorkerEventEnvelope, WorkerEventPayload, WorkerFrame, WorkerFrameBody,
    WorkerHello, WorkerLifecycle, WorkerReady, WorkerRecovery, WorkerRequest,
};

pub const PROCESS_CONTRACT_VERSION: &str = PROCESS_CONTRACT_SCHEMA_VERSION;
pub const PROCESS_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:P-03-PROCESS-EXECUTOR-UNAVAILABLE";
pub const PROCESS_EVIDENCE_PLAN_GAP: &str = "PLAN_GAP:A-13:P-03-EVIDENCE-SINK-UNAVAILABLE";
pub const ADMISSION_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:G-01-ADMISSION-UNAVAILABLE";
pub const REPLAY_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:DURABLE-REPLAY-UNAVAILABLE";
pub const CHECKPOINT_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:DURABLE-CHECKPOINT-UNAVAILABLE";

struct ObservingEvidenceSink {
    downstream: Arc<dyn ProcessEvidenceSink>,
    observed: Mutex<Vec<ProcessEvidence>>,
}

impl ObservingEvidenceSink {
    fn new(downstream: Arc<dyn ProcessEvidenceSink>) -> Self {
        Self {
            downstream,
            observed: Mutex::new(Vec::new()),
        }
    }

    fn snapshot(&self) -> Result<Vec<ProcessEvidence>, WorkerError> {
        self.observed
            .lock()
            .map(|observed| observed.clone())
            .map_err(|_| WorkerError::Process("P-03 evidence observer lock failed".to_owned()))
    }
}

impl ProcessEvidenceSink for ObservingEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        self.downstream.record(evidence.clone())?;
        self.observed
            .lock()
            .map_err(|_| EvidenceSinkError {
                message: "A-13 evidence observer lock failed".to_owned(),
            })?
            .push(evidence);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerError {
    #[error("native-worker protocol version is unsupported")]
    UnsupportedVersion,
    #[error("native-worker encoding profile is unsupported")]
    UnsupportedEncoding,
    #[error("invalid handshake field {0}")]
    InvalidHandshake(&'static str),
    #[error("invalid frame field {0}")]
    InvalidFrame(&'static str),
    #[error("invalid request field {0}")]
    InvalidRequest(&'static str),
    #[error("worker is not attached and ready")]
    NotReady,
    #[error("worker lifecycle transition is invalid")]
    InvalidLifecycle,
    #[error("worker frame connection is stale")]
    StaleConnection,
    #[error("worker authority epoch is stale")]
    StaleEpoch,
    #[error("worker state fence is stale")]
    StaleFence,
    #[error("worker lease is stale or expired")]
    StaleLease,
    #[error("worker admission revision is stale")]
    StaleRevision,
    #[error("worker admission was revoked at {0}")]
    Revoked(String),
    #[error("worker deadline expired")]
    DeadlineExpired,
    #[error("admission was rejected: {0}")]
    AdmissionRejected(String),
    #[error("admission outcome did not bind {0}")]
    AdmissionMismatch(&'static str),
    #[error("effect admission was rejected: {0}")]
    EffectRejected(String),
    #[error("effect admission outcome did not bind {0}")]
    EffectMismatch(&'static str),
    #[error("checkpoint provider rejected request: {0}")]
    CheckpointRejected(String),
    #[error("checkpoint receipt did not bind {0}")]
    CheckpointReceiptMismatch(&'static str),
    #[error("request id was reused with different content")]
    IdempotencyConflict,
    #[error("durable replay contract rejected {0}")]
    ReplayContract(&'static str),
    #[error("provider failure: {0}")]
    Provider(String),
    #[error("process contract failure: {0}")]
    Process(String),
    #[error("process start receipt did not bind {0}")]
    ProcessReceiptMismatch(&'static str),
    #[error("process outcome is unknown and requires reconciliation")]
    UnknownOutcome,
    #[error("{code}: {detail}")]
    PlanGap {
        code: &'static str,
        detail: &'static str,
    },
}

fn map_native_worker_facet_stub_error(
    error: crate::generated::NativeWorkerFacetStubError,
) -> WorkerError {
    match error {
        crate::generated::NativeWorkerFacetStubError::InvalidField(field) => {
            WorkerError::InvalidRequest(field)
        }
        crate::generated::NativeWorkerFacetStubError::InvalidSource => {
            WorkerError::InvalidRequest("execute_facet_source")
        }
        crate::generated::NativeWorkerFacetStubError::Serialization => {
            WorkerError::InvalidRequest("execute_facet_encoding")
        }
    }
}

fn prepare_execute_call_and_fingerprint(
    frame: &WorkerFrame,
    grant: &CapabilityGrant,
) -> Result<String, WorkerError> {
    if let WorkerFrameBody::Execute(call) = &frame.body {
        let admitted_facet = crate::protocol::admitted_facet_ref_for_dispatch(
            grant.claim_binding_digest(),
            grant.executable_expectation(),
        )?;
        if let Some(facet_ref) = admitted_facet {
            let binding = &grant
                .executable_expectation()
                .ok_or(WorkerError::InvalidRequest("executable_binding"))?
                .current;
            if frame.authority_epoch != binding.authority_epoch {
                return Err(WorkerError::StaleEpoch);
            }
            if frame.state_fence != binding.state_fence {
                return Err(WorkerError::StaleFence);
            }
            let admitted_attempt = grant
                .claim_attempt_id()
                .ok_or(WorkerError::InvalidRequest("execute_attempt_binding"))?;
            if &call.input.attempt_id != admitted_attempt {
                return Err(WorkerError::AdmissionMismatch("attempt_id"));
            }
            call.validate_for_dispatch(facet_ref, &binding.capability_cell)
                .map_err(map_native_worker_facet_stub_error)?;
        } else {
            // Pre-claim starts have no owner-produced executable join. Keep
            // their existing compatibility contour while requiring a valid,
            // generated Execute call from the canonical ELIOT facet source.
            call.validate_for_dispatch(&call.facet_manifest_ref, &call.capability_cell)
                .map_err(map_native_worker_facet_stub_error)?;
        }
        return serde_json::to_string(call).map_err(|_| WorkerError::InvalidFrame("fingerprint"));
    }
    serde_json::to_string(&frame.body).map_err(|_| WorkerError::InvalidFrame("fingerprint"))
}

/// Link to the live process-capacity owner consulted at every claimed launch
/// and recovery use (issue #1701, R2-owners/W5).
///
/// The held reservation lives with the capacity owner (the Host/Kernel
/// process-tree owner on the control-reserve boundary), never in this core: a
/// retained [`CapacityPermitBinding`] alone is evidence of a past grant, not
/// live capacity. The composition root links the current owner lookup here;
/// the claimed gates replay it at every use and carry its authenticated
/// identity into the start/recovery decision. No link means no live
/// authority, and the gates refuse fail-closed.
///
/// Norm: `docs/architecture/I14-03-control-reserve.md:3-13,29`.
pub type CapacityAuthorityLink = Arc<dyn ProcessCapacityAuthority + Send + Sync>;

/// Authenticated owner-mediated capacity lookup for one retained permit
/// (issue #1701, R2-owners/W5).
///
/// This is the consumer side of the process-capacity handoff: the implementor
/// holds the live owner reservation (or a mediated path to it) and replays
/// the owner's exact issuance/currency check — same owner instance, exact
/// issuance record, current owner generation, profile, and epoch — against
/// the retained binding and request. A detached binding alone is never
/// sufficient: without the live holding there is nothing to authenticate
/// against, so the lookup fails closed.
///
/// Norm: `docs/architecture/I14-06-durable-work-admission-and-execution-axes.md:49-61`.
pub trait ProcessCapacityAuthority {
    /// Replays the authenticated owner lookup for one retained pair.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityAuthorityError::NotHeld`] when no live holding
    /// remains (released or never acquired),
    /// [`CapacityAuthorityError::ForeignOwner`] when the holding lives at
    /// another owner instance, [`CapacityAuthorityError::StaleEpoch`] when the
    /// authority epoch moved, [`CapacityAuthorityError::StaleOwner`] when the
    /// owner generation or compiled profile moved,
    /// [`CapacityAuthorityError::Conflict`] when the binding is not the
    /// holding's issuance record or does not match its request, or
    /// [`CapacityAuthorityError::Unavailable`] when the lookup itself cannot
    /// run (fail-closed, never a pass).
    fn verify_live_capacity(
        &self,
        binding: &CapacityPermitBinding,
        request: &CapacityRequest,
    ) -> Result<VerifiedCapacityIdentity, CapacityAuthorityError>;
}

/// Exact identity the capacity owner authenticated for one live permit
/// (issue #1701, R2-owners/W5).
///
/// Carried from the owner's verification into the consumer: the claimed gates
/// keep this value alongside the retained binding and require the lookup to
/// return the identical value at every use, so a rotated handle or a
/// substituted record refuses instead of replaying.
///
/// Norm: `docs/architecture/I14-20-canonical-runtime-lifecycle-vocabulary.md:91-99`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCapacityIdentity {
    /// Owner-minted permit identity of the live holding.
    pub permit_id: String,
    /// Operation identity the holding was granted for.
    pub operation_id: String,
    /// Bottleneck dimension the holding was granted from.
    pub bottleneck: CapacityBottleneck,
    /// Capacity owner that authenticated the holding.
    pub capacity_owner_ref: String,
    /// Owner generation the holding was issued under.
    pub owner_generation: ResourceGeneration,
    /// Compiled profile identity the holding is bound to.
    pub profile_id: String,
    /// Compiled profile revision the holding is bound to.
    pub profile_revision: String,
    /// Authority epoch the holding is fenced against.
    pub authority_epoch: EpochId,
}

impl VerifiedCapacityIdentity {
    /// Returns `true` only when every authenticated field names the presented
    /// binding. Changed content never matches; it conflicts instead of
    /// replaying.
    #[must_use]
    pub fn binds_permit(&self, binding: &CapacityPermitBinding) -> bool {
        self.permit_id == binding.permit_id
            && self.operation_id == binding.operation_id
            && self.bottleneck == binding.bottleneck
            && self.capacity_owner_ref == binding.capacity_owner_ref
            && self.owner_generation == binding.capacity_owner_generation_ref
            && self.profile_id == binding.profile_id
            && self.profile_revision == binding.profile_revision
            && self.authority_epoch == binding.authority_epoch_ref
    }
}

/// Typed refusal of one owner-mediated capacity lookup (issue #1701,
/// R2-owners/W5). Every variant refuses before P-03 starts anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityAuthorityError {
    /// No live holding remains: the permit was released (or never acquired).
    NotHeld,
    /// The permit is held at another owner instance.
    ForeignOwner,
    /// The authority epoch moved under the retained binding.
    StaleEpoch,
    /// The owner generation or compiled profile moved under the retained binding.
    StaleOwner,
    /// The binding is not the holding's issuance record, or does not match
    /// its request: changed content conflicts instead of replaying.
    Conflict,
    /// The lookup itself was unavailable. Fail-closed, never a pass.
    Unavailable,
}

/// Maps one owner-lookup refusal to the typed gate error.
fn map_capacity_authority_error(operation_id: &str, error: CapacityAuthorityError) -> WorkerError {
    match error {
        CapacityAuthorityError::NotHeld => WorkerError::AdmissionRejected(format!(
            "capacity_permit_released: no live owner holding remains for operation {operation_id}"
        )),
        CapacityAuthorityError::ForeignOwner => {
            WorkerError::AdmissionMismatch("capacity_permit_foreign_owner")
        }
        CapacityAuthorityError::StaleEpoch => WorkerError::StaleEpoch,
        CapacityAuthorityError::StaleOwner => {
            WorkerError::AdmissionMismatch("capacity_permit_stale_owner")
        }
        CapacityAuthorityError::Conflict => {
            WorkerError::AdmissionMismatch("capacity_permit_authority_conflict")
        }
        CapacityAuthorityError::Unavailable => WorkerError::AdmissionRejected(format!(
            "capacity_authority_unavailable: owner lookup unavailable for operation {operation_id}"
        )),
    }
}

/// Owner-issued process-launch capacity retained under one operation identity
/// (issue #1701, R2-owners/W5).
///
/// The binding and request are the presented evidence; the verified identity
/// is what the linked owner lookup authenticated at presentation; the link
/// is the live lookup the gates replay at every use. A data-only retention
/// (no link) keeps the evidence but refuses at the gates: without a live
/// authority there is nothing to authenticate against.
struct RetainedCapacityPermit {
    /// Presented owner-issued binding.
    binding: CapacityPermitBinding,
    /// Request the binding was issued for.
    request: CapacityRequest,
    /// Identity the linked lookup authenticated at presentation, if any.
    verified_identity: Option<VerifiedCapacityIdentity>,
    /// Live owner lookup replayed at every use, if any.
    authority: Option<CapacityAuthorityLink>,
}

/// Evidence checks shared by both capacity presentations (issue #1701,
/// R2-owners/W5): a malformed request or binding, a binding that does not
/// match its request, a non-process-launch bottleneck, or an expired window
/// refuses before any effect or retention.
fn check_capacity_pair(
    permit: &CapacityPermitBinding,
    request: &CapacityRequest,
    now_ms: u64,
) -> Result<(), WorkerError> {
    request
        .validate()
        .map_err(|_| WorkerError::InvalidRequest("capacity_permit_request"))?;
    permit
        .validate()
        .map_err(|_| WorkerError::InvalidRequest("capacity_permit_binding"))?;
    if !permit.matches_request(request) {
        return Err(WorkerError::InvalidRequest("capacity_permit_foreign"));
    }
    if permit.bottleneck != CapacityBottleneck::ProcessLaunchSlots {
        return Err(WorkerError::InvalidRequest("capacity_permit_bottleneck"));
    }
    if permit.expires_at_ms <= now_ms {
        return Err(WorkerError::DeadlineExpired);
    }
    Ok(())
}

/// A-13's composition core. Generic P-03 injection is required because the
/// canonical `ProcessExecutor` async trait deliberately remains provider-neutral.
pub struct WorkerCore<E, A, R, C> {
    executor: Option<E>,
    admission: Option<A>,
    replay: Option<R>,
    checkpoint: Option<C>,
    evidence_sink: Option<Arc<dyn ProcessEvidenceSink>>,
    lifecycle: WorkerLifecycle,
    grant: Option<CapabilityGrant>,
    capacity_permit: Option<RetainedCapacityPermit>,
    process_binding: Option<ProcessBindingSnapshot>,
    process_start_receipt: Option<ProcessStartReceipt>,
    connection_id: Option<String>,
    last_event_id: Option<String>,
    last_event_sequence: u64,
}

impl<E, A, R, C> WorkerCore<E, A, R, C>
where
    E: ProcessExecutor,
    A: CapabilityAdmissionPort,
    R: DurableReplayPort,
    C: DurableCheckpointPort,
{
    #[must_use]
    pub fn new(
        executor: Option<E>,
        admission: Option<A>,
        replay: Option<R>,
        checkpoint: Option<C>,
        evidence_sink: Option<Arc<dyn ProcessEvidenceSink>>,
    ) -> Self {
        Self {
            executor,
            admission,
            replay,
            checkpoint,
            evidence_sink,
            lifecycle: WorkerLifecycle::Created,
            grant: None,
            capacity_permit: None,
            process_binding: None,
            process_start_receipt: None,
            connection_id: None,
            last_event_id: None,
            last_event_sequence: 0,
        }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> WorkerLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn process_state(&self) -> eliot_runtime_contracts::ServiceProcessState {
        self.lifecycle.service_state()
    }

    #[must_use]
    pub const fn process_start_receipt(&self) -> Option<&ProcessStartReceipt> {
        self.process_start_receipt.as_ref()
    }

    /// Admits an exact route/capability envelope, invokes P-03, and becomes
    /// ready only after the returned start receipt binds the exact request.
    pub async fn demand_start(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<WorkerReady, WorkerError> {
        let admission_request = CapabilityAdmissionRequest::from_start(&hello, &process);
        self.demand_start_inner(hello, process, admission_request)
            .await
    }

    /// Consumes one owner-issued process-launch capacity permit and retains
    /// it under the admitted operation identity (issue #1701, R2-owners/W5).
    ///
    /// The issuing owner is the control-reserve capacity owner on the
    /// `ControlReserveFrontDoor::issue_permit` boundary
    /// (`eliot-kernel-core`); this core never mints a permit, it only
    /// validates a presented binding against the request it was issued for
    /// and retains the exact pair. A data-only retention carries no live
    /// lookup, so the claimed launch/recovery gates refuse it fail-closed
    /// (`capacity_authority_unlinked`): use
    /// [`WorkerCore::admit_capacity_permit_verified`] to attach the live
    /// owner lookup. A malformed request or binding, a binding
    /// that does not match its request (foreign operation, owner, epoch, or
    /// profile revision), a binding that names any bottleneck dimension other
    /// than the process-launch path this core starts through, or an expired
    /// binding is refused here, before any effect. Only the exact
    /// `ProcessLaunchSlots` vector is consumable here: any other dimension
    /// (notably a control-channel permit) authorizes other work, never a
    /// process start. Retention is keyed by operation identity: re-presenting the
    /// identical binding is idempotent (post-restart evidence replay), while
    /// changed content for the same operation conflicts instead of replaying
    /// unless the lifecycle is quiescent (`Created`, `Stopped`, `Cancelled`,
    /// or `Reconciled` — the previous attempt reached a proven terminal
    /// state, so a linked new revision after a clean failure replaces the
    /// retention). While a possible effect is outstanding, a different
    /// operation's permit is refused: unknown outcomes retain exclusion.
    /// Norm: `docs/architecture/I14-03-control-reserve.md` (independent
    /// process-launch capacity) and the frozen `CapacityPermitBinding`
    /// match/replay rule.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for a malformed request or
    /// binding, a binding that does not match its request, or a binding that
    /// names any bottleneck dimension other than the process-launch path
    /// (`capacity_permit_bottleneck`);
    /// [`WorkerError::DeadlineExpired`] for an expired binding;
    /// [`WorkerError::IdempotencyConflict`] for changed content while a
    /// possible effect is outstanding; [`WorkerError::InvalidRequest`] with
    /// `capacity_permit_excluded` for a different operation while fenced.
    pub fn admit_capacity_permit(
        &mut self,
        permit: &CapacityPermitBinding,
        request: &CapacityRequest,
        now_ms: u64,
    ) -> Result<(), WorkerError> {
        check_capacity_pair(permit, request, now_ms)?;
        self.retain_capacity_pair(permit, request, None, None)
    }

    /// Consumes one owner-issued process-launch capacity permit with its live
    /// owner lookup and retains both under the admitted operation identity
    /// (issue #1701, R2-owners/W5).
    ///
    /// Runs the same evidence checks as
    /// [`WorkerCore::admit_capacity_permit`], then replays the linked owner
    /// lookup against the presented pair before retaining anything: a
    /// released holding, a foreign instance, a stale owner/generation/
    /// profile/epoch, or a binding that is not the holding's issuance record
    /// refuses here, before any effect. The authenticated identity is carried
    /// into the retention and re-proved at every launch/recovery use, so a
    /// rotated handle or substituted record after presentation refuses instead
    /// of replaying. While a possible effect is outstanding, unknown outcomes
    /// keep the actual retained owner exclusion until receipted resolution or
    /// release replaces it — exactly like the data-only presentation, only
    /// with the live lookup attached.
    ///
    /// # Errors
    ///
    /// Returns the [`WorkerCore::admit_capacity_permit`] evidence refusals,
    /// the typed owner-lookup refusal (`AdmissionRejected`
    /// `capacity_permit_released` / `capacity_authority_unavailable`,
    /// `AdmissionMismatch` `capacity_permit_foreign_owner` /
    /// `capacity_permit_authority_conflict` /
    /// `capacity_permit_stale_owner`, or `StaleEpoch`), `AdmissionMismatch`
    /// `capacity_permit_identity` when the lookup answers for another
    /// binding, or the retention conflict/exclusion refusals.
    pub fn admit_capacity_permit_verified(
        &mut self,
        permit: &CapacityPermitBinding,
        request: &CapacityRequest,
        now_ms: u64,
        authority: CapacityAuthorityLink,
    ) -> Result<(), WorkerError> {
        check_capacity_pair(permit, request, now_ms)?;
        let identity = authority
            .verify_live_capacity(permit, request)
            .map_err(|error| map_capacity_authority_error(&permit.operation_id, error))?;
        if !identity.binds_permit(permit) {
            return Err(WorkerError::AdmissionMismatch("capacity_permit_identity"));
        }
        self.retain_capacity_pair(permit, request, Some(identity), Some(authority))
    }

    /// Returns the owner-authenticated identity carried for the retained
    /// permit, if a live lookup authenticated one at presentation.
    #[must_use]
    pub fn retained_capacity_identity(&self) -> Option<&VerifiedCapacityIdentity> {
        self.capacity_permit
            .as_ref()
            .and_then(|retained| retained.verified_identity.as_ref())
    }

    /// Retains one evidence-checked pair under the operation identity.
    ///
    /// Re-presenting the identical binding is idempotent (post-restart
    /// evidence replay): a verified re-presentation additionally refreshes
    /// the carried identity and link, while a data-only re-presentation keeps
    /// the existing retention untouched. Changed content for the same
    /// operation conflicts instead of replaying unless the lifecycle is
    /// quiescent — the previous attempt reached a proven terminal state, so
    /// a linked new revision after a clean failure replaces the retention.
    /// While a possible effect is outstanding, a different operation's permit
    /// is refused: unknown outcomes retain exclusion.
    fn retain_capacity_pair(
        &mut self,
        permit: &CapacityPermitBinding,
        request: &CapacityRequest,
        identity: Option<VerifiedCapacityIdentity>,
        authority: Option<CapacityAuthorityLink>,
    ) -> Result<(), WorkerError> {
        if let Some(retained) = self.capacity_permit.as_ref() {
            if retained.binding == *permit {
                if let (Some(identity), Some(authority)) = (identity, authority) {
                    self.capacity_permit = Some(RetainedCapacityPermit {
                        binding: permit.clone(),
                        request: request.clone(),
                        verified_identity: Some(identity),
                        authority: Some(authority),
                    });
                }
                return Ok(());
            }
            if matches!(
                self.lifecycle,
                WorkerLifecycle::Created
                    | WorkerLifecycle::Stopped
                    | WorkerLifecycle::Cancelled
                    | WorkerLifecycle::Reconciled
            ) {
                self.capacity_permit = Some(RetainedCapacityPermit {
                    binding: permit.clone(),
                    request: request.clone(),
                    verified_identity: identity,
                    authority,
                });
                return Ok(());
            }
            if retained.binding.operation_id == permit.operation_id {
                return Err(WorkerError::IdempotencyConflict);
            }
            return Err(WorkerError::InvalidRequest("capacity_permit_excluded"));
        }
        self.capacity_permit = Some(RetainedCapacityPermit {
            binding: permit.clone(),
            request: request.clone(),
            verified_identity: identity,
            authority,
        });
        Ok(())
    }

    /// Requires the retained capacity permit to cover the claimed start.
    ///
    /// The retained binding must name the claim's exact operation identity,
    /// agree with the claim's authority epoch, name exactly the
    /// process-launch bottleneck this core starts through, bind the claim's
    /// own worker generation, and stay valid through the claim's deadline;
    /// otherwise the start is refused before P-03 starts anything. A missing
    /// retention refuses as an admission prerequisite (fail-closed: no
    /// owner-issued process-launch evidence, no effect), and so does a
    /// retention with no linked live lookup (fail-closed: a detached binding
    /// alone is evidence of a past grant, not live capacity). The generation
    /// and window re-checks run at every use — not only at presentation — so
    /// a generation move or an expired new-start permit after presentation
    /// refuses here, and an unknown outcome keeps the actual retained owner
    /// exclusion (not a copied string) until receipted reconciliation or
    /// release replaces it. The linked lookup additionally re-proves owner,
    /// generation, profile, and epoch currency at every use, so a
    /// profile-revision or owner-generation move after presentation refuses
    /// here even though the claim itself carries no profile identity (the
    /// data-level profile check stays with the dispatch contour binding the
    /// current revision into the admitted material: owner contract, issue
    /// #1679).
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::AdmissionRejected`] when no permit is retained
    /// for the operation, [`WorkerError::AdmissionMismatch`] when the
    /// retained permit names another operation, another bottleneck dimension,
    /// or another requester generation, [`WorkerError::StaleEpoch`] when the
    /// retained permit's epoch disagrees with the claim epoch, or
    /// [`WorkerError::DeadlineExpired`] when the retained permit does not
    /// cover the claim's deadline.
    fn require_capacity_for_claim(&self, claim: &NativeWorkerClaim) -> Result<(), WorkerError> {
        let retained = self.capacity_permit.as_ref().ok_or_else(|| {
            WorkerError::AdmissionRejected(format!(
                "capacity_permit_missing: no owner-issued process-launch permit retained for operation {}",
                claim.operation_id.as_str()
            ))
        })?;
        let retained_binding = &retained.binding;
        if retained_binding.operation_id != claim.operation_id.as_str() {
            return Err(WorkerError::AdmissionMismatch("capacity_permit_operation"));
        }
        if !retained_binding
            .authority_epoch_ref
            .is_same_authority(&claim.authority_epoch)
        {
            return Err(WorkerError::StaleEpoch);
        }
        if retained_binding.bottleneck != CapacityBottleneck::ProcessLaunchSlots {
            return Err(WorkerError::AdmissionMismatch("capacity_permit_bottleneck"));
        }
        if retained_binding.requesting_generation_ref.value() != claim.worker_generation {
            return Err(WorkerError::AdmissionMismatch("capacity_permit_generation"));
        }
        if claim.deadline_unix_ms >= retained_binding.expires_at_ms {
            return Err(WorkerError::DeadlineExpired);
        }
        // Live owner verification at every use (issue #1701, R2-owners/W5):
        // the retained binding alone is evidence of a past grant, not live
        // capacity. The linked lookup replays the owner's exact
        // issuance/currency check against the live holding — a released
        // holding, a foreign instance, or a moved owner/generation/profile/
        // epoch refuses here, before P-03 starts anything — and must answer
        // with the exact identity carried at presentation, so a rotated
        // handle or substituted record refuses instead of replaying. No
        // linked lookup means no live authority: fail-closed.
        let authority = retained.authority.as_ref().ok_or_else(|| {
            WorkerError::AdmissionRejected(format!(
                "capacity_authority_unlinked: no live owner lookup is linked for operation {}",
                claim.operation_id.as_str()
            ))
        })?;
        let identity = authority
            .verify_live_capacity(retained_binding, &retained.request)
            .map_err(|error| map_capacity_authority_error(&retained_binding.operation_id, error))?;
        if retained.verified_identity.as_ref() != Some(&identity) {
            return Err(WorkerError::AdmissionMismatch("capacity_permit_identity"));
        }
        Ok(())
    }

    /// Binds the existing start path to one exact claim presentation,
    /// validation only; mints nothing.
    ///
    /// First validates the claim/registration cross-binding, then performs
    /// the checked join of the claim with the owner-supplied `hello` and
    /// `process` via `CapabilityAdmissionRequest::from_claim` (including the
    /// executable join binding to `hello`/`process`/registration). Any
    /// mismatch fails here, before the admission owner is consulted and
    /// before P-03 starts anything. On a match the call delegates to the
    /// same downstream path as [`WorkerCore::demand_start`] (admit, grant
    /// validation including the claim echo and the owner-produced executable
    /// expectation, executable-binding gate, P-03 start, receipt/proof
    /// validation, ready). No `ProcessRequest` is minted and no grant is
    /// sealed by the join itself: only the supplied `claim`, `hello`, and
    /// `process` are reused.
    ///
    /// The executable-binding gate enforces the owner-produced T9-02 join:
    /// a valid owner record passes, while a changed route, adapter, config,
    /// facet, grant revision, nonce, stream, invocation digest, or owner
    /// digest, a stale or revoked authority, an epoch/fence/generation
    /// mismatch, an expired registration lease, or an expired window is refused with a typed
    /// [`WorkerError`] before P-03 starts anything.
    ///
    /// # Errors
    ///
    /// Returns the `from_claim` join failure (`InvalidRequest`,
    /// `UnsupportedVersion`, `StaleEpoch`, `StaleFence`, or
    /// `DeadlineExpired`), the capacity-permit refusal (`AdmissionRejected`
    /// when no owner-issued process-launch permit is retained,
    /// `AdmissionMismatch` for another operation, another bottleneck
    /// dimension, or another requester generation, `StaleEpoch` for a moved
    /// epoch, `DeadlineExpired` when the retained permit does not cover the
    /// claim deadline), the downstream admission/start/proof failure, or
    /// the typed executable-join refusal (`InvalidRequest`, `StaleEpoch`,
    /// `StaleFence`, `DeadlineExpired`, `Revoked`, or `UnsupportedVersion`).
    pub async fn demand_start_claimed(
        &mut self,
        claim: ClaimAdmissionRequest,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<WorkerReady, WorkerError> {
        claim.validate_binding()?;
        let admission_request = CapabilityAdmissionRequest::from_claim(&claim, &hello, &process)?;
        self.require_capacity_for_claim(claim.claim())?;
        self.demand_start_inner(hello, process, admission_request)
            .await
    }

    /// Shared downstream start path for [`WorkerCore::demand_start`] and
    /// [`WorkerCore::demand_start_claimed`]: lifecycle gate, owner
    /// validation, admission, grant checks (including the claim echo and the
    /// executable expectation when the request carries one), the executable
    /// join gate, P-03 start, and receipt/proof validation.
    ///
    /// Start-failure disposition (issue #1701, step 4): a reported
    /// [`ProcessExecutionError::UnknownOutcome`] retains the exact possible
    /// effect under the admitted binding. Any other start error is reconciled
    /// through the existing P-03 inspect owner before the local lifecycle
    /// moves: reset to `Created` happens only when the executor retains
    /// nothing under the admitted operation identity (`NotFound`, which
    /// establishes no effect from this call). A retained operation, a
    /// reported unknown outcome, or an inconclusive inspection retains the
    /// binding and fences to `UnknownOutcome`, blocking overlapping work
    /// until the existing reconcile path resolves the operation. The
    /// reservation is never released on a locally-unknown outcome.
    #[allow(clippy::too_many_lines)]
    async fn demand_start_inner(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
        admission_request: CapabilityAdmissionRequest,
    ) -> Result<WorkerReady, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Created | WorkerLifecycle::Stopped
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        hello.validate()?;
        process
            .validate()
            .map_err(|error| WorkerError::Process(error.to_string()))?;
        eliot_security_contracts::contract_identity()
            .map_err(|error| WorkerError::Provider(error.to_string()))?;
        self.require_replay()?;
        self.require_executor()?;
        let evidence_sink = self.evidence_sink.clone().ok_or(WorkerError::PlanGap {
            code: PROCESS_EVIDENCE_PLAN_GAP,
            detail: "P-03 evidence sink was not injected",
        })?;

        let admission_outcome = self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .admit(&admission_request)
            .map_err(provider_error)?;
        let grant = match admission_outcome {
            CapabilityAdmissionOutcome::Admitted(facts) => CapabilityGrant::seal(*facts),
            CapabilityAdmissionOutcome::Rejected { reason } => {
                return Err(WorkerError::AdmissionRejected(reason));
            }
            CapabilityAdmissionOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        validate_grant(&grant, &hello, &process, admission_request.claim())?;
        if let Some(presented) = admission_request.claim() {
            require_claim_executable_binding(presented, &hello, &process, &grant)?;
        }
        let process_binding = ProcessBindingSnapshot::from_request(&process);

        self.transition(WorkerLifecycle::Starting)?;
        let observing_sink = Arc::new(ObservingEvidenceSink::new(evidence_sink));
        let process_sink: Arc<dyn ProcessEvidenceSink> = observing_sink.clone();
        let start_result = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .start(process, process_sink)
            .await;

        let receipt = match start_result {
            Ok(receipt) => receipt,
            Err(ProcessExecutionError::UnknownOutcome) => {
                return self.retain_unknown_start_outcome(
                    &hello,
                    grant,
                    process_binding,
                    "process start outcome requires reconciliation",
                );
            }
            Err(error) => {
                return self
                    .reconcile_start_failure(&hello, grant, process_binding, error)
                    .await;
            }
        };
        if let Err(error) = validate_start_receipt(&receipt, &process_binding) {
            return self.reject_start_proof(
                &hello,
                grant,
                process_binding.clone(),
                "process start receipt did not bind the admitted request",
                error,
            );
        }

        let observed = observing_sink.snapshot()?;
        if observed.is_empty() {
            return self.reject_start_proof(
                &hello,
                grant,
                process_binding.clone(),
                "P-03 start produced no observed process evidence",
                WorkerError::PlanGap {
                    code: PROCESS_EVIDENCE_PLAN_GAP,
                    detail: "P-03 start produced no observed process evidence",
                },
            );
        }
        let inspected = match self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .inspect(process_binding.operation_id().clone())
            .await
        {
            Ok(view) => view,
            Err(error) => {
                let error = map_start_inspect_error(error);
                return self.reject_start_proof(
                    &hello,
                    grant,
                    process_binding.clone(),
                    "P-03 readiness inspection was unavailable or unknown",
                    error,
                );
            }
        };
        if let Err(error) = validate_start_proof(&receipt, &observed, &inspected, &process_binding)
        {
            return self.reject_start_proof(
                &hello,
                grant,
                process_binding.clone(),
                "P-03 evidence or inspection did not bind readiness",
                error,
            );
        }

        self.install_binding(&hello, grant, process_binding);
        self.process_start_receipt = Some(receipt.clone());
        self.transition(WorkerLifecycle::Ready)?;
        let ready_event = self.append_from_hello(
            &hello,
            "worker.ready",
            WorkerEventPayload::Ready,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        let grant = self.grant.as_ref().ok_or(WorkerError::NotReady)?;
        Ok(WorkerReady {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
            connection_id: hello.connection_id,
            request_id: hello.request_id,
            admission_revision: grant.admission_revision().to_owned(),
            stream_id: grant.stream_id().to_owned(),
            process_start_receipt: receipt,
            ready_event,
        })
    }

    /// Retains a possibly-effected start under the exact admitted binding
    /// (issue #1701): installs the grant/binding, fences the lifecycle to
    /// `UnknownOutcome`, and records the durable unknown-outcome event
    /// carrying the exact reason. Overlapping work stays blocked until the
    /// existing reconcile path resolves the operation; the reservation is
    /// never released on a locally-unknown outcome.
    fn retain_unknown_start_outcome(
        &mut self,
        hello: &WorkerHello,
        grant: CapabilityGrant,
        process: ProcessBindingSnapshot,
        reason: &str,
    ) -> Result<WorkerReady, WorkerError> {
        self.install_binding(hello, grant, process);
        self.transition(WorkerLifecycle::UnknownOutcome)?;
        let _ = self.append_from_hello(
            hello,
            "worker.unknown_outcome",
            WorkerEventPayload::UnknownOutcome,
            ReceiptDisposition::Unknown {
                reason: reason.to_owned(),
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        Err(WorkerError::UnknownOutcome)
    }

    /// Reconciles a non-unknown P-03 start failure through the existing
    /// process owner before deciding the local disposition (issue #1701,
    /// step 4).
    ///
    /// The provider contract establishes no effect only when the executor
    /// retains nothing under the admitted operation identity: `inspect`
    /// answers `NotFound`, so this call started nothing and the lifecycle
    /// resets to `Created` with the provider's original error mapping
    /// (`Unavailable` stays a `PlanGap`, anything else stays `Process`).
    /// When the executor retains the operation, reports `UnknownOutcome`,
    /// or cannot answer, the possible effect is retained exactly like a
    /// reported unknown outcome: the binding is installed, the lifecycle
    /// fences to `UnknownOutcome`, and the durable event preserves the
    /// original failure text as the reason. Inconclusive inspection fails
    /// closed to retention, never to reset.
    async fn reconcile_start_failure(
        &mut self,
        hello: &WorkerHello,
        grant: CapabilityGrant,
        process: ProcessBindingSnapshot,
        error: ProcessExecutionError,
    ) -> Result<WorkerReady, WorkerError> {
        let operation_id = process.operation_id().clone();
        let inspection = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .inspect(operation_id)
            .await;
        // Only a `NotFound` answer establishes no effect from this call: the
        // executor retains nothing under the admitted operation identity. A
        // retained operation, a reported unknown outcome, or any other
        // inspection failure keeps the possible effect.
        let retained = !matches!(inspection, Err(ProcessExecutionError::NotFound));
        if retained {
            let reason = format!(
                "process start failed without a no-effect proof ({error}); outcome requires reconciliation"
            );
            return self.retain_unknown_start_outcome(hello, grant, process, &reason);
        }
        match error {
            ProcessExecutionError::Unavailable(_) => {
                self.lifecycle = WorkerLifecycle::Created;
                Err(WorkerError::PlanGap {
                    code: PROCESS_PROVIDER_PLAN_GAP,
                    detail: "P-03 ProcessExecutor is unavailable",
                })
            }
            error => {
                self.lifecycle = WorkerLifecycle::Created;
                Err(WorkerError::Process(error.to_string()))
            }
        }
    }

    /// Restores an exact process/admission binding after an A-13 restart without
    /// launching a duplicate process. P-03 inspect and durable replay are the source.
    ///
    /// Unclaimed projection: delegates to the shared downstream recovery path
    /// with no claim echo and no executable gate. Observable behavior is
    /// unchanged from the previous inline implementation.
    pub async fn recover_after_restart(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<WorkerRecovery, WorkerError> {
        let admission_request = CapabilityAdmissionRequest::from_start(&hello, &process);
        self.recover_after_restart_inner(hello, process, admission_request, replay_after_sequence)
            .await
    }

    /// Claim-bound restart recovery: the same retained-acquisition inspect +
    /// replay-suffix path as [`WorkerCore::recover_after_restart`], bound to
    /// one exact claim presentation exactly like
    /// [`WorkerCore::demand_start_claimed`].
    ///
    /// First validates the claim/registration cross-binding, then performs
    /// the checked join of the claim with the owner-supplied `hello` and
    /// `process` via `CapabilityAdmissionRequest::from_claim` (including the
    /// executable join binding to `hello`/`process`/registration). Any
    /// mismatch fails here, before the admission owner is consulted and
    /// without launching anything. On a match the call delegates to the
    /// shared downstream recovery path (admit, grant validation including
    /// the claim echo and the owner-produced executable expectation,
    /// executable-binding gate, retained P-03 inspect, durable replay
    /// suffix). No `ProcessRequest` is minted, no grant is sealed by the
    /// join itself, and no duplicate process is ever launched: only the
    /// supplied `claim`, `hello`, and `process` are reused.
    ///
    /// A stale-generation/epoch or misaddressed join is refused typed,
    /// exactly like `demand_start_claimed`. The recovered binding keeps the
    /// ORIGINAL claim identity — nothing is minted — so a later
    /// cancel/checkpoint acts under the same binding and an unknown outcome
    /// reconciles under the original claim echo. The drain analogue remains
    /// quiesce→shutdown (docs only; no new owner).
    ///
    /// # Errors
    ///
    /// Returns the `from_claim` join failure (`InvalidRequest`,
    /// `UnsupportedVersion`, `StaleEpoch`, `StaleFence`, or
    /// `DeadlineExpired`), the capacity-permit refusal (same family as
    /// [`WorkerCore::demand_start_claimed`], re-checked before any replay
    /// effect), the downstream admission/inspect/replay failure, or
    /// the typed executable-join refusal (`InvalidRequest`, `StaleEpoch`,
    /// `StaleFence`, `DeadlineExpired`, `Revoked`, or `UnsupportedVersion`).
    pub async fn recover_after_restart_claimed(
        &mut self,
        claim: ClaimAdmissionRequest,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<WorkerRecovery, WorkerError> {
        claim.validate_binding()?;
        let admission_request = CapabilityAdmissionRequest::from_claim(&claim, &hello, &process)?;
        self.require_capacity_for_claim(claim.claim())?;
        self.recover_after_restart_inner(hello, process, admission_request, replay_after_sequence)
            .await
    }

    /// Shared downstream recovery path for [`WorkerCore::recover_after_restart`]
    /// and [`WorkerCore::recover_after_restart_claimed`]: lifecycle gate,
    /// owner validation, admission, grant checks (including the claim echo
    /// and the owner-produced executable expectation when the request carries
    /// one), the executable join gate, retained P-03 inspect, and the durable
    /// replay suffix. No duplicate process is ever launched.
    async fn recover_after_restart_inner(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
        admission_request: CapabilityAdmissionRequest,
        replay_after_sequence: u64,
    ) -> Result<WorkerRecovery, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Created | WorkerLifecycle::Stopped
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        hello.validate()?;
        process
            .validate()
            .map_err(|error| WorkerError::Process(error.to_string()))?;
        self.require_replay()?;
        self.require_executor()?;
        let grant = match self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .admit(&admission_request)
            .map_err(provider_error)?
        {
            CapabilityAdmissionOutcome::Admitted(facts) => CapabilityGrant::seal(*facts),
            CapabilityAdmissionOutcome::Rejected { reason } => {
                return Err(WorkerError::AdmissionRejected(reason));
            }
            CapabilityAdmissionOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        validate_grant(&grant, &hello, &process, admission_request.claim())?;
        if let Some(presented) = admission_request.claim() {
            require_claim_executable_binding(presented, &hello, &process, &grant)?;
        }
        let process_binding = ProcessBindingSnapshot::from_request(&process);
        let view = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .inspect(process_binding.operation_id().clone())
            .await
            .map_err(map_process_error)?;
        validate_process_evidence_binding(
            view.operation_id(),
            view.request_digest(),
            view.fence(),
            &process_binding,
        )?;
        validate_recovered_process_view(&view, &process_binding)?;
        let recovered_lifecycle = worker_lifecycle_from_process(view.lifecycle());
        let replayed_events = self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .replay(grant.stream_id(), replay_after_sequence)
            .map_err(provider_error)?;
        validate_replayed_events(&replayed_events, &grant, Some(replay_after_sequence))?;
        self.install_binding(&hello, grant, process_binding);
        self.lifecycle = recovered_lifecycle;
        if let Some(tail) = replayed_events.last() {
            self.last_event_id = Some(tail.event_id.clone());
            self.last_event_sequence = tail.sequence;
        }
        Ok(WorkerRecovery {
            connection_id: hello.connection_id,
            lifecycle: recovered_lifecycle,
            replayed_events,
        })
    }

    /// Handles one complete native-worker protocol frame.
    pub async fn handle(
        &mut self,
        frame: WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        frame.validate_shape()?;
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        self.validate_frame_binding(&frame, &grant)?;
        self.revalidate_admission(&grant, frame.deadline_unix_ms)?;

        if let WorkerFrameBody::Acknowledge(receipt) = &frame.body {
            validate_ack(receipt, &grant)?;
            self.replay
                .as_mut()
                .ok_or(WorkerError::PlanGap {
                    code: REPLAY_PROVIDER_PLAN_GAP,
                    detail: "durable replay provider was not injected",
                })?
                .acknowledge(receipt)
                .map_err(provider_error)?;
            return Ok(Vec::new());
        }

        let fingerprint = prepare_execute_call_and_fingerprint(&frame, &grant)?;
        match self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .lookup_request(grant.stream_id(), &frame.request_id, &fingerprint)
            .map_err(provider_error)?
        {
            DurableRequestDecision::New => {}
            DurableRequestDecision::Replay(events) => {
                if events.is_empty() {
                    return Err(WorkerError::ReplayContract("incomplete_request"));
                }
                validate_replayed_events(&events, &grant, None)?;
                validate_request_replay(&events, &frame.request_id)?;
                return Ok(events);
            }
            DurableRequestDecision::Conflict => return Err(WorkerError::IdempotencyConflict),
        }
        let prepared_effect = self.prepare_body(&frame.body, &grant)?;
        match self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .begin_request(grant.stream_id(), &frame.request_id, &fingerprint)
            .map_err(provider_error)?
        {
            DurableRequestDecision::New => {}
            DurableRequestDecision::Replay(events) => {
                if events.is_empty() {
                    return Err(WorkerError::ReplayContract("incomplete_request"));
                }
                validate_replayed_events(&events, &grant, None)?;
                validate_request_replay(&events, &frame.request_id)?;
                return Ok(events);
            }
            DurableRequestDecision::Conflict => return Err(WorkerError::IdempotencyConflict),
        }

        match frame.body.clone() {
            WorkerFrameBody::Execute(call) => self.execute(&frame, call.input, prepared_effect),
            WorkerFrameBody::Cancel(request) => self.cancel(&frame, request).await,
            WorkerFrameBody::Heartbeat => self.heartbeat(&frame),
            WorkerFrameBody::Health => self.health(&frame),
            WorkerFrameBody::Checkpoint(request) => self.checkpoint(&frame, request),
            WorkerFrameBody::Quiesce => self.quiesce(&frame),
            WorkerFrameBody::Reconnect(request) => self.reconnect(&frame, request),
            WorkerFrameBody::Reconcile => self.reconcile(&frame).await,
            WorkerFrameBody::Shutdown => self.shutdown(&frame),
            WorkerFrameBody::Acknowledge(_) => unreachable!("ack handled before idempotency"),
        }
    }

    fn execute(
        &mut self,
        frame: &WorkerFrame,
        request: WorkerRequest,
        authorized: Option<AuthorizedEffect>,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if self.lifecycle == WorkerLifecycle::Ready {
            self.transition(WorkerLifecycle::Running)?;
        }
        let mut events = vec![self.append_from_frame(
            frame,
            "worker.accepted",
            WorkerEventPayload::Accepted {
                attempt_id: request.attempt_id.clone(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableObservation,
            true,
        )?];
        if let (Some(proposal), Some(authorized_effect)) = (request.proposed_effect, authorized) {
            events.push(self.append_from_frame(
                frame,
                "worker.candidate_effect",
                WorkerEventPayload::CandidateOnly {
                    proposal: Box::new(proposal),
                    authorized_effect: Box::new(authorized_effect),
                },
                ReceiptDisposition::Success {
                    proof: ProofCeiling::CandidateArtifact,
                },
                DeliveryClass::DurableObservation,
                true,
            )?);
        }
        Ok(events)
    }

    fn prepare_body(
        &mut self,
        body: &WorkerFrameBody,
        grant: &CapabilityGrant,
    ) -> Result<Option<AuthorizedEffect>, WorkerError> {
        match body {
            WorkerFrameBody::Execute(call) => {
                let request = &call.input;
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Ready | WorkerLifecycle::Running
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                request
                    .validate_shape()
                    .map_err(WorkerError::InvalidRequest)?;
                if !grant.capabilities().contains(&request.capability) {
                    return Err(WorkerError::AdmissionRejected(
                        "capability was not admitted".to_owned(),
                    ));
                }
                request
                    .proposed_effect
                    .as_ref()
                    .map(|proposal| self.authorize_effect(grant, request, proposal))
                    .transpose()
            }
            WorkerFrameBody::Cancel(request) => {
                if request.reason.trim().is_empty() {
                    return Err(WorkerError::InvalidRequest("cancel_reason"));
                }
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Ready | WorkerLifecycle::Running | WorkerLifecycle::Quiescing
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Checkpoint(request) => {
                if request.checkpoint_ref.trim().is_empty() {
                    return Err(WorkerError::InvalidRequest("checkpoint_ref"));
                }
                Ok(None)
            }
            WorkerFrameBody::Quiesce => {
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Ready | WorkerLifecycle::Running
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Reconnect(request) => {
                if self.connection_id.as_deref() != Some(request.previous_connection_id.as_str())
                    || request.new_connection_id.trim().is_empty()
                {
                    return Err(WorkerError::StaleConnection);
                }
                Ok(None)
            }
            WorkerFrameBody::Reconcile => {
                if self.lifecycle != WorkerLifecycle::UnknownOutcome {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Shutdown => {
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Quiescing
                        | WorkerLifecycle::Cancelled
                        | WorkerLifecycle::Reconciled
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Heartbeat | WorkerFrameBody::Health => Ok(None),
            WorkerFrameBody::Acknowledge(_) => unreachable!("ack prepared separately"),
        }
    }

    async fn cancel(
        &mut self,
        frame: &WorkerFrame,
        request: CancelRequest,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if request.reason.trim().is_empty() {
            return Err(WorkerError::InvalidRequest("cancel_reason"));
        }
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Ready | WorkerLifecycle::Running | WorkerLifecycle::Quiescing
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        let operation_id = self
            .process_binding
            .as_ref()
            .ok_or(WorkerError::NotReady)?
            .operation_id()
            .clone();
        let outcome = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .cancel(operation_id)
            .await;
        match outcome {
            Ok(receipt) => {
                self.lifecycle = match receipt.status() {
                    CancellationStatus::Completed => WorkerLifecycle::Cancelled,
                    CancellationStatus::UnknownOutcome => WorkerLifecycle::UnknownOutcome,
                    _ => WorkerLifecycle::Cancelling,
                };
                Ok(vec![self.append_from_frame(
                    frame,
                    "worker.cancel",
                    WorkerEventPayload::Cancellation {
                        status: receipt.status(),
                        reason: request.reason,
                    },
                    ReceiptDisposition::Cancelled {
                        reason: "P-03 cancellation accepted".to_owned(),
                    },
                    DeliveryClass::DurableControl,
                    true,
                )?])
            }
            Err(ProcessExecutionError::UnknownOutcome) => {
                self.lifecycle = WorkerLifecycle::UnknownOutcome;
                Ok(vec![self.append_from_frame(
                    frame,
                    "worker.unknown_outcome",
                    WorkerEventPayload::UnknownOutcome,
                    ReceiptDisposition::Unknown {
                        reason: "cancellation outcome requires reconciliation".to_owned(),
                    },
                    DeliveryClass::DurableControl,
                    true,
                )?])
            }
            Err(error) => Err(map_process_error(error)),
        }
    }

    async fn reconcile(
        &mut self,
        frame: &WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if self.lifecycle != WorkerLifecycle::UnknownOutcome {
            return Err(WorkerError::InvalidLifecycle);
        }
        let process = self.process_binding.clone().ok_or(WorkerError::NotReady)?;
        let evidence = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .reconcile(process.operation_id().clone())
            .await
            .map_err(map_process_error)?;
        validate_process_evidence(&evidence, &process)?;
        if evidence.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
            return Err(WorkerError::UnknownOutcome);
        }
        if evidence.view().lifecycle() != ProcessLifecycle::Reconciled {
            return Err(WorkerError::ProcessReceiptMismatch("reconcile_lifecycle"));
        }
        self.lifecycle = WorkerLifecycle::Reconciled;
        Ok(vec![self.append_from_frame(
            frame,
            "worker.reconciled",
            WorkerEventPayload::Reconciled {
                process_lifecycle: evidence.view().lifecycle(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?])
    }

    fn heartbeat(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        Ok(vec![self.append_from_frame(
            frame,
            "worker.heartbeat",
            WorkerEventPayload::Heartbeat,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::BestEffortTelemetry,
            false,
        )?])
    }

    fn health(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        Ok(vec![self.append_from_frame(
            frame,
            "worker.health",
            WorkerEventPayload::Health {
                state: self.process_state(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableObservation,
            true,
        )?])
    }

    fn checkpoint(
        &mut self,
        frame: &WorkerFrame,
        request: CheckpointRequest,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if request.checkpoint_ref.trim().is_empty() {
            return Err(WorkerError::InvalidRequest("checkpoint_ref"));
        }
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        let process = self.process_binding.clone().ok_or(WorkerError::NotReady)?;
        let durable_request = DurableCheckpointRequest::new(
            request.checkpoint_ref.clone(),
            frame.request_id.clone(),
            &grant,
            &process,
        );
        let receipt = match self
            .checkpoint
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: CHECKPOINT_PROVIDER_PLAN_GAP,
                detail: "durable checkpoint provider was not injected",
            })?
            .persist_checkpoint(&durable_request)
            .map_err(provider_error)?
        {
            CheckpointProviderOutcome::Stored(receipt) => *receipt,
            CheckpointProviderOutcome::Rejected { reason } => {
                return Err(WorkerError::CheckpointRejected(reason));
            }
        };
        validate_checkpoint_receipt(&receipt, &durable_request)?;
        Ok(vec![self.append_from_frame(
            frame,
            "worker.checkpoint",
            WorkerEventPayload::Checkpoint {
                checkpoint_ref: request.checkpoint_ref,
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::CandidateArtifact,
            },
            DeliveryClass::DurableControl,
            true,
        )?])
    }

    fn quiesce(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Ready | WorkerLifecycle::Running
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        let event = self.append_from_frame(
            frame,
            "worker.quiescing",
            WorkerEventPayload::Quiescing,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        self.transition(WorkerLifecycle::Quiescing)?;
        Ok(vec![event])
    }

    fn reconnect(
        &mut self,
        frame: &WorkerFrame,
        request: ReconnectRequest,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        let current = self.connection_id.as_deref().ok_or(WorkerError::NotReady)?;
        if request.previous_connection_id != current || request.new_connection_id.trim().is_empty()
        {
            return Err(WorkerError::StaleConnection);
        }
        if request.replay_after_sequence > self.last_event_sequence {
            return Err(WorkerError::ReplayContract("cursor_ahead"));
        }
        let known_last_sequence = self.last_event_sequence;
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        let mut events = self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .replay(grant.stream_id(), request.replay_after_sequence)
            .map_err(provider_error)?;
        validate_replayed_events(&events, &grant, Some(request.replay_after_sequence))?;
        if known_last_sequence > request.replay_after_sequence
            && events.last().map_or(0, |event| event.sequence) < known_last_sequence
        {
            return Err(WorkerError::ReplayContract("stale_replay_tail"));
        }
        if let Some(tail) = events.last() {
            self.last_event_id = Some(tail.event_id.clone());
            self.last_event_sequence = tail.sequence;
        }
        let previous = request.previous_connection_id;
        let new_connection = request.new_connection_id;
        let reconnect_event = self.append_from_frame(
            frame,
            "worker.reconnected",
            WorkerEventPayload::Reconnected {
                previous_connection_id: previous,
                new_connection_id: new_connection.clone(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        self.connection_id = Some(new_connection);
        events.push(reconnect_event);
        Ok(events)
    }

    fn shutdown(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Quiescing | WorkerLifecycle::Cancelled | WorkerLifecycle::Reconciled
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        let event = self.append_from_frame(
            frame,
            "worker.shutdown",
            WorkerEventPayload::Shutdown,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        self.lifecycle = WorkerLifecycle::Stopped;
        Ok(vec![event])
    }

    fn authorize_effect(
        &mut self,
        grant: &CapabilityGrant,
        request: &WorkerRequest,
        proposal: &ProposedEffect,
    ) -> Result<AuthorizedEffect, WorkerError> {
        proposal
            .validate_against(&grant.authority().effect_ceiling)
            .map_err(|_| {
                WorkerError::EffectRejected("effect exceeds admitted ceiling".to_owned())
            })?;
        let effect_request =
            EffectAdmissionRequest::new(proposal.clone(), request.attempt_id.clone(), grant);
        // W1 ceiling-coverage join (#1793, I6.6 seq 4): the admitted ceiling
        // must cover the exact shared domain class projected from the
        // proposal, with no rank upgrade; rank stays with the Governor
        // `ImpactClass` check. A miss is a typed rejection before the
        // admission owner is consulted, never a silent pass.
        if !grant
            .authority()
            .effect_ceiling
            .permits_effect_class(effect_request.effect_class())
        {
            return Err(WorkerError::EffectRejected(
                "effect class exceeds admitted ceiling".to_owned(),
            ));
        }
        let outcome = self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .authorize_effect(&effect_request)
            .map_err(provider_error)?;
        let effect_grant = match outcome {
            EffectAdmissionOutcome::Authorized(facts) => EffectAdmissionGrant::seal(*facts),
            EffectAdmissionOutcome::Rejected { reason } => {
                return Err(WorkerError::EffectRejected(reason));
            }
            EffectAdmissionOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        validate_effect_grant(&effect_grant, grant, proposal)?;
        Ok(effect_grant.authorized_effect().clone())
    }

    fn validate_frame_binding(
        &self,
        frame: &WorkerFrame,
        grant: &CapabilityGrant,
    ) -> Result<(), WorkerError> {
        if self.connection_id.as_deref() != Some(frame.connection_id.as_str()) {
            return Err(WorkerError::StaleConnection);
        }
        if frame.authority_epoch != grant.authority().epoch {
            return Err(WorkerError::StaleEpoch);
        }
        if frame.state_fence != grant.authority().state_fence {
            return Err(WorkerError::StaleFence);
        }
        if frame.lease_id != grant.authority().lease {
            return Err(WorkerError::StaleLease);
        }
        if frame.admission_revision != grant.admission_revision() {
            return Err(WorkerError::StaleRevision);
        }
        if frame.producer_generation != grant.worker_generation() {
            return Err(WorkerError::StaleEpoch);
        }
        Ok(())
    }

    fn revalidate_admission(
        &mut self,
        grant: &CapabilityGrant,
        deadline_unix_ms: u64,
    ) -> Result<(), WorkerError> {
        let liveness_request = CapabilityLivenessRequest::from_grant(grant);
        let outcome = self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .revalidate(&liveness_request)
            .map_err(provider_error)?;
        let live = match outcome {
            AdmissionLivenessOutcome::Live(facts) => AdmissionLiveness::seal(facts),
            AdmissionLivenessOutcome::Rejected { reason } => {
                // Terminal for this grant: the owner refused liveness, so the
                // admitted authority (including any credential-bearing
                // introduction) is dropped and no further frame dispatches
                // under it. A new admission must seal a new grant.
                self.grant = None;
                return Err(WorkerError::AdmissionRejected(reason));
            }
            AdmissionLivenessOutcome::Revoked { revision } => {
                self.grant = None;
                return Err(WorkerError::Revoked(revision));
            }
        };
        if live.revoked() {
            self.grant = None;
            return Err(WorkerError::Revoked(live.admission_revision().to_owned()));
        }
        if live.admission_id() != grant.admission_id()
            || live.lease() != &grant.authority().lease
            || live.authority_epoch() != &grant.authority().epoch
        {
            self.grant = None;
            return Err(WorkerError::StaleLease);
        }
        if live.state_fence() != &grant.authority().state_fence {
            self.grant = None;
            return Err(WorkerError::StaleFence);
        }
        if live.admission_revision() != grant.admission_revision()
            || live.revocation_revision() != grant.revocation_revision()
        {
            self.grant = None;
            return Err(WorkerError::StaleRevision);
        }
        if live.expires_at_unix_ms() != grant.expires_at_unix_ms()
            || live.observed_at_unix_ms() >= live.expires_at_unix_ms()
        {
            self.grant = None;
            return Err(WorkerError::StaleLease);
        }
        if live.observed_at_unix_ms() > deadline_unix_ms {
            return Err(WorkerError::DeadlineExpired);
        }
        Ok(())
    }

    fn append_from_hello(
        &mut self,
        hello: &WorkerHello,
        payload_type: &'static str,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        delivery_class: DeliveryClass,
        ack_required: bool,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        self.append_event(
            &hello.request_id,
            &hello.trace_context,
            payload_type,
            payload,
            disposition,
            delivery_class,
            ack_required,
        )
    }

    fn append_from_frame(
        &mut self,
        frame: &WorkerFrame,
        payload_type: &'static str,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        delivery_class: DeliveryClass,
        ack_required: bool,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        self.append_event(
            &frame.request_id,
            &frame.trace_context,
            payload_type,
            payload,
            disposition,
            delivery_class,
            ack_required,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_event(
        &mut self,
        request_id: &RequestId,
        trace_context: &BTreeMap<String, String>,
        payload_type: &'static str,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        delivery_class: DeliveryClass,
        ack_required: bool,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        let causal_predecessor_refs: Vec<String> = self.last_event_id.iter().cloned().collect();
        let expected_causal_predecessor_refs = causal_predecessor_refs.clone();
        let expected_payload = payload.clone();
        let expected_disposition = disposition.clone();
        let draft = WorkerEventDraft::new(
            grant.stream_id().to_owned(),
            grant.producer_id().to_owned(),
            grant.worker_generation(),
            grant.authority().epoch.clone(),
            request_id.clone(),
            causal_predecessor_refs,
            delivery_class,
            ack_required,
            payload_type,
            payload,
            disposition,
            grant.authority().state_fence.clone(),
            trace_context.clone(),
        );
        let event = self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .append(draft)
            .map_err(provider_error)?;
        validate_event(
            &event,
            &grant,
            request_id,
            payload_type,
            &expected_payload,
            &expected_disposition,
            trace_context,
            &expected_causal_predecessor_refs,
            delivery_class,
            ack_required,
        )?;
        if event.sequence <= self.last_event_sequence {
            return Err(WorkerError::ReplayContract("event_sequence"));
        }
        self.last_event_id = Some(event.event_id.clone());
        self.last_event_sequence = event.sequence;
        Ok(event)
    }

    fn install_binding(
        &mut self,
        hello: &WorkerHello,
        grant: CapabilityGrant,
        process: ProcessBindingSnapshot,
    ) {
        self.connection_id = Some(hello.connection_id.clone());
        self.grant = Some(grant);
        self.process_binding = Some(process);
    }

    fn reject_start_proof(
        &mut self,
        hello: &WorkerHello,
        grant: CapabilityGrant,
        process: ProcessBindingSnapshot,
        reason: &str,
        error: WorkerError,
    ) -> Result<WorkerReady, WorkerError> {
        self.install_binding(hello, grant, process);
        self.transition(WorkerLifecycle::UnknownOutcome)?;
        let _ = self.append_from_hello(
            hello,
            "worker.unknown_outcome",
            WorkerEventPayload::UnknownOutcome,
            ReceiptDisposition::Unknown {
                reason: reason.to_owned(),
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        Err(error)
    }

    fn transition(&mut self, next: WorkerLifecycle) -> Result<(), WorkerError> {
        if self.lifecycle.can_transition_to(next) {
            self.lifecycle = next;
            Ok(())
        } else {
            Err(WorkerError::InvalidLifecycle)
        }
    }

    fn require_executor(&self) -> Result<(), WorkerError> {
        self.executor.as_ref().map_or_else(
            || {
                Err(WorkerError::PlanGap {
                    code: PROCESS_PROVIDER_PLAN_GAP,
                    detail: "P-03 ProcessExecutor was not injected",
                })
            },
            |_| Ok(()),
        )
    }

    fn require_replay(&self) -> Result<(), WorkerError> {
        self.replay.as_ref().map_or_else(
            || {
                Err(WorkerError::PlanGap {
                    code: REPLAY_PROVIDER_PLAN_GAP,
                    detail: "durable replay provider was not injected",
                })
            },
            |_| Ok(()),
        )
    }
}

fn validate_grant(
    grant: &CapabilityGrant,
    hello: &WorkerHello,
    process: &ProcessRequest,
    claim: Option<&ClaimAdmissionRequest>,
) -> Result<(), WorkerError> {
    grant
        .authority()
        .validate()
        .map_err(|_| WorkerError::AdmissionMismatch("authority"))?;
    for (field, value) in [
        ("admission_id", grant.admission_id()),
        ("admission_revision", grant.admission_revision()),
        ("stream_id", grant.stream_id()),
        ("producer_id", grant.producer_id()),
        ("route_ref", grant.route_ref()),
        ("artifact_manifest_digest", grant.artifact_manifest_digest()),
        ("process_request_digest", grant.process_request_digest()),
    ] {
        if value.trim().is_empty() {
            return Err(WorkerError::AdmissionMismatch(field));
        }
    }
    if grant.observed_at_unix_ms() >= grant.expires_at_unix_ms()
        || grant.observed_at_unix_ms() > hello.deadline_unix_ms
    {
        return Err(WorkerError::StaleLease);
    }
    if grant.route_ref() != hello.route_ref {
        return Err(WorkerError::AdmissionMismatch("route_ref"));
    }
    if grant.artifact_manifest_digest() != hello.artifact_manifest_digest {
        return Err(WorkerError::AdmissionMismatch("artifact_manifest_digest"));
    }
    if grant.worker_generation() != hello.worker_generation
        || grant.process_generation() != process.generation()
        || grant.worker_generation() != process.generation().get()
    {
        return Err(WorkerError::AdmissionMismatch("generation"));
    }
    if grant.authority().epoch != hello.authority_epoch {
        return Err(WorkerError::AdmissionMismatch("authority_epoch"));
    }
    if grant.authority().state_fence != hello.state_fence
        || !grant.process_fence().matches(process.fence())
    {
        return Err(WorkerError::AdmissionMismatch("state_fence"));
    }
    if grant.operation_id() != process.operation_id()
        || grant.process_tree_id() != process.process_tree_id()
        || grant.process_request_digest() != process.invocation_digest()
        || grant.resource_limits() != process.resource_limits()
    {
        return Err(WorkerError::AdmissionMismatch("process_request"));
    }
    if grant.capabilities().is_empty()
        || !grant
            .capabilities()
            .is_subset(&hello.requested_capabilities)
    {
        return Err(WorkerError::AdmissionMismatch("capabilities"));
    }
    if let Some(presented) = claim {
        validate_grant_claim_binding(grant, presented)?;
        // Registration-lease currentness (Implements #22 AC5 lease scope
        // and the W1 admitted-lease dimension): the presenting registration
        // states the exact lease window this generation was admitted under,
        // and expiry ends authority without renewal. A start observed at or
        // past the lease end is refused with the typed stale-lease refusal,
        // so broker/session/lease loss revokes credential/resource scope
        // here, before P-03 starts anything. This runs after the executable
        // currentness check so an expired binding window keeps its exact
        // `DeadlineExpired` dimension. The owner restores authority through
        // a new admission, never a local repair in the worker.
        if grant.observed_at_unix_ms() >= presented.registration().lease_expires_at_unix_ms {
            return Err(WorkerError::StaleLease);
        }
    }
    Ok(())
}

/// Re-checks the presented claim against the owner-admitted grant.
///
/// Binds the claim digest (recomputed at admission time), the claimed
/// operation/generation, the owner's echo of the exact claim
/// digest/attempt/operation, and — for v2 claims — the owner-produced
/// executable expectation. A missing or disagreeing echo or expectation
/// fails closed: both are inert data, never authority by themselves. The
/// full executable currentness (route, adapter, config, facet, grant,
/// stream, nonce, invocation, owner digest, epoch, generation, fence,
/// expiry) is enforced by [`NativeWorkerClaim::require_executable_binding`]
/// against the grant's expectation using the grant observation time; this
/// function additionally binds the join's route/stream/nonce/invocation to
/// the admitted grant so a well-formed but misaddressed join cannot pass on
/// digest equality alone.
///
/// # Errors
///
/// Returns [`WorkerError::InvalidRequest`] for a digest that no longer
/// recomputes or a misaddressed join field,
/// [`WorkerError::AdmissionMismatch`] when the admitted grant or its claim
/// echo does not name the presented claim, and the typed executable refusal
/// (`StaleEpoch`, `StaleFence`, `DeadlineExpired`, `Revoked`,
/// `UnsupportedVersion`) when the join disagrees with current owner
/// authority.
fn validate_grant_claim_binding(
    grant: &CapabilityGrant,
    claim: &ClaimAdmissionRequest,
) -> Result<(), WorkerError> {
    let presented = claim.claim();
    if presented.compute_binding_digest()? != presented.binding_digest {
        return Err(WorkerError::InvalidRequest("binding_digest"));
    }
    if grant.operation_id() != &presented.operation_id {
        return Err(WorkerError::AdmissionMismatch("claim_operation"));
    }
    if grant.worker_generation() != presented.worker_generation {
        return Err(WorkerError::AdmissionMismatch("claim_generation"));
    }
    if grant.claim_binding_digest() != Some(presented.binding_digest.as_str()) {
        return Err(WorkerError::AdmissionMismatch("claim_binding"));
    }
    if grant.claim_attempt_id() != Some(&presented.attempt_id) {
        return Err(WorkerError::AdmissionMismatch("claim_attempt"));
    }
    if grant.claim_operation_id() != Some(&presented.operation_id) {
        return Err(WorkerError::AdmissionMismatch("claim_operation"));
    }
    if presented.wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
        return Ok(());
    }
    let join = presented
        .executable_binding
        .as_ref()
        .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
    let expected = grant
        .executable_expectation()
        .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
    presented.require_executable_binding(expected, grant.observed_at_unix_ms())?;
    if join.route_ref != grant.route_ref() {
        return Err(WorkerError::InvalidRequest("executable_binding.route_ref"));
    }
    if join.replay_stream_id != grant.stream_id() {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.replay_stream_id",
        ));
    }
    Ok(())
}

/// Executable-binding gate: enforces the owner-produced T9-02 join after
/// admission and grant validation but before P-03 start.
///
/// The claimed path fails closed here when the presented v2 join disagrees
/// with the owner-produced expectation carried by the admitted grant
/// (route, adapter, config, facet, grant revision, stream, nonce,
/// invocation digest, owner digest, epoch, generation, fence, expiry, or
/// revocation), when the join disagrees with the owner-supplied
/// `hello`/`process` (route, nonce, invocation digest), or when the join is
/// addressed to another registration (capability cell, Module Catalog
/// revision). A generation admitted under one cell or catalog revision never
/// starts work bound to another: advancement needs a new admission, never a
/// local repair. Checks follow the
/// documented absent-input order (route, adapter, config, facet, grant,
/// stream, nonce, invocation, digest, wire, epoch, generation, fence) so
/// the first reported field is the first input callers must repair; later
/// inputs stay unreachable until the earlier ones agree. A v1 claim parses
/// but never promotes; an unknown wire is rejected as
/// [`WorkerError::UnsupportedVersion`].
///
/// # Errors
///
/// Returns the typed executable refusal (`InvalidRequest`, `StaleEpoch`,
/// `StaleFence`, `DeadlineExpired`, `Revoked`, or `UnsupportedVersion`).
fn require_claim_executable_binding(
    claim: &ClaimAdmissionRequest,
    hello: &WorkerHello,
    process: &ProcessRequest,
    grant: &CapabilityGrant,
) -> Result<(), WorkerError> {
    let presented = claim.claim();
    let expected = grant
        .executable_expectation()
        .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
    presented.require_executable_binding(expected, grant.observed_at_unix_ms())?;
    let join = presented
        .executable_binding
        .as_ref()
        .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
    if join.route_ref != hello.route_ref {
        return Err(WorkerError::InvalidRequest("executable_binding.route_ref"));
    }
    if join.launch_nonce != hello.launch_nonce {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.launch_nonce",
        ));
    }
    if join.process_invocation_digest != process.invocation_digest() {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.process_invocation_digest",
        ));
    }
    // Registration cross-binding (Implements #22 W7 cell identity and the
    // W1 admitted-catalog dimension): the presenting registration states the
    // exact cell and catalog revision this generation was admitted under, so
    // a well-formed join minted for another cell or revision is refused here
    // even when the (possibly echoed) owner expectation agrees with it. The
    // owner advances either value through a new admission, never a local
    // repair in the worker.
    if join.capability_cell != claim.registration().capability_cell {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.capability_cell",
        ));
    }
    if join.module_catalog_revision != claim.registration().module_catalog_revision {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.module_catalog_revision",
        ));
    }
    Ok(())
}

fn validate_start_receipt(
    receipt: &ProcessStartReceipt,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if receipt.operation_id() != process.operation_id() {
        return Err(WorkerError::ProcessReceiptMismatch("operation_id"));
    }
    if receipt.request_digest() != process.request_digest() {
        return Err(WorkerError::ProcessReceiptMismatch("request_digest"));
    }
    if receipt.accepted_generation() != process.generation() {
        return Err(WorkerError::ProcessReceiptMismatch("generation"));
    }
    if !matches!(
        receipt.lifecycle(),
        ProcessLifecycle::Starting | ProcessLifecycle::Running
    ) {
        return Err(WorkerError::ProcessReceiptMismatch("lifecycle"));
    }
    Ok(())
}

fn validate_start_proof(
    receipt: &ProcessStartReceipt,
    observed: &[ProcessEvidence],
    inspected: &ProcessExecutionView,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if receipt.lifecycle() != ProcessLifecycle::Running {
        return Err(WorkerError::ProcessReceiptMismatch("receipt_not_running"));
    }
    for evidence in observed {
        validate_process_evidence(evidence, process)?;
    }
    let latest = observed.last().ok_or(WorkerError::ProcessReceiptMismatch(
        "missing_process_evidence",
    ))?;
    if latest.view() != inspected {
        return Err(WorkerError::ProcessReceiptMismatch("inspect_evidence_view"));
    }
    validate_process_evidence_binding(
        inspected.operation_id(),
        inspected.request_digest(),
        inspected.fence(),
        process,
    )?;
    if inspected.lifecycle() != ProcessLifecycle::Running || !inspected.health().ready() {
        return Err(WorkerError::ProcessReceiptMismatch("readiness_lifecycle"));
    }
    let identity = inspected
        .identity()
        .ok_or(WorkerError::ProcessReceiptMismatch("process_identity"))?;
    if identity.process_tree_id() != process.process_tree_id()
        || identity.generation() != process.generation()
        || identity.executable_sha256() != process.executable_sha256()
    {
        return Err(WorkerError::ProcessReceiptMismatch("process_identity"));
    }
    Ok(())
}

fn validate_recovered_process_view(
    view: &ProcessExecutionView,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if view.lifecycle() == ProcessLifecycle::Running {
        if !view.health().ready() {
            return Err(WorkerError::ProcessReceiptMismatch("recovery_readiness"));
        }
        let identity = view
            .identity()
            .ok_or(WorkerError::ProcessReceiptMismatch("recovery_identity"))?;
        if identity.process_tree_id() != process.process_tree_id()
            || identity.generation() != process.generation()
            || identity.executable_sha256() != process.executable_sha256()
        {
            return Err(WorkerError::ProcessReceiptMismatch("recovery_identity"));
        }
    }
    Ok(())
}

fn validate_effect_grant(
    effect: &EffectAdmissionGrant,
    grant: &CapabilityGrant,
    proposal: &ProposedEffect,
) -> Result<(), WorkerError> {
    if effect.revoked() {
        return Err(WorkerError::Revoked(effect.admission_revision().to_owned()));
    }
    if effect.authorized_effect().proposal != *proposal {
        return Err(WorkerError::EffectMismatch("proposal"));
    }
    effect
        .authorized_effect()
        .validate(grant.authority())
        .map_err(|_| WorkerError::EffectMismatch("authority"))?;
    if effect.lease() != &grant.authority().lease {
        return Err(WorkerError::StaleLease);
    }
    if effect.state_fence() != &grant.authority().state_fence {
        return Err(WorkerError::StaleFence);
    }
    if effect.admission_revision() != grant.admission_revision()
        || effect.revocation_revision() != grant.revocation_revision()
    {
        return Err(WorkerError::StaleRevision);
    }
    if effect.observed_at_unix_ms() >= effect.expires_at_unix_ms()
        || effect.expires_at_unix_ms() > grant.expires_at_unix_ms()
    {
        return Err(WorkerError::StaleLease);
    }
    Ok(())
}

fn validate_checkpoint_receipt(
    receipt: &CheckpointReceiptFacts,
    request: &DurableCheckpointRequest,
) -> Result<(), WorkerError> {
    if receipt.receipt_id().trim().is_empty() || receipt.durable_at_unix_ms() == 0 {
        return Err(WorkerError::CheckpointReceiptMismatch("durable_identity"));
    }
    if receipt.checkpoint_ref() != request.checkpoint_ref()
        || receipt.request_id() != request.request_id()
        || receipt.stream_id() != request.stream_id()
        || receipt.producer_generation() != request.producer_generation()
        || receipt.authority_epoch() != request.authority_epoch()
        || receipt.state_fence() != request.state_fence()
        || receipt.admission_revision() != request.admission_revision()
        || receipt.operation_id() != request.operation_id()
        || receipt.process_request_digest() != request.process_request_digest()
    {
        return Err(WorkerError::CheckpointReceiptMismatch("request_binding"));
    }
    Ok(())
}

fn validate_ack(receipt: &EventAckReceipt, grant: &CapabilityGrant) -> Result<(), WorkerError> {
    if receipt.stream_id != grant.stream_id()
        || receipt.producer_generation != grant.worker_generation()
        || receipt.event_id.trim().is_empty()
        || receipt.sequence == 0
        || receipt.acknowledged_at_unix_ms == 0
    {
        return Err(WorkerError::ReplayContract("ack_identity"));
    }
    if receipt.authority_epoch != grant.authority().epoch {
        return Err(WorkerError::StaleEpoch);
    }
    if receipt.state_fence != grant.authority().state_fence {
        return Err(WorkerError::StaleFence);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_event(
    event: &WorkerEventEnvelope,
    grant: &CapabilityGrant,
    request_id: &RequestId,
    payload_type: &str,
    payload: &WorkerEventPayload,
    disposition: &ReceiptDisposition,
    trace_context: &BTreeMap<String, String>,
    causal_predecessor_refs: &[String],
    delivery_class: DeliveryClass,
    ack_required: bool,
) -> Result<(), WorkerError> {
    if event.stream_id != grant.stream_id()
        || event.producer_id != grant.producer_id()
        || event.producer_generation != grant.worker_generation()
        || event.authority_epoch != grant.authority().epoch
        || event.state_fence != grant.authority().state_fence
        || event.event_id.trim().is_empty()
        || event.sequence == 0
        || event.request_id != *request_id
        || event.payload_type != payload_type
        || event.payload != *payload
        || event.disposition != *disposition
        || event.trace_context != *trace_context
        || event.causal_predecessor_refs != causal_predecessor_refs
        || event.delivery_class != delivery_class
        || event.ack_required != ack_required
    {
        return Err(WorkerError::ReplayContract("event_binding"));
    }
    Ok(())
}

fn validate_replayed_events(
    events: &[WorkerEventEnvelope],
    grant: &CapabilityGrant,
    after_sequence: Option<u64>,
) -> Result<(), WorkerError> {
    let mut prior_sequence = after_sequence.unwrap_or(0);
    let mut prior_event_id: Option<&str> = None;
    let mut event_ids = std::collections::BTreeSet::new();
    for event in events {
        if event.stream_id != grant.stream_id()
            || event.producer_id != grant.producer_id()
            || event.producer_generation != grant.worker_generation()
            || event.authority_epoch != grant.authority().epoch
            || event.state_fence != grant.authority().state_fence
            || event.event_id.trim().is_empty()
            || event.sequence == 0
            // request_id is the shared RequestId contract: blank and
            // control-bearing values cannot be constructed (RequestId::new)
            // or deserialized, so no local shape check remains here.
            || event.payload_type.trim().is_empty()
            || event.sequence <= prior_sequence
            || (after_sequence.is_some() && event.sequence != prior_sequence.saturating_add(1))
            || !event_ids.insert(event.event_id.as_str())
            || event
                .causal_predecessor_refs
                .iter()
                .any(|reference| reference.trim().is_empty() || reference == &event.event_id)
            || (event.sequence > 1 && event.causal_predecessor_refs.is_empty())
            || prior_event_id.is_some_and(|prior| {
                !event
                    .causal_predecessor_refs
                    .iter()
                    .any(|reference| reference == prior)
            })
            || !delivery_ack_is_valid(event.delivery_class, event.ack_required)
        {
            return Err(WorkerError::ReplayContract("replay_binding"));
        }
        prior_sequence = event.sequence;
        prior_event_id = Some(&event.event_id);
    }
    Ok(())
}

fn validate_request_replay(
    events: &[WorkerEventEnvelope],
    request_id: &RequestId,
) -> Result<(), WorkerError> {
    if events.iter().any(|event| event.request_id != *request_id) {
        return Err(WorkerError::ReplayContract("request_replay_binding"));
    }
    Ok(())
}

const fn delivery_ack_is_valid(delivery_class: DeliveryClass, ack_required: bool) -> bool {
    match delivery_class {
        DeliveryClass::DurableControl | DeliveryClass::DurableObservation => ack_required,
        DeliveryClass::BestEffortTelemetry => !ack_required,
    }
}

fn validate_process_evidence(
    evidence: &ProcessEvidence,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    validate_process_evidence_binding(
        evidence.operation_id(),
        evidence.request_digest(),
        evidence.view().fence(),
        process,
    )
}

fn validate_process_evidence_binding(
    operation_id: &OperationId,
    request_digest: &str,
    fence: &FencingToken,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if operation_id != process.operation_id()
        || request_digest != process.request_digest()
        || !fence.matches(process.fence())
    {
        return Err(WorkerError::ProcessReceiptMismatch("process_evidence"));
    }
    Ok(())
}

fn worker_lifecycle_from_process(lifecycle: ProcessLifecycle) -> WorkerLifecycle {
    match lifecycle {
        ProcessLifecycle::Created | ProcessLifecycle::Starting => WorkerLifecycle::Starting,
        ProcessLifecycle::Running => WorkerLifecycle::Ready,
        ProcessLifecycle::Cancelling => WorkerLifecycle::Cancelling,
        ProcessLifecycle::Exited | ProcessLifecycle::Quarantined | ProcessLifecycle::Failed => {
            WorkerLifecycle::Stopped
        }
        ProcessLifecycle::UnknownOutcome => WorkerLifecycle::UnknownOutcome,
        ProcessLifecycle::Reconciled => WorkerLifecycle::Reconciled,
    }
}

fn provider_error(error: ProviderFailure) -> WorkerError {
    let ProviderFailure { provider, detail } = error;
    WorkerError::Provider(format!("provider {provider} failed: {detail}"))
}

fn map_process_error(error: ProcessExecutionError) -> WorkerError {
    match error {
        ProcessExecutionError::Unavailable(_) => WorkerError::PlanGap {
            code: PROCESS_PROVIDER_PLAN_GAP,
            detail: "P-03 ProcessExecutor is unavailable",
        },
        ProcessExecutionError::UnknownOutcome => WorkerError::UnknownOutcome,
        other => WorkerError::Process(other.to_string()),
    }
}

fn map_start_inspect_error(error: ProcessExecutionError) -> WorkerError {
    match error {
        ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome => {
            WorkerError::UnknownOutcome
        }
        other => map_process_error(other),
    }
}

#[cfg(test)]
mod tests;
