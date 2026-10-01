//! Kernel-owned canonical Store gateway and its replacement flight fence.
//!
//! Architecture traceability: `A12.3` and `ARCH-SEC-02` keep one governed
//! Store write path; `A13.2`, `A13.6`, `ARCH-AUTH-01`, and `ARCH-RES-01` bind
//! recovery to the live Kernel route and exact fence. Implementation anchors
//! are `I1.8`, `I5.1`, `I5.9`, `I5.11`, `B.2`, `P.3`, and `I14.21`: the Store
//! owns durable records, this gateway verifies route/fence and admission, and
//! Governor remains the only semantic owner. Recovery payloads stay opaque;
//! no capability is advertised, no retry/cache/default policy is invented,
//! and unknown genesis outcomes remain the EBP client's exact-operation
//! reconciliation result.
//!
//! # Live status
//!
//! The maintenance-trigger owner surface of [`KernelStoreGateway`] below is
//! **not** a live route, with exactly one exception.
//!
//! [`KernelStoreGateway::admit_maintenance_trigger`] is live: `eliotd` is not
//! its only caller, and the Kernel front door reaches it through the
//! `maintenance_trigger_intake` operation dispatched by
//! `bins/eliot-kernel/src/daemon_request_dispatch.rs`.
//!
//! The other fourteen owner entries — `claim_maintenance_trigger`,
//! `release_expired_maintenance_trigger_claim`,
//! `maintenance_trigger_pending_page`,
//! `record_maintenance_trigger_decision`, `acknowledge_maintenance_trigger`,
//! `replay_maintenance_trigger_after_crash`,
//! `recover_maintenance_trigger_commit`,
//! `mark_maintenance_trigger_commit_ambiguous`,
//! `revoke_maintenance_trigger_consumer`,
//! `maintenance_trigger_replacement_pending_set`, `expire_maintenance_trigger`,
//! `supersede_maintenance_trigger`, `record_maintenance_trigger_gap`, and
//! `restore_maintenance_trigger_ledger` — have **no production caller**. Each
//! one has exactly one code caller, and every such caller lives in the
//! `#1694` W2–W7 route of `bins/eliotd/src/maintenance_dispatch.rs`, which is
//! itself entirely unwired. Three of those callers are additionally
//! *transitively* dead, so a name-level scan reports a call site where no live
//! path exists.
//!
//! Because `KernelStoreGateway` is re-exported from this crate's root
//! (`pub use store_gateway::KernelStoreGateway`), these entries are effectively
//! publicly reachable and `rustc`'s `dead_code` lint will never report any of
//! them, even though `mod store_gateway` is itself private. A reader therefore
//! gets no compiler signal at all on this surface; each entry below states its
//! own status under a `# Live status` heading instead.
//!
//! A source implementation is not evidence of a live edge, and nothing here
//! promotes these entries to current support. Whether each is wired to a
//! daemon maintenance route or retired is an owner decision for the Kernel
//! and `eliotd` composition roots, not a documentation one. Nothing is wired,
//! removed, or allow-listed to produce this status.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, HostCorrelationDomain, HostCorrelationProjection, OperationId, RequestMetadata,
    ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_ipc::NamedPipeTransport;
use eliot_kernel_core::GenerationRoute;
use eliot_kernel_core::KernelError;
use eliot_kernel_core::UserAutomationOperation;
use eliot_kernel_core::UserAutomationOperatorIntent;
use eliot_kernel_core::user_automation::{
    ConfigPolicySnapshot, DeliveryChannel, UserAutomationConfigurationState,
    UserAutomationDeferReason, UserAutomationExecutionMode, UserAutomationInvocation,
    UserAutomationPreflightAssembly, UserAutomationPreflightContext,
    UserAutomationPreflightDecision, UserAutomationPreflightEvidence,
    UserAutomationPreflightProjection, UserAutomationRevision,
};
use eliot_ors::{
    CONTRACT_VERSION as ORS_CONTRACT_VERSION, HOST_REQUEST_SEND_CLAIM_LEASE_MS, HostRequestAttempt,
    HostRequestAttemptPhase, HostRequestDeliveryReceipt, HostRequestKind, HostRequestNoSendProof,
    HostRequestOwnerReadbackEvidence, HostRequestRecord, HostRequestResponseSource,
    HostRequestState, HostRequestTransportBoundary, HostRequestTransportObservation, OpaqueLabel,
    RedbRecoveryStore, ReservationRecord, UnknownCommitOutcome, UnknownCommitRecord,
    WriterReservationToken,
};
use eliot_ors::{OrsError, prove_maintenance_trigger_staging};
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse, JobOperation};
use eliot_protocol::{
    MaintenanceTriggerAck, MaintenanceTriggerClaim, MaintenanceTriggerDecisionReceipt,
    MaintenanceTriggerGapKind, MaintenanceTriggerIntakeReceipt, MaintenanceTriggerPage,
    MaintenanceTriggerRecord, MaintenanceTriggerRevocation, ProtocolError,
};
use eliot_runtime_contracts::{
    AffectedOperationClass, BackpressureDisposition, BottleneckAvailability,
    BottleneckCoverageState, BottleneckObservationV1, CapacityBottleneck,
    EarliestRecoveryCondition, EvidenceCoverageState, HumanActionRequirement,
    I14_BACKPRESSURE_RESPONSE_VERSION, I14AlternativeRoute, I14BackpressureCause,
    I14BackpressureResponseV1, I14CurrentnessState, I14EscalationCondition, I14ForbiddenAction,
    I14RecoveryAction, I14RecoveryDirectiveV1, I14RequiredAuthority, I14ResolutionState,
    I14WorkOutcome, NormalWorkClass, RecoveryCommitStatus, StatePreservationStatus, WakeIntent,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalRestoreBatch, CanonicalStoreClient, CanonicalValidationSnapshot,
    NamedReadRequest, NamedReadResponse, OperationIdentity, OrderingHead, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, RecoveryRecord, RecoveryRecordKey, RequestMeta,
    ReservedWriteRequest, RestoreValidationReceipt, RevisionHead, RevisionHeadExpectation,
    RevisionKey, ScopeId, ScopeRevisionView, StoreError, StoreGenesisRequest, StoreHealth,
    StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt, WriteReceiptStatus, WriteSubmission,
    admit_write_submission, canonical_request_hash, dreamer_job_queue_key,
    generated_operation_manifests, operation_manifest_set_digest, verify_canonical_request_hash,
};
use serde::{Deserialize, Serialize};

use crate::commit_recovery::{
    CheckedPauseObservation, CommitRecoveryClass, CommitRecoveryError, PauseReleaseOutcome,
    PauseScopeView, PausedScopeMirror, RetainedCommitState, classify_commit_receipt,
    classify_retained_commit, open_record_for, receipt_evidence_digest, recover_commit,
    resolve_open_record, verify_dreamer_canonical_request_hash, verify_receipt_binding,
    verify_retained_binding, verify_terminal_evidence,
};
use crate::store_client::DreamerCommitEvidence;
use crate::store_write_reservation::{
    CompositionReservation, ReservationSeed, ReservedSubmission, ResolvedSendOutcome,
    StagedWriteRecovery, begin_execute_after_send, cancel_before_send, ensure_eligible,
    finalize_reservation, mark_unknown_outcome, reconcile_receipt, reserve_for_transition,
    retain_unsupported_prepared_plan, writer_epoch_for_fence_from_epoch,
};
use crate::user_automation_execution::{
    UserAutomationDueWakeResolution, UserAutomationDurableJobMaterial,
    UserAutomationExecutionError, UserAutomationExecutionOutcome, UserAutomationExecutionRequest,
    UserAutomationRemovalResult, UserAutomationRuntimeAdmission, UserAutomationWakeCancellation,
    UserAutomationWakeCancellationTarget, UserAutomationWakeEnumerationReceipt,
    UserAutomationWakePublication, UserAutomationWakeTargetEnumeration,
    read_retirement_wake_targets, retirement_wake_enumeration_request,
};
use crate::user_automation_execution_client::{
    UserAutomationHostExecutionObserver, UserAutomationHostExecutionOperation,
    UserAutomationHostExecutionRequest, UserAutomationHostExecutionResponse,
};
use crate::user_automation_orchestration::{
    USER_AUTOMATION_RUNTIME_CHANNEL, UserAutomationOrchestrationRecord,
    UserAutomationRuntimeObligation, UserAutomationRuntimeObligationAnswer,
    UserAutomationRuntimeObligationDisposition, UserAutomationRuntimeObligationKind,
    retained_user_automation_cancellation_obligation, retained_user_automation_obligation,
    runtime_obligation_payload_digest,
};
use crate::{
    AuthenticatedMaintenanceTriggerSession, CanonicalUserAutomationStore, EbpCanonicalStoreClient,
    EbpStoreTransport, KernelService, KernelServiceError, MaintenanceTriggerClaimRequest,
    MaintenanceTriggerDeliveryError, MaintenanceTriggerDeliveryLedger,
    MaintenanceTriggerDeliveryRow, StoreClientFault, StoreClientFaultHarness,
    UserAutomationConfigurationPhase, UserAutomationExecutionPhase, UserAutomationHorizonOutcome,
    UserAutomationHorizonPhase, UserAutomationHorizonTrigger, UserAutomationMutationResult,
    UserAutomationOperatorTransition, UserAutomationOwnerLookup, UserAutomationOwnerSnapshot,
    UserAutomationReadResult, UserAutomationRuntimeError, UserAutomationRuntimePort,
    UserAutomationService, UserAutomationServiceRequest, UserAutomationStoreOutcome,
    UserAutomationStoreRequest, UserAutomationWakeHorizonPublication, UserAutomationWakePhase,
    UserAutomationWakePort, committed_configuration_state, compile_wake_horizon,
    handle_maintenance_trigger_ack, handle_maintenance_trigger_claim,
    handle_maintenance_trigger_decision, handle_maintenance_trigger_expiry,
    handle_maintenance_trigger_gap, handle_maintenance_trigger_mark_ambiguous,
    handle_maintenance_trigger_pending_page, handle_maintenance_trigger_release_expired,
    handle_maintenance_trigger_replacement_pending_set, handle_maintenance_trigger_revocation,
    handle_maintenance_trigger_supersession, recover_maintenance_trigger_commit,
    replay_maintenance_trigger_after_crash, run_now_wake_read_request,
};
use eliot_kernel_core::user_automation::UserAutomationExecutionProjection;

const ACTIVE_DAEMON_CALLER: &str = "eliotd";

/// Monotonic per-process counter behind one `UserAutomation` send claim.
///
/// The durable claim is first-writer-wins, so a second acquisition of the same
/// obligation must never be able to replay as the first caller's attempt. Every
/// claim therefore mints a distinct launch nonce from this counter, so the ORS
/// `HostRequestAttempt` two competing callers present can only be byte-equal
/// when they are the same attempt. It is process-local identity for a durable
/// record; it grants no authority and carries no decision of its own.
static USER_AUTOMATION_SEND_CLAIM_NONCE: AtomicU64 = AtomicU64::new(0);

/// ORS-backed observer for one exact `UserAutomation` cancellation claim.
///
/// The expected typed cancellation, staged row, and acquired claim are
/// immutable snapshots. Every callback revalidates the actual authenticated
/// carrier against those snapshots before advancing ORS.
struct UserAutomationCancellationCustodyObserver<'a> {
    ors: &'a RedbRecoveryStore,
    record: HostRequestRecord,
    attempt: HostRequestAttempt,
    expected_cancellation: UserAutomationWakeCancellation,
}

impl UserAutomationCancellationCustodyObserver<'_> {
    fn validate_carrier(
        &self,
        request: &UserAutomationHostExecutionRequest,
    ) -> Result<(), UserAutomationRuntimeError> {
        request.validate()?;
        let authenticated_channel = request.channel.authenticated_evidence_digest()?;
        let exact_cancellation = matches!(
            &request.operation,
            UserAutomationHostExecutionOperation::CancelPendingWakes { request: actual }
                if actual.as_ref() == &self.expected_cancellation
        );
        if !exact_cancellation
            || request.request_sha256 != request.compute_digest()?
            || self.record.send_claim_protocol_version
                != eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            || self.record.attempt.as_ref() != Some(&self.attempt)
            || self.record.transport_channel_binding_sha256.as_deref()
                != Some(authenticated_channel.as_str())
            || self.attempt.channel_binding_sha256.as_deref()
                != Some(authenticated_channel.as_str())
            || self
                .expected_cancellation
                .enumeration_receipt
                .as_deref()
                .is_none_or(|receipt| {
                    receipt.authenticated_channel_binding_sha256 != authenticated_channel
                })
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok(())
    }

    fn persist_observation(
        &self,
        request: &UserAutomationHostExecutionRequest,
        boundary: HostRequestTransportBoundary,
        delivery_receipt: Option<HostRequestDeliveryReceipt>,
        response_commitment_sha256: Option<String>,
        no_send_proof: Option<HostRequestNoSendProof>,
    ) -> Result<(), UserAutomationRuntimeError> {
        self.validate_carrier(request)?;
        let channel_binding_sha256 = request.channel.authenticated_evidence_digest()?;
        let observation = HostRequestTransportObservation {
            operation_id: self.record.operation_id.clone(),
            request_digest: self.record.request_digest.clone(),
            attempt_id: self.attempt.attempt_id.clone(),
            attempt_generation: self.attempt.generation,
            boundary,
            channel_binding_sha256,
            transport_request_sha256: request.request_sha256.clone(),
            request_commitment_sha256: self.record.request_digest.clone(),
            payload_commitment_sha256: self.record.payload_digest.clone(),
            delivery_receipt,
            response_commitment_sha256,
            response_source: (boundary == HostRequestTransportBoundary::ResponseReceived)
                .then_some(HostRequestResponseSource::AuthenticatedTransport),
            no_send_proof,
        };
        let persisted = if boundary == HostRequestTransportBoundary::DispatchStarted {
            self.ors.begin_host_request_transport_dispatch(
                &self.record.operation_id,
                &self.record.request_digest,
                &self.attempt,
                &observation,
            )
        } else {
            self.ors.observe_host_request_transport_custody(
                &self.record.operation_id,
                &self.record.request_digest,
                &self.attempt,
                &observation,
            )
        }
        .map_err(|error| match error {
            eliot_ors::OrsError::HostRequestAttemptExpired => {
                UserAutomationRuntimeError::UnknownOutcome(
                    "the retained send claim expired before dispatch and remains in reconciliation"
                        .to_owned(),
                )
            }
            _ => UserAutomationRuntimeError::UnknownOutcome(
                "the typed transport boundary could not be persisted under its exact claim"
                    .to_owned(),
            ),
        })?;
        if persisted.is_none() {
            return Err(UserAutomationRuntimeError::UnknownOutcome(
                "the retained cancellation claim disappeared while recording transport custody"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl UserAutomationHostExecutionObserver for UserAutomationCancellationCustodyObserver<'_> {
    fn dispatch_started(
        &self,
        request: &UserAutomationHostExecutionRequest,
    ) -> Result<(), UserAutomationRuntimeError> {
        self.persist_observation(
            request,
            HostRequestTransportBoundary::DispatchStarted,
            None,
            None,
            None,
        )
    }

    fn definitely_not_sent(
        &self,
        request: &UserAutomationHostExecutionRequest,
        proof: HostRequestNoSendProof,
    ) -> Result<(), UserAutomationRuntimeError> {
        self.persist_observation(
            request,
            HostRequestTransportBoundary::DefinitelyNotSent,
            None,
            None,
            Some(proof),
        )
    }

    fn delivery_outcome(
        &self,
        request: &UserAutomationHostExecutionRequest,
        receipt: HostRequestDeliveryReceipt,
    ) -> Result<(), UserAutomationRuntimeError> {
        let boundary = match receipt {
            HostRequestDeliveryReceipt::Delivered => {
                HostRequestTransportBoundary::DeliveredToAuthenticatedHost
            }
            HostRequestDeliveryReceipt::UnknownOutcome => {
                HostRequestTransportBoundary::DeliveryOutcomeUnknown
            }
        };
        self.persist_observation(request, boundary, Some(receipt), None, None)
    }

    fn response_received(
        &self,
        request: &UserAutomationHostExecutionRequest,
        response: &UserAutomationHostExecutionResponse,
    ) -> Result<(), UserAutomationRuntimeError> {
        self.validate_carrier(request)?;
        response.validate_for(request)?;
        let result_response = serde_json::to_value(response).map_err(|_| {
            UserAutomationRuntimeError::UnknownOutcome(
                "the validated Host response could not be encoded for durable retention".to_owned(),
            )
        })?;
        let result_digest = canonical_json_bytes(&result_response)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| {
                UserAutomationRuntimeError::UnknownOutcome(
                    "the validated Host response could not be committed for durable retention"
                        .to_owned(),
                )
            })?;
        self.persist_observation(
            request,
            HostRequestTransportBoundary::ResponseReceived,
            None,
            Some(result_digest.clone()),
            None,
        )?;
        let persisted = self
            .ors
            .persist_claimed_host_request_result(
                &self.record.operation_id,
                &self.record.request_digest,
                &self.attempt,
                &result_digest,
                &result_response,
                None,
            )
            .map_err(|_| {
                UserAutomationRuntimeError::UnknownOutcome(
                    "the validated Host response was observed but its exact result body could not be terminalized"
                        .to_owned(),
                )
            })?;
        if persisted.is_none() {
            return Err(UserAutomationRuntimeError::UnknownOutcome(
                "the validated Host response was observed but its retained claim disappeared before terminalization"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn user_automation_gateway_unknown(error: impl std::fmt::Display) -> UserAutomationExecutionError {
    UserAutomationExecutionError::Runtime(UserAutomationRuntimeError::UnknownOutcome(
        error.to_string(),
    ))
}

fn normalization_receipt_binding() -> UserAutomationExecutionError {
    UserAutomationExecutionError::Contract(
        eliot_kernel_core::user_automation::UserAutomationError::ReceiptBinding,
    )
}

fn normalization_selector(
    request: &UserAutomationServiceRequest,
) -> Result<(String, String), UserAutomationExecutionError> {
    match &request.intent.operation {
        UserAutomationOperation::NormalizeSchedule { revision, .. }
        | UserAutomationOperation::MigrateLegacySchedule { revision, .. } => {
            Ok((revision.automation_id.clone(), revision.revision.clone()))
        }
        _ => Err(UserAutomationExecutionError::Contract(
            eliot_kernel_core::user_automation::UserAutomationError::Invalid(
                "operation.schedule_normalization",
            ),
        )),
    }
}

#[path = "store_receipt_gateway.rs"]
mod store_receipt_gateway;

/// Kernel answer for one Dreamer ledger mutation whose ledger answer could not
/// be observed on the wire (I14.21, issue #1690).
///
/// `commit_recovery::recover_commit` shapes the commits that answer with a
/// `WriteReceipt`; a Dreamer commit answers with a ledger projection instead,
/// so this leg states the same three mandated branches over its own typed
/// answer and never collapses them into a success or a retry permission.
///
/// It is public because it is the recovered outcome its real caller must
/// distinguish: it travels inside [`DreamerJobGatewayError`], so a
/// caller-reachable field may not be crate-private. Every arm names the
/// admitted idempotency key, the exact terminal `UnknownCommitOutcome`, the
/// receipt evidence digest that proves it, and the obligation that remains.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DreamerCommitUncertain {
    /// The commit outcome is proven by an exact receipt and this leg
    /// reconciled the durable record with that receipt digest bound as its
    /// terminal evidence. Exactly one canonical operation exists under the
    /// admitted identity, this leg issues no second mutation, and the ledger
    /// projection stays unknown, so the caller follows up with a ledger
    /// `Status`/`Reconcile` observation.
    #[error(
        "dreamer ledger mutation {idempotency_key} is reconciled exactly once ({outcome:?}): the durable unknown-commit record is bound to receipt evidence {evidence_receipt_digest} and no second mutation is issued; the ledger answer is still unknown and needs a Status/Reconcile observation"
    )]
    Reconciled {
        /// Admitted idempotency key whose commit outcome is proven.
        idempotency_key: String,
        /// SHA-256 of the exact observed receipt bytes.
        evidence_receipt_digest: String,
        /// Terminal outcome the receipt evidence supports.
        outcome: UnknownCommitOutcome,
    },
    /// The key already carries an evidence-backed disposition. A resolved
    /// record never reopens, so this leg neither restages, re-resolves, nor
    /// pauses an Ordering Scope for it.
    ///
    /// The recorded terminal outcome is carried through, not flattened into
    /// an ambiguous success (issue #2764 item 6): `Committed` and
    /// `RolledBack` are different proven facts and a caller acting on the
    /// difference must not have to re-derive it from prose.
    #[error(
        "dreamer ledger mutation {idempotency_key} is already dispositioned as {outcome:?} with receipt evidence {evidence_receipt_digest}; the durable record is not reopened, no Ordering Scope is paused, and no mutation is resent"
    )]
    AlreadyDispositioned {
        /// Admitted idempotency key.
        idempotency_key: String,
        /// Terminal outcome already recorded for this key.
        outcome: UnknownCommitOutcome,
        /// SHA-256 already bound by the earlier disposition.
        evidence_receipt_digest: String,
    },
    /// The key already carries an evidence-backed disposition and a pause
    /// refresh after it could not be proven complete. The recorded
    /// disposition stands: the commit is not reopened and not reported as
    /// failed, the affected Ordering Scopes stay paused, and the limitation
    /// is stated (issue #2763 item 4).
    #[error(
        "dreamer ledger mutation {idempotency_key} is recorded as {outcome:?} with receipt evidence {evidence_receipt_digest}, but the pause refresh after that disposition could not be proven complete: {refresh_limitation}; the recorded commit stands, its Ordering Scopes stay paused, and no mutation is resent"
    )]
    ReconciledWithRefreshLimitation {
        /// Admitted idempotency key whose commit outcome is proven.
        idempotency_key: String,
        /// Terminal outcome the receipt evidence supports.
        outcome: UnknownCommitOutcome,
        /// SHA-256 of the exact observed receipt bytes.
        evidence_receipt_digest: String,
        /// Exactly why the pause release could not be completed.
        refresh_limitation: String,
    },
    /// The outcome stays unknown: the operation is preserved in the durable ORS
    /// record and its Ordering Scopes are paused while this recoverable Problem
    /// State remains open. This is the same Problem State
    /// `commit_recovery::open_problem_state` opens for a `WriteReceipt` commit.
    #[error(
        "dreamer ledger mutation {idempotency_key} has an unknown commit outcome: the operation is preserved, these Ordering Scopes are paused ({paused_scopes:?}) and a recoverable Problem State is open for Doctor or Human disposition"
    )]
    UnknownCommitOpen {
        /// Admitted idempotency key whose outcome is unknown.
        idempotency_key: String,
        /// Ordering Scopes paused while the record is open.
        paused_scopes: Vec<String>,
    },
}

/// Outcome of the read-first exact-recovery branch for one retained
/// operation (issue #2764).
#[derive(Clone, Debug, Eq, PartialEq)]
enum DreamerRetainedOutcome {
    /// The retained operation is settled from exact receipt evidence, or
    /// remains unresolved with that evidence stated. The typed answer is the
    /// caller-facing report: a `WriteReceipt` proves a mutation disposition,
    /// never the missing `DurableJobResponse`, so the answer still carries
    /// the remaining ledger-read obligation.
    Settled(DreamerCommitUncertain),
    /// A proven noncommit whose resubmission policy still allows the
    /// identical identity, observed while the retained record is open. The
    /// caller re-enters normal admission and the other-key pause check for
    /// one bounded same-identity retry. This branch has issued zero mutation
    /// sends: the receipt query is a pure read.
    SameIdentityRetryPermitted,
}

/// The checked pause gate for one admitted Dreamer operation (#2763).
///
/// A derived Ordering Scope is matched against the complete observed record
/// set, so every open record covering the scope is considered. Because every
/// closed Dreamer kind now proves at least one scope, a pause is reported
/// precisely for all of them: the refusal names the scope and the idempotency
/// key holding it, which is what makes the pause displayable and actionable
/// rather than a bare Problem State.
///
/// What remains unproven is the link *above* the proven set. The kinds that
/// bind only a `JobLease` or a job id reach their own ordered job-attempt
/// ledger but not the Work Scope that ledger is ordered inside, and a record
/// opened by `Submit` or by a lease selection is indexed by work scope without
/// having to name any job. For those kinds `OrderingScopeUnresolved` keeps the
/// complete-record closure: an unproven link is not evidence of being
/// unpaused, so admission stays closed while any other open record exists.
/// This is a stated limitation, never a bypass.
fn dreamer_pause_refusal(
    observed: &CheckedPauseObservation,
    identity: &OperationIdentity,
    proof: &DreamerOrderingScopeProof,
    effect: DreamerOperationEffect,
) -> Option<CommitRecoveryError> {
    if effect != DreamerOperationEffect::Mutation {
        return None;
    }
    let key = identity.idempotency_key.as_str();
    let paused = proof.scopes.iter().find_map(|scope| {
        observed
            .pausing_key_for(scope, key)
            .map(|pausing_key| CommitRecoveryError::ScopePaused {
                scope: scope.clone(),
                paused_by_key: pausing_key.to_owned(),
            })
    });
    if paused.is_some() {
        return paused;
    }
    if !proof.work_scope_proven && observed.any_open_except(key) {
        return Some(CommitRecoveryError::OrderingScopeUnresolved {
            operation: "dreamer-job".to_owned(),
            detail: format!(
                "the Ordering Scopes this operation proves ({}) do not reach the Work Scope \
                 its ledger record is ordered inside, so its coverage by the open \
                 unknown-commit record set observed at revision {} cannot be proven and \
                 dependent durable admission stays closed",
                proof.rendered(),
                observed.binding().revision
            ),
        });
    }
    None
}

/// Renders an ORS failure as the fail-closed recovery refusal (I14.24).
///
/// The value stays typed: the fail-closed refusal is a
/// [`CommitRecoveryError::OrsUnavailable`], and every caller of this helper
/// composes it into an error that already carries that type, so no gateway
/// refusal has to be flattened to text to travel anywhere.
fn ors_unavailable(error: impl std::fmt::Display) -> CommitRecoveryError {
    CommitRecoveryError::OrsUnavailable {
        detail: error.to_string(),
    }
}

/// Reads back the recorded terminal outcome and evidence digest of one
/// resolved durable record.
///
/// `UnknownCommitRecord::validate` (run by the load) rejects a resolved record
/// that binds no evidence, so the missing pair is unreachable from ORS and
/// stays a typed refusal rather than a substituted outcome: a terminal state
/// is never reported as an invented success.
fn retained_terminal_evidence(
    idempotency_key: &str,
    record: &UnknownCommitRecord,
) -> Result<(UnknownCommitOutcome, String), CommitRecoveryError> {
    match (record.outcome, record.evidence_receipt_digest.clone()) {
        (Some(outcome), Some(evidence_receipt_digest)) => Ok((outcome, evidence_receipt_digest)),
        _ => Err(CommitRecoveryError::ReceiptQueryFailed {
            idempotency_key: idempotency_key.to_owned(),
            detail: "resolved unknown-commit record binds no receipt evidence".to_owned(),
        }),
    }
}

/// Selects the schedule normalization receipt envelopes the canonical Store
/// retains beside one immutable owner revision, under the request fence.
///
/// The normalization receipt is owner evidence over the compiled occurrence set,
/// so it is read from the owner that retained it and is never assembled, derived
/// or defaulted here. Retention lives on the revision row the revision leg wrote
/// — the `normalization_receipt_json` mechanism `ApplyNotificationState` already
/// uses for `source_receipt_json` — and NOT in the canonical Store's own
/// `WriteReceipt` history, which provably cannot carry this digest:
/// `receipt_artifacts` emits exactly `store-transition:{op}` (the committed
/// transition digest) and `store-plan:{commit_id}`, and that envelope's
/// content-derived identity depends on the committed transition plus the
/// adapter-assigned `commit_id`/`commit_sequence`. It is therefore not
/// computable before the commit, and re-pointing it at a compiled occurrence set
/// would be circular, because the transition digest already covers the very
/// `revision_json` that names the envelope id.
///
/// Selection is by the envelope's own content-derived identity — exactly the id
/// the immutable revision names — and the binding is then closed by
/// `UserAutomationPreflightProjection::assemble`, which validates the envelope
/// through its own `validate()` and requires its canonical bytes to carry the
/// revision's compiled-occurrence digest. `check_normalization_receipt_binding`
/// is unchanged by where the envelope is read from. A revision that retained no
/// such envelope yields none, and the caller reports the missing owner instead
/// of substituting a receipt.
fn select_retained_normalization_receipts(
    state_fence: &StateFence,
    owner: &UserAutomationOwnerSnapshot,
) -> Result<Vec<eliot_receipts::ReceiptEnvelope>, RunNowPreflightAssembly> {
    if owner.state_fence != *state_fence {
        return Err(RunNowPreflightAssembly::Unknown(
            "the retained UserAutomation owner revision does not bind to the request fence"
                .to_owned(),
        ));
    }
    let declared = &owner.revision.schedule.normalization_receipt;
    Ok(owner
        .normalization_receipt
        .iter()
        .filter(|envelope| envelope.identity.receipt_id.as_str() == declared.receipt_id.as_str())
        .cloned()
        .collect())
}

/// Projects one already-resolved durable record into its typed answer,
/// preserving the outcome it actually recorded.
///
/// The recorded outcome and its evidence digest are returned as the values the
/// record holds, never as a synthesized success: a `RolledBack` key and a
/// `Committed` key are different proven facts and the caller is given the one
/// that actually happened.
fn dreamer_dispositioned(
    idempotency_key: &str,
    record: &UnknownCommitRecord,
) -> Result<DreamerCommitUncertain, CommitRecoveryError> {
    let (outcome, evidence_receipt_digest) = retained_terminal_evidence(idempotency_key, record)?;
    Ok(DreamerCommitUncertain::AlreadyDispositioned {
        idempotency_key: idempotency_key.to_owned(),
        outcome,
        evidence_receipt_digest,
    })
}

/// Whether one closed Dreamer operation may write the ledger.
///
/// Classification is by the operation's real owner semantics, never by its
/// name: `Status` and the exact receipt lookup are the only observations the
/// ledger contract defines as side-effect-free. An operation called
/// `Reconcile` records a caller-declared disposition and an operation called
/// `RequestCancel` transitions a job, so both are mutations here and are
/// gated like any other. A resolved Ordering Scope set is NOT evidence that an
/// operation is read-only, which is why this classification does not consult
/// [`dreamer_ordering_scope_proof`] at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DreamerOperationEffect {
    /// A permitted read: the ledger contract defines no ledger transition.
    Observation,
    /// Any ledger write, including lease acquisition, checkpointing,
    /// outcome publication, cancellation request, and caller-declared
    /// reconciliation.
    Mutation,
}

fn dreamer_operation_effect(operation: &JobOperation) -> DreamerOperationEffect {
    match operation {
        // The single side-effect-free closed kind. The exact receipt lookup
        // is not a `JobOperation` at all: it is the Kernel's own
        // observation-only receipt client, so it needs no gate here.
        JobOperation::Status { .. } => DreamerOperationEffect::Observation,
        JobOperation::Submit { .. }
        | JobOperation::LeaseNext { .. }
        | JobOperation::LeaseExact { .. }
        | JobOperation::Renew { .. }
        | JobOperation::Start { .. }
        | JobOperation::Checkpoint { .. }
        | JobOperation::Resume { .. }
        | JobOperation::BeginVerification { .. }
        | JobOperation::Publish { .. }
        | JobOperation::RequestCancel { .. }
        | JobOperation::Reconcile { .. }
        | JobOperation::RecordApplicability { .. } => DreamerOperationEffect::Mutation,
    }
}

/// Ordering Scope coverage of one admitted Dreamer mutation.
///
/// The provable set comes from the Dreamer protocol itself
/// (`JobOperation::ordering_scopes`), so no scope is inferred here, and each
/// entry is spelled by the owner of that stream: a work scope by its own
/// `WorkScopeId`, and the one ordered job-attempt ledger by the Store
/// contract's canonical `dreamer_job_queue_key`. There is no second name for
/// either stream and no scope-local alias table.
///
/// `work_scope_proven` records whether the set also reaches the Work Scope the
/// ledger record is ordered inside. That is the level at which an open record
/// opened by `Submit` or a lease selection is indexed without naming this
/// job, so it is exactly the link whose absence keeps the complete-record
/// closure in force; see [`dreamer_pause_refusal`].
struct DreamerOrderingScopeProof {
    /// The complete provable Ordering Scope set, in canonical spelling.
    scopes: Vec<String>,
    /// Whether `scopes` also names the Work Scope the ledger is ordered
    /// inside, as opposed to only this job's own ledger stream.
    work_scope_proven: bool,
}

impl DreamerOrderingScopeProof {
    /// Renders the proven set for a refusal message, never as an empty claim.
    fn rendered(&self) -> String {
        if self.scopes.is_empty() {
            return "none".to_owned();
        }
        self.scopes.join(", ")
    }
}

/// Resolves the Ordering Scopes one admitted Dreamer mutation belongs to.
///
/// Every kind of the closed Dreamer vocabulary now proves at least one scope,
/// so an unknown commit on any of them records a durable, displayable pause
/// instead of an empty vector that the scope-indexed
/// [`KernelStoreGateway::paused_ordering_scopes`] view could not show. The
/// kinds that bind only a `JobLease` or a job id resolve to their own ordered
/// job-attempt ledger; `Submit` additionally carries its work scope, and the
/// two lease selections carry their selector's.
fn dreamer_ordering_scope_proof(request: &DurableJobRequest) -> DreamerOrderingScopeProof {
    let proven = request.operation.ordering_scopes();
    let mut scopes = Vec::new();
    if let Some(work_scope) = proven.work_scope {
        scopes.push(work_scope.as_str().to_owned());
    }
    if let Some((job_id, attempt_id)) = proven.job_ledger {
        scopes.push(dreamer_job_queue_key(job_id, attempt_id));
    }
    DreamerOrderingScopeProof {
        work_scope_proven: proven.work_scope.is_some(),
        scopes,
    }
}

/// The in-flight synchronization state for one canonical Store gateway.
#[derive(Default)]
struct GatewayFlightState {
    fenced: bool,
    in_flight: usize,
}

/// Tracks operations that must drain before a Store gateway is replaced.
struct GatewayFlight {
    state: Mutex<GatewayFlightState>,
    drained: tokio::sync::Notify,
}

/// Releases one in-flight gateway operation when dropped.
struct GatewayFlightGuard<'a> {
    flight: &'a GatewayFlight,
}

impl GatewayFlight {
    fn new() -> Self {
        Self {
            state: Mutex::new(GatewayFlightState::default()),
            drained: tokio::sync::Notify::new(),
        }
    }

    fn enter(&self) -> Result<GatewayFlightGuard<'_>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "canonical-store gateway flight lock poisoned".to_owned())?;
        if state.fenced {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .ok_or_else(|| "canonical-store gateway flight count overflowed".to_owned())?;
        Ok(GatewayFlightGuard { flight: self })
    }

    fn fence(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.fenced = true;
            if state.in_flight == 0 {
                self.drained.notify_waiters();
            }
        }
    }

    fn is_fenced(&self) -> bool {
        self.state.lock().map_or(true, |state| state.fenced)
    }

    fn is_drained(&self) -> Result<bool, String> {
        self.state
            .lock()
            .map(|state| state.in_flight == 0)
            .map_err(|_| "canonical-store gateway flight lock poisoned".to_owned())
    }

    async fn fence_and_drain(&self, timeout: Duration) -> Result<(), String> {
        self.fence();
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.drained.notified();
                if self.is_drained()? {
                    return Ok::<(), String>(());
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| "canonical-store gateway in-flight drain timed out".to_owned())??;
        Ok(())
    }
}

impl Drop for GatewayFlightGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.flight.state.lock() {
            state.in_flight = state.in_flight.saturating_sub(1);
            if state.in_flight == 0 {
                self.flight.drained.notify_waiters();
            }
        }
    }
}

/// Concrete non-generic gateway retained by one Kernel composition.
///
/// There is deliberately no public constructor accepting a client or caller:
/// the Kernel composition is the only production construction path and
/// supplies the Host-approved client, fixed `store_bridge` route, and fixed
/// active daemon caller.
pub struct KernelStoreGateway {
    service: Arc<Mutex<KernelService>>,
    store: Arc<EbpCanonicalStoreClient<NamedPipeTransport>>,
    route: GenerationRoute,
    flight: GatewayFlight,
    /// Durable owner for unknown-commit recovery (I14.21, issue #1690).
    /// Production composition always supplies the Kernel ORS handle; `None`
    /// (tests, or a composition that cannot open ORS) degrades recovery to
    /// fail-closed errors without staging, pause, or disposition.
    commit_ors: Option<Arc<RedbRecoveryStore>>,
    /// In-process mirror of the ordering scopes paused by open
    /// unknown-commit records, with per-entry source, observation revision
    /// and explicit coverage (issue #2763). The durable open set in ORS is
    /// authoritative; this mirror gates admission only through a checked
    /// observation and never answers on its own. Its initial state is
    /// uninitialized evidence, not an observed clear ledger.
    paused_scopes: PausedScopeMirror,
    /// The one Kernel-owned retained maintenance-trigger delivery ledger
    /// (issue #1694). Every ledger transition is performed through this
    /// owner: the intake/claim/decision/ack and recovery seams below lock it
    /// together with the service guard (service-first, ledger-second) and
    /// snapshot its durable rows on every transition. There is no second
    /// ledger, database, or poller; row durability rides the ORS staging
    /// proof (intake) and the committed named Store transaction the decision
    /// receipt binds (decision), and startup restores through
    /// [`Self::restore_maintenance_trigger_ledger`].
    maintenance_triggers: Mutex<MaintenanceTriggerDeliveryLedger>,
}

impl std::fmt::Debug for KernelStoreGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelStoreGateway")
            .field("route", &self.route)
            .field("caller", &ACTIVE_DAEMON_CALLER)
            .finish_non_exhaustive()
    }
}

/// Borrowed view of the retained canonical Store client.
///
/// [`CanonicalUserAutomationStore`] owns its client, and the production
/// `EbpCanonicalStoreClient` is deliberately neither cloned nor reconnected
/// outside the gateway that owns it. This adapter lends that one retained
/// client to the Store adapter and forwards every canonical operation
/// verbatim. It owns no client, connection, cache, or state and adds no second
/// write path: every call lands on the same authenticated generation-routed
/// client the gateway itself uses.
///
/// Because it reaches the retained client directly, it is exactly the contour
/// that could have served a generation the durable `canonical_store` route no
/// longer names. Every method therefore re-checks the same route gate as the
/// gateway's own entry points through `require_active_generation`, so the claim
/// above is enforced by the borrow rather than asserted in this doc.
pub struct BorrowedCanonicalStoreClient<'a> {
    gateway: &'a KernelStoreGateway,
}

impl<'a> BorrowedCanonicalStoreClient<'a> {
    /// Borrows the gateway that owns the retained canonical Store client.
    #[must_use]
    pub const fn new(gateway: &'a KernelStoreGateway) -> Self {
        Self { gateway }
    }

    /// Refuses a borrowed-client call unless this gateway's generation is the
    /// durable `canonical_store` route's active generation.
    ///
    /// The refusal is the same typed [`StoreError::FenceMismatch`] the gateway
    /// uses, so a cut-over-to-a-newer-generation reads identically on this
    /// contour and on the gateway's own methods.
    fn require_active_generation(&self) -> Result<(), StoreError> {
        self.gateway.require_active_store_generation()
    }
}

impl CanonicalStoreClient for BorrowedCanonicalStoreClient<'_> {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        self.require_active_generation()?;
        self.gateway
            .store
            .apply_prepared(
                ctx,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.receipt(operation_id).await
    }

    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.revision_heads(keys).await
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.validation_snapshot().await
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.scope_revision_view(scope_id).await
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.ordering_heads(scopes).await
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.execute_named(query).await
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        self.require_active_generation()?;
        self.gateway.store.health().await
    }
}

/// Canonical-store gateway bound to the active Kernel generation route.
/// Governor-issued wire envelope of the `owner/policy` recovery record.
///
/// The Governor owns the record bytes; this struct only names the exact shape
/// the Kernel decoder accepts, with the same deny-unknown-fields closure the
/// Kernel applies to every typed boundary. It lives beside its single decoder
/// so no second interpretation of the record can drift in elsewhere.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationPolicyOwnerSnapshotWire {
    /// Fence under which the Governor issued the record.
    pub state_fence: StateFence,
    /// Durable outer revision of the record.
    pub revision: u64,
    /// Digest of the canonical snapshot bytes.
    pub policy_digest: String,
    /// Complete B-owned config snapshot.
    pub snapshot: ConfigPolicySnapshot,
}

/// Refusal of one `RunNow` preflight assembly that preserves whether an owner
/// was unreadable or simply has no Kernel-side evidence issuer.
///
/// The distinction is load-bearing for the transition phases: an unreadable
/// owner may already have effected the disposition, so it reports unknown;
/// absent evidence means nothing was sent, so it reports unavailable with the
/// exact missing owner named.
enum RunNowPreflightAssembly {
    /// An owner could not be read; the execution disposition may be effected.
    Unknown(String),
    /// Named owner evidence has no issuer at this boundary; nothing was sent.
    Unavailable(String),
}

/// Typed refusal of the retained wake-horizon publication route, carrying the
/// exact durable record that exists — or the exact fact that none does.
///
/// **The defect this type closes.** The route used to return a bare `String` on
/// every failure, so a step that failed AFTER
/// [`KernelStoreGateway::settle_wake_horizon_acknowledgement`] had already
/// written the owner's answer as the record's retained body threw away the only
/// handle to a durable record that provably existed. The caller could report a
/// horizon it could not name, or name nothing at all while a record waited for a
/// reconciliation nothing could reach. That is the same defect class this issue
/// keeps producing: an answer that cannot be reached from the place the question
/// is asked.
///
/// **No identity is minted here.** The carried obligation is the one
/// `retained_user_automation_obligation` already derived from the EXISTING
/// `runtime_obligation_operation_id(kind, parent, subject_ids)` and the route
/// already settled. `Retained` is therefore reachable only from a failure site
/// that holds that value; a step that fails before the identity exists reports
/// [`Self::NothingRetained`] and must not construct one to look reportable.
///
/// **What a caller must do with each arm.**
/// * [`Self::Retained`] — a durable record exists under
///   `owner_operation_id`. Report that obligation beside the failure, never
///   re-issue the slice, and reconcile under that ORIGINAL owner operation
///   identity (I14.21: query by the original identity; no blind duplicate
///   effect). The record is already answered when this arm is produced, so the
///   reconciliation is a readback of the owner's retained body, not a resend.
/// * [`Self::NothingRetained`] — no record was written and nothing was issued,
///   so there is nothing to reconcile and the slice may still be issued later
///   under the same identity. This arm must never be read as "the record was
///   deleted": nothing was ever created.
///
/// **The two arms render differently, and that is load-bearing.** Before this
/// type existed, both rendered as the same bare reason, so a caller that
/// rendered the reason and dropped the payload produced a status line asserting
/// "no obligation was retained" while a durable record sat behind it — the exact
/// unreconcilable-loss defect this type exists to remove. A `Retained` rendering
/// therefore ends with the owner operation identity the record lives under, so
/// that a consumer which still renders only this text states the retained record
/// rather than denying it.
///
/// [`Self::into_reason`] is the one projection that is byte-identical to the text
/// this route produced before it was typed, on BOTH arms: the operator route
/// calls it, its result is a bare reason, and no operator-visible message moves.
/// [`Self::into_retained_obligation`] is the projection that closes the defect —
/// it is what the due-wake consumer's call site must consume in place of a
/// hand-written `None`.
#[derive(Debug)]
pub enum UserAutomationHorizonPublicationRefusal {
    /// The route failed before the obligation identity existed, so no durable
    /// record was written and no owner was asked.
    NothingRetained {
        /// Closed reason the slice could not even be bound and named coherently.
        reason: String,
    },
    /// The owner operation identity was established and the durable record was
    /// written, and a later step of the same route failed.
    Retained {
        /// The obligation that was actually written, under its original owner
        /// operation identity. Boxed so a refusal value stays small enough to
        /// return by value from every entry point.
        obligation: Box<UserAutomationRuntimeObligation>,
        /// Closed reason the projection failed after the record was written.
        reason: String,
    },
}

impl std::fmt::Display for UserAutomationHorizonPublicationRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingRetained { reason } => formatter.write_str(reason),
            Self::Retained { obligation, reason } => write!(
                formatter,
                "{reason}; this bounded slice IS durably retained under owner operation identity \
                 {} and must be reported and reconciled under that original identity rather than \
                 re-issued",
                obligation.owner_operation_id
            ),
        }
    }
}

impl std::error::Error for UserAutomationHorizonPublicationRefusal {}

impl UserAutomationHorizonPublicationRefusal {
    /// Arms the pre-retention arm from its closed reason.
    pub fn nothing_retained(reason: String) -> Self {
        Self::NothingRetained { reason }
    }

    /// Arms the post-retention arm from the obligation that was really written.
    pub fn retained(obligation: UserAutomationRuntimeObligation, reason: String) -> Self {
        Self::Retained {
            obligation: Box::new(obligation),
            reason,
        }
    }

    /// Consumes the refusal and yields the retained obligation, for a caller that
    /// reports it in place of a re-derived one.
    ///
    /// This hands back the EXACT record this route wrote. It never derives an
    /// identity: a caller holding `NothingRetained` gets `None` and must say so
    /// rather than construct a substitute.
    #[must_use]
    pub fn into_retained_obligation(self) -> Option<UserAutomationRuntimeObligation> {
        match self {
            Self::NothingRetained { .. } => None,
            Self::Retained { obligation, .. } => Some(*obligation),
        }
    }

    /// Consumes the refusal and yields its closed reason, which is what the
    /// operator route reports in its `String` result.
    ///
    /// The reason is preserved verbatim, so typing this route changes no operator
    /// visible text; only the typed arm the caller can now read changes.
    pub fn into_reason(self) -> String {
        match self {
            Self::NothingRetained { reason } | Self::Retained { reason, .. } => reason,
        }
    }
}

impl KernelStoreGateway {
    /// Constructs the gateway from the Kernel-approved service and Store client.
    #[doc(hidden)]
    pub fn new(
        service: Arc<Mutex<KernelService>>,
        store: Arc<EbpCanonicalStoreClient<NamedPipeTransport>>,
        route: GenerationRoute,
        commit_ors: Option<Arc<RedbRecoveryStore>>,
    ) -> Self {
        // Bind the route to the live lineage at composition (Implements #64).
        // `GenerationRoute` carries its own complete `(lineage_id, sequence)`
        // tuple, so this gateway keeps no second epoch mirror: route currency
        // is read from `route.authority_epoch()` and proven with
        // `is_same_authority` against live authority — never by coercing a
        // sequence to `u64`. Mint stays Host-owned; the gateway only pins and
        // re-checks the tuple.
        Self {
            service,
            store,
            route,
            flight: GatewayFlight::new(),
            commit_ors,
            // Uninitialized evidence, never an observed clear ledger: the
            // first admission decision reads an authoritative owner
            // observation, and until one succeeds a negative mirror answer
            // is unavailable rather than clear.
            paused_scopes: PausedScopeMirror::new(),
            // One delivery ledger per gateway: the owner of every retained
            // maintenance trigger row. It starts empty; the startup path
            // restores it before any claim is served.
            maintenance_triggers: Mutex::new(MaintenanceTriggerDeliveryLedger::new()),
        }
    }

    #[doc(hidden)]
    pub fn fence(&self) {
        self.flight.fence();
    }

    /// Observes the protected-control reserve through the gateway (issue #992).
    ///
    /// Diagnostic seam for the reserved-write path: normal admission never
    /// moves this counter, while protected cancellation consumes exactly one
    /// permit while held and returns it on release.
    #[doc(hidden)]
    pub fn available_control(&self) -> Result<usize, String> {
        self.service
            .lock()
            .map(|service| service.available_control())
            .map_err(|_| "Kernel service lock poisoned".to_owned())
    }

    #[doc(hidden)]
    pub fn is_fenced(&self) -> bool {
        self.flight.is_fenced()
    }

    #[doc(hidden)]
    pub async fn fence_and_drain(&self, timeout: Duration) -> Result<(), String> {
        self.flight.fence_and_drain(timeout).await
    }

    /// Refuses a mutating Store or ORS effect while this Kernel candidate is
    /// in `shadow_no_authority` (I14.16 step 4).
    ///
    /// Every mutating entry point calls this as its *first* gated step, before
    /// any ORS reservation, scope advance, or Store send. It exists because
    /// [`Self::apply`] and [`Self::apply_reserved`] do not reach
    /// `acquire_admission` until after their staging work, so a
    /// `shadow_no_authority` candidate could otherwise write ORS rows before
    /// the lease gate refused the send. Read-only inspection
    /// ([`Self::execute_named`], [`Self::receipt`], [`Self::recovery`]) is
    /// deliberately not gated: I14.16 step 3 permits immutable/read-only
    /// inspection and compatibility checks in this phase.
    ///
    /// The refusal is the crate's existing [`KernelServiceError::AdmissionClosed`]
    /// carrying the exact current state, flattened to this module's `String`
    /// error the way every other gateway refusal is.
    ///
    /// Finite shadow-denial map, gateway half (issue #1953, map item 2 —
    /// classified by actual effects, not method names):
    ///
    /// Named `refuse_shadow_mutation` gates: [`Self::apply`],
    /// [`Self::apply_reserved`], [`Self::cancel_reserved`] (ORS-reservation
    /// cancellation is an ORS mutation), [`Self::reconcile_staged_writes`]
    /// (startup reconciliation mutates staged envelopes),
    /// [`Self::reconcile_reserved`] (exact-receipt reconciliation finalizes
    /// ORS reservation scopes), [`Self::initialize_genesis`] (Store write),
    /// [`Self::dreamer_job`] (ledger mutations; the permitted `Status` read
    /// stays available through the operation-effect classification),
    /// [`Self::backup_restore_batch`] (Store restore write),
    /// [`Self::execute_user_automation_operation`] and
    /// [`Self::due_wake_execution_join`] (their Store commits travel through
    /// the borrowed client, which bypasses [`Self::apply`], so the entries
    /// carry the named check with their own typed refusal).
    ///
    /// Intentionally available in shadow (no Store/ORS write, no issuance):
    /// `recovery`, `receipt`, `execute_named`/`execute_named_with_error`,
    /// the `read_user_automation_*` reads, `validate_user_automation_request`
    /// (pure validation), `project_reserved_submission` (bounded local
    /// projection only, never ORS or network work),
    /// `maintenance_trigger_pending_page`,
    /// `maintenance_trigger_replacement_pending_set`,
    /// `replay_maintenance_trigger_after_crash`, and
    /// `recover_maintenance_trigger_commit` (ledger reads whose sessions
    /// cannot be bound in shadow anyway),
    /// `restore_maintenance_trigger_ledger` (in-memory restore of already
    /// persisted rows; inert while shadow because every serving path binds a
    /// `Ready`-only session), `drain_reserved` (flight fence plus an ORS
    /// recovery-page read; shutdown handling, no reservation write),
    /// `validation_snapshot`, `health`, `paused_ordering_scopes`,
    /// `available_control`, `is_fenced`, `fence`, and `fence_and_drain`
    /// (observation and lifecycle fences, never authority effects).
    ///
    /// The mutating maintenance-trigger entries (`admit`, `claim`,
    /// `release_expired`, `record_decision`, `acknowledge`,
    /// `mark_ambiguous`, `revoke_consumer`, `expire`, `supersede`, `gap`)
    /// all bind their session through the one
    /// `AuthenticatedMaintenanceTriggerSession::bind` choke point, which
    /// requires `Ready` and carries the named service-side check, so no
    /// trigger claim, decision, or revocation can issue from a shadow.
    fn refuse_shadow_mutation(&self) -> Result<(), String> {
        let service = self
            .service
            .lock()
            .map_err(|_| "Kernel service lock poisoned".to_owned())?;
        service
            .admit_shadow_effect()
            .map_err(|error| error.to_string())
    }

    /// Applies one already prepared transition after fixed Kernel admission.
    ///
    /// The refusal is the typed [`StoreApplyRefusal`] rather than a flattened
    /// string, so the I5.19 admission decision this route actually took reaches
    /// the caller as typed evidence instead of being erased into prose: the
    /// `not_accepted` decision keeps its submission id, reason codes, and next
    /// allowed action, while every pre-existing gateway refusal keeps the exact
    /// text it has always returned.
    pub async fn apply(
        &self,
        context: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreApplyRefusal> {
        let _flight = self
            .flight
            .enter()
            .map_err(StoreApplyRefusal::GatewayRefusal)?;
        if self.is_fenced() {
            return Err(StoreApplyRefusal::GatewayRefusal(
                "canonical-store gateway is fenced for rebind".to_owned(),
            ));
        }
        self.refuse_shadow_mutation()
            .map_err(StoreApplyRefusal::GatewayRefusal)?;
        // The durable route read below is an ORS transaction, so it is taken
        // before the Kernel service lock rather than inside it: the service
        // lock is never held across ORS work anywhere in this module.
        self.require_active_store_generation()
            .map_err(|error| StoreApplyRefusal::GatewayRefusal(error.to_string()))?;
        // 1927: authenticate the caller before plan admission (I5.6 step 1),
        // mirroring `apply_reserved_admission`.
        if context.source_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(StoreApplyRefusal::GatewayRefusal(
                "transition caller is not the active daemon".to_owned(),
            ));
        }
        // I5.19: `admit_prepared_transition` is the single decision point for
        // this route. It reports the typed `not_accepted` or
        // `resolved_existing` decision as an `Err` and returns nothing on its
        // accepted arm, so a refused submission can never reach the store send
        // below and no state re-check is owed here. The accepted arm carries no
        // `staged` value: this is the I5.6 steps 1-12 boundary, and the I5.19
        // `staged` state asserts an ORS acceptance that happens at step 13, so
        // there is deliberately nothing here for this route to re-inspect and
        // nothing that could be read as one. A gate that later resolves an
        // existing receipt must refuse inside `admit_prepared_transition` (it
        // has no existing-receipt lookup today) rather than return that
        // decision as a success this route would then have to re-inspect.
        admit_prepared_transition(
            context,
            &transition,
            &expected_revision_heads,
            &expected_ordering_heads,
        )?;

        let lease = {
            let service = self.service.lock().map_err(|_| {
                StoreApplyRefusal::GatewayRefusal("Kernel service lock poisoned".to_owned())
            })?;
            if service.generation_fenced() {
                return Err(StoreApplyRefusal::GatewayRefusal(
                    "Kernel generation is fenced".to_owned(),
                ));
            }
            if self.is_fenced() {
                return Err(StoreApplyRefusal::GatewayRefusal(
                    "canonical-store gateway is fenced for rebind".to_owned(),
                ));
            }
            // Canonical route/epoch gate (Implements #64): route currency is
            // the exact-tuple match between the composition-bound route epoch
            // and live authority — never a scalar `sequence.get()` coercion.
            // Cross-lineage same-sequence routes never authorize: the route
            // carries its own lineage. The durable active-generation gate ran
            // above, before this lock.
            let live_epoch = service.authority_epoch();
            if !self.route.authority_epoch().is_same_authority(&live_epoch)
                || self.route.active_generation() != transition.state_fence.resource_generation
            {
                return Err(StoreApplyRefusal::GatewayRefusal(
                    "canonical-store route is outside the active Kernel generation".to_owned(),
                ));
            }
            let lease = service
                .acquire_admission()
                .map_err(|error| StoreApplyRefusal::GatewayRefusal(error.to_string()))?;
            // Slices A+B (#65): `apply_prepared` is normal Store work
            // (`CANONICAL_WRITE` maps to `NORMAL_WORKLOAD`). The normal lease
            // above holds a Slice A typed normal permit from the disjoint
            // normal partition, so this path never consumes the protected
            // reserve. Protected cancellation / fencing / health / drain /
            // problem / incident / recovery stays on
            // `acquire_protected_control` / `issue_control_receipt`.
            if !lease
                .authority_epoch()
                .is_same_authority(&transition.state_fence.authority_epoch)
            {
                return Err(StoreApplyRefusal::GatewayRefusal(
                    "canonical-store route authority epoch is stale".to_owned(),
                ));
            }
            lease
        };
        if self.is_fenced() {
            return Err(StoreApplyRefusal::GatewayRefusal(
                "canonical-store gateway is fenced for rebind".to_owned(),
            ));
        }

        let identity = transition.identity.clone();
        let ordering_scopes: Vec<String> = transition
            .ordering_scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect();
        // I14.21 (#1690): the single commit runs through unknown-commit
        // recovery. The closures below borrow the admitted values and clone
        // per attempt, so the same-identity retry resends the identical
        // admitted transition and never a rebuilt one.
        let send = || {
            self.store.apply_prepared(
                context,
                transition.clone(),
                expected_revision_heads.clone(),
                expected_ordering_heads.clone(),
            )
        };
        let query = || {
            self.store.receipt_exact(
                identity.operation_id.clone(),
                identity.canonical_request_hash.as_str(),
            )
        };
        let result = recover_commit(
            self.commit_ors.as_deref(),
            &self.paused_scopes,
            &identity,
            &ordering_scopes,
            send,
            query,
        )
        .await
        .map_err(|error| StoreApplyRefusal::GatewayRefusal(error.to_string()));
        drop(lease);
        result
    }

    /// Lists the currently paused ordering scopes with the idempotency key
    /// pausing each, together with the checked coverage that produced them
    /// (I14.21, issue #1690; issue #2763).
    ///
    /// The return type is the checked view, not a `Vec`: a failed or absent
    /// ORS read now surfaces as `PauseScopeView::limitation` with
    /// `observation` unavailable, so a diagnostic consumer reports a bounded
    /// known subset labelled unavailable and never "zero paused". Every open
    /// record covering a scope is kept, so two operations pausing one scope
    /// both appear.
    pub fn paused_ordering_scopes(&self) -> PauseScopeView {
        crate::commit_recovery::paused_ordering_scope_view(
            &self.paused_scopes,
            self.commit_ors.as_deref(),
        )
    }

    /// Applies one already prepared transition through a durable ORS
    /// reservation and the exact #990/#991 reserved-write contract (issue
    /// #992).
    ///
    /// Admission mirrors [`Self::apply`] (flight, fence, validation, active
    /// daemon caller, fence equality, canonical request-hash recompute, live
    /// route/epoch binding) with one addition: the composition-bound ORS must
    /// be present. A missing ORS or a backend without reserved-write support
    /// fails with an explicit unsupported error; there is deliberately no
    /// fallback to unreserved `Apply`, and legacy/reference use stays on
    /// [`Self::apply`].
    ///
    /// Lifecycle ordering (no orphaned tokens):
    ///
    /// ```text
    /// reserve (no lease held) -> eligible (no lease held) ->
    /// normal admission lease -> revalidate generation/fence ->
    /// project -> single send ->
    ///   Ok(Committed)   -> begin_execute_after_send -> reconcile -> Finalized
    ///   Ok(not-applied) -> begin_execute_after_send -> reconcile -> Released (+gap)
    ///   Err(unknown)    -> begin_execute_after_send -> mark_unknown -> Reconciling
    ///   Err(refused)    -> release the still-Eligible token
    /// ```
    ///
    /// Queued work holds no admission lease, Kernel lock, provider permit, or
    /// protected-control resource while awaiting eligibility: the lease is
    /// acquired only for the bounded send window, and the service lock is
    /// never held across ORS or network work. Cancellation after execution
    /// starts is rejected by the owner (see [`Self::cancel_reserved`]);
    /// `begin_execute_after_send` runs only after the single send resolves
    /// with the typed [`ResolvedSendOutcome`] evidence, so a refused
    /// backend never strands an `Executing` reservation without receipt
    /// evidence.
    pub async fn apply_reserved(
        &self,
        context: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        seed: ReservationSeed,
    ) -> Result<WriteReceipt, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        // I14.16 step 4: the shadow refusal precedes the ORS `stage_and_reserve`
        // write below. The normal admission lease is only acquired later, at
        // the bounded send window, so without this gate a
        // `shadow_no_authority` candidate would stage and reserve ORS rows
        // before the lease gate refused the Store send.
        self.refuse_shadow_mutation()?;
        apply_reserved_admission(context, &transition)?;
        {
            let view = CanonicalRequestView::from_apply(
                context,
                &transition,
                &expected_revision_heads,
                &expected_ordering_heads,
            );
            verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
                .map_err(|error| error.to_string())?;
        }
        let commit_ors = self.commit_ors.clone().ok_or_else(|| {
            "reserved writes require the composition-bound ORS; refusing without unreserved Apply fallback"
                .to_owned()
        })?;
        let owner = self.bind_reservation_owner(&commit_ors, context, &transition)?;
        // Reservation and eligibility run without any admission lease: queued
        // normal work holds no provider permit, Kernel lock, or
        // protected-control resource while awaiting a predecessor (I14.3).
        let sealed = reserve_for_transition(
            &owner,
            &seed,
            context,
            &transition,
            &expected_revision_heads,
            &expected_ordering_heads,
        )
        .map_err(|error| error.to_string())?;
        ensure_eligible(&owner, &sealed.token).map_err(|error| error.to_string())?;
        // Bounded send window: one normal admission lease, mirroring `apply`
        // (Slices A+B, #65). Cancellation and reconciliation stay on the
        // protected reserve and never consume this lease.
        let lease = self.acquire_send_lease(&transition)?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        let operation_id = transition.identity.operation_id.as_str().to_owned();
        // The single authenticated send goes through the Kernel-visible
        // reserved submission (issue #2031): the exact `#990` projection plus
        // the boundary validation, so the production path and the tested
        // projection share one constructor and one serializer.
        let submission = ReservedSubmission::from_sealed(
            &sealed,
            context,
            &transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .map_err(|error| error.to_string())?;
        let outcome = self
            .store
            .apply_reserved_write(submission.into_request())
            .await;
        match outcome {
            Ok(receipt) => {
                // Execution starts only now that the single send resolved: a
                // refused backend can never strand an `Executing` reservation.
                // A stale epoch here preserves the committed operation id for
                // exact-receipt recovery under the current epoch instead of
                // finalizing under the wrong one.
                let post_send = ResolvedSendOutcome::after_resolved_send(&sealed.token);
                begin_execute_after_send(&owner, &sealed.token, &post_send).map_err(|error| {
                    format!(
                        "reserved write committed for operation {operation_id} but the reservation cannot execute ({error}); reconcile by exact receipt once the writer epoch is current"
                    )
                })?;
                let reconciliation = reconcile_receipt(&sealed.token, &receipt)
                    .map_err(|error| error.to_string())?;
                finalize_reservation(&owner, &reconciliation).map_err(|error| error.to_string())?;
                drop(lease);
                Ok(receipt)
            }
            Err(StoreError::MissingReceiptEnvelope) => {
                // Still unknown after possible submission: preserve
                // `Executing`/`Reconciling` identity until exact Store receipt
                // reconciliation. Never a blind retry, never a release.
                let post_send = ResolvedSendOutcome::after_resolved_send(&sealed.token);
                begin_execute_after_send(&owner, &sealed.token, &post_send)
                    .map_err(|error| error.to_string())?;
                mark_unknown_outcome(&owner, &sealed.token).map_err(|error| error.to_string())?;
                drop(lease);
                Err(format!(
                    "reserved write outcome unknown for operation {operation_id}: reconciling; reconcile by exact Store receipt"
                ))
            }
            Err(error) => {
                // Deterministic refusal: the Store owner proves no effect, so
                // the still-`Eligible` token releases cleanly and nothing
                // orphans.
                let refusal =
                    refuse_determinate_reserved_write(&owner, &sealed.token, &error, &operation_id);
                drop(lease);
                Err(refusal)
            }
        }
    }

    /// Binds the reservation owner from the live composition fence tuple.
    ///
    /// Staging step shared by the reserved-write entry points so each stays a
    /// composition of audited gates: the service lock below is short and is
    /// never held across ORS or network work.
    fn bind_reservation_owner(
        &self,
        commit_ors: &Arc<RedbRecoveryStore>,
        context: &RequestMetadata,
        transition: &PreparedTransition,
    ) -> Result<CompositionReservation, String> {
        // The generation the route is checked against is the admitted
        // transition's own fence, so the equality is re-asserted here rather
        // than inherited from a caller: the shared helper below then reads the
        // same tuple the transition was admitted under.
        if transition.state_fence != context.state_fence {
            return Err("transition state fence does not match request metadata".to_owned());
        }
        self.bind_reservation_owner_for_fence(commit_ors, &context.state_fence)
    }

    /// Binds the reservation owner from one already-validated live fence.
    ///
    /// Same gates as [`Self::bind_reservation_owner`] for the entry points that
    /// present a fence instead of an admitted transition: the presented fence
    /// must be the same-generation, same-authority tuple the active route and
    /// the live service epoch both name. A stale or foreign fence never reaches
    /// ORS, so a recovery pass can never read or close another generation's
    /// reservation.
    fn bind_reservation_owner_for_fence(
        &self,
        commit_ors: &Arc<RedbRecoveryStore>,
        fence: &StateFence,
    ) -> Result<CompositionReservation, String> {
        // The durable route read below is an ORS transaction, so it is taken
        // before the Kernel service lock rather than inside it: the service
        // lock is never held across ORS work anywhere in this module.
        self.require_active_store_generation()
            .map_err(|error| error.to_string())?;
        let service = self
            .service
            .lock()
            .map_err(|_| "Kernel service lock poisoned".to_owned())?;
        if service.generation_fenced() {
            return Err("Kernel generation is fenced".to_owned());
        }
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        let live_epoch = service.authority_epoch();
        if !self.route.authority_epoch().is_same_authority(&live_epoch)
            || self.route.active_generation() != fence.resource_generation
            || !live_epoch.is_same_authority(&fence.authority_epoch)
        {
            return Err("canonical-store route is outside the active Kernel generation".to_owned());
        }
        let writer_epoch =
            writer_epoch_for_fence_from_epoch(&fence.authority_epoch).map_err(|e| e.to_string())?;
        drop(service);
        CompositionReservation::bind(Arc::clone(commit_ors), writer_epoch)
            .map_err(|error| error.to_string())
    }

    /// Acquires the one normal admission lease for the bounded send window.
    ///
    /// Staging step mirroring `apply`: the lease draws from the normal
    /// partition only, so normal saturation backpressures here while the
    /// protected reserve stays untouched.
    fn acquire_send_lease(
        &self,
        transition: &PreparedTransition,
    ) -> Result<crate::AdmissionLease, String> {
        let service = self
            .service
            .lock()
            .map_err(|_| "Kernel service lock poisoned".to_owned())?;
        if service.generation_fenced() {
            return Err("Kernel generation is fenced".to_owned());
        }
        let lease = service
            .acquire_admission()
            .map_err(|error| error.to_string())?;
        if !lease
            .authority_epoch()
            .is_same_authority(&transition.state_fence.authority_epoch)
        {
            return Err("canonical-store route authority epoch is stale".to_owned());
        }
        Ok(lease)
    }

    /// Arms the production fault hook on the bound store client (issue #2030
    /// follow-up binding for 994/11-12).
    ///
    /// Read-through delegation only: no dispatch, admission, or reservation
    /// behavior changes. Harness-gated like `arm_fault` itself — only `test`
    /// or `--features test-support` builds can construct the token, so
    /// production callers cannot arm faults. The 994 follow-up cases arm the
    /// hook on the proven kernel route, then drive `apply_reserved` through
    /// the existing owner-bound path.
    pub fn arm_store_fault(&self, harness: &StoreClientFaultHarness, fault: StoreClientFault) {
        self.store.arm_fault(harness, fault);
    }

    /// Cancels one reserved write before possible submission (issue #992).
    ///
    /// Cancellation is protected-control work (I14.3): it holds one
    /// `cancellation` protected lease across the bounded ORS write only, so a
    /// normal queue can neither consume the cancellation reserve nor be
    /// consumed by it. Only `Reserved`/`Eligible` tokens release; from
    /// `Executing`/`Reconciling` the owner rejects with `InvalidTransition`
    /// and identity is preserved until exact receipt reconciliation.
    /// Cancellation, timeout, or socket replacement can never finalize or
    /// free such a reservation.
    pub fn cancel_reserved(
        &self,
        token: &WriterReservationToken,
    ) -> Result<ReservationRecord, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        // I14.16 step 4: cancelling a reservation is an ORS mutation, so a
        // `shadow_no_authority` candidate refuses it before the owner and
        // protected lease are taken below.
        self.refuse_shadow_mutation()?;
        let commit_ors = self.commit_ors.clone().ok_or_else(|| {
            "reserved writes require the composition-bound ORS; nothing to cancel".to_owned()
        })?;
        // The protected lease is acquired inside the lock scope and returned
        // alongside the owner, so it stays alive across the bounded ORS write
        // below while the service lock itself is released first.
        let (owner, _lease) = {
            let service = self
                .service
                .lock()
                .map_err(|_| "Kernel service lock poisoned".to_owned())?;
            if service.generation_fenced() {
                return Err("Kernel generation is fenced".to_owned());
            }
            let lease = service
                .acquire_protected_control("cancellation")
                .map_err(|error| error.to_string())?;
            let live_epoch = lease.authority_epoch();
            let writer_epoch =
                crate::store_write_reservation::writer_epoch_for_fence_from_epoch(&live_epoch)
                    .map_err(|error| error.to_string())?;
            let owner = CompositionReservation::bind(commit_ors, writer_epoch)
                .map_err(|error| error.to_string())?;

            (owner, lease)
        };
        cancel_before_send(&owner, token).map_err(|error| error.to_string())
    }

    /// Reconciles one reserved write by its exact admitted request and
    /// observed receipt (issue #992).
    ///
    /// Delegates to the exact-receipt reconciliation path shared with the
    /// unknown-commit recovery surface; see
    /// `store_receipt_gateway::reconcile_reserved`. Synchronous: every check
    /// below is a bounded local validation or ORS write, never a network
    /// wait, so reconciliation never holds the gateway across I/O.
    pub fn reconcile_reserved(
        &self,
        token: &WriterReservationToken,
        request: &ReservedWriteRequest,
        receipt: &WriteReceipt,
    ) -> Result<ReservationRecord, String> {
        // I14.16 step 4 (issue #1953, map item 2): exact-receipt
        // reconciliation finalizes ORS reservation scopes, so a
        // `shadow_no_authority` candidate refuses before the delegate runs.
        self.refuse_shadow_mutation()?;
        store_receipt_gateway::reconcile_reserved(self, token, request, receipt)
    }

    /// Projects one sealed reservation into a Kernel-visible reserved
    /// submission carrying the reserved capability (issue #2031).
    ///
    /// Runs the exact `#990` projection shared with [`Self::apply_reserved`]
    /// without sending: the returned submission is validated and ready for the
    /// single authenticated send. A fenced gateway refuses the projection, so
    /// no new submission is minted while migration exclusivity holds.
    /// Synchronous: projection is bounded local validation only, never ORS or
    /// network work.
    pub fn project_reserved_submission(
        &self,
        sealed: &crate::SealedReservation,
        context: &RequestMetadata,
        transition: &PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<ReservedSubmission, String> {
        if self.is_fenced() {
            return Err(
                "canonical-store gateway is fenced for rebind; refusing reserved projection"
                    .to_owned(),
            );
        }
        ReservedSubmission::from_sealed(
            sealed,
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .map_err(|error| error.to_string())
    }

    /// Drains reserved work before migration exclusivity (issue #992).
    ///
    /// Fences the gateway, waits out in-flight operations, then accounts for
    /// every unresolved reservation in the composition-bound ORS. An exact
    /// non-zero count fails with the honest pending count; a truncated
    /// recovery page fails with a distinct truncated-scan report whose shown
    /// count is explicitly incomplete: migration must reconcile first, and
    /// nothing is force-released to make the count zero. Without a bound ORS
    /// this degrades to the flight fence only, and says so.
    pub async fn drain_reserved(&self, timeout: Duration) -> Result<(), String> {
        self.flight.fence_and_drain(timeout).await?;
        let Some(commit_ors) = self.commit_ors.as_ref() else {
            return Ok(());
        };
        let live_epoch = {
            let service = self
                .service
                .lock()
                .map_err(|_| "Kernel service lock poisoned".to_owned())?;
            service.authority_epoch()
        };
        let writer_epoch =
            writer_epoch_for_fence_from_epoch(&live_epoch).map_err(|error| error.to_string())?;
        let owner = CompositionReservation::bind(Arc::clone(commit_ors), writer_epoch)
            .map_err(|error| error.to_string())?;
        let page = crate::store_write_reservation::recovery_page(&owner, 256)
            .map_err(|error| error.to_string())?;
        let pending = page
            .records
            .iter()
            .filter(|record| {
                !matches!(
                    record.state,
                    eliot_ors::ReservationState::Finalized | eliot_ors::ReservationState::Released
                )
            })
            .count();
        if page.next_after_order.is_some() {
            return Err(format!(
                "migration drain blocked: recovery scan truncated after {pending} pending reservations in the first page; full unresolved count unknown; reconcile by exact receipt before exclusivity (no forced release)"
            ));
        }
        if pending > 0 {
            return Err(format!(
                "migration drain blocked: {pending} unresolved reservations remain; reconcile by exact receipt before exclusivity (no forced release)"
            ));
        }
        Ok(())
    }

    /// Enumerates and reconciles the durable staged write envelopes in the
    /// composition-bound ORS (issue #1925, I1.11 step 6, I5.2/I5.6).
    ///
    /// This is the recovery owner for the same envelope
    /// [`Self::apply_reserved`] stages, not a second scan vocabulary: it runs
    /// the ORS pending-reservation reconciliation by exact operation identity,
    /// revalidates every reported staged envelope through the owner, and
    /// reports the durable Recovery Problems a corrupted or unreadable staged
    /// payload leaves behind. Nothing is decoded, defaulted, force-released, or
    /// deleted, and no unresolved operation is retried.
    ///
    /// Gates: the flight counter, the rebind fence, the I14.16 step 4 shadow
    /// refusal (reconciliation is an ORS mutation), and the same
    /// generation/route/authority binding the reserved write uses — a fence from
    /// another generation or authority never reaches ORS. A composition with no
    /// bound ORS refuses explicitly instead of reporting an empty clean scan.
    ///
    /// `limit` is the whole-scan ceiling for the reservation scan and the
    /// retained-problem listing.
    pub async fn reconcile_staged_writes(
        &self,
        fence: &StateFence,
        limit: u16,
    ) -> Result<StagedWriteRecovery, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        self.refuse_shadow_mutation()?;
        let commit_ors = self.commit_ors.clone().ok_or_else(|| {
            "staged write recovery requires the composition-bound ORS; refusing to report an empty reconciliation"
                .to_owned()
        })?;
        let owner = self.bind_reservation_owner_for_fence(&commit_ors, fence)?;
        crate::store_write_reservation::reconcile_staged_writes_at_startup(
            &owner, fence, self, limit,
        )
        .await
        .map_err(|error| error.to_string())
    }

    /// Locks the Kernel service for one maintenance-trigger owner step.
    ///
    /// Guards are always taken service-first, ledger-second, and no guard is
    /// ever held across ORS or Store IO: IO runs guard-free before the
    /// transition, then the transition runs under both guards.
    fn lock_maintenance_service(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, KernelService>, MaintenanceTriggerDeliveryError> {
        self.service.lock().map_err(|_| {
            MaintenanceTriggerDeliveryError::OwnerUnavailable(
                "Kernel service lock poisoned".to_owned(),
            )
        })
    }

    /// Locks the owned delivery ledger; always after the service guard.
    fn lock_maintenance_ledger(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, MaintenanceTriggerDeliveryLedger>,
        MaintenanceTriggerDeliveryError,
    > {
        self.maintenance_triggers.lock().map_err(|_| {
            MaintenanceTriggerDeliveryError::OwnerUnavailable(
                "maintenance trigger ledger lock poisoned".to_owned(),
            )
        })
    }

    /// Binds one maintenance-trigger session from live Kernel authority.
    ///
    /// The principal reference comes from the authenticated composition
    /// boundary, never from a request DTO. The guard is released before any
    /// IO the caller performs afterwards; the transition re-proves liveness
    /// under a fresh guard.
    fn bind_maintenance_session(
        &self,
        principal_ref: &str,
    ) -> Result<AuthenticatedMaintenanceTriggerSession, MaintenanceTriggerDeliveryError> {
        let service = self.lock_maintenance_service()?;
        AuthenticatedMaintenanceTriggerSession::bind(&service, principal_ref)
            .map_err(MaintenanceTriggerDeliveryError::Service)
    }

    /// Admits one retained maintenance trigger into the owned delivery ledger
    /// (issue #1694).
    ///
    /// The complete opaque input must already be staged through the ORS
    /// owner: staging is proven with no owner guard held (the service lock
    /// is never held across ORS work anywhere in this module), then the
    /// session is bound, liveness re-proved, and the row admitted under both
    /// guards. The returned rows are the ledger's durable snapshot after
    /// this transition. `handle_maintenance_trigger_intake` stays the seam
    /// for guard-free front-door callers (STITCH): this owner entry proves
    /// staging first so no guard is ever held across the ORS read.
    ///
    /// # Live status
    ///
    /// This entry is the one **live** member of the maintenance-trigger owner
    /// surface; the other fourteen entries in this cluster have no production
    /// caller. It has two code callers, and only one of them is live: the
    /// `eliotd` intake leg in `bins/eliotd/src/maintenance_dispatch.rs` is
    /// itself uncalled, but the Kernel front door reaches this entry
    /// independently through the `maintenance_trigger_intake` operation
    /// dispatched by `bins/eliot-kernel/src/daemon_request_dispatch.rs`, which
    /// runs under `main()` via `run_front_door_loop`.
    pub fn admit_maintenance_trigger(
        &self,
        principal_ref: &str,
        record: MaintenanceTriggerRecord,
    ) -> Result<
        (
            MaintenanceTriggerIntakeReceipt,
            Vec<MaintenanceTriggerDeliveryRow>,
        ),
        MaintenanceTriggerDeliveryError,
    > {
        let session = self.bind_maintenance_session(principal_ref)?;
        let commit_ors = self.commit_ors.clone().ok_or_else(|| {
            MaintenanceTriggerDeliveryError::StagingProof(OrsError::IntegrityProblem {
                record_type: "maintenance_trigger_delivery",
                reason: "maintenance trigger intake requires the composition-bound ORS".to_owned(),
            })
        })?;
        prove_maintenance_trigger_staging(
            &*commit_ors,
            &record.trigger_id,
            &record.payload.envelope_reference,
            &record.payload.payload_hash,
        )
        .map_err(MaintenanceTriggerDeliveryError::StagingProof)?;
        let service = self.lock_maintenance_service()?;
        session
            .service_context(&service)
            .map_err(MaintenanceTriggerDeliveryError::Service)?;
        let mut ledger = self.lock_maintenance_ledger()?;
        let receipt = ledger.admit_intake(record)?;
        Ok((receipt, ledger.durable_rows()))
    }

    /// Issues one finite fenced claim from the owned delivery ledger (issue
    /// #1694).
    ///
    /// Binds the session from live authority, then issues the claim bound to
    /// the current compatible daemon generation/session, trigger revision,
    /// and delivery identity through the existing ledger seam. The returned
    /// rows are the durable snapshot after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller. It is *transitively*
    /// dead rather than name-level dead, so a scan for call sites reports
    /// one: the single call is `claim_maintenance_trigger_for_daemon` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, whose own only caller,
    /// `redeliver_maintenance_trigger_after_timeout`, is itself uncalled.
    /// No live daemon claim loop issues a claim through this entry today.
    /// Whether a daemon claim loop is wired to it or the entry is retired is
    /// an owner decision, not a documentation one.
    pub fn claim_maintenance_trigger(
        &self,
        principal_ref: &str,
        request: MaintenanceTriggerClaimRequest,
    ) -> Result<
        (MaintenanceTriggerClaim, Vec<MaintenanceTriggerDeliveryRow>),
        MaintenanceTriggerDeliveryError,
    > {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        let claim = handle_maintenance_trigger_claim(&service, &session, &mut ledger, request)?;
        Ok((claim, ledger.durable_rows()))
    }

    /// Releases one expired claim back under the same trigger identity
    /// (issue #1694).
    ///
    /// A timed-out `Claimed` row returns to `Pending`; a `DecisionRecorded`
    /// row with a lapsed claim moves to `Reconciling` with its committed
    /// receipt preserved. Redelivery always needs a fresh finite claim,
    /// never a new trigger ID. The returned rows are the durable snapshot
    /// after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller. It is *transitively*
    /// dead rather than name-level dead, so a scan for call sites reports
    /// one: the single call is
    /// `redeliver_maintenance_trigger_after_timeout` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// Whether a timeout-redelivery loop is wired to it or the entry is
    /// retired is an owner decision, not a documentation one.
    pub fn release_expired_maintenance_trigger_claim(
        &self,
        principal_ref: &str,
        trigger_id: &str,
        now_unix_ms: u64,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_release_expired(
            &service,
            &session,
            &mut ledger,
            trigger_id,
            now_unix_ms,
        )?;
        Ok(ledger.durable_rows())
    }

    /// Enumerates one bounded pending page from the owned delivery ledger
    /// (issue #1694).
    ///
    /// A read: no ledger transition, so no rows snapshot. A reconnect
    /// resumes from its cursor and never resets progress to a guessed
    /// complete-empty set.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `collect_pending_maintenance_triggers` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is uncalled outright.
    /// Whether a pending-set collector is wired to it or the entry is retired
    /// is an owner decision, not a documentation one.
    pub fn maintenance_trigger_pending_page(
        &self,
        principal_ref: &str,
        continuation: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_pending_page(
            &service,
            &session,
            &ledger,
            continuation,
            now_unix_ms,
        )
    }

    /// Records one daemon decision into the owned delivery ledger against
    /// its committed named Store transaction (issue #1694).
    ///
    /// Were it reached, the authenticated daemon would submit its decision
    /// through the Governor `PreparedTransition` → Kernel → named Store
    /// transaction; that transaction's committed [`WriteReceipt`] is the
    /// durability the ledger row rides on. This owner entry re-reads the
    /// exact receipt through the existing Store client, requires `Committed`
    /// status, re-proves the canonical-bytes digest the decision receipt
    /// binds, and requires the receipt fence to match live service authority
    /// — an arbitrary receipt ID or transport `Ok(())` can never complete
    /// this transition. Only then is the decision recorded; the returned
    /// rows are the durable snapshot after the transition. A lost or
    /// ambiguous commit stays pending/reconciling through
    /// [`Self::mark_maintenance_trigger_commit_ambiguous`]: receipt absence
    /// here is never reported as proof of non-commit.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `record_committed_maintenance_decision` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// The first paragraph above is therefore conditional on reachability,
    /// not a report that a daemon decision currently travels this path. This
    /// is the strongest claim in the maintenance-trigger surface and it is
    /// not established by any live caller. The body, its receipt
    /// re-validation, and its fence check are unchanged; wiring or retiring
    /// the entry is an owner decision, not a documentation one.
    pub async fn record_maintenance_trigger_decision(
        &self,
        principal_ref: &str,
        trigger_id: &str,
        receipt: MaintenanceTriggerDecisionReceipt,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let _flight = self
            .flight
            .enter()
            .map_err(MaintenanceTriggerDeliveryError::OwnerUnavailable)?;
        receipt.validate()?;
        let session = self.bind_maintenance_session(principal_ref)?;
        let operation_id =
            OperationId::new(receipt.canonical_receipt_ref.clone()).map_err(|_| {
                MaintenanceTriggerDeliveryError::Protocol(ProtocolError::InvalidField {
                    field: "maintenance_trigger_decision_receipt.canonical_receipt_ref",
                    reason: "decision receipt names no well-formed canonical receipt",
                })
            })?;
        let stored = self.store.receipt(operation_id).await?;
        let stored = stored.ok_or(MaintenanceTriggerDeliveryError::Protocol(
            ProtocolError::InvalidField {
                field: "maintenance_trigger_decision_receipt.canonical_receipt_ref",
                reason: "no committed Store receipt answers this decision",
            },
        ))?;
        stored.validate()?;
        if stored.status != WriteReceiptStatus::Committed {
            return Err(MaintenanceTriggerDeliveryError::Protocol(
                ProtocolError::InvalidField {
                    field: "maintenance_trigger_decision_receipt.canonical_receipt_ref",
                    reason: "the bound Store transaction was not committed",
                },
            ));
        }
        let receipt_bytes = canonical_json_bytes(&stored)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if sha256_hex(&receipt_bytes) != receipt.receipt_digest {
            return Err(MaintenanceTriggerDeliveryError::Protocol(
                ProtocolError::InvalidField {
                    field: "maintenance_trigger_decision_receipt.receipt_digest",
                    reason: "the receipt digest does not bind this operation",
                },
            ));
        }
        let service = self.lock_maintenance_service()?;
        let context = session
            .service_context(&service)
            .map_err(MaintenanceTriggerDeliveryError::Service)?;
        if !stored
            .state_fence
            .authority_epoch
            .is_same_authority(&context.authority_epoch)
            || stored.state_fence.resource_generation.value() != context.generation
        {
            return Err(MaintenanceTriggerDeliveryError::Service(
                KernelServiceError::HandshakeMismatch {
                    field: "maintenance_trigger.fence",
                },
            ));
        }
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_decision(&service, &session, &mut ledger, trigger_id, receipt)?;
        Ok(ledger.durable_rows())
    }

    /// Acknowledges one delivery against the exact committed decision
    /// receipt (issue #1694).
    ///
    /// The ack must echo the live claim exactly and embed the committed
    /// receipt byte for byte; a stale consumer cannot ack after revocation.
    /// The returned rows are the durable snapshot after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `acknowledge_recovered_maintenance_commit` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// Whether a post-recovery acknowledgement path is wired to it or the
    /// entry is retired is an owner decision, not a documentation one.
    pub fn acknowledge_maintenance_trigger(
        &self,
        principal_ref: &str,
        ack: &MaintenanceTriggerAck,
        current_fence: &StateFence,
        now_unix_ms: u64,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_ack(
            &service,
            &session,
            &mut ledger,
            ack,
            current_fence,
            now_unix_ms,
        )?;
        Ok(ledger.durable_rows())
    }

    /// Replays one retained trigger after a pre-commit crash, without
    /// minting new state (issue #1694).
    ///
    /// A read: a caller would re-present the exact retained record to the
    /// evaluator under the same identity.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `recover_maintenance_trigger_handoff` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// The `A read:` paragraph describes what the entry would do if reached;
    /// no live path reaches it today. Whether a crash-recovery path is wired
    /// to it or the entry is retired is an owner decision, not a
    /// documentation one.
    pub fn replay_maintenance_trigger_after_crash(
        &self,
        principal_ref: &str,
        trigger_id: &str,
    ) -> Result<MaintenanceTriggerRecord, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let ledger = self.lock_maintenance_ledger()?;
        replay_maintenance_trigger_after_crash(&service, &session, &ledger, trigger_id)
    }

    /// Recovers one committed decision receipt after a post-commit crash
    /// (issue #1694).
    ///
    /// A read: a caller would acknowledge this exact receipt without a new
    /// job, recommendation, or wake.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `recover_maintenance_trigger_handoff` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// Note that this entry is the one the sibling
    /// `recover_maintenance_trigger_handoff` leg would use, so it shares that
    /// leg's disposition; it is not independently live. Whether a
    /// crash-recovery path is wired to it or the entry is retired is an owner
    /// decision, not a documentation one.
    pub fn recover_maintenance_trigger_commit(
        &self,
        principal_ref: &str,
        trigger_id: &str,
    ) -> Result<MaintenanceTriggerDecisionReceipt, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let ledger = self.lock_maintenance_ledger()?;
        recover_maintenance_trigger_commit(&service, &session, &ledger, trigger_id)
    }

    /// Marks one lost or ambiguous commit as reconciling (issue #1694).
    ///
    /// Receipt absence during an outage is not proof of non-commit: the
    /// trigger stays open, gains an `AmbiguousCommit` gap record, and must
    /// be reconciled by receipt lookup before any further effect. The
    /// returned rows are the durable snapshot after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `mark_maintenance_trigger_commit_ambiguous_after_loss` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// Because the sibling [`Self::record_maintenance_trigger_decision`] entry
    /// that cross-references this one is also uncallered, the ambiguous-commit
    /// reconciliation this describes is not currently reachable at all.
    /// Whether that reconciliation is wired or the entry is retired is an
    /// owner decision, not a documentation one.
    pub fn mark_maintenance_trigger_commit_ambiguous(
        &self,
        principal_ref: &str,
        trigger_id: &str,
        now_unix_ms: u64,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_mark_ambiguous(
            &service,
            &session,
            &mut ledger,
            trigger_id,
            now_unix_ms,
        )?;
        Ok(ledger.durable_rows())
    }

    /// Revokes one daemon generation/session's trigger-consumer authority
    /// (issue #1694).
    ///
    /// Pending claims return under the same identity for the replacement
    /// generation, committed rows move to `Reconciling` with receipts
    /// preserved, and every later old-generation claim or ack fails. The
    /// returned rows are the durable snapshot after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller. It is *transitively*
    /// dead rather than name-level dead, so a scan for call sites reports
    /// one: the single call is
    /// `revoke_lost_daemon_consumer_for_replacement` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, whose own only caller,
    /// `recover_replacement_generation`, is itself uncalled. The revocation
    /// this describes therefore does not currently occur on any live path.
    /// Whether a daemon generation-replacement path is wired to it or the
    /// entry is retired is an owner decision, not a documentation one.
    pub fn revoke_maintenance_trigger_consumer(
        &self,
        principal_ref: &str,
        revocation: MaintenanceTriggerRevocation,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_revocation(&service, &session, &mut ledger, revocation)?;
        Ok(ledger.durable_rows())
    }

    /// Surfaces the bounded pending set to a replacement generation (issue
    /// #1694).
    ///
    /// A read: were it reached, then after replacement authentication plus the
    /// required mirror recovery the replacement would see the bounded pending
    /// set before reconciliation could be claimed complete. Ordinary pending
    /// debt acquires no runtime lease here.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller. It is *transitively*
    /// dead rather than name-level dead, so a scan for call sites reports
    /// one: the single call is `surface_replacement_pending_set` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, whose own only caller,
    /// `recover_replacement_generation`, is itself uncalled. No replacement
    /// generation currently enumerates this pending set. Whether a
    /// generation-replacement path is wired to it or the entry is retired is
    /// an owner decision, not a documentation one.
    pub fn maintenance_trigger_replacement_pending_set(
        &self,
        principal_ref: &str,
        continuation: Option<&str>,
        mirror_recovered: bool,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_replacement_pending_set(
            &service,
            &session,
            &ledger,
            continuation,
            mirror_recovered,
            now_unix_ms,
        )
    }

    /// Records terminal expiry for a past-window trigger (issue #1694).
    ///
    /// Expired eligibility blocks stale execution but never deletes the row,
    /// its record, or its evidence locators. The returned rows are the
    /// durable snapshot after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `expire_inapplicable_maintenance_trigger` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// No live expiry path records terminal expiry through this entry.
    /// Whether one is wired or the entry is retired is an owner decision,
    /// not a documentation one.
    pub fn expire_maintenance_trigger(
        &self,
        principal_ref: &str,
        trigger_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_expiry(
            &service,
            &session,
            &mut ledger,
            trigger_id,
            reason,
            now_unix_ms,
        )?;
        Ok(ledger.durable_rows())
    }

    /// Records supersession by an explicitly linked successor trigger
    /// (issue #1694).
    ///
    /// The successor is named, both rows stay readable, and materially new
    /// evidence arrives as a new trigger rather than an overwrite. The
    /// returned rows are the durable snapshot after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `supersede_maintenance_trigger_with_successor` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// No live path supersedes a trigger through this entry. Whether one is
    /// wired or the entry is retired is an owner decision, not a
    /// documentation one.
    pub fn supersede_maintenance_trigger(
        &self,
        principal_ref: &str,
        trigger_id: &str,
        successor_trigger_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_supersession(
            &service,
            &session,
            &mut ledger,
            trigger_id,
            successor_trigger_id,
            reason,
            now_unix_ms,
        )?;
        Ok(ledger.durable_rows())
    }

    /// Records a visible recovery gap for unrepairable damage (issue #1694).
    ///
    /// Missing keys, corrupt payloads, inaccessible sources, and incomplete
    /// enumeration produce this record — never a plaintext fallback and
    /// never silent deletion. The returned rows are the durable snapshot
    /// after this transition.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller: the single call is
    /// `record_maintenance_trigger_damage` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// Because no live path records a gap here either, a maintenance-trigger
    /// damage event is currently neither recorded nor recoverable through
    /// this surface. Whether a damage recorder is wired or the entry is
    /// retired is an owner decision, not a documentation one.
    pub fn record_maintenance_trigger_gap(
        &self,
        principal_ref: &str,
        trigger_id: &str,
        kind: MaintenanceTriggerGapKind,
        detail: &str,
        now_unix_ms: u64,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let session = self.bind_maintenance_session(principal_ref)?;
        let service = self.lock_maintenance_service()?;
        let mut ledger = self.lock_maintenance_ledger()?;
        handle_maintenance_trigger_gap(
            &service,
            &session,
            &mut ledger,
            trigger_id,
            kind,
            detail,
            now_unix_ms,
        )?;
        Ok(ledger.durable_rows())
    }

    /// Restores the owned delivery ledger from previously persisted durable
    /// rows (issue #1694).
    ///
    /// Were it reached, it would run once at startup before any claim is
    /// served: refuses when the owner already holds rows, then every row is
    /// revalidated through the existing validators before entering the
    /// ledger — a damaged row fails the restore instead of entering as a
    /// guessed-complete entry. The rows source is the startup composition's
    /// read-back of the persisted rows through the Store-lane rows backend
    /// (STITCH): this entry owns the restore, not the read-back. The
    /// returned rows are the restored durable snapshot.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller. It is *transitively*
    /// dead rather than name-level dead, so a scan for call sites reports
    /// one: the single call is
    /// `restore_maintenance_trigger_ledger_at_startup` in
    /// `bins/eliotd/src/maintenance_dispatch.rs`, which is itself uncalled.
    /// The sentence above about running "once at startup" therefore describes
    /// an intended startup order, not observed behaviour: no startup path
    /// calls this entry, so the ledger is never restored from persisted rows.
    /// The body is unchanged and still correct if reached; whether a startup
    /// composition is wired to it or the entry is retired is an owner
    /// decision, not a documentation one.
    pub fn restore_maintenance_trigger_ledger(
        &self,
        rows: Vec<MaintenanceTriggerDeliveryRow>,
    ) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerDeliveryError> {
        let mut ledger = self.lock_maintenance_ledger()?;
        if !ledger.durable_rows().is_empty() {
            return Err(MaintenanceTriggerDeliveryError::Protocol(
                ProtocolError::InvalidField {
                    field: "maintenance_trigger_delivery.ledger",
                    reason: "restore runs once at startup before any claim is served",
                },
            ));
        }
        ledger.restore_rows(rows)?;
        Ok(ledger.durable_rows())
    }

    /// Reads one bounded, opaque Store recovery snapshot through the active
    /// Kernel generation route. The gateway validates only Store-owned shape
    /// and fencing; Governor remains the semantic owner of payload decoding.
    pub async fn recovery(
        &self,
        request: StoreRecoveryRequest,
    ) -> Result<StoreRecoverySnapshot, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        request.validate().map_err(|error| error.to_string())?;
        self.validate_active_route(&request.state_fence)?;
        let snapshot = self
            .store
            .recovery(request.clone())
            .await
            .map_err(|error| error.to_string())?;
        snapshot.validate().map_err(|error| error.to_string())?;
        if snapshot.state_fence != request.state_fence {
            return Err("Store recovery snapshot fence does not match request".to_owned());
        }
        Ok(snapshot)
    }

    /// Reads one Store receipt by exact operation identity through the active
    /// Kernel generation route.
    pub async fn receipt(
        &self,
        state_fence: &StateFence,
        operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, String> {
        store_receipt_gateway::receipt(self, state_fence, operation_id).await
    }

    /// Executes one closed named read through the active Kernel generation
    /// route and returns the Store-owned response unchanged.
    ///
    /// The gateway validates only Store-owned shape and fencing
    /// (`NamedReadRequest::validate`, the exact route mirror, then
    /// `NamedReadResponse::validate` plus operation/fence match against the
    /// admitted request); Governor remains the semantic owner of payload
    /// decoding. Raw query strings are impossible by construction: only the
    /// closed [`eliot_store_api::NamedReadOperation`] catalogue crosses this
    /// boundary. T11.1 activates `GetEvidencePack`; T11.2 additionally
    /// activates `GetCurrentEpistemicPosition`. No allowlist lives
    /// here because catalogue membership stays owned by the Store adapters.
    pub async fn execute_named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, String> {
        self.require_active_store_generation()
            .map_err(|error| error.to_string())?;
        execute_named_via(
            &self.flight,
            &self.service,
            &self.route,
            &self.store,
            request,
        )
        .await
    }

    /// Executes one named read while preserving whether failure came from the
    /// Store API or from gateway validation and fencing.
    pub async fn execute_named_with_error(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, NamedReadGatewayError> {
        self.require_active_store_generation()
            .map_err(NamedReadGatewayError::Store)?;
        execute_named_via_with_error(
            &self.flight,
            &self.service,
            &self.route,
            &self.store,
            request,
        )
        .await
    }

    /// Reads and authenticates the current UserAutomation owner material through
    /// the active generation-routed Store contour. The UserAutomation adapter
    /// constructs and projects the closed named reads; this gateway remains the
    /// only production path that performs their Store IO.
    pub async fn read_user_automation_owner(
        &self,
        lookup: &UserAutomationOwnerLookup,
    ) -> Result<UserAutomationOwnerSnapshot, String> {
        let (current_request, history_request) = CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::owner_read_requests(lookup)
        .map_err(|error| error.to_string())?;
        let current_response = self.execute_named(current_request.clone()).await?;
        let history_response = self.execute_named(history_request.clone()).await?;
        let current_after_response = self.execute_named(current_request.clone()).await?;
        CanonicalUserAutomationStore::<EbpCanonicalStoreClient<NamedPipeTransport>>::project_owner_snapshot(
            lookup,
            &current_request,
            current_response,
            &history_request,
            history_response,
            &current_request,
            current_after_response,
        )
        .map_err(|error| error.to_string())
    }

    /// Reads one owner-issued invocation by its exact occurrence identity
    /// through the active generation route. The bounded invocation page is
    /// never used for production provenance recovery.
    pub async fn read_user_automation_invocation(
        &self,
        state_fence: &StateFence,
        automation_id: &str,
        occurrence_id: &str,
    ) -> Result<UserAutomationInvocation, String> {
        state_fence.validate().map_err(|error| error.to_string())?;
        let request = CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::invocation_read_request(
            automation_id.to_owned(),
            occurrence_id.to_owned(),
            state_fence.clone(),
        )
        .map_err(|error| error.to_string())?;
        let response = self.execute_named(request.clone()).await?;
        CanonicalUserAutomationStore::<EbpCanonicalStoreClient<NamedPipeTransport>>::project_invocation(
            automation_id,
            occurrence_id,
            &request,
            response,
        )
        .map_err(|error| error.to_string())
    }

    /// Validates the immutable caller-authored operation before Store admission.
    ///
    /// This check deliberately excludes `OperationIdentity::canonical_request_hash`:
    /// the daemon supplies that field empty and the gateway seals it only after
    /// building the exact canonical transition. This method is pure and makes no
    /// Store call, so a returned `Contract` error is a pre-Store refusal for this
    /// attempt.
    pub fn validate_user_automation_request(
        request: &UserAutomationServiceRequest,
    ) -> Result<(), UserAutomationExecutionError> {
        request
            .intent
            .validate()
            .map_err(UserAutomationExecutionError::Contract)
    }

    /// Performs or replays the authenticated schedule normalization operation.
    /// A newly compiled answer is retained through the existing canonical
    /// writer before this method returns it to the Kernel operator route.
    pub async fn normalize_user_automation_schedule(
        &self,
        request: &UserAutomationServiceRequest,
    ) -> Result<
        (
            UserAutomationServiceRequest,
            UserAutomationRevision,
            eliot_receipts::ReceiptEnvelope,
        ),
        UserAutomationExecutionError,
    > {
        request
            .validate_for_schedule_normalization()
            .map_err(UserAutomationExecutionError::Contract)?;
        let (automation_id, revision_id) = normalization_selector(request)?;
        let record = self
            .read_user_automation_normalization_record(
                &request.context.state_fence,
                &automation_id,
                &revision_id,
            )
            .await?;
        if let Some(record) = record {
            let (original, revision, envelope) =
                super::user_automation_store::validate_normalization_record(&record)
                    .map_err(|_| normalization_receipt_binding())?;
            if !Self::same_normalization_intent(&original, request) {
                return Err(normalization_receipt_binding());
            }
            return Ok((original, revision, envelope));
        }

        // A reused operation ID whose original result is not present under
        // this exact selector is a known conflict. Never compile and retry it.
        if self
            .receipt(
                &request.context.state_fence,
                request.identity.operation_id.clone(),
            )
            .await
            .map_err(user_automation_gateway_unknown)?
            .is_some()
        {
            return Err(normalization_receipt_binding());
        }

        let (revision, envelope) =
            super::user_automation_store::normalize_user_automation_operation(request)
                .map_err(UserAutomationExecutionError::Contract)?;
        self.retain_user_automation_normalization_result(request, &revision, &envelope)
            .await
    }

    async fn read_user_automation_normalization_record(
        &self,
        state_fence: &StateFence,
        automation_id: &str,
        revision_id: &str,
    ) -> Result<
        Option<super::user_automation_store::UserAutomationNormalizationRecord>,
        UserAutomationExecutionError,
    > {
        let named = CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::normalization_read_request(
            state_fence.clone(),
            automation_id.to_owned(),
            revision_id.to_owned(),
        )
        .map_err(user_automation_gateway_unknown)?;
        let response = self
            .execute_named(named.clone())
            .await
            .map_err(user_automation_gateway_unknown)?;
        let record = CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::project_normalization_record(automation_id, revision_id, &named, response)
        .map_err(user_automation_gateway_unknown)?;
        if let Some(record) = &record {
            let receipt = self
                .receipt(state_fence, record.operation_id.clone())
                .await
                .map_err(user_automation_gateway_unknown)?
                .ok_or_else(|| {
                    user_automation_gateway_unknown(
                        "retained normalization has no canonical write receipt",
                    )
                })?;
            CanonicalUserAutomationStore::<
                EbpCanonicalStoreClient<NamedPipeTransport>,
            >::validate_normalization_write_receipt(record, &receipt)
            .map_err(user_automation_gateway_unknown)?;
        }
        Ok(record)
    }

    async fn retain_user_automation_normalization_result(
        &self,
        request: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        envelope: &eliot_receipts::ReceiptEnvelope,
    ) -> Result<
        (
            UserAutomationServiceRequest,
            UserAutomationRevision,
            eliot_receipts::ReceiptEnvelope,
        ),
        UserAutomationExecutionError,
    > {
        let (automation_id, revision_id) = normalization_selector(request)?;
        let original_request_json = serde_json::to_string(request)
            .map_err(user_automation_gateway_unknown)?;
        let store_request = crate::UserAutomationStoreRequest {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal.clone(),
            identity: request.identity.clone(),
            intent: request.intent.clone(),
        };
        let (mut transition, manifest_digest) =
            CanonicalUserAutomationStore::<BorrowedCanonicalStoreClient<'_>>::build_normalization_transition(
                &store_request,
                revision,
                envelope,
                original_request_json,
            )
            .map_err(user_automation_gateway_unknown)?;
        let view = CanonicalRequestView::from_apply(
            &store_request.context,
            &transition,
            &[],
            &[],
        );
        let planned_hash = canonical_request_hash(&view).map_err(user_automation_gateway_unknown)?;
        transition.identity.canonical_request_hash = planned_hash.clone();
        let receipt = self
            .apply(&store_request.context, transition, Vec::new(), Vec::new())
            .await
            .map_err(user_automation_gateway_unknown)?;
        receipt.validate().map_err(user_automation_gateway_unknown)?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.operation_id != request.identity.operation_id
            || receipt.idempotency_key != request.identity.idempotency_key
            || receipt.canonical_request_hash != planned_hash
            || receipt.state_fence != request.context.state_fence
            || receipt.operation_manifest_digest != manifest_digest
        {
            return Err(user_automation_gateway_unknown(
                "normalization retention receipt does not bind the prepared transition",
            ));
        }
        receipt
            .require_reconciliation_envelope()
            .map_err(user_automation_gateway_unknown)?;

        let record = self
            .read_user_automation_normalization_record(
                &request.context.state_fence,
                &automation_id,
                &revision_id,
            )
            .await
            ?
        .ok_or_else(|| {
            user_automation_gateway_unknown(
                "committed normalization retention was not visible on exact readback",
            )
        })?;
        let (original, retained_revision, retained_envelope) =
            super::user_automation_store::validate_normalization_record(&record)
                .map_err(|_| normalization_receipt_binding())?;
        if !Self::same_normalization_intent(&original, request)
            || retained_revision != *revision
            || retained_envelope != *envelope
        {
            return Err(normalization_receipt_binding());
        }
        Ok((original, retained_revision, retained_envelope))
    }

    /// A retained normalization replay may arrive over a new transport
    /// request, but its logical operation, source, principal and fence must be
    /// identical to the original authenticated request.
    fn same_normalization_intent(
        original: &UserAutomationServiceRequest,
        current: &UserAutomationServiceRequest,
    ) -> bool {
        original.identity.operation_id == current.identity.operation_id
            && original.identity.idempotency_key == current.identity.idempotency_key
            && original.authenticated_principal == current.authenticated_principal
            && original.intent == current.intent
            && original.context.session_id == current.context.session_id
            && original.context.task_id == current.context.task_id
            && original.context.product_id == current.context.product_id
            && original.context.source_id == current.context.source_id
            && original.context.state_fence == current.context.state_fence
    }

    /// Executes one authenticated `UserAutomation` operator operation as one
    /// post-commit orchestration transition.
    ///
    /// The caller contributes only the authenticated request metadata, the
    /// authenticated principal, the operation identity triple, and the closed
    /// [`UserAutomationOperation`](eliot_kernel_core::UserAutomationOperation).
    /// The canonical request hash is sealed here over the exact prepared
    /// transition before dispatch, so a caller can never supply it and the
    /// Store adapter rebuilds byte-identical bytes deterministically. This is
    /// the one production path from a Kernel front-door route into
    /// [`CanonicalUserAutomationStore`]; it adds no second writer.
    ///
    /// The canonical Store commit is only the first phase. The transition then
    /// hands the committed operation to the existing runtime owners over the
    /// already-authenticated `UserAutomationRuntimePort` and returns the Store
    /// commit, the wake publication/cancellation handoff and the execution
    /// disposition as three distinct phases of one parent operation. A Store
    /// receipt is never reported as an execution result, and an unresolved
    /// handoff is returned as a typed phase that
    /// [`UserAutomationOperatorTransition::recovery`] turns into the caller's
    /// recovery directive.
    ///
    /// Every runtime effect this operation owns is retained in the
    /// composition-bound durable outbox under its ORIGINAL owner operation
    /// identity BEFORE the effect is issued, and the retained record is the
    /// source of the transition's orchestration record. A replay of the same
    /// parent operation therefore resumes that record: an answered obligation
    /// serves its retained owner answer verbatim, and an obligation whose effect
    /// may already have been issued is reported as reconciling under its
    /// retained identity instead of being issued a second time. There is no
    /// cross-store atomic transaction and no process-local retry ledger.
    ///
    /// `runtime` is `Some` for every operation that owns a wake or execution
    /// handoff. A read-only answer passes `None` and reports both handoff
    /// phases as not applicable; a handoff operation answered without a
    /// composed runtime fails closed as unavailable rather than as a Store-only
    /// success.
    pub async fn execute_user_automation_operation<R>(
        &self,
        request: UserAutomationServiceRequest,
        runtime: Option<&R>,
    ) -> Result<UserAutomationOperatorTransition, UserAutomationExecutionError>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        // I14.16 step 4 (issue #1953, map item 2): the Store commits below
        // travel through the borrowed client, which bypasses `Self::apply`,
        // so the entry refuses a `shadow_no_authority` candidate itself. The
        // typed `Rejected` refusal proves nothing was admitted: no UnknownOutcome.
        self.refuse_shadow_mutation().map_err(|error| {
            UserAutomationExecutionError::Runtime(UserAutomationRuntimeError::Rejected(error))
        })?;
        Self::validate_user_automation_request(&request)?;
        if matches!(
            &request.intent.operation,
            UserAutomationOperation::Create { .. } | UserAutomationOperation::Edit { .. }
        ) {
            self.validate_submitted_normalization_owner(&request).await?;
        }
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(self));
        // The sealed request is the one value this frame must keep across every
        // remaining await, and it inlines the closed operator operation
        // vocabulary, so holding it by value makes this future larger than the
        // frame budget while it is suspended. The heap box is a storage detail
        // only: it is read by reference everywhere below, and it is dropped at
        // the same point the by-value value was dropped, so no step observes a
        // different request, lifetime or ownership.
        let sealed = Box::new(
            self.seal_user_automation_operation(&store, request)
                .await
                .map_err(user_automation_gateway_unknown)?,
        );
        let response =
            Box::pin(UserAutomationService::new(&store).dispatch(sealed.as_ref().clone()))
                .await
                .map_err(user_automation_gateway_unknown)?;
        if response.identity != sealed.identity
            || response.state_fence != sealed.context.state_fence
        {
            return Err(user_automation_gateway_unknown(
                "canonical UserAutomation response does not bind to the sealed operation",
            ));
        }
        let configuration = UserAutomationConfigurationPhase::from_store_outcome(response.outcome);
        let mut obligations: Vec<UserAutomationRuntimeObligation> = Vec::new();
        let (wake, execution) = self
            .user_automation_runtime_handoff(&sealed, &configuration, runtime, &mut obligations)
            .await
            .map_err(user_automation_gateway_unknown)?;
        let horizon = self
            .publish_schedule_horizon(&sealed, &configuration, runtime, &mut obligations)
            .await
            .map_err(user_automation_gateway_unknown)?;
        let orchestration =
            Self::compose_user_automation_orchestration(&sealed, &configuration, obligations)
                .map_err(user_automation_gateway_unknown)?;
        let transition = UserAutomationOperatorTransition::with_horizon(
            sealed.identity.clone(),
            sealed.context.state_fence.clone(),
            configuration,
            wake,
            execution,
            horizon,
            orchestration,
        );
        transition
            .validate()
            .map_err(user_automation_gateway_unknown)?;
        Ok(transition)
    }

    /// Proves Create/Edit's revision and original envelope came from the
    /// independently retained normalization owner before any Store mutation.
    async fn validate_submitted_normalization_owner(
        &self,
        request: &UserAutomationServiceRequest,
    ) -> Result<(), UserAutomationExecutionError> {
        let (revision, envelope) = match &request.intent.operation {
            UserAutomationOperation::Create {
                revision,
                normalization_receipt_envelope,
            }
            | UserAutomationOperation::Edit {
                revision,
                normalization_receipt_envelope,
                ..
            } => (revision, normalization_receipt_envelope),
            _ => return Ok(()),
        };
        let fence = request.context.state_fence.clone();
        let named = CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::normalization_read_request(
            fence.clone(),
            revision.automation_id.clone(),
            revision.revision.clone(),
        )
        .map_err(user_automation_gateway_unknown)?;
        let response = self
            .execute_named(named.clone())
            .await
            .map_err(user_automation_gateway_unknown)?;
        let record = CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::project_normalization_record(
            &revision.automation_id,
            &revision.revision,
            &named,
            response,
        )
        .map_err(|_| normalization_receipt_binding())?
        .ok_or_else(normalization_receipt_binding)?;
        let receipt = self
            .receipt(&fence, record.operation_id.clone())
            .await
            .map_err(user_automation_gateway_unknown)?
            .ok_or_else(|| {
                user_automation_gateway_unknown(
                    "retained normalization has no canonical write receipt",
                )
            })?;
        CanonicalUserAutomationStore::<
            EbpCanonicalStoreClient<NamedPipeTransport>,
        >::validate_normalization_write_receipt(&record, &receipt)
        .map_err(|_| normalization_receipt_binding())?;
        let (original, retained_revision, retained_envelope) =
            super::user_automation_store::validate_normalization_record(&record)
                .map_err(|_| normalization_receipt_binding())?;
        let same_context = original.authenticated_principal == request.authenticated_principal
            && original.context.session_id == request.context.session_id
            && original.context.task_id == request.context.task_id
            && original.context.product_id == request.context.product_id
            && original.context.source_id == request.context.source_id
            && original.context.state_fence == request.context.state_fence;
        let migration_predecessor_matches = match (
            &original.intent.operation,
            &request.intent.operation,
        ) {
            (
                UserAutomationOperation::MigrateLegacySchedule {
                    previous_revision, ..
                },
                UserAutomationOperation::Edit {
                    previous_revision: submitted, ..
                },
            ) => previous_revision == submitted,
            (UserAutomationOperation::NormalizeSchedule { .. }, _) => true,
            _ => false,
        };
        let submitted_revision_json = serde_json::to_string(revision)
            .map_err(user_automation_gateway_unknown)?;
        let submitted_envelope = serde_json::to_value(envelope)
            .map_err(user_automation_gateway_unknown)?;
        if !same_context
            || !migration_predecessor_matches
            || record.revision_json != submitted_revision_json
            || record.normalization_receipt_json != submitted_envelope
            || retained_revision != *revision
            || retained_envelope != *envelope
        {
            return Err(normalization_receipt_binding());
        }
        let operation_kind =
            super::user_automation_store::submitted_normalization_operation_kind(
                &request.intent.operation,
            )
            .map_err(|_| normalization_receipt_binding())?;
        super::user_automation_store::revision_with_owner_normalization_receipt(
            revision,
            &retained_envelope,
            operation_kind,
        )
        .map_err(|_| normalization_receipt_binding())?;
        Ok(())
    }

    /// Composes the one post-commit orchestration record of a parent operator
    /// operation from the obligations its legs retained.
    ///
    /// The record binds the parent operation, the exact digest of the committed
    /// canonical receipt, the immutable automation/revision those obligations
    /// belong to, and the State Fence every phase was observed under. An
    /// operation that retained no obligation owns no orchestration: that is a
    /// complete answer about an obligation that never existed, not an empty
    /// record, so a read-only answer and a `RunNow` answer carry none.
    fn compose_user_automation_orchestration(
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        obligations: Vec<UserAutomationRuntimeObligation>,
    ) -> Result<Option<UserAutomationOrchestrationRecord>, String> {
        if obligations.is_empty() {
            return Ok(None);
        }
        let revision = committed_revision(configuration).ok_or_else(|| {
            "a committed UserAutomation operation that retained a runtime obligation did not \
             return a canonical revision"
                .to_owned()
        })?;
        let committed_receipt_digest =
            committed_receipt_digest(configuration).ok_or_else(|| {
                "a UserAutomation operation that retained a runtime obligation has no committed \
             canonical receipt to bind"
                    .to_owned()
            })?;
        Ok(Some(UserAutomationOrchestrationRecord::new(
            sealed.identity.clone(),
            sealed.context.state_fence.clone(),
            revision.automation_id.clone(),
            revision.revision.clone(),
            revision.digest().map_err(|error| error.to_string())?,
            committed_receipt_digest,
            obligations,
        )))
    }

    /// Reads the durable outbox record of one runtime obligation, if the
    /// composition-bound owner already holds one.
    ///
    /// It is read before anything is staged, so a replay of a parent operation
    /// that already has a record never compares its own live fence, epoch,
    /// generation and clock against the staged request's era binding — a replay
    /// legitimately carries a different one.
    fn read_user_automation_obligation(
        &self,
        obligation: &UserAutomationRuntimeObligation,
    ) -> RetainedObligationLookup {
        let Some(ors) = self.commit_ors.as_deref() else {
            return RetainedObligationLookup::unreadable(unretained_obligation_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so no \
                 runtime obligation can be read or retained",
            ));
        };
        let Ok(operation_id) = user_automation_obligation_operation_id(obligation) else {
            return RetainedObligationLookup::Unreadable {
                reason: unretained_obligation_reason(
                    obligation,
                    "the derived owner operation identity is not a well-formed durable label",
                ),
            };
        };
        match ors.load_host_request(&operation_id, &obligation.request_digest) {
            Ok(Some(existing)) => {
                let expiry_attempt = (existing.send_claim_protocol_version
                    == eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION)
                    .then(|| existing.attempt.clone())
                    .flatten();
                let existing = if let Some(attempt) = expiry_attempt {
                    match ors.reconcile_expired_host_request_claim(
                        &operation_id,
                        &obligation.request_digest,
                        &attempt,
                    ) {
                        Ok(Some(reconciled)) => reconciled,
                        Ok(None) => {
                            return RetainedObligationLookup::unreadable(
                                unretained_obligation_reason(
                                    obligation,
                                    "the retained send claim disappeared during expiry reconciliation",
                                ),
                            );
                        }
                        Err(_) => {
                            return RetainedObligationLookup::unreadable(
                                unretained_obligation_reason(
                                    obligation,
                                    "the retained send claim could not be revalidated for expiry",
                                ),
                            );
                        }
                    }
                } else {
                    existing
                };
                RetainedObligationLookup::Held(classify_retained_obligation(obligation, existing))
            }
            Ok(None) => RetainedObligationLookup::Absent,
            Err(error) => RetainedObligationLookup::unreadable(unretained_obligation_reason(
                obligation,
                format!("the retained obligation could not be read back: {error}"),
            )),
        }
    }

    /// Reconciles a v1 cancellation only after dispatch was durably observed.
    /// The Host readback is bound to the exact original typed request and the
    /// active ORS claim; its result and owner receipt are terminalized in one
    /// ORS transaction. A missing, legacy, or inaccessible Host batch leaves
    /// the obligation reconciling and never authorizes a resend.
    #[allow(
        clippy::too_many_lines,
        reason = "exact owner readback, claim evidence, and terminal result are checked together"
    )]
    async fn reconcile_cancellation_owner_readback<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        obligation: &UserAutomationRuntimeObligation,
        revision: &UserAutomationRevision,
        targets: &[UserAutomationWakeCancellationTarget],
        enumeration_receipt: &UserAutomationWakeEnumerationReceipt,
        runtime: &R,
    ) -> RetainedObligationLookup
    where
        R: UserAutomationWakePort + ?Sized,
    {
        let retained = self.retain_user_automation_obligation(sealed, obligation);
        if !matches!(
            &retained,
            RetainedObligationLookup::Held(RetainedUserAutomationObligation::Reconciling { .. })
        ) {
            return retained;
        }
        let Some(ors) = self.commit_ors.as_deref() else {
            return retained;
        };
        let Ok(operation_id) = user_automation_obligation_operation_id(obligation) else {
            return retained;
        };
        let Ok(Some(record)) = ors.load_host_request(&operation_id, &obligation.request_digest)
        else {
            return retained;
        };
        let Some(attempt) = record.attempt.clone() else {
            return retained;
        };
        let Ok(expected_payload_digest) =
            runtime_obligation_payload_digest(&obligation.subject_ids)
        else {
            return retained;
        };
        let Ok(expected_fence_digest) = user_automation_obligation_fence_digest(sealed, obligation)
        else {
            return retained;
        };
        let exact_request = UserAutomationWakeCancellation {
            context: sealed.context.clone(),
            authenticated_principal: sealed.authenticated_principal.clone(),
            identity: sealed.identity.clone(),
            automation_id: revision.automation_id.clone(),
            automation_revision: revision.revision.clone(),
            state_fence: sealed.context.state_fence.clone(),
            only_unadmitted: true,
            targets: targets.to_vec(),
            enumeration_receipt: Some(Box::new(enumeration_receipt.clone())),
        };
        let request_valid = exact_request.validate().is_ok();
        let original_channel = enumeration_receipt
            .authenticated_channel_binding_sha256
            .as_str();
        let crossed_dispatch = attempt
            .transport_observations
            .first()
            .is_some_and(|observation| {
                observation.boundary == HostRequestTransportBoundary::DispatchStarted
            })
            && attempt
                .transport_observations
                .last()
                .is_some_and(|observation| {
                    matches!(
                        observation.boundary,
                        HostRequestTransportBoundary::DispatchStarted
                            | HostRequestTransportBoundary::DeliveryOutcomeUnknown
                            | HostRequestTransportBoundary::DeliveredToAuthenticatedHost
                            | HostRequestTransportBoundary::ResponseReceived
                    )
                });
        if !request_valid
            || !crossed_dispatch
            || record.send_claim_protocol_version
                != eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            || record.kind != HostRequestKind::Cancellation
            || record.operation_id != operation_id
            || record.request_digest != obligation.request_digest
            || record.connection_ref.as_str() != USER_AUTOMATION_RUNTIME_CHANNEL
            || record.parent_operation_id.as_ref().map(OpaqueLabel::as_str)
                != Some(sealed.identity.operation_id.as_str())
            || record.payload_digest != expected_payload_digest
            || record.fence_digest != expected_fence_digest
            || record.transport_channel_binding_sha256.as_deref() != Some(original_channel)
            || attempt.channel_binding_sha256.as_deref() != Some(original_channel)
            || attempt.phase == HostRequestAttemptPhase::DefinitelyNotSent
            || attempt.phase == HostRequestAttemptPhase::DeferredNoEffect
        {
            return retained;
        }
        let Ok(authenticated_readback) =
            runtime.read_cancellation_batch(exact_request.clone()).await
        else {
            return retained;
        };
        if authenticated_readback
            .readback
            .validate_for(&exact_request)
            .is_err()
            || authenticated_readback
                .validate_for(
                    &exact_request,
                    &authenticated_readback.authenticated_channel_binding_sha256,
                )
                .is_err()
        {
            return retained;
        }
        let Some(original_observation) = attempt.transport_observations.first() else {
            return retained;
        };
        let response = UserAutomationHostExecutionResponse::Cancelled {
            request_sha256: original_observation.transport_request_sha256.clone(),
            state_fence: exact_request.state_fence.clone(),
            wake_ids: authenticated_readback.readback.cancelled_wake_ids.clone(),
        };
        let Ok(result_response) = serde_json::to_value(&response) else {
            return retained;
        };
        let result_digest = match canonical_json_bytes(&result_response) {
            Ok(bytes) => sha256_hex(&bytes),
            Err(_) => return retained,
        };
        let Ok(owner_receipt_commitment_sha256) = authenticated_readback
            .readback
            .owner_receipt_commitment_sha256()
        else {
            return retained;
        };
        let evidence = HostRequestOwnerReadbackEvidence {
            operation_id: record.operation_id.clone(),
            request_digest: record.request_digest.clone(),
            payload_digest: record.payload_digest.clone(),
            attempt_id: attempt.attempt_id.clone(),
            attempt_generation: attempt.generation,
            readback_channel_binding_sha256: authenticated_readback
                .authenticated_channel_binding_sha256
                .clone(),
            owner_receipt_commitment_sha256,
            result_commitment_sha256: result_digest.clone(),
        };
        match ors.persist_claimed_host_request_result(
            &operation_id,
            &obligation.request_digest,
            &attempt,
            &result_digest,
            &result_response,
            Some(&evidence),
        ) {
            Ok(Some(answered)) => {
                RetainedObligationLookup::Held(classify_retained_obligation(obligation, answered))
            }
            Ok(None) | Err(_) => retained,
        }
    }

    /// Retains one runtime obligation of a committed operator operation in the
    /// composition-bound durable outbox, before any owner effect is issued.
    ///
    /// This is the existing Kernel operational outbox, not a new one: one
    /// `eliot_ors::HostRequestRecord` per obligation, first-writer-wins under
    /// its own durable `operation_id::request_digest` key, with the
    /// persist-before-ack contract, the anti-blind-retry fence, and the bounded
    /// answer body an exact replay serves verbatim. The lookup key is derived
    /// only from immutable content, so the same parent operation finds the same
    /// record after a restart or a fence change; the fence, epoch, generation
    /// and observed clock are era binding and are compared only when the record
    /// is first staged.
    ///
    /// An obligation that cannot be retained is a named failure, never a silent
    /// skip: the caller reports it as an explicit unavailability and issues no
    /// owner effect at all.
    ///
    /// The window between handing the request to the owner and recording its
    /// answer is closed by [`Self::claim_user_automation_send`], which acquires
    /// one exclusive durable send claim and persists the monotonic `Routed`
    /// state before the first transport await (issue #2970). A process death
    /// after that claim therefore reloads as a reconciling record, never as
    /// re-issuable `Admitted` work, and a competing caller that loses the claim
    /// issues nothing. Every *reported* response loss is still armed by
    /// [`Self::mark_user_automation_obligation_unknown`], and no state is ever
    /// moved backward out of a possible-effect contour to enable a retry.
    fn retain_user_automation_obligation(
        &self,
        sealed: &UserAutomationServiceRequest,
        obligation: &UserAutomationRuntimeObligation,
    ) -> RetainedObligationLookup {
        match self.read_user_automation_obligation(obligation) {
            RetainedObligationLookup::Absent => {}
            held => return held,
        }
        let Some(ors) = self.commit_ors.as_deref() else {
            return RetainedObligationLookup::unreadable(unretained_obligation_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so no \
                 runtime obligation can be retained",
            ));
        };
        let record = match Self::user_automation_obligation_outbox_record(sealed, obligation) {
            Ok(record) => record,
            Err(reason) => return RetainedObligationLookup::unreadable(reason),
        };
        match ors.stage_host_request(&record) {
            Ok(staged) => {
                RetainedObligationLookup::Held(classify_retained_obligation(obligation, staged))
            }
            Err(error) => RetainedObligationLookup::unreadable(unretained_obligation_reason(
                obligation,
                format!("the obligation intent could not be retained: {error}"),
            )),
        }
    }

    /// Retains the exact owner answer of one runtime obligation as the durable
    /// record's bounded response body, and completes that record.
    ///
    /// The body is what an exact replay of the same parent operation serves
    /// instead of issuing the effect a second time, so a lost response is
    /// resumed from the record rather than re-derived from a fresh owner call.
    #[allow(
        clippy::too_many_lines,
        reason = "the retained answer and original send claim are validated as one operation"
    )]
    fn retain_user_automation_obligation_answer(
        &self,
        obligation: &UserAutomationRuntimeObligation,
        answer: &UserAutomationRuntimeObligationAnswer,
    ) -> Result<(), String> {
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(unretained_answer_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so the \
                 owner answer cannot be retained"
                    .to_owned(),
            ));
        };
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        if obligation.kind == UserAutomationRuntimeObligationKind::WakeCancellation {
            let retained = ors
                .load_host_request(&operation_id, &obligation.request_digest)
                .map_err(|error| {
                    unretained_answer_reason(
                        obligation,
                        format!("the observed cancellation result could not be read: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    unretained_answer_reason(
                        obligation,
                        "the observed cancellation result row disappeared before answer projection",
                    )
                })?;
            if retained.send_claim_protocol_version
                == eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            {
                let UserAutomationRuntimeObligationAnswer::WakeCancellation {
                    cancelled_wake_ids,
                    enumeration_receipt: Some(receipt),
                } = answer
                else {
                    return Err(unretained_answer_reason(
                        obligation,
                        "the returned v1 cancellation answer has no exact enumeration receipt",
                    ));
                };
                let expected_receipt =
                    obligation
                        .wake_enumeration_receipt
                        .as_deref()
                        .ok_or_else(|| {
                            unretained_answer_reason(
                                obligation,
                                "the retained v1 cancellation has no exact enumeration receipt",
                            )
                        })?;
                let attempt = retained.attempt.as_ref().ok_or_else(|| {
                    unretained_answer_reason(
                        obligation,
                        "the retained cancellation result has no claimed attempt",
                    )
                })?;
                let observation = attempt
                    .transport_observations
                    .last()
                    .filter(|observation| {
                        observation.boundary == HostRequestTransportBoundary::ResponseReceived
                    })
                    .ok_or_else(|| {
                        unretained_answer_reason(
                            obligation,
                            "the retained cancellation result has no response-received custody event",
                        )
                    })?;
                let response = UserAutomationHostExecutionResponse::Cancelled {
                    request_sha256: observation.transport_request_sha256.clone(),
                    state_fence: expected_receipt.state_fence.clone(),
                    wake_ids: cancelled_wake_ids.clone(),
                };
                let response_value = serde_json::to_value(&response).map_err(|_| {
                    unretained_answer_reason(
                        obligation,
                        "the exact Host cancellation response could not be projected for comparison",
                    )
                })?;
                let response_digest = canonical_json_bytes(&response_value)
                    .map(|bytes| sha256_hex(&bytes))
                    .map_err(|_| {
                        unretained_answer_reason(
                            obligation,
                            "the exact Host cancellation response could not be committed for comparison",
                        )
                    })?;
                if receipt.as_ref() != expected_receipt
                    || retained.state != HostRequestState::ResultReceived
                    || attempt.phase != HostRequestAttemptPhase::ResponseReceived
                    || retained.result_response.as_ref() != Some(&response_value)
                    || retained.result_digest.as_deref() != Some(response_digest.as_str())
                    || observation.response_commitment_sha256.as_deref()
                        != Some(response_digest.as_str())
                    || observation.request_digest != obligation.request_digest
                    || observation.operation_id != operation_id
                    || retained.transport_channel_binding_sha256.as_deref()
                        != Some(receipt.authenticated_channel_binding_sha256.as_str())
                {
                    return Err(unretained_answer_reason(
                        obligation,
                        "the retained Host response does not match the exact cancellation answer, channel, request, and claim",
                    ));
                }
                return Ok(());
            }
        }
        let result_response = serde_json::to_value(answer).map_err(|error| {
            unretained_answer_reason(
                obligation,
                format!("the owner answer could not be encoded for retention: {error}"),
            )
        })?;
        let result_digest = canonical_json_bytes(answer)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| {
                unretained_answer_reason(
                    obligation,
                    format!("the owner answer could not be digested for retention: {error}"),
                )
            })?;
        ors.persist_host_request_result(
            &operation_id,
            &obligation.request_digest,
            &result_digest,
            &result_response,
            // Issue #1853 W2: a retained owner answer is not an executor
            // observation and carries no result lineage, so neither is
            // retained. Absence means nothing was observed or claimed here.
            None,
            None,
        )
        .map_err(|error| {
            unretained_answer_reason(
                obligation,
                format!("the owner answer could not be retained: {error}"),
            )
        })?;
        Ok(())
    }

    /// Walks one retained obligation to `Admitted` through the durable outbox's
    /// own mechanical progression, before the request leaves this boundary.
    ///
    /// `Admitted` is the last state that still proves the owner was never handed
    /// the request, and it is the state the outbox's own answer path continues
    /// from. This advance is a mechanical, idempotent state projection and
    /// deliberately grants no ownership: [`Self::claim_user_automation_send`]
    /// then acquires the exclusive send claim that actually permits the owner
    /// handoff, and that claim is what persists the monotonic `Routed` state
    /// before the first transport await. An owner that is not available leaves
    /// the record admitted, so a later attempt of the same parent operation may
    /// still claim and issue it; nothing here is ever moved backward out of a
    /// possible-effect contour, and a lost answer is armed by
    /// [`Self::mark_user_automation_obligation_unknown`] instead.
    fn mark_user_automation_obligation_admitted(
        &self,
        obligation: &UserAutomationRuntimeObligation,
    ) -> Result<(), String> {
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(unretained_obligation_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so the \
                 owner effect cannot be marked as admitted"
                    .to_owned(),
            ));
        };
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        match ors
            .advance_host_request(
                &operation_id,
                &obligation.request_digest,
                HostRequestState::Admitted,
                None,
            )
            .map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the obligation could not be advanced to Admitted: {error}"),
                )
            })? {
            Some(_) => Ok(()),
            None => Err(unretained_obligation_reason(
                obligation,
                "the retained obligation record disappeared before the owner effect could be issued"
                    .to_owned(),
            )),
        }
    }

    /// Durably records that one wake-horizon publication MAY ALREADY have been
    /// handed to the schedule owner, and does so BEFORE the transport await that
    /// could commit it (issue #2970).
    ///
    /// `Admitted` alone cannot carry that meaning on this contour: it is the very
    /// same durable state the horizon path leaves behind when no schedule owner
    /// was reachable, so a restart cannot distinguish a horizon the owner never
    /// received from one it already retained. This advance therefore walks the
    /// outbox's own mechanical progression to `Routed`, the state
    /// `classify_retained_obligation` already reads as "the owner may already
    /// have acted". Nothing here is ever moved backward out of that contour.
    ///
    /// The write lands before the first await, so a process death inside the
    /// await window reloads as reconciling work rather than re-issuable
    /// `Retained` work, and the later attempt must answer "did this possibly
    /// happen?" from the owner itself under the ORIGINAL owner operation
    /// identity instead of publishing the slice again.
    fn mark_wake_horizon_obligation_possible_effect(
        &self,
        obligation: &UserAutomationRuntimeObligation,
    ) -> Result<(), String> {
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(unretained_obligation_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so the wake \
                 horizon publication cannot be recorded as a possible owner effect"
                    .to_owned(),
            ));
        };
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        let Some(existing) = ors
            .load_host_request(&operation_id, &obligation.request_digest)
            .map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the retained horizon obligation could not be read: {error}"),
                )
            })?
        else {
            return Err(unretained_obligation_reason(
                obligation,
                "the retained horizon obligation record disappeared before its possible owner effect \
                 could be recorded"
                    .to_owned(),
            ));
        };
        // Only the edges this row has not already taken are walked. A record
        // that already reached `Routed` proves the possible effect durably, and
        // this contour never moves a row backward out of it.
        let missing = match existing.state {
            HostRequestState::Requested => {
                vec![HostRequestState::Admitted, HostRequestState::Routed]
            }
            HostRequestState::Admitted => vec![HostRequestState::Routed],
            _ => Vec::new(),
        };
        for target in missing {
            match ors.advance_host_request(&operation_id, &obligation.request_digest, target, None)
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(unretained_obligation_reason(
                        obligation,
                        "the retained horizon obligation record disappeared before its possible \
                         owner effect could be recorded"
                            .to_owned(),
                    ));
                }
                Err(error) => {
                    return Err(unretained_obligation_reason(
                        obligation,
                        format!(
                            "the wake horizon publication could not be advanced to {target:?} \
                             before the schedule owner handoff: {error}"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Prepares one retained wake cancellation for its single owner handoff,
    /// and reports the unresolved phases to return when it cannot.
    ///
    /// A first attempt is durably advanced to `Admitted` before claiming. A
    /// retry after retained typed definitely-not-sent evidence already has the
    /// monotonic `Routed` state, so it skips that backward state edge and
    /// acquires the next bounded claim directly. The claim transaction is the
    /// only step that grants send ownership. Any failure issues no owner
    /// effect and is reported under the original operation identity.
    ///
    /// Returns the phases the caller must return instead, or `None` when the
    /// cancellation now holds its claim and may reach the owner.
    fn claim_wake_cancellation_send(
        &self,
        sealed: &UserAutomationServiceRequest,
        settled: &mut UserAutomationRuntimeObligation,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
        execution: &UserAutomationExecutionPhase,
        retry_after_proven_no_send: bool,
    ) -> Option<(UserAutomationWakePhase, UserAutomationExecutionPhase)> {
        if !retry_after_proven_no_send {
            // The first attempt is admitted durably before it leaves this
            // boundary. A retry already has a retained Routed row and may
            // advance only through the next claim, never back to Admitted.
            if let Err(reason) = self.mark_user_automation_obligation_admitted(settled) {
                return Some(unresolved_wake_cancellation(
                    settled,
                    obligations,
                    execution,
                    reason,
                ));
            }
        }
        // Exactly one caller may hand this cancellation to the owner. The claim
        // is acquired before the first transport await and, in the same durable
        // write, persists the monotonic `Routed` state, so a process death
        // inside the await window cannot reload as re-issuable `Retained` work
        // and a competing caller issues nothing at all.
        self.claim_user_automation_send(sealed, settled)
            .err()
            .map(|reason| unresolved_wake_cancellation(settled, obligations, execution, reason))
    }

    /// Acquires the one exclusive, durable send claim of one retained
    /// obligation before its owner effect is handed to the transport
    /// (issue #2970).
    ///
    /// This is the existing ORS `HostRequest` claim seam, not a new outbox: the
    /// claim is a `HostRequestAttempt` on the same row the obligation already
    /// owns, and [`RedbRecoveryStore::claim_host_request_attempt`] performs the
    /// whole acquisition in one ORS write transaction. Two guarantees come
    /// from that single transaction rather than from this caller:
    ///
    /// - Acquisition is first-writer-wins. `Admitted` is the last state that
    ///   proves the owner was never handed the request, and exactly one caller
    ///   can move the row out of it with a claimed attempt. A second caller's
    ///   presented attempt never matches the durable one, so ORS returns the
    ///   first attempt unchanged and this caller refuses to issue anything.
    /// - The monotonic non-reissuable `Routed` state is persisted in that same
    ///   transaction, before this function returns and therefore before the
    ///   first transport await. A process death after this point reloads as a
    ///   reconciling record unless the retained attempt contains typed
    ///   definitely-not-sent evidence, which permits the single bounded retry
    ///   under the same operation identity. Nothing is written between the
    ///   claim and the routed state because they are one write.
    ///
    /// Ownership is then confirmed by CONTENT, not by the mere existence of a
    /// claimed attempt or by a same-target `Routed` replay: the durable attempt
    /// is compared against the exact attempt this caller presented, so only
    /// the claim that actually won proceeds to the transport. A caller that
    /// loses returns a closed reason and makes zero Host calls, and the
    /// obligation is left for reconciliation under its original owner operation
    /// identity instead.
    fn claim_user_automation_send(
        &self,
        sealed: &UserAutomationServiceRequest,
        obligation: &UserAutomationRuntimeObligation,
    ) -> Result<(), String> {
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(unretained_obligation_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so no \
                 exclusive send claim can be acquired"
                    .to_owned(),
            ));
        };
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        let attempt = self.user_automation_send_claim_attempt(sealed, obligation)?;
        let claimed = ors
            .claim_host_request_attempt(&operation_id, &obligation.request_digest, &attempt)
            .map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the exclusive send claim could not be acquired: {error}"),
                )
            })?;
        let Some(claimed) = claimed else {
            return Err(unretained_obligation_reason(
                obligation,
                "the retained obligation record disappeared before its exclusive send claim could \
                 be acquired"
                    .to_owned(),
            ));
        };
        // The routed state and this caller's own claim are one durable write;
        // anything else is a competing attempt, not ownership.
        if claimed.state != HostRequestState::Routed || claimed.attempt.as_ref() != Some(&attempt) {
            return Err(format!(
                "the {} runtime obligation under owner operation identity {} was already claimed by \
                 another caller, which is durably recorded as {:?} with a different attempt; no \
                 owner effect was issued from this caller and the claim stays owned by its winner \
                 for reconciliation",
                obligation.kind.as_str(),
                obligation.owner_operation_id,
                claimed.state
            ));
        }
        Ok(())
    }

    /// Builds the exact ORS `HostRequestAttempt` one `UserAutomation` send claim
    /// presents, bound by content to this obligation and to the live Kernel
    /// route.
    ///
    /// `attempt.fence_digest` is the parent's own State Fence digest, the same
    /// digest the staged row carries, so ORS's own `attempt.validate` refuses
    /// a claim that does not belong to the record it is claiming. The owner
    /// fields name the claiming Kernel generation, its authority session, and
    /// this claim's unique launch identity, which is what makes two competing
    /// claims distinguishable instead of interchangeable.
    #[allow(
        clippy::too_many_lines,
        reason = "the exclusive attempt and bounded no-send retry use one durable claim transition"
    )]
    fn user_automation_send_claim_attempt(
        &self,
        sealed: &UserAutomationServiceRequest,
        obligation: &UserAutomationRuntimeObligation,
    ) -> Result<HostRequestAttempt, String> {
        let fence_digest = user_automation_obligation_fence_digest(sealed, obligation)?;
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(unretained_obligation_reason(
                obligation,
                "no durable ORS owner is bound for send-attempt generation lookup",
            ));
        };
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        let record = ors
            .load_host_request(&operation_id, &obligation.request_digest)
            .map_err(|_| {
                unretained_obligation_reason(
                    obligation,
                    "the retained send-attempt generation could not be read",
                )
            })?
            .ok_or_else(|| {
                unretained_obligation_reason(
                    obligation,
                    "the retained obligation disappeared before attempt generation lookup",
                )
            })?;
        if record.send_claim_protocol_version != eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
        {
            return Err(unretained_obligation_reason(
                obligation,
                "a legacy send-claim record requires reconciliation before dispatch",
            ));
        }
        let attempt_generation = match record.attempt.as_ref() {
            None if record.state == HostRequestState::Admitted
                && record.attempt_history.is_empty() =>
            {
                1
            }
            Some(previous)
                if previous.phase == HostRequestAttemptPhase::DefinitelyNotSent
                    && record.state == HostRequestState::Routed
                    && record.attempt_history.is_empty() =>
            {
                previous.generation.checked_add(1).ok_or_else(|| {
                    unretained_obligation_reason(
                        obligation,
                        "the durable send-attempt generation is exhausted",
                    )
                })?
            }
            Some(previous)
                if previous.phase == HostRequestAttemptPhase::DefinitelyNotSent
                    && !record.attempt_history.is_empty() =>
            {
                return Err(unretained_obligation_reason(
                    obligation,
                    "the same operation already used its bounded no-send retry and requires reconciliation",
                ));
            }
            _ => {
                return Err(unretained_obligation_reason(
                    obligation,
                    "the retained operation is not eligible for a new send attempt",
                ));
            }
        };
        let claim_nonce = USER_AUTOMATION_SEND_CLAIM_NONCE
            .fetch_add(1, AtomicOrdering::Relaxed)
            .checked_add(1)
            .ok_or_else(|| {
                unretained_obligation_reason(
                    obligation,
                    "this process exhausted its send claim identity space, so a new claim identity \
                     could not be minted",
                )
            })?;
        let owner_connection_ref = obligation_label(
            obligation,
            format!(
                "{}:{}:{}",
                self.route.route_scope().as_str(),
                self.route.active_generation().value(),
                std::process::id()
            ),
        )?;
        let owner_launch_nonce = obligation_label(
            obligation,
            format!("{USER_AUTOMATION_RUNTIME_CHANNEL}:{claim_nonce:016x}"),
        )?;
        let claim_expires_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                unretained_obligation_reason(
                    obligation,
                    "the system clock is before the Unix epoch, so the send claim cannot be bounded",
                )
            })
            .and_then(|duration| {
                u64::try_from(duration.as_millis())
                    .map_err(|_| {
                        unretained_obligation_reason(
                            obligation,
                            "the system clock exceeds the send-claim timestamp range",
                        )
                    })?
                    .checked_add(HOST_REQUEST_SEND_CLAIM_LEASE_MS)
                    .ok_or_else(|| {
                        unretained_obligation_reason(
                            obligation,
                            "the bounded send-claim expiry exceeds the timestamp range",
                        )
                    })
            })?;
        Ok(HostRequestAttempt {
            attempt_id: obligation_label(
                obligation,
                format!(
                    "ua-obligation-send-claim:{}:{}:attempt-{}:{claim_nonce:016x}",
                    obligation.owner_operation_id, obligation.request_digest, attempt_generation
                ),
            )?,
            generation: attempt_generation,
            claim_expires_at_unix_ms: Some(claim_expires_at_unix_ms),
            fence_digest,
            owner_connection_ref,
            owner_launch_nonce,
            owner_session_epoch: self.route.authority_epoch().sequence.get(),
            phase: HostRequestAttemptPhase::Claimed,
            channel_binding_sha256: Some(
                record
                    .transport_channel_binding_sha256
                    .clone()
                    .ok_or_else(|| {
                        unretained_obligation_reason(
                            obligation,
                            "the versioned cancellation record has no staged authenticated channel binding",
                        )
                    })?,
            ),
            transport_observations: Vec::new(),
            owner_readback: None,
        })
    }

    /// Checks that a typed transport observation already armed the
    /// anti-blind-retry fence of one retained obligation.
    ///
    /// This is deliberately read-only. A generic runtime error cannot create
    /// possible-effect evidence or advance the outbox; only the authenticated
    /// transport observer may persist that transition under the exact claim.
    fn mark_user_automation_obligation_unknown(
        &self,
        obligation: &UserAutomationRuntimeObligation,
    ) -> Result<(), String> {
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(unretained_obligation_reason(
                obligation,
                "this Kernel composition bound no durable operational outbox handle, so a possible \
                 owner effect cannot be retained"
                    .to_owned(),
            ));
        };
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        let record = ors
            .load_host_request(&operation_id, &obligation.request_digest)
            .map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the retained custody evidence could not be read: {error}"),
                )
            })?
            .ok_or_else(|| {
                unretained_obligation_reason(
                    obligation,
                    "the retained obligation record disappeared before its possible owner effect could \
                     be reconciled",
                )
            })?;
        let possible_effect_is_retained = record.send_claim_protocol_version
            == eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            && record.connection_ref.as_str() == USER_AUTOMATION_RUNTIME_CHANNEL
            && matches!(
                record.state,
                HostRequestState::Submitted
                    | HostRequestState::Unknown
                    | HostRequestState::Reconciling
                    | HostRequestState::ResultReceived
                    | HostRequestState::Terminal
            )
            && record.attempt.as_ref().is_some_and(|attempt| {
                matches!(
                    attempt.phase,
                    HostRequestAttemptPhase::DeliveryOutcomeUnknown
                        | HostRequestAttemptPhase::DeliveredToAuthenticatedHost
                        | HostRequestAttemptPhase::ResponseReceived
                ) && (attempt.owner_readback.is_some()
                    || attempt.transport_observations.last().is_some_and(|observation| {
                        matches!(
                            observation.boundary,
                            eliot_ors::HostRequestTransportBoundary::DeliveryOutcomeUnknown
                                | eliot_ors::HostRequestTransportBoundary::DeliveredToAuthenticatedHost
                                | eliot_ors::HostRequestTransportBoundary::ResponseReceived
                        )
                    }))
            });
        if possible_effect_is_retained {
            Ok(())
        } else {
            Err(unretained_obligation_reason(
                obligation,
                "no typed transport observation under this exact UserAutomation claim proves a \
                 possible owner effect; the outbox state was left unchanged",
            ))
        }
    }

    /// Builds the durable outbox record that retains one runtime obligation.
    ///
    /// Every identity is transcribed from the admitted parent request and the
    /// obligation's own derived key; nothing here is a Store read, a
    /// reinterpretation of a wake reason, or a second writer. The request and
    /// cancellation identities are derived from the obligation rather than
    /// copied from a transport, so two attempts of one parent operation always
    /// present the same durable request identity.
    #[allow(
        clippy::too_many_lines,
        reason = "the exact obligation identity and custody fields are built together"
    )]
    fn user_automation_obligation_outbox_record(
        sealed: &UserAutomationServiceRequest,
        obligation: &UserAutomationRuntimeObligation,
    ) -> Result<HostRequestRecord, String> {
        let observed_unix_ms =
            u64::try_from(observed_retention_instant(&sealed.context).ok_or_else(|| {
                unretained_obligation_reason(
                    obligation,
                    "the parent request carries no observed wall-clock instant, so the durable \
                     obligation cannot name a non-zero retention instant",
                )
            })?)
            .map_err(|_| {
                unretained_obligation_reason(
                    obligation,
                    "the observed retention instant of the parent request is not a valid \
                 non-negative duration",
                )
            })?;
        let fence_digest = user_automation_obligation_fence_digest(sealed, obligation)?;
        let payload_digest =
            runtime_obligation_payload_digest(&obligation.subject_ids).map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the obligation subject identities are not bindable: {error}"),
                )
            })?;
        let request_id = obligation_label(
            obligation,
            format!(
                "ua-obligation-request:{}:{}",
                obligation.kind.as_str(),
                obligation.request_digest
            ),
        )?;
        let request_label = request_id.as_str().to_owned();
        let (send_claim_protocol_version, transport_channel_binding_sha256) = if obligation.kind
            == UserAutomationRuntimeObligationKind::WakeCancellation
        {
            let receipt = obligation
                    .wake_enumeration_receipt
                    .as_deref()
                    .ok_or_else(|| {
                        unretained_obligation_reason(
                            obligation,
                            "a versioned cancellation requires the retained authenticated owner enumeration receipt",
                        )
                    })?;
            receipt.validate_integrity().map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the retained cancellation enumeration receipt is invalid: {error}"),
                )
            })?;
            let receipt_subject_ids = receipt
                .denominator
                .iter()
                .map(|identity| identity.occurrence_id.clone())
                .collect::<Vec<_>>();
            if receipt.parent_operation_identity != sealed.identity
                || receipt.state_fence != sealed.context.state_fence
                || receipt.authenticated_owner_identity != sealed.authenticated_principal
                || receipt_subject_ids != obligation.subject_ids
            {
                return Err(unretained_obligation_reason(
                    obligation,
                    "the retained cancellation receipt does not bind the exact parent, fence, owner, and denominator",
                ));
            }
            (
                eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION,
                Some(receipt.authenticated_channel_binding_sha256.clone()),
            )
        } else {
            (0, None)
        };
        Ok(HostRequestRecord {
            contract_version: ORS_CONTRACT_VERSION,
            send_claim_protocol_version,
            transport_channel_binding_sha256,
            operation_id: user_automation_obligation_operation_id(obligation)?,
            kind: match obligation.kind {
                UserAutomationRuntimeObligationKind::WakeHorizonPublication
                | UserAutomationRuntimeObligationKind::WakeTargetEnumerationReceipt => {
                    HostRequestKind::Invocation
                }
                UserAutomationRuntimeObligationKind::WakeCancellation => {
                    HostRequestKind::Cancellation
                }
            },
            request_id: request_id.clone(),
            correlation_projection: Some(user_automation_obligation_correlation_projection(
                obligation,
                request_label.clone(),
            )),
            idempotency_key: obligation_label(obligation, sealed.identity.idempotency_key.clone())?,
            cancellation_id: obligation_label(
                obligation,
                format!("{USER_AUTOMATION_RUNTIME_CHANNEL}/{request_label}:cancel"),
            )?,
            parent_operation_id: Some(obligation_label(
                obligation,
                sealed.identity.operation_id.as_str().to_owned(),
            )?),
            request_digest: obligation.request_digest.clone(),
            payload_digest,
            payload_schema_id: None,
            payload_body: None,
            connection_ref: obligation_label(
                obligation,
                USER_AUTOMATION_RUNTIME_CHANNEL.to_owned(),
            )?,
            session_ref: sealed
                .context
                .session_id
                .as_ref()
                .map(|session_id| obligation_label(obligation, session_id.as_str().to_owned()))
                .transpose()?,
            task_ref: sealed
                .context
                .task_id
                .as_ref()
                .map(|task_id| obligation_label(obligation, task_id.as_str().to_owned()))
                .transpose()?,
            scope_ref: None,
            capability_ref: obligation_label(
                obligation,
                obligation.kind.capability_ref().to_owned(),
            )?,
            fence_digest,
            authority_epoch: sealed.context.state_fence.authority_epoch.clone(),
            generation: sealed.context.state_fence.resource_generation.value(),
            deadline_unix_ms: observed_unix_ms,
            state: HostRequestState::Requested,
            attempt: None,
            attempt_history: Vec::new(),
            cancellation_target: None,
            result_digest: None,
            result_response: None,
            result_evidence: None,
            result_lineage: None,
            commit_order: 0,
        })
    }

    /// Reads the complete owner execution projection for one automation through
    /// the same `Status` read every other consumer uses.
    ///
    /// This is the gateway-level entry for runtime boundaries that must inspect
    /// the canonical Durable Job projection before crossing into an effect owner
    /// — the due-wake consumer's duplicate guard, for example. It delegates to
    /// [`UserAutomationService::owner_execution_view`], so it inherits the
    /// complete-denominator gate: a denominator the owner could not prove
    /// complete is refused instead of answered as "no admitted job". It reuses
    /// the caller's admitted operation identity and issues no transition, so it
    /// mints no canonical identity and needs no runtime port.
    pub async fn read_user_automation_owner_execution_view(
        &self,
        request: &UserAutomationServiceRequest,
        automation_id: &str,
    ) -> Result<UserAutomationExecutionProjection, String> {
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(self));
        // The `Status` join carries the whole read projection and its response
        // across the await, so it is pinned rather than held inline; the pinned
        // form is the same production Store path the operator route uses.
        Box::pin(UserAutomationService::new(&store).owner_execution_view(request, automation_id))
            .await
            .map_err(|error| error.to_string())
    }

    /// Reads the exact retained Governor Policy owner record from Store.
    ///
    /// This route deliberately accepts no handshake digest as snapshot data:
    /// the Store record key, owner schema, canonical bytes, owner revision,
    /// policy digest, embedded fence, and embedded revision must all correlate.
    /// It is the single decoder of the `owner/policy` owner record: the daemon
    /// trigger path calls this method rather than decoding the record a second
    /// time, so the typed snapshot has one producer.
    pub async fn read_user_automation_policy_snapshot(
        &self,
        state_fence: &StateFence,
    ) -> Result<ConfigPolicySnapshot, UserAutomationRuntimeError> {
        let recovery = self
            .read_user_automation_preflight_owner_snapshot(state_fence)
            .await?;
        Self::user_automation_policy_snapshot_from_recovery(&recovery, state_fence)
    }

    /// Decodes the B-owned complete config snapshot from one validated owner
    /// recovery snapshot.
    pub fn user_automation_policy_snapshot_from_recovery(
        recovery: &StoreRecoverySnapshot,
        state_fence: &StateFence,
    ) -> Result<ConfigPolicySnapshot, UserAutomationRuntimeError> {
        let record = recovery
            .owner_records
            .iter()
            .find(|record| record.namespace == "owner" && record.key == "policy")
            .ok_or(UserAutomationRuntimeError::IdentityConflict)?;
        if recovery.state_fence != *state_fence
            || record.state_fence != *state_fence
            || record.schema != eliot_store_api::OWNER_SNAPSHOT_SCHEMA
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let owner: UserAutomationPolicyOwnerSnapshotWire = serde_json::from_slice(&record.payload)
            .map_err(|_| {
                UserAutomationRuntimeError::Rejected(
                    "canonical Policy owner snapshot schema is invalid".to_owned(),
                )
            })?;
        let canonical_owner = canonical_json_bytes(&owner).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical Policy owner snapshot encoding failed: {error}"
            ))
        })?;
        let snapshot_bytes = canonical_json_bytes(&owner.snapshot).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical Policy snapshot encoding failed: {error}"
            ))
        })?;
        owner.snapshot.validate().map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical Policy owner snapshot is invalid: {error}"
            ))
        })?;
        if canonical_owner != record.payload
            || owner.state_fence != *state_fence
            || owner.revision != record.revision
            || owner.revision == 0
            || owner.snapshot.state_fence != *state_fence
            || owner.snapshot.revision.value() != owner.revision
            || owner.policy_digest != sha256_hex(&snapshot_bytes)
            || owner.policy_digest.len() != 64
            || !owner
                .policy_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok(owner.snapshot)
    }

    /// Reads the canonical owner and Durable Job inputs for one `UserAutomation`
    /// preflight at a single Store State Fence. This remains a mechanical
    /// Kernel join: payloads stay opaque, but Store record identity, schema,
    /// canonical bytes, and any embedded fence must agree before the caller
    /// can use the readback as preflight evidence.
    async fn read_user_automation_preflight_owner_snapshot(
        &self,
        state_fence: &StateFence,
    ) -> Result<StoreRecoverySnapshot, UserAutomationRuntimeError> {
        state_fence
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let records = ["config", "policy", "task", "skill", "module_registry"]
            .into_iter()
            .map(|key| {
                RecoveryRecordKey::new("owner", key)
                    .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_records = records.iter().cloned().collect::<BTreeSet<_>>();
        let request = StoreRecoveryRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            state_fence: state_fence.clone(),
            records,
            include_receipts: false,
            include_jobs: true,
        };
        let recovery = self
            .recovery(request)
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        recovery
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let observed_records = recovery
            .owner_records
            .iter()
            .map(RecoveryRecord::record_key)
            .collect::<BTreeSet<_>>();
        if recovery.state_fence != *state_fence
            || recovery.canonical_scope.state_fence != *state_fence
            || recovery.owner_records.len() != expected_records.len()
            || observed_records != expected_records
            || !recovery.receipts.is_empty()
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        for record in &recovery.owner_records {
            Self::validate_user_automation_preflight_record(record, state_fence, true)?;
        }
        for record in &recovery.job_records {
            Self::validate_user_automation_preflight_record(record, state_fence, false)?;
        }
        Ok(recovery)
    }

    /// Validates one preflight recovery record as opaque canonical bytes.
    ///
    /// Owner records must additionally carry the Governor owner snapshot
    /// schema; every record must be canonical JSON and every embedded fence
    /// must equal the request fence. Payloads are never interpreted here: the
    /// policy snapshot decoder above is the only typed consumer.
    fn validate_user_automation_preflight_record(
        record: &RecoveryRecord,
        state_fence: &StateFence,
        owner_record: bool,
    ) -> Result<(), UserAutomationRuntimeError> {
        record
            .validate()
            .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
        if record.state_fence != *state_fence
            || (owner_record && record.schema != eliot_store_api::OWNER_SNAPSHOT_SCHEMA)
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let payload: serde_json::Value = serde_json::from_slice(&record.payload).map_err(|_| {
            UserAutomationRuntimeError::Rejected(
                "canonical UserAutomation preflight owner payload is invalid JSON".to_owned(),
            )
        })?;
        let canonical = canonical_json_bytes(&payload).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical UserAutomation preflight owner encoding failed: {error}"
            ))
        })?;
        if canonical != record.payload {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Self::validate_embedded_user_automation_fences(&payload, state_fence)
    }

    /// Requires every embedded fence in one owner payload to equal the request
    /// fence, recursing through arrays and objects.
    fn validate_embedded_user_automation_fences(
        value: &serde_json::Value,
        expected: &StateFence,
    ) -> Result<(), UserAutomationRuntimeError> {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    Self::validate_embedded_user_automation_fences(value, expected)?;
                }
            }
            serde_json::Value::Object(fields) => {
                if let Some(fence_value) = fields.get("state_fence") {
                    let observed: StateFence = serde_json::from_value(fence_value.clone())
                        .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
                    if &observed != expected {
                        return Err(UserAutomationRuntimeError::IdentityConflict);
                    }
                }
                for value in fields.values() {
                    Self::validate_embedded_user_automation_fences(value, expected)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Assembles the complete preflight projection for one committed `RunNow`
    /// occurrence from its owner members.
    ///
    /// Joins the canonical owner revision and live state, the B-owned policy
    /// snapshot, the committed Store receipt envelope, the complete owner
    /// execution view, and — when the owner reports `blocked_config` — the last
    /// owner-issued failure. The declared Skill/Tool closure and the delivery
    /// capability of the declared channels are readable from owners this
    /// boundary already holds, so an active deterministic revision assembles the
    /// complete projection. The one member with no Kernel-side owner — the
    /// observed provider/model/adapter fingerprint an agent revision needs —
    /// stays absent and is reported as the named missing owner rather than
    /// synthesized. No model, provider, scheduler, or notification call is
    /// reachable from this join.
    async fn assemble_run_now_preflight_projection(
        &self,
        sealed: &UserAutomationServiceRequest,
        owner: &UserAutomationOwnerSnapshot,
        invocation: &UserAutomationInvocation,
    ) -> Result<UserAutomationPreflightProjection, RunNowPreflightAssembly> {
        let state_fence = &sealed.context.state_fence;
        if invocation.automation_id != owner.automation_id
            || invocation.automation_revision != owner.revision.revision
        {
            return Err(RunNowPreflightAssembly::Unknown(
                "committed UserAutomation occurrence does not bind to the current owner revision"
                    .to_owned(),
            ));
        }
        let config_snapshot = self
            .read_user_automation_policy_snapshot(state_fence)
            .await
            .map_err(|error| RunNowPreflightAssembly::Unknown(error.to_string()))?;
        let source_receipt = self
            .read_run_now_source_envelope(sealed, invocation)
            .await?;
        let execution = self
            .read_user_automation_owner_execution_view(sealed, &owner.automation_id)
            .await
            .map_err(RunNowPreflightAssembly::Unknown)?;
        if execution.history_query_ref != owner.revision.execution_history_query_ref {
            return Err(RunNowPreflightAssembly::Unknown(
                "owner execution view does not bind to the current owner revision".to_owned(),
            ));
        }
        let failure = match owner.current_configuration_state {
            UserAutomationConfigurationState::BlockedConfig => Some(
                self.read_run_now_owner_failure(sealed, owner)
                    .await?
                    .ok_or_else(|| {
                        RunNowPreflightAssembly::Unavailable(
                            "the current owner configuration state is blocked_config but the \
                             owner retains no owner-issued failure projection, so no preflight \
                             decision can be reported"
                                .to_owned(),
                        )
                    })?,
            ),
            _ => None,
        };
        // Live evidence below the Kernel decoding boundary. The run-now path
        // issues no provider call before preflight, so the only honest provider
        // observation here is none — which is exactly what deterministic mode
        // requires (I11.12:49) and what an active agent revision still cannot
        // obtain at this boundary. That absence is not a missing Cargo edge this
        // crate could close: an observed route is a post-attempt runtime fact
        // (I3.4), so no observation of provider/model/adapter exists yet at this
        // point in the causal order anywhere in the tree, and the one route the
        // revision names is its own declared Human route policy, so admitting
        // against it would compare the policy with itself. The exact Tool
        // Definitions are the Tool-Definition half of the closure the canonical
        // owner revision already declares, so they are read from that same owner
        // instead of being left unattested. Delivery capability is a named
        // observation of the declared channels, not an inference from an adapter
        // result.
        let evidence = UserAutomationPreflightEvidence {
            observed_provider_fingerprint: None,
            trusted_tool_definition_refs: owner.revision.trusted_tool_definition_refs.clone(),
            delivery_available: Self::read_run_now_delivery_capability(&owner.revision),
            failure,
        };
        if owner.current_configuration_state == UserAutomationConfigurationState::Active
            && owner.revision.mode == UserAutomationExecutionMode::Agent
        {
            Self::require_run_now_agent_evidence(owner, &execution, &evidence)?;
        }
        // The schedule normalization envelope the revision names is owner
        // evidence over the compiled occurrence set, so it is read from the
        // owner that retained it beside the revision row rather than assembled
        // here. The read selects the envelope by its own content-derived
        // identity; assembly then re-checks that envelope's canonical bytes name
        // the compiled occurrence digest, so a self-asserted digest cannot
        // satisfy the binding. An owner that has retained no such envelope leaves
        // the occurrence unadmitted by name instead of substituting a receipt.
        let normalization_receipts = select_retained_normalization_receipts(state_fence, owner)?;
        if normalization_receipts.is_empty() {
            return Err(RunNowPreflightAssembly::Unavailable(
                "no owner-issued schedule normalization receipt envelope is retained under this \
                 State Fence for the receipt identity the immutable revision names, so the \
                 compiled occurrence set stays self-asserted and the committed occurrence is not \
                 admitted"
                    .to_owned(),
            ));
        }
        UserAutomationPreflightProjection::assemble(&UserAutomationPreflightAssembly {
            revision: &owner.revision,
            configuration_state: owner.current_configuration_state,
            config_snapshot: &config_snapshot,
            source_receipt: &source_receipt,
            normalization_receipts: &normalization_receipts,
            execution: &execution,
            invocation,
            request_metadata: &sealed.context,
            evidence: &evidence,
        })
        .map_err(|error| RunNowPreflightAssembly::Unknown(error.to_string()))
    }

    /// Assembles the complete owner-issued preflight projection for one due
    /// authenticated scheduled wake from the same live owners
    /// [`Self::assemble_run_now_preflight_projection`] reads.
    ///
    /// `sealed` is the owner read this leg issues under: it reuses the carrier's
    /// admitted parent identity for the `Status` execution projection, so this
    /// read mints no canonical identity and issues no transition.
    async fn due_wake_preflight_projection(
        &self,
        sealed: &UserAutomationServiceRequest,
        request: &UserAutomationRuntimeAdmission,
        resolution: &UserAutomationDueWakeResolution,
    ) -> Result<UserAutomationPreflightProjection, UserAutomationRuntimeError> {
        let state_fence = &sealed.context.state_fence;
        let owner = self
            .read_user_automation_owner(&UserAutomationOwnerLookup {
                automation_id: resolution.revision.automation_id.clone(),
                requested_revision: resolution.revision.revision.clone(),
                authenticated_principal: request.authenticated_principal.clone(),
                state_fence: state_fence.clone(),
            })
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        // The resolution was made against an earlier read of the same owner, and
        // the projection below is assembled from this one. Comparing the two
        // immutable revisions by content is what proves they are the same
        // document rather than two reads that happened to agree on a selector.
        if owner.automation_id != resolution.revision.automation_id
            || owner.revision != resolution.revision
            || owner.revision.owner_principal != request.authenticated_principal
            || owner.state_fence != *state_fence
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        // `resolve_due_wake` refused every state that admits no occurrence, so
        // this read only has to prove it still reads the same admitted state.
        // Anything else is a refusal the deterministic preflight re-derives,
        // not one asserted here.
        let config_snapshot = self
            .read_user_automation_policy_snapshot(state_fence)
            .await?;
        // This read refuses rather than answering "no admitted job" when the
        // owner cannot prove the occurrence denominator complete, and that refusal
        // carries the durable query handle the caller needs to finish enumerating
        // it. Reporting it as an unreachable owner would answer the same question
        // the run-now leg answers as `unknown`.
        let execution = self
            .read_user_automation_owner_execution_view(sealed, &owner.automation_id)
            .await
            .map_err(UserAutomationRuntimeError::UnknownOutcome)?;
        if execution.history_query_ref != owner.revision.execution_history_query_ref {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let normalization_receipts = select_retained_normalization_receipts(state_fence, &owner)
            .map_err(|assembly| match assembly {
                RunNowPreflightAssembly::Unknown(reason) => {
                    UserAutomationRuntimeError::UnknownOutcome(reason)
                }
                RunNowPreflightAssembly::Unavailable(reason) => {
                    UserAutomationRuntimeError::Unavailable(reason)
                }
            })?;
        if normalization_receipts.is_empty() {
            return Err(UserAutomationRuntimeError::Unavailable(
                "no owner-issued schedule normalization receipt envelope is retained under this \
                 State Fence for the receipt identity the immutable revision names, so the \
                 compiled occurrence set stays self-asserted and the due occurrence is not \
                 admitted"
                    .to_owned(),
            ));
        }
        // The same live evidence the run-now assembly reads. A due wake issues no
        // provider call before preflight either, so the only honest provider
        // observation here is none - which is what deterministic mode requires
        // (I11.12:49) and what an agent revision still cannot obtain at this
        // boundary for the same reason and against the same named owner
        // `Self::require_run_now_agent_evidence` records. There is no owner-issued
        // blocked failure to carry either: `resolve_due_wake` refuses every
        // configuration state that is not `Active`, so
        // `UserAutomationPreflightProjection::assemble` never sees a
        // `BlockedConfig` projection on this leg. The assembly itself refuses an
        // active revision whose declared closure, delivery capability, or
        // provider policy these members do not satisfy, so no caller-side
        // re-derivation of that decision is added here.
        let evidence = UserAutomationPreflightEvidence {
            observed_provider_fingerprint: None,
            trusted_tool_definition_refs: owner.revision.trusted_tool_definition_refs.clone(),
            delivery_available: Self::read_run_now_delivery_capability(&owner.revision),
            failure: None,
        };
        UserAutomationPreflightProjection::assemble(&UserAutomationPreflightAssembly {
            revision: &owner.revision,
            configuration_state: owner.current_configuration_state,
            config_snapshot: &config_snapshot,
            source_receipt: &request.preflight.source_receipt,
            normalization_receipts: &normalization_receipts,
            execution: &execution,
            invocation: &resolution.invocation,
            request_metadata: &request.context,
            evidence: &evidence,
        })
        .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))
    }

    /// Runs one due authenticated scheduled wake through the same deterministic
    /// execution join the committed `RunNow` occurrence crosses (issue #2806
    /// items 5, A6 and W5).
    ///
    /// A scheduled occurrence owns no committed Store operation of its own, so
    /// [`Self::run_now_handoff`] cannot serve it and neither can
    /// [`Self::assemble_run_now_preflight_projection`], whose `source_receipt` is
    /// the committed manual-nonce receipt a scheduled wake never has. The
    /// projection is therefore assembled by [`Self::due_wake_preflight_projection`]
    /// from the live owners, with the one member this leg does not mint named
    /// there.
    ///
    /// The call then crosses
    /// [`UserAutomationService::execute_occurrence_with_durable_job`] - the same
    /// join `run_now_handoff` composes, reached here through its occurrence entry
    /// point. That join is what makes this leg honest: it runs the complete
    /// occurrence-denominator refusal and the owner's own
    /// [`UserAutomationPreflightProjection::preflight`] decision immediately
    /// before it builds the admission it sends. Reaching the Durable Job owner
    /// with only the ingress revalidation would admit an occurrence whose
    /// unresolved prior effects, overlap policy, declared closure, or provider
    /// policy were never decided, which is exactly the blind rerun I11.12:59 and
    /// I14.21 forbid.
    ///
    /// The `WakeIntent` is the schedule owner's own journal record, read back by
    /// the caller over the authenticated channel. It is inert evidence of a
    /// published wake and grants no execution authority by itself; the
    /// deterministic preflight is what admits this occurrence.
    pub async fn due_wake_execution_join<R>(
        &self,
        request: &UserAutomationRuntimeAdmission,
        resolution: &UserAutomationDueWakeResolution,
        wake_intent: WakeIntent,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationRuntimeError>
    where
        R: UserAutomationRuntimePort + ?Sized,
    {
        // I14.16 step 4 (issue #1953, map item 2): the occurrence execution
        // below commits through the borrowed client, which bypasses
        // `Self::apply`, so the join refuses a `shadow_no_authority`
        // candidate itself. `Rejected` proves nothing was admitted.
        self.refuse_shadow_mutation()
            .map_err(UserAutomationRuntimeError::Rejected)?;
        // The owner read this leg issues under reuses the carrier's admitted
        // parent identity for a `Status` execution projection, so it mints no
        // canonical identity and issues no transition.
        let sealed = UserAutomationServiceRequest {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal.clone(),
            identity: request.identity.clone(),
            intent: UserAutomationOperatorIntent {
                intent_id: format!(
                    "{}:due-wake-execution-view",
                    request.identity.operation_id.as_str()
                ),
                principal_ref: request.authenticated_principal.clone(),
                state_fence: request.context.state_fence.clone(),
                operation: UserAutomationOperation::Status {
                    automation_id: resolution.revision.automation_id.clone(),
                },
            },
        };
        let projection = self
            .due_wake_preflight_projection(&sealed, request, resolution)
            .await?;
        let durable_job = Self::owner_issued_durable_job_material(
            &sealed,
            &resolution.invocation,
            &projection,
            wake_intent.clone(),
        );
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(self));
        let service = UserAutomationService::new(&store);
        let occurrence = UserAutomationExecutionRequest {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal.clone(),
            identity: request.identity.clone(),
            invocation: resolution.invocation.clone(),
            projection,
            wake_intent,
        };
        // The two joins are different future types, so each arm owns its own
        // awaited value. The material arm is polled through one box for the same
        // reason `join_run_now_occurrence` boxes its own: `from_admitted_occurrence`
        // holds a whole canonical-JSON K0 `JobSubmission` and its digest inputs on
        // the stack, and the transient allocation is released as soon as the
        // owner's answer is back, so this contour's future stays bounded.
        let outcome = match durable_job {
            Some(material) => {
                Box::pin(service.execute_occurrence_with_durable_job(occurrence, material, runtime))
                    .await
            }
            None => Box::pin(service.execute_occurrence(occurrence, runtime)).await,
        };
        outcome.map_err(Self::due_wake_execution_error)
    }

    /// Maps one due-wake execution failure onto the runtime's typed phases.
    ///
    /// The declared occurrence denominator is unproven, so that answer is unknown
    /// and the durable query handle the obligation carries stays the caller's
    /// route to finish enumerating it. Reporting it as a refusal would claim the
    /// owner decided something it did not. Every other join failure is a decided
    /// answer about this occurrence, before any owner effect.
    fn due_wake_execution_error(error: UserAutomationExecutionError) -> UserAutomationRuntimeError {
        match error {
            UserAutomationExecutionError::Runtime(runtime) => runtime,
            UserAutomationExecutionError::OccurrenceDenominatorIncomplete(obligation) => {
                UserAutomationRuntimeError::UnknownOutcome(format!(
                    "occurrence {} has no owner-proven complete occurrence denominator: \
                     operation_ref={} cause={:?} read_revision={} \
                     denominator_query_ref={}",
                    obligation.occurrence_id,
                    obligation.operation_ref,
                    obligation.cause,
                    obligation.read_revision,
                    obligation
                        .denominator_query_ref
                        .as_deref()
                        .unwrap_or("<none>"),
                ))
            }
            decided => UserAutomationRuntimeError::Rejected(decided.to_string()),
        }
    }

    /// Requires the live evidence an active **agent** revision still lacks.
    ///
    /// Deterministic mode reaches the Durable Job owner from the revision and
    /// the named delivery observation alone, so this arm exists only for the
    /// one member no Kernel-side route can produce: the observed
    /// provider/model/adapter fingerprint.
    ///
    /// **The invariant this arm protects.** I11.12:47 requires unexpected
    /// provider/model drift to fail closed "unless the Human policy already
    /// admitted the observed compatible set", and forbids silent route
    /// substitution. The check can only mean that if the value compared against
    /// the admitted set came from outside that set, so the observation must be
    /// independent of `provider_policy` by construction.
    ///
    /// **Why no observation can be produced here.** The only provider-route
    /// observations in the tree (`ObservedRoute`, `ActualRouteReceipt`,
    /// `effective_route_key`, `RouteFingerprint`) are post-attempt runtime
    /// facts: the Governor route registry stores requested and observed routes
    /// separately and refuses any receipt naming no evidence-bearing runtime
    /// handshake, and a configured route's provider/model field is documented
    /// as a request. Before the first model call there is therefore no
    /// observation of provider/model/adapter to read anywhere. The two
    /// substitutes are both provably wrong here. Reading the configured route
    /// the revision names resolves nothing — the Kernel submits only the
    /// opaque `route_class` label and route selection stays with its own owner —
    /// and even if it resolved, that route is chosen by the same Human route
    /// policy this revision declares, so `admits` would compare the policy
    /// against itself and every provider would pass. Reading the first member
    /// of `provider_policy` is the same comparison spelled out.
    ///
    /// **The owner that must produce it.** The route/runtime owner that performs
    /// the handshake — `CapabilityRouteRegistry` in `eliot-governor`, driven from
    /// the eliotd route-receipt contour — must publish the observed
    /// provider/model/adapter for this exact pending occurrence *before* the
    /// Durable Job admission, over an authenticated leg this boundary reads.
    /// The Governor registry is not an edge this crate may take: it is a runtime
    /// root above the Kernel (I2.3 dependency direction is outward only), and
    /// the Store recovery snapshot this boundary already reads carries no route
    /// owner record, so there is no such read to widen. Until that publication
    /// exists, the absence is reported with this exact owner instead of being
    /// filled with the policy's own expectation, which would make drift
    /// undetectable while still appearing to be enforced.
    ///
    /// The unresolved-prior-effect refusal stays here because it is an
    /// execution fact, not an evidence fact: I14.21 reconciliation owns that
    /// disposition for every mode.
    fn require_run_now_agent_evidence(
        owner: &UserAutomationOwnerSnapshot,
        execution: &eliot_kernel_core::user_automation::UserAutomationExecutionProjection,
        evidence: &UserAutomationPreflightEvidence,
    ) -> Result<(), RunNowPreflightAssembly> {
        if execution.requires_reconciliation() {
            return Err(RunNowPreflightAssembly::Unavailable(
                "the committed occurrence has unresolved prior effects: their I14.21 \
                 disposition belongs to the reconciliation owner, so no new admission is \
                 attempted and the occurrence stays unadmitted"
                    .to_owned(),
            ));
        }
        if evidence.trusted_tool_definition_refs.is_empty() {
            return Err(RunNowPreflightAssembly::Unavailable(
                "the current owner revision declares no trusted Tool Definition revisions, \
                 so the declared dependency closure is empty and the committed occurrence \
                 stays unadmitted"
                    .to_owned(),
            ));
        }
        if !evidence.delivery_available {
            return Err(RunNowPreflightAssembly::Unavailable(
                "the declared delivery target is not currently capable: no interactive user \
                 session backs its native-toast channel, so the committed occurrence stays \
                 unadmitted"
                    .to_owned(),
            ));
        }
        if !owner
            .revision
            .provider_policy
            .admits(evidence.observed_provider_fingerprint.as_ref())
        {
            return Err(RunNowPreflightAssembly::Unavailable(
                "no observed provider/model/adapter fingerprint exists for this occurrence: the \
                 only provider-route observations are post-attempt runtime facts that \
                 CapabilityRouteRegistry refuses to record without a handshake, this boundary \
                 submits only the opaque route_class label and reads no route owner record, and \
                 the revision's own route policy is exactly what is being checked, so an active \
                 agent revision whose policy admits only an observed compatible set stays \
                 unadmitted until the route owner publishes that observation for this pending \
                 occurrence"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Observes whether the declared delivery target is currently capable.
    ///
    /// I11.12:43 makes delivery capability a preflight input, and
    /// I11.12:61 routes delivery through the declared target and the canonical
    /// outbox. Of the four canonical channels only
    /// [`DeliveryChannel::NativeToast`] is gated on a live interactive user
    /// session: the Control Board is a persistent in-process inbox projection,
    /// and the Windows Event Log and recovery-fallback routes are owned by
    /// services that run without one. `eliot_platform_windows::
    /// interactive_user_session_available` is exactly that named observation —
    /// it "exposes" the condition "so a delivery caller can name the no-session
    /// condition honestly instead of inferring it from a generic adapter
    /// failure" — and `eliot-platform-windows` is already a production
    /// dependency of this crate, so no new edge is introduced.
    ///
    /// The result is never defaulted to `true`: a declared `NativeToast` target
    /// read from a session with no interactive user reports the capability it
    /// actually observed. `ASSUMPTION:` a Kernel daemon running as a service in
    /// session 0 observes `false` there, which is honest for that process even
    /// when a user is logged on elsewhere; the `ControlBoard` channel is
    /// unaffected and is the channel a headless daemon can still deliver to.
    fn read_run_now_delivery_capability(revision: &UserAutomationRevision) -> bool {
        !revision
            .delivery_target
            .channels
            .contains(&DeliveryChannel::NativeToast)
            || eliot_platform_windows::interactive_user_session_available()
    }

    /// Reads the committed `RunNow` Store receipt envelope that sources one
    /// occurrence.
    ///
    /// The invocation provenance must bind the sealed parent identity exactly;
    /// the receipt must be committed under the request fence and carry its
    /// reconciliation envelope. A receipt the owner cannot prove is an unknown
    /// disposition, never a missing fact.
    async fn read_run_now_source_envelope(
        &self,
        sealed: &UserAutomationServiceRequest,
        invocation: &UserAutomationInvocation,
    ) -> Result<eliot_receipts::ReceiptEnvelope, RunNowPreflightAssembly> {
        let unknown = |reason: &str| RunNowPreflightAssembly::Unknown(reason.to_owned());
        let provenance = invocation
            .require_run_now_provenance(&sealed.context.state_fence)
            .map_err(|error| unknown(&error.to_string()))?;
        if provenance.operation_id != sealed.identity.operation_id
            || provenance.idempotency_key != sealed.identity.idempotency_key
            || provenance.canonical_request_hash != sealed.identity.canonical_request_hash
        {
            return Err(unknown(
                "committed UserAutomation occurrence does not bind to the sealed parent identity",
            ));
        }
        let receipt = self
            .receipt(
                &sealed.context.state_fence,
                sealed.identity.operation_id.clone(),
            )
            .await
            .map_err(RunNowPreflightAssembly::Unknown)?
            .ok_or_else(|| unknown("canonical UserAutomation Store receipt is not retained"))?;
        receipt
            .validate()
            .map_err(|error| unknown(&error.to_string()))?;
        if receipt.operation_id != sealed.identity.operation_id
            || receipt.idempotency_key != sealed.identity.idempotency_key
            || receipt.canonical_request_hash != sealed.identity.canonical_request_hash
            || receipt.state_fence != sealed.context.state_fence
        {
            return Err(unknown(
                "canonical UserAutomation Store receipt does not bind to the sealed parent identity",
            ));
        }
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(unknown(
                "canonical UserAutomation Store operation is not committed",
            ));
        }
        receipt
            .require_reconciliation_envelope()
            .cloned()
            .map_err(|error| unknown(&error.to_string()))
    }

    /// Reads the last owner-issued failure projection for one automation.
    ///
    /// The read reuses the sealed parent identity and issues no transition, so
    /// it mints no canonical identity. A failure the owner cannot prove is an
    /// unknown disposition; no failure content is synthesized.
    async fn read_run_now_owner_failure(
        &self,
        sealed: &UserAutomationServiceRequest,
        owner: &UserAutomationOwnerSnapshot,
    ) -> Result<
        Option<eliot_kernel_core::user_automation::UserAutomationFailureProjection>,
        RunNowPreflightAssembly,
    > {
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(self));
        let response = Box::pin(UserAutomationService::new(&store).dispatch(
            UserAutomationServiceRequest {
                context: sealed.context.clone(),
                authenticated_principal: sealed.authenticated_principal.clone(),
                identity: sealed.identity.clone(),
                intent: UserAutomationOperatorIntent {
                    intent_id: format!(
                        "{}:run-now-preflight-last-failure",
                        sealed.identity.operation_id.as_str()
                    ),
                    principal_ref: sealed.authenticated_principal.clone(),
                    state_fence: sealed.context.state_fence.clone(),
                    operation: UserAutomationOperation::InspectLastFailure {
                        automation_id: owner.automation_id.clone(),
                    },
                },
            },
        ))
        .await
        .map_err(|error| RunNowPreflightAssembly::Unknown(error.to_string()))?;
        match response.outcome {
            UserAutomationStoreOutcome::Read {
                result:
                    UserAutomationReadResult::InspectLastFailure {
                        automation_id,
                        revision,
                        failure,
                    },
            } => {
                if revision.revision != owner.revision.revision
                    || revision.automation_id != owner.automation_id
                    || automation_id != owner.automation_id
                {
                    return Err(RunNowPreflightAssembly::Unknown(
                        "owner failure read does not bind to the current owner revision".to_owned(),
                    ));
                }
                Ok(failure.map(|failure| *failure))
            }
            _ => Err(RunNowPreflightAssembly::Unknown(
                "owner failure read did not return a failure projection".to_owned(),
            )),
        }
    }

    /// Seals the canonical request hash over the exact prepared transition.
    async fn seal_user_automation_operation<C: CanonicalStoreClient>(
        &self,
        store: &CanonicalUserAutomationStore<C>,
        request: UserAutomationServiceRequest,
    ) -> Result<UserAutomationServiceRequest, String> {
        let mut unsealed = request.clone();
        unsealed.identity.canonical_request_hash = String::new();
        let unsealed_store_request = UserAutomationStoreRequest {
            context: unsealed.context.clone(),
            authenticated_principal: unsealed.authenticated_principal.clone(),
            identity: unsealed.identity.clone(),
            intent: unsealed.intent.clone(),
        };
        let (transition, _manifest_digest) = store
            .build_transition(&unsealed_store_request)
            .await
            .map_err(|error| error.to_string())?;
        let view = CanonicalRequestView::from_apply(
            &unsealed_store_request.context,
            &transition,
            &[],
            &[],
        );
        let mut sealed = request;
        sealed.identity.canonical_request_hash =
            canonical_request_hash(&view).map_err(|error| error.to_string())?;
        Ok(sealed)
    }

    /// Routes one committed operator operation to its runtime handoff phases.
    ///
    /// Every leg that may issue an owner effect retains its obligation in the
    /// composition-bound durable outbox first and appends it to `obligations`,
    /// so the parent transition reports exactly the obligations it retained.
    ///
    /// Classification and revalidation (issue #2806 item 2): read-only answers
    /// own no handoff; a changed or rejected configuration never reaches this
    /// router because the Store dispatch returned no committed outcome. Before
    /// each owner call the leg re-proves principal, revision, State Fence, and
    /// owner denominator against the live owner: `RunNow` reads back the exact
    /// committed invocation and the current owner revision, `Remove`/`Pause`/
    /// superseding-`Edit` enumerate and cancel through the complete fail-closed
    /// owner execution view, and the horizon publication revalidates the
    /// compiled slice against the live owner before it is issued.
    async fn user_automation_runtime_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        if configuration.read_result().is_some() {
            return Ok((not_applicable_wake(), not_applicable_execution()));
        }
        match &sealed.intent.operation {
            UserAutomationOperation::RunNow {
                automation_id,
                automation_revision,
                ..
            } => {
                self.run_now_handoff(
                    sealed,
                    configuration,
                    runtime,
                    automation_id,
                    automation_revision,
                )
                .await
            }
            UserAutomationOperation::Remove { .. } => {
                self.remove_handoff(sealed, configuration, runtime, obligations)
                    .await
            }
            UserAutomationOperation::Pause { .. } => {
                self.pause_handoff(sealed, configuration, runtime, obligations)
                    .await
            }
            UserAutomationOperation::Edit { .. } => {
                self.superseding_edit_handoff(sealed, configuration, runtime, obligations)
                    .await
            }
            _ => Ok((not_applicable_wake(), not_applicable_execution())),
        }
    }

    /// Completes the wake handoff of a committed `Remove` against the wake owner.
    ///
    /// This is the wake-cancellation half of the complete owner view contract
    /// (issue #2808, item 8). The retirement is already committed when this leg
    /// runs, so it never refuses the retirement and never rewrites, drops, or
    /// reorders its obligations: the admitted Durable Job references and the
    /// immutable execution history stay in the committed revision, and the exact
    /// unresolved reconciliation references stay durable in the canonical owner
    /// and remain readable through the same `Status`/`History` reads.
    ///
    /// The leg enumerates the exact owner-issued pending wake targets of the
    /// committed revision from the wake owner itself, then hands the retirement
    /// and the cancellation to
    /// [`UserAutomationService::remove_and_cancel_with_targets`], which reads the
    /// same complete, fail-closed owner execution view the execution-admission
    /// boundary reads and refuses the cancellation when that denominator is not
    /// owner-proven complete. Nothing here derives a wake identity, parses a
    /// wake reason, or reports a hard-coded cancellation set: the cancelled
    /// identities are exactly what the wake owner returned.
    ///
    /// A target list the wake owner cannot prove is reported as an unresolved
    /// wake phase, and so is a cancellation whose answer is absent, empty, or
    /// unknown for a non-empty proven target set. The parent transition then
    /// yields a recovery directive instead of a known success, and the retired
    /// automation keeps its not-yet-admitted wakes as an explicit open
    /// obligation rather than as a proven absence.
    ///
    /// A wake owner that reads its own journal for every committed occurrence and
    /// definitively retains no unadmitted wake is the opposite case: that is a
    /// complete negative answer, so the phase is resolved, no cancellation is
    /// requested, and the retirement reports a known result instead of staying
    /// reconciling forever. Only an owner that could not answer produces an
    /// unknown.
    ///
    /// Once a non-empty exact target set is owner-proven, the cancellation is an
    /// owner effect and is retained in the composition-bound durable outbox
    /// before it is issued. Its subject identities are the retired revision's own
    /// committed occurrence denominator, which is immutable, so a replay of the
    /// same parent operation finds the same retained record: an answered
    /// cancellation is served from that record instead of re-issued, and a
    /// cancellation whose effect may already have been issued is reported as
    /// reconciling under its original owner operation identity rather than
    /// repeated, because a later read of the committed retirement is empty of
    /// the cancelled wakes.
    async fn remove_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let UserAutomationOperation::Remove {
            automation_id,
            automation_revision,
        } = &sealed.intent.operation
        else {
            return Err("the remove handoff requires remove".to_owned());
        };
        let revision = committed_retirement_revision(
            configuration,
            Some(automation_id),
            automation_revision,
            UserAutomationConfigurationState::Retired,
        )?;
        // The revision is immutable, so this deterministic recompile of its own
        // normalized denominator is the exact set the wake walk below asks about,
        // and it is also the exact immutable subject set the durable cancellation
        // obligation is bound to.
        let committed_occurrence_ids = revision
            .compile_occurrence_identities()
            .map_err(|error| error.to_string())?
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        let execution = not_applicable_execution();
        let Some(runtime) = runtime else {
            return Ok((
                UserAutomationWakePhase::Unavailable {
                    reason: unproven_wake_channel_reason(),
                },
                execution,
            ));
        };
        self.continue_retirement_wake_handoff(
            OwnerWakeHandoffKind::Remove,
            sealed,
            &revision,
            &committed_occurrence_ids,
            runtime,
            obligations,
        )
        .await
    }

    /// Completes the wake handoff of a committed `Pause` against the wake owner.
    ///
    /// This is the same affected-revision contour as [`Self::remove_handoff`]:
    /// the pause is already committed when this leg runs, so it never refuses
    /// the pause itself. It enumerates the exact owner-issued pending wake
    /// targets of the committed paused revision from the wake owner itself and
    /// cancels exactly those targets through
    /// [`UserAutomationService::pause_and_cancel_with_targets`], which replays
    /// the pause under the same admitted identity and shares the complete,
    /// fail-closed owner execution view. An unproven target list, or a
    /// cancellation whose answer is absent, empty, or unknown for a non-empty
    /// proven target set, stays an unresolved wake phase with a recovery
    /// directive instead of a known success.
    async fn pause_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let UserAutomationOperation::Pause {
            automation_id,
            automation_revision,
        } = &sealed.intent.operation
        else {
            return Err("the pause handoff requires pause".to_owned());
        };
        let revision = committed_retirement_revision(
            configuration,
            Some(automation_id),
            automation_revision,
            UserAutomationConfigurationState::Paused,
        )?;
        // The revision is immutable, so this deterministic recompile of its own
        // normalized denominator is the exact set the wake walk below asks about,
        // and it is also the exact immutable subject set the durable cancellation
        // obligation is bound to.
        let committed_occurrence_ids = revision
            .compile_occurrence_identities()
            .map_err(|error| error.to_string())?
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        let execution = not_applicable_execution();
        let Some(runtime) = runtime else {
            return Ok((
                UserAutomationWakePhase::Unavailable {
                    reason: unproven_wake_channel_reason(),
                },
                execution,
            ));
        };
        self.continue_retirement_wake_handoff(
            OwnerWakeHandoffKind::Pause,
            sealed,
            &revision,
            &committed_occurrence_ids,
            runtime,
            obligations,
        )
        .await
    }

    /// Completes the wake handoff of a committed superseding `Edit` against the
    /// wake owner (issue #2806 item 6).
    ///
    /// The affected revision is the immutable predecessor, not the committed
    /// document: the new revision keeps its own horizon (published by
    /// [`Self::publish_schedule_horizon`]), while the predecessor's
    /// not-yet-admitted wakes are invalidated. The predecessor denominator is
    /// the edit intent's own previous revision, re-checked here against the
    /// committed new revision through the same supersession validation the
    /// Store admission ran, and bound to the live owner read proving the new
    /// revision is still current under this principal and fence. Enumeration
    /// and cancellation then follow the same affected-revision contour as
    /// remove and pause, cancelling only owner-issued targets through
    /// [`UserAutomationService::edit_and_cancel_with_targets`].
    async fn superseding_edit_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let UserAutomationOperation::Edit {
            previous_revision,
            revision,
            ..
        } = &sealed.intent.operation
        else {
            return Err("the superseding-edit handoff requires edit".to_owned());
        };
        let Some(UserAutomationMutationResult::Revision {
            revision: committed,
            ..
        }) = configuration.mutation_result()
        else {
            return Err("superseding edit did not return a canonical revision".to_owned());
        };
        if committed != revision.as_ref() {
            return Err(
                "committed UserAutomation revision does not match the superseding edit request"
                    .to_owned(),
            );
        }
        committed
            .validate_supersedes(previous_revision)
            .map_err(|error| error.to_string())?;
        // The predecessor document is immutable, but the link to it is only as
        // current as this owner read: it proves the committed new revision is
        // still the current one under this principal and fence, so this leg
        // never cancels predecessor wakes for an edit that a newer transition
        // already superseded again.
        let owner = self
            .read_user_automation_owner(&UserAutomationOwnerLookup {
                automation_id: revision.automation_id.clone(),
                requested_revision: revision.revision.clone(),
                authenticated_principal: sealed.authenticated_principal.clone(),
                state_fence: sealed.context.state_fence.clone(),
            })
            .await?;
        if owner.revision != *revision.as_ref() {
            return Err(
                "committed UserAutomation revision does not match the current owner revision"
                    .to_owned(),
            );
        }
        let predecessor_occurrence_ids = previous_revision
            .compile_occurrence_identities()
            .map_err(|error| error.to_string())?
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        let execution = not_applicable_execution();
        let Some(runtime) = runtime else {
            return Ok((
                UserAutomationWakePhase::Unavailable {
                    reason: unproven_wake_channel_reason(),
                },
                execution,
            ));
        };
        self.continue_retirement_wake_handoff(
            OwnerWakeHandoffKind::SupersedingEdit,
            sealed,
            previous_revision,
            &predecessor_occurrence_ids,
            runtime,
            obligations,
        )
        .await
    }

    async fn continue_retirement_wake_handoff<R>(
        &self,
        handoff: OwnerWakeHandoffKind,
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        committed_occurrence_ids: &[String],
        runtime: &R,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let execution = not_applicable_execution();
        let committed_occurrences = committed_occurrence_ids.len();
        // Legacy unqualified cancellation records predate the enumeration
        // receipt binding and belong to the remove contour only: pause and
        // superseding-edit obligations always carry their receipt, so there is
        // no legacy record to guard for them.
        if handoff == OwnerWakeHandoffKind::Remove
            && let Err(reason) = self.ensure_legacy_cancellation_unqualified(
                sealed,
                revision,
                committed_occurrence_ids,
                obligations,
            )
        {
            return Ok(unresolved_retirement_phases(reason, execution));
        }
        let enumeration_request = match retirement_wake_enumeration_request(
            revision,
            &sealed.context,
            &sealed.authenticated_principal,
            &sealed.identity,
        ) {
            Ok(request) => request,
            Err(error) => return Err(error.to_string()),
        };
        let mut receipt_obligation = match Self::retirement_enumeration_obligation(
            sealed,
            revision,
            committed_occurrence_ids,
        ) {
            Ok(obligation) => obligation,
            Err(reason) => return Ok(unresolved_retirement_phases(reason, execution)),
        };
        let receipt = match self
            .read_or_retain_retirement_enumeration_receipt(
                sealed,
                revision,
                &enumeration_request,
                &mut receipt_obligation,
                runtime,
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(reason) => {
                obligations.push(receipt_obligation);
                return Ok(unresolved_retirement_phases(reason, execution));
            }
        };
        let targets = match receipt.cancellation_targets() {
            Ok(targets) => targets,
            Err(error) => {
                let reason = error.to_string();
                obligations.push(receipt_obligation);
                return Ok(unresolved_retirement_phases(reason, execution));
            }
        };
        if targets.is_empty() {
            obligations.push(receipt_obligation);
            let noun = handoff.noun();
            return Ok((
                UserAutomationWakePhase::NotApplicable {
                    reason: format!(
                        "the Host owner receipt accounts for all {} committed occurrences of {} \
                         revision {} and proves there is no pending target to cancel",
                        committed_occurrences, noun, revision.revision
                    ),
                },
                execution,
            ));
        }

        let mut obligation = match Self::retirement_cancellation_obligation_with_receipt(
            sealed,
            revision,
            committed_occurrence_ids,
            receipt.clone(),
        ) {
            Ok(obligation) => obligation,
            Err(reason) => {
                obligations.push(receipt_obligation);
                return Ok(unresolved_retirement_phases(reason, execution));
            }
        };
        obligations.push(receipt_obligation);
        self.issue_retirement_cancellation(
            handoff,
            sealed,
            &mut obligation,
            (revision.clone(), targets, receipt),
            runtime,
            obligations,
        )
        .await
    }

    fn ensure_legacy_cancellation_unqualified(
        &self,
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        committed_occurrence_ids: &[String],
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(), String> {
        let mut legacy_obligation =
            Self::retirement_cancellation_obligation(sealed, revision, committed_occurrence_ids)?;
        match self.read_user_automation_obligation(&legacy_obligation) {
            RetainedObligationLookup::Absent => Ok(()),
            RetainedObligationLookup::Held(_) => {
                let reason = format!(
                    "legacy cancellation record for revision {} has no bound one-snapshot enumeration receipt; it remains unqualified and requires reconciliation under its original identity",
                    revision.revision
                );
                legacy_obligation.disposition =
                    UserAutomationRuntimeObligationDisposition::Reconciling {
                        reason: reason.clone(),
                    };
                obligations.push(legacy_obligation);
                Err(reason)
            }
            RetainedObligationLookup::Unreadable { reason } => {
                legacy_obligation.disposition =
                    UserAutomationRuntimeObligationDisposition::Unavailable {
                        reason: reason.clone(),
                    };
                obligations.push(legacy_obligation);
                Err(reason)
            }
        }
    }

    /// Reads or durably records the one Host enumeration receipt for a retired
    /// revision. A retained answer is validated against the current exact
    /// request, including State Fence; a replay under a different fence remains
    /// reconciling instead of being silently rebound to the new era.
    #[allow(
        clippy::too_many_lines,
        reason = "enumeration receipt validation and retention share one exact owner operation"
    )]
    async fn read_or_retain_retirement_enumeration_receipt<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        request: &crate::user_automation_execution::UserAutomationWakeEnumerationRequest,
        obligation: &mut UserAutomationRuntimeObligation,
        runtime: &R,
    ) -> Result<UserAutomationWakeEnumerationReceipt, String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        match self.read_user_automation_obligation(obligation) {
            RetainedObligationLookup::Held(RetainedUserAutomationObligation::Answered {
                result_response,
                ..
            }) => {
                let receipt = match decode_retained_wake_enumeration_receipt(
                    result_response,
                    request,
                    &revision.revision,
                    &obligation.owner_operation_id,
                ) {
                    Ok(receipt) => receipt,
                    Err(reason) => {
                        obligation.disposition =
                            UserAutomationRuntimeObligationDisposition::Reconciling {
                                reason: reason.clone(),
                            };
                        return Err(reason);
                    }
                };
                self.classify_enumeration_receipt(obligation, request, receipt, false)
            }
            RetainedObligationLookup::Held(RetainedUserAutomationObligation::Reconciling {
                reason,
            }) => {
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                    reason: reason.clone(),
                };
                Err(reason)
            }
            RetainedObligationLookup::Held(
                RetainedUserAutomationObligation::RetryAfterProvenNoSend,
            ) => {
                let reason =
                    "a cancellation retry claim cannot satisfy a wake-enumeration read".to_owned();
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                    reason: reason.clone(),
                };
                Err(reason)
            }
            RetainedObligationLookup::Unreadable { reason } => {
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Unavailable {
                    reason: reason.clone(),
                };
                Err(reason)
            }
            RetainedObligationLookup::Absent
            | RetainedObligationLookup::Held(RetainedUserAutomationObligation::Retained) => {
                match self.retain_user_automation_obligation(sealed, obligation) {
                    RetainedObligationLookup::Held(
                        RetainedUserAutomationObligation::Answered {
                            result_response, ..
                        },
                    ) => {
                        let receipt = match decode_retained_wake_enumeration_receipt(
                            result_response,
                            request,
                            &revision.revision,
                            &obligation.owner_operation_id,
                        ) {
                            Ok(receipt) => receipt,
                            Err(reason) => {
                                obligation.disposition =
                                    UserAutomationRuntimeObligationDisposition::Reconciling {
                                        reason: reason.clone(),
                                    };
                                return Err(reason);
                            }
                        };
                        self.classify_enumeration_receipt(obligation, request, receipt, false)
                    }
                    RetainedObligationLookup::Held(RetainedUserAutomationObligation::Retained) => {
                        self.enumerate_retirement_wakes_once(
                            sealed, revision, request, obligation, runtime,
                        )
                        .await
                    }
                    RetainedObligationLookup::Held(
                        RetainedUserAutomationObligation::Reconciling { reason },
                    ) => {
                        obligation.disposition =
                            UserAutomationRuntimeObligationDisposition::Reconciling {
                                reason: reason.clone(),
                            };
                        Err(reason)
                    }
                    RetainedObligationLookup::Held(
                        RetainedUserAutomationObligation::RetryAfterProvenNoSend,
                    ) => {
                        let reason =
                            "a cancellation retry claim cannot satisfy a wake-enumeration read"
                                .to_owned();
                        obligation.disposition =
                            UserAutomationRuntimeObligationDisposition::Reconciling {
                                reason: reason.clone(),
                            };
                        Err(reason)
                    }
                    RetainedObligationLookup::Unreadable { reason } => {
                        obligation.disposition =
                            UserAutomationRuntimeObligationDisposition::Unavailable {
                                reason: reason.clone(),
                            };
                        Err(reason)
                    }
                    RetainedObligationLookup::Absent => {
                        let reason = format!(
                            "the durable Host enumeration receipt obligation for revision {} disappeared before the owner read",
                            revision.revision
                        );
                        obligation.disposition =
                            UserAutomationRuntimeObligationDisposition::Unavailable {
                                reason: reason.clone(),
                            };
                        Err(reason)
                    }
                }
            }
        }
    }

    async fn enumerate_retirement_wakes_once<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        request: &crate::user_automation_execution::UserAutomationWakeEnumerationRequest,
        obligation: &mut UserAutomationRuntimeObligation,
        runtime: &R,
    ) -> Result<UserAutomationWakeEnumerationReceipt, String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        if let Err(reason) = self.mark_user_automation_obligation_admitted(obligation) {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.clone(),
            };
            return Err(reason);
        }
        match read_retirement_wake_targets(
            revision,
            &sealed.context,
            &sealed.authenticated_principal,
            &sealed.identity,
            runtime,
        )
        .await
        {
            Ok(UserAutomationWakeTargetEnumeration::Proven { receipt }) => {
                self.classify_enumeration_receipt(obligation, request, receipt, true)
            }
            Ok(UserAutomationWakeTargetEnumeration::Unproven {
                reason,
                receipt: Some(receipt),
            }) => match self.classify_enumeration_receipt(obligation, request, receipt, true) {
                Ok(_) => Err(reason),
                Err(receipt_reason) => Err(receipt_reason),
            },
            Ok(UserAutomationWakeTargetEnumeration::Unproven {
                reason,
                receipt: None,
            }) => {
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Retained;
                Err(reason)
            }
            Err(error) => {
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Retained;
                Err(error.to_string())
            }
        }
    }

    fn classify_enumeration_receipt(
        &self,
        obligation: &mut UserAutomationRuntimeObligation,
        request: &crate::user_automation_execution::UserAutomationWakeEnumerationRequest,
        receipt: UserAutomationWakeEnumerationReceipt,
        persist: bool,
    ) -> Result<UserAutomationWakeEnumerationReceipt, String> {
        if let Err(error) = receipt.validate_for(request) {
            let reason = format!(
                "the retained Host enumeration receipt does not match the exact revision, denominator, authenticated owner, or State Fence request: {error}"
            );
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.clone(),
            };
            return Err(reason);
        }
        let answer = UserAutomationRuntimeObligationAnswer::WakeTargetEnumerationReceipt {
            receipt: Box::new(receipt.clone()),
        };
        if persist
            && let Err(reason) = self.retain_user_automation_obligation_answer(obligation, &answer)
        {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.clone(),
            };
            return Err(reason);
        }
        obligation.disposition = UserAutomationRuntimeObligationDisposition::Answered {
            answer: Box::new(answer),
        };
        if !receipt.coverage.complete || receipt.coverage.unresolved_count != 0 {
            return Err(format!(
                "the durable Host receipt for revision {} accounts for the denominator but leaves {} occurrence(s) unresolved; no cancellation is issued",
                receipt.automation_revision, receipt.coverage.unresolved_count
            ));
        }
        Ok(receipt)
    }

    /// Derives the durable wake-cancellation obligation of one committed
    /// retirement, or names why the exact durable key is not derivable.
    fn retirement_cancellation_obligation(
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        committed_occurrence_ids: &[String],
    ) -> Result<UserAutomationRuntimeObligation, String> {
        retained_user_automation_obligation(
            UserAutomationRuntimeObligationKind::WakeCancellation,
            &sealed.identity,
            &revision.automation_id,
            &revision.revision,
            &revision.digest().map_err(|error| error.to_string())?,
            committed_occurrence_ids,
        )
        .map_err(|error| unretained_cancellation_reason(&revision.revision, error.to_string()))
    }

    fn retirement_enumeration_obligation(
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        committed_occurrence_ids: &[String],
    ) -> Result<UserAutomationRuntimeObligation, String> {
        retained_user_automation_obligation(
            UserAutomationRuntimeObligationKind::WakeTargetEnumerationReceipt,
            &sealed.identity,
            &revision.automation_id,
            &revision.revision,
            &revision.digest().map_err(|error| error.to_string())?,
            committed_occurrence_ids,
        )
        .map_err(|error| {
            format!(
                "the exact Host enumeration receipt obligation for revision {} could not be derived: {error}",
                revision.revision
            )
        })
    }

    fn retirement_cancellation_obligation_with_receipt(
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        committed_occurrence_ids: &[String],
        receipt: UserAutomationWakeEnumerationReceipt,
    ) -> Result<UserAutomationRuntimeObligation, String> {
        retained_user_automation_cancellation_obligation(
            &sealed.identity,
            &revision.automation_id,
            &revision.revision,
            &revision.digest().map_err(|error| error.to_string())?,
            committed_occurrence_ids,
            receipt,
        )
        .map_err(|error| unretained_cancellation_reason(&revision.revision, error.to_string()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the observer binds the complete cancellation claim before dispatch"
    )]
    fn user_automation_cancellation_custody_observer<'a>(
        &'a self,
        sealed: &UserAutomationServiceRequest,
        obligation: &UserAutomationRuntimeObligation,
        revision: &UserAutomationRevision,
        targets: &[UserAutomationWakeCancellationTarget],
        enumeration_receipt: &UserAutomationWakeEnumerationReceipt,
    ) -> Result<UserAutomationCancellationCustodyObserver<'a>, String> {
        let ors = self.commit_ors.as_deref().ok_or_else(|| {
            unretained_obligation_reason(
                obligation,
                "no durable ORS owner is bound for observing cancellation transport custody",
            )
        })?;
        enumeration_receipt
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        if obligation.kind != UserAutomationRuntimeObligationKind::WakeCancellation
            || obligation.wake_enumeration_receipt.as_deref() != Some(enumeration_receipt)
            || enumeration_receipt.parent_operation_identity != sealed.identity
            || enumeration_receipt.state_fence != sealed.context.state_fence
            || enumeration_receipt.authenticated_owner_identity != sealed.authenticated_principal
            || enumeration_receipt.automation_id != revision.automation_id
            || enumeration_receipt.automation_revision != revision.revision
            || enumeration_receipt.revision_digest
                != revision.digest().map_err(|e| e.to_string())?
        {
            return Err(unretained_obligation_reason(
                obligation,
                "the exact parent, revision, owner, or receipt changed before cancellation custody was bound",
            ));
        }
        let operation_id = user_automation_obligation_operation_id(obligation)?;
        let record = ors
            .load_host_request(&operation_id, &obligation.request_digest)
            .map_err(|_| {
                unretained_obligation_reason(
                    obligation,
                    "the claimed cancellation record could not be read for transport custody",
                )
            })?
            .ok_or_else(|| {
                unretained_obligation_reason(
                    obligation,
                    "the claimed cancellation record disappeared before transport custody",
                )
            })?;
        let attempt = record.attempt.clone().ok_or_else(|| {
            unretained_obligation_reason(
                obligation,
                "the claimed cancellation record has no active transport attempt",
            )
        })?;
        let expected_payload_digest = runtime_obligation_payload_digest(&obligation.subject_ids)
            .map_err(|error| {
                unretained_obligation_reason(
                    obligation,
                    format!("the exact cancellation denominator could not be committed: {error}"),
                )
            })?;
        let expected_fence_digest = user_automation_obligation_fence_digest(sealed, obligation)?;
        if record.send_claim_protocol_version != eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION
            || record.state != HostRequestState::Routed
            || record.kind != HostRequestKind::Cancellation
            || record.operation_id != operation_id
            || record.request_digest != obligation.request_digest
            || record.connection_ref.as_str() != USER_AUTOMATION_RUNTIME_CHANNEL
            || record.parent_operation_id.as_ref().map(OpaqueLabel::as_str)
                != Some(sealed.identity.operation_id.as_str())
            || record.payload_digest != expected_payload_digest
            || record.fence_digest != expected_fence_digest
            || record.transport_channel_binding_sha256.as_deref()
                != Some(
                    enumeration_receipt
                        .authenticated_channel_binding_sha256
                        .as_str(),
                )
            || attempt.phase != HostRequestAttemptPhase::Claimed
            || !attempt.transport_observations.is_empty()
            || attempt.channel_binding_sha256.as_deref()
                != Some(
                    enumeration_receipt
                        .authenticated_channel_binding_sha256
                        .as_str(),
                )
        {
            return Err(unretained_obligation_reason(
                obligation,
                "the current ORS row is not the exact unobserved v1 cancellation claim for this parent and receipt",
            ));
        }
        let expected_cancellation = UserAutomationWakeCancellation {
            context: sealed.context.clone(),
            authenticated_principal: sealed.authenticated_principal.clone(),
            identity: sealed.identity.clone(),
            automation_id: revision.automation_id.clone(),
            automation_revision: revision.revision.clone(),
            state_fence: sealed.context.state_fence.clone(),
            only_unadmitted: true,
            targets: targets.to_vec(),
            enumeration_receipt: Some(Box::new(enumeration_receipt.clone())),
        };
        expected_cancellation
            .validate()
            .map_err(|error| error.to_string())?;
        Ok(UserAutomationCancellationCustodyObserver {
            ors,
            record,
            attempt,
            expected_cancellation,
        })
    }

    /// Retains, claims, routes and issues the wake cancellation of one
    /// committed retirement under its durable owner operation identity, and
    /// returns the wake phase the owner produced.
    ///
    /// The intent is staged under the ORIGINAL owner operation identity before
    /// the request leaves this boundary, so a response loss at the wake owner or
    /// the Host transport leaves a record a later attempt of the same parent
    /// operation resumes instead of re-deriving. A record that answered between
    /// the earlier read and this staging is the concurrent attempt of the same
    /// parent operation: its retained disposition is honoured and nothing is
    /// issued.
    ///
    /// The cancellation is then handed to the owner under ONE exclusive durable
    /// send claim acquired before the first transport await (issue #2970). That
    /// claim is what makes the handoff single-owner rather than merely
    /// single-request: two concurrent attempts of the same parent operation
    /// yield at most one owner handoff, because the second one fails to acquire
    /// the claim and issues nothing. The claim also persists the monotonic
    /// `Routed` state in the same transaction, so a crash anywhere inside the
    /// await window leaves a non-reissuable reconciling record under the
    /// ORIGINAL owner operation identity rather than ordinary `Retained` work
    /// that a later attempt would blindly reissue.
    #[allow(
        clippy::too_many_lines,
        reason = "retirement dispatch and exact reconciliation remain in one causal contour"
    )]
    async fn issue_retirement_cancellation<R>(
        &self,
        handoff: OwnerWakeHandoffKind,
        sealed: &UserAutomationServiceRequest,
        obligation: &mut UserAutomationRuntimeObligation,
        retirement: (
            UserAutomationRevision,
            Vec<UserAutomationWakeCancellationTarget>,
            UserAutomationWakeEnumerationReceipt,
        ),
        runtime: &R,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let (revision, targets, enumeration_receipt) = retirement;
        let execution = not_applicable_execution();
        let noun = handoff.noun();
        let mut settled = obligation.clone();
        let retained_lookup = self
            .reconcile_cancellation_owner_readback(
                sealed,
                &settled,
                &revision,
                &targets,
                &enumeration_receipt,
                runtime,
            )
            .await;
        let retained =
            classify_retained_cancellation(&settled, &revision.revision, retained_lookup);
        let retry_after_proven_no_send =
            matches!(&retained, RetainedCancellation::RetryAfterProvenNoSend);
        if let Some(phases) = retained_cancellation_phases(retained, &mut settled, &execution) {
            obligations.push(settled);
            return Ok(phases);
        }
        if let Some(phases) = self.claim_wake_cancellation_send(
            sealed,
            &mut settled,
            obligations,
            &execution,
            retry_after_proven_no_send,
        ) {
            return Ok(phases);
        }
        let observer = match self.user_automation_cancellation_custody_observer(
            sealed,
            &settled,
            &revision,
            &targets,
            &enumeration_receipt,
        ) {
            Ok(observer) => observer,
            Err(reason) => {
                return Ok(self.refused_claimed_cancellation(
                    (
                        UserAutomationExecutionError::Runtime(
                            UserAutomationRuntimeError::Unavailable(reason),
                        ),
                        false,
                    ),
                    &revision,
                    noun,
                    &mut settled,
                    obligations,
                    &execution,
                ));
            }
        };
        let removal = match self
            .cancel_retirement_wakes(
                handoff,
                sealed,
                revision.clone(),
                targets,
                enumeration_receipt.clone(),
                runtime,
                &observer,
            )
            .await
        {
            Ok(removal) => removal,
            Err(refusal) => {
                return Ok(self.refused_claimed_cancellation(
                    refusal,
                    &revision,
                    noun,
                    &mut settled,
                    obligations,
                    &execution,
                ));
            }
        };
        // Reached only with a NON-EMPTY proven target set. An owner that
        // cancelled none of the targets it was handed contradicted itself, so
        // that is an unresolved handoff rather than a proven absence.
        if removal.cancelled_wake_ids.is_empty() {
            let reason = format!(
                "the wake owner returned no cancelled identity for the owner-issued targets of {} \
                 revision {} of {}; an empty answer is not proof that no unadmitted wake existed, \
                 so the wake handoff stays unknown",
                noun, revision.revision, revision.automation_id
            );
            settled.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.clone(),
            };
            obligations.push(settled);
            return Ok(unresolved_retirement_phases(reason, execution));
        }
        // The exact owner answer becomes the durable record's retained body, so
        // a replay of this same parent operation serves it verbatim instead of
        // issuing a second cancellation whose effect is no longer observable.
        let cancelled_wake_ids = removal.cancelled_wake_ids;
        let answer = UserAutomationRuntimeObligationAnswer::WakeCancellation {
            cancelled_wake_ids: cancelled_wake_ids.clone(),
            enumeration_receipt: Some(Box::new(enumeration_receipt)),
        };
        settled.disposition = match self.retain_user_automation_obligation_answer(&settled, &answer)
        {
            // The owner answered and the answer is retained, so the retirement is
            // fully resolved under its original owner operation identity.
            Ok(()) => UserAutomationRuntimeObligationDisposition::Answered {
                answer: Box::new(answer),
            },
            // The owner answered and the answer is in hand, but it could not be
            // retained, so it is not yet a replayable obligation. The retirement
            // is still a known configuration fact and the exact answer is
            // reported; the obligation stays open under its original owner
            // operation identity so a later attempt reconciles it instead of
            // cancelling again.
            Err(reason) => UserAutomationRuntimeObligationDisposition::Reconciling { reason },
        };
        obligations.push(settled);
        Ok((
            UserAutomationWakePhase::Cancelled { cancelled_wake_ids },
            execution,
        ))
    }

    /// Reports one refused wake cancellation that already held the exclusive
    /// send claim, and returns the phases its caller must return.
    ///
    /// The retirement is committed and durable, so a refusal at this leg is an
    /// unresolved handoff of a committed fact. It is reported as such, with the
    /// exact refusal, instead of being reported as a failed retirement or as a
    /// cancellation that did not happen. The exclusive send claim is already
    /// durable, so no arm here may report the obligation as still re-issuable:
    /// a claim that survived the attempt to hand the request over can only be
    /// settled by exact owner reconciliation under the original owner
    /// operation identity.
    #[allow(clippy::too_many_arguments)]
    fn refused_claimed_cancellation(
        &self,
        refusal: (UserAutomationExecutionError, bool),
        revision: &UserAutomationRevision,
        noun: &str,
        settled: &mut UserAutomationRuntimeObligation,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
        execution: &UserAutomationExecutionPhase,
    ) -> (UserAutomationWakePhase, UserAutomationExecutionPhase) {
        let (error, owner_answered_unknown) = refusal;
        if owner_answered_unknown
            && let Err(arm) = self.mark_user_automation_obligation_unknown(settled)
        {
            return unresolved_wake_cancellation(settled, obligations, execution, arm);
        }
        let reason = if owner_answered_unknown {
            unretained_cancellation_outcome_reason(
                &revision.revision,
                &settled.owner_operation_id,
                &error.to_string(),
            )
        } else {
            claimed_cancellation_outcome_reason(
                &revision.revision,
                &settled.owner_operation_id,
                &error.to_string(),
            )
        };
        settled.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
            reason: reason.clone(),
        };
        obligations.push(settled.clone());
        unresolved_retirement_phases(
            format!(
                "revision {} of {} is {}, but its unadmitted wakes were not cancelled from the \
                 complete owner view: {}; the not-yet-admitted wakes and the exact unresolved \
                 reconciliation references of this revision are preserved and stay open",
                revision.revision, revision.automation_id, noun, error
            ),
            execution.clone(),
        )
    }

    /// Issues the wake cancellation of one committed retirement-like transition
    /// through the existing execution join, and reports whether the refusal
    /// left a possibly issued owner effect.
    ///
    /// The committed transition is replayed under the same admitted identity
    /// this route already committed, so the owner view, the transition and the
    /// cancellation observe one canonical operation rather than two. The boolean
    /// is the only classification the caller needs: a lost owner answer means the
    /// effect may already be applied, while every other refusal happened before
    /// the cancellation left this boundary.
    #[allow(
        clippy::too_many_arguments,
        reason = "the exact retirement operation, target set, receipt, runtime, and observer are all required"
    )]
    async fn cancel_retirement_wakes<R>(
        &self,
        handoff: OwnerWakeHandoffKind,
        sealed: &UserAutomationServiceRequest,
        affected: UserAutomationRevision,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
        observer: &dyn UserAutomationHostExecutionObserver,
    ) -> Result<UserAutomationRemovalResult, (UserAutomationExecutionError, bool)>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(self));
        let service = UserAutomationService::new(&store);
        // Each join is awaited in its own arm: the three joins are different
        // future types, so they cannot share one match value.
        let result = match handoff {
            OwnerWakeHandoffKind::Remove => {
                Box::pin(service.remove_and_cancel_with_targets_observed(
                    sealed.clone(),
                    targets,
                    enumeration_receipt,
                    runtime,
                    observer,
                ))
                .await
            }
            OwnerWakeHandoffKind::Pause => {
                Box::pin(service.pause_and_cancel_with_targets_observed(
                    sealed.clone(),
                    targets,
                    enumeration_receipt,
                    runtime,
                    observer,
                ))
                .await
            }
            OwnerWakeHandoffKind::SupersedingEdit => {
                Box::pin(service.edit_and_cancel_with_targets_observed(
                    sealed.clone(),
                    affected,
                    targets,
                    enumeration_receipt,
                    runtime,
                    observer,
                ))
                .await
            }
        };
        result.map_err(|error| {
            let owner_answered_unknown = matches!(
                &error,
                UserAutomationExecutionError::Runtime(UserAutomationRuntimeError::UnknownOutcome(
                    _
                ))
            );
            (error, owner_answered_unknown)
        })
    }

    /// Revalidates principal, revision, State Fence, and owner denominator of a
    /// compiled horizon publication against the live canonical owner before
    /// the slice is handed to the schedule owner (issue #2806 item 2).
    ///
    /// The committed revision proves what this identity committed; only the
    /// live owner proves that revision is still the current accepted one under
    /// this principal and fence, with the same normalized denominator this
    /// publication compiled. An unreadable owner means nothing was proven and
    /// nothing is sent (`Unavailable`); a moved owner — another current
    /// revision, a different principal binding, a fence drift, a changed
    /// denominator, or a no-longer-active admission state — means the wake
    /// disposition now belongs to that newer transition and must be reconciled
    /// (`UnknownOutcome`). Neither case publishes from a stale commit.
    async fn revalidate_horizon_owner(
        &self,
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        publication: &UserAutomationWakeHorizonPublication,
    ) -> Result<(), (UnreachedHorizonKind, String)> {
        let unavailable = |detail: String| {
            (
                UnreachedHorizonKind::Unavailable,
                format!(
                    "the live UserAutomation owner could not prove revision {} current for horizon \
                     publication: {}; nothing was sent and every requested occurrence stays owed",
                    revision.revision, detail
                ),
            )
        };
        let moved = |detail: String| {
            (
                UnreachedHorizonKind::UnknownOutcome,
                format!(
                    "the live UserAutomation owner no longer shows revision {} as the current \
                     accepted revision for horizon publication: {}; the wake disposition belongs to \
                     that newer transition and must be reconciled under its identity",
                    revision.revision, detail
                ),
            )
        };
        let owner = self
            .read_user_automation_owner(&UserAutomationOwnerLookup {
                automation_id: revision.automation_id.clone(),
                requested_revision: revision.revision.clone(),
                authenticated_principal: sealed.authenticated_principal.clone(),
                state_fence: sealed.context.state_fence.clone(),
            })
            .await
            .map_err(unavailable)?;
        if owner.automation_id != revision.automation_id
            || owner.authenticated_principal != sealed.authenticated_principal
            || owner.state_fence != sealed.context.state_fence
        {
            return Err(moved(
                "automation, principal, or State Fence binding drifted".to_owned(),
            ));
        }
        if owner.revision != *revision {
            return Err(moved(
                "the current owner revision document is not the committed one".to_owned(),
            ));
        }
        let owner_denominator = owner
            .revision
            .compile_occurrence_identities()
            .map_err(|error| unavailable(error.to_string()))?
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        if owner_denominator != publication.denominator_occurrence_ids {
            return Err(moved(
                "the owner denominator is not the denominator this publication compiled".to_owned(),
            ));
        }
        if owner.current_configuration_state != UserAutomationConfigurationState::Active {
            return Err(moved(format!(
                "the current admission state is {:?}, which admits no wake",
                owner.current_configuration_state
            )));
        }
        Ok(())
    }

    /// Retains, then publishes, the one bounded wake horizon a committed
    /// operator operation owns, if any.
    ///
    /// `Create`, a `Resume` of the same immutable revision, and an `Edit` that
    /// committed a new `Active` revision each own exactly one publication
    /// obligation. It is reported as its own phase beside the wake publication or
    /// cancellation phase, because a superseding `Edit` also owns the
    /// predecessor's unresolved cancellation obligation: collapsing the two
    /// would either hide the new horizon or silently answer for a cancellation
    /// this contour does not perform.
    ///
    /// The horizon is compiled from the committed revision and nothing else: its
    /// own immutable normalized occurrence denominator, the compiled trigger
    /// basis, and the publishing State Fence. An inactive committed revision
    /// owns no wake at all and publishes nothing. A revision that owns a horizon
    /// with no reachable schedule owner reports the exact requested and
    /// remaining sets with a replay handle, which is the failure cut of issue
    /// #2806: a committed configuration plus an explicit publication obligation,
    /// never a silent success.
    ///
    /// This entry point only decides whether a horizon exists and compiles it.
    /// Retaining and publishing it is [`Self::retain_and_publish_wake_horizon`],
    /// the single owner of that sequence, which the post-disposition slice a due
    /// wake advances reaches through [`Self::publish_due_wake_horizon_advance`].
    async fn publish_schedule_horizon<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
        obligations: &mut Vec<UserAutomationRuntimeObligation>,
    ) -> Result<Option<UserAutomationHorizonPhase>, String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let Some(trigger) = schedule_horizon_trigger(&sealed.intent.operation) else {
            return Ok(None);
        };
        let Some(revision) = committed_revision(configuration) else {
            return Err(
                "a configuration mutation that owns a wake horizon did not return a canonical \
                 revision"
                    .to_owned(),
            );
        };
        if revision.configuration_state != UserAutomationConfigurationState::Active {
            // A committed non-active revision admits no future occurrence, so it
            // owns no horizon. That is a complete answer about an obligation
            // that never existed, not a partial publication.
            return Ok(None);
        }
        let publication = compile_wake_horizon(
            revision,
            sealed.context.clone(),
            sealed.authenticated_principal.clone(),
            sealed.identity.clone(),
            sealed.context.state_fence.clone(),
            trigger,
            None,
        )
        .map_err(|error| error.to_string())?;
        // The operator route reports a bare refusal reason and its result envelope is
        // only composed on the success arm, so the typed arm is projected back to
        // the identical text here. That mapping is the honest reading of the
        // operator route's own contract — its caller receives a reason, not an
        // obligation — and it is NAMED rather than left implicit: a
        // post-retention refusal on this leg still drops the obligation, exactly
        // as it did before, because `execute_user_automation_operation` returns
        // `Err` here and never reaches the orchestration composition. Closing
        // that leg means typing `execute_user_automation_operation`'s own error
        // and giving the operator envelope a field for a retained-but-unprojectable
        // obligation; that is a wider `crates/**` + `bins/**` contract change
        // than this residual, and it is reported as such rather than half-done
        // here. The arm is NOT dropped for the due-wake consumer, whose own entry
        // point returns it unchanged.
        let (obligation, phase) = self
            .retain_and_publish_wake_horizon(sealed, revision, &publication, runtime)
            .await
            .map_err(UserAutomationHorizonPublicationRefusal::into_reason)?;
        obligations.extend(obligation);
        Ok(Some(phase))
    }

    /// Retains and then publishes one bounded wake horizon, for any caller that
    /// already proved the slice belongs to an immutable revision it may publish.
    ///
    /// This is the ONLY implementation of the horizon obligation route, and both
    /// of its entry points run it unchanged: [`Self::publish_schedule_horizon`]
    /// for the horizon a committed `Create`/`Resume`/`Edit` owns, and
    /// [`Self::publish_due_wake_horizon_advance`] for the post-disposition slice
    /// a due wake advances. Neither may re-derive any part of it, so the
    /// composition-bound durable outbox, the retained-obligation
    /// classification, the possible-effect marking and the acknowledgement
    /// settlement each have exactly one owner and there is no second durable
    /// write path.
    ///
    /// The publication is an owner effect, so its intent is retained before
    /// anything is handed to the schedule owner, in the composition-bound durable
    /// outbox under its original owner operation identity. A record that could
    /// not be retained is a named unavailability: nothing is issued, and the
    /// horizon keeps its exact requested and remaining sets beside it.
    ///
    /// The returned obligation is present exactly when a durable record backs
    /// this publication. `None` is a pre-retention answer — nothing was retained
    /// and nothing was issued, so there is no record a reconciliation could read.
    ///
    /// The `Err` is typed rather than a bare reason, so a step that fails AFTER
    /// the record was durably settled hands the caller the obligation that was
    /// actually written instead of dropping the only handle to it. See
    /// [`UserAutomationHorizonPublicationRefusal`]. The obligation in that arm is
    /// the one `retained_user_automation_obligation` already derived from the
    /// existing `runtime_obligation_operation_id(kind, parent, subject_ids)`; no
    /// identity is minted on the error path, and a step that fails before that
    /// identity exists reports
    /// [`UserAutomationHorizonPublicationRefusal::NothingRetained`] instead of
    /// constructing one to look reportable.
    async fn retain_and_publish_wake_horizon<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        revision: &UserAutomationRevision,
        publication: &UserAutomationWakeHorizonPublication,
        runtime: Option<&R>,
    ) -> Result<
        (
            Option<UserAutomationRuntimeObligation>,
            UserAutomationHorizonPhase,
        ),
        UserAutomationHorizonPublicationRefusal,
    >
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        // This is the first `?` of the route and it runs before the obligation
        // identity exists, so it is a pre-retention refusal and is named as one.
        let requested_occurrence_ids = publication.requested_occurrence_ids();
        let retry_handle = publication
            .retry_handle(&requested_occurrence_ids)
            .map_err(|error| {
                UserAutomationHorizonPublicationRefusal::nothing_retained(error.to_string())
            })?;
        // Revalidate principal, revision, State Fence, and owner denominator
        // against the live owner before any owner call (issue #2806 item 2).
        // The committed document proves what this identity committed; only the
        // live owner proves it is still the current accepted revision under
        // this principal and fence. A revision that a concurrent pause,
        // remove, or superseding edit already moved is not published from a
        // stale commit: that leg owns the wake disposition instead.
        if let Err((kind, reason)) = self
            .revalidate_horizon_owner(sealed, revision, publication)
            .await
        {
            return Ok((
                None,
                unreached_horizon_phase(
                    publication,
                    &requested_occurrence_ids,
                    retry_handle,
                    kind,
                    &reason,
                ),
            ));
        }
        let mut obligation = match retained_user_automation_obligation(
            UserAutomationRuntimeObligationKind::WakeHorizonPublication,
            &sealed.identity,
            &publication.automation_id,
            &publication.automation_revision,
            &publication.revision_digest,
            &requested_occurrence_ids,
        ) {
            Ok(obligation) => obligation,
            Err(error) => {
                return Ok((
                    None,
                    unretained_wake_horizon_phase(
                        publication,
                        &requested_occurrence_ids,
                        &retry_handle,
                        error.to_string(),
                    ),
                ));
            }
        };
        // The retained record is consulted first, so an answered or reconciling
        // obligation is reported under its original owner operation identity
        // without publishing the slice a second time. A row the durable owner
        // classifies as possible-effect is first put to the schedule owner, which
        // is the only party that can say whether the effect landed; a row it
        // answers for settles here and any other answer keeps it reconciling.
        //
        // The gate is the durable `Reconciling` classification and nothing else.
        // Two neighbouring outcomes deliberately do NOT reach the owner, because a
        // readback would destroy the only evidence each of them carries: a row
        // whose retained answer no longer decodes stays unresolved so the
        // corruption remains visible instead of being overwritten with a fresh
        // answer, and a row holding a wake-cancellation retry claim is not a
        // horizon obligation at all.
        let retained = self.retain_user_automation_obligation(sealed, &obligation);
        if matches!(
            &retained,
            RetainedObligationLookup::Held(RetainedUserAutomationObligation::Reconciling { .. })
        ) && let Some(phase) = self
            .reconcile_wake_horizon_possible_effect(
                runtime,
                &mut obligation,
                publication,
                &requested_occurrence_ids,
                &retry_handle,
            )
            .await?
        {
            return Ok((Some(obligation), phase));
        }
        let retained = classify_retained_horizon_publication(&obligation, publication, retained);
        if let Some(phase) = retained_horizon_phase(
            retained,
            &mut obligation,
            publication,
            &requested_occurrence_ids,
            &retry_handle,
        ) {
            return Ok((Some(obligation), phase));
        }
        let (settled, phase) = self
            .issue_wake_horizon(
                &obligation,
                runtime,
                publication,
                &requested_occurrence_ids,
                retry_handle,
            )
            .await?;
        Ok((Some(settled), phase))
    }

    /// Retains, then publishes, the one bounded recurring horizon slice a due
    /// wake's post-disposition advance owns (issue #2806 items 6, W6 and W8, and
    /// the lost-response half of A3).
    ///
    /// This is the entry point that makes the retention route reachable for that
    /// advance. Until now [`Self::publish_schedule_horizon`] was the only caller
    /// of the `retained_user_automation_obligation` →
    /// [`Self::mark_wake_horizon_obligation_possible_effect`] →
    /// [`Self::settle_wake_horizon_acknowledgement`] sequence, so the due-wake
    /// consumer reached [`UserAutomationWakePort::publish_wake_horizon`]
    /// directly and a lost response to its post-disposition slice had nothing to
    /// resume from. This runs the SAME sequence, through the SAME
    /// [`Self::retain_and_publish_wake_horizon`] the operator route runs, over the
    /// SAME composition-bound outbox: no second durable write path, no second
    /// copy of the retained-obligation classification, no process-local retry
    /// ledger and no detached scheduler loop.
    ///
    /// **How a lost response resumes, and under which identity.** The obligation
    /// key is `runtime_obligation_operation_id(kind, parent, subject_ids)` over
    /// the admitted due-wake carrier's parent identity triple, the existing
    /// `WakeHorizonPublication` kind, and this slice's exact requested occurrence
    /// set. All three are immutable content — the revision is immutable, the
    /// cursor is positional, and the consumed occurrence is excluded from its own
    /// slice — so the key is byte-identical after a restart. A repeat delivery of
    /// the same due wake therefore FINDS the same row: an answered row serves the
    /// owner's retained acknowledgement verbatim instead of republishing, and a
    /// row that already reached the monotonic `Routed` state is put to the
    /// schedule owner as a possible effect under that same original owner
    /// operation identity instead of being re-issued. A later calendar occurrence
    /// advances a different set, so it keys a different record rather than
    /// overwriting this one — which is I11.12's "a later calendar occurrence is a
    /// different identity" held in the durable store and not only in the
    /// compiler.
    ///
    /// The parent is the admitted due-wake carrier's identity, not an operator
    /// commit's: the advance is not a committed operator operation and mints no
    /// canonical identity of its own (see
    /// [`Self::due_wake_horizon_parent_request`]).
    ///
    /// The returned obligation is present exactly when a durable record backs
    /// this publication. `None` is a pre-retention answer — nothing was retained
    /// and nothing was issued, so there is no record a reconciliation could read.
    ///
    /// **The returned `Err` distinguishes the two cases a bare reason string could
    /// not.** The binding checks below fail before the obligation identity exists,
    /// so they report [`UserAutomationHorizonPublicationRefusal::NothingRetained`]
    /// and the caller may state that no record exists. A step that fails AFTER
    /// [`Self::settle_wake_horizon_acknowledgement`] has written the owner's
    /// answer reports [`UserAutomationHorizonPublicationRefusal::Retained`] and
    /// hands back that exact obligation, so the caller can report and later
    /// reconcile the record under its ORIGINAL owner operation identity instead
    /// of dropping the only handle to it. The caller must still project either
    /// arm as an unknown outcome rather than as a clean absence of work; what it
    /// may no longer do is claim that nothing was retained while a record exists.
    ///
    /// No identity is minted on either arm. The retained obligation is the one
    /// `retained_user_automation_obligation` already derived from the existing
    /// `runtime_obligation_operation_id(kind, parent, subject_ids)`; a caller that
    /// wants an identity for a `NothingRetained` refusal must say it has none
    /// rather than construct one.
    pub async fn publish_due_wake_horizon_advance<R>(
        &self,
        request: &UserAutomationRuntimeAdmission,
        resolution: &UserAutomationDueWakeResolution,
        publication: &UserAutomationWakeHorizonPublication,
        runtime: &R,
    ) -> Result<
        (
            Option<UserAutomationRuntimeObligation>,
            UserAutomationHorizonPhase,
        ),
        UserAutomationHorizonPublicationRefusal,
    >
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let sealed = Self::due_wake_horizon_parent_request(request, resolution);
        // Every check in `validate_due_wake_horizon_advance` runs before the
        // obligation identity is derived and before any durable write, so its
        // refusals are named as pre-retention rather than left ambiguous.
        Self::validate_due_wake_horizon_advance(&sealed, resolution, publication)
            .map_err(UserAutomationHorizonPublicationRefusal::nothing_retained)?;
        self.retain_and_publish_wake_horizon(
            &sealed,
            &resolution.revision,
            publication,
            Some(runtime),
        )
        .await
    }

    /// Composes the retained-parent request one due-wake horizon advance is
    /// issued under.
    ///
    /// The advance follows an owner-acknowledged occurrence disposition; it is
    /// not a committed operator operation, so it owns no sealed operator request
    /// and must mint no canonical identity for one. It reuses the admitted
    /// due-wake carrier's identity, principal and live request metadata — the
    /// same triple [`Self::due_wake_execution_join`] reads — and names the
    /// read-only `Status` view of the exact revision this advance publishes for,
    /// so the retained record is bound to the occurrence's own parent operation
    /// and this leg issues no transition.
    fn due_wake_horizon_parent_request(
        request: &UserAutomationRuntimeAdmission,
        resolution: &UserAutomationDueWakeResolution,
    ) -> UserAutomationServiceRequest {
        UserAutomationServiceRequest {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal.clone(),
            identity: request.identity.clone(),
            intent: UserAutomationOperatorIntent {
                intent_id: format!(
                    "{}:due-wake-horizon-advance",
                    request.identity.operation_id.as_str()
                ),
                principal_ref: request.authenticated_principal.clone(),
                state_fence: request.context.state_fence.clone(),
                operation: UserAutomationOperation::Status {
                    automation_id: resolution.revision.automation_id.clone(),
                },
            },
        }
    }

    /// Binds one caller-supplied horizon slice to the due-wake carrier and the
    /// resolved revision it must be retained under, before anything is retained
    /// or issued.
    ///
    /// A horizon request carries its own context, identity, fence and revision
    /// binding, so a caller could otherwise hand this boundary a slice that is
    /// internally valid but belongs to a different carrier or a different
    /// revision than the due wake actually resolved. The durable record is keyed
    /// on the parent identity and the slice's own subject set, so accepting one
    /// of those would retain a real obligation under a false parent. The
    /// revision-relative proof itself is
    /// [`UserAutomationWakeHorizonPublication::validate_against_revision`], the
    /// same function `advance_wake_horizon` already ran; it is repeated here
    /// because the caller, not this boundary, chose the value.
    fn validate_due_wake_horizon_advance(
        sealed: &UserAutomationServiceRequest,
        resolution: &UserAutomationDueWakeResolution,
        publication: &UserAutomationWakeHorizonPublication,
    ) -> Result<(), String> {
        // The retained row's fence digest, Authority Epoch, generation and
        // retention instant all derive from the parent request, while every wake
        // intent in this slice is bound to the publication's own fence. A slice
        // whose two fences differ would retain a record under a fence its own
        // entries were never compiled for, so no record is written at all.
        if publication.state_fence != sealed.context.state_fence {
            return Err(
                "the bounded horizon slice after the admitted occurrence is issued under a \
                 State Fence that is not the one its retained obligation would be recorded \
                 under; nothing was retained and nothing was sent"
                    .to_owned(),
            );
        }
        if publication.trigger != UserAutomationHorizonTrigger::DispositionAdvance
            || publication.revision_digest != resolution.revision_digest
        {
            return Err(
                "the horizon slice handed to the due-wake advance is not the bounded advance of \
                 the revision this due wake resolved; nothing was retained and nothing was sent"
                    .to_owned(),
            );
        }
        publication
            .validate_against_revision(&resolution.revision)
            .map_err(|error| {
                format!(
                    "the bounded horizon slice after the admitted occurrence is not a slice of \
                     the resolved revision's own normalized contract: {error}; nothing was \
                     retained and nothing was sent"
                )
            })
    }

    /// Makes one schedule owner's own acknowledgement the durable retained body
    /// of the horizon obligation it answers.
    ///
    /// The acknowledgement is tied to the exact request twice before it is
    /// retained: once as this owner's answer to this publication, and once as an
    /// answer shape this obligation may durably hold. Either refusal returns its
    /// typed reason and writes nothing, leaving the record reconciling rather
    /// than retaining a horizon that cannot be tied to the request that asked
    /// for it. Retaining the answer is the last step, and it is the only step
    /// that changes the durable record: a failure to retain it is reported as a
    /// reason, never as a partial acknowledgement.
    fn settle_wake_horizon_acknowledgement(
        &self,
        obligation: &UserAutomationRuntimeObligation,
        publication: &UserAutomationWakeHorizonPublication,
        acknowledgement: &UserAutomationWakePublication,
    ) -> Result<UserAutomationRuntimeObligationDisposition, String> {
        acknowledgement
            .validate_for(publication)
            .map_err(|error| error.to_string())?;
        let answer = UserAutomationRuntimeObligationAnswer::WakeHorizonPublication {
            publication_request: Some(Box::new(publication.clone())),
            acknowledgement: Box::new(acknowledgement.clone()),
        };
        answer
            .validate_horizon_for(publication)
            .map_err(|error| error.to_string())?;
        self.retain_user_automation_obligation_answer(obligation, &answer)?;
        Ok(UserAutomationRuntimeObligationDisposition::Answered {
            answer: Box::new(answer),
        })
    }

    /// Asks the schedule owner whether one possible-effect horizon obligation was
    /// already applied, and settles the retained row out of the owner's own
    /// answer.
    ///
    /// A row that reached the monotonic `Routed` state is reconciling until
    /// something asks the owner the only question that can close it, so this is
    /// that ask. It runs ahead of the ordinary classification and only for the
    /// one durable classification that means "the owner may already have acted";
    /// an absent, issued, answered, or unreadable row is left to
    /// `classify_retained_horizon_publication` exactly as before.
    ///
    /// The discriminator is the SHAPE of the owner's answer, and it introduces
    /// no new state, digest, nonce, cap, or timeout. `Ok` is the owner's own
    /// retained acknowledgement for THIS exact publication, so it settles the row
    /// to `Answered` through the same `settle_wake_horizon_acknowledgement` the
    /// issue path uses: one retained body, one pair of validators, one ORS
    /// writer, no second settlement path. The next attempt of this parent
    /// operation then reads the row back as answered and serves that body
    /// verbatim instead of publishing the slice again.
    ///
    /// EVERY other answer DEFERS, and the row stays reconciling. That set is
    /// deliberately large, and `NotRetained` is the member that has to be argued
    /// rather than assumed. It is a genuine complete negative, and it is still
    /// not proof that the effect was never issued: it answers a question about
    /// the owner's CURRENT activation generation, because the Host journal
    /// clears its whole wake projection at an activation cutover
    /// (`eliot_host_state::journal`), so a horizon published and fired under an
    /// earlier generation reads as absent under this one. Settling that to
    /// `Retained` would republish occurrences whose effect already happened,
    /// which is the exact double-publish issue #2970 exists to close, and the
    /// port's own contract forbids the inference: "an absent or inconclusive
    /// lookup is an error, never proof that publication did not occur."
    /// `Unavailable` proves less still, because `map_journal_error` collapses an
    /// explicitly indeterminate `BackendError::Unknown` into it. Every deferred
    /// answer keeps its typed detail in the reconciling reason, so the row
    /// records that reconciliation was attempted and what the owner said.
    ///
    /// `None` means this obligation is not in the classification this reconciles
    /// and the caller must run the ordinary path.
    ///
    /// The only step here that can fail is the projection, and it runs AFTER
    /// `settle_wake_horizon_acknowledgement` has written the owner's answer as the
    /// row's durable retained body. That is why the refusal carries the settled
    /// obligation: the row provably exists and is provably answered, so dropping
    /// its handle here would leave a durable record that nothing can name.
    async fn reconcile_wake_horizon_possible_effect<R>(
        &self,
        runtime: Option<&R>,
        obligation: &mut UserAutomationRuntimeObligation,
        publication: &UserAutomationWakeHorizonPublication,
        requested_occurrence_ids: &[String],
        retry_handle: &str,
    ) -> Result<Option<UserAutomationHorizonPhase>, UserAutomationHorizonPublicationRefusal>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let Some(runtime) = runtime else {
            // The intent is durably retained and this transition composed no
            // schedule owner at all, so there is nothing to ask and nothing to
            // settle. The ordinary classification reports it as unresolved.
            return Ok(None);
        };
        let acknowledgement = match UserAutomationWakePort::read_wake_horizon_publication(
            runtime,
            publication.clone(),
        )
        .await
        {
            Ok(acknowledgement) => acknowledgement,
            Err(refusal) => {
                // No answer this boundary may close the question on. The row
                // keeps its `Reconciling` disposition and its possible-effect
                // state, and the reported reason now names the typed owner
                // answer that refused to settle it.
                let detail = unretained_horizon_outcome_reason(
                    &publication.automation_revision,
                    &obligation.owner_operation_id,
                    &refusal.to_string(),
                );
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                    reason: detail.clone(),
                };
                return Ok(Some(unreached_horizon_phase(
                    publication,
                    requested_occurrence_ids,
                    retry_handle.to_owned(),
                    UnreachedHorizonKind::UnknownOutcome,
                    &detail,
                )));
            }
        };
        // The owner's retained acknowledgement becomes this obligation's durable
        // body through the existing settle seam. A refusal here — a foreign
        // identity, a failed horizon accounting, a row that could not be
        // retained — writes nothing and keeps the record reconciling, so a wrong
        // answer can never become a settled horizon.
        let disposition = match self.settle_wake_horizon_acknowledgement(
            obligation,
            publication,
            &acknowledgement,
        ) {
            Ok(disposition) => disposition,
            Err(reason) => {
                obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                    reason: reason.clone(),
                };
                return Ok(Some(unreached_horizon_phase(
                    publication,
                    requested_occurrence_ids,
                    retry_handle.to_owned(),
                    UnreachedHorizonKind::UnknownOutcome,
                    &reason,
                )));
            }
        };
        obligation.disposition = disposition;
        // The owner's answer is the row's durable retained body from here on, so a
        // projection failure is a post-retention refusal that must hand back the
        // obligation it settled. `obligation` is the very record that was written:
        // its `Answered` disposition came from `settle_wake_horizon_acknowledgement`
        // and its `owner_operation_id` came from
        // `runtime_obligation_operation_id`, neither of which is recomputed here.
        let phase = match acknowledged_horizon_phase(
            publication,
            requested_occurrence_ids,
            &acknowledgement,
        ) {
            Ok(phase) => phase,
            Err(reason) => {
                return Err(UserAutomationHorizonPublicationRefusal::retained(
                    obligation.clone(),
                    reason,
                ));
            }
        };
        Ok(Some(phase))
    }

    /// Issues one bounded wake horizon under a durably routed obligation and
    /// returns the obligation's final disposition beside the horizon phase the
    /// schedule owner produced.
    ///
    /// The retained record is advanced to the monotonic `Routed` state BEFORE the
    /// request leaves this boundary, so that state answers "may the schedule
    /// owner already have retained this slice?" durably and from durable state
    /// alone. The exact owner answer becomes the durable record's retained body,
    /// so a replay of this same parent operation serves it instead of publishing
    /// the slice a second time. Once the record is `Routed` no reported answer
    /// makes it re-issuable: an owner that answers `Unavailable`, a typed refusal,
    /// and a lost response all leave an obligation that must be reconciled under
    /// its original owner operation identity, because a later read of the
    /// committed configuration is empty of the effect either way.
    ///
    /// The `Unavailable` arm is the one that pays for that rule with real
    /// availability, and it documents its own lumped producers rather than
    /// leaving a reader to assume a clean no-send.
    ///
    /// The only `Err` this reaches is the projection below, and it is reached
    /// ONLY after `settle_wake_horizon_acknowledgement` wrote the owner's answer
    /// as the record's durable retained body. The refusal therefore carries
    /// `settled`: the obligation this route actually settled, under its original
    /// owner operation identity. Every other outcome here is an `Ok` whose phase
    /// names the exact remaining set and replay handle, including the arms where
    /// the row is armed and stays reconciling.
    async fn issue_wake_horizon<R>(
        &self,
        obligation: &UserAutomationRuntimeObligation,
        runtime: Option<&R>,
        publication: &UserAutomationWakeHorizonPublication,
        requested_occurrence_ids: &[String],
        retry_handle: String,
    ) -> Result<
        (UserAutomationRuntimeObligation, UserAutomationHorizonPhase),
        UserAutomationHorizonPublicationRefusal,
    >
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let mut settled = obligation.clone();
        let unreached = |kind: UnreachedHorizonKind, reason: &str| {
            unreached_horizon_phase(
                publication,
                requested_occurrence_ids,
                retry_handle.clone(),
                kind,
                reason,
            )
        };
        let mut reconcile = |reason: &str| {
            settled.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.to_owned(),
            };
        };
        let Some(runtime) = runtime else {
            // The intent is durably retained and the owner was never composed, so
            // no effect was issued and the obligation may still be issued under
            // the retained identity by a later attempt of this parent operation.
            settled.disposition = UserAutomationRuntimeObligationDisposition::Retained;
            return Ok((
                settled,
                unreached(
                    UnreachedHorizonKind::Unavailable,
                    UNREACHED_WAKE_OWNER_REASON,
                ),
            ));
        };
        // Issue #2970: the durable possible-effect state is persisted BEFORE the
        // awaited owner call, not after it. `Admitted` on its own cannot say the
        // owner was never handed this slice, so the record is advanced to
        // `Routed` first: a process death inside the await window then reloads
        // as reconciling under this original owner operation identity rather than
        // as work a later attempt would publish a second time.
        if let Err(reason) = self.mark_wake_horizon_obligation_possible_effect(obligation) {
            reconcile(&reason);
            return Ok((
                settled,
                unreached(UnreachedHorizonKind::UnknownOutcome, &reason),
            ));
        }
        match UserAutomationWakePort::publish_wake_horizon(runtime, publication.clone()).await {
            Ok(acknowledgement) => {
                settled.disposition = match self.settle_wake_horizon_acknowledgement(
                    obligation,
                    publication,
                    &acknowledgement,
                ) {
                    Ok(disposition) => disposition,
                    Err(reason) => {
                        reconcile(&reason);
                        return Ok((
                            settled,
                            unreached(UnreachedHorizonKind::UnknownOutcome, &reason),
                        ));
                    }
                };
                // The owner's acknowledgement is now the row's durable retained
                // body and `settled` carries that `Answered` disposition, so a
                // projection failure below must hand the caller the record it
                // wrote instead of a bare reason. `settled` is moved into the
                // refusal on that arm and returned on this one, so it is consumed
                // exactly once.
                let phase = match acknowledged_horizon_phase(
                    publication,
                    requested_occurrence_ids,
                    &acknowledgement,
                ) {
                    Ok(phase) => phase,
                    Err(reason) => {
                        return Err(UserAutomationHorizonPublicationRefusal::retained(
                            settled, reason,
                        ));
                    }
                };
                Ok((settled, phase))
            }
            // `Unavailable` is a LUMPED owner answer, NOT a "nothing was sent"
            // proof, and this branch must not read it as one. It is produced
            // both by a contour that never engaged a transport at all (the
            // `UserAutomationWakePort::publish_wake_horizon` trait default in
            // `user_automation_execution.rs`) and, on the composed Host route,
            // from inside an ALREADY-ISSUED publication. The Host wake adapter's
            // `map_journal_error` collapses `JournalError::Synchronization`,
            // `BackendError::Unavailable`, `BackendError::PlanGap` and the
            // explicitly indeterminate `BackendError::Unknown` into
            // `Unavailable`, and that one mapping fires both on the
            // per-occurrence journal append and on the post-append
            // acknowledgement readback, so a horizon whose every occurrence was
            // already retained can still answer `Unavailable`. Those answers
            // return as `UserAutomationHostExecutionFailure::Unavailable` and are
            // mapped back by `UserAutomationHostExecutionClient`, i.e. after a
            // complete authenticated round trip.
            //
            // The lump therefore cannot be split here. Reading it as clean
            // absence would re-open exactly the double-publish window issue
            // #2970 closes, and the record is already durably `Routed`, so the
            // obligation is reported unresolved under its original identity.
            //
            // The availability cost is real and is not hidden: an answer from
            // the never-engaged default IS provably never-sent, yet it is not
            // retryable from this contour. `UserAutomationRuntimeError` has no
            // value that separates "owner absent" from "owner's own state
            // unreadable or its write indeterminate", so the honest resolution
            // is to split that vocabulary on the owner's error contract, not to
            // infer a narrower meaning here. Tracked as a named follow-up.
            Err(UserAutomationRuntimeError::Unavailable(reason)) => {
                let detail = unretained_horizon_outcome_reason(
                    &publication.automation_revision,
                    &obligation.owner_operation_id,
                    &reason,
                );
                reconcile(&detail);
                Ok((
                    settled,
                    unreached(UnreachedHorizonKind::UnknownOutcome, &detail),
                ))
            }
            // The owner may have retained the slice and the answer was lost, so
            // the durable record is armed and a later attempt of this parent
            // operation reconciles it instead of publishing the slice again. A
            // typed refusal or a foreign answer is never a lost response, and
            // repeating the same request would be refused the same way, so it is
            // armed the same way rather than re-issued.
            Err(error) => {
                let detail = error.to_string();
                if let Err(arm) = self.mark_user_automation_obligation_unknown(obligation) {
                    reconcile(&arm);
                    return Ok((
                        settled,
                        unreached(UnreachedHorizonKind::UnknownOutcome, &arm),
                    ));
                }
                let reason = unretained_horizon_outcome_reason(
                    &publication.automation_revision,
                    &obligation.owner_operation_id,
                    &detail,
                );
                reconcile(&reason);
                Ok((
                    settled,
                    unreached(UnreachedHorizonKind::UnknownOutcome, &reason),
                ))
            }
        }
    }

    fn run_now_defer_reason(
        state: UserAutomationConfigurationState,
    ) -> Option<UserAutomationDeferReason> {
        match state {
            UserAutomationConfigurationState::Paused => Some(UserAutomationDeferReason::Paused),
            UserAutomationConfigurationState::Retired => Some(UserAutomationDeferReason::Retired),
            UserAutomationConfigurationState::Active
            | UserAutomationConfigurationState::BlockedConfig => None,
        }
    }

    /// Completes the `RunNow` handoff: exact committed/replayed invocation
    /// readback, current owner projection, and the owner readback of the wake
    /// for that exact occurrence over the authenticated runtime channel.
    async fn run_now_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
        automation_id: &str,
        automation_revision: &str,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let Some(UserAutomationMutationResult::RunNow {
            invocation,
            wake_intent,
        }) = configuration.mutation_result()
        else {
            return Err("run-now did not return a run-now projection".to_owned());
        };
        // The committed `WakeIntent` the canonical Store minted for this manual
        // occurrence beside the invocation is the owner record this join binds
        // through. It is kept rather than discarded in favour of a journal
        // readback, because a manual nonce is deliberately not a published
        // calendar occurrence (I11.12:33) and therefore never appears in the
        // Host wake journal at all.
        let committed_wake_intent = wake_intent.clone();
        let occurrence_id = invocation
            .occurrence_identity()
            .map_err(|error| error.to_string())?;
        let (owner, invocation) = self
            .read_run_now_owner(
                sealed,
                invocation,
                automation_id,
                automation_revision,
                &occurrence_id,
            )
            .await?;
        // The canonical owner can decide paused and retired admissions without
        // a Host wake or provider observation. Report that real disposition
        // even when no runtime channel is composed, and leave an admitted job
        // and its history untouched.
        let defer_reason = Self::run_now_defer_reason(owner.current_configuration_state);
        // An active or blocked revision still needs the remaining owner
        // preflight evidence. The committed configuration phase stays visible
        // beside that disposition, never as a failed commit.
        let Some(runtime) = runtime else {
            return Ok((
                UserAutomationWakePhase::Unavailable {
                    reason: unproven_wake_channel_reason(),
                },
                match defer_reason {
                    Some(reason) => UserAutomationExecutionPhase::Deferred { reason },
                    None => UserAutomationExecutionPhase::Unavailable {
                        reason: unproven_execution_channel_reason(),
                    },
                },
            ));
        };
        let wake = Self::resolve_run_now_wake_phase(sealed, &invocation, runtime).await;
        if let Some(reason) = defer_reason {
            return Ok((wake, UserAutomationExecutionPhase::Deferred { reason }));
        }
        // The committed occurrence joins the existing Durable Job execution path
        // through deterministic preflight: the complete projection is assembled
        // from the live owners, the service runs the model-free preflight, and
        // an admitted occurrence reaches the Durable Job owner over the composed
        // runtime channel.
        //
        // The occurrence binding this join needs is proved from the committed
        // owner record itself, not from a journal record that cannot exist for a
        // manual occurrence: the committed `WakeIntent` must name this exact
        // occurrence under this exact State Fence, which is the same pair
        // `UserAutomationExecutionRequest::validate` and the Durable Job
        // admission both re-check. A gate that no committed manual occurrence
        // could ever open is therefore replaced by a proof that one can, and
        // nothing is defaulted or substituted: a committed intent that does not
        // bind leaves the occurrence unadmitted beside its named reason.
        //
        // A retained readback, when the owner does answer with one, is still
        // held to full equality with that committed intent by
        // `UserAutomationOperatorTransition::validate_phase_joins`, so the
        // owner's own proof is never traded away for the committed one.
        if committed_wake_intent.wake_id != occurrence_id
            || committed_wake_intent.state_fence != sealed.context.state_fence
        {
            return Ok((
                wake,
                UserAutomationExecutionPhase::Unavailable {
                    reason: unproven_run_now_wake_reason(&occurrence_id),
                },
            ));
        }
        let wake_intent = committed_wake_intent;
        let projection = match self
            .assemble_run_now_preflight_projection(sealed, &owner, &invocation)
            .await
        {
            Ok(projection) => projection,
            // A preflight that could not be assembled is reported as the phase it
            // is, beside the committed configuration, rather than as a route error
            // that discards the committed `WriteReceipt` — the only carrier of that
            // commit. Nothing is claimed about an admission here: the assembly
            // stopped before the Durable Job owner was asked on this attempt, so the
            // disposition stays unresolved under this exact occurrence identity and
            // the caller reconciles it instead of being handed prose that names only
            // the occurrence.
            Err(assembly) => {
                return Ok(Self::project_run_now_preflight_assembly(
                    wake,
                    &occurrence_id,
                    assembly,
                ));
            }
        };
        // The blocked fingerprint is retained before the execution join moves
        // the projection: a blocked decision the notification owner cannot be
        // reached for must still name its deterministic failure class instead
        // of collapsing into an unattributed error.
        let blocked_fingerprint = match owner.current_configuration_state {
            UserAutomationConfigurationState::BlockedConfig => projection
                .failure
                .as_ref()
                .map(|failure| failure.failure_fingerprint.clone()),
            _ => None,
        };
        // The committed occurrence crosses into the existing `RunNow` execution
        // join with the complete owner-issued Durable Job material, rather than
        // through a hand-assembled execution request beside it. The join reads
        // the canonical run-now answer under the very identity this phase
        // already committed, so it replays that one operation and can neither
        // commit the invocation again nor mint a second manual nonce, and it
        // then runs the same deterministic preflight and Durable Job admission
        // every other occurrence uses.
        let durable_job = Self::owner_issued_durable_job_material(
            sealed,
            &invocation,
            &projection,
            wake_intent.clone(),
        );
        let outcome = self
            .join_run_now_occurrence(sealed, projection, durable_job, runtime)
            .await;
        Self::project_run_now_execution_outcome(
            wake,
            outcome,
            owner.current_configuration_state,
            blocked_fingerprint,
            &occurrence_id,
        )
    }

    /// Projects one preflight assembly this leg could not complete into the
    /// execution phase it is, beside the already-resolved wake phase.
    ///
    /// The committed configuration is deliberately NOT dropped here. The
    /// `WriteReceipt` it carries is the sole carrier of the committed run-now
    /// invocation, so returning a route error instead would leave the caller
    /// naming an occurrence it has no committed receipt for — which is the
    /// `recovery=null`-shaped loss item 9 of issue #2806 refuses. Both arms
    /// therefore return a phase the caller can act on, and `recovery()` still
    /// reports the unresolved disposition because neither phase is `resolved()`.
    ///
    /// The two arms are NOT merged, because they are not the same claim.
    /// [`RunNowPreflightAssembly::Unknown`] is an owner that could not be read:
    /// the Durable Job owner may already hold an answer this leg cannot see, so
    /// the honest phase is `UnknownOutcome` and the occurrence must be reconciled
    /// under its own identity. [`RunNowPreflightAssembly::Unavailable`] is named
    /// evidence with no issuer at this boundary, which proves nothing was sent,
    /// so it stays `Unavailable`. Collapsing them would either fabricate a
    /// possible effect that provably did not issue, or hide a possibly-issued
    /// effect behind "unreachable" — and this vocabulary deliberately keeps the
    /// two apart (see the `RunNowPreflightAssembly` contract).
    ///
    /// An unresolved wake changes what the execution phase may honestly say, and
    /// the change is a strict narrowing rather than a substitution. When the wake
    /// handoff is itself unresolved, the wake owner has already reported the
    /// answer this leg cannot see, and
    /// [`UserAutomationOperatorTransition::recovery`] returns that wake answer
    /// ahead of the execution phase, so the unresolved owner fact is still the
    /// caller's recovery directive. The execution phase then says only what is
    /// true of itself: the handoff to the Durable Job owner was never attempted,
    /// because the preflight stopped before the join. It claims no admission and
    /// no refusal, and `is_known()` is still false, so nothing here converts an
    /// unresolved answer into a decided one. This is also the only phase
    /// `validate_phase_joins` will join beside an unresolved wake, which is why
    /// the distinction is load-bearing rather than cosmetic.
    fn project_run_now_preflight_assembly(
        wake: UserAutomationWakePhase,
        occurrence_id: &str,
        assembly: RunNowPreflightAssembly,
    ) -> (UserAutomationWakePhase, UserAutomationExecutionPhase) {
        // A wake that names this occurrence — the owner's retained record or its
        // complete negative — is what an unresolved execution may sit beside. An
        // unresolved wake proves neither, so it is excluded here exactly as
        // `validate_phase_joins` excludes it there.
        let wake_proven = matches!(
            &wake,
            UserAutomationWakePhase::Published { .. }
                | UserAutomationWakePhase::NotApplicable { .. }
        );
        let execution = match assembly {
            RunNowPreflightAssembly::Unknown(reason) if wake_proven => {
                UserAutomationExecutionPhase::UnknownOutcome {
                    reason: unestablished_run_now_preflight_reason(occurrence_id, &reason),
                }
            }
            RunNowPreflightAssembly::Unknown(reason) => UserAutomationExecutionPhase::Unavailable {
                reason: unattempted_run_now_preflight_reason(occurrence_id, &reason),
            },
            RunNowPreflightAssembly::Unavailable(reason) => {
                UserAutomationExecutionPhase::Unavailable { reason }
            }
        };
        (wake, execution)
    }

    /// Resolves the wake phase of one committed `RunNow` occurrence over the
    /// authenticated runtime channel.
    ///
    /// The request reuses the admitted parent identity and the committed
    /// invocation, so a replayed Store mutation asks about the same original
    /// occurrence instead of minting another manual nonce.
    async fn resolve_run_now_wake_phase<R>(
        sealed: &UserAutomationServiceRequest,
        invocation: &UserAutomationInvocation,
        runtime: &R,
    ) -> UserAutomationWakePhase
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let wake_request = run_now_wake_read_request(
            sealed.context.clone(),
            sealed.authenticated_principal.clone(),
            sealed.identity.clone(),
            invocation.clone(),
        );
        match UserAutomationWakePort::read_pending_wake(runtime, wake_request).await {
            Ok(readback) => UserAutomationWakePhase::Published { readback },
            // A complete negative from the sole writer of that journal. The Host
            // journal publishes only the calendar occurrences the immutable
            // revision compiles, and an explicit manual `run-now` nonce is
            // deliberately outside that set (I11.12:33), so "the owner retains
            // no such wake" is the expected and correct answer here rather than
            // a lost one. Reporting it as an unknown would leave every committed
            // run-now permanently reconciling over a proven absence. Every other
            // answer - an owner that could not be reached, an answer that was
            // lost, a record about another occurrence - proves nothing and stays
            // unresolved.
            Err(UserAutomationRuntimeError::NotRetained(reason)) => {
                UserAutomationWakePhase::NotApplicable { reason }
            }
            Err(error) => UserAutomationWakePhase::UnknownOutcome {
                reason: error.to_string(),
            },
        }
    }

    /// Completes the owner-issued Durable Job submission for one occurrence the
    /// deterministic preflight admits, or reports that no such submission exists
    /// to hand over.
    ///
    /// Both occurrence legs reach this one helper: the committed `RunNow`
    /// occurrence [`Self::run_now_handoff`] carries, and the scheduled occurrence
    /// [`Self::due_wake_execution_join`] carries. Both then cross the same
    /// execution join with the completed submission.
    ///
    /// The submission is compiled by the existing
    /// [`UserAutomationDurableJobMaterial::from_admitted_occurrence`] out of the
    /// members this occurrence already carries: the accepted revision the
    /// preflight projection was assembled from, the deterministic preflight
    /// receipt that authorises the admission, the wake intent bound to this
    /// occurrence under this State Fence, and the authenticated parent identity.
    /// Nothing is defaulted and no value is asserted on an owner's behalf, so the
    /// occurrence identity, the certified capability closure and the declared
    /// cost and runtime ceilings the Durable Job owner is asked to admit are the
    /// ones the committed revision itself declares.
    ///
    /// The deterministic preflight is the owner's own pure decision function, so
    /// asking it here answers exactly one question: does an admitted occurrence
    /// exist for which owner-issued material can be completed at all. The
    /// execution join runs the same function on the same projection immediately
    /// before it builds the admission it sends, so this read cannot disagree
    /// with the decision the join makes. A preflight that does not admit, and a
    /// submission the compiler itself refuses, are both handed to the join
    /// without one: the join's own owner boundary is where that typed refusal is
    /// already produced, so the reported disposition stays the join's own answer
    /// rather than the same refusal restated under another error type.
    fn owner_issued_durable_job_material(
        sealed: &UserAutomationServiceRequest,
        invocation: &UserAutomationInvocation,
        projection: &UserAutomationPreflightProjection,
        wake_intent: WakeIntent,
    ) -> Option<UserAutomationDurableJobMaterial> {
        let context = UserAutomationPreflightContext {
            request_metadata: sealed.context.clone(),
        };
        let UserAutomationPreflightDecision::Admitted { receipt } =
            projection.preflight(invocation, &context).ok()?
        else {
            return None;
        };
        let admission = UserAutomationRuntimeAdmission {
            context: sealed.context.clone(),
            authenticated_principal: sealed.authenticated_principal.clone(),
            identity: sealed.identity.clone(),
            revision: projection.revision.clone(),
            invocation: invocation.clone(),
            preflight: receipt,
            wake_intent,
            durable_job: None,
        };
        UserAutomationDurableJobMaterial::from_admitted_occurrence(&admission).ok()
    }

    /// Hands one committed `RunNow` occurrence to the existing `RunNow` execution
    /// join over the composed runtime channel.
    ///
    /// The join is the same `UserAutomationService` contour every other
    /// occurrence uses: it dispatches the canonical run-now Store operation
    /// under the admitted parent identity, reads back the committed invocation
    /// and its wake intent, runs the deterministic preflight, and reaches the
    /// Durable Job owner. It adds no channel, no retry and no second admission.
    ///
    /// The two joins are different future types, so each arm owns its own
    /// awaited value. The material arm is polled through one box because
    /// `from_admitted_occurrence` holds a whole canonical-JSON K0
    /// `JobSubmission` and its digest inputs on the stack; the transient
    /// allocation is released as soon as the owner's answer is back, so this
    /// contour's own future stays bounded.
    async fn join_run_now_occurrence<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        projection: UserAutomationPreflightProjection,
        durable_job: Option<UserAutomationDurableJobMaterial>,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError>
    where
        R: UserAutomationRuntimePort + ?Sized,
    {
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(self));
        let service = UserAutomationService::new(&store);
        match durable_job {
            Some(material) => {
                Box::pin(service.run_now_and_execute_with_durable_job(
                    sealed.clone(),
                    projection,
                    material,
                    runtime,
                ))
                .await
            }
            None => {
                Box::pin(service.run_now_and_execute(sealed.clone(), projection, runtime)).await
            }
        }
    }

    /// Re-proves one committed `RunNow` occurrence against the live owner.
    ///
    /// The exact committed/replayed invocation readback is compared with the
    /// answer of this very identity, so a replayed Store mutation resumes the
    /// same occurrence and can never mint a second manual nonce or a second
    /// occurrence; the current owner revision must then bind the same
    /// automation, revision, and authenticated principal.
    async fn read_run_now_owner(
        &self,
        sealed: &UserAutomationServiceRequest,
        committed: &UserAutomationInvocation,
        automation_id: &str,
        automation_revision: &str,
        occurrence_id: &str,
    ) -> Result<(UserAutomationOwnerSnapshot, UserAutomationInvocation), String> {
        let persisted = self
            .read_user_automation_invocation(
                &sealed.context.state_fence,
                automation_id,
                occurrence_id,
            )
            .await?;
        if persisted != *committed {
            return Err(
                "committed UserAutomation occurrence does not match the canonical invocation readback"
                    .to_owned(),
            );
        }
        let owner = self
            .read_user_automation_owner(&UserAutomationOwnerLookup {
                automation_id: automation_id.to_owned(),
                requested_revision: automation_revision.to_owned(),
                authenticated_principal: sealed.authenticated_principal.clone(),
                state_fence: sealed.context.state_fence.clone(),
            })
            .await?;
        if owner.automation_id != automation_id
            || owner.revision.revision != automation_revision
            || owner.revision.owner_principal != sealed.authenticated_principal
        {
            return Err(
                "committed UserAutomation occurrence does not bind to the current owner revision"
                    .to_owned(),
            );
        }
        Ok((owner, persisted))
    }

    /// Projects one `RunNow` execution join into its transition phases.
    ///
    /// An admitted occurrence reaches the Durable Job owner; a deferred one
    /// carries its owner reason; a blocked one carries its deterministic
    /// failure fingerprint. An unreachable runtime owner leaves the occurrence
    /// unadmitted beside its named reason, except for a blocked decision the
    /// notification owner cannot be reached for, which stays unknown under its
    /// failure fingerprint instead of collapsing into an unattributed error.
    ///
    /// Every answer the Durable Job owner could give about an effect it may
    /// already have issued is the occurrence's `UnknownOutcome` disposition, not
    /// a route error and never an admission. This leg's wake phase names the
    /// occurrence at this point — the owner's retained record or its complete
    /// negative beside the committed owner intent that binds it — so the
    /// occurrence exists, its Durable Job identity is the occurrence identity,
    /// and the disposition names exactly that occurrence: the caller is told
    /// what must be reconciled instead of being handed a route error that
    /// discards the committed configuration and every phase beside it. A
    /// refusal the owner answered before any effect, and every precondition
    /// this leg could not establish locally, stay route errors: those provably
    /// admitted nothing, and no phase member may claim otherwise.
    fn project_run_now_execution_outcome(
        wake: UserAutomationWakePhase,
        outcome: Result<UserAutomationExecutionOutcome, UserAutomationExecutionError>,
        configuration_state: UserAutomationConfigurationState,
        blocked_fingerprint: Option<String>,
        occurrence_id: &str,
    ) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String> {
        match outcome {
            Ok(UserAutomationExecutionOutcome::Admitted { execution, .. }) => Ok((
                wake,
                UserAutomationExecutionPhase::Admitted {
                    execution: Box::new(execution),
                },
            )),
            Ok(UserAutomationExecutionOutcome::Deferred { reason, .. }) => {
                Ok((wake, UserAutomationExecutionPhase::Deferred { reason }))
            }
            Ok(UserAutomationExecutionOutcome::BlockedConfig { failure, .. }) => Ok((
                wake,
                UserAutomationExecutionPhase::BlockedConfig {
                    failure_fingerprint: failure.failure_fingerprint,
                },
            )),
            Err(UserAutomationExecutionError::Runtime(
                UserAutomationRuntimeError::Unavailable(reason),
            )) => {
                if configuration_state == UserAutomationConfigurationState::BlockedConfig
                    && let Some(fingerprint) = blocked_fingerprint
                {
                    return Err(format!(
                        "occurrence {occurrence_id} is blocked_config under failure \
                         fingerprint {fingerprint}, decided before any model call, but the \
                         failure-history and notification owners are not reachable from the \
                         operator route: {reason}"
                    ));
                }
                Ok((wake, UserAutomationExecutionPhase::Unavailable { reason }))
            }
            // The join crossed the Durable Job admission boundary and the owner
            // did not establish what it did there: the answer was lost, it was
            // settled without a readable ledger result, it was bound to another
            // identity, or it returned a reference that does not bind to this
            // occurrence. The occurrence is therefore unadmitted exactly as far
            // as this caller can prove, and the only honest member of the
            // canonical disposition vocabulary is `UnknownOutcome`. It is never
            // reported as `Admitted`, and it is not discarded into a route error
            // that would hide the committed Store receipt and the occurrence the
            // caller must reconcile.
            Err(
                error @ (UserAutomationExecutionError::Runtime(
                    UserAutomationRuntimeError::UnknownOutcome(_)
                    | UserAutomationRuntimeError::IdentityConflict
                    | UserAutomationRuntimeError::OutcomeSettled(_),
                )
                | UserAutomationExecutionError::RuntimeResponseMismatch(_)),
            ) => Ok((
                wake,
                UserAutomationExecutionPhase::UnknownOutcome {
                    reason: unestablished_run_now_execution_reason(occurrence_id, &error),
                },
            )),
            // A refusal the runtime owner answered before any owner effect is a
            // DECIDED answer, not a lost one: the owner read the typed admission
            // request and refused it, so the occurrence provably admitted nothing
            // and there is no effect to reconcile. It is therefore neither an
            // unknown outcome (which would claim an effect may have issued) nor
            // an admission (which would claim a job that does not exist), and the
            // owner's own reason is carried through rather than re-derived here —
            // only the refusing owner can say why it refused.
            Err(UserAutomationExecutionError::Runtime(UserAutomationRuntimeError::Rejected(
                reason,
            ))) => Ok((wake, UserAutomationExecutionPhase::Rejected { reason })),
            // A precondition this leg could not prove locally also admitted
            // nothing, but it carries no owner decision to report, so it stays a
            // route error rather than being dressed up as one.
            Err(error) => Err(error.to_string()),
        }
    }

    /// Seeds the Store's all-absent genesis state under the active Kernel
    /// admission lease. Unknown outcome handling remains owned by the EBP
    /// client, which reconciles the exact operation identity.
    pub async fn initialize_genesis(
        &self,
        context: &RequestMeta,
        request: StoreGenesisRequest,
    ) -> Result<WriteReceipt, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        // I14.16 step 4: a `shadow_no_authority` candidate performs no Store
        // write. The gate precedes the normal admission lease below.
        self.refuse_shadow_mutation()?;
        context.validate().map_err(|error| error.to_string())?;
        request
            .validate_for_context(context)
            .map_err(|error| error.to_string())?;
        if context.source_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err("genesis caller is not the active daemon".to_owned());
        }
        self.validate_active_route(&context.state_fence)?;
        if request.state_fence != context.state_fence {
            return Err("genesis request fence does not match request metadata".to_owned());
        }

        let lease = {
            let service = self
                .service
                .lock()
                .map_err(|_| "Kernel service lock poisoned".to_owned())?;
            if service.generation_fenced() {
                return Err("Kernel generation is fenced".to_owned());
            }
            let lease = service
                .acquire_admission()
                .map_err(|error| error.to_string())?;
            // Slices A+B (#65): genesis is normal Store work holding the
            // typed `NORMAL_WORKLOAD` normal lease; see the `apply` path
            // note and `lifecycle.rs:acquire_admission`.
            if lease.authority_epoch() != request.state_fence.authority_epoch {
                return Err("genesis route authority epoch is stale".to_owned());
            }
            lease
        };
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        let identity = eliot_store_api::OperationIdentity {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            canonical_request_hash: request.canonical_request_hash.clone(),
        };
        // I14.21 (#1690): genesis commits run the same recovery. Genesis
        // names no ordering scopes, so nothing pauses, but the durable
        // unknown-commit record plus disposition-first still apply.
        let send = || self.store.initialize_genesis(context, request.clone());
        let query = || {
            self.store.receipt_exact(
                identity.operation_id.clone(),
                identity.canonical_request_hash.as_str(),
            )
        };
        let result = recover_commit(
            self.commit_ors.as_deref(),
            &self.paused_scopes,
            &identity,
            &[],
            send,
            query,
        )
        .await
        .map_err(|error| error.to_string());
        drop(lease);
        result
    }

    /// Applies one closed Dreamer ledger operation through the active Kernel
    /// generation route (T12-04 K1, owner #779). Public input/output remain
    /// exactly the S0 K0 types. Gates mirror `initialize_genesis` (flight
    /// enter, fence, validation, active route, fence equality, one admission
    /// lease, a single store call, deterministic release), except the caller
    /// rule: the closed K0 `JobRole` projection decides, never the
    /// `eliotd` source check. The presented role agrees with the operation
    /// but grants nothing by itself; K2 binds the authenticated principal.
    ///
    /// Unknown-commit recovery (I14.21, issue #1690) is Kernel-owned here, as
    /// it already is for [`Self::apply`] and [`Self::initialize_genesis`]:
    ///
    /// ```text
    /// pause gate (paused scope? refuse, naming the open Problem State)
    ///   -> send once through the EBP client
    ///   -> Ok(answer)          -> return it (exactly one mutation)
    ///   -> proven receipt      -> reconcile the durable ORS record with the
    ///                             receipt digest bound as its evidence
    ///   -> still unknown      -> preserve the operation, pause its Ordering
    ///                             Scopes, open a recoverable Problem State
    ///   -> deterministic refusal -> returned unchanged
    /// ```
    ///
    /// The EBP client still owns the exact receipt lookup performed before any
    /// retry, but the receipt it proves is no longer discarded: the outcome is
    /// reconciled into the durable record that `I14.21` requires to survive a
    /// restart, and a still-unknown outcome opens a recoverable Problem State
    /// instead of vanishing. Nothing is ever resent under a fresh identity and
    /// no acceptance is synthesized.
    ///
    /// ## Exact recovery before the pause gate (issue #2764)
    ///
    /// An operation's own pause used to block its own evidence: the pause
    /// gate ran before the client, so a retained unknown commit K refused at
    /// the pause K itself opened and could never reach the receipt that
    /// settles it. The order is now:
    ///
    /// ```text
    /// existing caller/role/route/fence checks
    ///   -> classify the closed operation by its real owner effect
    ///   -> classify K's retained state from the exact ORS identity
    ///        Absent  -> new-send path below
    ///        Open|Terminal
    ///             -> protected recovery admission
    ///             -> observation-only exact receipt lookup, ZERO sends
    ///                  committed                  -> persist/reuse the
    ///                                                 terminal disposition,
    ///                                                 retain its digest,
    ///                                                 return committed
    ///                                                 recovery evidence
    ///                  proven noncommit, same
    ///                  identity retryable       -> re-enter normal admission
    ///                                                 and the other-key pause
    ///                                                 gate for one bounded
    ///                                                 same-identity retry
    ///                  nonretryable directive   -> retain that exact terminal
    ///                                                 outcome, allocate nothing
    ///                  missing/unavailable      -> K stays open and paused,
    ///                                                 no resend, no rollback
    ///                  identity/evidence conflict -> reject adoption, keep
    ///                                                 the old history
    ///   -> new-send path: normal admission lease, checked pause gate, one send
    /// ```
    ///
    /// A pause may prohibit a new write; it does not alone prohibit a
    /// permitted read of K's own receipt, so the read-first branch is a real
    /// receipt query and not a skipped self-pause followed by the ordinary
    /// mutation send. The retained record keeps its original operation and
    /// fence data; only the new recovery request is authenticated under
    /// current authority.
    ///
    /// ## The typed answer reaches the caller (issue #2764 item 6)
    ///
    /// The error type is [`DreamerJobGatewayError`], not `String`. A settled
    /// recovery leg returns [`DreamerJobGatewayError::Uncertain`] carrying the
    /// [`DreamerCommitUncertain`] value itself, so the caller receives the
    /// original operation/key, the exact recorded outcome, the receipt evidence
    /// digest, and the remaining `Status`/`Reconcile` ledger-read obligation as
    /// values it can branch on. A `WriteReceipt` proves a mutation disposition,
    /// never the missing `DurableJobResponse`, so no terminal state is reduced
    /// to an ambiguous success. Every non-recovery refusal keeps its own variant
    /// too: [`DreamerJobGatewayError::Commit`] holds the whole
    /// [`CommitRecoveryError`] set and [`DreamerJobGatewayError::GatewayRefusal`]
    /// holds this route's pre-existing gate text unchanged, so the only string
    /// conversion left is the caller's own frame projection.
    pub async fn dreamer_job(
        &self,
        context: &RequestMeta,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, DreamerJobGatewayError> {
        let _flight = self
            .flight
            .enter()
            .map_err(DreamerJobGatewayError::GatewayRefusal)?;
        if self.is_fenced() {
            return Err(DreamerJobGatewayError::GatewayRefusal(
                "canonical-store gateway is fenced for rebind".to_owned(),
            ));
        }
        // The retained-recovery leg below reaches the Store before the
        // transition's own route check, so the active-generation gate has to
        // precede the whole method rather than the send.
        self.require_active_store_generation()
            .map_err(|error| DreamerJobGatewayError::GatewayRefusal(error.to_string()))?;
        // I14.16 step 4: a `shadow_no_authority` candidate performs no Store
        // write. The gate reuses this module's own
        // [`dreamer_operation_effect`] classification, so a permitted
        // `Status` read stays available (the read-only inspection I14.16 step
        // 3 allows) while every ledger mutation is refused before the durable
        // recovery state is read and before the retained-commit
        // classification, so a shadow candidate cannot stage, classify or
        // reconcile a mutation.
        let (identity, scope_proof, effect) = self.admit_dreamer_operation(context, &request)?;
        // `true` means this operation is making its ONE bounded same-identity
        // retry under a still-open retained record; `false` means no retained
        // state existed. A retained state that has already been reached and
        // settled never returns here — that answer leaves as the typed
        // `DreamerJobGatewayError::Uncertain` instead.
        let retried_under_retained_record = self
            .reach_retained_dreamer_recovery(&identity, &scope_proof, effect)
            .await?;

        let lease = {
            let service = self.service.lock().map_err(|_| {
                DreamerJobGatewayError::GatewayRefusal("Kernel service lock poisoned".to_owned())
            })?;
            if service.generation_fenced() {
                return Err(DreamerJobGatewayError::GatewayRefusal(
                    "Kernel generation is fenced".to_owned(),
                ));
            }
            let lease = service
                .acquire_admission()
                .map_err(|error| DreamerJobGatewayError::GatewayRefusal(error.to_string()))?;
            // Slices A+B (#65): Dreamer-job Store admission rides the typed
            // `NORMAL_WORKLOAD` normal lease; protected work stays on
            // `acquire_protected_control`. See
            // `lifecycle.rs:acquire_admission`. The recovery leg above does
            // NOT ride this normal lease, so exhausted normal capacity cannot
            // make an admitted operation's own recovery unreachable.
            if lease.authority_epoch() != context.state_fence.authority_epoch {
                return Err(DreamerJobGatewayError::GatewayRefusal(
                    "dreamer job route authority epoch is stale".to_owned(),
                ));
            }
            lease
        };
        if self.is_fenced() {
            return Err(DreamerJobGatewayError::GatewayRefusal(
                "canonical-store gateway is fenced for rebind".to_owned(),
            ));
        }
        // Checked pause gate (#2763). The owner is observed here, after
        // admission and immediately before the send, so a pause published
        // after this point cannot be missed by a clearance computed at
        // construction, and an unreadable ledger closes admission rather than
        // permitting it. `Self::paused_ordering_scopes` is the visible
        // Problem State; this reads the same checked observation as the
        // admission input, not the display projection.
        if effect == DreamerOperationEffect::Mutation {
            let observed = self.paused_scopes.observe(self.commit_ors.as_deref());
            if let Some(error) = observed.unavailable_error() {
                return Err(error.into());
            }
            if let Some(refusal) = dreamer_pause_refusal(&observed, &identity, &scope_proof, effect)
            {
                return Err(refusal.into());
            }
        }
        let result = match self.store.dreamer_job_recovery(context, request).await {
            Ok(response) => {
                // A successful same-identity retry settles nothing on its own:
                // the ledger answer is not receipt evidence, so the retained
                // record is resolved by reading its exact mutation receipt.
                // A ledger `Status` alone could never settle it.
                if retried_under_retained_record {
                    self.settle_after_same_identity_retry(&identity, &scope_proof.scopes)
                        .await?;
                }
                Ok(response)
            }
            Err(DreamerCommitEvidence::Refused(error)) => {
                Err(DreamerJobGatewayError::GatewayRefusal(error.to_string()))
            }
            // Both arms below answer with the *typed* recovered outcome when the
            // commit is settled, and `?` carries the typed recovery error when it
            // is not. Neither the exact disposition nor the failure that kept
            // it unsettled is rendered to text here.
            Err(DreamerCommitEvidence::Reconciled(receipt)) => {
                Err(DreamerJobGatewayError::Uncertain(
                    self.reconcile_dreamer_commit(&identity, &scope_proof.scopes, &receipt)?,
                ))
            }
            Err(DreamerCommitEvidence::Unknown) => Err(DreamerJobGatewayError::Uncertain(
                self.preserve_dreamer_operation(&identity, &scope_proof.scopes)?,
            )),
        };
        drop(lease);
        result
    }

    /// Returns the typed refusal when durable recovery state is unavailable,
    /// or `None` when a complete observation is available.
    fn pause_observation_limitation(&self) -> Option<CommitRecoveryError> {
        self.paused_scopes
            .observe(self.commit_ors.as_deref())
            .unavailable_error()
    }

    /// Runs every Dreamer gate that precedes any retained-state work and
    /// returns the admitted identity, its proven Ordering Scope set, and its
    /// owner effect class (issue #2764 items 1 and 6).
    ///
    /// The order here is load-bearing. The `shadow_no_authority` refusal, the
    /// two contract validations, the presented-role projection, the active-route
    /// check and the fence-equality join all run before anything is read from
    /// durable state, and the contract-recomputed canonical request hash
    /// (`verify_dreamer_canonical_request_hash`, I5.27) runs last among them:
    /// a spelled hash is refused before the retained state is classified,
    /// before a receipt is queried, and before any send is authorized, so a
    /// caller-spelled identity can never reach recovery. The digest that leaves
    /// this function is the contract-derived one, and it is what the identity
    /// carries into retained-state comparison — not the string the caller
    /// presented.
    fn admit_dreamer_operation(
        &self,
        context: &RequestMeta,
        request: &DurableJobRequest,
    ) -> Result<
        (
            OperationIdentity,
            DreamerOrderingScopeProof,
            DreamerOperationEffect,
        ),
        DreamerJobGatewayError,
    > {
        if dreamer_operation_effect(&request.operation) == DreamerOperationEffect::Mutation {
            self.refuse_shadow_mutation()
                .map_err(DreamerJobGatewayError::GatewayRefusal)?;
        }
        context
            .validate()
            .map_err(|error| DreamerJobGatewayError::GatewayRefusal(error.to_string()))?;
        request
            .validate()
            .map_err(|error| DreamerJobGatewayError::GatewayRefusal(error.to_string()))?;
        if !request.role.permits(request.operation.kind()) {
            return Err(DreamerJobGatewayError::GatewayRefusal(
                "dreamer job caller role does not permit the operation".to_owned(),
            ));
        }
        self.validate_active_route(&context.state_fence)
            .map_err(DreamerJobGatewayError::GatewayRefusal)?;
        if request.request_identity.operation.state_fence != context.state_fence {
            return Err(DreamerJobGatewayError::GatewayRefusal(
                "dreamer job request fence does not match request metadata".to_owned(),
            ));
        }
        // Durable recovery state must be available for mutating work even when
        // the local scope vector is empty (#2763). A permitted read and the
        // exact receipt lookup stay available: I14.24 keeps read-only
        // inspection and independent noncanonical work alive.
        let effect = dreamer_operation_effect(&request.operation);
        if effect == DreamerOperationEffect::Mutation
            && let Some(error) = self.pause_observation_limitation()
        {
            return Err(error.into());
        }
        // I14.21 (#1690) write-attempt identity: the admitted Dreamer mutation
        // identity, taken from the stable operation binding only. Fresh
        // transport correlation never enters it, so a retry under the same
        // identity always reuses this record. Its canonical request hash is the
        // contract-recomputed one, not caller spelling (I5.27, #2764 item 1).
        let identity = OperationIdentity {
            operation_id: request.request_identity.operation.operation_id.clone(),
            idempotency_key: request.request_identity.operation.idempotency_key.clone(),
            canonical_request_hash: verify_dreamer_canonical_request_hash(request)?,
        };
        Ok((identity, dreamer_ordering_scope_proof(request), effect))
    }

    /// Reaches this operation's own retained commit evidence before the
    /// normal scope-pause gate (issue #2764).
    ///
    /// Returns `Ok(true)` when the caller may make its one bounded
    /// same-identity retry under the still-open retained record, and `Ok(false)`
    /// when no retained state exists and the new-send path applies. A retained
    /// state that has been *reached* leaves as the typed
    /// [`DreamerJobGatewayError::Uncertain`] answer instead, so the caller
    /// receives the recorded outcome and evidence as values.
    ///
    /// An already-terminal record is answered from the record itself, on this
    /// side of the observation-only receipt read, and that ordering is the
    /// point rather than an accident. The `Open | Terminal` destructuring below
    /// binds `record` for BOTH classified states, so one guard placed here
    /// afterwards is provably reached by each of them, while a guard written
    /// into either arm of that match would be reachable only from the arm it
    /// sits in. Once a disposition is durably recorded the outcome is settled:
    /// a store read that reports "no receipt" for a key ORS already holds as
    /// `Committed` is no longer evidence about that key, and treating it as
    /// such would replace a proven terminal result with an open Problem State
    /// and fence the caller for a mutation that provably did commit. This is
    /// what makes replay after a restart or a lost response return the same
    /// outcome without a second mutation and without a store read at all.
    ///
    /// An unreadable record is never absent: [`classify_retained_commit`]
    /// returns the typed ORS failure rather than an empty answer, and the
    /// comparison runs against the operation's own proven scope set — the exact
    /// set the record was staged with — so a record that paused a different
    /// scope set is a conflict at classification time.
    async fn reach_retained_dreamer_recovery(
        &self,
        identity: &OperationIdentity,
        scope_proof: &DreamerOrderingScopeProof,
        effect: DreamerOperationEffect,
    ) -> Result<bool, DreamerJobGatewayError> {
        let retained =
            classify_retained_commit(self.commit_ors.as_deref(), identity, &scope_proof.scopes)?;
        let record = match &retained {
            RetainedCommitState::Absent => return Ok(false),
            RetainedCommitState::Open { record } | RetainedCommitState::Terminal { record } => {
                record
            }
        };
        // The already-terminal check sits ABOVE the match's per-arm work and
        // ABOVE the observation-only receipt read, and `record` above is bound
        // for both the `Open` and the `Terminal` arm, so neither can bypass it
        // and no arm-specific edit can reintroduce the ordering. A terminal
        // record keeps its recorded outcome and evidence digest as values: it
        // releases the pause its own earlier disposition may have left open,
        // and it never reads the store, because a receipt that cannot be read
        // says nothing about a disposition ORS has already durably recorded.
        if record.outcome.is_some() {
            return Err(DreamerJobGatewayError::Uncertain(
                self.replay_terminal_retained_answer(record)?,
            ));
        }
        // The typed answer is the caller-facing report. It travels as itself so
        // the caller can act on the distinction between a reconciled commit, a
        // preserved earlier disposition, a disposition whose pause release is
        // incomplete, and a still-open Problem State. The obligation it names —
        // a ledger `Status`/`Reconcile` read — is why this can never be
        // reported as a completed operation.
        match self
            .reconcile_retained_dreamer_operation(identity, &scope_proof.scopes, record)
            .await?
        {
            DreamerRetainedOutcome::Settled(answer) => {
                Err(DreamerJobGatewayError::Uncertain(answer))
            }
            // A proven noncommit whose resubmission policy allows the same
            // identity again, observed while the record is still open. The
            // record keeps owning this retry: it is not resolved first, so the
            // terminal-state invariant is not bypassed. Falling through re-enters
            // current normal admission and the other-key pause check for exactly
            // one bounded same-identity send, keeping the original operation,
            // content, authorized effect and retry budget. This leg issued zero
            // mutation sends: the receipt query is a pure read and is not
            // counted as another attempt.
            DreamerRetainedOutcome::SameIdentityRetryPermitted => {
                Ok(effect == DreamerOperationEffect::Mutation)
            }
        }
    }

    /// Resolves the still-open record a same-identity retry was made under.
    ///
    /// The retry's `DurableJobResponse` is the ledger answer, not receipt
    /// evidence, so the record is settled by reading the exact mutation
    /// receipt and binding its digest. This is the observation-only exact
    /// receipt client again — a pure read, so it is not counted as another
    /// mutation attempt and the retry budget is not consumed — and it is the
    /// only thing that can resolve the record: a ledger `Status` alone cannot.
    ///
    /// A missing or unavailable receipt leaves the record open and its pauses
    /// in force: no second send, no rollback, and no claim that nothing
    /// happened. The service mutex is not held across this `await` — the
    /// caller's admission lease is an owned guard, not a lock, and the
    /// `commit_ors` handle is read before the query.
    async fn settle_after_same_identity_retry(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
    ) -> Result<(), CommitRecoveryError> {
        let Some(ors) = self.commit_ors.as_deref() else {
            return Err(CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "the same-identity retry for Dreamer operation {} returned a ledger answer, \
                     but no durable recovery owner is bound to bind its receipt evidence, so the \
                     record stays open",
                    identity.idempotency_key
                ),
            });
        };
        let key = identity.idempotency_key.as_str();
        let staged = ors.load_unknown_commit(key).map_err(|error| {
            CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "the same-identity retry for Dreamer operation {key} returned a ledger answer, \
                     but its retained record could not be re-read to bind receipt evidence: \
                     {error}; the record stays open"
                ),
            }
        })?;
        let Some(record) = staged else {
            // The record is gone: nothing is retained to settle.
            return Ok(());
        };
        if record.outcome.is_some() {
            // A concurrent reconciliation already settled it; its recorded
            // outcome stands and is never replaced here.
            return Ok(());
        }
        let receipt = self
            .store
            .receipt_exact(
                identity.operation_id.clone(),
                identity.canonical_request_hash.as_str(),
            )
            .await;
        let receipt = match receipt {
            Ok(receipt) => receipt,
            // Missing, unavailable or inconclusive: the record and its pauses
            // stay unresolved. No resend, no rollback, no false no-effect.
            Err(StoreError::MissingReceiptEnvelope | StoreError::Unavailable) => {
                self.paused_scopes.record_paused(ordering_scopes, key);
                return Ok(());
            }
            // A substituted receipt or a digest divergence is a conflict and
            // is carried as itself rather than flattened into the record.
            Err(error) => {
                return Err(CommitRecoveryError::ReceiptQueryFailed {
                    idempotency_key: key.to_owned(),
                    detail: format!(
                        "the same-identity retry for Dreamer operation {key} returned a ledger \
                         answer, but its exact receipt evidence could not be adopted: {error}; the \
                         record stays open and its Ordering Scopes stay paused"
                    ),
                });
            }
        };
        verify_receipt_binding(&receipt, identity)?;
        let outcome = match classify_commit_receipt(&receipt) {
            CommitRecoveryClass::Committed => UnknownCommitOutcome::Committed,
            CommitRecoveryClass::KnownRollback => UnknownCommitOutcome::RolledBack,
            CommitRecoveryClass::NeedsNewIdentity(outcome) => outcome,
        };
        let evidence_receipt_digest = receipt_evidence_digest(&receipt);
        let disposition = self.commit_dreamer_disposition(
            identity,
            ordering_scopes,
            outcome,
            &evidence_receipt_digest,
        );
        // This leg reports only that the durable disposition succeeded; a
        // refresh limitation a successful release still carries is reported on
        // the answer the gateway returns, not here. The disposition path
        // renders its own typed variant, so that rendering is carried verbatim
        // as the cause of this typed failure: no blanket `From<String>`
        // conversion is introduced for this seam.
        if let Err(error) = disposition {
            return Err(CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "the same-identity retry for Dreamer operation {key} reached exact receipt \
                     evidence, but its durable disposition could not be recorded: {error}; the \
                     record stays open and its Ordering Scopes stay paused"
                ),
            });
        }
        Ok(())
    }

    /// Reaches exact receipt evidence for one retained Dreamer operation
    /// before the normal scope-pause gate, and settles it from that evidence
    /// (issue #2764).
    ///
    /// This is the read-first branch, and it is a genuine read: the only
    /// transport call is the crate's existing observation-only
    /// `receipt_exact` for the exact admitted operation and canonical request
    /// hash. It is not a skipped self-pause followed by the ordinary
    /// mutation send, and it never calls `dreamer_job_recovery`.
    ///
    /// Admission is the *protected* recovery lane
    /// (`reconciliation:<key>` → `UnknownOutcomeReconciliation`), so
    /// exhausted normal capacity cannot make an admitted operation's own
    /// recovery unreachable (I14.3). Caller authorization, route currency and
    /// fence equality were already checked by `dreamer_job` before this runs;
    /// the retained record's own historical operation and fence data is
    /// preserved exactly as staged and is never rewritten to today's epoch.
    ///
    /// Evidence handling follows the existing receipt classifier and
    /// resubmission policy, not an enum name.
    ///
    /// Only a record that is still OPEN reaches this function.
    /// `reach_retained_dreamer_recovery` answers an already-terminal record
    /// from the record itself, before the read below, because a store
    /// observation cannot unsettle a disposition ORS has already durably
    /// recorded. What this function decides is therefore only what an open
    /// record does with the receipt it can reach:
    ///
    /// * a committed receipt persists K's terminal disposition, retains its
    ///   digest, releases only the scopes no other open record covers, and
    ///   returns committed-recovery evidence with the remaining ledger-read
    ///   obligation — no resend;
    /// * a proven noncommit whose `Resubmission` still allows the identical
    ///   identity, observed while K is open, permits one bounded
    ///   same-identity retry through the caller's normal path;
    /// * a dead-lettered or new-identity-required disposition retains that
    ///   exact terminal outcome and directive and allocates nothing here;
    /// * a missing, unavailable or inconclusive receipt keeps K and its
    ///   pauses unresolved: no resend, no automatic rollback, and no false
    ///   no-effect result;
    /// * an identity or content conflict rejects the adoption, preserves the
    ///   old history and exposes the exact conflict.
    async fn reconcile_retained_dreamer_operation(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
        record: &UnknownCommitRecord,
    ) -> Result<DreamerRetainedOutcome, CommitRecoveryError> {
        // Precondition, asserted once at the function boundary rather than per
        // arm: `record` is open here and only here. `reach_retained_dreamer_recovery`
        // tests `record.outcome.is_some()` before it forwards ANY retained record
        // to this function, and it tests it on the ONE `record` binding that both
        // arms of its `Open | Terminal` destructuring produce, so no arm of that
        // match can bypass the test and no per-arm edit can reintroduce the
        // ordering. That single hoist is also why the terminal projection has
        // exactly one owner, `Self::replay_terminal_retained_answer`, and why this
        // function needs no second copy of it.
        debug_assert!(record.is_open());
        let key = identity.idempotency_key.as_str();
        // Protected recovery admission: a retained unknown commit is
        // `UnknownOutcomeReconciliation` work, not normal workload, so
        // saturation of the normal partition leaves this lane open.
        let _recovery = {
            let service = self
                .service
                .lock()
                .map_err(|_| CommitRecoveryError::OrsUnavailable {
                    detail:
                        "Kernel service lock poisoned, so the protected recovery lane for this \
                             retained operation cannot be acquired"
                            .to_owned(),
                })?;
            service
                .acquire_protected_control(&format!("reconciliation:{key}"))
                .map_err(|error| CommitRecoveryError::OrsUnavailable {
                    detail: format!(
                        "the protected recovery lane for retained operation {key} is not \
                         available ({error}); its own exact recovery stays reachable while normal \
                         capacity is exhausted, so this is not a normal-admission refusal"
                    ),
                })?
        };
        if self.is_fenced() {
            return Err(CommitRecoveryError::OrsUnavailable {
                detail: "canonical-store gateway is fenced for rebind, so the retained operation \
                         was not read"
                    .to_owned(),
            });
        }
        // Observation-only exact receipt query under the current route. The
        // service mutex was released with the block above; only the protected
        // permit is held, deliberately, across this read. If the lookup itself
        // is cancelled, the prior source and effect uncertainty is preserved
        // untouched: nothing below has run, K stays open, and its pauses stay
        // in force.
        let receipt = self
            .store
            .receipt_exact(
                identity.operation_id.clone(),
                identity.canonical_request_hash.as_str(),
            )
            .await;
        let receipt = match receipt {
            Ok(receipt) => receipt,
            // Missing, unavailable or inconclusive: K and its pauses stay
            // unresolved. No resend, no rollback, and never a claim that no
            // effect happened.
            Err(StoreError::MissingReceiptEnvelope | StoreError::Unavailable) => {
                return Ok(DreamerRetainedOutcome::Settled(
                    DreamerCommitUncertain::UnknownCommitOpen {
                        idempotency_key: key.to_owned(),
                        paused_scopes: record.ordering_scopes.clone(),
                    },
                ));
            }
            // A substituted receipt or a determinate refusal is carried as
            // itself; an identity conflict stays a conflict.
            Err(error) => {
                return Err(CommitRecoveryError::ReceiptQueryFailed {
                    idempotency_key: key.to_owned(),
                    detail: error.to_string(),
                });
            }
        };
        // The one full operation/key/hash verifier runs at this adoption, and
        // the retained record was already binding-verified by
        // `classify_retained_commit`. A receipt for another operation that
        // happens to share this key is never adopted.
        verify_receipt_binding(&receipt, identity)?;
        let outcome = match classify_commit_receipt(&receipt) {
            CommitRecoveryClass::Committed => UnknownCommitOutcome::Committed,
            CommitRecoveryClass::KnownRollback => UnknownCommitOutcome::RolledBack,
            CommitRecoveryClass::NeedsNewIdentity(outcome) => outcome,
        };
        let evidence_receipt_digest = receipt_evidence_digest(&receipt);
        // A proven noncommit that the Store's own resubmission policy
        // still allows under this identical identity. The record stays
        // open, so it keeps owning the retry; the caller re-enters normal
        // admission and the other-key pause check for one bounded send.
        if matches!(
            classify_commit_receipt(&receipt),
            CommitRecoveryClass::KnownRollback
        ) {
            Ok(DreamerRetainedOutcome::SameIdentityRetryPermitted)
        } else {
            Ok(DreamerRetainedOutcome::Settled(
                self.commit_retained_disposition(
                    identity,
                    ordering_scopes,
                    outcome,
                    &evidence_receipt_digest,
                    key,
                )?,
            ))
        }
    }

    /// Commits the durable disposition for a retained operation that has now
    /// reached receipt evidence, and reports the reconciled result.
    ///
    /// The disposition path reports its own typed variant, so a durable commit
    /// that cannot be recorded is composed here into the same
    /// [`CommitRecoveryError::OrsUnavailable`] the other disposition sites use,
    /// naming the retained key. No blanket `From<String>` conversion is
    /// introduced for this seam: the reported variant still leaves here as the
    /// [`DreamerCommitUncertain`] value, not as rendered text.
    fn commit_retained_disposition(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
        outcome: UnknownCommitOutcome,
        evidence_receipt_digest: &str,
        key: &str,
    ) -> Result<DreamerCommitUncertain, CommitRecoveryError> {
        let disposition = self.commit_dreamer_disposition(
            identity,
            ordering_scopes,
            outcome,
            evidence_receipt_digest,
        );
        if let Err(error) = disposition {
            return Err(CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "the retained operation {key} reached receipt evidence, but its \
                     durable disposition could not be recorded: {error}; the record stays \
                     open and its Ordering Scopes stay paused"
                ),
            });
        }
        Ok(DreamerCommitUncertain::Reconciled {
            idempotency_key: key.to_owned(),
            evidence_receipt_digest: evidence_receipt_digest.to_owned(),
            outcome,
        })
    }

    /// Reconciles one proven Dreamer commit into the durable ORS record
    /// (I14.21, issue #1690).
    ///
    /// The client proved the outcome with an exact receipt bound to the
    /// admitted identity, so exactly one canonical operation exists under that
    /// identity and this path never resends it. It stages the durable
    /// pending-operation record and resolves it exactly once with the receipt
    /// digest bound as its terminal evidence, so the preserved evidence
    /// survives a restart and an operator can read what the commit was. The
    /// terminal outcome is the receipt's own classification, so a proven
    /// rollback is recorded as `RolledBack` and a dead-lettered one as
    /// `DeadLetter` — this leg never upgrades a non-commit into a commit. A
    /// proven outcome pauses nothing: it only lifts the pause an earlier
    /// unknown outcome opened for the same key, through
    /// [`Self::release_dreamer_scopes`]. A key already dispositioned keeps its
    /// earlier evidence-backed disposition, because a resolved record never
    /// reopens.
    fn reconcile_dreamer_commit(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
        receipt: &WriteReceipt,
    ) -> Result<DreamerCommitUncertain, CommitRecoveryError> {
        // The one full operation/key/hash verifier runs at this adoption. The
        // previous entry compared only the receipt's idempotency key, which let
        // a receipt for a different operation sharing that key reach the
        // durable record; operation id and canonical request hash are compared
        // here too, so another attempt's receipt is never adopted as this
        // operation's evidence however it was observed.
        verify_receipt_binding(receipt, identity)?;
        let ors = self.commit_ors.as_deref().ok_or_else(|| {
            CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "ORS recovery unavailable: the exact receipt for Dreamer operation {} cannot be bound as durable unknown-commit evidence, so no reconciled canonical operation is claimed",
                    identity.idempotency_key
                ),
            }
        })?;
        let key = identity.idempotency_key.as_str();
        let staged = ors.load_unknown_commit(key).map_err(ors_unavailable)?;
        if let Some(record) = staged {
            // A retained record is binding-verified before anything else, so a
            // terminal record for a different operation under this key is a
            // conflict rather than a shortcut to "already dispositioned". The
            // presented set is this operation's own proven scope set, which is
            // the set the record was staged with, so a record that paused a
            // different scope set is a conflict here too.
            verify_retained_binding(&record, identity, ordering_scopes)?;
            if record.outcome.is_some() {
                let outcome = match classify_commit_receipt(receipt) {
                    CommitRecoveryClass::Committed => UnknownCommitOutcome::Committed,
                    CommitRecoveryClass::KnownRollback => UnknownCommitOutcome::RolledBack,
                    CommitRecoveryClass::NeedsNewIdentity(outcome) => outcome,
                };
                let evidence_receipt_digest = receipt_evidence_digest(receipt);
                // A wrong receipt or a changed terminal digest cannot resolve
                // the record: it is rejected here, before the projection runs,
                // and the recorded history stands. The projection itself is
                // the same single owner the retained-replay path uses.
                verify_terminal_evidence(&record, outcome, &evidence_receipt_digest)?;
                return self.replay_terminal_retained_answer(&record);
            }
        }
        let outcome = match classify_commit_receipt(receipt) {
            CommitRecoveryClass::Committed => UnknownCommitOutcome::Committed,
            CommitRecoveryClass::KnownRollback => UnknownCommitOutcome::RolledBack,
            CommitRecoveryClass::NeedsNewIdentity(outcome) => outcome,
        };
        let evidence_receipt_digest = receipt_evidence_digest(receipt);
        self.commit_dreamer_disposition(
            identity,
            ordering_scopes,
            outcome,
            &evidence_receipt_digest,
        )
    }

    /// Persists one terminal Dreamer disposition under exact expected
    /// identity, outcome and receipt commitment, then releases only the
    /// scopes no remaining open record covers (issue #2764 item 5).
    ///
    /// The durable write is the commit point and happens before any release
    /// or report. A failed ORS write leaves the publication pending/unknown
    /// and is an error; a successful write followed by response loss replays
    /// the same terminal result through `resolve_open_record`, which reuses a
    /// concurrent identical resolution and rejects a different one. The
    /// release that follows cannot undo the recorded commit, and a refresh
    /// that cannot be proven complete becomes an explicit limitation on the
    /// reported answer rather than a claim that the commit failed.
    fn commit_dreamer_disposition(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
        outcome: UnknownCommitOutcome,
        evidence_receipt_digest: &str,
    ) -> Result<DreamerCommitUncertain, CommitRecoveryError> {
        let ors = self.commit_ors.as_deref().ok_or_else(|| {
            CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "ORS recovery unavailable: the exact receipt for Dreamer operation {} cannot be bound as durable unknown-commit evidence, so no reconciled canonical operation is claimed",
                    identity.idempotency_key
                ),
            }
        })?;
        let key = identity.idempotency_key.as_str();
        let record = open_record_for(identity, ordering_scopes)?;
        ors.stage_unknown_commit(&record).map_err(ors_unavailable)?;
        let resolution = resolve_open_record(ors, key, outcome, evidence_receipt_digest)?;
        // The durable record is read back through the resolution so the report
        // below is backed by what ORS actually holds, not by what this leg
        // intended to write.
        let persisted = resolution.record();
        debug_assert_eq!(persisted.outcome, Some(outcome));
        debug_assert_eq!(
            persisted.evidence_receipt_digest.as_deref(),
            Some(evidence_receipt_digest)
        );
        let release = self
            .paused_scopes
            .release_resolved(Some(ors), &record.ordering_scopes, key);
        match release {
            PauseReleaseOutcome::RefreshUnavailable { detail, .. } => {
                Ok(DreamerCommitUncertain::ReconciledWithRefreshLimitation {
                    idempotency_key: key.to_owned(),
                    outcome,
                    evidence_receipt_digest: evidence_receipt_digest.to_owned(),
                    refresh_limitation: detail,
                })
            }
            _ => Ok(DreamerCommitUncertain::Reconciled {
                idempotency_key: key.to_owned(),
                evidence_receipt_digest: evidence_receipt_digest.to_owned(),
                outcome,
            }),
        }
    }

    /// Releases the Ordering Scopes one resolved record paused that no open
    /// unknown-commit record still covers (I14.21, issue #1690; #2763).
    ///
    /// This shares the single unified release implementation in
    /// `commit_recovery`: it releases nothing on a failed or incomplete scan
    /// and exposes that failure through the returned outcome, and it removes a
    /// scope only when no other open record covers it, so two records over one
    /// scope need both to resolve. The durable set is re-observed at release
    /// time rather than reusing the pre-resolution scan, so an older scan
    /// cannot erase a concurrent new pause.
    fn release_dreamer_scopes(&self, record: &UnknownCommitRecord) -> PauseReleaseOutcome {
        self.paused_scopes.release_resolved(
            self.commit_ors.as_deref(),
            &record.ordering_scopes,
            record.idempotency_key.as_str(),
        )
    }

    /// Projects one already-terminal retained Dreamer record into the typed
    /// answer its caller must be given (issue #2764 items 5 and 6).
    ///
    /// This is the single terminal projection for the two RECONCILING sites —
    /// the retained-replay path and the receipt-adoption path — so neither can
    /// reach a differently-shaped copy of the same decision, and the two no
    /// longer have to be kept in agreement by hand. It is not the only place in
    /// this file where a terminal record can become a caller answer:
    /// [`Self::preserve_dreamer_operation`] keeps its own independent
    /// already-resolved guard and projects through the scope-free
    /// `dreamer_dispositioned` helper, because that leg stages rather than
    /// releases and has no Ordering-Scope bookkeeping to report a limitation
    /// for. The recorded outcome and its evidence digest are returned here as
    /// the values the record holds: `Committed` and `RolledBack` are different
    /// proven facts and neither is reduced to an ambiguous success.
    ///
    /// The Ordering Scopes this record itself paused are released here, so a
    /// replay also repairs a pause left behind by an earlier disposition whose
    /// release could not be proven complete. When the release still cannot be
    /// proven, the recorded disposition stands and that limitation is reported
    /// rather than dropped.
    ///
    /// The projection reads nothing from the Store. Once a disposition is
    /// durably recorded its outcome is settled, so a store observation is no
    /// longer evidence about that key: it can neither replace the recorded
    /// outcome nor turn it back into an open Problem State. Each of its two
    /// callers therefore reaches it only after its own binding has been
    /// verified: the retained-replay path through `verify_retained_binding`
    /// inside `classify_retained_commit`, and the receipt-adoption path
    /// through `verify_receipt_binding` plus `verify_terminal_evidence`.
    fn replay_terminal_retained_answer(
        &self,
        record: &UnknownCommitRecord,
    ) -> Result<DreamerCommitUncertain, CommitRecoveryError> {
        // The recorded terminal disposition stands; only the release
        // bookkeeping can be incomplete, and that limitation is reported
        // instead of being dropped.
        let release = self.release_dreamer_scopes(record);
        let (outcome, evidence_receipt_digest) =
            retained_terminal_evidence(record.idempotency_key.as_str(), record)?;
        Ok(match release {
            PauseReleaseOutcome::RefreshUnavailable { detail, .. } => {
                DreamerCommitUncertain::ReconciledWithRefreshLimitation {
                    idempotency_key: record.idempotency_key.clone(),
                    outcome,
                    evidence_receipt_digest,
                    refresh_limitation: detail,
                }
            }
            _ => DreamerCommitUncertain::AlreadyDispositioned {
                idempotency_key: record.idempotency_key.clone(),
                outcome,
                evidence_receipt_digest,
            },
        })
    }

    /// Preserves one still-unknown Dreamer operation and opens its recoverable
    /// Problem State (I14.21, issue #1690).
    ///
    /// The durable stage happens first and the mirror is updated only after
    /// it, so the pause this leg reports is always backed by a record a Doctor
    /// or Human can dispose. The durable open set in ORS remains authoritative
    /// for every later admission gate. With no ORS handle there is nowhere to
    /// preserve the receipt evidence, so durable mutation admission fails
    /// closed (I14.24) instead of pretending it exists.
    fn preserve_dreamer_operation(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
    ) -> Result<DreamerCommitUncertain, CommitRecoveryError> {
        let ors = self.commit_ors.as_deref().ok_or_else(|| {
            CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "ORS recovery unavailable for unknown Dreamer commit {}: the exact receipt evidence is unpreserved, so durable admission fails closed and no blind retry follows",
                    identity.idempotency_key
                ),
            }
        })?;
        let key = identity.idempotency_key.as_str();
        let staged = ors.load_unknown_commit(key).map_err(ors_unavailable)?;
        if let Some(record) = staged {
            // The presented set is this operation's own proven scope set — the
            // same set the record was staged with — so a record that paused a
            // different scope set is a conflict, not a shortcut to "already
            // dispositioned".
            verify_retained_binding(&record, identity, ordering_scopes)?;
            if record.outcome.is_some() {
                // A resolved record never reopens: the earlier evidence-backed
                // disposition stands, so this leg neither restages the record nor
                // pauses an Ordering Scope for a key that is already closed. The
                // recorded outcome and its evidence digest are returned as they
                // were recorded.
                return dreamer_dispositioned(key, &record);
            }
        }
        let record = open_record_for(identity, ordering_scopes)?;
        ors.stage_unknown_commit(&record).map_err(ors_unavailable)?;
        // Only a durably staged record marks a scope paused, and the mirror
        // keeps the pausing key with the entry.
        self.paused_scopes.record_paused(ordering_scopes, key);
        Ok(DreamerCommitUncertain::UnknownCommitOpen {
            idempotency_key: key.to_owned(),
            paused_scopes: ordering_scopes.to_owned(),
        })
    }

    /// Reads one Host-bound canonical validation snapshot.
    ///
    /// This read carries no caller fence, so the caller's generation is not
    /// available to compare; the active-generation gate is what admits it, and
    /// a gateway for a generation the durable `canonical_store` route no longer
    /// names is refused here exactly as it is on the fenced reads.
    pub async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        self.require_active_store_generation()
            .map_err(|error| error.to_string())?;
        self.store
            .validation_snapshot()
            .await
            .map_err(|error| error.to_string())
    }

    fn validate_active_route(&self, state_fence: &StateFence) -> Result<(), String> {
        self.require_active_store_generation()
            .map_err(|error| error.to_string())?;
        validate_route(&self.service, &self.route, state_fence)
    }

    /// The store generation that currently owns the durable `canonical_store`
    /// capability route.
    ///
    /// [`crate::canonical_store_route_owner`] reads the same ORS owners the
    /// `I5.11` stage-8 cutover commits through and the same record that names
    /// the generation an un-cut-over route started at, so the answer survives a
    /// restart and cannot be a composition-local flag. `None` therefore means
    /// neither a committed cutover nor an established owner exists for this
    /// scope, which is the state of a database this build has not composed yet;
    /// a gateway built without the composition-retained ORS handle also answers
    /// `None`, because it holds no handle to read either owner with. That is the
    /// behaviour that existed before this gate, and it is reachable only from a
    /// gateway no production composition builds: both production construction
    /// sites — `KernelComposition`'s initial canonical-store connect
    /// (`canonical_store_runtime.rs`) and `KernelComposition::rebind_store`
    /// (`lib.rs`) — pass the retained ORS handle.
    fn active_store_generation(&self) -> Result<Option<ResourceGeneration>, StoreError> {
        let Some(commit_ors) = self.commit_ors.as_deref() else {
            return Ok(None);
        };
        // An unreadable durable route owner is unavailability, not a mismatch:
        // the owner is then unproven and nothing may be admitted on its behalf.
        // `StoreError` has no refusal-with-reason variant, so the typed ORS
        // class stops here rather than being re-invented.
        crate::canonical_store_route_owner(commit_ors).map_err(|_error| StoreError::Unavailable)
    }

    /// Refuses any Store read or write unless this gateway's generation is the
    /// durable `canonical_store` route's owner.
    ///
    /// This is the `I5.11` stage-8/stage-10 gate enforced from the Kernel
    /// side. `self.route` is a composition-fixed snapshot of the generation this
    /// gateway was built for, so before this gate a completed stage-8 cutover
    /// changed nothing here: the incumbent kept serving reads and writes and the
    /// candidate could not serve either. Resolving the owner from the durable
    /// cutover ownership table instead makes the governed Store path follow the
    /// route, so from the commit onward the incumbent generation is not the
    /// owner and every Store operation reaching this gateway — fenced or
    /// unfenced, direct or through the borrowed client — is refused.
    ///
    /// The same comparison decides the pre-first-commit window, because the
    /// owner read also returns the generation the route scope was established
    /// at. An approved-but-uncommitted candidate bridge therefore reaches the
    /// identical refusal here, at the same gate, for the same reason a cut-over
    /// incumbent does: the durable owner does not name its generation.
    ///
    /// `I5.11` says "keep old store read-only for rollback window" and names no
    /// mechanism, and nothing in this process can fence another process's reader
    /// of the retired store. The reading implemented here is the strictest one
    /// the Kernel can enforce on its own path: from the cutover onward the
    /// incumbent generation is admitted by nobody, and `I14.14`'s "rollback is
    /// another cutover with a newer epoch" is the only way it is served again —
    /// which is exactly what the window exists to make possible.
    fn require_active_store_generation(&self) -> Result<(), StoreError> {
        let Some(active) = self.active_store_generation()? else {
            return Ok(());
        };
        if active != self.route.active_generation() {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }

    /// Reads and validates the retained canonical Store health observation.
    ///
    /// Like [`Self::validation_snapshot`] this read carries no caller fence, so
    /// the active-generation gate is the only thing that can tell this
    /// generation from a cut-over one.
    pub async fn health(&self) -> Result<StoreHealth, String> {
        let _flight = self.flight.enter()?;
        self.require_active_store_generation()
            .map_err(|error| error.to_string())?;
        let health = self
            .store
            .health()
            .await
            .map_err(|error| error.to_string())?;
        health.validate().map_err(|error| error.to_string())?;
        Ok(health)
    }

    /// Restores one bounded canonical batch into its admitted isolated
    /// destination through this gateway's own Store client (issue #952).
    ///
    /// This is the missing Kernel hop, not a second route: it sends over the
    /// `store` client composed once by [`Self::new`] and retained by the
    /// composition, so the destination Store process, its credentials and its
    /// `store_backup_client` binding are the ones the gateway already owns. No
    /// `NamedPipeTransport` is constructed here and there is no caller endpoint
    /// override, so a fresh connection — which would duplicate the owner and
    /// escape the generation-route gate, the drain/fence accounting and the
    /// `I14.21` unknown-commit recovery — is not representable on this path.
    ///
    /// The batch is forwarded as given. Nothing is assembled, defaulted,
    /// filtered, reordered or reinterpreted: the admitted `CanonicalRestoreBatch`
    /// this entry hands to the Store is the caller's own batch, byte for byte,
    /// because the archive/artifact owner resolved its payloads, its purge
    /// obligations and its per-member dispositions before this hop and the
    /// destination transaction is where those owner facts are committed.
    ///
    /// The gate and the accounting are the same ones every other mutating route
    /// runs: the flight slot is taken first so `fence_and_drain` still owns this
    /// connection, and the active-generation check still refuses a generation
    /// the durable `canonical_store` route no longer names. Neither is relaxed
    /// to make the entry reachable.
    ///
    /// The refusal is the typed [`StoreApplyRefusal`] of this module's
    /// mutating routes, for the same reason [`Self::apply`] uses it: an I5.19
    /// admission decision and a pre-existing gateway refusal are different
    /// facts and must not be flattened into one prose string. A restore that
    /// cannot be admitted is refused without a send, exactly as an apply is.
    pub async fn backup_restore_batch(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreApplyRefusal> {
        let _flight = self
            .flight
            .enter()
            .map_err(StoreApplyRefusal::GatewayRefusal)?;
        // I14.16 step 4 (issue #1953, map item 2): a restore batch is a Store
        // write, so a `shadow_no_authority` candidate refuses before the
        // generation gate and the send.
        self.refuse_shadow_mutation()
            .map_err(StoreApplyRefusal::GatewayRefusal)?;
        self.require_active_store_generation()
            .map_err(|error| StoreApplyRefusal::GatewayRefusal(error.to_string()))?;
        self.store
            .backup_restore_batch(ctx, batch)
            .await
            .map_err(|error| StoreApplyRefusal::GatewayRefusal(error.to_string()))
    }
}

/// The startup ORS scan reads canonical receipts through this gateway, not
/// through the raw `CanonicalStoreClient` trait call (issue #1713, item 6).
///
/// The one named path is [`KernelStoreGateway::receipt`], so the scan keeps the
/// flight slot, the fenced-rebind refusal, the fence validation and the
/// active-route checks before and after the query, and the receipt's own
/// operation/fence binding check. This impl only names that method and
/// translates a refusal; it repeats none of those checks. A refusal stays a
/// failed check, so the scan reports an error rather than an absent receipt or
/// a safely absent operation.
impl crate::store_write_reservation::StartupReceiptRoute for KernelStoreGateway {
    fn observe_receipt<'a>(
        &'a self,
        state_fence: &'a StateFence,
        operation_id: OperationId,
    ) -> crate::store_write_reservation::StartupReceiptObservation<'a> {
        Box::pin(async move {
            self.receipt(state_fence, operation_id.clone())
                .await
                .map_err(
                    |refusal| crate::store_write_reservation::ReservationWriteError::Binding {
                        operation_id: operation_id.as_str().to_owned(),
                        detail: format!(
                            "named authenticated canonical-Store receipt gateway refused the \
                         observation: {refusal}"
                        ),
                    },
                )
        })
    }
}

/// Which retirement-like transition owns an affected-revision wake
/// cancellation (issue #2806 item 6).
///
/// `Remove` retires the committed document, `Pause` pauses it, and a
/// superseding `Edit` invalidates the not-yet-admitted wakes of its immutable
/// predecessor while the new revision keeps its own horizon. All three
/// enumerate the affected revision's owner `Pending` targets from the wake
/// owner itself and cancel exactly those targets; already admitted jobs,
/// completed occurrences, and unknown effects are never rewritten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerWakeHandoffKind {
    /// Committed `Remove` of the affected revision.
    Remove,
    /// Committed `Pause` of the affected revision.
    Pause,
    /// Committed superseding `Edit`; the affected revision is its immutable
    /// predecessor.
    SupersedingEdit,
}

impl OwnerWakeHandoffKind {
    /// Plain noun naming the affected revision state in reasons.
    const fn noun(self) -> &'static str {
        match self {
            Self::Remove => "retired",
            Self::Pause => "paused",
            Self::SupersedingEdit => "superseded",
        }
    }
}

/// Composes the phase pair of a committed retirement whose wake handoff could
/// not be proven.
///
/// The retirement itself is a committed, durable fact, so every unprovable step
/// after it is reported as an unresolved wake handoff of that fact rather than
/// as a failed retirement or as a cancellation that silently did nothing. The
/// parent transition then yields a recovery directive instead of a known
/// success, and the exact reason travels with it.
fn unresolved_retirement_phases(
    reason: String,
    execution: UserAutomationExecutionPhase,
) -> (UserAutomationWakePhase, UserAutomationExecutionPhase) {
    (
        UserAutomationWakePhase::UnknownOutcome { reason },
        execution,
    )
}

/// Records one retained wake cancellation as an unresolved handoff of an
/// already committed retirement, and reports the phases its caller must return.
///
/// Both the durable admit and the exclusive send claim refuse without ever
/// issuing an owner effect, so a caller that cannot take one of them reports
/// the committed fact exactly like a refusal that reached no owner. The
/// disposition is `Reconciling` rather than retained work in both cases: a
/// committed retirement can only be settled by exact owner reconciliation
/// under its original owner operation identity.
fn unresolved_wake_cancellation(
    settled: &mut UserAutomationRuntimeObligation,
    obligations: &mut Vec<UserAutomationRuntimeObligation>,
    execution: &UserAutomationExecutionPhase,
    reason: String,
) -> (UserAutomationWakePhase, UserAutomationExecutionPhase) {
    settled.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
        reason: reason.clone(),
    };
    obligations.push(settled.clone());
    unresolved_retirement_phases(reason, execution.clone())
}

/// What the composition-bound durable outbox already holds for one runtime
/// obligation of the current parent operator operation.
///
/// It answers whether this effect may be issued: `Retained` allows the first
/// send, while `RetryAfterProvenNoSend` allows only the same operation's
/// bounded retry. Every other state is answered or must be reconciled by its
/// original owner operation identity.
enum RetainedUserAutomationObligation {
    /// The obligation is durably retained and its owner effect has not been
    /// issued, so it may be issued now under the retained identity.
    Retained,
    /// The first attempt was durably proven not to have sent any request bytes;
    /// the one permitted retry can acquire generation two without regressing
    /// the parent row from `Routed` to `Admitted`.
    RetryAfterProvenNoSend,
    /// The durable record already holds this obligation's exact owner answer as
    /// its bounded response body.
    Answered {
        /// The retained bounded owner answer body, served verbatim on replay.
        result_response: serde_json::Value,
        /// Actual carrier request commitment retained by the v1 response event.
        /// Absent on the legacy wrapped-answer contract.
        transport_request_sha256: Option<String>,
    },
    /// The durable record proves the owner effect was issued and its answer is
    /// not durably known, so repeating it is not safe.
    Reconciling {
        /// Closed reason the obligation cannot be issued or answered again.
        reason: String,
    },
}

/// Classifies one durable outbox record into what this boundary may do next.
///
/// The mapping is mechanical over the outbox's own state and custody evidence:
/// `Requested` and current-protocol `Admitted` rows with no attempt still prove
/// the owner was never handed the request; the only `Routed` retry is backed by
/// a retained first-attempt `DefinitelyNotSent` proof. Legacy `Admitted` rows
/// and every other routed or possible-effect state remain reconciling.
fn classify_retained_obligation(
    obligation: &UserAutomationRuntimeObligation,
    record: HostRequestRecord,
) -> RetainedUserAutomationObligation {
    let reconciling = |state: HostRequestState| RetainedUserAutomationObligation::Reconciling {
        reason: format!(
            "the retained runtime obligation {} is durably recorded as {state:?}, so the schedule \
             or wake owner may already have acted; a later read of the committed configuration is \
             empty of that effect, so reconcile this original owner operation identity instead \
             of repeating it",
            obligation.owner_operation_id
        ),
    };
    let transport_request_sha256 = (record.send_claim_protocol_version
        == eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION)
        .then(|| {
            record.attempt.as_ref().and_then(|attempt| {
                attempt
                    .transport_observations
                    .last()
                    .filter(|observation| {
                        observation.boundary == HostRequestTransportBoundary::ResponseReceived
                    })
                    .map(|observation| observation.transport_request_sha256.clone())
            })
        })
        .flatten();
    let is_current_protocol =
        record.send_claim_protocol_version == eliot_ors::HOST_REQUEST_SEND_CLAIM_PROTOCOL_VERSION;
    let has_no_attempt = record.attempt.is_none();
    let retry_after_proven_no_send = is_current_protocol
        && record.state == HostRequestState::Routed
        && record.attempt_history.is_empty()
        && matches!(
            record.attempt.as_ref(),
            Some(attempt)
                if attempt.phase == HostRequestAttemptPhase::DefinitelyNotSent
        );
    match (record.state, record.result_response) {
        (HostRequestState::Requested, None) if has_no_attempt => {
            RetainedUserAutomationObligation::Retained
        }
        (HostRequestState::Admitted, None) if is_current_protocol && has_no_attempt => {
            RetainedUserAutomationObligation::Retained
        }
        (HostRequestState::Admitted, None) => reconciling(HostRequestState::Admitted),
        (HostRequestState::Routed, None) if retry_after_proven_no_send => {
            RetainedUserAutomationObligation::RetryAfterProvenNoSend
        }
        (HostRequestState::ResultReceived | HostRequestState::Terminal, Some(result_response)) => {
            RetainedUserAutomationObligation::Answered {
                result_response,
                transport_request_sha256,
            }
        }
        (state, _) => reconciling(state),
    }
}

/// The answer of the composition-bound durable outbox about one runtime
/// obligation.
///
/// `Absent` is a complete answer that no record is held for this exact derived
/// key, not a gap in coverage: the owner is the sole writer of that table and
/// the key is a pure function of the obligation's immutable bindings.
enum RetainedObligationLookup {
    /// No record is held for this exact obligation identity.
    Absent,
    /// The owner holds a record, already classified over its durable states.
    Held(RetainedUserAutomationObligation),
    /// The owner could not be read or the intent could not be retained, so
    /// nothing about this obligation is proven.
    Unreadable {
        /// Closed reason the durable owner could not answer.
        reason: String,
    },
}

impl RetainedObligationLookup {
    /// Builds the answer of a lookup that failed.
    fn unreadable(reason: String) -> Self {
        Self::Unreadable { reason }
    }
}

/// What the durable outbox already holds for the wake-cancellation obligation of
/// one committed retirement.
///
/// It answers whether this cancellation may be issued: `Issue` permits the
/// first send and `RetryAfterProvenNoSend` permits its single proven-safe retry.
enum RetainedCancellation {
    /// The cancellation may be issued now under the retained owner operation
    /// identity, because the durable record proves the owner never received it.
    Issue,
    /// The first retained attempt is proven not to have sent request bytes, so
    /// the same operation may acquire its single bounded retry claim.
    RetryAfterProvenNoSend,
    /// The retirement is already answered by the owner's retained answer, which
    /// is served verbatim instead of issuing the cancellation again.
    Answered {
        /// Exact wake identities the owner reported as cancelled.
        cancelled_wake_ids: Vec<String>,
        /// Exact pre-cancellation Host receipt bound to this answer.
        enumeration_receipt: Box<UserAutomationWakeEnumerationReceipt>,
    },
    /// The wake handoff is unresolved under the retained owner operation
    /// identity and must be reconciled; repeating the effect is not safe.
    Unresolved {
        /// Closed reason the cancellation is neither issued nor answered.
        reason: String,
    },
    /// No durable owner was reachable, so nothing was retained and nothing is
    /// issued.
    Unavailable {
        /// Closed reason the obligation could not be read or retained.
        reason: String,
    },
}

/// Projects one durable-outbox classification of a wake-cancellation obligation.
fn classify_retained_cancellation(
    obligation: &UserAutomationRuntimeObligation,
    automation_revision: &str,
    retained: RetainedObligationLookup,
) -> RetainedCancellation {
    match retained {
        RetainedObligationLookup::Absent
        | RetainedObligationLookup::Held(RetainedUserAutomationObligation::Retained) => {
            RetainedCancellation::Issue
        }
        RetainedObligationLookup::Held(
            RetainedUserAutomationObligation::RetryAfterProvenNoSend,
        ) => RetainedCancellation::RetryAfterProvenNoSend,
        RetainedObligationLookup::Unreadable { reason } => {
            RetainedCancellation::Unavailable { reason }
        }
        RetainedObligationLookup::Held(RetainedUserAutomationObligation::Reconciling {
            reason,
        }) => RetainedCancellation::Unresolved { reason },
        RetainedObligationLookup::Held(RetainedUserAutomationObligation::Answered {
            result_response,
            transport_request_sha256,
        }) => match decode_retained_cancellation_answer(
            result_response,
            automation_revision,
            &obligation.owner_operation_id,
            obligation.wake_enumeration_receipt.as_deref(),
            transport_request_sha256.as_deref(),
        ) {
            Ok((cancelled_wake_ids, enumeration_receipt)) => RetainedCancellation::Answered {
                cancelled_wake_ids,
                enumeration_receipt: Box::new(enumeration_receipt),
            },
            Err(reason) => RetainedCancellation::Unresolved { reason },
        },
    }
}

/// Projects one retained-cancellation classification into the wake phase of a
/// committed retirement, or `None` when the effect may be issued now.
fn retained_cancellation_phases(
    classification: RetainedCancellation,
    obligation: &mut UserAutomationRuntimeObligation,
    execution: &UserAutomationExecutionPhase,
) -> Option<(UserAutomationWakePhase, UserAutomationExecutionPhase)> {
    match classification {
        RetainedCancellation::Issue | RetainedCancellation::RetryAfterProvenNoSend => None,
        RetainedCancellation::Answered {
            cancelled_wake_ids,
            enumeration_receipt,
        } => {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Answered {
                answer: Box::new(UserAutomationRuntimeObligationAnswer::WakeCancellation {
                    cancelled_wake_ids: cancelled_wake_ids.clone(),
                    enumeration_receipt: Some(enumeration_receipt),
                }),
            };
            Some((
                UserAutomationWakePhase::Cancelled { cancelled_wake_ids },
                execution.clone(),
            ))
        }
        RetainedCancellation::Unresolved { reason } => {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.clone(),
            };
            Some(unresolved_retirement_phases(reason, execution.clone()))
        }
        RetainedCancellation::Unavailable { reason } => {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Unavailable {
                reason: reason.clone(),
            };
            Some((
                UserAutomationWakePhase::Unavailable { reason },
                execution.clone(),
            ))
        }
    }
}

/// What the durable outbox already holds for the wake-horizon publication
/// obligation of one committed revision.
enum RetainedHorizonPublication {
    /// The slice may be published now under the retained owner operation
    /// identity, because the durable record proves the owner never received it.
    Issue,
    /// The publication is already answered by the owner's retained
    /// acknowledgement, which is served verbatim instead of publishing again.
    Answered {
        /// Exact request kept beside the answer in the durable outbox.
        publication_request: Box<UserAutomationWakeHorizonPublication>,
        /// The owner's own acknowledgement, re-validated against this request.
        acknowledgement: Box<UserAutomationWakePublication>,
    },
    /// The publication may already have been applied and must be reconciled
    /// under the retained owner operation identity.
    Unresolved {
        /// Closed reason the publication is neither issued nor answered.
        reason: String,
    },
    /// No durable owner was reachable, so nothing was retained and nothing is
    /// issued.
    Unavailable {
        /// Closed reason the obligation could not be read or retained.
        reason: String,
    },
}

/// Projects one durable-outbox classification of a wake-horizon obligation.
fn classify_retained_horizon_publication(
    obligation: &UserAutomationRuntimeObligation,
    publication: &UserAutomationWakeHorizonPublication,
    retained: RetainedObligationLookup,
) -> RetainedHorizonPublication {
    match retained {
        RetainedObligationLookup::Absent
        | RetainedObligationLookup::Held(RetainedUserAutomationObligation::Retained) => {
            RetainedHorizonPublication::Issue
        }
        RetainedObligationLookup::Unreadable { reason } => {
            RetainedHorizonPublication::Unavailable { reason }
        }
        RetainedObligationLookup::Held(RetainedUserAutomationObligation::Reconciling {
            reason,
        }) => RetainedHorizonPublication::Unresolved { reason },
        RetainedObligationLookup::Held(
            RetainedUserAutomationObligation::RetryAfterProvenNoSend,
        ) => RetainedHorizonPublication::Unresolved {
            reason: "a cancellation retry claim cannot satisfy a wake-horizon publication"
                .to_owned(),
        },
        RetainedObligationLookup::Held(RetainedUserAutomationObligation::Answered {
            result_response,
            ..
        }) => match decode_retained_horizon_answer(
            result_response,
            publication,
            &obligation.owner_operation_id,
        ) {
            Ok((publication_request, acknowledgement)) => RetainedHorizonPublication::Answered {
                publication_request,
                acknowledgement,
            },
            Err(reason) => RetainedHorizonPublication::Unresolved { reason },
        },
    }
}

/// Projects one retained-horizon classification into the bounded horizon phase,
/// or `None` when the slice may be published now.
fn retained_horizon_phase(
    classification: RetainedHorizonPublication,
    obligation: &mut UserAutomationRuntimeObligation,
    publication: &UserAutomationWakeHorizonPublication,
    requested_occurrence_ids: &[String],
    retry_handle: &str,
) -> Option<UserAutomationHorizonPhase> {
    match classification {
        RetainedHorizonPublication::Issue => None,
        RetainedHorizonPublication::Answered {
            publication_request,
            acknowledgement,
        } => {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Answered {
                answer: Box::new(
                    UserAutomationRuntimeObligationAnswer::WakeHorizonPublication {
                        publication_request: Some(publication_request),
                        acknowledgement: acknowledgement.clone(),
                    },
                ),
            };
            match acknowledged_horizon_phase(
                publication,
                requested_occurrence_ids,
                acknowledgement.as_ref(),
            ) {
                Ok(phase) => Some(phase),
                Err(reason) => {
                    obligation.disposition =
                        UserAutomationRuntimeObligationDisposition::Reconciling {
                            reason: reason.clone(),
                        };
                    Some(unreached_horizon_phase(
                        publication,
                        requested_occurrence_ids,
                        retry_handle.to_owned(),
                        UnreachedHorizonKind::UnknownOutcome,
                        &reason,
                    ))
                }
            }
        }
        RetainedHorizonPublication::Unresolved { reason } => {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Reconciling {
                reason: reason.clone(),
            };
            Some(unreached_horizon_phase(
                publication,
                requested_occurrence_ids,
                retry_handle.to_owned(),
                UnreachedHorizonKind::UnknownOutcome,
                &reason,
            ))
        }
        RetainedHorizonPublication::Unavailable { reason } => {
            obligation.disposition = UserAutomationRuntimeObligationDisposition::Unavailable {
                reason: reason.clone(),
            };
            Some(unreached_horizon_phase(
                publication,
                requested_occurrence_ids,
                retry_handle.to_owned(),
                UnreachedHorizonKind::Unavailable,
                &reason,
            ))
        }
    }
}

/// Selects the disjoint durable identity family for a Kernel-owned obligation.
fn user_automation_obligation_correlation_projection(
    obligation: &UserAutomationRuntimeObligation,
    occurrence: String,
) -> HostCorrelationProjection {
    HostCorrelationProjection::KernelOperational {
        domain: match obligation.kind {
            UserAutomationRuntimeObligationKind::WakeHorizonPublication
            | UserAutomationRuntimeObligationKind::WakeTargetEnumerationReceipt => {
                HostCorrelationDomain::Request
            }
            UserAutomationRuntimeObligationKind::WakeCancellation => {
                HostCorrelationDomain::Cancellation
            }
        },
        occurrence,
    }
}

/// Returns the durable outbox operation identity of one runtime obligation.
fn user_automation_obligation_operation_id(
    obligation: &UserAutomationRuntimeObligation,
) -> Result<eliot_ors::OperationIdentity, String> {
    eliot_ors::OperationIdentity::new(obligation.owner_operation_id.clone()).map_err(|error| {
        unretained_obligation_reason(
            obligation,
            format!("the derived owner operation identity is not a well-formed label: {error}"),
        )
    })
}

/// Digests the State Fence one admitted parent request carries.
///
/// The staged durable row and the exclusive send claim that later competes for
/// that same row both bind the fence through this one derivation, so a claim
/// can only be recognized as belonging to the record it claims: ORS compares
/// the claim's fence against the staged row's fence by content and refuses any
/// other pairing.
fn user_automation_obligation_fence_digest(
    sealed: &UserAutomationServiceRequest,
    obligation: &UserAutomationRuntimeObligation,
) -> Result<String, String> {
    canonical_json_bytes(&sealed.context.state_fence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| {
            unretained_obligation_reason(
                obligation,
                format!("the State Fence of the obligation could not be digested: {error}"),
            )
        })
}

/// Builds one durable outbox label, naming the obligation when the value is not
/// a well-formed label.
fn obligation_label(
    obligation: &UserAutomationRuntimeObligation,
    value: String,
) -> Result<OpaqueLabel, String> {
    OpaqueLabel::new(value).map_err(|error| {
        unretained_obligation_reason(
            obligation,
            format!("the durable obligation identity is not well formed: {error}"),
        )
    })
}

/// Returns the observed non-negative retention instant of the parent request.
///
/// The durable outbox record requires a non-zero instant. This contour owns no
/// caller deadline of its own, so it retains the instant at which the parent
/// operator request observed time, and the obligation cannot be retained at all
/// when that request observed none: an unbound instant would have to be
/// invented.
fn observed_retention_instant(context: &RequestMetadata) -> Option<i64> {
    context
        .clock
        .valid_time_ms
        .or(context.clock.known_time_ms)
        .filter(|observed| *observed > 0)
}

/// Decodes and revalidates the exact typed Host enumeration receipt retained by
/// the durable outbox.
fn decode_retained_wake_enumeration_receipt(
    result_response: serde_json::Value,
    request: &crate::user_automation_execution::UserAutomationWakeEnumerationRequest,
    automation_revision: &str,
    owner_operation_id: &str,
) -> Result<UserAutomationWakeEnumerationReceipt, String> {
    let reason = || {
        format!(
            "the retained Host enumeration receipt for revision {automation_revision} under owner operation {owner_operation_id} is malformed or does not match its original request"
        )
    };
    let Ok(UserAutomationRuntimeObligationAnswer::WakeTargetEnumerationReceipt { receipt }) =
        serde_json::from_value::<UserAutomationRuntimeObligationAnswer>(result_response)
    else {
        return Err(reason());
    };
    receipt.validate_for(request).map_err(|_| reason())?;
    Ok(*receipt)
}

/// Decodes the retained wake-cancellation answer of one durable obligation, or
/// names why the retained body is not this operation's answer.
fn decode_retained_cancellation_answer(
    result_response: serde_json::Value,
    automation_revision: &str,
    owner_operation_id: &str,
    expected_receipt: Option<&UserAutomationWakeEnumerationReceipt>,
    expected_transport_request_sha256: Option<&str>,
) -> Result<(Vec<String>, UserAutomationWakeEnumerationReceipt), String> {
    let Some(expected_receipt) = expected_receipt else {
        return Err(unretained_cancellation_answer_reason(
            automation_revision,
            owner_operation_id,
        ));
    };
    if let Ok(UserAutomationRuntimeObligationAnswer::WakeCancellation {
        cancelled_wake_ids,
        enumeration_receipt: Some(enumeration_receipt),
    }) = serde_json::from_value::<UserAutomationRuntimeObligationAnswer>(result_response.clone())
    {
        enumeration_receipt.validate_integrity().map_err(|_| {
            unretained_cancellation_answer_reason(automation_revision, owner_operation_id)
        })?;
        if enumeration_receipt.as_ref() != expected_receipt {
            return Err(unretained_cancellation_answer_reason(
                automation_revision,
                owner_operation_id,
            ));
        }
        let expected_wake_ids = enumeration_receipt
            .cancellation_targets()
            .map_err(|_| {
                unretained_cancellation_answer_reason(automation_revision, owner_operation_id)
            })?
            .into_iter()
            .map(|target| target.wake_id)
            .collect::<Vec<_>>();
        if expected_wake_ids.is_empty() || cancelled_wake_ids != expected_wake_ids {
            return Err(unretained_cancellation_answer_reason(
                automation_revision,
                owner_operation_id,
            ));
        }
        return Ok((cancelled_wake_ids, *enumeration_receipt));
    }
    let Some(expected_transport_request_sha256) = expected_transport_request_sha256 else {
        return Err(unretained_cancellation_answer_reason(
            automation_revision,
            owner_operation_id,
        ));
    };
    let Ok(UserAutomationHostExecutionResponse::Cancelled {
        request_sha256,
        state_fence,
        wake_ids,
    }) = serde_json::from_value::<UserAutomationHostExecutionResponse>(result_response)
    else {
        return Err(unretained_cancellation_answer_reason(
            automation_revision,
            owner_operation_id,
        ));
    };
    expected_receipt.validate_integrity().map_err(|_| {
        unretained_cancellation_answer_reason(automation_revision, owner_operation_id)
    })?;
    let expected_wake_ids = expected_receipt
        .cancellation_targets()
        .map_err(|_| {
            unretained_cancellation_answer_reason(automation_revision, owner_operation_id)
        })?
        .into_iter()
        .map(|target| target.wake_id)
        .collect::<Vec<_>>();
    if request_sha256 != expected_transport_request_sha256
        || state_fence != expected_receipt.state_fence
        || wake_ids != expected_wake_ids
    {
        return Err(unretained_cancellation_answer_reason(
            automation_revision,
            owner_operation_id,
        ));
    }
    Ok((wake_ids, expected_receipt.clone()))
}

/// Decodes and re-validates the retained schedule-owner acknowledgement of one
/// durable horizon obligation, or names why the retained body is not this
/// operation's answer.
fn decode_retained_horizon_answer(
    result_response: serde_json::Value,
    publication: &UserAutomationWakeHorizonPublication,
    owner_operation_id: &str,
) -> Result<
    (
        Box<UserAutomationWakeHorizonPublication>,
        Box<UserAutomationWakePublication>,
    ),
    String,
> {
    let Ok(answer) =
        serde_json::from_value::<UserAutomationRuntimeObligationAnswer>(result_response)
    else {
        return Err(unretained_horizon_answer_reason(
            &publication.automation_revision,
            owner_operation_id,
        ));
    };
    let UserAutomationRuntimeObligationAnswer::WakeHorizonPublication {
        publication_request: Some(publication_request),
        acknowledgement,
    } = &answer
    else {
        return Err(unretained_horizon_answer_reason(
            &publication.automation_revision,
            owner_operation_id,
        ));
    };
    answer
        .validate_horizon_for(publication)
        .map_err(|error| error.to_string())?;
    Ok((publication_request.clone(), acknowledgement.clone()))
}

/// Projects the schedule owner's acknowledgement into the bounded horizon phase
/// this operation reports.
fn acknowledged_horizon_phase(
    publication: &UserAutomationWakeHorizonPublication,
    requested_occurrence_ids: &[String],
    acknowledgement: &UserAutomationWakePublication,
) -> Result<UserAutomationHorizonPhase, String> {
    // One flight is bounded (issue #2806 item 10): the owner acknowledged only
    // the requested prefix, so the denominator tail past this flight is still
    // owed. It joins the owner's own remaining set, and a non-empty combined
    // remainder forces `Partial` with a handle over the exact combined set —
    // never a `Published` horizon for occurrences that were never sent.
    let tail = publication
        .uncapped_tail_ids()
        .map_err(|error| error.to_string())?;
    let mut remaining_occurrence_ids = acknowledgement.remaining_occurrence_ids.clone();
    remaining_occurrence_ids.extend(tail.iter().cloned());
    let publication_operation_id = Box::new(acknowledgement.publication_operation_id.clone());
    let (outcome, retry_handle) = if remaining_occurrence_ids.is_empty()
        && acknowledgement.acknowledged_all()
    {
        (
            UserAutomationHorizonOutcome::Published {
                publication_operation_id,
            },
            acknowledgement.retry_handle.clone(),
        )
    } else {
        let retry_handle = publication
            .retry_handle(&remaining_occurrence_ids)
            .map_err(|error| error.to_string())?;
        let reason = format!(
            "the schedule owner acknowledged {} of the {} requested occurrences of revision {}; \
             {} further occurrence(s) past the single-flight bound of {} were never sent; the \
             exact remaining set is retained and must be replayed under its handle before the \
             horizon counts as published",
            acknowledgement.acknowledged_occurrence_ids.len(),
            requested_occurrence_ids.len(),
            publication.automation_revision,
            tail.len(),
            crate::user_automation_execution::USER_AUTOMATION_HORIZON_ENTRY_BOUND
        );
        (
            UserAutomationHorizonOutcome::Partial {
                publication_operation_id,
                reason,
            },
            retry_handle,
        )
    };
    Ok(UserAutomationHorizonPhase {
        trigger: publication.trigger,
        automation_id: publication.automation_id.clone(),
        automation_revision: publication.automation_revision.clone(),
        revision_digest: publication.revision_digest.clone(),
        requested_occurrence_ids: requested_occurrence_ids.to_vec(),
        remaining_occurrence_ids,
        retry_handle,
        outcome,
    })
}

/// Returns the exact digest of the canonical receipt a committed or replayed
/// mutation produced, which the orchestration record binds beside its
/// obligations. A read-only answer has no receipt and owns no obligation.
fn committed_receipt_digest(configuration: &UserAutomationConfigurationPhase) -> Option<String> {
    match configuration {
        UserAutomationConfigurationPhase::Committed { receipt, .. }
        | UserAutomationConfigurationPhase::Replayed { receipt, .. } => {
            Some(receipt_evidence_digest(receipt))
        }
        UserAutomationConfigurationPhase::Read { .. } => None,
    }
}

/// Returns the canonical revision a committed configuration mutation produced.
fn committed_revision(
    configuration: &UserAutomationConfigurationPhase,
) -> Option<&UserAutomationRevision> {
    match configuration.mutation_result()? {
        UserAutomationMutationResult::Revision { revision, .. } => Some(revision),
        UserAutomationMutationResult::RunNow { .. } => None,
    }
}

/// Whether a committed configuration operation owns one bounded recurring wake
/// horizon publication, and which closed reason names that slice.
fn schedule_horizon_trigger(
    operation: &UserAutomationOperation,
) -> Option<UserAutomationHorizonTrigger> {
    match operation {
        UserAutomationOperation::Create { .. } => {
            Some(UserAutomationHorizonTrigger::AcceptedRevision)
        }
        UserAutomationOperation::Resume { .. } => {
            Some(UserAutomationHorizonTrigger::ResumedRevision)
        }
        UserAutomationOperation::Edit { .. } => Some(UserAutomationHorizonTrigger::SupersedingEdit),
        UserAutomationOperation::List { .. }
        | UserAutomationOperation::Status { .. }
        | UserAutomationOperation::History { .. }
        | UserAutomationOperation::Pause { .. }
        | UserAutomationOperation::RunNow { .. }
        | UserAutomationOperation::Remove { .. }
        | UserAutomationOperation::InspectLastFailure { .. }
        | UserAutomationOperation::GetContext
        | UserAutomationOperation::NormalizeSchedule { .. }
        | UserAutomationOperation::MigrateLegacySchedule { .. }
        // A committed recurring wake horizon belongs to a committed AUTOMATION
        // configuration revision, and the closed reason above names the
        // revision transition that produced it. I12.24:65's decision-owner
        // selection names no revision and schedules nothing: it records one
        // disposition against one brief, and I12.24:82 makes the advisory class
        // "default; changes nothing until owner acts", so there is no recurring
        // schedule for it to own. `None` is the honest answer, and naming it
        // here keeps the exclusion exhaustive rather than silent.
        | UserAutomationOperation::DecideImprovementBrief { .. } => None,
    }
}

/// Whether an unacknowledged horizon is a request that was never sent or a
/// request whose answer was lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnreachedHorizonKind {
    Unavailable,
    UnknownOutcome,
}

/// Reason used when this transition composes no schedule owner at all.
const UNREACHED_WAKE_OWNER_REASON: &str = "no authenticated UserAutomation runtime channel was composed for this transition, so the \
     compiled wake horizon was never handed to the schedule owner and no wake is retained";

/// Projects a horizon that the schedule owner did not fully acknowledge.
///
/// Builds the phase a wake-horizon publication reports when its owner effect
/// could not be retained at all.
///
/// The horizon keeps its exact requested and remaining sets and the replay
/// handle, so a caller that retained nothing still learns which occurrences were
/// outstanding and under which identity it may ask again. Nothing is issued and
/// no receipt is substituted for the missing record: the obligation is a
/// precondition of the owner effect, not a receipt for it.
fn unretained_wake_horizon_phase(
    publication: &UserAutomationWakeHorizonPublication,
    requested_occurrence_ids: &[String],
    retry_handle: &str,
    error: String,
) -> UserAutomationHorizonPhase {
    let reason = unretained_horizon_reason(&publication.automation_revision, error);
    unreached_horizon_phase(
        publication,
        requested_occurrence_ids,
        retry_handle.to_owned(),
        UnreachedHorizonKind::Unavailable,
        &reason,
    )
}

/// The exact requested and remaining occurrence sets and the replay handle are
/// always retained. A failure answer never reports an empty remainder: an empty
/// set would claim that nothing is outstanding, which is exactly the answer this
/// boundary cannot prove without an owner.
fn unreached_horizon_phase(
    publication: &UserAutomationWakeHorizonPublication,
    requested_occurrence_ids: &[String],
    retry_handle: String,
    kind: UnreachedHorizonKind,
    reason: &str,
) -> UserAutomationHorizonPhase {
    let outcome = match kind {
        UnreachedHorizonKind::Unavailable => UserAutomationHorizonOutcome::Unavailable {
            reason: reason.to_owned(),
        },
        UnreachedHorizonKind::UnknownOutcome => UserAutomationHorizonOutcome::UnknownOutcome {
            reason: reason.to_owned(),
        },
    };
    UserAutomationHorizonPhase {
        trigger: publication.trigger,
        automation_id: publication.automation_id.clone(),
        automation_revision: publication.automation_revision.clone(),
        revision_digest: publication.revision_digest.clone(),
        requested_occurrence_ids: requested_occurrence_ids.to_vec(),
        remaining_occurrence_ids: requested_occurrence_ids.to_vec(),
        retry_handle,
        outcome,
    }
}

/// Completes the retirement handoff for `Pause`.
///
/// A `Pause` stops the revision admitting new occurrences but this contour owns
/// no proof of which already published wakes its owner still retains, so the
/// phase stays unresolved rather than asserting a cancellation it cannot
/// enumerate.
/// Returns the committed revision a retirement committed, after checking it
/// against the exact request this identity asked for.
///
/// The committed document is checked against the requested automation,
/// revision, and the exact configuration state that operation must produce, so
/// both retirement phases are only derived from the exact revision this
/// identity committed.
fn committed_retirement_revision(
    configuration: &UserAutomationConfigurationPhase,
    automation_id: Option<&str>,
    automation_revision: &str,
    expected_state: UserAutomationConfigurationState,
) -> Result<UserAutomationRevision, String> {
    let Some(revision) = committed_revision(configuration) else {
        return Err("retirement did not return a canonical revision".to_owned());
    };
    if revision.revision != automation_revision
        || automation_id.is_some_and(|id| revision.automation_id != id)
        || committed_configuration_state(configuration) != Some(expected_state)
    {
        return Err(
            "committed UserAutomation revision does not match the retirement request".to_owned(),
        );
    }
    Ok(revision.clone())
}

/// Wake phase for an operation that owns no wake publication or cancellation.
fn not_applicable_wake() -> UserAutomationWakePhase {
    UserAutomationWakePhase::NotApplicable {
        reason: "this operator operation owns no wake publication or cancellation".to_owned(),
    }
}

/// Execution phase for an operation that owns no execution disposition.
fn not_applicable_execution() -> UserAutomationExecutionPhase {
    UserAutomationExecutionPhase::NotApplicable {
        reason:
            "this operator operation commits configuration only and owns no occurrence to execute"
                .to_owned(),
    }
}

/// Wake phase reason used when no authenticated runtime channel was composed.
fn unproven_wake_channel_reason() -> String {
    "no authenticated UserAutomation runtime channel was composed for this transition, so the \
     committed occurrence was not handed to the wake owner"
        .to_owned()
}

/// Execution phase reason used when no authenticated runtime channel was composed.
fn unproven_execution_channel_reason() -> String {
    "no authenticated UserAutomation runtime channel was composed for this transition, so the \
     committed occurrence was not handed to the Durable Job owner"
        .to_owned()
}

/// Execution phase reason for a committed occurrence whose committed
/// `WakeIntent` does not bind it.
///
/// The preflight execution join needs the committed pending wake as its
/// occurrence binding, and the Durable Job admission re-checks the same pair. A
/// committed intent that names another occurrence or another State Fence proves
/// nothing to join, so no admission is invented and the Durable Job owner is
/// never asked.
fn unproven_run_now_wake_reason(occurrence_id: &str) -> String {
    format!(
        "the wake handoff of committed occurrence {occurrence_id} did not prove a pending wake, \
         so no occurrence joins the Durable Job owner and the occurrence stays unadmitted"
    )
}

/// Execution phase reason for a `RunNow` join whose owner answer does not
/// establish whether the occurrence was admitted.
///
/// The Durable Job owner's answer for this exact occurrence was lost, bound to
/// another identity, settled without a readable ledger result, or returned a
/// reference that does not bind to this occurrence. The wake handoff is proven,
/// so the occurrence exists, and its Durable Job identity is the occurrence
/// identity: naming it is what lets a later attempt reconcile that same
/// occurrence under its original job identity instead of submitting a second
/// job. An unknown external effect is reported as unresolved and is never
/// turned into a fabricated admission (I5.19).
fn unestablished_run_now_execution_reason(
    occurrence_id: &str,
    detail: impl std::fmt::Display,
) -> String {
    format!(
        "the Durable Job owner did not establish an admission for committed occurrence \
         {occurrence_id}, so the occurrence stays unadmitted until that same occurrence is \
         reconciled: {detail}"
    )
}

/// Execution phase reason for one committed occurrence whose owner preflight
/// could not be assembled because an owner could not be read.
///
/// This is deliberately NOT a refusal and NOT an admission. The preflight never
/// completed, so the leg has no decision to report in either direction: naming it
/// `UnknownOutcome` alongside the committed `WriteReceipt` is what lets the caller
/// reconcile this exact occurrence under its own Durable Job identity, instead of
/// receiving a route error that discards the commit and names the occurrence in
/// prose alone. Reporting it as a decided `Rejected` would claim the occurrence
/// provably admitted nothing, which an unread owner does not prove — the reason
/// text is therefore the owner's own failure and never a re-derived outcome.
fn unestablished_run_now_preflight_reason(occurrence_id: &str, detail: &str) -> String {
    format!(
        "the owner preflight for committed occurrence {occurrence_id} could not be assembled, so \
         this occurrence's execution disposition is unresolved and no admission or refusal is \
         claimed for it until that same occurrence is reconciled: {detail}"
    )
}

/// Execution phase reason for one committed occurrence whose preflight could not
/// be assembled while the WAKE handoff was itself unresolved.
///
/// The unresolved owner fact is the wake phase's, and
/// `UserAutomationOperatorTransition::recovery` reports it first, so this reason
/// states only what is true of the execution handoff itself: the preflight never
/// completed, so the Durable Job owner was never asked on this attempt. It claims
/// no admission and no refusal, and the transition is still not `known`.
fn unattempted_run_now_preflight_reason(occurrence_id: &str, detail: &str) -> String {
    format!(
        "the wake handoff of committed occurrence {occurrence_id} is itself unresolved, and its \
         owner preflight could not be assembled either, so this occurrence was never handed to the \
         Durable Job owner and no admission or refusal is claimed for it: {detail}"
    )
}

/// Reason used when one runtime obligation could not be retained durably.
///
/// It names the obligation and its original owner operation identity, so an
/// operator reads which exact effect was not retained rather than a generic
/// outage, and no owner effect is issued without that record.
fn unretained_obligation_reason(
    obligation: &UserAutomationRuntimeObligation,
    detail: impl std::fmt::Display,
) -> String {
    format!(
        "the {} runtime obligation of this committed operation was not retained under its owner \
         operation identity {}: {detail}; no owner effect was issued and the effect stays owed \
         durably",
        obligation.kind.as_str(),
        obligation.owner_operation_id
    )
}

/// Reason used when the exact owner answer of one runtime obligation could not
/// be retained, so it is not yet a replayable obligation.
fn unretained_answer_reason(
    obligation: &UserAutomationRuntimeObligation,
    detail: impl std::fmt::Display,
) -> String {
    format!(
        "the owner answer of the {} runtime obligation under owner operation identity {} was not \
         retained: {detail}; the effect that produced it is not repeatable, so this original owner \
         operation identity must be reconciled before it is released",
        obligation.kind.as_str(),
        obligation.owner_operation_id
    )
}

/// Reason used when the exact durable key of a horizon publication could not be
/// derived from its own immutable bindings.
fn unretained_horizon_reason(automation_revision: &str, detail: impl std::fmt::Display) -> String {
    format!(
        "the bounded wake horizon of revision {automation_revision} could not be bound to a durable \
         owner operation identity: {detail}; the compiled slice was not handed to the schedule \
         owner and every one of its occurrences stays owed"
    )
}

/// Reason used when a retained horizon answer does not bind to the exact
/// publication it is resumed under.
fn unretained_horizon_answer_reason(automation_revision: &str, owner_operation_id: &str) -> String {
    format!(
        "the retained wake horizon answer of owner operation identity {owner_operation_id} does not \
         bind to the exact publication of revision {automation_revision} this attempt compiled, so \
         it is another operation's answer and the horizon stays unknown under its own retained \
         identity"
    )
}

/// Reason used when a horizon publication's owner effect may already have been
/// issued and its answer was lost.
fn unretained_horizon_outcome_reason(
    automation_revision: &str,
    owner_operation_id: &str,
    detail: &str,
) -> String {
    format!(
        "the schedule owner may have retained the horizon of revision {automation_revision} and its \
         answer was lost: {detail}; that possible effect is recorded under owner operation identity \
         {owner_operation_id}, so reconcile that identity instead of publishing the slice again"
    )
}

/// Reason used when the exact durable key of a wake cancellation could not be
/// derived from its own immutable bindings.
fn unretained_cancellation_reason(
    automation_revision: &str,
    detail: impl std::fmt::Display,
) -> String {
    format!(
        "the unadmitted-wake cancellation of retired revision {automation_revision} could not be \
         bound to a durable owner operation identity: {detail}; the owner-proven targets were not \
         handed to the wake owner and every one of them stays owed"
    )
}

/// Reason used when a retained cancellation answer does not bind to the exact
/// retirement it is resumed under.
fn unretained_cancellation_answer_reason(
    automation_revision: &str,
    owner_operation_id: &str,
) -> String {
    format!(
        "the retained cancellation answer of owner operation identity {owner_operation_id} does not \
         bind to the exact retirement of revision {automation_revision} this attempt replayed, so it \
         is another operation's answer and the cancellation stays unknown under its own retained \
         identity"
    )
}

/// Reason used when a wake cancellation may already have been applied and its
/// owner answer was lost.
fn unretained_cancellation_outcome_reason(
    automation_revision: &str,
    owner_operation_id: &str,
    detail: &str,
) -> String {
    format!(
        "the wake owner may already have cancelled the unadmitted pending wakes of retired revision \
         {automation_revision} and its answer was lost: {detail}; that possible effect is recorded \
         under owner operation identity {owner_operation_id}, whose cancelled wake identities are \
         absent from every later read, so reconcile that identity instead of cancelling again"
    )
}

/// Reason used when a wake cancellation held the exclusive send claim and the
/// owner then refused it, so the request is known to have been handed over but
/// its answer was not retained as such (issue #2970).
///
/// Because the claim is durable before the first transport await, this is never
/// reported as a re-issuable obligation: the exact owner operation identity has
/// to be reconciled, and only owner or transport evidence that the request was
/// never issued may release it.
fn claimed_cancellation_outcome_reason(
    automation_revision: &str,
    owner_operation_id: &str,
    detail: &str,
) -> String {
    format!(
        "the wake cancellation of retired revision {automation_revision} held the exclusive durable \
         send claim of owner operation identity {owner_operation_id} before the owner was handed \
         the request, and the owner refused it without a retained answer: {detail}; that claim \
         stays owned by its holder and can only be settled by reconciling the exact owner \
         operation identity, so the cancellation is not reissued from here"
    )
}

/// Canonical route/epoch gate shared by every gateway read/write path.
///
/// `validate_active_route` delegates here so the transport-generic named-read
/// helper below enforces the identical gate without a second implementation:
/// the composition-bound route epoch must be the exact live tuple, the
/// presented fence must match it exactly, and the route's active generation
/// must equal the fence generation (Implements #64). No scalar projection
/// participates: equal sequences across lineages fail closed here.
fn validate_route(
    service: &Mutex<KernelService>,
    route: &GenerationRoute,
    state_fence: &StateFence,
) -> Result<(), String> {
    let service = service
        .lock()
        .map_err(|_| "Kernel service lock poisoned".to_owned())?;
    if service.generation_fenced() {
        return Err("Kernel generation is fenced".to_owned());
    }
    let live_epoch = service.authority_epoch();
    if !route.authority_epoch().is_same_authority(&live_epoch)
        || !live_epoch.is_same_authority(&state_fence.authority_epoch)
    {
        return Err("canonical-store route is outside the active Kernel epoch".to_owned());
    }
    if route.active_generation() != state_fence.resource_generation {
        return Err("canonical-store route is outside the active Kernel generation".to_owned());
    }
    Ok(())
}

/// Handles one determinate reserved-write refusal (issue #1927, I05-06).
///
/// The Store owner has proved no external effect, so the still-`Eligible`
/// token releases cleanly and nothing orphans. `UnknownOperation` is explicit
/// unsupported behavior from a backend without reserved capability, never a
/// reason to fall back to unreserved `Apply`.
///
/// A `ManifestMismatch` is the one determinate refusal I05-06 treats as a
/// PRESERVED plan rather than a discarded one: the plan's recorded operation
/// manifest is outside current admissible support, so this build refuses to
/// execute it and must not reinterpret it under newer code. The reserved order
/// is still released, but the staged plan is first recorded as a visible
/// durable Recovery Problem keyed by its own operation identity, so it enters
/// visible recovery instead of vanishing with the release. Recording precedes
/// the release because the retention reads the staged operation's own epoch,
/// fence, recovery owner and reservation identity.
///
/// A failure to record never discards the refusal itself: the original cause is
/// reported and the retention failure is appended, so the caller still learns
/// the plan was refused. In that case the order is still released, so a
/// recorder fault cannot strand an `Eligible` reservation.
fn refuse_determinate_reserved_write(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
    error: &StoreError,
    operation_id: &str,
) -> String {
    if matches!(error, StoreError::ManifestMismatch) {
        let retained = retain_unsupported_prepared_plan(
            owner,
            token,
            "prepared transition outside current operation-manifest support",
        );
        if let Err(retained) = retained {
            let _ = cancel_before_send(owner, token);
            return format!(
                "reserved write refused for operation {operation_id}: the staged prepared \
                 transition is outside current operation-manifest support and could not be \
                 retained as visible recovery work ({retained}); cause: {error}"
            );
        }
    }
    let _ = cancel_before_send(owner, token);
    if matches!(error, StoreError::UnknownOperation) {
        return format!(
            "reserved write unsupported for operation {operation_id}: Store backend has no \
             reserved-write capability; refusing without unreserved Apply fallback"
        );
    }
    error.to_string()
}

/// Deterministic `PreparedTransition` admission before store execution (1927).
///
/// Guards the unreserved `apply` entry point: identity/shape validation, fence equality, canonical
/// request-hash recompute over the exact executable bytes, and operation
/// manifest support against the currently admitted catalogue. A plan whose
/// contents, effect ceiling, named operation parameters, or admission digest
/// changed after staging fails the hash recompute rather than executing. A
/// plan whose recorded manifest is not in the current catalogue fails as
/// visible recovery work: it is refused with an explicit unsupported error
/// and is never reinterpreted, widened, or translated under new code. A
/// staged transition therefore survives daemon replacement only when the
/// replacement Kernel explicitly supports its recorded protocol revision and
/// operation manifest. The protocol half is decided by CONTENT against this
/// build's own live revision through [`PreparedTransition::validate`], which
/// refuses any recorded revision other than the [`eliot_store_api::CONTRACT_VERSION`]
/// this Kernel implements; the manifest half is decided by
/// `validate_against_catalogue` against the generated manifests.
///
/// `admission_contract_set_digest` is deliberately NOT claimed here: it is
/// carried and hash-bound like every other plan field, but this boundary holds
/// no live contract-set value to compare it against, because I05-15 records that
/// no generated authoritative catalogue exists yet
/// (`ImplementationSupport = TARGET`). Inventing one here would be exactly the
/// invented authority this gate must not create. When that catalogue lands,
/// this is where the comparison belongs.
///
/// The gate ORDER is load-bearing and unchanged: every gate below runs before
/// any store send, and this is the *unreserved* admission point, so a refusal
/// here has reserved no Ordering Scope sequence and issued no external effect.
/// That is what lets the refusal be a typed I5.19 `not_accepted`
/// `WriteSubmission` instead of an erased string: the decision is taken at the
/// I5.6 steps 1-12 boundary, strictly before I5.6 step 13 stages anything in
/// ORS. The reserved-write path is a different owner with a different act and
/// deliberately does not come through here.
///
/// The only decisions converted into the `Err` arm HERE are the two refusals,
/// which is why the decision point is this function and not
/// [`KernelStoreGateway::apply`]: there is no second state check downstream
/// that a `not_accepted` or `resolved_existing` value would have to be caught
/// by. The refusal is the typed [`StoreApplyRefusal`], whose rendered line
/// keeps both the typed decision and the gate's own cause, so the operational
/// response can name the I5.19 decision that was taken and the specific
/// refusal under it.
///
/// A passing gate returns no submission at all. This is the I5.6 steps 1-12
/// boundary, before the step 13 ORS staging act, and I5.19's `staged` state
/// means "ORS accepted the exact operation identity" — so the accepted path has
/// no I5.19 front-door result to report and must not borrow the `staged` token
/// for a value nothing staged. The unit return carries the only claim this
/// boundary can make: this exact transition is admitted to be sent, and its
/// outcome is the canonical receipt the send produces.
fn admit_prepared_transition(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), StoreApplyRefusal> {
    let gate: Result<(), StoreError> = (|| {
        context.validate().map_err(StoreError::Foundation)?;
        transition.validate()?;
        if transition.state_fence != context.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        // RECHECK-63 slice B: recompute the canonical request hash from the
        // exact values about to be executed (context + transition + expected
        // heads) and reject divergence before any store work. The view is
        // built from these references — not re-forwarded copies — so a
        // mutation after admission fails here with the typed mismatch.
        let view = CanonicalRequestView::from_apply(
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        );
        verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)?;
        let entries = generated_operation_manifests()?;
        transition.validate_against_catalogue(&entries)
    })();
    // The gate's own typed refusal is kept so the operational response can name
    // both the typed `not_accepted` decision and the specific cause under it.
    let gate_cause = gate.as_ref().err().map(ToString::to_string);
    let submission = match admit_write_submission(transition, gate, None) {
        // `Ok(None)` is the passing gate: this boundary has no I5.19 front-door
        // result to report, because the I5.19 `staged` state means ORS accepted
        // this exact operation identity and nothing here has staged it.
        Ok(None) => return Ok(()),
        Ok(Some(submission)) => submission,
        // A request whose own identity is unnameable has no submission to
        // report under, so the gate's own typed refusal is reported instead.
        Err(unnameable) => {
            return Err(StoreApplyRefusal::GatewayRefusal(
                gate_cause.unwrap_or_else(|| unnameable.to_string()),
            ));
        }
    };
    // The gate ORDER above is load-bearing and this runs before any store
    // send, so the decision below is always produced BY one of those gates:
    // `gate_cause` is therefore present on every armed `Admission` refusal and
    // the composed text stays byte-identical to the single line this arm has
    // always rendered.
    let cause = gate_cause.unwrap_or_else(|| submission.to_string());
    Err(StoreApplyRefusal::admission(submission, cause))
}

/// Reserved-write admission gates shared by the gateway entry point.
///
/// Mirrors the `apply` gates (context/transition validation, active daemon
/// caller, fence equality): the caller rule lives at this boundary while the
/// binding rules live in the reservation module. The canonical request-hash
/// recompute runs in the entry body before reservation, and manifest support
/// is enforced at store execution by the bridge catalogue gate.
///
/// A staged plan the replacement store no longer supports is therefore NOT
/// reinterpreted here. On that determinate refusal the reserved order is still
/// safely released, and the plan is recorded as a visible durable Recovery
/// Problem keyed by its own operation identity, so it enters visible recovery
/// instead of vanishing with the release. Staging step so the entry point stays
/// a composition of audited gates.
fn apply_reserved_admission(
    context: &RequestMetadata,
    transition: &PreparedTransition,
) -> Result<(), String> {
    context.validate().map_err(|error| error.to_string())?;
    transition.validate().map_err(|error| error.to_string())?;
    if context.source_id.as_str() != ACTIVE_DAEMON_CALLER {
        return Err("transition caller is not the active daemon".to_owned());
    }
    if transition.state_fence != context.state_fence {
        return Err("transition state fence does not match request metadata".to_owned());
    }
    Ok(())
}

/// Transport-generic named-read path behind
/// [`KernelStoreGateway::execute_named`].
///
/// The production method delegates with its retained flight/service/route and
/// concrete `NamedPipeTransport` client; behaviour tests call this helper
/// with a loopback transport that replays Surreal-conformant
/// `StoreResponse::Named` frames through the real `EbpCanonicalStoreClient`
/// exchange, so every flight/fence/route/validation/match line below is the
/// executed production logic rather than a test copy. The step order mirrors
/// `recovery` plus the receipt template: flight enter, fenced check, request
/// validate, active-route check, forward, fenced + route re-check, response
/// validate, then operation/fence match against the admitted request.
async fn execute_named_via<T>(
    flight: &GatewayFlight,
    service: &Mutex<KernelService>,
    route: &GenerationRoute,
    store: &EbpCanonicalStoreClient<T>,
    request: NamedReadRequest,
) -> Result<NamedReadResponse, String>
where
    T: EbpStoreTransport + 'static,
{
    execute_named_via_with_error(flight, service, route, store, request)
        .await
        .map_err(|error| error.to_string())
}

async fn execute_named_via_with_error<T>(
    flight: &GatewayFlight,
    service: &Mutex<KernelService>,
    route: &GenerationRoute,
    store: &EbpCanonicalStoreClient<T>,
    request: NamedReadRequest,
) -> Result<NamedReadResponse, NamedReadGatewayError>
where
    T: EbpStoreTransport + 'static,
{
    let _flight = flight
        .enter()
        .map_err(NamedReadGatewayError::GatewayRefusal)?;
    if flight.is_fenced() {
        return Err(NamedReadGatewayError::GatewayRefusal(
            "canonical-store gateway is fenced for rebind".to_owned(),
        ));
    }
    request.validate()?;
    validate_route(service, route, &request.state_fence)
        .map_err(NamedReadGatewayError::GatewayRefusal)?;
    let response = store.execute_named(request.clone()).await?;
    if flight.is_fenced() {
        return Err(NamedReadGatewayError::GatewayRefusal(
            "canonical-store gateway is fenced for rebind".to_owned(),
        ));
    }
    validate_route(service, route, &request.state_fence)
        .map_err(NamedReadGatewayError::GatewayRefusal)?;
    response.validate()?;
    if response.operation != request.operation {
        return Err(NamedReadGatewayError::GatewayRefusal(
            "Store named-read operation does not match request".to_owned(),
        ));
    }
    if response.state_fence != request.state_fence {
        return Err(NamedReadGatewayError::GatewayRefusal(
            "Store named-read fence does not match request".to_owned(),
        ));
    }
    Ok(response)
}

/// Closed refusal set for one `Apply` through the Kernel gateway.
///
/// Two arms, and they stay separate because they carry different evidence:
///
/// - [`StoreApplyRefusal::Admission`] is a real I5.19 admission decision. The
///   typed [`WriteSubmission`] is kept whole, so the submission id, state,
///   reason codes, retry-identity rule, next allowed action, and any I5.17
///   split directive reach the caller as typed evidence instead of being
///   erased into prose before the response is built. The `cause` is the
///   preserving gate's own text, carried beside the decision rather than
///   re-derived from it, and the rendered line is byte-identical to the single
///   line this refusal has always produced.
/// - [`StoreApplyRefusal::GatewayRefusal`] is every pre-existing refusal
///   (flight fence, shadow mutation, route/epoch staleness, unknown-commit
///   recovery) plus a request whose own identity is too malformed to name a
///   submission under. Its text is preserved exactly; no message is rewritten,
///   reworded, or reinterpreted on the way out.
///
/// The `Display` of both arms is the operator-visible refusal line, so every
/// existing consumer that renders the value sees the same message it saw when
/// this route returned a bare `String`.
#[derive(Debug, thiserror::Error)]
pub enum StoreApplyRefusal {
    /// The I5.19 admission decision refused the submission, composed with the
    /// specific preserving gate that refused it.
    #[error("{submission}; cause: {cause}")]
    Admission {
        /// The typed admission decision taken by the gate, boxed so a refusal
        /// value stays small enough to return by value from every entry point.
        /// The decision itself is unchanged and is handed out as a plain
        /// borrow by [`StoreApplyRefusal::admission_decision`].
        submission: Box<WriteSubmission>,
        /// The preserving gate's own refusal text, preserved unchanged.
        cause: String,
    },
    /// A pre-existing gateway refusal, preserved exactly.
    #[error("{0}")]
    GatewayRefusal(String),
}

impl StoreApplyRefusal {
    /// Arms the typed admission arm from a decision and its preserving cause.
    ///
    /// The cause is taken as given, never re-derived: it is the exact text the
    /// preserving gate produced, and the rendered line is the same
    /// `"<decision>; cause: <cause>"` line this refusal has always rendered.
    pub fn admission(submission: WriteSubmission, cause: String) -> Self {
        Self::Admission {
            submission: Box::new(submission),
            cause,
        }
    }

    /// Returns the typed admission decision when this refusal carries one.
    ///
    /// `None` is a pre-existing gateway refusal: there is no admission decision
    /// to report, and a caller must not infer one from the prose.
    pub fn admission_decision(&self) -> Option<&WriteSubmission> {
        match self {
            Self::Admission { submission, .. } => Some(submission.as_ref()),
            Self::GatewayRefusal(_) => None,
        }
    }
}

/// Closed failure set for one named Store read through the Kernel gateway.
#[derive(Debug, thiserror::Error)]
pub enum NamedReadGatewayError {
    /// The canonical Store API returned a typed failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Gateway validation, fencing, or route checks refused the read.
    #[error("{0}")]
    GatewayRefusal(String),
}

/// Builds the complete versioned I14.5 directive for one read that the
/// canonical Store could not answer.
///
/// A read has no effect, so nothing was committed and nothing needs
/// reconciliation: this is [`RecoveryCommitStatus::None`] with
/// [`I14WorkOutcome::NotAccepted`], which is why the read may be re-issued under
/// its own identity once the condition is met. The typed cause is read off the
/// [`StoreError`] variant — never off a rendered sentence — so the closed cause
/// `CANONICAL_STORE_UNAVAILABLE` is produced by pattern-matching the enum, not by
/// comparing text a transport happened to produce.
///
/// The read-only boundary is preserved rather than widened: the only authorized
/// fallback is [`I14AlternativeRoute::CanonicalReadOnly`], which continues to
/// consult canonical state and grants no noncanonical substitute, and the only
/// permitted next action is to await the named condition. A caller holding this
/// directive cannot read it as permission to proceed on stale truth.
///
/// `operation_id` is the caller's exact admitted read identity when one exists.
/// `profile_revision` is the owner-produced compiled read-profile artifact the
/// directive was built from. Both are declared here and validated by the existing
/// [`I14BackpressureResponseV1::validate`], so an inconsistent directive fails
/// closed instead of shipping a partial one.
pub fn store_read_unavailable_response(
    state_fence: &StateFence,
    operation_id: Option<&OperationId>,
    profile_revision: &ArtifactId,
) -> Result<I14BackpressureResponseV1, KernelError> {
    let response = I14BackpressureResponseV1 {
        contract_version: I14_BACKPRESSURE_RESPONSE_VERSION,
        disposition: BackpressureDisposition::DbUnavailable,
        directive: I14RecoveryDirectiveV1 {
            cause: I14BackpressureCause::CanonicalStoreUnavailable,
            affected_operation_class: AffectedOperationClass::Normal(NormalWorkClass::Interactive),
            // A read depends on the canonical Store connection, not on a
            // capacity dimension this owner has measured. The contract permits
            // an explicit unknown observation for a non-capacity cause; claiming
            // a measured exhausted dimension here would fabricate capacity
            // evidence the outage path never observed.
            bottlenecks: vec![BottleneckObservationV1 {
                bottleneck: CapacityBottleneck::StoreConnectionSlots,
                unit: CapacityBottleneck::StoreConnectionSlots.unit(),
                requested_amount: 1,
                availability: BottleneckAvailability::Unknown,
                coverage_state: BottleneckCoverageState::Unknown,
            }],
            work_outcome: I14WorkOutcome::NotAccepted,
            commit_status: RecoveryCommitStatus::None,
            state_preservation: StatePreservationStatus::Preserved,
            operation_id: operation_id.cloned(),
            preserve_operation_id: operation_id.is_some(),
            stage_receipt: None,
            rollback_receipt: None,
            // The read is refused, not staged and not uncertain: re-issue it once
            // the Store is answering again. Polling or receipt reconciliation
            // would be false, because no operation reached the Store to leave an
            // effect to reconcile.
            retry_strategy: I14RecoveryAction::AwaitCondition,
            earliest_permitted_condition: EarliestRecoveryCondition::AuthorityRestored,
            earliest_permitted_unix_millis: None,
            actions_temporarily_forbidden: vec![
                I14ForbiddenAction::AssumeCommitWithoutReadback,
                I14ForbiddenAction::ContinueWithStaleAuthority,
            ],
            safe_fallback: Some(I14AlternativeRoute::CanonicalReadOnly),
            required_authority: I14RequiredAuthority::ExistingOperationAuthority,
            human_action_required: HumanActionRequirement::NoneRequired,
            // A read that never reached the Store leaves no receipt to cite, and
            // coverage is reported as unavailable rather than claimed complete.
            evidence_refs: Vec::new(),
            evidence_coverage: EvidenceCoverageState::Unavailable,
            escalation_condition: I14EscalationCondition::ManualPlatformRecovery,
            resolution_state: I14ResolutionState::Pending,
            // The observation is live at the moment the Store refused, so the
            // directive itself is current even though the answer it carries is
            // not: the distinction is that a current observation of an
            // unavailable Store still yields no current result.
            currentness: I14CurrentnessState::Current,
            profile_revision: profile_revision.clone(),
            state_fence: Some(state_fence.clone()),
            authority_epoch: Some(state_fence.authority_epoch.clone()),
        },
    };
    response.validate()?;
    Ok(response)
}

/// The owner-produced compiled read-profile artifact identity every
/// `DB_UNAVAILABLE` read directive is bound to.
///
/// This is the generated Store operation-manifest set digest — the exact
/// catalogue the read was validated against — not a caller-supplied string, so
/// the directive names the profile it was actually issued under. It is derived
/// from crate constants and is therefore the same value on every process, which
/// is what makes it a usable artifact reference rather than per-process noise.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when the generated catalogue cannot be
/// produced or hashed into an artifact identity.
pub fn store_read_profile_revision() -> Result<ArtifactId, KernelError> {
    let entries = generated_operation_manifests().map_err(|error| KernelError::InvalidField {
        field: "store_read_profile_revision.manifests",
        reason: match error {
            StoreError::Duplicate { .. } => "generated operation manifests contain a duplicate",
            StoreError::Empty { .. } => "generated operation manifest set is empty",
            _ => "generated operation manifests are not well formed",
        },
    })?;
    let digest =
        operation_manifest_set_digest(&entries).map_err(|_| KernelError::InvalidField {
            field: "store_read_profile_revision.digest",
            reason: "operation manifest set digest could not be computed",
        })?;
    ArtifactId::new(digest.as_str()).map_err(|_| KernelError::InvalidField {
        field: "store_read_profile_revision.artifact_id",
        reason: "operation manifest set digest is not a valid artifact identity",
    })
}

/// Closed failure set for one Dreamer ledger operation through the Kernel
/// gateway (issue #2764 item 6).
///
/// This is the minimal carrier the real caller needs, and it exists because the
/// recovery leg answers with facts a `String` cannot hold. The issue spends
/// W1-W5 building a typed recovered-outcome: an exact terminal outcome, its
/// receipt evidence, and the remaining ledger-read obligation. Flattening that
/// answer to text at the function boundary discarded the distinction the slice
/// exists to make, and left the caller unable to tell "already committed" from
/// "reconciled, but the pause release is incomplete" from "outcome still
/// unknown and the scopes are still paused". The enum arms here keep all of it
/// addressable, and only the *final* transport edge renders it.
///
/// The `Display` of every arm is the operator-visible refusal line the caller
/// projects, so a consumer that renders the value sees the same sentence it saw
/// when this route returned a bare `String`. Nothing downstream has to parse it
/// back apart.
#[derive(Debug, thiserror::Error)]
pub enum DreamerJobGatewayError {
    /// Unknown-commit recovery refused, failed closed, or reported a conflict
    /// (I14.21, I14.24). The typed [`CommitRecoveryError`] travels whole:
    /// fence/route/role/validation refusals, an unavailable ORS owner, a paused
    /// scope, an identity or terminal-evidence conflict, and a determinate
    /// commit refusal keep their own variants instead of sharing one string.
    #[error(transparent)]
    Commit(#[from] CommitRecoveryError),
    /// The mutation's disposition is proven but the ledger answer is not (or not
    /// entirely). The typed [`DreamerCommitUncertain`] travels whole, so the
    /// caller receives the original operation/key, the exact recorded outcome,
    /// the receipt evidence digest, and the remaining `Status`/`Reconcile`
    /// ledger-read obligation as addressable values.
    #[error(transparent)]
    Uncertain(#[from] DreamerCommitUncertain),
    /// A pre-existing gateway refusal (flight fence, shadow mutation,
    /// role/route/epoch staleness, request validation, protected-lane
    /// unavailability). Its text is preserved exactly; no message is rewritten,
    /// reworded, or reinterpreted on the way out.
    #[error("{0}")]
    GatewayRefusal(String),
}

impl DreamerJobGatewayError {
    /// Returns the typed recovered outcome when this refusal carries one.
    ///
    /// `None` is a refusal that proves nothing about the mutation's
    /// disposition, and a caller must not infer one from the prose.
    pub fn uncertain(&self) -> Option<&DreamerCommitUncertain> {
        match self {
            Self::Uncertain(uncertain) => Some(uncertain),
            Self::Commit(_) | Self::GatewayRefusal(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_gateway_fence_waits_for_in_flight_work_before_replacement() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!());
        runtime.block_on(async {
            let flight = Arc::new(GatewayFlight::new());
            let guard = flight.enter().unwrap_or_else(|_| unreachable!());
            let draining = {
                let flight = Arc::clone(&flight);
                tokio::spawn(async move { flight.fence_and_drain(Duration::from_secs(1)).await })
            };
            tokio::task::yield_now().await;
            assert!(!draining.is_finished());
            drop(guard);
            assert!(draining.await.unwrap_or_else(|_| unreachable!()).is_ok());
            assert!(flight.is_fenced());
            assert!(flight.enter().is_err());
        });
    }

    #[test]
    fn prepared_admission_rejects_tampered_and_unsupported_plans() {
        // 1927 acceptance: changing the plan contents, effect ceiling, named
        // operation parameters, or admission digest after staging causes
        // rejection rather than execution; an unsupported recorded plan is
        // visible as recovery work and is not reinterpreted.
        use std::collections::BTreeMap;
        use std::num::NonZeroU64;

        use eliot_contracts::{
            ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration,
            SourceId,
        };
        use eliot_store_api::{
            EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
            NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId,
            ScopeId, SecurityContext, TransitionClass, bind_issue18_digests,
            canonical_request_hash, operation_manifest_set_digest,
        };

        const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        let epoch = EpochId::new(
            EpochLineageId::new(LINEAGE).unwrap_or_else(|_| unreachable!()),
            NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!());
        let fence = StateFence::new(epoch, ResourceGeneration::genesis());
        let context = RequestMeta {
            request_id: RequestId::new("req-1927-1").unwrap_or_else(|_| unreachable!()),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1927").unwrap_or_else(|_| unreachable!()),
            source_id: SourceId::new("eliotd").unwrap_or_else(|_| unreachable!()),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        let entries = generated_operation_manifests().unwrap_or_else(|_| unreachable!());
        let set_digest = operation_manifest_set_digest(&entries).unwrap_or_else(|_| unreachable!());
        let mut transition = PreparedTransition {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: OperationId::new("op-1927-1").unwrap_or_else(|_| unreachable!()),
                idempotency_key: "idem-1927-1".to_owned(),
                canonical_request_hash: "0".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-1927").unwrap_or_else(|_| unreachable!()),
            task_id: None,
            ordering_scopes: vec![
                OrderingScopeId::new("scope-1927").unwrap_or_else(|_| unreachable!()),
            ],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: set_digest,
            // Issue-#18 digests are derived below via `bind_issue18_digests`,
            // never defaulted; no semantic source is bound here (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-1927-1"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        bind_issue18_digests(&mut transition).unwrap_or_else(|_| unreachable!());
        transition.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&context, &transition, &[], &[]),
        )
        .unwrap_or_else(|_| unreachable!());
        admit_prepared_transition(&context, &transition, &[], &[])
            .unwrap_or_else(|_| unreachable!());

        let mut widened = transition.clone();
        widened.requested_effect_ceiling = EffectClass::ReversibleMutation;
        assert!(admit_prepared_transition(&context, &widened, &[], &[]).is_err());

        let mut reparam = transition.clone();
        reparam.named_operations[0].parameters.insert(
            "subject".to_owned(),
            serde_json::json!("observation-substituted"),
        );
        assert!(admit_prepared_transition(&context, &reparam, &[], &[]).is_err());

        let mut redigest = transition.clone();
        redigest.admission_contract_set_digest = "d".repeat(64);
        assert!(admit_prepared_transition(&context, &redigest, &[], &[]).is_err());

        let mut unsupported = transition.clone();
        unsupported.operation_manifest_digest =
            OperationManifestDigest::new("f".repeat(64)).unwrap_or_else(|_| unreachable!());
        unsupported.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&context, &unsupported, &[], &[]),
        )
        .unwrap_or_else(|_| unreachable!());
        let error = match admit_prepared_transition(&context, &unsupported, &[], &[]) {
            Err(error) => error,
            Ok(_) => unreachable!("unsupported manifest must fail"),
        };
        assert!(
            error.to_string().contains("recovery"),
            "unsupported plan must name recovery, got: {error}"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "T11.1 behaviour test: every asserted identity, fence, bound, and payload value is derived from the request inputs and the temp-root capture file; nothing is canned"
)]
mod named_read_gateway_tests {
    //! T11.1 daemon-half named-read behaviour through the real gateway path.
    //!
    //! The test drives the production [`execute_named_via`] helper through a
    //! real [`EbpCanonicalStoreClient`] whose loopback transport replays
    //! Surreal-conformant `StoreResponse::Named` frames: the closed evidence
    //! SELECT is replaced by a temp-root capture file (one captured subject,
    //! written then read back), while request validation, the generated
    //! operation-catalogue gate, exact-subject filtering (never substring),
    //! the explicit `max_records` bound with over-bound `PayloadTooLarge`
    //! refusal, and the versioned `records`/`provenance` payload shape all
    //! follow the Surreal adapter's `read_boundary::evidence_pack_payload`
    //! rules. Typed refusals travel as correctly-bound `StoreFailure`
    //! payloads through the real exchange classifier, so the asserted
    //! `PayloadTooLarge`/`FenceMismatch` surfaces are the production mapping,
    //! not test prose. The memory adapter is never used here; it remains the
    //! reference handler only.

    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration};
    use eliot_ipc::{DeliveryOutcome, TransportLimits, server_hello_frame};
    use eliot_kernel_core::RouteScope;
    use eliot_platform::PlatformHandle;
    use eliot_protocol::{Frame, FrameKind, ProtocolVersion, ServerHello};
    use eliot_store_api::{
        CAPABILITIES, EFFECTS, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, NamedReadRequest,
        ReadConsistency, ScopeId, StoreError, StoreFailure, StoreFailureIdentityContext,
        StoreRequest, StoreResponse, generated_operation_manifests, named_mutation_operation_name,
    };
    use serde_json::{Value, json};

    use super::{GatewayFlight, execute_named_via};
    use crate::{EbpCanonicalStoreClient, EbpStoreTransport, HostStoreBootstrapRequirement};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const EVIDENCE_PACK_VERSION: u32 = 1;

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence() -> eliot_contracts::StateFence {
        eliot_contracts::StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    fn requirement(fence: &eliot_contracts::StateFence) -> HostStoreBootstrapRequirement {
        HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new("store_bridge").expect("route"),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").expect("pipe"),
            store_generation: ResourceGeneration::genesis(),
            state_fence: fence.clone(),
            launch_nonce: PlatformHandle::new("launch").expect("launch"),
            connection_id: PlatformHandle::new("connection").expect("connection"),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
            expected_peer_session_id: 1,
            approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
            approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
            timeout_ms: 30_000,
        }
    }

    fn evidence_params(subject: &str, max_records: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("subject".to_owned(), Value::String(subject.to_owned())),
            (
                "max_records".to_owned(),
                Value::String(max_records.to_owned()),
            ),
        ])
    }

    /// Loopback transport replaying Surreal-conformant named-read frames.
    ///
    /// Only the pipe itself is looped back: handshake, readiness, the
    /// `StoreRequest::Named` round trip, and every refusal use the real
    /// `EbpCanonicalStoreClient` exchange code. Durable evidence is one
    /// temp-root capture file (subjects in capture order, one per line);
    /// filtering is exact-match only, mirroring the Surreal adapter's
    /// Rust-side exact filter over its closed SELECT.
    struct LoopbackSurrealTransport {
        requirement: HostStoreBootstrapRequirement,
        pending: Option<Frame>,
        captured_subjects_path: PathBuf,
    }

    impl LoopbackSurrealTransport {
        fn response(
            connection_id: String,
            request_id: RequestId,
            response: StoreResponse,
        ) -> Frame {
            eliot_store_api::response_frame(
                connection_id,
                ProtocolVersion::CURRENT,
                Some(request_id),
                response,
            )
            .expect("loopback response frame encodes")
        }

        /// Reports a typed, correctly-bound store refusal for the admitted
        /// call: no admitted operation exists for reads, the fence echoes the
        /// bootstrap requirement, and the idempotency key echoes the client's
        /// `store-named-read` key, so the production `bind_failure` classifier
        /// accepts the binding and the exact `StoreError` round-trips.
        fn typed_failure(&self, request_id: &RequestId, error: StoreError) -> Frame {
            let context = StoreFailureIdentityContext {
                request_id: Some(request_id.clone()),
                operation_id: None,
                idempotency_key_ref_or_digest: Some("store-named-read".to_owned()),
                state_fence_ref_or_exact_safe_projection: Some(
                    self.requirement.state_fence.clone(),
                ),
                evidence_ref: None,
                transport_unavailable: false,
            };
            let failure =
                StoreFailure::from_store_error(error, context).expect("typed failure builds");
            Self::response(
                self.requirement.connection_id.as_str().to_owned(),
                request_id.clone(),
                StoreResponse::Failure { failure },
            )
        }

        fn handle_named(&self, request: &NamedReadRequest, request_id: &RequestId) -> Frame {
            if let Err(error) = request.validate() {
                return self.typed_failure(request_id, error);
            }
            let entries = match generated_operation_manifests() {
                Ok(entries) => entries,
                Err(error) => return self.typed_failure(request_id, error),
            };
            if let Err(error) = request.validate_against_catalogue(&entries) {
                return self.typed_failure(request_id, error);
            }
            if request.operation != NamedReadOperation::GetEvidencePack
                && request.operation != NamedReadOperation::GetCurrentEpistemicPosition
            {
                return self.typed_failure(request_id, StoreError::UnknownOperation);
            }
            if request.state_fence != self.requirement.state_fence {
                return self.typed_failure(request_id, StoreError::FenceMismatch);
            }
            if request.operation == NamedReadOperation::GetCurrentEpistemicPosition {
                if request.consistency != ReadConsistency::ExactFence {
                    return self.typed_failure(
                        request_id,
                        StoreError::InvalidField {
                            field: "operation.consistency",
                            reason: "GetCurrentEpistemicPosition requires ExactFence",
                        },
                    );
                }
                let Some(scope_id) = request.scope_id.clone() else {
                    return self.typed_failure(
                        request_id,
                        StoreError::InvalidField {
                            field: "scope_id",
                            reason: "position read requires scope_id",
                        },
                    );
                };
                let Some(position) = request.parameters.get("position").and_then(Value::as_str)
                else {
                    return self.typed_failure(
                        request_id,
                        StoreError::InvalidField {
                            field: "operation.parameter",
                            reason: "missing required parameter",
                        },
                    );
                };
                if position.trim().is_empty() || position.chars().any(char::is_control) {
                    return self.typed_failure(
                        request_id,
                        StoreError::InvalidField {
                            field: "operation.parameter",
                            reason: "position must be a non-blank string",
                        },
                    );
                }
                let payload = json!({
                    "position": position,
                    "scope_id": scope_id,
                    "state_fence": request.state_fence,
                });
                let response = eliot_store_api::NamedReadResponse {
                    operation: request.operation,
                    state_fence: request.state_fence.clone(),
                    revision_heads: Vec::new(),
                    payload,
                };
                if let Err(error) = response.validate() {
                    return self.typed_failure(request_id, error);
                }
                return Self::response(
                    self.requirement.connection_id.as_str().to_owned(),
                    request_id.clone(),
                    StoreResponse::Named { response },
                );
            }
            let Some(scope_id) = request.scope_id.clone() else {
                return self.typed_failure(
                    request_id,
                    StoreError::InvalidField {
                        field: "scope_id",
                        reason: "evidence pack read requires scope_id",
                    },
                );
            };
            let Some(subject) = request.parameters.get("subject").and_then(Value::as_str) else {
                return self.typed_failure(
                    request_id,
                    StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "missing required parameter",
                    },
                );
            };
            if subject.trim().is_empty() || subject.chars().any(char::is_control) {
                return self.typed_failure(
                    request_id,
                    StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "subject must be a non-blank string",
                    },
                );
            }
            let Some(bound_raw) = request
                .parameters
                .get("max_records")
                .and_then(Value::as_str)
            else {
                return self.typed_failure(
                    request_id,
                    StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "missing required parameter",
                    },
                );
            };
            let max_records: u32 = match bound_raw.parse() {
                Ok(bound) => bound,
                Err(_) => {
                    return self.typed_failure(
                        request_id,
                        StoreError::InvalidField {
                            field: "operation.parameter",
                            reason: "max_records must be a positive decimal bound",
                        },
                    );
                }
            };
            if max_records == 0 {
                return self.typed_failure(
                    request_id,
                    StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "max_records must be a positive decimal bound",
                    },
                );
            }
            if max_records > EVIDENCE_PACK_MAX_RECORDS {
                return self.typed_failure(request_id, StoreError::PayloadTooLarge);
            }
            let Ok(captured) = std::fs::read_to_string(&self.captured_subjects_path) else {
                return self.typed_failure(request_id, StoreError::Unavailable);
            };
            let limit = usize::try_from(max_records).expect("u32 fits usize");
            // Exact subject match only — never substring, never a default.
            let matched: Vec<(u64, String)> = captured
                .lines()
                .enumerate()
                .filter(|(_, captured)| *captured == subject)
                .map(|(index, captured)| (index as u64, captured.to_owned()))
                .collect();
            let matched_total = matched.len();
            let records: Vec<Value> = matched
                .into_iter()
                .take(limit)
                .map(|(capture_index, captured)| {
                    json!({
                        "capture_index": capture_index,
                        "operation": named_mutation_operation_name(
                            eliot_store_api::NamedMutationOperation::CaptureObservation,
                        ),
                        "parameters": { "subject": captured },
                    })
                })
                .collect();
            let returned = records.len();
            let payload = json!({
                "version": EVIDENCE_PACK_VERSION,
                "subject": subject,
                "scope_id": scope_id,
                "records": records,
                "provenance": {
                    "state_fence": request.state_fence,
                    "matched_total": matched_total,
                    "returned": returned,
                    "max_records": max_records,
                    "truncated": matched_total > returned,
                },
            });
            let response = eliot_store_api::NamedReadResponse {
                operation: request.operation,
                state_fence: request.state_fence.clone(),
                revision_heads: Vec::new(),
                payload,
            };
            if let Err(error) = response.validate() {
                return self.typed_failure(request_id, error);
            }
            Self::response(
                self.requirement.connection_id.as_str().to_owned(),
                request_id.clone(),
                StoreResponse::Named { response },
            )
        }
    }

    impl EbpStoreTransport for LoopbackSurrealTransport {
        fn ensure_authenticated(
            &self,
            _requirement: &HostStoreBootstrapRequirement,
        ) -> Result<(), crate::StoreClientError> {
            Ok(())
        }

        async fn send_frame(
            &mut self,
            frame: &Frame,
            _limits: TransportLimits,
        ) -> Result<DeliveryOutcome, crate::StoreClientError> {
            if frame.kind == FrameKind::Control {
                let hello = ServerHello {
                    selected_protocol: ProtocolVersion::CURRENT,
                    session_principal_binding: "loopback-store-session".to_owned(),
                    allowed_capabilities: CAPABILITIES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    allowed_effects: EFFECTS.iter().map(|value| (*value).to_owned()).collect(),
                    config_snapshot: json!({
                        "config_hash": self.requirement.approved_config_hash.as_str(),
                        "artifact_hash": self.requirement.approved_artifact_hash.as_str(),
                    }),
                    heartbeat_ms: 1_000,
                    control_channel: "loopback-store-control".to_owned(),
                    rejection_reason: None,
                    authority_epoch: self.requirement.authority_epoch().clone(),
                };
                self.pending = Some(
                    server_hello_frame(self.requirement.connection_id.as_str(), &hello)
                        .expect("loopback server hello encodes"),
                );
                return Ok(DeliveryOutcome::Delivered);
            }
            let (request_id, _identity, request) = eliot_store_api::decode_request_frame(frame)
                .map_err(crate::StoreClientError::from)?;
            match request {
                StoreRequest::Readiness => {
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        StoreResponse::Readiness {
                            receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
                        },
                    ));
                }
                StoreRequest::Named { request } => {
                    self.pending = Some(self.handle_named(&request, &request_id));
                }
                _ => {
                    return Err(crate::StoreClientError::Contract(
                        "loopback received unexpected request".to_owned(),
                    ));
                }
            }
            Ok(DeliveryOutcome::Delivered)
        }

        async fn receive_frame(
            &mut self,
            _limits: TransportLimits,
        ) -> Result<Frame, crate::StoreClientError> {
            self.pending.take().ok_or_else(|| {
                crate::StoreClientError::Transport("loopback response missing".to_owned())
            })
        }
    }

    #[tokio::test]
    async fn execute_named_get_evidence_pack_proves_identity_and_fence() {
        // Temp-root capture file: the one durable evidence subject, derived
        // at runtime so no canned value can satisfy the identity assertions.
        let subject = format!("evidence-subject-{}", std::process::id());
        let scratch =
            std::env::temp_dir().join(format!("eliot-t11-daemon-gateway-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch root creates");
        let captured_path = scratch.join("captured_subjects");
        std::fs::write(&captured_path, format!("{subject}\n")).expect("capture stages");

        let fence = test_fence();
        let bootstrap = requirement(&fence);
        let service = Arc::new(Mutex::new(
            crate::KernelService::new([7_u8; 32], 8, 8).expect("kernel service creates"),
        ));
        let route = eliot_kernel_core::GenerationRoute::new(
            RouteScope::new("store_bridge").expect("route scope"),
            ResourceGeneration::genesis(),
            test_epoch(1),
        )
        .expect("store route binds");
        let transport = LoopbackSurrealTransport {
            requirement: bootstrap.clone(),
            pending: None,
            captured_subjects_path: captured_path.clone(),
        };
        let store = EbpCanonicalStoreClient::connect(transport, bootstrap)
            .await
            .expect("loopback handshake and readiness");
        let flight = GatewayFlight::new();

        let request = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(ScopeId::new("scope-evidence").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: evidence_params(&subject, "10"),
        };
        let response = execute_named_via(&flight, &service, &route, &store, request)
            .await
            .expect("exact evidence pack reads");
        assert_eq!(response.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(response.state_fence, fence);
        assert_eq!(
            response.payload.get("version"),
            Some(&json!(EVIDENCE_PACK_VERSION))
        );
        assert_eq!(
            response.payload.get("subject"),
            Some(&Value::String(subject.clone()))
        );
        let records = response
            .payload
            .get("records")
            .and_then(Value::as_array)
            .expect("records array present");
        assert_eq!(records.len(), 1, "exact subject yields its one record");
        assert_eq!(records[0].get("capture_index"), Some(&json!(0)));
        assert_eq!(
            records[0].get("operation"),
            Some(&json!("CaptureObservation"))
        );
        assert_eq!(
            records[0]
                .get("parameters")
                .and_then(|parameters| parameters.get("subject")),
            Some(&Value::String(subject.clone()))
        );
        let provenance = response
            .payload
            .get("provenance")
            .and_then(Value::as_object)
            .expect("provenance present");
        assert_eq!(provenance.get("matched_total"), Some(&json!(1)));
        assert_eq!(provenance.get("returned"), Some(&json!(1)));
        assert_eq!(provenance.get("truncated"), Some(&json!(false)));
        let expected_fence = serde_json::to_value(&fence).expect("fence encodes");
        assert_eq!(provenance.get("state_fence"), Some(&expected_fence));

        // T11.1 acceptance negative: a changed fence must not return a
        // successful current view.
        let changed_fence =
            eliot_contracts::StateFence::new(test_epoch(2), ResourceGeneration::genesis());
        let fenced_request = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(ScopeId::new("scope-evidence").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: changed_fence,
            parameters: evidence_params(&subject, "10"),
        };
        let fenced = execute_named_via(&flight, &service, &route, &store, fenced_request).await;
        assert!(
            fenced.is_err(),
            "changed fence must fail closed, observed: {fenced:?}"
        );

        // T11.1 acceptance negative: exceeding the declared bound must not
        // return a successful current view.
        let over_bound = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(ScopeId::new("scope-evidence").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence,
            parameters: evidence_params(&subject, &(EVIDENCE_PACK_MAX_RECORDS + 1).to_string()),
        };
        let bounded = execute_named_via(&flight, &service, &route, &store, over_bound).await;
        match bounded {
            Err(error) => assert!(
                error.contains("payload exceeds named-operation limit"),
                "over-bound refusal must surface the typed limit, observed: {error}"
            ),
            Ok(_) => panic!("over-bound request must fail closed"),
        }

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[tokio::test]
    async fn execute_named_get_current_epistemic_position_proves_identity_and_fence() {
        let position = format!("position-{}", std::process::id());
        let scratch =
            std::env::temp_dir().join(format!("eliot-t11-2-daemon-gateway-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch root creates");
        let captured_path = scratch.join("captured_subjects");
        std::fs::write(&captured_path, "unused\n").expect("capture stages");

        let fence = test_fence();
        let bootstrap = requirement(&fence);
        let service = Arc::new(Mutex::new(
            crate::KernelService::new([7_u8; 32], 8, 8).expect("kernel service creates"),
        ));
        let route = eliot_kernel_core::GenerationRoute::new(
            RouteScope::new("store_bridge").expect("route scope"),
            ResourceGeneration::genesis(),
            test_epoch(1),
        )
        .expect("store route binds");
        let transport = LoopbackSurrealTransport {
            requirement: bootstrap.clone(),
            pending: None,
            captured_subjects_path: captured_path.clone(),
        };
        let store = EbpCanonicalStoreClient::connect(transport, bootstrap)
            .await
            .expect("loopback handshake and readiness");
        let flight = GatewayFlight::new();

        let request = NamedReadRequest {
            operation: NamedReadOperation::GetCurrentEpistemicPosition,
            scope_id: Some(ScopeId::new("scope-epistemic").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: BTreeMap::from([("position".to_owned(), Value::String(position.clone()))]),
        };
        let response = execute_named_via(&flight, &service, &route, &store, request)
            .await
            .expect("exact position read passes the gateway");
        assert_eq!(
            response.operation,
            NamedReadOperation::GetCurrentEpistemicPosition
        );
        assert_eq!(response.state_fence, fence);
        assert_eq!(
            response.payload.get("position"),
            Some(&Value::String(position.clone()))
        );

        let changed_fence =
            eliot_contracts::StateFence::new(test_epoch(2), ResourceGeneration::genesis());
        let fenced_request = NamedReadRequest {
            operation: NamedReadOperation::GetCurrentEpistemicPosition,
            scope_id: Some(ScopeId::new("scope-epistemic").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: changed_fence,
            parameters: BTreeMap::from([("position".to_owned(), Value::String(position.clone()))]),
        };
        let fenced = execute_named_via(&flight, &service, &route, &store, fenced_request).await;
        assert!(
            fenced.is_err(),
            "changed fence must fail closed, observed: {fenced:?}"
        );

        let eventual = NamedReadRequest {
            operation: NamedReadOperation::GetCurrentEpistemicPosition,
            scope_id: Some(ScopeId::new("scope-epistemic").expect("scope")),
            consistency: ReadConsistency::Eventual,
            state_fence: fence.clone(),
            parameters: BTreeMap::from([("position".to_owned(), Value::String(position.clone()))]),
        };
        assert!(
            execute_named_via(&flight, &service, &route, &store, eventual)
                .await
                .is_err(),
            "non-ExactFence position read must fail closed"
        );

        let missing = NamedReadRequest {
            operation: NamedReadOperation::GetCurrentEpistemicPosition,
            scope_id: Some(ScopeId::new("scope-epistemic").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence,
            parameters: BTreeMap::new(),
        };
        assert!(
            execute_named_via(&flight, &service, &route, &store, missing)
                .await
                .is_err(),
            "missing position selector must fail closed"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "T11.1 live-Surreal daemon-half E2E: every asserted identity, fence, bound, and payload value is derived from runtime inputs and the live provider; nothing is canned"
)]
mod live_surreal_evidence_pack_e2e {
    //! T11.1 daemon-half live proof against the real embedded Surreal store.
    //!
    //! Unlike `named_read_gateway_tests` (a loopback transport replaying
    //! Surreal-conformant frames), this module boots a REAL `surreal.exe`
    //! provider on an isolated temp root, drives the production
    //! [`SurrealStoreAdapter`](eliot_store_surreal_adapter::SurrealStoreAdapter)
    //! (schema migration, one `CaptureObservation` mutation, one
    //! `GetEvidencePack` named read), and serves the `eliot.query`
    //! acceptance through the production Governor
    //! [`ReadService`](eliot_read::ReadService) — the exact service type
    //! `DaemonComposition::context_read_client` pairs with the daemon's
    //! `KernelContextReadClient` over the same `CanonicalReadClient`
    //! interface. The memory adapter is never used here; it remains the
    //! reference handler only.
    //!
    //! Coverage in two tests sharing one fixture builder:
    //!
    //! * `daemon_query_gates_fail_closed_before_store_io` — the #1465
    //!   residuals through the real `ReadService` over a real (unconnected)
    //!   adapter instance: smuggled `query`/`exact_resource_uri` parameters
    //!   and a `QueryRequest`-level `exact_resource_uri` fail closed, and
    //!   `state()` rejects `GetEvidencePack`. These gates sit before any
    //!   transport by contract, so no provider is needed; this test is green.
    //! * `live_surreal_capture_then_eliot_query_returns_exact_evidence_pack`
    //!   — the T11.1 acceptance live: one real capture, then `eliot.query`
    //!   returns the exact record/provenance with an explicit `Verification`
    //!   intent (free-text `query` stays intent data, never a selector), and
    //!   wrong-fence / over-bound requests fail. Green on base `67a1af95`
    //!   (with `#1480`): the prior colon-binding substrate block no longer
    //!   reproduces here; captures commit and the acceptance holds. The test
    //!   must not be weakened, ignored, or deleted.
    //!
    //! Prior substrate note (retained for traceability, not a current block):
    //! on the older base the live capture rolled back with `Couldn't coerce
    //! value for field revision_key ... Expected string but found
    //! scope:scope` (`SurrealDB` 3.1.4 RPC `query` colon-binding coercion via
    //! `scope:{scope_id}` keys in `plan.rs`, `schema.rs`, `apply/atomic_write.rs`).
    //! That belonged to the adapter owner
    //! (`crates/storage/eliot-store-surreal-adapter/`, ASTRA T11.2) and was
    //! never touched here; on `67a1af95` the live capture commits unchanged.

    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_platform_windows::{RetainedProcessPathLease, WindowsPlatform};
    use eliot_read::{
        BranchEnvironmentScope, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode,
        QueryRequest, ReadApi, ReadError, ReadOrderingBinding, ReadService, RequiredAssurance,
        StateRequest, StoreReadFailure, TimeScope,
    };
    use eliot_store_api::{
        EVIDENCE_PACK_MAX_RECORDS, EffectClass, EventProjectionRelationIntents,
        NamedMutationOperation, NamedMutationRequest, NamedReadOperation, OperationId,
        OperationIdentity, OrderingScopeId, PreparedTransition, ReadConsistency, ScopeId,
        TransitionClass, WriteReceiptStatus, generated_operation_manifests,
        operation_manifest_set_digest, sha256_hex,
    };
    use eliot_store_surreal_adapter::{
        PINNED_SURREALDB_MAJOR, SchemaGeneration, SemanticReadiness, SurrealAdapterConfig,
        SurrealStoreAdapter,
    };
    use serde_json::{Value, json};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const DEFAULT_PROVIDER_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
    const PROVIDER_EXE_OVERRIDE_ENV: &str = "ELIOT_T11_SURREAL_EXE";

    fn provider_exe() -> PathBuf {
        std::env::var_os(PROVIDER_EXE_OVERRIDE_ENV)
            .map_or_else(|| PathBuf::from(DEFAULT_PROVIDER_EXE), PathBuf::from)
    }

    fn live_fence() -> StateFence {
        let lineage = EpochLineageId::new(TEST_LINEAGE).expect("test lineage parses");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero sequence"))
            .expect("test epoch builds");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn wrong_fence() -> StateFence {
        let lineage = EpochLineageId::new(TEST_LINEAGE).expect("test lineage parses");
        let epoch = EpochId::new(lineage, NonZeroU64::new(2).expect("nonzero sequence"))
            .expect("changed epoch builds");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn now_ms() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis()),
        )
        .unwrap_or(i64::MAX)
    }

    fn live_clock() -> ClockReading {
        let observed = now_ms();
        ClockReading {
            valid_time_ms: Some(observed),
            known_time_ms: Some(observed),
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn live_context(fence: &StateFence, tag: &str) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new(format!("t11-live-{tag}")).expect("request identity"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("t11-live-product").expect("product identity"),
            source_id: SourceId::new("t11-live-source").expect("source identity"),
            state_fence: fence.clone(),
            clock: live_clock(),
        }
    }

    fn live_capture_transition(
        fence: &StateFence,
        scope: &ScopeId,
        subject: &str,
        tag: &str,
    ) -> PreparedTransition {
        let entries = generated_operation_manifests().expect("operation catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest computes");
        let mut transition = PreparedTransition {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: OperationId::new(format!("op-t11-live-{tag}"))
                    .expect("operation identity"),
                idempotency_key: format!("idem-t11-live-{tag}"),
                canonical_request_hash: sha256_hex(format!("op-t11-live-{tag}").as_bytes()),
            },
            state_fence: fence.clone(),
            scope_id: scope.clone(),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new(scope.as_str()).expect("ordering scope")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: set_digest.as_str().to_owned(),
            operation_manifest_digest: set_digest,
            // Issue-#18 digests are derived, never defaulted; no semantic
            // source is bound here (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([("subject".to_owned(), json!(subject))]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: eliot_store_api::SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    fn verification_intent() -> QueryIntent {
        QueryIntent {
            mode: QueryMode::Verification,
            time_scope: TimeScope::EvidenceWindow,
            branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
            freshness_policy: FreshnessPolicy::ExactFence,
            required_assurance: RequiredAssurance::VerifierEvidence,
        }
    }

    fn evidence_parameters(subject: &str, max_records: &str) -> NamedParameters {
        NamedParameters::from_map(BTreeMap::from([
            ("subject".to_owned(), Value::String(subject.to_owned())),
            (
                "max_records".to_owned(),
                Value::String(max_records.to_owned()),
            ),
        ]))
        .expect("the evidence selectors satisfy the closed-selector bounds")
    }

    fn live_query(scope: &ScopeId, subject: &str, max_records: &str) -> QueryRequest {
        QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters: evidence_parameters(subject, max_records),
            provenance_handles: Vec::new(),
        }
    }

    fn live_roots(suffix: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        // The suffix keeps parallel tests in one process (same pid) on
        // disjoint roots: sharing a root would let one test's cleanup
        // remove another test's live provider files mid-run.
        let root = std::env::temp_dir().join(format!(
            "eliot-t11-live-surreal-{}-{suffix}",
            std::process::id()
        ));
        let data = root.join("data");
        let work = root.join("work");
        let tmp = root.join("tmp");
        for dir in [&root, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("live temp root creates");
        }
        (root, data, work, tmp)
    }

    fn free_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("loopback probe binds")
            .local_addr()
            .expect("probe address reads")
            .port()
    }

    /// Creates the provider root user on a FRESH data root, then stops.
    ///
    /// The adapter's canonical argv carries no `--user/--pass` (credentials
    /// never enter argv or the environment), so a fresh datastore must first
    /// observe its installation root user exactly once — the same bootstrap
    /// the Host-managed installation performs. This fixture spawns the
    /// provider briefly with the test credential, waits for its bound
    /// endpoint, then kills and reaps it; the adapter spawns and owns its own
    /// provider child afterwards. The child is always reaped (`kill_on_drop`
    /// plus explicit `kill`/`wait`), never orphaned.
    async fn bootstrap_root_user(
        exe: &Path,
        work: &Path,
        data: &Path,
        bind: &str,
        username: &str,
        password: &str,
    ) {
        let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
        let mut child = tokio::process::Command::new(exe)
            .args([
                "start",
                "--no-banner",
                "--bind",
                bind,
                "--username",
                username,
                "--password",
                password,
                &data_url,
            ])
            .current_dir(work)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("bootstrap provider spawns");
        let mut bound = false;
        for _ in 0..300 {
            assert!(
                child.try_wait().expect("bootstrap child polls").is_none(),
                "bootstrap provider exited before binding {bind}"
            );
            if matches!(
                tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::TcpStream::connect(bind)
                )
                .await,
                Ok(Ok(_))
            ) {
                bound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(bound, "bootstrap provider never bound {bind}");
        child.kill().await.expect("bootstrap provider kills");
        child.wait().await.expect("bootstrap provider reaps");
    }

    fn live_lease(work: &Path, exe: &Path, exe_digest: &str) -> RetainedProcessPathLease {
        let platform =
            WindowsPlatform::new(Path::new(r"C:\")).expect("platform binds the system root");
        platform
            .retain_process_path_lease(exe, work, exe_digest)
            .expect("provider lease retains")
    }

    struct LiveAdapterParts {
        adapter: SurrealStoreAdapter,
        root: PathBuf,
        bind: String,
        username: String,
        password: String,
        work: PathBuf,
        data: PathBuf,
        exe: PathBuf,
    }

    /// Builds a real adapter on an isolated temp root without connecting.
    ///
    /// Construction is pure (catalogue digest + lease validation); no
    /// provider spawns here. Callers that need live I/O bootstrap the root
    /// user and call `connect` themselves.
    fn build_adapter(tag: &str) -> LiveAdapterParts {
        let exe = provider_exe();
        assert!(
            exe.is_file(),
            "the live proof requires a real SurrealDB provider; set {PROVIDER_EXE_OVERRIDE_ENV} or install it at {}",
            exe.display()
        );
        let exe_bytes = std::fs::read(&exe).expect("provider bytes read");
        let exe_digest = sha256_hex(&exe_bytes);
        let roots_digest = sha256_hex(format!("t11-live-roots-{tag}").as_bytes());
        let (root, data, work, tmp) = live_roots(tag);
        let port = free_loopback_port();
        let bind = format!("127.0.0.1:{port}");
        let username = "t11-live-provider".to_owned();
        let password = format!("t11-live-provider-password-{tag}");
        let mut config = SurrealAdapterConfig {
            endpoint: format!("ws://{bind}/rpc"),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: username.clone(),
            password: secrecy::SecretString::new(password.clone().into()),
            provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
            provider_bootstrap_password: secrecy::SecretString::new(
                "provider-bootstrap-fixture-secret".into(),
            ),
            provider_bind_address: bind.clone(),
            installation_id: "t11-live-installation".to_owned(),
            installation_profile: "portable_dev".to_owned(),
            runtime_state_roots_digest: roots_digest,
            provider_executable_path: exe.to_string_lossy().into_owned(),
            provider_artifact_digest: exe_digest.clone(),
            provider_arguments: Vec::new(),
            store_data_root: data.to_string_lossy().into_owned(),
            store_work_root: work.to_string_lossy().into_owned(),
            store_temp_root: tmp.to_string_lossy().into_owned(),
            connect_timeout_ms: 60_000,
            query_timeout_ms: 30_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        };
        config.provider_arguments = config.expected_provider_arguments();
        config.validate().expect("live adapter config validates");
        let lease = live_lease(&work, &exe, &exe_digest);
        let adapter = SurrealStoreAdapter::new(config, lease).expect("live adapter constructs");
        LiveAdapterParts {
            adapter,
            root,
            bind,
            username,
            password,
            work,
            data,
            exe,
        }
    }

    #[tokio::test]
    async fn daemon_query_gates_fail_closed_before_store_io() {
        // #1465 residuals through the production facade over a real adapter
        // instance. Every check below fails before any transport by
        // contract, so this test needs no provider and stays green while
        // the live capture substrate is blocked (see module docs).
        let tag = format!("gates-p{}", std::process::id());
        let subject = format!("t11-live-observation-{tag}");
        let scope = ScopeId::new("scope-t11-live").expect("scope parses");
        let fence = live_fence();
        let parts = build_adapter(&tag);
        let service = ReadService::new(parts.adapter);

        // A retired `query` selector can no longer be built through
        // `NamedParameters`, but the newtype is `#[serde(transparent)]` with a
        // derived `Deserialize` that does not validate — so the wire can still
        // present one. The gate that must hold is the service's, before any
        // transport.
        let smuggled = serde_json::from_value::<NamedParameters>(json!({
            "subject": subject.clone(),
            "max_records": "10",
            "query": subject.clone(),
        }))
        .expect("wire-shaped named parameters deserialize without validation");
        let smuggled_request = QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters: smuggled,
            provenance_handles: Vec::new(),
        };
        assert!(
            matches!(
                service
                    .query(
                        &live_context(&fence, &format!("query-smuggled-{tag}")),
                        smuggled_request
                    )
                    .await,
                Err(ReadError::DuplicateField(_))
            ),
            "a wire-smuggled `query` selector must fail closed at the service gate"
        );

        // Exact expansion belongs to `ResourceRequest`, never to
        // `QueryRequest`. The request-level selector is now structurally
        // unrepresentable — `QueryRequest` has no `exact_resource_uri` field —
        // so the only remaining bypass is the wire-decoded parameter key, and
        // that is what this proves.
        let smuggled_uri = serde_json::from_value::<NamedParameters>(json!({
            "subject": subject.clone(),
            "max_records": "10",
            "exact_resource_uri": "eliot://evidence/pack",
        }))
        .expect("wire-shaped named parameters deserialize without validation");
        let smuggled_uri_request = QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters: smuggled_uri,
            provenance_handles: Vec::new(),
        };
        assert!(
            matches!(
                service
                    .query(
                        &live_context(&fence, &format!("query-smuggled-uri-{tag}")),
                        smuggled_uri_request
                    )
                    .await,
                Err(ReadError::DuplicateField(_))
            ),
            "a wire-smuggled `exact_resource_uri` selector must fail closed at the service gate"
        );
        // Deleted with #1976: `QueryRequest` no longer has an
        // `exact_resource_uri` field, so a request-level exact selector on the
        // broad-query path is structurally unrepresentable. The invariant is
        // held by the type, not by this assertion; the wire-smuggled parameter
        // key above covers the one bypass that still exists.

        // `state()` owns current-state operations only — `GetEvidencePack`
        // is rejected before any transport.
        let state_rejected = service
            .state(
                &live_context(&fence, &format!("state-pack-{tag}")),
                StateRequest {
                    operation: NamedReadOperation::GetEvidencePack,
                    scope_id: Some(scope.clone()),
                    consistency: ReadConsistency::Eventual,
                    dependency_revisions: BTreeMap::new(),
                    ordering: ReadOrderingBinding::without_order_dependency(),
                    parameters: evidence_parameters(&subject, "10"),
                    provenance_handles: Vec::new(),
                },
            )
            .await;
        match state_rejected {
            Err(ReadError::OperationNotAllowed { operation, context }) => {
                assert_eq!(operation, NamedReadOperation::GetEvidencePack);
                assert_eq!(context, "state");
            }
            other => panic!("state(GetEvidencePack) must fail closed, observed: {other:?}"),
        }

        drop(service);
        let _ = std::fs::remove_dir_all(&parts.root);
    }

    #[tokio::test]
    async fn live_surreal_capture_then_eliot_query_returns_exact_evidence_pack() {
        let tag = format!("p{}", std::process::id());
        let subject = format!("t11-live-observation-{tag}");
        let scope = ScopeId::new("scope-t11-live").expect("scope parses");
        let fence = live_fence();

        let parts = build_adapter(&tag);
        let LiveAdapterParts {
            adapter,
            root,
            bind,
            username,
            password,
            work,
            data,
            exe,
        } = parts;
        bootstrap_root_user(&exe, &work, &data, &bind, &username, &password).await;
        adapter.connect().await.expect("live adapter connects");

        assert!(
            matches!(
                adapter.probe_readiness().await.expect("readiness probes"),
                SemanticReadiness::MigrationRequired { .. }
            ),
            "a fresh temp-root provider must observe MigrationRequired before migration"
        );
        adapter
            .apply_migration(
                &SurrealStoreAdapter::v2_baseline_migration(),
                &live_clock(),
                &fence,
            )
            .await
            .expect("v2 baseline migrates");
        assert!(
            matches!(
                adapter
                    .probe_readiness()
                    .await
                    .expect("readiness re-probes"),
                SemanticReadiness::Ready { .. }
            ),
            "the migrated provider must observe Ready before capture"
        );

        // Existing capture path: one real observation through the production
        // atomic writer on the live provider.
        let ctx = live_context(&fence, &format!("capture-{tag}"));
        let transition = live_capture_transition(&fence, &scope, &subject, &tag);
        let receipt = adapter
            .apply_prepared(&ctx, transition, Vec::new(), Vec::new())
            .await
            .expect("live capture commits");
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(receipt.state_fence, fence);

        // `eliot.query` acceptance: the Governor read facade over the SAME
        // live adapter returns the exact record/provenance. Free text cannot
        // be supplied at all now — the closed named operation and the closed
        // selectors fully determine the read.
        let service = ReadService::new(adapter);
        let result = service
            .query(
                &live_context(&fence, &format!("query-{tag}")),
                live_query(&scope, &subject, "10"),
            )
            .await
            .expect("live eliot.query reads its exact pack");
        assert_eq!(result.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(result.state_fence, fence);
        assert_eq!(result.intent, verification_intent());
        assert_eq!(
            result.payload.get("subject"),
            Some(&Value::String(subject.clone()))
        );
        let records = result
            .payload
            .get("records")
            .and_then(Value::as_array)
            .expect("records array present");
        assert_eq!(records.len(), 1, "exact subject yields its one record");
        assert_eq!(records[0].get("capture_index"), Some(&json!(0)));
        assert_eq!(
            records[0].get("operation"),
            Some(&json!("CaptureObservation"))
        );
        assert_eq!(
            records[0]
                .get("parameters")
                .and_then(|parameters| parameters.get("subject")),
            Some(&Value::String(subject.clone()))
        );
        let provenance = result
            .payload
            .get("provenance")
            .and_then(Value::as_object)
            .expect("provenance present");
        assert_eq!(provenance.get("matched_total"), Some(&json!(1)));
        assert_eq!(provenance.get("returned"), Some(&json!(1)));
        assert_eq!(provenance.get("truncated"), Some(&json!(false)));
        let expected_fence = serde_json::to_value(&fence).expect("fence encodes");
        assert_eq!(provenance.get("state_fence"), Some(&expected_fence));
        for head in &result.revision_heads {
            assert_eq!(
                head.state_fence, fence,
                "every observed head stays on the admitted fence"
            );
        }

        // Acceptance negative: a changed fence must not return a successful
        // current view.
        let fenced = service
            .query(
                &live_context(&wrong_fence(), &format!("query-wrong-fence-{tag}")),
                live_query(&scope, &subject, "10"),
            )
            .await;
        match fenced {
            Err(ReadError::Store(StoreReadFailure::FenceMismatch)) => {}
            other => panic!("wrong fence must fail closed with FenceMismatch, observed: {other:?}"),
        }

        // Acceptance negative: exceeding the declared bound must not return
        // a successful current view.
        let over_bound = service
            .query(
                &live_context(&fence, &format!("query-over-bound-{tag}")),
                live_query(
                    &scope,
                    &subject,
                    &(EVIDENCE_PACK_MAX_RECORDS + 1).to_string(),
                ),
            )
            .await;
        match over_bound {
            Err(ReadError::Store(StoreReadFailure::PayloadTooLarge)) => {}
            other => panic!(
                "over-bound request must fail closed with PayloadTooLarge, observed: {other:?}"
            ),
        }

        // An admitted state operation still serves on the same live store
        // (`GetEvidencePack` rejection is covered in
        // `daemon_query_gates_fail_closed_before_store_io`).
        let state_view = service
            .state(
                &live_context(&fence, &format!("state-heads-{tag}")),
                StateRequest {
                    operation: NamedReadOperation::GetRevisionHeads,
                    scope_id: None,
                    consistency: ReadConsistency::Eventual,
                    dependency_revisions: BTreeMap::new(),
                    ordering: ReadOrderingBinding::without_order_dependency(),
                    parameters: NamedParameters::new(),
                    provenance_handles: Vec::new(),
                },
            )
            .await
            .expect("admitted state operation still serves on the live store");
        assert_eq!(state_view.operation, NamedReadOperation::GetRevisionHeads);
        assert_eq!(state_view.state_fence, fence);

        drop(service);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = std::fs::remove_dir_all(&root);
    }
}
