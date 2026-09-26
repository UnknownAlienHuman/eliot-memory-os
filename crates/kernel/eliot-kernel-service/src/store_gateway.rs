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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_contracts::{OperationId, RequestMetadata, StateFence};
use eliot_ipc::NamedPipeTransport;
use eliot_kernel_core::GenerationRoute;
use eliot_kernel_core::UserAutomationOperation;
use eliot_kernel_core::user_automation::{
    UserAutomationConfigurationState, UserAutomationInvocation, UserAutomationRevision,
};
use eliot_ors::{
    RedbRecoveryStore, ReservationRecord, UnknownCommitOutcome, UnknownCommitRecord,
    WriterReservationToken,
};
use eliot_protocol::dreamer_job::{
    DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, CanonicalValidationSnapshot, NamedReadRequest,
    NamedReadResponse, OperationIdentity, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, ReservedWriteRequest, RevisionHead, RevisionHeadExpectation,
    RevisionKey, ScopeId, ScopeRevisionView, StoreError, StoreGenesisRequest, StoreHealth,
    StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt, canonical_request_hash,
    generated_operation_manifests, verify_canonical_request_hash,
};

use crate::commit_recovery::{
    CheckedPauseObservation, CommitRecoveryClass, CommitRecoveryError, PauseReleaseOutcome,
    PauseScopeView, PausedScopeMirror, RetainedCommitState, classify_commit_receipt,
    classify_retained_commit, open_record_for, receipt_evidence_digest, recover_commit,
    resolve_open_record, verify_receipt_binding, verify_retained_binding, verify_terminal_evidence,
};
use crate::store_client::DreamerCommitEvidence;
use crate::store_write_reservation::{
    CompositionReservation, ReservationSeed, ReservedSubmission, ResolvedSendOutcome,
    begin_execute_after_send, cancel_before_send, ensure_eligible, finalize_reservation,
    mark_unknown_outcome, reconcile_receipt, reserve_for_transition, writer_epoch_for_fence,
    writer_epoch_for_fence_from_epoch,
};
use crate::user_automation_execution::{
    UserAutomationWakeTargetEnumeration, read_retirement_wake_targets,
};
use crate::{
    AdmissionLease, CanonicalUserAutomationStore, EbpCanonicalStoreClient, EbpStoreTransport,
    KernelService, StoreClientFault, StoreClientFaultHarness, UserAutomationConfigurationPhase,
    UserAutomationExecutionPhase, UserAutomationHorizonOutcome, UserAutomationHorizonPhase,
    UserAutomationHorizonTrigger, UserAutomationMutationResult, UserAutomationOperatorTransition,
    UserAutomationOwnerLookup, UserAutomationOwnerSnapshot, UserAutomationRuntimeError,
    UserAutomationRuntimePort, UserAutomationService, UserAutomationServiceRequest,
    UserAutomationStoreRequest, UserAutomationWakeHorizonPublication, UserAutomationWakePhase,
    UserAutomationWakePort, committed_configuration_state, compile_wake_horizon,
    run_now_wake_read_request,
};
use eliot_kernel_core::user_automation::UserAutomationExecutionProjection;

const ACTIVE_DAEMON_CALLER: &str = "eliotd";

#[path = "store_receipt_gateway.rs"]
mod store_receipt_gateway;

/// Kernel answer for one Dreamer ledger mutation whose ledger answer could not
/// be observed on the wire (I14.21, issue #1690).
///
/// `commit_recovery::recover_commit` shapes the commits that answer with a
/// `WriteReceipt`; a Dreamer commit answers with a ledger projection instead,
/// so this leg states the same three mandated branches over its own typed
/// answer and never collapses them into a success or a retry permission.
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
///
/// This is the recovery leg's own closed branch set, and it is the level at
/// which the issue's five-way classification is observable:
///
/// * [`Self::Settled`] carries a [`DreamerCommitUncertain`], whose four
///   variants (`Reconciled`, `AlreadyDispositioned`,
///   `ReconciledWithRefreshLimitation`, `UnknownCommitOpen`) are the settled
///   outcomes a caller must tell apart;
/// * [`Self::SameIdentityRetryPermitted`] is the fifth branch. It is a
///   decision, not a report: the route consumes it by re-entering current
///   normal admission and the other-key pause gate for exactly one bounded
///   same-identity retry, so it is never rendered as a caller-visible answer
///   and never becomes an ambiguous "retry allowed" string. It is named here
///   so the branch cannot be confused with a settled outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DreamerRetainedOutcome {
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

/// Closed failure of one admitted Dreamer ledger route.
///
/// This is the minimal compatible carrier issue #2764 item 6 asks for. The
/// route used to answer `Result<DurableJobResponse, String>`, which flattened
/// every recovered outcome into prose at the boundary: the real caller could
/// not tell `Reconciled` from `AlreadyDispositioned` from
/// `ReconciledWithRefreshLimitation` from `UnknownCommitOpen`, and could not
/// see `OrderingScopeUnresolved` as anything but a sentence. Nothing in the
/// recovery leg is stringified any more; the typed value crosses the route and
/// is rendered exactly once, at the single transport edge.
///
/// The three variants are closed and none is defaulted:
///
/// * [`Self::Recovered`] is a proven or preserved commit outcome. It is never
///   a refusal and never a success: no `DurableJobResponse` exists.
/// * [`Self::Recovery`] is a refusal the recovery leg produced, carried as
///   its owning [`CommitRecoveryError`] variant so
///   `OrderingScopeUnresolved`, `ScopePaused`, `RetainedRecordConflict` and
///   the rest stay distinguishable without parsing text.
/// * [`Self::Refused`] is a deterministic pre-store or store-side refusal
///   whose text is the owner's own. Nothing in the recovery leg uses it, so a
///   recovered outcome can never be reported through this variant.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DreamerJobFailure {
    /// A deterministic refusal, in the owner's own words: the route's
    /// pre-store checks, or the transport client's own `StoreError`
    /// rendering. The recovery leg never answers here.
    #[error("{0}")]
    Refused(String),
    /// A refusal reported by the recovery leg's own typed variant.
    #[error("{0}")]
    Recovery(CommitRecoveryError),
    /// The commit outcome is proven or preserved and no ledger answer
    /// exists. Carries the exact outcome so the caller acts on the proven
    /// fact rather than on its prose.
    #[error("{0}")]
    Recovered(DreamerCommitUncertain),
}

/// The checked pause gate for one admitted Dreamer operation (#2763).
///
/// A derived Ordering Scope is matched against the complete observed record
/// set, so every open record covering the scope is considered. An operation
/// that proves no Ordering Scope is not exempted: `OrderingScopeUnresolved`
/// states the limitation and closes admission whenever any other open record
/// exists, because an absent scope vector is not evidence of being unpaused.
fn dreamer_pause_refusal(
    observed: &CheckedPauseObservation,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
    effect: DreamerOperationEffect,
) -> Option<CommitRecoveryError> {
    if effect != DreamerOperationEffect::Mutation {
        return None;
    }
    let key = identity.idempotency_key.as_str();
    if ordering_scopes.is_empty() {
        if observed.any_open_except(key) {
            return Some(CommitRecoveryError::OrderingScopeUnresolved {
                operation: "dreamer-job".to_owned(),
                detail: format!(
                    "no Ordering Scope is derivable for this operation, so its coverage by the \
                     open unknown-commit record set observed at revision {} cannot be proven \
                     and dependent durable admission stays closed",
                    observed.binding().revision
                ),
            });
        }
        return None;
    }
    ordering_scopes.iter().find_map(|scope| {
        observed
            .pausing_key_for(scope, key)
            .map(|pausing_key| CommitRecoveryError::ScopePaused {
                scope: scope.clone(),
                paused_by_key: pausing_key.to_owned(),
            })
    })
}

/// Renders an ORS failure as the fail-closed recovery refusal (I14.24).
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

/// Projects one already-resolved durable record into its typed answer,
/// preserving the outcome it actually recorded.
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
/// gated like any other. An empty derived scope list is NOT evidence that an
/// operation is read-only, which is why this classification does not consult
/// [`dreamer_ordering_scopes`] at all.
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
        | JobOperation::Reconcile { .. } => DreamerOperationEffect::Mutation,
    }
}

/// Ordering Scopes one admitted Dreamer ledger mutation belongs to.
///
/// A Dreamer ledger is ordered inside its Work Scope, and only the closed
/// kinds that select a job by scope carry that identity on the request:
/// `Submit` names its submission's work scope, and `LeaseNext`/`LeaseExact`
/// name their selector's scope.
///
/// The remaining closed kinds bind a lease, a job id, or a pure observation
/// and therefore prove no Ordering Scope. That is now a *stated limitation*
/// rather than a silent exemption: the caller turns an empty vector into a
/// fail-closed gate over the complete observed record set rather than into
/// admission. No scope is ever invented, and an absent scope is never used as
/// a bypass.
fn dreamer_ordering_scopes(request: &DurableJobRequest) -> Vec<String> {
    let scope = match &request.operation {
        JobOperation::Submit { submission } => submission.work_scope.scope_id.as_str(),
        JobOperation::LeaseNext { selector } | JobOperation::LeaseExact { selector, .. } => {
            selector.scope_id.as_str()
        }
        _ => return Vec::new(),
    };
    vec![scope.to_owned()]
}

/// Recomputes the Dreamer canonical request binding through its owning
/// contract instead of trusting the presented digest (issue #2764 item 1).
///
/// The clause is "recompute/verify canonical request binding through the
/// existing contract, not caller spelling", and the shared implementation of
/// it for the `Apply` leg is
/// [`eliot_store_api::verify_canonical_request_hash`](eliot_store_api::verify_canonical_request_hash)
/// — used at `admit_prepared_transition`, `apply_reserved_admission` and
/// `EbpCanonicalStoreClient::apply_prepared`. This is the same mechanism for
/// the Dreamer ledger leg: the digest is rebuilt by its own owner from the
/// exact values about to be executed, and a divergence is refused before the
/// identity is formed.
///
/// The one shared function cannot serve both legs, and the reason is a shape
/// difference rather than a choice. The store-side view is a
/// `CanonicalRequestView` built from a `PreparedTransition` plus the expected
/// revision and ordering heads; the Dreamer ledger leg carries no prepared
/// transition at all — it sends `StoreRequest::DreamerJob { context, request }`
/// and its digest owner is the K0 contract. The Dreamer digest's owner is
/// therefore [`DurableRequestIdentity::digest_for`], which hashes the same
/// load-bearing bindings this comparison depends on: the versioned canonical
/// encoding tag, the operation binding (operation id, idempotency key,
/// operation kind), the operation payload, the role, the session, task,
/// product and source metadata, and the State Fence.
///
/// That recompute is what gives the retained-hash comparison its force. An
/// opaque presented digest binds nothing, so comparing it would prove only
/// that a string matched a string; a recomputed one binds the owner, scope,
/// fence and contract-version content I1.8 names as load-bearing identity,
/// which is why this runs before the identity is built and not only inside
/// the request validator.
///
/// `JobOperation::Reconcile` is the single closed kind whose presented digest
/// is by K0 contract the *original* mutation's digest, carried forward on
/// purpose, and therefore is not derivable from the `Reconcile` payload;
/// `DurableJobRequest::validate` exempts it from recomputation for that
/// reason. Its identity stays bound — the value is still compared against the
/// retained record, and the exact receipt lookup pins operation id *and* hash
/// — but it is caller-spelled for that one kind, and it is named here rather
/// than left implicit in another crate's exemption. Changing that contract
/// belongs to the K0 owner (`crates/foundation/eliot-protocol`), not to this
/// leg.
fn dreamer_canonical_request_hash(
    request: &DurableJobRequest,
) -> Result<String, CommitRecoveryError> {
    let presented = request.request_identity.canonical_request_hash.as_str();
    if matches!(request.operation, JobOperation::Reconcile { .. }) {
        return Ok(presented.to_owned());
    }
    let recomputed = DurableRequestIdentity::digest_for(
        &request.request_identity.operation,
        &request.request_identity.request,
        &request.operation,
        request.role,
    )
    .map_err(|error| CommitRecoveryError::CommitRefused {
        detail: format!(
            "the canonical request binding for idempotency key {} could not be recomputed \
                 by its owning contract: {error}",
            request.request_identity.operation.idempotency_key
        ),
    })?;
    if recomputed != presented {
        return Err(CommitRecoveryError::CommitRefused {
            detail: format!(
                "the presented canonical request hash {presented} is not the {recomputed} the \
                 owning contract recomputes from this exact operation, role, scope and State \
                 Fence, so no retained binding is compared against caller spelling; nothing was \
                 staged and no Ordering Scope is paused"
            ),
        });
    }
    Ok(recomputed)
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
pub struct BorrowedCanonicalStoreClient<'a> {
    client: &'a EbpCanonicalStoreClient<NamedPipeTransport>,
}

impl<'a> BorrowedCanonicalStoreClient<'a> {
    /// Borrows the already-composed canonical Store client.
    #[must_use]
    pub const fn new(client: &'a EbpCanonicalStoreClient<NamedPipeTransport>) -> Self {
        Self { client }
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
        self.client
            .apply_prepared(
                ctx,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        self.client.receipt(operation_id).await
    }

    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        self.client.revision_heads(keys).await
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        self.client.validation_snapshot().await
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        self.client.scope_revision_view(scope_id).await
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        self.client.ordering_heads(scopes).await
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        self.client.execute_named(query).await
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        self.client.health().await
    }
}

/// Canonical-store gateway bound to the active Kernel generation route.
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

    /// Applies one already prepared transition after fixed Kernel admission.
    pub async fn apply(
        &self,
        context: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        // 1927: authenticate the caller before plan admission (I5.6 step 1),
        // mirroring `apply_reserved_admission`.
        if context.source_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err("transition caller is not the active daemon".to_owned());
        }
        admit_prepared_transition(
            context,
            &transition,
            &expected_revision_heads,
            &expected_ordering_heads,
        )?;

        let lease = {
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
            // Canonical route/epoch gate (Implements #64): route currency is
            // the exact-tuple match between the composition-bound route epoch
            // and live authority — never a scalar `sequence.get()` coercion.
            // Cross-lineage same-sequence routes never authorize: the route
            // carries its own lineage.
            let live_epoch = service.authority_epoch();
            if !self.route.authority_epoch().is_same_authority(&live_epoch)
                || self.route.active_generation() != transition.state_fence.resource_generation
            {
                return Err(
                    "canonical-store route is outside the active Kernel generation".to_owned(),
                );
            }
            let lease = service
                .acquire_admission()
                .map_err(|error| error.to_string())?;
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
                return Err("canonical-store route authority epoch is stale".to_owned());
            }
            lease
        };
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
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
        .map_err(|error| error.to_string());
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
                // orphans. `UnknownOperation` is explicit unsupported behavior
                // from a backend without reserved capability, never a reason
                // to fall back to unreserved `Apply`.
                let _ = cancel_before_send(&owner, &sealed.token);
                drop(lease);
                if matches!(error, StoreError::UnknownOperation) {
                    return Err(format!(
                        "reserved write unsupported for operation {operation_id}: Store backend has no reserved-write capability; refusing without unreserved Apply fallback"
                    ));
                }
                Err(error.to_string())
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
            || self.route.active_generation() != transition.state_fence.resource_generation
            || !live_epoch.is_same_authority(&context.state_fence.authority_epoch)
        {
            return Err("canonical-store route is outside the active Kernel generation".to_owned());
        }
        let writer_epoch = writer_epoch_for_fence(context).map_err(|error| error.to_string())?;
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
        execute_named_via(
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
    /// `runtime` is `Some` for every operation that owns a wake or execution
    /// handoff. A read-only answer passes `None` and reports both handoff
    /// phases as not applicable; a handoff operation answered without a
    /// composed runtime fails closed as unavailable rather than as a Store-only
    /// success.
    pub async fn execute_user_automation_operation<R>(
        &self,
        request: UserAutomationServiceRequest,
        runtime: Option<&R>,
    ) -> Result<UserAutomationOperatorTransition, String>
    where
        R: UserAutomationRuntimePort + UserAutomationWakePort + ?Sized,
    {
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(
            self.store.as_ref(),
        ));
        let sealed = self.seal_user_automation_operation(&store, request).await?;
        let response = Box::pin(UserAutomationService::new(&store).dispatch(sealed.clone()))
            .await
            .map_err(|error| error.to_string())?;
        if response.identity != sealed.identity
            || response.state_fence != sealed.context.state_fence
        {
            return Err(
                "canonical UserAutomation response does not bind to the sealed operation"
                    .to_owned(),
            );
        }
        let configuration = UserAutomationConfigurationPhase::from_store_outcome(response.outcome);
        let (wake, execution) = self
            .user_automation_runtime_handoff(&sealed, &configuration, runtime)
            .await?;
        let horizon = self
            .publish_schedule_horizon(&sealed, &configuration, runtime)
            .await?;
        let transition = UserAutomationOperatorTransition::with_horizon(
            sealed.identity.clone(),
            sealed.context.state_fence.clone(),
            configuration,
            wake,
            execution,
            horizon,
        );
        transition.validate()?;
        Ok(transition)
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
        let store = CanonicalUserAutomationStore::new(BorrowedCanonicalStoreClient::new(
            self.store.as_ref(),
        ));
        // The `Status` join carries the whole read projection and its response
        // across the await, so it is pinned rather than held inline; the pinned
        // form is the same production Store path the operator route uses.
        Box::pin(UserAutomationService::new(&store).owner_execution_view(request, automation_id))
            .await
            .map_err(|error| error.to_string())
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
    async fn user_automation_runtime_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
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
                self.remove_handoff(sealed, configuration, runtime).await
            }
            UserAutomationOperation::Pause {
                automation_id,
                automation_revision,
            } => retirement_handoff(
                configuration,
                Some(automation_id),
                automation_revision,
                UserAutomationConfigurationState::Paused,
            ),
            UserAutomationOperation::Edit {
                previous_revision, ..
            } => Ok((
                superseded_wake_phase(&previous_revision.revision)?,
                not_applicable_execution(),
            )),
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
    async fn remove_handoff<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
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
        // normalized denominator is the exact set the wake walk below asks about.
        let committed_occurrences = revision
            .compile_occurrence_identities()
            .map_err(|error| error.to_string())?
            .len();
        let execution = not_applicable_execution();
        let Some(runtime) = runtime else {
            return Ok((
                UserAutomationWakePhase::Unavailable {
                    reason: unproven_wake_channel_reason(),
                },
                execution,
            ));
        };
        let targets = match read_retirement_wake_targets(
            &revision,
            &sealed.context,
            &sealed.identity,
            runtime,
        )
        .await
        {
            Ok(UserAutomationWakeTargetEnumeration::Proven { targets }) => targets,
            Ok(UserAutomationWakeTargetEnumeration::Unproven { reason }) => {
                return Ok(unresolved_retirement_phases(reason, execution));
            }
            // A committed revision whose own occurrence denominator does not
            // compile is a canonical identity defect, not an absent owner.
            Err(error) => return Err(error.to_string()),
        };
        if targets.is_empty() {
            // The owner read its own journal for every committed occurrence and
            // definitively retains no unadmitted wake for any of them. That is a
            // complete negative answer, so the retirement is reported as resolved
            // and no cancellation is requested: the concrete Host owner refuses
            // an empty target list by design, and asking it to cancel nothing
            // would be a request whose only possible answer is a refusal.
            return Ok((
                UserAutomationWakePhase::NotApplicable {
                    reason: format!(
                        "the wake owner read its own journal for all {committed_occurrences} \
                         committed occurrence identities of retired revision {} and definitively \
                         retains no unadmitted pending wake for any of them, so there is nothing \
                         to cancel",
                        revision.revision
                    ),
                },
                execution,
            ));
        }
        // The retirement transition is replayed under the same admitted identity
        // this route already committed, so the owner view, the retirement and
        // the cancellation observe one canonical operation rather than two.
        let removal = match Box::pin(
            UserAutomationService::new(&CanonicalUserAutomationStore::new(
                BorrowedCanonicalStoreClient::new(self.store.as_ref()),
            ))
            .remove_and_cancel_with_targets(sealed.clone(), targets, runtime),
        )
        .await
        {
            Ok(removal) => removal,
            // The retirement is committed and durable, so a refusal at this leg
            // is an unresolved handoff of a committed fact. It is reported as
            // such, with the exact refusal, instead of being reported as a
            // failed retirement or as a cancellation that did not happen.
            Err(error) => {
                return Ok(unresolved_retirement_phases(
                    format!(
                        "revision {automation_revision} of {automation_id} is retired, but its \
                         unadmitted wakes were not cancelled from the complete owner view: \
                         {error}; the not-yet-admitted wakes and the exact unresolved \
                         reconciliation references of this revision are preserved and stay open"
                    ),
                    execution,
                ));
            }
        };
        // Reached only with a NON-EMPTY proven target set. An owner that
        // cancelled none of the targets it was handed contradicted itself, so
        // that is an unresolved handoff rather than a proven absence.
        if removal.cancelled_wake_ids.is_empty() {
            return Ok(unresolved_retirement_phases(
                format!(
                    "the wake owner returned no cancelled identity for the owner-issued targets of \
                     retired revision {automation_revision} of {automation_id}; an empty answer is \
                     not proof that no unadmitted wake existed, so the wake handoff stays unknown"
                ),
                execution,
            ));
        }
        Ok((
            UserAutomationWakePhase::Cancelled {
                cancelled_wake_ids: removal.cancelled_wake_ids,
            },
            execution,
        ))
    }

    /// Compiles and publishes the bounded recurring wake horizon this committed
    /// operation owns, if any.
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
    async fn publish_schedule_horizon<R>(
        &self,
        sealed: &UserAutomationServiceRequest,
        configuration: &UserAutomationConfigurationPhase,
        runtime: Option<&R>,
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
        let requested_occurrence_ids = publication.requested_occurrence_ids();
        let retry_handle = publication
            .retry_handle(&requested_occurrence_ids)
            .map_err(|error| error.to_string())?;
        let Some(runtime) = runtime else {
            return Ok(Some(unreached_horizon_phase(
                &publication,
                &requested_occurrence_ids,
                retry_handle,
                UnreachedHorizonKind::Unavailable,
                UNREACHED_WAKE_OWNER_REASON,
            )));
        };
        match UserAutomationWakePort::publish_wake_horizon(runtime, publication.clone()).await {
            Ok(acknowledgement) => {
                acknowledgement
                    .validate_for(&publication)
                    .map_err(|error| error.to_string())?;
                let publication_operation_id =
                    Box::new(acknowledgement.publication_operation_id.clone());
                let outcome = if acknowledgement.acknowledged_all() {
                    UserAutomationHorizonOutcome::Published {
                        publication_operation_id,
                    }
                } else {
                    UserAutomationHorizonOutcome::Partial {
                        publication_operation_id,
                        reason: format!(
                            "the schedule owner acknowledged {} of the {} requested occurrences of \
                             revision {}; the exact remaining set is retained and must be \
                             replayed under its handle before the horizon counts as published",
                            acknowledgement.acknowledged_occurrence_ids.len(),
                            requested_occurrence_ids.len(),
                            publication.automation_revision
                        ),
                    }
                };
                Ok(Some(UserAutomationHorizonPhase {
                    trigger: publication.trigger,
                    automation_id: publication.automation_id.clone(),
                    automation_revision: publication.automation_revision.clone(),
                    revision_digest: publication.revision_digest.clone(),
                    requested_occurrence_ids,
                    remaining_occurrence_ids: acknowledgement.remaining_occurrence_ids,
                    retry_handle: acknowledgement.retry_handle,
                    outcome,
                }))
            }
            Err(UserAutomationRuntimeError::Unavailable(reason)) => {
                Ok(Some(unreached_horizon_phase(
                    &publication,
                    &requested_occurrence_ids,
                    retry_handle,
                    UnreachedHorizonKind::Unavailable,
                    &reason,
                )))
            }
            Err(UserAutomationRuntimeError::UnknownOutcome(reason)) => {
                Ok(Some(unreached_horizon_phase(
                    &publication,
                    &requested_occurrence_ids,
                    retry_handle,
                    UnreachedHorizonKind::UnknownOutcome,
                    &reason,
                )))
            }
            Err(error) => Err(error.to_string()),
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
        let Some(UserAutomationMutationResult::RunNow { invocation, .. }) =
            configuration.mutation_result()
        else {
            return Err("run-now did not return a run-now projection".to_owned());
        };
        let occurrence_id = invocation
            .occurrence_identity()
            .map_err(|error| error.to_string())?;
        // Exact committed/replayed invocation readback. The persisted document
        // is compared with the answer of this very identity, so a replayed Store
        // mutation resumes the same occurrence and can never mint a second
        // manual nonce or a second occurrence.
        let persisted = self
            .read_user_automation_invocation(
                &sealed.context.state_fence,
                automation_id,
                &occurrence_id,
            )
            .await?;
        if persisted != *invocation {
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
        // The current configuration state is the owner's admission fact. A
        // paused, retired or blocked owner admits no occurrence, so no wake or
        // Durable Job owner is asked. The committed configuration phase stays
        // visible: an unadmitted occurrence is reported as such, never as a
        // failed commit.
        if owner.current_configuration_state != UserAutomationConfigurationState::Active {
            return Ok((
                UserAutomationWakePhase::NotApplicable {
                    reason: unadmitted_wake_reason(
                        automation_id,
                        automation_revision,
                        owner.current_configuration_state,
                    ),
                },
                UserAutomationExecutionPhase::Unavailable {
                    reason: unadmitted_execution_reason(
                        &occurrence_id,
                        owner.current_configuration_state,
                    ),
                },
            ));
        }
        let Some(runtime) = runtime else {
            return Ok((
                UserAutomationWakePhase::Unavailable {
                    reason: unproven_wake_channel_reason(),
                },
                UserAutomationExecutionPhase::Unavailable {
                    reason: unproven_execution_channel_reason(),
                },
            ));
        };
        let wake_request = run_now_wake_read_request(
            sealed.context.clone(),
            sealed.authenticated_principal.clone(),
            sealed.identity.clone(),
            invocation.clone(),
        );
        let wake = match UserAutomationWakePort::read_pending_wake(runtime, wake_request).await {
            Ok(readback) => UserAutomationWakePhase::Published { readback },
            Err(error) => UserAutomationWakePhase::UnknownOutcome {
                reason: error.to_string(),
            },
        };
        let execution = UserAutomationExecutionPhase::Unavailable {
            reason: unproven_durable_job_material_reason(&occurrence_id, automation_revision),
        };
        Ok((wake, execution))
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
    /// ## Typed answer (issue #2764 item 6)
    ///
    /// The route answers `Result<DurableJobResponse, DreamerJobFailure>`,
    /// never a bare `String`. No recovered outcome is rendered inside this
    /// leg: `Reconciled`, `AlreadyDispositioned`,
    /// `ReconciledWithRefreshLimitation` and `UnknownCommitOpen` cross the
    /// route as the four [`DreamerCommitUncertain`] variants, a recovery
    /// refusal crosses as its own [`CommitRecoveryError`] variant (so
    /// `OrderingScopeUnresolved` and `ScopePaused` stay distinguishable), and
    /// the single rendering happens at the transport edge. A `WriteReceipt`
    /// proves a mutation disposition, never the missing
    /// `DurableJobResponse`, so the recovered variants still carry the
    /// remaining ledger-read obligation in their own text.
    pub async fn dreamer_job(
        &self,
        context: &RequestMeta,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, DreamerJobFailure> {
        let _flight = self.flight.enter().map_err(DreamerJobFailure::Refused)?;
        if self.is_fenced() {
            return Err(DreamerJobFailure::Refused(
                "canonical-store gateway is fenced for rebind".to_owned(),
            ));
        }
        context
            .validate()
            .map_err(|error| DreamerJobFailure::Refused(error.to_string()))?;
        request
            .validate()
            .map_err(|error| DreamerJobFailure::Refused(error.to_string()))?;
        if !request.role.permits(request.operation.kind()) {
            return Err(DreamerJobFailure::Refused(
                "dreamer job caller role does not permit the operation".to_owned(),
            ));
        }
        self.validate_active_route(&context.state_fence)
            .map_err(DreamerJobFailure::Refused)?;
        if request.request_identity.operation.state_fence != context.state_fence {
            return Err(DreamerJobFailure::Refused(
                "dreamer job request fence does not match request metadata".to_owned(),
            ));
        }
        // I14.21 (#1690) write-attempt identity: the admitted Dreamer mutation
        // identity, taken from the stable operation binding only. Fresh
        // transport correlation never enters it, so a retry under the same
        // identity always reuses this record.
        //
        // The canonical request hash is not the presented spelling: it is
        // recomputed through the operation's owning contract first
        // (`dreamer_canonical_request_hash`). This is the clause that makes
        // the retained-hash comparison below carry any scope/owner or
        // contract-version weight at all, so it runs while the identity is
        // being built rather than being inherited from the request.
        let ordering_scopes = dreamer_ordering_scopes(&request);
        let identity = OperationIdentity {
            operation_id: request.request_identity.operation.operation_id.clone(),
            idempotency_key: request.request_identity.operation.idempotency_key.clone(),
            canonical_request_hash: dreamer_canonical_request_hash(&request)
                .map_err(DreamerJobFailure::Recovery)?,
        };
        let effect = dreamer_operation_effect(&request.operation);

        // Durable recovery state must be available for mutating work even
        // when the local scope vector is empty (#2763). A permitted read and
        // the exact receipt lookup stay available: I14.24 keeps read-only
        // inspection and independent noncanonical work alive.
        if effect == DreamerOperationEffect::Mutation
            && let Some(limitation) = self.pause_observation_limitation()
        {
            return Err(DreamerJobFailure::Recovery(limitation));
        }

        // Retained state is classified before new-send admission (#2764).
        // An unreadable record is not absent: `classify_retained_commit`
        // returns the typed ORS failure instead. It also compares the
        // presented complete Ordering Scope set against the retained one, so
        // a resubmission under one key with a different scope set is a
        // conflict before anything is adopted.
        let retained =
            classify_retained_commit(self.commit_ors.as_deref(), &identity, &ordering_scopes)
                .map_err(DreamerJobFailure::Recovery)?;
        let mut retried_under_retained_record = false;
        if let Some(record) = match &retained {
            RetainedCommitState::Absent => None,
            RetainedCommitState::Open { record } | RetainedCommitState::Terminal { record } => {
                Some(record)
            }
        } {
            match self
                .reconcile_retained_dreamer_operation(&identity, &ordering_scopes, record)
                .await
                .map_err(DreamerJobFailure::Recovery)?
            {
                DreamerRetainedOutcome::Settled(answer) => {
                    return Err(DreamerJobFailure::Recovered(answer));
                }
                DreamerRetainedOutcome::SameIdentityRetryPermitted => {
                    // A proven noncommit whose resubmission policy allows the
                    // same identity again, observed while the record is still
                    // open. The record therefore keeps owning this retry: it
                    // is not resolved first, so the terminal-state invariant
                    // is not bypassed. Falling through re-enters current
                    // normal admission and the other-key pause check below
                    // before exactly one bounded same-identity send, keeping
                    // the original operation, content, authorized effect and
                    // retry budget. This leg issued zero mutation sends: the
                    // receipt query above is a pure read and is not counted
                    // as another attempt.
                    retried_under_retained_record = true;
                }
            }
        }

        let lease = self.admit_dreamer_mutation(context, &identity, &ordering_scopes, effect)?;
        let result = match self.store.dreamer_job_recovery(context, request).await {
            Ok(response) => {
                // A successful same-identity retry settles nothing on its own:
                // the ledger answer is not receipt evidence, so the retained
                // record is resolved by reading its exact mutation receipt.
                // A ledger `Status` alone could never settle it.
                if retried_under_retained_record {
                    self.settle_after_same_identity_retry(&identity, &ordering_scopes)
                        .await
                        .map_err(DreamerJobFailure::Recovery)?;
                }
                Ok(response)
            }
            Err(DreamerCommitEvidence::Refused(error)) => {
                Err(DreamerJobFailure::Refused(error.to_string()))
            }
            Err(DreamerCommitEvidence::Reconciled(receipt)) => Err(DreamerJobFailure::Recovered(
                self.reconcile_dreamer_commit(&identity, &ordering_scopes, &receipt)
                    .map_err(DreamerJobFailure::Recovery)?,
            )),
            Err(DreamerCommitEvidence::Unknown) => Err(DreamerJobFailure::Recovered(
                self.preserve_dreamer_operation(&identity, &ordering_scopes)
                    .map_err(DreamerJobFailure::Recovery)?,
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

    /// Acquires the normal admission lease and runs the checked pause gate
    /// for one admitted Dreamer operation (issue #2763).
    ///
    /// The lease rides the typed `NORMAL_WORKLOAD` normal partition (Slices
    /// A+B, #65); protected work stays on `acquire_protected_control`. See
    /// `lifecycle.rs:acquire_admission`. The read-first recovery branch does
    /// NOT ride this normal lease, so exhausted normal capacity cannot make an
    /// admitted operation's own recovery unreachable.
    ///
    /// The pause gate observes the durable owner here, after admission and
    /// immediately before the send, so a pause published after this point
    /// cannot be missed by a clearance computed at construction, and an
    /// unreadable ledger closes admission rather than permitting it.
    /// `Self::paused_ordering_scopes` is the visible Problem State; this reads
    /// the same checked observation as the admission input, not the display
    /// projection. A permitted observation (`Status`) takes no lease and
    /// reaches no pause gate, so a read is never blocked by a pause.
    ///
    /// The service mutex is released before the gate runs, so neither it nor
    /// the flight state is held across an await or a store call.
    fn admit_dreamer_mutation(
        &self,
        context: &RequestMeta,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
        effect: DreamerOperationEffect,
    ) -> Result<AdmissionLease, DreamerJobFailure> {
        let lease = {
            let service = self.service.lock().map_err(|_| {
                DreamerJobFailure::Refused("Kernel service lock poisoned".to_owned())
            })?;
            if service.generation_fenced() {
                return Err(DreamerJobFailure::Refused(
                    "Kernel generation is fenced".to_owned(),
                ));
            }
            let lease = service
                .acquire_admission()
                .map_err(|error| DreamerJobFailure::Refused(error.to_string()))?;
            if lease.authority_epoch() != context.state_fence.authority_epoch {
                return Err(DreamerJobFailure::Refused(
                    "dreamer job route authority epoch is stale".to_owned(),
                ));
            }
            lease
        };
        if self.is_fenced() {
            return Err(DreamerJobFailure::Refused(
                "canonical-store gateway is fenced for rebind".to_owned(),
            ));
        }
        if effect == DreamerOperationEffect::Mutation {
            let observed = self.paused_scopes.observe(self.commit_ors.as_deref());
            if let Some(error) = observed.unavailable_error() {
                return Err(DreamerJobFailure::Recovery(error));
            }
            if let Some(refusal) =
                dreamer_pause_refusal(&observed, identity, ordering_scopes, effect)
            {
                return Err(DreamerJobFailure::Recovery(refusal));
            }
        }
        Ok(lease)
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
    /// resubmission policy, not an enum name:
    ///
    /// * a committed receipt persists or reuses K's terminal disposition,
    ///   retains its digest, releases only the scopes no other open record
    ///   covers, and returns committed-recovery evidence with the remaining
    ///   ledger-read obligation — no resend;
    /// * a proven noncommit whose `Resubmission` still allows the identical
    ///   identity, observed while K is open, permits one bounded
    ///   same-identity retry through the caller's normal path;
    /// * a dead-lettered or new-identity-required disposition retains that
    ///   exact terminal outcome and directive and allocates nothing here;
    /// * a missing, unavailable or inconclusive receipt keeps K and its
    ///   pauses unresolved: no resend, no automatic rollback, and no false
    ///   no-effect result;
    /// * an identity, content, or terminal-evidence conflict rejects the
    ///   adoption, preserves the old history and exposes the exact conflict.
    async fn reconcile_retained_dreamer_operation(
        &self,
        identity: &OperationIdentity,
        ordering_scopes: &[String],
        record: &UnknownCommitRecord,
    ) -> Result<DreamerRetainedOutcome, CommitRecoveryError> {
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
        if record.outcome.is_some() {
            // An already-terminal record keeps its recorded outcome: the
            // later evidence is compared against it, and a contradiction is a
            // conflict rather than a replacement. This is what makes replay
            // after a restart or a lost response return the same outcome
            // without a second mutation.
            verify_terminal_evidence(record, outcome, &evidence_receipt_digest)?;
            let (recorded_outcome, recorded_digest) = retained_terminal_evidence(key, record)?;
            let release = self.release_dreamer_scopes(record);
            return Ok(DreamerRetainedOutcome::Settled(match release {
                // The recorded terminal disposition stands; only the release
                // bookkeeping is incomplete, and that limitation is reported
                // instead of being dropped.
                PauseReleaseOutcome::RefreshUnavailable { detail, .. } => {
                    DreamerCommitUncertain::ReconciledWithRefreshLimitation {
                        idempotency_key: key.to_owned(),
                        outcome: recorded_outcome,
                        evidence_receipt_digest: recorded_digest,
                        refresh_limitation: detail,
                    }
                }
                _ => DreamerCommitUncertain::AlreadyDispositioned {
                    idempotency_key: key.to_owned(),
                    outcome: recorded_outcome,
                    evidence_receipt_digest: recorded_digest,
                },
            }));
        }
        // A proven noncommit that the Store's own resubmission policy
        // still allows under this identical identity. The record stays
        // open, so it keeps owning the retry; the caller re-enters normal
        // admission and the other-key pause check for one bounded send.
        // A record that is already terminal cannot legally reopen, so
        // that case never reaches here.
        if matches!(
            classify_commit_receipt(&receipt),
            CommitRecoveryClass::KnownRollback
        ) {
            debug_assert!(record.is_open());
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
    /// This is one of the two opposed-direction string conversions the
    /// `Result<_, String>` boundary used to force, and the typed carrier
    /// removes the need for it: the disposition failure is re-wrapped as
    /// [`CommitRecoveryError::OrsUnavailable`] with the original rendering as
    /// its cause, and a blanket `From` in either direction is deliberately not
    /// introduced.
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
            // terminal record for a different operation under this key, or one
            // staged under a different complete Ordering Scope set, is a
            // conflict rather than a shortcut to "already dispositioned". The
            // scope comparison is what stops the restage below from ever
            // being asked to restate a retained record's historical scope set
            // with this request's scopes.
            verify_retained_binding(&record, identity, ordering_scopes)?;
            if record.outcome.is_some() {
                let outcome = match classify_commit_receipt(receipt) {
                    CommitRecoveryClass::Committed => UnknownCommitOutcome::Committed,
                    CommitRecoveryClass::KnownRollback => UnknownCommitOutcome::RolledBack,
                    CommitRecoveryClass::NeedsNewIdentity(outcome) => outcome,
                };
                let evidence_receipt_digest = receipt_evidence_digest(receipt);
                // A wrong receipt or a changed terminal digest cannot resolve
                // the record: it is rejected and the recorded history stands.
                verify_terminal_evidence(&record, outcome, &evidence_receipt_digest)?;
                return match self.release_dreamer_scopes(&record) {
                    // The terminal disposition stands and the recorded
                    // outcome is preserved; only the pause release is
                    // incomplete, and that is stated rather than hidden.
                    PauseReleaseOutcome::RefreshUnavailable { detail, .. } => {
                        let (recorded_outcome, recorded_digest) =
                            retained_terminal_evidence(key, &record)?;
                        Ok(DreamerCommitUncertain::ReconciledWithRefreshLimitation {
                            idempotency_key: key.to_owned(),
                            outcome: recorded_outcome,
                            evidence_receipt_digest: recorded_digest,
                            refresh_limitation: detail,
                        })
                    }
                    _ => dreamer_dispositioned(key, &record),
                };
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
            // The complete Ordering Scope set is compared here too, so a
            // preserved open record's historical scope set is never restated
            // from a request that addresses a different one.
            verify_retained_binding(&record, identity, ordering_scopes)?;
            if record.outcome.is_some() {
                // A resolved record never reopens: the earlier evidence-backed
                // disposition stands, so this leg neither restages the record nor
                // pauses an Ordering Scope for a key that is already closed.
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
    pub async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        self.store
            .validation_snapshot()
            .await
            .map_err(|error| error.to_string())
    }

    fn validate_active_route(&self, state_fence: &StateFence) -> Result<(), String> {
        validate_route(&self.service, &self.route, state_fence)
    }

    /// Reads and validates the retained canonical Store health observation.
    pub async fn health(&self) -> Result<StoreHealth, String> {
        let _flight = self.flight.enter()?;
        let health = self
            .store
            .health()
            .await
            .map_err(|error| error.to_string())?;
        health.validate().map_err(|error| error.to_string())?;
        Ok(health)
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
        | UserAutomationOperation::InspectLastFailure { .. } => None,
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
fn retirement_handoff(
    configuration: &UserAutomationConfigurationPhase,
    automation_id: Option<&str>,
    automation_revision: &str,
    expected_state: UserAutomationConfigurationState,
) -> Result<(UserAutomationWakePhase, UserAutomationExecutionPhase), String> {
    let revision = committed_retirement_revision(
        configuration,
        automation_id,
        automation_revision,
        expected_state,
    )?;
    let committed_occurrences = revision
        .compile_occurrence_identities()
        .map_err(|error| error.to_string())?
        .len();
    Ok((
        unproven_wake_target_phase(
            &revision.automation_id,
            &revision.revision,
            committed_occurrences,
        ),
        not_applicable_execution(),
    ))
}

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

/// Wake phase for a superseding `Edit`, whose affected revision is the retired
/// predecessor rather than the committed document.
///
/// The superseded document is not the answer of this identity, so its committed
/// occurrence denominator cannot be counted here. The phase is therefore
/// unresolved by construction instead of asserting that no wake exists.
fn superseded_wake_phase(previous_revision: &str) -> Result<UserAutomationWakePhase, String> {
    if previous_revision.trim().is_empty() {
        return Err("superseding edit did not name the affected revision".to_owned());
    }
    Ok(UserAutomationWakePhase::UnknownOutcome {
        reason: format!(
            "superseded revision {previous_revision} is not the committed document of this identity, \
             so its committed occurrence denominator is unknown; its not-yet-admitted wakes cannot \
             be cancelled from a bounded subset and stay unknown until the owner enumerates them"
        ),
    })
}

/// Wake phase for a retirement whose exact owner-issued target list could not be
/// proven complete.
///
/// The canonical revision exposes its committed calendar occurrence identities,
/// but the authenticated wake owner publishes an exact per-occurrence readback
/// only for a Human `RunNow` occurrence. A retirement therefore cannot present
/// a non-empty, complete, exact cancellation target list here, and an empty list
/// is not proof that no unadmitted wake exists: the phase stays unknown.
fn unproven_wake_target_phase(
    automation_id: &str,
    automation_revision: &str,
    committed_occurrences: usize,
) -> UserAutomationWakePhase {
    UserAutomationWakePhase::UnknownOutcome {
        reason: format!(
            "retired revision {automation_revision} of {automation_id} exposes {committed_occurrences} \
             committed calendar occurrence identities, but the authenticated wake owner publishes an \
             exact per-occurrence target only for a Human run-now occurrence, so no complete exact \
             unadmitted target list is owner-proven; no cancellation is issued and the already \
             admitted jobs, immutable history and unresolved obligations are preserved"
        ),
    }
}

/// Wake phase reason used when no authenticated runtime channel was composed.
fn unproven_wake_channel_reason() -> String {
    "no authenticated UserAutomation runtime channel was composed for this transition, so the \
     committed occurrence was not handed to the wake owner"
        .to_owned()
}

/// Wake phase reason for a committed occurrence the current owner does not admit.
fn unadmitted_wake_reason(
    automation_id: &str,
    automation_revision: &str,
    state: UserAutomationConfigurationState,
) -> String {
    format!(
        "the current owner configuration state of {automation_id}/{automation_revision} is {state:?}, \
         which admits no wake, so the committed occurrence was not handed to the wake owner"
    )
}

/// Execution phase reason for a committed occurrence the current owner does not
/// admit.
fn unadmitted_execution_reason(
    occurrence_id: &str,
    state: UserAutomationConfigurationState,
) -> String {
    format!(
        "the current owner configuration state for occurrence {occurrence_id} is {state:?}, which \
         admits no execution, so the Durable Job owner was never asked and the occurrence stays \
         unadmitted"
    )
}

/// Execution phase reason used when no authenticated runtime channel was composed.
fn unproven_execution_channel_reason() -> String {
    "no authenticated UserAutomation runtime channel was composed for this transition, so the \
     committed occurrence was not handed to the Durable Job owner"
        .to_owned()
}

/// Execution phase reason for a committed occurrence with no owner-issued
/// Durable Job submission material.
///
/// The existing Durable Job owner admits a complete submission. That submission
/// carries the qualified artifact content reference and the job admission
/// receipt; neither is derivable from the canonical Store receipt, and deriving
/// either would fabricate content evidence and authority. The Durable Job owner
/// is therefore never asked, so the phase is `Unavailable` rather than a lost
/// answer: nothing was sent, no job was minted, and the occurrence stays
/// unadmitted for a later owner-issued submission to admit.
fn unproven_durable_job_material_reason(occurrence_id: &str, automation_revision: &str) -> String {
    format!(
        "occurrence {occurrence_id} of revision {automation_revision} is committed and its wake is \
         owner-read, but the Durable Job owner was never asked: no owner-issued submission material \
         exists for it, because the qualified artifact content reference and the job admission \
         receipt are issued by that owner and are not derivable from the canonical Store commit"
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
/// replacement Kernel explicitly supports its recorded contract digest and
/// operation manifest.
fn admit_prepared_transition(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), String> {
    context.validate().map_err(|error| error.to_string())?;
    transition.validate().map_err(|error| error.to_string())?;
    if transition.state_fence != context.state_fence {
        return Err("transition state fence does not match request metadata".to_owned());
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
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(|error| error.to_string())?;
    let entries = generated_operation_manifests().map_err(|error| error.to_string())?;
    transition
        .validate_against_catalogue(&entries)
        .map_err(|error| {
            format!(
                "unsupported prepared transition; preserve as recovery, do not reinterpret: {error}"
            )
        })?;
    Ok(())
}

/// Reserved-write admission gates shared by the gateway entry point.
///
/// Mirrors the `apply` gates (context/transition validation, active daemon
/// caller, fence equality): the caller rule lives at this boundary while the
/// binding rules live in the reservation module. The canonical request-hash
/// recompute runs in the entry body before reservation, and manifest support
/// is enforced at store execution by the bridge catalogue gate, so a staged
/// plan that the replacement store no longer supports stays staged as
/// visible recovery work instead of being reinterpreted here. Staging step so
/// the entry point stays a composition of audited gates.
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
    let _flight = flight.enter()?;
    if flight.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    request.validate().map_err(|error| error.to_string())?;
    validate_route(service, route, &request.state_fence)?;
    let response = store
        .execute_named(request.clone())
        .await
        .map_err(|error| error.to_string())?;
    if flight.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    validate_route(service, route, &request.state_fence)?;
    response.validate().map_err(|error| error.to_string())?;
    if response.operation != request.operation {
        return Err("Store named-read operation does not match request".to_owned());
    }
    if response.state_fence != request.state_fence {
        return Err("Store named-read fence does not match request".to_owned());
    }
    Ok(response)
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
            Ok(()) => unreachable!("unsupported manifest must fail"),
        };
        assert!(
            error.contains("recovery"),
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
