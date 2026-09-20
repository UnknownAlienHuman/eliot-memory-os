//! Kernel-owned, store-neutral S-03 EBP client.
//!
//! The client owns only authenticated EBP framing and closed store-api
//! operations.  It never opens a provider SDK, constructs a query, mints
//! authority, or decides completion.  An uncertain apply is reconciled only
//! by the exact operation identity carried by the prepared transition.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, StateFence};
use eliot_ipc::{DeliveryOutcome, TransportError, TransportLimits};
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse};
use eliot_protocol::{ClientHello, Frame, ProtocolRange, ProtocolVersion, ServerHello};
use eliot_runtime_contracts::{ModuleContract, ModuleGeneration, ModuleGenerationState};
use eliot_store_api::{
    CAPABILITIES, CanonicalRequestView, CanonicalStoreClient, CanonicalValidationSnapshot, EFFECTS,
    NamedReadOperation, NamedReadRequest, NamedReadResponse, OperationId, OrderingHead,
    OrderingHeadExpectation, OrderingScopeId, PreparedTransition, ReadConsistency,
    RecoveryRecordKey, RequestMeta, ReservedWriteRequest, RevisionHead, RevisionHeadExpectation,
    RevisionKey, ScopeId, ScopeRevisionView, StoreError, StoreGenesisRequest, StoreHealth,
    StoreRecoveryRequest, StoreRecoverySnapshot, StoreRequest, StoreResponse, StoreWireError,
    WriteReceipt, dreamer_job_capability, map_durable_error, validate_genesis_receipt_envelope,
    verify_canonical_request_hash,
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{HostStoreBootstrapRequirement, STORE_MODULE_IDENTITY};

#[path = "store_exchange.rs"]
mod store_exchange;

use store_exchange::RequestFailure;

/// Transport boundary used by the neutral EBP store client.
///
/// Implementations must establish the platform authentication proof before
/// returning `Ok(())`; a pipe name or process id alone is insufficient.
#[allow(async_fn_in_trait)]
pub trait EbpStoreTransport: Send {
    /// Confirms that the lower transport has authenticated the peer.
    fn ensure_authenticated(
        &self,
        requirement: &HostStoreBootstrapRequirement,
    ) -> Result<(), StoreClientError>;

    /// Sends one bounded EBP frame.
    async fn send_frame(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, StoreClientError>;

    /// Receives one bounded EBP frame.
    async fn receive_frame(&mut self, limits: TransportLimits) -> Result<Frame, StoreClientError>;
}

/// Client-side failures before a canonical store receipt exists.
#[derive(Debug, Error)]
pub enum StoreClientError {
    /// Transport or peer authentication failed.
    #[error("store transport: {0}")]
    Transport(String),
    /// The store handshake or response violated the closed contract.
    #[error("store EBP contract: {0}")]
    Contract(String),
    /// The store returned an application-level failure.
    #[error("store contract: {0}")]
    Store(#[from] StoreError),
}

impl From<TransportError> for StoreClientError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<StoreWireError> for StoreClientError {
    fn from(error: StoreWireError) -> Self {
        Self::Contract(error.to_string())
    }
}

/// Production fault-injection hook for the S-CONC-ACCEPT crash and
/// response-loss phases (issue #2030; S-CONC-ACCEPT #994 cases 11-12).
///
/// The hook is one-shot and explicit: the 994 harness arms exactly one fault
/// before one admitted write, and the client consumes it on that write.
/// Disarmed production traffic never observes it.
///
/// Contract:
/// - [`StoreClientFault::PreCommitCrash`] (994/11) fires before any provider
///   effect: the write returns [`StoreError::MissingReceiptEnvelope`]
///   (unknown — never success, never `Unavailable`, which would invite a
///   same-identity retry) with zero transport sends, so the caller
///   reconciles the exact admitted identity and proves absence before any
///   resubmission.
/// - [`StoreClientFault::PostCommitResponseLoss`] (994/12) fires after the
///   provider durably committed: the observed receipt is discarded and the
///   write returns [`StoreError::MissingReceiptEnvelope`] instead of
///   success, so the caller reconciles the exact admitted identity and
///   recovers the original receipt without a replay under any identity.
/// - Validation failures still precede the hook: an inadmissible request
///   fails with its typed error and leaves the armed fault in place.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StoreClientFault {
    /// No fault armed: production behavior.
    #[default]
    None,
    /// Drop the response after a durable provider commit (994/12).
    PostCommitResponseLoss,
    /// Crash precisely before any durable commit (994/11).
    PreCommitCrash,
}

impl StoreClientFault {
    const NONE: u8 = 0;
    const POST_COMMIT_RESPONSE_LOSS: u8 = 1;
    const PRE_COMMIT_CRASH: u8 = 2;

    const fn encode(self) -> u8 {
        match self {
            Self::None => Self::NONE,
            Self::PostCommitResponseLoss => Self::POST_COMMIT_RESPONSE_LOSS,
            Self::PreCommitCrash => Self::PRE_COMMIT_CRASH,
        }
    }

    const fn decode(value: u8) -> Self {
        match value {
            Self::POST_COMMIT_RESPONSE_LOSS => Self::PostCommitResponseLoss,
            Self::PRE_COMMIT_CRASH => Self::PreCommitCrash,
            _ => Self::None,
        }
    }
}

/// Authenticated neutral S-03 EBP client implementing the canonical store API.
pub struct EbpCanonicalStoreClient<T> {
    transport: Arc<Mutex<T>>,
    requirement: HostStoreBootstrapRequirement,
    protocol_version: ProtocolVersion,
    limits: TransportLimits,
    request_counter: AtomicU64,
    /// One-shot production fault hook (issue #2030). `&self` methods arm,
    /// observe, and consume it through this atomic; the transport path never
    /// invents faults on its own.
    fault: AtomicU8,
}

impl<T> std::fmt::Debug for EbpCanonicalStoreClient<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EbpCanonicalStoreClient")
            .field("connection_id", &self.requirement.connection_id)
            .field("store_generation", &self.requirement.store_generation)
            .field("route_identity", &self.requirement.route_identity)
            .field("protocol_version", &self.protocol_version)
            .finish_non_exhaustive()
    }
}

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
    /// Completes the authenticated EBP handshake and schema-readiness check.
    pub async fn connect(
        mut transport: T,
        requirement: HostStoreBootstrapRequirement,
    ) -> Result<Self, StoreClientError> {
        requirement
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        transport.ensure_authenticated(&requirement)?;
        let hello = client_hello(&requirement)?;
        let limits = TransportLimits::default();
        let hello_frame =
            eliot_ipc::client_hello_frame(requirement.connection_id.as_str(), &hello)?;
        let outcome = transport.send_frame(&hello_frame, limits).await?;
        if outcome != DeliveryOutcome::Delivered {
            return Err(StoreClientError::Transport(
                "store handshake crossed an unknown delivery boundary".to_owned(),
            ));
        }
        let response = transport.receive_frame(limits).await?;
        let server = decode_server_hello(&response, &requirement)?;
        let client = Self {
            transport: Arc::new(Mutex::new(transport)),
            requirement,
            protocol_version: server.selected_protocol,
            limits,
            request_counter: AtomicU64::new(1),
            fault: AtomicU8::new(StoreClientFault::NONE),
        };
        client.verify_readiness().await?;
        Ok(client)
    }

    /// Arms the one-shot production fault hook (issue #2030).
    ///
    /// The next admitted [`Self::apply_prepared`] or
    /// [`CanonicalStoreClient::apply_reserved_write`] consumes it;
    /// [`StoreClientFault::None`] disarms. Validation failures leave the
    /// armed fault in place for the next admissible attempt.
    pub fn arm_fault(&self, fault: StoreClientFault) {
        self.fault.store(fault.encode(), Ordering::SeqCst);
    }

    /// Currently armed production fault, if any. Observation only: reading
    /// never consumes the hook.
    #[must_use]
    pub fn armed_fault(&self) -> StoreClientFault {
        StoreClientFault::decode(self.fault.load(Ordering::SeqCst))
    }

    /// Consumes the armed production fault, returning the disarmed state.
    fn take_fault(&self) -> StoreClientFault {
        StoreClientFault::decode(self.fault.swap(StoreClientFault::NONE, Ordering::SeqCst))
    }

    /// Returns the exact Host-approved bootstrap binding.
    #[must_use]
    pub const fn requirement(&self) -> &HostStoreBootstrapRequirement {
        &self.requirement
    }

    async fn verify_readiness(&self) -> Result<(), StoreClientError> {
        let response = self
            .execute_raw(StoreRequest::Readiness, None, "store-readiness")
            .await
            .map_err(|error| StoreClientError::Store(error.into_store_error()))?;
        let StoreResponse::Readiness { receipt } = response else {
            return Err(StoreClientError::Contract(
                "store readiness response was not Readiness".to_owned(),
            ));
        };
        receipt.validate()?;
        if receipt.status != eliot_store_api::ReadinessStatus::Ready
            || receipt.expected_generation.is_none()
            || receipt.observed_generation.is_none()
        {
            return Err(StoreClientError::Contract(
                "store schema generation is not the Host-approved ready generation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_requirement_fence(&self, observed: &StateFence) -> Result<(), StoreError> {
        if observed != &self.requirement.state_fence
            || observed.resource_generation != self.requirement.store_generation
            || &observed.authority_epoch != self.requirement.authority_epoch()
        {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_recovery_snapshot(
        &self,
        request: &StoreRecoveryRequest,
        snapshot: &StoreRecoverySnapshot,
    ) -> Result<(), StoreError> {
        snapshot.validate()?;
        self.validate_requirement_fence(&request.state_fence)?;
        self.validate_requirement_fence(&snapshot.state_fence)?;

        let requested_keys = request.records.iter().cloned().collect::<BTreeSet<_>>();
        let returned_keys = snapshot
            .owner_records
            .iter()
            .map(eliot_store_api::RecoveryRecord::record_key)
            .collect::<BTreeSet<RecoveryRecordKey>>();
        if snapshot.owner_records.len() != request.records.len() || returned_keys != requested_keys
        {
            return Err(StoreError::IdentityConflict);
        }
        if !request.include_jobs && !snapshot.job_records.is_empty() {
            return Err(StoreError::InvalidField {
                field: "recovery.job_records",
                reason: "jobs were not requested",
            });
        }
        if !request.include_receipts && !snapshot.receipts.is_empty() {
            return Err(StoreError::InvalidField {
                field: "recovery.receipts",
                reason: "receipts were not requested",
            });
        }
        Ok(())
    }

    fn validate_genesis_receipt(
        &self,
        context: &RequestMeta,
        request: &StoreGenesisRequest,
        receipt: &WriteReceipt,
    ) -> Result<(), StoreError> {
        self.validate_requirement_fence(&context.state_fence)?;
        self.validate_requirement_fence(&request.state_fence)?;
        if receipt.operation_id != request.operation_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.canonical_request_hash != request.canonical_request_hash
        {
            return Err(StoreError::IdentityConflict);
        }
        self.validate_requirement_fence(&receipt.state_fence)?;
        validate_genesis_receipt_envelope(context, request, receipt)
    }

    /// Binds one reserved-write answer to the exact admitted reservation
    /// through the shared #991 verifier for the Kernel gateway boundary
    /// (issue #992).
    ///
    /// This is the same production check as the `apply_reserved_write` send
    /// path above, pinned to the Host-approved requirement fence: the gateway
    /// reconciliation path calls it instead of a second implementation, so
    /// there is exactly one receipt-binding authority.
    pub(crate) fn check_reserved_write_receipt(
        &self,
        request: &ReservedWriteRequest,
        receipt: &WriteReceipt,
    ) -> Result<(), StoreError> {
        self.validate_reserved_write_receipt(request, receipt)
    }

    /// Binds one reserved-write answer to the exact admitted reservation
    /// (issue #991).
    ///
    /// Operation, idempotency, canonical hash, transition class, fence, and
    /// the reserved scope/sequence coverage must all match the admitted
    /// request. Anything else observed after the single send is an uncertain
    /// observation for the caller to reconcile — never success and never an
    /// adopted peer identity.
    fn validate_reserved_write_receipt(
        &self,
        request: &ReservedWriteRequest,
        receipt: &WriteReceipt,
    ) -> Result<(), StoreError> {
        receipt.validate()?;
        receipt.require_reconciliation_envelope().map(|_| ())?;
        if receipt.operation_id != request.transition.identity.operation_id
            || receipt.idempotency_key != request.transition.identity.idempotency_key
            || receipt.canonical_request_hash != request.transition.identity.canonical_request_hash
        {
            return Err(StoreError::IdentityConflict);
        }
        if receipt.transition_class != request.transition.transition_class {
            return Err(StoreError::IdentityConflict);
        }
        self.validate_requirement_fence(&receipt.state_fence)?;
        if receipt.ordering_sequences.len() != request.admission.scopes.len() {
            return Err(StoreError::IdentityConflict);
        }
        for scope in &request.admission.scopes {
            let covered = receipt
                .ordering_sequences
                .iter()
                .any(|head| head.scope == scope.scope && head.sequence == scope.reserved_sequence);
            if !covered {
                return Err(StoreError::IdentityConflict);
            }
        }
        Ok(())
    }

    async fn reconcile_genesis(
        &self,
        context: &RequestMeta,
        request: &StoreGenesisRequest,
    ) -> Result<WriteReceipt, StoreError> {
        let receipt = self
            .receipt_exact(
                request.operation_id.clone(),
                &request.canonical_request_hash,
            )
            .await?;
        self.validate_genesis_receipt(context, request, &receipt)?;
        Ok(receipt)
    }

    /// Reconciles one uncertain Dreamer ledger mutation by its exact admitted
    /// identity (T12-04 K1, owner #779).
    ///
    /// A `WriteReceipt` proves only that the mutation committed; it never
    /// carries the ledger answer, so even a successful exact lookup stays
    /// unknown for the job response: the caller must follow up with a ledger
    /// `Status`/`Reconcile` observation. The query still pins the admitted
    /// operation id and canonical hash with fresh transport correlation, and
    /// its typed outcome is preserved: a substituted receipt surfaces the
    /// identity/digest conflict, while an absent or unreachable receipt stays
    /// `MissingReceiptEnvelope` (still unknown — never `Unavailable`, which
    /// would invite a same-identity write retry after a possible commit).
    async fn reconcile_dreamer_job(
        &self,
        operation_id: &OperationId,
        canonical_request_hash: &str,
    ) -> Result<DurableJobResponse, StoreError> {
        let _ = self
            .receipt_exact(operation_id.clone(), canonical_request_hash)
            .await?;
        Err(StoreError::MissingReceiptEnvelope)
    }
}

impl<T: EbpStoreTransport + 'static> CanonicalStoreClient for EbpCanonicalStoreClient<T> {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        transition.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        if ctx.state_fence != self.requirement.state_fence
            || transition.state_fence != self.requirement.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        // RECHECK-63 slice B: recompute the canonical request hash from the
        // exact values about to be sent (context + transition + expected
        // heads) and reject divergence before the Apply frame is built. The
        // view borrows these references — not re-forwarded copies — so a
        // mutation after admission fails here with the typed mismatch.
        {
            let view = CanonicalRequestView::from_apply(
                ctx,
                &transition,
                &expected_revision_heads,
                &expected_ordering_heads,
            );
            verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)?;
        }
        // Production fault hook (issue #2030): consumed only after the
        // request validated, so inadmissible input keeps its typed error
        // and the armed fault. A pre-commit crash returns unknown with
        // zero provider effects; a post-commit loss is applied below.
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let operation_id = transition.identity.operation_id.clone();
        let idempotency_key = transition.identity.idempotency_key.clone();
        let canonical_request_hash = transition.identity.canonical_request_hash.clone();
        let result = self
            .execute_raw(
                StoreRequest::Apply {
                    context: ctx.clone(),
                    transition,
                    expected_revision_heads,
                    expected_ordering_heads,
                },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Transaction { receipt }) if receipt.operation_id == operation_id => {
                // Post-commit response loss (issue #2030, 994/12): the
                // provider durably committed, but the response is dropped
                // here. Unknown — never success — so the caller reconciles
                // the exact admitted identity and recovers this same
                // receipt without a replay.
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Ok(receipt)
            }
            // Once Apply has crossed the transport boundary, a valid response
            // with the wrong operation identity or response kind is itself an
            // uncertain observation. Reconcile only the operation that this
            // Kernel call admitted; never adopt an identity from the peer.
            Ok(_) => {
                self.receipt_exact(operation_id, &canonical_request_hash)
                    .await
            }
            Err(RequestFailure::Unknown {
                operation_id: observed,
                ..
            }) => {
                // The peer's identity is evidence of a mismatch only; the
                // receipt lookup remains bound to our admitted operation.
                let _ = observed;
                self.receipt_exact(operation_id, &canonical_request_hash)
                    .await
            }
            // A typed unknown-outcome failure was already bound to the
            // admitted operation in `execute_raw`; reconcile exactly it.
            Err(error) if error.is_unknown_outcome_failure() => {
                self.receipt_exact(operation_id, &canonical_request_hash)
                    .await
            }
            Err(error) => Err(error.into_store_error()),
        }
    }

    /// Applies one sealed reserved-write request through the existing
    /// authenticated Store path (issue #991).
    ///
    /// The client serializes the exact #990 fields — immutable
    /// transition/admission digest, operation/idempotency, full scope and head
    /// set, reservation order/token binding, writer epoch/fence and expiry —
    /// and dispatches once through the existing `CanonicalStoreClient`
    /// operation. Response correlation (`request_id`) stays separate from
    /// operation identity: the receipt is accepted only when its exact
    /// operation/class/fence/head/receipt identity matches the admitted
    /// request. Committed, deterministic not-applied/conflict, unsupported,
    /// and possible-commit/reconciliation outcomes are preserved with no
    /// catch-all success, no automatic retry, no second ledger, and no
    /// fallback to ordinary `Apply`. A misbound or malformed receipt observed
    /// after the single send returns its typed receipt-validation error, a
    /// wrong-kind response returns the typed contract error, and an unknown
    /// outcome returns the typed unknown-outcome error — never success and
    /// never a second wire operation after `execute_raw`.
    async fn apply_reserved_write(
        &self,
        request: ReservedWriteRequest,
    ) -> Result<WriteReceipt, StoreError> {
        request.validate()?;
        request.context.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&request.context.state_fence)?;
        self.validate_requirement_fence(&request.transition.state_fence)?;
        self.validate_requirement_fence(&request.admission.state_fence)?;
        // Production fault hook (issue #2030): same contract as
        // `apply_prepared` — validation first, pre-commit crash with zero
        // provider effects, post-commit loss discarding the observed
        // receipt into unknown.
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let idempotency_key = request.transition.identity.idempotency_key.clone();
        let result = self
            .execute_raw(
                StoreRequest::ReservedWrite {
                    request: request.clone(),
                },
                Some(&request.context),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Transaction { receipt }) => {
                // A misbound or malformed receipt observed after the single
                // send is a typed receipt-validation failure for the caller
                // to reconcile — never success, never an adopted peer
                // identity, and never a second wire operation.
                self.validate_reserved_write_receipt(&request, &receipt)?;
                // Post-commit response loss (issue #2030, 994/12): the
                // commit is durable, but the answer is dropped into
                // unknown so the caller reconciles the exact admitted
                // identity instead of observing success.
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Ok(receipt)
            }
            // Once the reserved write has crossed the transport boundary, a
            // valid response of the wrong kind is itself a typed contract
            // defect. It is preserved as an error with no second send, no
            // retry under a new identity, and no fallback to ordinary
            // `Apply`.
            Ok(_) => Err(StoreError::InvalidReceipt),
            // Unknown outcomes (transport loss, a peer `Unknown`, or a typed
            // unknown-outcome failure already bound to the admitted operation
            // by the `ReservedWrite` exchange arm) project to the typed
            // unknown-outcome error with no second wire operation. Every
            // other typed failure keeps its `into_store_error` projection
            // unchanged.
            Err(error) => Err(error.into_store_error()),
        }
    }

    async fn recovery(
        &self,
        request: StoreRecoveryRequest,
    ) -> Result<StoreRecoverySnapshot, StoreError> {
        request.validate()?;
        self.validate_requirement_fence(&request.state_fence)?;
        let response = self
            .execute_raw(
                StoreRequest::Recovery {
                    request: request.clone(),
                },
                None,
                "store-recovery",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::Recovery { snapshot } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        self.validate_recovery_snapshot(&request, &snapshot)?;
        Ok(snapshot)
    }

    async fn initialize_genesis(
        &self,
        context: &RequestMeta,
        request: StoreGenesisRequest,
    ) -> Result<WriteReceipt, StoreError> {
        request.validate_for_context(context)?;
        self.validate_requirement_fence(&context.state_fence)?;
        self.validate_requirement_fence(&request.state_fence)?;
        let operation_id = request.operation_id.clone();
        let result = self
            .execute_raw(
                StoreRequest::InitializeGenesis {
                    context: context.clone(),
                    request: request.clone(),
                },
                Some(context),
                &request.idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Genesis { receipt }) if receipt.operation_id == operation_id => {
                self.validate_genesis_receipt(context, &request, &receipt)?;
                Ok(receipt)
            }
            Ok(_) | Err(RequestFailure::Unknown { .. }) => {
                self.reconcile_genesis(context, &request).await
            }
            // A typed unknown-outcome failure was already bound to the
            // admitted operation in `execute_raw`; reconcile exactly it.
            Err(error) if error.is_unknown_outcome_failure() => {
                self.reconcile_genesis(context, &request).await
            }
            Err(error) => Err(error.into_store_error()),
        }
    }

    /// Applies one closed Dreamer ledger operation (T12-04 K1, owner #779).
    ///
    /// Public input/output remain exactly the S0 K0 types. The call validates
    /// the context and the K0 request (including the closed role projection),
    /// pins the fence to the Host-approved requirement and the admitted
    /// operation, checks the exact per-operation wire capability admitted by
    /// the handshake, executes exactly once, and binds the answer with
    /// [`DurableJobResponse::validate_for`]. A wrong-variant, misbound, or
    /// fence-divergent answer observed after the single send is an uncertain
    /// observation reconciled by the exact admitted identity — never success
    /// and never a blind retry. Typed failures keep their mapped directive
    /// (`into_store_error`); only unknown outcomes reconcile.
    async fn dreamer_job(
        &self,
        ctx: &RequestMeta,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        request.validate().map_err(map_durable_error)?;
        if ctx.state_fence != self.requirement.state_fence
            || ctx.state_fence != request.request_identity.operation.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        // Per-operation capability admitted by the handshake pin: the closed
        // K0 vocabulary maps every kind, so a missing entry is a contract
        // defect, never a default-allowed operation.
        if !CAPABILITIES.contains(&dreamer_job_capability(&request.operation)) {
            return Err(StoreError::UnknownOperation);
        }
        let operation_id = request.request_identity.operation.operation_id.clone();
        let canonical_request_hash = request.request_identity.canonical_request_hash.clone();
        let transport_key = request.request_identity.request.idempotency_key.clone();
        let result = self
            .execute_raw(
                StoreRequest::DreamerJob {
                    context: ctx.clone(),
                    request: request.clone(),
                },
                Some(ctx),
                &transport_key,
            )
            .await;
        match result {
            Ok(StoreResponse::DreamerJob { response }) => match response.validate_for(&request) {
                Ok(()) => Ok(response),
                Err(_) => {
                    self.reconcile_dreamer_job(&operation_id, &canonical_request_hash)
                        .await
                }
            },
            Ok(_) | Err(RequestFailure::Unknown { .. }) => {
                self.reconcile_dreamer_job(&operation_id, &canonical_request_hash)
                    .await
            }
            // A typed unknown-outcome failure was already bound to the
            // admitted operation in `execute_raw`; reconcile exactly it.
            Err(error) if error.is_unknown_outcome_failure() => {
                self.reconcile_dreamer_job(&operation_id, &canonical_request_hash)
                    .await
            }
            Err(error) => Err(error.into_store_error()),
        }
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::Receipt {
                    operation_id: operation_id.clone(),
                },
                None,
                "store-receipt",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::Receipt {
                receipt: Some(receipt),
            } if receipt.operation_id == operation_id => Ok(Some(receipt)),
            StoreResponse::Receipt { receipt: None } => Ok(None),
            StoreResponse::Receipt { .. } => Err(StoreError::IdentityConflict),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::RevisionHeads { keys },
                None,
                "store-revision-heads",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::RevisionHeads { heads } => Ok(heads),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::ValidationSnapshot,
                None,
                "store-validation-snapshot",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::ValidationSnapshot { snapshot } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        snapshot.validate()?;
        if snapshot.state_fence != self.requirement.state_fence
            || snapshot.state_fence.resource_generation != self.requirement.store_generation
            || &snapshot.state_fence.authority_epoch != self.requirement.authority_epoch()
        {
            return Err(StoreError::FenceMismatch);
        }
        let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        if snapshot.observed_at_unix_ms > now
            || now.saturating_sub(snapshot.observed_at_unix_ms) > 30_000
        {
            return Err(StoreError::Unavailable);
        }
        Ok(snapshot)
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetScopeRevisionView,
            scope_id: Some(scope_id.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: self.requirement.state_fence.clone(),
            parameters: BTreeMap::default(),
        };
        let response = self
            .execute_raw(
                StoreRequest::Named { request },
                None,
                "store-scope-revision-view",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::Named { response } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        if response.operation != NamedReadOperation::GetScopeRevisionView
            || response.state_fence != self.requirement.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        let view: ScopeRevisionView = serde_json::from_value(response.payload)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        view.validate()?;
        if view.scope_id != scope_id {
            return Err(StoreError::IdentityConflict);
        }
        Ok(view)
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::OrderingHeads { scopes },
                None,
                "store-ordering-heads",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::OrderingHeads { heads } => Ok(heads),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        query.validate()?;
        if query.state_fence != self.requirement.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        let response = self
            .execute_raw(
                StoreRequest::Named { request: query },
                None,
                "store-named-read",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::Named { response } => Ok(response),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        let response = self
            .execute_raw(StoreRequest::Health, None, "store-health")
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::Health { record } => Ok(record),
            _ => Err(StoreError::InvalidReceipt),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    clippy::expect_used,
    clippy::items_after_test_module,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
        StateFence,
    };
    use eliot_ipc::DeliveryOutcome;
    use eliot_platform::PlatformHandle;
    use eliot_protocol::{FrameKind, MessageType, ProtocolPayload, ServerHello};
    use eliot_store_api::StoreResponse;
    use eliot_store_api::{
        CommitId, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
        NamedMutationRequest, OperationIdentity, OperationManifestDigest, Resubmission,
        StoreFailure, StoreFailureIdentityContext, TransitionClass, WriteReceiptStatus,
        canonical_request_hash,
    };
    use serde_json::json;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    #[derive(Clone, Copy, Debug)]
    enum SnapshotFault {
        Valid,
        Unavailable,
        WrongRequestId,
        WrongFence,
        WrongGeneration,
        WrongAuthority,
        FutureTimestamp,
        StaleTimestamp,
        MalformedZeroRevision,
        DuplicateHeads,
        MixedHeadFence,
        SubstitutedConnection,
    }

    struct FakeEbpStoreTransport {
        requirement: HostStoreBootstrapRequirement,
        pending: Option<Frame>,
        fault: SnapshotFault,
        validation_calls: usize,
        recovery_response: Option<Box<StoreResponse>>,
        genesis_response: Option<Box<StoreResponse>>,
        apply_response: Option<Box<StoreResponse>>,
        reconciliation_receipt: Option<Box<WriteReceipt>>,
        recovery_calls: usize,
        genesis_calls: usize,
        apply_calls: usize,
        receipt_requests: Vec<OperationId>,
    }

    impl FakeEbpStoreTransport {
        fn new(requirement: HostStoreBootstrapRequirement, fault: SnapshotFault) -> Self {
            Self {
                requirement,
                pending: None,
                fault,
                validation_calls: 0,
                recovery_response: None,
                genesis_response: None,
                apply_response: None,
                reconciliation_receipt: None,
                recovery_calls: 0,
                genesis_calls: 0,
                apply_calls: 0,
                receipt_requests: Vec::new(),
            }
        }

        fn with_recovery_response(mut self, response: StoreResponse) -> Self {
            self.recovery_response = Some(Box::new(response));
            self
        }

        fn with_genesis_response(mut self, response: StoreResponse) -> Self {
            self.genesis_response = Some(Box::new(response));
            self
        }

        fn with_apply_response(mut self, response: StoreResponse) -> Self {
            self.apply_response = Some(Box::new(response));
            self
        }

        fn with_reconciliation_receipt(mut self, receipt: WriteReceipt) -> Self {
            self.reconciliation_receipt = Some(Box::new(receipt));
            self
        }

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
            .expect("fake response")
        }

        fn raw_snapshot(
            connection_id: String,
            request_id: RequestId,
            value: serde_json::Value,
        ) -> Frame {
            Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
                connection_id,
                request_id: Some(request_id),
                kind: FrameKind::Response,
                message_type: MessageType::Result,
                request_identity: None,
                payload: ProtocolPayload::Json(value),
                trace_context: BTreeMap::new(),
            }
        }
    }

    impl EbpStoreTransport for FakeEbpStoreTransport {
        fn ensure_authenticated(
            &self,
            _requirement: &HostStoreBootstrapRequirement,
        ) -> Result<(), StoreClientError> {
            Ok(())
        }

        async fn send_frame(
            &mut self,
            frame: &Frame,
            _limits: TransportLimits,
        ) -> Result<DeliveryOutcome, StoreClientError> {
            if frame.kind == FrameKind::Control {
                let hello = ServerHello {
                    selected_protocol: ProtocolVersion::CURRENT,
                    session_principal_binding: "fake-store-session".to_owned(),
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
                    control_channel: "fake-store-control".to_owned(),
                    rejection_reason: None,
                    authority_epoch: self.requirement.authority_epoch().clone(),
                };
                self.pending = Some(
                    eliot_ipc::server_hello_frame(self.requirement.connection_id.as_str(), &hello)
                        .expect("fake server hello"),
                );
                return Ok(DeliveryOutcome::Delivered);
            }
            let (request_id, _identity, request) =
                eliot_store_api::decode_request_frame(frame).map_err(StoreClientError::from)?;
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
                StoreRequest::ValidationSnapshot => {
                    self.validation_calls += 1;
                    let response_id = match self.fault {
                        SnapshotFault::WrongRequestId => {
                            RequestId::new("wrong-request").expect("id")
                        }
                        _ => request_id.clone(),
                    };
                    let connection_id = match self.fault {
                        SnapshotFault::SubstitutedConnection => "substituted-connection".to_owned(),
                        _ => self.requirement.connection_id.as_str().to_owned(),
                    };
                    let fence = match self.fault {
                        SnapshotFault::WrongFence | SnapshotFault::WrongAuthority => {
                            StateFence::new(
                                test_epoch(2),
                                ResourceGeneration::new(1).expect("generation"),
                            )
                        }
                        SnapshotFault::WrongGeneration => StateFence::new(
                            test_epoch(1),
                            ResourceGeneration::new(2).expect("generation"),
                        ),
                        _ => self.requirement.state_fence.clone(),
                    };
                    let observed_at_unix_ms = match self.fault {
                        SnapshotFault::FutureTimestamp => unix_ms().saturating_add(60_000) as i64,
                        SnapshotFault::StaleTimestamp => unix_ms().saturating_sub(60_000) as i64,
                        _ => unix_ms() as i64,
                    };
                    if matches!(self.fault, SnapshotFault::Unavailable) {
                        self.pending = Some(Self::response(
                            connection_id,
                            response_id.clone(),
                            StoreResponse::Failure {
                                failure: StoreFailure::from_store_error(
                                    StoreError::Unavailable,
                                    StoreFailureIdentityContext {
                                        // A same-identity retry directive is
                                        // only valid with exact request or
                                        // idempotency evidence, so the failure
                                        // carries the request it answers.
                                        request_id: Some(response_id.clone()),
                                        operation_id: None,
                                        idempotency_key_ref_or_digest: None,
                                        state_fence_ref_or_exact_safe_projection: Some(
                                            self.requirement.state_fence.clone(),
                                        ),
                                        evidence_ref: None,
                                        transport_unavailable: true,
                                    },
                                )
                                .expect("unavailable store failure is valid"),
                            },
                        ));
                    } else {
                        let head = json!({
                            "key": "scope:one",
                            "revision": 1,
                            "state_fence": fence,
                        });
                        let heads = match self.fault {
                            SnapshotFault::MalformedZeroRevision => json!([{
                                "key": "scope:one",
                                "revision": 0,
                                "state_fence": self.requirement.state_fence,
                            }]),
                            SnapshotFault::DuplicateHeads => json!([head.clone(), head]),
                            SnapshotFault::MixedHeadFence => json!([
                                head,
                                {
                                    "key": "scope:two",
                                    "revision": 1,
                                    "state_fence": StateFence::new(
                                        test_epoch(1),
                                        ResourceGeneration::new(2).expect("generation"),
                                    ),
                                }
                            ]),
                            _ => json!([]),
                        };
                        let snapshot = json!({
                            "state_fence": fence,
                            "revision_heads": heads,
                            "validation_revision": 1,
                            "observed_at_unix_ms": observed_at_unix_ms,
                        });
                        self.pending = Some(Self::raw_snapshot(
                            connection_id,
                            response_id,
                            json!({ "status": "validation_snapshot", "snapshot": snapshot }),
                        ));
                    }
                }
                StoreRequest::Recovery { .. } => {
                    self.recovery_calls += 1;
                    let response = *self.recovery_response.take().ok_or_else(|| {
                        StoreClientError::Contract("fake recovery response missing".to_owned())
                    })?;
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        response,
                    ));
                }
                StoreRequest::InitializeGenesis { .. } => {
                    self.genesis_calls += 1;
                    let response = *self.genesis_response.take().ok_or_else(|| {
                        StoreClientError::Contract("fake genesis response missing".to_owned())
                    })?;
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        response,
                    ));
                }
                StoreRequest::Apply { .. } => {
                    self.apply_calls += 1;
                    let response = *self.apply_response.take().ok_or_else(|| {
                        StoreClientError::Contract("fake apply response missing".to_owned())
                    })?;
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        response,
                    ));
                }
                StoreRequest::Receipt { operation_id } => {
                    self.receipt_requests.push(operation_id);
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        StoreResponse::Receipt {
                            receipt: self.reconciliation_receipt.as_deref().cloned(),
                        },
                    ));
                }
                _ => {
                    return Err(StoreClientError::Contract(
                        "fake transport received unexpected request".to_owned(),
                    ));
                }
            }
            Ok(DeliveryOutcome::Delivered)
        }

        async fn receive_frame(
            &mut self,
            _limits: TransportLimits,
        ) -> Result<Frame, StoreClientError> {
            self.pending
                .take()
                .ok_or_else(|| StoreClientError::Transport("fake response missing".to_owned()))
        }
    }

    fn requirement() -> HostStoreBootstrapRequirement {
        let fence = StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("generation"),
        );
        HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new("store_bridge").expect("route"),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").expect("pipe"),
            store_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence,
            launch_nonce: PlatformHandle::new("launch").expect("launch"),
            connection_id: PlatformHandle::new("connection").expect("connection"),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
            expected_peer_session_id: 1,
            approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
            approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
            timeout_ms: 30_000,
        }
    }

    fn context_for(fence: &StateFence, request_id: &str, source_id: &str) -> RequestMeta {
        RequestMeta {
            request_id: RequestId::new(request_id).expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product").expect("product"),
            source_id: SourceId::new(source_id).expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn recovery_record(
        fence: &StateFence,
        namespace: &str,
        key: &str,
        payload: &[u8],
    ) -> eliot_store_api::RecoveryRecord {
        eliot_store_api::RecoveryRecord {
            namespace: namespace.to_owned(),
            key: key.to_owned(),
            state_fence: fence.clone(),
            revision: 1,
            schema: eliot_store_api::OWNER_SNAPSHOT_SCHEMA.to_owned(),
            payload: payload.to_vec(),
            value_digest: eliot_store_api::sha256_hex(payload),
        }
    }

    fn recovery_request(
        fence: &StateFence,
        records: Vec<RecoveryRecordKey>,
        include_receipts: bool,
        include_jobs: bool,
    ) -> StoreRecoveryRequest {
        StoreRecoveryRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            state_fence: fence.clone(),
            records,
            include_receipts,
            include_jobs,
        }
    }

    fn recovery_snapshot(
        fence: &StateFence,
        owner_records: Vec<eliot_store_api::RecoveryRecord>,
        job_records: Vec<eliot_store_api::RecoveryRecord>,
        receipts: Vec<WriteReceipt>,
    ) -> StoreRecoverySnapshot {
        let snapshot = StoreRecoverySnapshot {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            state_fence: fence.clone(),
            validation_revision: 1,
            canonical_scope: ScopeRevisionView {
                scope_id: ScopeId::new("store").expect("scope"),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                state_fence: fence.clone(),
            },
            owner_records,
            job_records,
            receipts,
        };
        snapshot.validate().expect("recovery snapshot");
        snapshot
    }

    fn genesis_request(
        fence: &StateFence,
        operation_id: &str,
        idempotency_key: &str,
    ) -> StoreGenesisRequest {
        StoreGenesisRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            operation_id: OperationId::new(operation_id).expect("operation id"),
            idempotency_key: idempotency_key.to_owned(),
            canonical_request_hash: String::new(),
            state_fence: fence.clone(),
            owner_records: vec![recovery_record(
                fence,
                "owner",
                "current",
                br#"{"current_plan":null}"#,
            )],
        }
        .with_computed_digest()
        .expect("genesis request")
    }

    fn genesis_receipt(context: &RequestMeta, request: &StoreGenesisRequest) -> WriteReceipt {
        let transition =
            eliot_store_api::genesis_transition(context, request).expect("genesis transition");
        let mut receipt = WriteReceipt {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            canonical_request_hash: request.canonical_request_hash.clone(),
            transition_class: eliot_store_api::TransitionClass::RecoverySchema,
            status: eliot_store_api::WriteReceiptStatus::Committed,
            commit_id: Some(eliot_store_api::CommitId::new("commit-genesis").expect("commit")),
            state_fence: request.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["genesis-seed".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            error_code: None,
            resubmission: eliot_store_api::Resubmission::None,
            committed_at: Some(format!("commit-sequence-{0:016}", 1)),
            envelope: None,
        };
        assert_eq!(context.state_fence, transition.state_fence);
        assert_eq!(context.state_fence, receipt.state_fence);
        assert_eq!(receipt.operation_id, transition.identity.operation_id);
        assert_eq!(receipt.idempotency_key, transition.identity.idempotency_key);
        assert_eq!(
            receipt.canonical_request_hash,
            transition.identity.canonical_request_hash
        );
        assert_eq!(receipt.transition_class, transition.transition_class);
        assert_eq!(
            receipt.operation_manifest_digest,
            transition.operation_manifest_digest
        );
        assert_eq!(
            receipt.status,
            eliot_store_api::WriteReceiptStatus::Committed
        );
        assert!(receipt.commit_id.is_some());
        receipt.envelope = Some(
            eliot_store_api::issue_genesis_receipt_envelope(context, request, &receipt, 1)
                .expect("genesis envelope"),
        );
        receipt.validate().expect("genesis receipt");
        receipt
    }

    /// Builds admission-valid apply parts bound to `fence`, with the
    /// transition's claimed digest computed from the exact values via the
    /// shared Slice A helper (the production Governor-admission shape).
    fn apply_parts(
        fence: &StateFence,
    ) -> (
        RequestMeta,
        PreparedTransition,
        Vec<RevisionHeadExpectation>,
        Vec<OrderingHeadExpectation>,
    ) {
        let context = context_for(fence, "apply-request-1", "source");
        let mut transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new("apply-op-1").expect("operation id"),
                idempotency_key: "apply-idem-1".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new("scope-authority").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-authority").expect("ordering")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-authority")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-1"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: eliot_store_api::SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        let revision_heads = vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:one").expect("key"),
            expected_revision: 1,
            state_fence: fence.clone(),
        }];
        let ordering_heads = vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-authority").expect("ordering"),
            expected_sequence: 1,
            state_fence: fence.clone(),
        }];
        let view = CanonicalRequestView::from_apply(
            &context,
            &transition,
            &revision_heads,
            &ordering_heads,
        );
        transition.identity.canonical_request_hash =
            canonical_request_hash(&view).expect("apply digest computes");
        transition.validate().expect("apply transition");
        (context, transition, revision_heads, ordering_heads)
    }

    fn apply_receipt(context: &RequestMeta, transition: &PreparedTransition) -> WriteReceipt {
        let mut receipt = WriteReceipt {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            transition_class: transition.transition_class,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-apply-1").expect("commit")),
            state_fence: context.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["capture-observation".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
        };
        // The wire requires the store-owned reconciliation envelope, issued
        // exactly as an adapter would after deriving the receipt.
        receipt.envelope = Some(
            eliot_store_api::issue_store_receipt_envelope(context, transition, &receipt, 1)
                .expect("apply receipt envelope"),
        );
        receipt.validate().expect("apply receipt");
        receipt
    }

    #[tokio::test]
    async fn apply_prepared_rejects_tampered_expected_head_before_store_send() {
        let requirement = requirement();
        let (context, transition, mut revision_heads, ordering_heads) =
            apply_parts(&requirement.state_fence);
        let claimed = transition.identity.canonical_request_hash.clone();
        // Mutation after admission: the exact expected-head list handed to
        // `apply_prepared` diverges from the admitted digest while every
        // other field stays valid, so only the hash recompute can catch it.
        revision_heads[0].expected_revision = 2;
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        match client
            .apply_prepared(&context, transition, revision_heads, ordering_heads)
            .await
        {
            Err(StoreError::TransitionDigestMismatch { expected, observed }) => {
                assert_eq!(expected, claimed);
                assert_ne!(observed, claimed);
            }
            other => panic!("tampered apply must fail with the typed mismatch: {other:?}"),
        }
        assert_eq!(
            client.transport.lock().await.apply_calls,
            0,
            "tampered apply must never reach the store"
        );
    }

    #[tokio::test]
    async fn apply_prepared_accepts_exact_replay_of_identical_bytes() {
        let requirement = requirement();
        let (context, transition, revision_heads, ordering_heads) =
            apply_parts(&requirement.state_fence);
        let receipt = apply_receipt(&context, &transition);
        // Exact replay: the byte-identical request re-encodes and applies.
        let request = StoreRequest::Apply {
            context,
            transition,
            expected_revision_heads: revision_heads,
            expected_ordering_heads: ordering_heads,
        };
        let bytes = serde_json::to_vec(&request).expect("apply request encodes");
        let replay: StoreRequest = serde_json::from_slice(&bytes).expect("apply request replays");
        assert_eq!(
            serde_json::to_vec(&replay).expect("replay re-encodes"),
            bytes
        );
        let StoreRequest::Apply {
            context,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        } = replay
        else {
            panic!("replayed request must stay an Apply");
        };
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_apply_response(StoreResponse::Transaction {
                    receipt: receipt.clone(),
                }),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert_eq!(
            client
                .apply_prepared(
                    &context,
                    transition,
                    expected_revision_heads,
                    expected_ordering_heads
                )
                .await
                .expect("exact replay applies"),
            receipt
        );
        assert_eq!(client.transport.lock().await.apply_calls, 1);
    }

    #[tokio::test]
    async fn receipt_exact_rejects_substituted_canonical_hash_with_typed_mismatch() {
        let requirement = requirement();
        let (context, transition, _, _) = apply_parts(&requirement.state_fence);
        let admitted = transition.identity.canonical_request_hash.clone();
        let operation_id = transition.identity.operation_id.clone();
        let receipt = apply_receipt(&context, &transition);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_reconciliation_receipt(receipt.clone()),
            requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert_eq!(
            client
                .receipt_exact(operation_id.clone(), &admitted)
                .await
                .expect("exact receipt reconciles"),
            receipt
        );

        let mut substituted = receipt.clone();
        substituted.canonical_request_hash = "e".repeat(64);
        let substituted_client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_reconciliation_receipt(substituted),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        match substituted_client
            .receipt_exact(operation_id, &admitted)
            .await
        {
            Err(StoreError::TransitionDigestMismatch { expected, observed }) => {
                assert_eq!(expected, admitted);
                assert_eq!(observed, "e".repeat(64));
            }
            other => panic!("substituted receipt hash must fail typed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn recovery_client_accepts_exact_snapshot_and_enforces_request_ceilings() {
        let requirement = requirement();
        let fence = requirement.state_fence.clone();
        let owner = recovery_record(&fence, "owner", "current", b"owner-state");
        let request = recovery_request(&fence, vec![owner.record_key()], false, false);
        let snapshot = recovery_snapshot(&fence, vec![owner], Vec::new(), Vec::new());
        let transport = FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
            .with_recovery_response(StoreResponse::Recovery { snapshot });
        let client = EbpCanonicalStoreClient::connect(transport, requirement)
            .await
            .expect("fake handshake and readiness");

        let recovered = client.recovery(request).await.expect("recovery snapshot");
        assert_eq!(recovered.owner_records.len(), 1);
        assert!(recovered.job_records.is_empty());
        assert!(recovered.receipts.is_empty());
        let transport = client.transport.lock().await;
        assert_eq!(transport.recovery_calls, 1);
    }

    #[tokio::test]
    async fn recovery_client_rejects_wrong_fence_key_and_excluded_jobs() {
        let approved_requirement = requirement();
        let wrong_fence = StateFence::new(
            test_epoch(2),
            ResourceGeneration::new(1).expect("generation"),
        );
        let owner = recovery_record(
            &approved_requirement.state_fence,
            "owner",
            "current",
            b"owner-state",
        );
        let wrong_fence_request =
            recovery_request(&wrong_fence, vec![owner.record_key()], false, false);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement.clone(), SnapshotFault::Valid),
            approved_requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert_eq!(
            client.recovery(wrong_fence_request).await,
            Err(StoreError::FenceMismatch)
        );
        assert_eq!(client.transport.lock().await.recovery_calls, 0);

        let requirement = requirement();
        let fence = requirement.state_fence.clone();
        let requested_owner = recovery_record(&fence, "owner", "current", b"owner-state");
        let substituted_owner = recovery_record(&fence, "owner", "substituted", b"owner-state");
        let request = recovery_request(&fence, vec![requested_owner.record_key()], false, false);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_recovery_response(StoreResponse::Recovery {
                    snapshot: recovery_snapshot(
                        &fence,
                        vec![substituted_owner],
                        Vec::new(),
                        Vec::new(),
                    ),
                }),
            requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.recovery(request.clone()).await.is_err());

        let job = recovery_record(&fence, "job", "one", b"job-state");
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_recovery_response(StoreResponse::Recovery {
                    snapshot: recovery_snapshot(
                        &fence,
                        vec![requested_owner],
                        vec![job],
                        Vec::new(),
                    ),
                }),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.recovery(request).await.is_err());
    }

    #[tokio::test]
    async fn genesis_client_accepts_direct_store_receipt() {
        let requirement = requirement();
        let context = context_for(&requirement.state_fence, "genesis-request", "source");
        let request = genesis_request(&requirement.state_fence, "genesis-1", "genesis-retry-1");
        let receipt = genesis_receipt(&context, &request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: receipt.clone(),
                }),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");

        assert_eq!(
            client
                .initialize_genesis(&context, request)
                .await
                .expect("genesis receipt"),
            receipt
        );
        let transport = client.transport.lock().await;
        assert_eq!(transport.genesis_calls, 1);
        assert!(transport.receipt_requests.is_empty());
    }

    #[tokio::test]
    async fn genesis_client_reconciles_unknown_and_wrong_response_by_admitted_operation() {
        let first_requirement = requirement();
        let context = context_for(&first_requirement.state_fence, "genesis-request", "source");
        let request = genesis_request(
            &first_requirement.state_fence,
            "genesis-1",
            "genesis-retry-1",
        );
        let receipt = genesis_receipt(&context, &request);
        let peer_operation = OperationId::new("peer-operation").expect("peer operation");
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(first_requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Unknown {
                    operation_id: peer_operation,
                    reason: "peer uncertainty".to_owned(),
                })
                .with_reconciliation_receipt(receipt.clone()),
            first_requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert_eq!(
            client
                .initialize_genesis(&context, request.clone())
                .await
                .expect("reconciled receipt"),
            receipt
        );
        assert_eq!(
            client.transport.lock().await.receipt_requests,
            vec![request.operation_id.clone()]
        );

        let requirement = requirement();
        let context = context_for(&requirement.state_fence, "genesis-request", "source");
        let request = genesis_request(&requirement.state_fence, "genesis-1", "genesis-retry-1");
        let receipt = genesis_receipt(&context, &request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Transaction {
                    receipt: receipt.clone(),
                })
                .with_reconciliation_receipt(receipt),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.initialize_genesis(&context, request).await.is_ok());
        assert_eq!(client.transport.lock().await.receipt_requests.len(), 1);
    }

    #[tokio::test]
    async fn genesis_client_rejects_substituted_operation_idempotency_and_envelope() {
        let approved_requirement = requirement();
        let context = context_for(
            &approved_requirement.state_fence,
            "genesis-request",
            "source",
        );
        let request = genesis_request(
            &approved_requirement.state_fence,
            "genesis-1",
            "genesis-retry-1",
        );
        let peer_request = genesis_request(
            &approved_requirement.state_fence,
            "peer-operation",
            "peer-idem",
        );
        let peer_receipt = genesis_receipt(&context, &peer_request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: peer_receipt.clone(),
                })
                .with_reconciliation_receipt(peer_receipt),
            approved_requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(
            client
                .initialize_genesis(&context, request.clone())
                .await
                .is_err()
        );
        assert_eq!(
            client.transport.lock().await.receipt_requests,
            vec![request.operation_id.clone()]
        );

        let substituted_request = genesis_request(
            &approved_requirement.state_fence,
            request.operation_id.as_str(),
            "substituted-idem",
        );
        let substituted_receipt = genesis_receipt(&context, &substituted_request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: substituted_receipt,
                }),
            approved_requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(
            client
                .initialize_genesis(&context, request.clone())
                .await
                .is_err()
        );
        assert!(client.transport.lock().await.receipt_requests.is_empty());

        let substituted_context = context_for(
            &approved_requirement.state_fence,
            "substituted-request",
            "other-source",
        );
        let substituted_receipt = genesis_receipt(&substituted_context, &request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement, SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: substituted_receipt,
                }),
            requirement(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.initialize_genesis(&context, request).await.is_err());
        assert!(client.transport.lock().await.receipt_requests.is_empty());
    }

    #[tokio::test]
    async fn validation_snapshot_transport_matrix_is_one_call_and_fail_closed() {
        let faults = [
            SnapshotFault::Unavailable,
            SnapshotFault::WrongRequestId,
            SnapshotFault::WrongFence,
            SnapshotFault::WrongGeneration,
            SnapshotFault::WrongAuthority,
            SnapshotFault::FutureTimestamp,
            SnapshotFault::StaleTimestamp,
            SnapshotFault::MalformedZeroRevision,
            SnapshotFault::DuplicateHeads,
            SnapshotFault::MixedHeadFence,
            SnapshotFault::SubstitutedConnection,
        ];
        for fault in faults {
            let req = requirement();
            let transport = FakeEbpStoreTransport::new(req.clone(), fault);
            let client = EbpCanonicalStoreClient::connect(transport, req)
                .await
                .expect("fake handshake and readiness");
            assert!(
                client.validation_snapshot().await.is_err(),
                "fault {fault:?} unexpectedly produced a valid snapshot"
            );
            let transport = client.transport.lock().await;
            assert_eq!(transport.validation_calls, 1);
        }
        let req = requirement();
        let transport = FakeEbpStoreTransport::new(req.clone(), SnapshotFault::Valid);
        let client = EbpCanonicalStoreClient::connect(transport, req)
            .await
            .expect("positive fake handshake and readiness");
        let snapshot = client
            .validation_snapshot()
            .await
            .expect("empty canonical snapshot");
        assert!(snapshot.revision_heads.is_empty());
        let transport = client.transport.lock().await;
        assert_eq!(transport.validation_calls, 1);
    }

    // WORK_UNIT_CASE: 2030/1 — production pre-commit crash (994/11).
    #[tokio::test]
    async fn production_fault_pre_commit_crash_has_no_provider_effect_and_stays_unknown() {
        let requirement = requirement();
        let (context, transition, revision_heads, ordering_heads) =
            apply_parts(&requirement.state_fence);
        let receipt = apply_receipt(&context, &transition);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_apply_response(StoreResponse::Transaction {
                    receipt: receipt.clone(),
                }),
            requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        client.arm_fault(StoreClientFault::PreCommitCrash);
        assert_eq!(
            client.armed_fault(),
            StoreClientFault::PreCommitCrash,
            "hook observes without consuming"
        );
        let error = client
            .apply_prepared(&context, transition, revision_heads, ordering_heads)
            .await
            .expect_err("pre-commit crash stays unknown");
        assert_eq!(
            error,
            StoreError::MissingReceiptEnvelope,
            "crash before commit is unknown — never success, never retryable Unavailable"
        );
        let transport = client.transport.lock().await;
        assert_eq!(
            transport.apply_calls, 0,
            "pre-commit crash crosses no provider effect boundary"
        );
        assert!(
            transport.receipt_requests.is_empty(),
            "no reconciliation identity is adopted by the crash itself"
        );
        drop(transport);
        assert_eq!(
            client.armed_fault(),
            StoreClientFault::None,
            "one-shot hook is consumed by the crashed write"
        );

        // Validation still precedes the hook: an inadmissible request keeps
        // its typed error and leaves the armed fault for the next attempt.
        let (context, transition, mut revision_heads, ordering_heads) =
            apply_parts(&requirement.state_fence);
        revision_heads[0].expected_revision = 2;
        client.arm_fault(StoreClientFault::PreCommitCrash);
        match client
            .apply_prepared(&context, transition, revision_heads, ordering_heads)
            .await
        {
            Err(StoreError::TransitionDigestMismatch { .. }) => {}
            other => panic!("tampered apply must keep its typed mismatch: {other:?}"),
        }
        assert_eq!(client.transport.lock().await.apply_calls, 0);
        assert_eq!(
            client.armed_fault(),
            StoreClientFault::PreCommitCrash,
            "validation failure must not consume the hook"
        );
    }

    // WORK_UNIT_CASE: 2030/2 — production post-commit response loss (994/12).
    #[tokio::test]
    async fn production_fault_post_commit_response_loss_recovers_original_receipt_without_replay() {
        let requirement = requirement();
        let (context, transition, revision_heads, ordering_heads) =
            apply_parts(&requirement.state_fence);
        let receipt = apply_receipt(&context, &transition);
        let operation_id = transition.identity.operation_id.clone();
        let admitted_hash = transition.identity.canonical_request_hash.clone();
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_apply_response(StoreResponse::Transaction {
                    receipt: receipt.clone(),
                })
                .with_reconciliation_receipt(receipt.clone()),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        client.arm_fault(StoreClientFault::PostCommitResponseLoss);
        let error = client
            .apply_prepared(&context, transition, revision_heads, ordering_heads)
            .await
            .expect_err("dropped response stays unknown");
        assert_eq!(
            error,
            StoreError::MissingReceiptEnvelope,
            "committed-but-unobserved is unknown — never success"
        );
        assert_eq!(
            client.transport.lock().await.apply_calls,
            1,
            "the commit reached the provider exactly once"
        );
        // Exact-identity reconciliation recovers the original receipt: no
        // replay under any identity, no adopted peer identity.
        let recovered = client
            .receipt_exact(operation_id.clone(), &admitted_hash)
            .await
            .expect("exact reconciliation recovers the committed receipt");
        assert_eq!(
            recovered, receipt,
            "response loss recovers the original receipt"
        );
        let transport = client.transport.lock().await;
        assert_eq!(
            transport.receipt_requests,
            vec![operation_id],
            "reconciliation binds the admitted operation only"
        );
        assert_eq!(
            transport.apply_calls, 1,
            "reconciliation issues no second Apply"
        );
    }
}

fn client_hello(
    requirement: &HostStoreBootstrapRequirement,
) -> Result<ClientHello, StoreClientError> {
    let module_id = ContractId::new(STORE_MODULE_IDENTITY)
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(requirement.approved_artifact_hash.as_str())
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    let module_contract = ModuleContract {
        module_id: module_id.clone(),
        version: ContractVersion::new(1, 0, 0),
        artifact_id: artifact_id.clone(),
        protocols: vec!["eliot.s03.ebp.v1".to_owned()],
        required_capabilities: vec![
            "store.readiness".to_owned(),
            "store.apply".to_owned(),
            "store.validation_snapshot".to_owned(),
        ],
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: "eliot-kernel".to_owned(),
        failure_domain: "canonical-store".to_owned(),
        hot_replace: false,
    };
    Ok(ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: module_id.as_str().to_owned(),
        artifact_hash: artifact_id.clone(),
        module_contract,
        module_generation: ModuleGeneration {
            module_id,
            generation: requirement.store_generation,
            artifact_id,
            state: ModuleGenerationState::Active,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            state_fence: requirement.state_fence.clone(),
        },
        launch_nonce: requirement.launch_nonce.as_str().to_owned(),
        capabilities: CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
            .map_err(|_| StoreClientError::Contract("protocol max frame exceeds u32".to_owned()))?,
        authority_epoch: requirement.authority_epoch().clone(),
    })
}

fn decode_server_hello(
    frame: &Frame,
    requirement: &HostStoreBootstrapRequirement,
) -> Result<ServerHello, StoreClientError> {
    let server = eliot_ipc::decode_server_hello_frame(frame, requirement.connection_id.as_str())?;
    let config_hash = server
        .config_snapshot
        .get("config_hash")
        .and_then(serde_json::Value::as_str);
    let artifact_hash = server
        .config_snapshot
        .get("artifact_hash")
        .and_then(serde_json::Value::as_str);
    let expected_capabilities: BTreeSet<&str> = CAPABILITIES.iter().copied().collect();
    let observed_capabilities: BTreeSet<&str> = server
        .allowed_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    let expected_effects: BTreeSet<&str> = EFFECTS.iter().copied().collect();
    let observed_effects: BTreeSet<&str> =
        server.allowed_effects.iter().map(String::as_str).collect();
    if server.authority_epoch != requirement.authority_epoch().clone()
        || server.selected_protocol != ProtocolVersion::CURRENT
        || server.rejection_reason.is_some()
        || artifact_hash != Some(requirement.approved_artifact_hash.as_str())
        || config_hash != Some(requirement.approved_config_hash.as_str())
        || observed_capabilities != expected_capabilities
        || observed_effects != expected_effects
    {
        return Err(StoreClientError::Contract(
            "store handshake did not admit the exact authority/fence capability set".to_owned(),
        ));
    }
    Ok(server)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(windows)]
impl EbpStoreTransport for eliot_ipc::NamedPipeTransport {
    fn ensure_authenticated(
        &self,
        requirement: &HostStoreBootstrapRequirement,
    ) -> Result<(), StoreClientError> {
        let identity = self.peer_identity();
        identity.validate().map_err(StoreClientError::from)?;
        match identity {
            eliot_ipc::PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } if user_identity == requirement.expected_peer_sid.as_str()
                && session_identity == &requirement.expected_peer_session_id.to_string() =>
            {
                Ok(())
            }
            _ => Err(StoreClientError::Transport(
                "authenticated store peer does not match Host-approved SID/session".to_owned(),
            )),
        }
    }

    async fn send_frame(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, StoreClientError> {
        eliot_ipc::NamedPipeTransport::send_frame(self, frame, limits)
            .await
            .map_err(Into::into)
    }

    async fn receive_frame(&mut self, limits: TransportLimits) -> Result<Frame, StoreClientError> {
        eliot_ipc::NamedPipeTransport::receive_frame(self, limits)
            .await
            .map_err(Into::into)
    }
}
