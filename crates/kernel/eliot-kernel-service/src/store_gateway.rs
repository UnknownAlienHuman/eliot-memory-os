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

use eliot_contracts::{EpochId, OperationId, RequestMetadata, StateFence};
use eliot_ipc::NamedPipeTransport;
use eliot_kernel_core::GenerationRoute;
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, CanonicalValidationSnapshot, NamedReadRequest,
    NamedReadResponse, OrderingHeadExpectation, PreparedTransition, RequestMeta,
    RevisionHeadExpectation, StoreGenesisRequest, StoreHealth, StoreRecoveryRequest,
    StoreRecoverySnapshot, WriteReceipt, verify_canonical_request_hash,
};

use crate::{EbpCanonicalStoreClient, EbpStoreTransport, KernelService};

const ACTIVE_DAEMON_CALLER: &str = "eliotd";

#[path = "store_receipt_gateway.rs"]
mod store_receipt_gateway;

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
    /// Canonical epoch the scalar route contour was bound to at composition
    /// (Implements #64): the route's sequence projection is only meaningful
    /// under this exact `(lineage_id, sequence)` tuple. Route currency is
    /// proven with `is_same_authority` against live authority — never by
    /// coercing a sequence to `u64`. `None` (a poisoned service lock at
    /// bind time) fails every later gate closed.
    route_epoch: Option<EpochId>,
    flight: GatewayFlight,
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

impl KernelStoreGateway {
    /// Constructs the gateway from the Kernel-approved service and Store client.
    #[doc(hidden)]
    pub fn new(
        service: Arc<Mutex<KernelService>>,
        store: Arc<EbpCanonicalStoreClient<NamedPipeTransport>>,
        route: GenerationRoute,
    ) -> Self {
        // Bind the scalar route contour to its canonical lineage at
        // composition (Implements #64): the sequence inside `route` was
        // minted by the Host-approved bootstrap for the live tuple observed
        // here, so snapshot that tuple as the route's canonical mirror. Mint
        // stays Host-owned; the gateway only pins and re-checks the tuple.
        let route_epoch = service.lock().map(|guard| guard.authority_epoch()).ok();
        Self {
            service,
            store,
            route,
            route_epoch,
            flight: GatewayFlight::new(),
        }
    }

    #[doc(hidden)]
    pub fn fence(&self) {
        self.flight.fence();
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
        context.validate().map_err(|error| error.to_string())?;
        transition.validate().map_err(|error| error.to_string())?;
        if context.source_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err("transition caller is not the active daemon".to_owned());
        }
        if transition.state_fence != context.state_fence {
            return Err("transition state fence does not match request metadata".to_owned());
        }
        // RECHECK-63 slice B: recompute the canonical request hash from the
        // exact values about to be executed (context + transition + expected
        // heads) and reject divergence before any store work. The view is
        // built from these references — not re-forwarded copies — so a
        // mutation after admission fails here with the typed mismatch.
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
            // Canonical route/epoch mirror (Implements #64): route currency
            // is the exact-tuple match between the composition-bound route
            // epoch and live authority — never a scalar `sequence.get()`
            // coercion. Cross-lineage same-sequence routes never authorize:
            // the bound tuple carries its lineage.
            let live_epoch = service.authority_epoch();
            if self
                .route_epoch
                .as_ref()
                .is_none_or(|bound| !bound.is_same_authority(&live_epoch))
                || self.route.active_generation() != transition.state_fence.resource_generation
            {
                return Err(
                    "canonical-store route is outside the active Kernel generation".to_owned(),
                );
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
            lease
        };
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }

        let result = self
            .store
            .apply_prepared(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(|error| error.to_string());
        drop(lease);
        result
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
    /// boundary. T11.1 activates `GetEvidencePack` only; no allowlist lives
    /// here because catalogue membership stays owned by the Store adapters.
    pub async fn execute_named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, String> {
        execute_named_via(
            &self.flight,
            &self.service,
            &self.route,
            self.route_epoch.as_ref(),
            &self.store,
            request,
        )
        .await
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
            if lease.authority_epoch() != request.state_fence.authority_epoch {
                return Err("genesis route authority epoch is stale".to_owned());
            }
            lease
        };
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        let result = self
            .store
            .initialize_genesis(context, request)
            .await
            .map_err(|error| error.to_string());
        drop(lease);
        result
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
        validate_route(
            &self.service,
            &self.route,
            self.route_epoch.as_ref(),
            state_fence,
        )
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

/// Canonical route/epoch mirror shared by every gateway read/write path.
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
    route_epoch: Option<&EpochId>,
    state_fence: &StateFence,
) -> Result<(), String> {
    let service = service
        .lock()
        .map_err(|_| "Kernel service lock poisoned".to_owned())?;
    if service.generation_fenced() {
        return Err("Kernel generation is fenced".to_owned());
    }
    let live_epoch = service.authority_epoch();
    if route_epoch.is_none_or(|bound| !bound.is_same_authority(&live_epoch))
        || !live_epoch.is_same_authority(&state_fence.authority_epoch)
    {
        return Err("canonical-store route is outside the active Kernel epoch".to_owned());
    }
    if route.active_generation() != state_fence.resource_generation {
        return Err("canonical-store route is outside the active Kernel generation".to_owned());
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
    route_epoch: Option<&EpochId>,
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
    validate_route(service, route, route_epoch, &request.state_fence)?;
    let response = store
        .execute_named(request.clone())
        .await
        .map_err(|error| error.to_string())?;
    if flight.is_fenced() {
        return Err("canonical-store gateway is fenced for rebind".to_owned());
    }
    validate_route(service, route, route_epoch, &request.state_fence)?;
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

    use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, RequestId, ResourceGeneration};
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
            if request.operation != NamedReadOperation::GetEvidencePack {
                return self.typed_failure(request_id, StoreError::UnknownOperation);
            }
            if request.state_fence != self.requirement.state_fence {
                return self.typed_failure(request_id, StoreError::FenceMismatch);
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
            AuthorityEpoch::new(1).expect("route epoch"),
        )
        .expect("store route binds");
        let route_epoch = Some(
            service
                .lock()
                .expect("service lock reads")
                .authority_epoch(),
        );
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
        let response = execute_named_via(
            &flight,
            &service,
            &route,
            route_epoch.as_ref(),
            &store,
            request,
        )
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
        let fenced = execute_named_via(
            &flight,
            &service,
            &route,
            route_epoch.as_ref(),
            &store,
            fenced_request,
        )
        .await;
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
        let bounded = execute_named_via(
            &flight,
            &service,
            &route,
            route_epoch.as_ref(),
            &store,
            over_bound,
        )
        .await;
        match bounded {
            Err(error) => assert!(
                error.contains("payload exceeds named-operation limit"),
                "over-bound refusal must surface the typed limit, observed: {error}"
            ),
            Ok(_) => panic!("over-bound request must fail closed"),
        }

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
