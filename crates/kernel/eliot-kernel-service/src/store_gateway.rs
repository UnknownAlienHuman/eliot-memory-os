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
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse};
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
        let result = self
            .store
            .initialize_genesis(context, request)
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
    /// Unknown outcome handling stays owned by the EBP client, which
    /// reconciles the exact admitted operation identity.
    pub async fn dreamer_job(
        &self,
        context: &RequestMeta,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, String> {
        let _flight = self.flight.enter()?;
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        context.validate().map_err(|error| error.to_string())?;
        request.validate().map_err(|error| error.to_string())?;
        if !request.role.permits(request.operation.kind()) {
            return Err("dreamer job caller role does not permit the operation".to_owned());
        }
        self.validate_active_route(&context.state_fence)?;
        if request.request_identity.operation.state_fence != context.state_fence {
            return Err("dreamer job request fence does not match request metadata".to_owned());
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
            // Slices A+B (#65): Dreamer-job Store admission rides the typed
            // `NORMAL_WORKLOAD` normal lease; protected work stays on
            // `acquire_protected_control`. See
            // `lifecycle.rs:acquire_admission`.
            if lease.authority_epoch() != context.state_fence.authority_epoch {
                return Err("dreamer job route authority epoch is stale".to_owned());
            }
            lease
        };
        if self.is_fenced() {
            return Err("canonical-store gateway is fenced for rebind".to_owned());
        }
        let result = self
            .store
            .dreamer_job(context, request)
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
                let Some(position) =
                    request.parameters.get("position").and_then(Value::as_str)
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

    #[tokio::test]
    async fn execute_named_get_current_epistemic_position_proves_identity_and_fence() {
        let position = format!("position-{}", std::process::id());
        let scratch = std::env::temp_dir().join(format!(
            "eliot-t11-2-daemon-gateway-{}",
            std::process::id()
        ));
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
            operation: NamedReadOperation::GetCurrentEpistemicPosition,
            scope_id: Some(ScopeId::new("scope-epistemic").expect("scope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: BTreeMap::from([("position".to_owned(), Value::String(position.clone()))]),
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

        let eventual = NamedReadRequest {
            operation: NamedReadOperation::GetCurrentEpistemicPosition,
            scope_id: Some(ScopeId::new("scope-epistemic").expect("scope")),
            consistency: ReadConsistency::Eventual,
            state_fence: fence.clone(),
            parameters: BTreeMap::from([("position".to_owned(), Value::String(position.clone()))]),
        };
        assert!(
            execute_named_via(&flight, &service, &route, route_epoch.as_ref(), &store, eventual)
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
            execute_named_via(&flight, &service, &route, route_epoch.as_ref(), &store, missing)
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
        EliotResourceUri, QueryIntent, QueryMode, QueryRequest, ReadApi, ReadError, ReadService,
        StateRequest,
    };
    use eliot_store_api::{
        EVIDENCE_PACK_MAX_RECORDS, EffectClass,
        EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        NamedReadOperation, OperationId, OperationIdentity, PreparedTransition, ReadConsistency,
        ScopeId, OrderingScopeId, TransitionClass, WriteReceiptStatus, generated_operation_manifests,
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
        std::env::var_os(PROVIDER_EXE_OVERRIDE_ENV).map_or_else(
            || PathBuf::from(DEFAULT_PROVIDER_EXE),
            PathBuf::from,
        )
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
        PreparedTransition {
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
        }
    }

    fn verification_intent() -> QueryIntent {
        QueryIntent {
            mode: QueryMode::Verification,
            time_scope: "t11-live-session-window".to_owned(),
            branch_environment_scope: "t11-live-branch".to_owned(),
            freshness_policy: "t11-live-exact-fence".to_owned(),
            required_assurance: "t11-live-evidence-provenance".to_owned(),
        }
    }

    fn evidence_parameters(subject: &str, max_records: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("subject".to_owned(), Value::String(subject.to_owned())),
            (
                "max_records".to_owned(),
                Value::String(max_records.to_owned()),
            ),
        ])
    }

    fn live_query(
        scope: &ScopeId,
        subject: &str,
        max_records: &str,
        free_text: &str,
    ) -> QueryRequest {
        QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            query: free_text.to_owned(),
            exact_resource_uri: None,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            parameters: evidence_parameters(subject, max_records),
            provenance_handles: Vec::new(),
        }
    }

    fn live_roots(suffix: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        // The suffix keeps parallel tests in one process (same pid) on
        // disjoint roots: sharing a root would let one test's cleanup
        // remove another test's live provider files mid-run.
        let root = std::env::temp_dir()
            .join(format!("eliot-t11-live-surreal-{}-{suffix}", std::process::id()));
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
            if child
                .try_wait()
                .expect("bootstrap child polls")
                .is_some()
            {
                panic!("bootstrap provider exited before binding {bind}");
            }
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

        // Free text is intent data only — a smuggled `query` selector fails
        // the closed catalogue gate before any transport.
        let mut smuggled = evidence_parameters(&subject, "10");
        smuggled.insert("query".to_owned(), Value::String(subject.clone()));
        let smuggled_request = QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            query: "unrelated prose".to_owned(),
            exact_resource_uri: None,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
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
            "a smuggled `query` parameter must fail closed"
        );

        // Exact expansion belongs to `ResourceRequest`, never to
        // `QueryRequest` — both the parameter key and the request-level
        // selector fail closed on this path.
        let mut smuggled_uri = evidence_parameters(&subject, "10");
        smuggled_uri.insert(
            "exact_resource_uri".to_owned(),
            Value::String("eliot://evidence/pack".to_owned()),
        );
        let smuggled_uri_request = QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            query: "unrelated prose".to_owned(),
            exact_resource_uri: None,
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
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
            "a smuggled `exact_resource_uri` parameter must fail closed"
        );
        let request_level_uri = QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            query: "unrelated prose".to_owned(),
            exact_resource_uri: Some(
                EliotResourceUri::new("eliot://evidence/pack").expect("test URI parses"),
            ),
            scope_id: Some(scope.clone()),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            parameters: evidence_parameters(&subject, "10"),
            provenance_handles: Vec::new(),
        };
        assert!(
            matches!(
                service
                    .query(
                        &live_context(&fence, &format!("query-request-uri-{tag}")),
                        request_level_uri
                    )
                    .await,
                Err(ReadError::InvalidField { .. })
            ),
            "a request-level `exact_resource_uri` must fail closed on the query path"
        );

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
                adapter.probe_readiness().await.expect("readiness re-probes"),
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
        // live adapter returns the exact record/provenance. Free text is
        // deliberately unrelated prose — it must never become a selector.
        let service = ReadService::new(adapter);
        let result = service
            .query(
                &live_context(&fence, &format!("query-{tag}")),
                live_query(
                    &scope,
                    &subject,
                    "10",
                    "summarize everything captured for the operator in prose",
                ),
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
                live_query(&scope, &subject, "10", "unrelated prose"),
            )
            .await;
        match fenced {
            Err(ReadError::Store(message)) => assert!(
                message.contains("state fence mismatch"),
                "wrong-fence refusal must surface the typed mismatch, observed: {message}"
            ),
            other => panic!("wrong fence must fail closed, observed: {other:?}"),
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
                    "unrelated prose",
                ),
            )
            .await;
        match over_bound {
            Err(ReadError::Store(message)) => assert!(
                message.contains("payload exceeds named-operation limit"),
                "over-bound refusal must surface the typed limit, observed: {message}"
            ),
            other => panic!("over-bound request must fail closed, observed: {other:?}"),
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
                    parameters: BTreeMap::new(),
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
