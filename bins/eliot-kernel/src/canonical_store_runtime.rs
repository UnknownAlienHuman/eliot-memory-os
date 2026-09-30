//! Kernel canonical-store bootstrap and attachment runtime.
//!
//! Architecture: A12.3 One governed write path; A13.2 Kernel and failure domains; ARCH-SEC-02 Authentication and identity; ARCH-RES-01 Resource lifecycle and ownership.
//! Implementation: I1.2 Obligatory processes; I5.1 Canonical store bootstrap; I5.9 Store client attachment; I5.11 Store gateway ownership; I15.3 Store composition binding.
//! Forbidden authority: must not embed raw `SurrealQL`, must not handle credentials, must not claim semantic ownership, must not create a second store writer — forbidden raw `SurrealQL`, credentials, semantic ownership, second store writer.
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition` canonical-store bootstrap/attachment closure plus inseparable helper with zero external users.
//! Capability cells (§15 req.1): cell 8 canonical-store attachment runtime plus
//! the pure cell 3/6 store-rebind predicates moved here from `lib` without
//! touching the `rebind_store` transaction body, which stays whole in `lib`.
//!
//! Also owns the I14.11 canonical-Store availability observation (issue #1681):
//! connectivity, process readiness and semantic freshness are three separately
//! owned facts, each with its own state, and canonical-sensitive authority is
//! refused unless all three hold. That is why the file grew the fact vocabulary
//! beside the attachment runtime: the observation reads the attachment this
//! module already owns and answers through the same bounded Store round trips
//! `connect_canonical_store` uses. It is not a second attachment, reconnection
//! ledger or process launcher.

use super::HostStoreBootstrapRequirement;
use super::KernelBuildError;
use super::KernelComposition;
use super::STORE_BRIDGE_ROUTE;
use crate::kernel_diagnostics::{
    EntrypointStage, observe_entrypoint_with_detail, observe_terminal_error,
};
#[cfg(windows)]
use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes};
#[cfg(windows)]
use eliot_platform::PlatformHandle;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(windows)]
use super::CanonicalStoreAttachmentTransaction;
#[cfg(windows)]
use super::KernelStoreGateway;
#[cfg(windows)]
use super::StoreBootstrapHandoff;

#[cfg(windows)]
use eliot_ipc::NamedPipeTransport;
#[cfg(windows)]
use eliot_kernel_core::RouteScope;
#[cfg(windows)]
use eliot_kernel_service::{EbpCanonicalStoreClient, StoreClientError};
#[cfg(windows)]
use eliot_ors::{RecoveryPayload, ReservationState, StateFenceSnapshot};
#[cfg(windows)]
use eliot_platform_windows::ProtectedSecret;
#[cfg(windows)]
use eliot_platform_windows::{NamedPipePeerExpectation, observe_named_pipe_peer_process_in_job};
#[cfg(windows)]
use eliot_kernel_service::{RESERVATION_KEY_NAME, RESERVATION_KEY_PROVIDER};
#[cfg(windows)]
use std::fmt;

/// Maps one Store bootstrap/build failure to its stable owner-typed code.
///
/// Only the variant name is emitted; any `String` payload is never logged.
#[cfg(windows)]
fn store_build_error_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "PLATFORM",
        KernelBuildError::Transport(_) => "TRANSPORT",
        KernelBuildError::Runtime(_) => "RUNTIME",
        KernelBuildError::Ors(_) => "ORS",
        KernelBuildError::Core(_) => "CORE",
        KernelBuildError::Service(_) => "SERVICE",
        KernelBuildError::StoreBootstrapRequired => "STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "STORE_ALREADY_CONNECTED",
        KernelBuildError::Principal(_) => "PRINCIPAL",
    }
}

#[cfg(windows)]
pub(crate) fn attach_then_retain_canonical_store<'a, T, Attach>(
    gateway: Arc<T>,
    retained: &'a Mutex<Option<Arc<T>>>,
    attach: Attach,
) -> Result<(), KernelBuildError>
where
    T: Send + Sync + 'static,
    Attach: FnOnce(
            Arc<T>,
        )
            -> Result<Box<dyn CanonicalStoreAttachmentTransaction + 'a>, KernelBuildError>
        + 'a,
{
    let process_attachment = attach(Arc::clone(&gateway))?;
    let mut retained = retained
        .lock()
        .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?;
    if retained.is_some() {
        // #1861 hard boundary 3 (canonical control records, one online writer
        // composition): a second canonical Store writer composition is the
        // multiple-writer survivor. The single retained gateway is the only
        // online writer; record the rejected second composition attempt so the
        // one-writer boundary is durably observable, then refuse it.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.attach_rejected:second_writer",
        );
        return Err(KernelBuildError::StoreAlreadyConnected);
    }
    *retained = Some(gateway);
    drop(retained);
    process_attachment.commit();
    Ok(())
}

impl KernelComposition {
    #[must_use]
    pub fn store_bootstrap(&self) -> Option<&HostStoreBootstrapRequirement> {
        // F-LOG-KERNEL-2 (#899): bootstrap-requirement request observation.
        // Presence/absence only; no requirement material is emitted.
        if self.store_bootstrap.is_some() {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_requested:present",
            );
        } else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_requested:absent",
            );
        }
        self.store_bootstrap.as_ref()
    }

    #[cfg(windows)]
    pub fn install_store_bootstrap(
        &self,
        handoff: StoreBootstrapHandoff,
    ) -> Result<(), KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): bootstrap validation boundary. One terminal
        // per failed install; exact replay is readback, not a new mutation.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.bootstrap_received",
        );
        if let Err(error) = handoff
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:validation",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        if self.store_bootstrap.as_ref() != Some(&handoff.requirement) {
            let error = KernelBuildError::Service(
                "Store handoff does not match the immutable bootstrap descriptor".to_owned(),
            );
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:mismatch",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        let Ok(mut retained) = self.store_handoff.lock() else {
            let error = KernelBuildError::Service("Store handoff lock poisoned".to_owned());
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:lock",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        };
        if let Some(existing) = retained.as_ref() {
            if existing == &handoff {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.bootstrap_validated:replay",
                );
                return Ok(());
            }
            let error = KernelBuildError::Service(
                "Store bootstrap handoff substitution rejected".to_owned(),
            );
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:substitution",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        *retained = Some(handoff);
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.bootstrap_validated:accepted",
        );
        Ok(())
    }

    #[cfg(windows)]
    pub async fn connect_canonical_store(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): Store connection boundary. Constructed
        // runtime is not ready; a send is not commit. One terminal per failed
        // connect; early rejection proves not-attempted only for the stage
        // whose ledger establishes it.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.connect_requested",
        );
        if self.canonical_store_claimed.load(Ordering::Acquire) {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:already_claimed",
            );
            let Ok(guard) = self.canonical_store_gateway.lock() else {
                let error = KernelBuildError::Service("store gateway lock poisoned".to_owned());
                observe_terminal_error(store_build_error_code(&error));
                return Err(error);
            };
            let gateway = guard.clone();
            if let Some(gateway) = gateway {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_retained:already_connected",
                );
                return Ok(gateway);
            }
            let error = KernelBuildError::StoreAlreadyConnected;
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:already_connected",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        if let Err(error) = self.claim_canonical_store_slot() {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:slot_claim",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        let result = self.connect_canonical_store_inner(timeout).await;
        match &result {
            Ok(_) => {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connected",
                );
            }
            Err(error) => {
                self.canonical_store_claimed.store(false, Ordering::Release);
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_failed",
                );
                observe_terminal_error(store_build_error_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "Store connection phases keep exact route/generation checks in one audited gateway"
    )]
    async fn connect_canonical_store_inner(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): inner connection phases only; the outer
        // `connect_canonical_store` owns the single terminal. No pipe/SID/
        // process/credential material is emitted, only fixed phases plus
        // numeric epoch/generation already held for the route check.
        self.process_gateway.as_ref().ok_or_else(|| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:no_process_authority",
            );
            KernelBuildError::Service(
                "process authority is required before canonical Store attachment".to_owned(),
            )
        })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.process_authority_present",
        );
        let requirement = self.store_bootstrap.clone().ok_or_else(|| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:no_bootstrap",
            );
            KernelBuildError::StoreBootstrapRequired
        })?;
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_rejected:no_handoff",
                );
                KernelBuildError::StoreBootstrapRequired
            })?;
        if let Err(error) = requirement
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:requirement_invalid",
            );
            return Err(error);
        }
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.requirement_validated",
        );
        let process = &handoff.process_binding.process;
        let observed = observe_named_pipe_peer_process_in_job(
            handoff.process_binding.job.as_str(),
            process.process_id,
        )
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:peer_observation",
            );
            KernelBuildError::Principal(error.to_string())
        })?;
        if observed.process_binding().process_id() != process.process_id
            || observed.process_binding().start_time_100ns() != process.start_time_100ns
            || observed.process_binding().image_path() != process.image_path
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:peer_binding_changed",
            );
            return Err(KernelBuildError::Principal(
                "Store process binding changed before pipe admission".to_owned(),
            ));
        }
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.peer_binding_matched",
        );
        let expectation = NamedPipePeerExpectation::new_with_process_and_job_binding(
            requirement.expected_peer_sid.as_str(),
            requirement.expected_peer_session_id,
            observed,
        )
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:peer_expectation",
            );
            KernelBuildError::Principal(error.to_string())
        })?;
        let transport = NamedPipeTransport::connect_authenticated(
            requirement.canonical_pipe_identity.as_str(),
            timeout,
            &expectation,
        )
        .await
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:transport",
            );
            KernelBuildError::Transport(error)
        })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.transport_connected",
        );
        let client = EbpCanonicalStoreClient::connect(transport, requirement.clone())
            .await
            .map_err(|error| {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_rejected:client",
                );
                match error {
                    StoreClientError::Transport(error) | StoreClientError::Contract(error) => {
                        KernelBuildError::Service(error)
                    }
                    StoreClientError::Store(error) => KernelBuildError::Service(error.to_string()),
                }
            })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.client_connected",
        );
        let route_scope = RouteScope::new(STORE_BRIDGE_ROUTE)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let routes = self
            .generation_route_snapshot()
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let route = routes
            .route(&route_scope)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?
            .clone();
        // Exact tuple equality is the authorization rule (Implements #64).
        if !route
            .authority_epoch()
            .is_same_authority(requirement.authority_epoch())
            || route.active_generation() != requirement.store_generation
            || requirement.route_identity.as_str() != STORE_BRIDGE_ROUTE
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:route_mismatch",
            );
            return Err(KernelBuildError::Core(
                "store bootstrap does not match the active Kernel store route".to_owned(),
            ));
        }
        // Exact route/generation match; only the fixed bridge name plus the
        // lineage-aware epoch tuple and generation are emitted.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            &format!(
                "kernel.store.route_matched:store_bridge:epoch={:?}:generation={}",
                route.authority_epoch(),
                route.active_generation().value()
            ),
        );
        let evidence = self
            .canonical_store_evidence
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                KernelBuildError::Service(
                    "canonical Store evidence provider is unavailable".to_owned(),
                )
            })?;
        let gateway = Arc::new(KernelStoreGateway::new_with_evidence(
            self.service.clone(),
            Arc::new(client),
            route,
            // I14.21 (#1690): the gateway owns unknown-commit recovery
            // against the composition-retained Kernel ORS handle.
            Some(Arc::clone(&self.generation_gateway.ors)),
            evidence,
        ));
        attach_then_retain_canonical_store(
            Arc::clone(&gateway),
            &self.canonical_store_gateway,
            |gateway| {
                self.process_gateway.as_ref().map_or_else(
                    || {
                        Err(KernelBuildError::Service(
                            "process authority is required before canonical Store attachment"
                                .to_owned(),
                        ))
                    },
                    |process_gateway| {
                        process_gateway
                            .attach_canonical_store(gateway)
                            .map(|attachment| {
                                Box::new(attachment) as Box<dyn CanonicalStoreAttachmentTransaction>
                            })
                    },
                )
            },
        )
        .inspect_err(|_| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:attach",
            );
        })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.gateway_attached",
        );
        Ok(gateway)
    }

    /// Resumes only new, exact full-operation Observe reservations after the
    /// existing Store and ORS recovery pass has established their denominator.
    /// Legacy transition-only records and uncertain send states stay on the
    /// receipt-only path. Complete original operations are decoded only from
    /// their protected reservation payload and are never reconstructed from
    /// current heads.
    #[cfg(windows)]
    pub(crate) async fn resume_staged_observe_reservations(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        inventory: &eliot_kernel_service::StagedWriteRecovery,
    ) -> Result<(), String> {
        for staged in &inventory.envelopes {
            let operation_identity =
                eliot_ors::OperationIdentity::new(staged.operation_id.as_str())
                    .map_err(|error| error.to_string())?;
            let Some(reservation) = self
                .generation_gateway
                .ors
                .load_write_reservation_by_operation(&operation_identity)
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            if reservation.token.operation_id != operation_identity
                || reservation.token.reservation_order != staged.reservation_order
                || reservation.state != staged.state
            {
                continue;
            }
            if matches!(
                reservation.state,
                ReservationState::Reserved
                    | ReservationState::Eligible
                    | ReservationState::Executing
                    | ReservationState::Reconciling
            ) {
                let _ = self
                    .resume_one_staged_observe_reservation(gateway, &reservation)
                    .await;
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    async fn resume_one_staged_observe_reservation(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        reservation: &eliot_ors::ReservationRecord,
    ) -> Result<(), String> {
        let token = &reservation.token;
        let Some(host_record) = self
            .generation_gateway
            .ors
            .load_host_request_by_operation(&token.operation_id)
            .map_err(|error| error.to_string())?
        else {
            return Ok(());
        };
        if host_record.kind != eliot_ors::HostRequestKind::Invocation
            || host_record.capability_ref.as_str() != "eliot.observe"
            || host_record.executable_input.is_none()
        {
            return Ok(());
        }
        let state_fence: StateFence = serde_json::from_str(&token.state_fence.canonical_json)
            .map_err(|error| error.to_string())?;
        let recaptured =
            StateFenceSnapshot::capture(&state_fence, token.state_fence.observed_authority_epoch)
                .map_err(|error| error.to_string())?;
        if recaptured != token.state_fence {
            return Err("retained Observe reservation fence did not round-trip".to_owned());
        }
        let operation_identity = eliot_ors::OperationIdentity::new(token.operation_id.as_str())
            .map_err(|error| error.to_string())?;
        let envelope = gateway.verify_staged_envelope(&state_fence, &operation_identity)?;
        let staged_access = envelope.privacy_and_visibility_class.clone();
        let ciphertext = match envelope.payload {
            RecoveryPayload::Encrypted { key, ciphertext }
                if key.provider.as_str() == RESERVATION_KEY_PROVIDER
                    && key.key.as_str() == RESERVATION_KEY_NAME =>
            {
                ciphertext
            }
            _ => {
                return Err(
                    "retained Observe reservation payload is not its protected operation"
                        .to_owned(),
                );
            }
        };
        let protected =
            ProtectedSecret::from_ciphertext(ciphertext).map_err(|error| error.to_string())?;
        let original_bytes = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| error.to_string())?;
        let operation: super::daemon_request_dispatch::StoreApplyOperation =
            serde_json::from_slice(original_bytes.expose())
                .map_err(|error| error.to_string())?;
        if canonical_json_bytes(&operation).map_err(|error| error.to_string())?
            != original_bytes.expose()
            || eliot_store_api::prepared_transition_digest(&operation.transition)
                .map_err(|error| error.to_string())?
                != token.prepared_transition_sha256
            || operation.context.state_fence != state_fence
            || operation.transition.identity.operation_id.as_str() != token.operation_id.as_str()
        {
            return Err("retained Observe operation differs from its reservation token".to_owned());
        }
        let input = Self::retained_observe_reservation_input(&host_record, &operation)?
            .ok_or_else(|| "retained Observe operation has no executable input".to_owned())?;
        let original_submission = operation
            .original_write_submission
            .as_ref()
            .ok_or_else(|| "retained Observe operation has no original write source".to_owned())?
            .clone();
        self.validate_original_write_submission_source(&host_record, &original_submission)
            .map_err(|error| format!("retained Observe source failed validation: {error}"))?;
        if staged_access != input.protected_envelope.privacy_and_visibility_class
            || input.payload_sha256 != host_record.payload_digest
        {
            return Err("retained Observe protected input does not match its owner row".to_owned());
        }
        let receipt = match gateway
            .receipt(
                &state_fence,
                operation.transition.identity.operation_id.clone(),
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(_) => return Ok(()),
        };
        if receipt.is_none()
            && !matches!(
                reservation.state,
                ReservationState::Reserved | ReservationState::Eligible
            )
        {
            return Ok(());
        }
        gateway
            .restore_staged_reserved(
                &operation.context,
                operation.transition,
                operation.expected_revision_heads,
                operation.expected_ordering_heads,
                &original_submission,
                token.clone(),
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Observes the three independent canonical-Store facts and refuses
    /// canonical-sensitive authority unless all three hold (issue #1681,
    /// I14.11, I14.20).
    ///
    /// Each fact is read from its own owner and recorded in its own field:
    ///
    /// - **connectivity** from the retained-gateway owner. A poisoned owner
    ///   is [`StoreConnectivity::Unreadable`], which is *not* the same answer
    ///   as the clean [`StoreConnectivity::Detached`] absence. This is the
    ///   `Path::exists` distinction made explicit: a denied traversal, a
    ///   poisoned lock and an empty slot are three different facts, and only
    ///   the last is a proven negative.
    /// - **process readiness** from the Store's own bounded health round trip
    ///   over that transport. A Store that declines to answer is
    ///   [`StoreProcessReadiness::Unreadable`], not `NotReady`: a timeout is
    ///   not evidence that the process is not running. It is an observation
    ///   *through* that transport rather than an independent one, and
    ///   [`StoreProcessReadiness`] says plainly what this producer therefore
    ///   cannot reach.
    /// - **semantic freshness** from the Store's own validated snapshot
    ///   compared against the caller's *current* request fence. A snapshot
    ///   bound to a different fence is [`StoreSemanticFreshness::Stale`],
    ///   which is refused; it is never served and never read as an outage.
    ///
    /// On success it returns the two owner-issued values the readiness receipt
    /// cites, taken from those same two round trips. Proving the three facts
    /// therefore costs no additional Store IO.
    ///
    /// The whole observation is bounded and performs no waiting beyond the two
    /// bounded Store round trips the readiness proof already performed, and it
    /// holds no lock across either of them: the gateway `Arc` is cloned out of
    /// its owner inside a block whose closing brace ends the guard's scope, so
    /// the release is structural rather than a `drop()` call. Control
    /// and cancellation therefore stay responsive during an outage — nothing
    /// here waits on a reconnect, and no control-reserve slot is drawn.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreFactRefusal`] naming the first owner that has not
    /// established its fact. The refusal is returned rather than a boolean or
    /// a bare `Unavailable`, so the caller can tell an absent transport from
    /// an unreadable owner and stale truth from a Store that is not running.
    #[cfg(windows)]
    pub async fn observe_canonical_store_availability(
        &self,
        request_fence: &eliot_contracts::StateFence,
    ) -> Result<StoreTruthEvidence, StoreFactRefusal> {
        // F-LOG-KERNEL-2 (#899): Store availability phases only; no operation,
        // digest, process, job or owner-error material is emitted.
        //
        // The record is always COMPLETE before the decision is taken: every
        // one of the three fields is assigned on every path, and a fact that
        // could not be read is recorded unreadable rather than left defaulted
        // or inferred from its neighbour. Only then does the single fail-closed
        // predicate decide.
        // The owner guard is held inside this block ONLY, and the only thing
        // that leaves it is a cloned `Arc`. The guard's lifetime therefore
        // ends at the closing brace the compiler can see, not at a `drop()`
        // call it has to reason about: both bounded Store round trips below
        // happen with the lock provably released, so control and cancellation
        // stay responsive during an outage.
        let gateway = {
            let Ok(retained) = self.canonical_store_gateway.lock() else {
                // Inability to read the owner is not absence. The composition
                // cannot prove a transport is missing, so connectivity is
                // recorded unreadable and both downstream facts are recorded
                // unreadable rather than being inferred from it.
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.availability:connectivity_owner_unreadable",
                );
                return Err(Self::refuse_on_connectivity(StoreConnectivity::Unreadable(
                    StoreOwnerUnreadable::GatewayOwnerPoisoned,
                )));
            };
            let Some(gateway) = retained.clone() else {
                // A clean absence: the owner answered and holds nothing. That
                // is the only clean absence in this observation, and the
                // downstream facts are recorded unreadable rather than absent,
                // because nothing was asked of an owner that does not exist.
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.availability:connectivity_detached",
                );
                return Err(Self::refuse_on_connectivity(StoreConnectivity::Detached));
            };
            // A fenced gateway belongs to a superseded generation awaiting
            // replacement. That is present-but-closed, a different fact from
            // "no transport", and I14.11 item 7 forbids reading it as restored.
            if gateway.is_fenced() {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.availability:connectivity_fenced",
                );
                return Err(Self::refuse_on_connectivity(StoreConnectivity::Fenced));
            }
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.availability:connectivity_attached",
            );
            gateway
        };
        let (availability, evidence) =
            Self::observe_store_facts_through_transport(&gateway, request_fence).await?;
        availability.refuse_canonical_sensitive_authority()?;
        Ok(evidence)
    }

    /// Observes the two facts that are only reachable THROUGH an attached
    /// transport and returns the complete record with the owner-issued
    /// evidence (#1681).
    ///
    /// This is the second half of
    /// [`Self::observe_canonical_store_availability`], split out so the
    /// connectivity decision and the transport-borne decision stay readable
    /// apart. It is reachable only once the retained owner was read and held an
    /// unfenced transport, and it records that `Attached` connectivity rather
    /// than re-deciding it: neither of the two facts below is observable
    /// without a transport to ask through, so they are returned together with
    /// the connectivity they were observed under.
    ///
    /// Both facts are the Store's own answers and the evidence is taken from
    /// those same two bounded round trips, so proving them costs no additional
    /// Store IO. No lock is held here and none can be: the caller passed a
    /// gateway cloned out of an owner guard whose scope ended at a block brace
    /// before this helper was entered.
    #[cfg(windows)]
    async fn observe_store_facts_through_transport(
        gateway: &KernelStoreGateway,
        request_fence: &eliot_contracts::StateFence,
    ) -> Result<(CanonicalStoreAvailability, StoreTruthEvidence), StoreFactRefusal> {
        let (process_readiness, health) = if let Ok(health) = gateway.health().await {
            let readiness = if health.status == eliot_store_api::StoreHealthStatus::Ready {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.availability:process_ready",
                );
                StoreProcessReadiness::Ready
            } else {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.availability:process_not_ready",
                );
                StoreProcessReadiness::NotReady
            };
            (readiness, health)
        } else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.availability:process_owner_unreadable",
            );
            return Err(Self::refuse_on(
                StoreProcessReadiness::Unreadable(StoreOwnerUnreadable::StoreDidNotAnswer),
                StoreSemanticFreshness::Unreadable(StoreOwnerUnreadable::StoreDidNotAnswer),
            ));
        };
        let Ok(snapshot) = gateway.validation_snapshot().await else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.availability:freshness_owner_unreadable",
            );
            return Err(Self::refuse_on(
                process_readiness,
                StoreSemanticFreshness::Unreadable(StoreOwnerUnreadable::StoreDidNotAnswer),
            ));
        };
        // The snapshot is validated through the Store's own existing
        // `validate()`; no digest is recomputed here to make a comparison
        // succeed. An answer its owner rejects is not a usable observation, so
        // freshness is unreadable rather than fresh.
        if snapshot.validate().is_err() {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.availability:freshness_owner_unreadable",
            );
            return Err(Self::refuse_on(
                process_readiness,
                StoreSemanticFreshness::Unreadable(StoreOwnerUnreadable::StoreAnswerInvalid),
            ));
        }
        // Freshness is judged against the authority tuple and the resource
        // generation of the fence the caller presented *now*, using the
        // contract's own exact-tuple rule (`authorizes_canonical`) rather than
        // a whole-struct comparison: the Store snapshot carries additional
        // revision fields the caller's presented fence legitimately leaves
        // unset, and comparing those would report a fresh Store as stale.
        // A snapshot outside that tuple is stale truth: refused, named as
        // stale, and never reported as an outage.
        let semantic_freshness = if eliot_contracts::StateFence::authorizes_canonical(
            &snapshot.state_fence.authority_epoch,
            &request_fence.authority_epoch,
        ) && snapshot.state_fence.resource_generation
            == request_fence.resource_generation
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.availability:fresh",
            );
            StoreSemanticFreshness::Fresh
        } else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.availability:stale",
            );
            StoreSemanticFreshness::Stale
        };
        // Complete again: connectivity is `Attached` because this helper is
        // only reached after the retained owner was read and held an unfenced
        // transport, and the two facts above are assigned on every path. The
        // single fail-closed predicate the caller applies decides; nothing here
        // consults only a subset of the three.
        let availability = CanonicalStoreAvailability {
            connectivity: StoreConnectivity::Attached,
            process_readiness,
            semantic_freshness,
        };
        Ok((
            availability,
            StoreTruthEvidence {
                // The health object is the Store's own neutral observation and
                // was already validated by the gateway before it was returned;
                // its recorded manifest digest is cited verbatim.
                manifest_digest: health.manifest_digest,
                validation_revision: snapshot.validation_revision,
            },
        ))
    }

    /// Fails closed on a connectivity fact alone, recording the two downstream
    /// facts as unreadable rather than as absences.
    ///
    /// There is no transport to ask the Store through, so nothing has been
    /// observed about the process or its semantic truth. Recording those two
    /// as absent would assert a negative nobody measured; recording them as
    /// fresh would grant authority on unread truth. They are recorded
    /// unreadable, and the connectivity fact is the one that decides.
    #[cfg(windows)]
    fn refuse_on_connectivity(connectivity: StoreConnectivity) -> StoreFactRefusal {
        let record = CanonicalStoreAvailability {
            connectivity,
            process_readiness: StoreProcessReadiness::Unreadable(
                StoreOwnerUnreadable::NoTransportToQuery,
            ),
            semantic_freshness: StoreSemanticFreshness::Unreadable(
                StoreOwnerUnreadable::NoTransportToQuery,
            ),
        };
        // Every non-`Attached` connectivity arm is a refusal, so the predicate
        // decides. The fallback is a defensive arm rather than an expected
        // path, and it still refuses: no edit to this function can turn an
        // unestablished record into a success.
        if let Err(refusal) = record.refuse_canonical_sensitive_authority() {
            refusal
        } else {
            StoreFactRefusal::NotEstablished {
                owner: StoreFactOwner::Connectivity,
                reason: StoreFactNotEstablished::NoRetainedTransport,
            }
        }
    }

    /// Fails closed on a record whose connectivity is established but whose
    /// later facts are not yet established.
    ///
    /// The record is still complete — every field is assigned — and the one
    /// fail-closed predicate decides which owner is named, so this helper adds
    /// no decision logic of its own.
    #[cfg(windows)]
    fn refuse_on(
        process_readiness: StoreProcessReadiness,
        semantic_freshness: StoreSemanticFreshness,
    ) -> StoreFactRefusal {
        let record = CanonicalStoreAvailability {
            connectivity: StoreConnectivity::Attached,
            process_readiness,
            semantic_freshness,
        };
        if let Err(refusal) = record.refuse_canonical_sensitive_authority() {
            refusal
        } else {
            StoreFactRefusal::NotEstablished {
                owner: StoreFactOwner::SemanticFreshness,
                reason: StoreFactNotEstablished::SemanticTruthStale,
            }
        }
    }

    pub(crate) fn claim_canonical_store_slot(&self) -> Result<(), KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): slot-claim phase only; the outer connect
        // owns the terminal. No gateway/pipe material is emitted.
        if self
            .canonical_store_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.slot_claimed",
            );
            Ok(())
        } else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.slot_already_claimed",
            );
            Err(KernelBuildError::StoreAlreadyConnected)
        }
    }
}

/// Pure cell 3/6 store-rebind predicates over `eliot_ors` replay records and
/// `eliot_kernel_service` handoffs. No `self`, no composition privates; the
/// `rebind_store` transaction body stays whole in `lib`.
#[cfg(windows)]
pub(crate) fn store_rebind_record_matches(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    // F-LOG-KERNEL-2 (#899): rebind-identity phase only; no operation/
    // digest/process/job material is emitted, only the fixed match outcome.
    let matched = record.operation_id.as_str() == handoff.operation_id.as_str()
        && record.request_digest == request_digest
        && record.candidate_binding_digest == handoff.candidate_binding_digest
        && record.store_fence == handoff.store_fence
        && record.requirement_digest == requirement_digest
        && record.process_id == handoff.process_binding.process.process_id
        && record.process_start_time_100ns == handoff.process_binding.process.start_time_100ns
        && record.process_image_path == handoff.process_binding.process.image_path
        && record.job_name == handoff.process_binding.job.as_str()
        && record.generation == handoff.generation.value()
        && record.authority_epoch == handoff.authority_epoch.sequence.get();
    if matched {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_record_matched",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_record_mismatched",
        );
    }
    matched
}

#[cfg(windows)]
pub(crate) fn store_rebind_record_is_committed(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    // F-LOG-KERNEL-2 (#899): committed-readback phase only; exact committed
    // replay is readback, not another mutation.
    let committed =
        store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
            && record.state == eliot_ors::StoreRebindReplayState::Committed
            && record.receipt.as_deref() == Some(request_digest);
    if committed {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_committed",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_not_committed",
        );
    }
    committed
}

#[cfg(windows)]
pub(crate) fn store_rebind_record_is_pending(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    // F-LOG-KERNEL-2 (#899): pending-uncertainty phase only; a timeout after
    // possible submission stays unknown under the same identity.
    let pending = store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
        && record.state == eliot_ors::StoreRebindReplayState::Pending
        && record.receipt.is_none();
    if pending {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_pending_unknown",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_not_pending",
        );
    }
    pending
}

#[cfg(windows)]
pub(crate) fn store_rebind_receipt_from_ors_record(
    record: &eliot_ors::StoreRebindReplayRecord,
    expected_epoch: &eliot_contracts::EpochId,
) -> Result<eliot_kernel_service::StoreRebindReceipt, KernelBuildError> {
    // F-LOG-KERNEL-2 (#899): committed-receipt validation phases only; stale/
    // foreign receipts never emit success. No record material is emitted.
    if record.state != eliot_ors::StoreRebindReplayState::Committed
        || record.receipt.as_deref() != Some(record.request_digest.as_str())
    {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_receipt_rejected:not_committed",
        );
        return Err(KernelBuildError::Service(
            "ORS Store rebind record is not an exact committed receipt".to_owned(),
        ));
    }
    if record.authority_epoch != expected_epoch.sequence.get() {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_receipt_rejected:foreign_epoch",
        );
        return Err(KernelBuildError::Service(
            "ORS Store rebind record epoch does not match the expected lineage sequence".to_owned(),
        ));
    }
    let receipt = eliot_kernel_service::StoreRebindReceipt {
        operation_id: PlatformHandle::new(record.operation_id.as_str())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        request_digest: record.request_digest.clone(),
        requirement_digest: record.requirement_digest.clone(),
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: eliot_kernel_service::HostProcessBinding {
                process_id: record.process_id,
                start_time_100ns: record.process_start_time_100ns,
                image_path: record.process_image_path.clone(),
            },
            job: PlatformHandle::new(record.job_name.clone())
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        },
        candidate_binding_digest: record.candidate_binding_digest.clone(),
        generation: ResourceGeneration::new(record.generation)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        authority_epoch: expected_epoch.clone(),
        store_fence: record.store_fence.clone(),
    };
    receipt.validate().map_err(|error| {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_receipt_rejected:invalid",
        );
        KernelBuildError::Service(error.to_string())
    })?;
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.rebind_receipt_validated",
    );
    Ok(receipt)
}

#[cfg(windows)]
#[allow(clippy::unwrap_used)]
pub(crate) fn is_store_rebind_latest_committed(
    ors: &eliot_ors::RedbRecoveryStore,
    record: &eliot_ors::StoreRebindReplayRecord,
) -> Result<bool, KernelBuildError> {
    // F-LOG-KERNEL-2 (#899): latest-commit phases only; superseded commits
    // never emit success. No record material is emitted.
    let all = ors
        .load_all_store_rebinds()
        .map_err(|e| KernelBuildError::Service(e.to_string()))?;
    let committed: Vec<_> = all
        .iter()
        .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Committed)
        .collect();
    if committed.is_empty() {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_latest:sole",
        );
        return Ok(true);
    }
    let same_lineage_zeros = committed
        .iter()
        .filter(|r| {
            r.commit_order == 0
                && r.requirement_digest == record.requirement_digest
                && r.generation == record.generation
                && r.authority_epoch == record.authority_epoch
        })
        .count();
    if same_lineage_zeros > 1 {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_latest_rejected:migration",
        );
        return Err(KernelBuildError::Service(
            "Store rebind legacy commit order requires migration/recovery".to_owned(),
        ));
    }
    let legacy_zeros = committed.iter().filter(|r| r.commit_order == 0).count();
    if legacy_zeros > 1 && record.commit_order == 0 {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_superseded",
        );
        return Ok(false);
    }
    if record.commit_order == 0 {
        let max_order = committed.iter().map(|r| r.commit_order).max().unwrap_or(0);
        if max_order > 0 {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.rebind_superseded",
            );
            return Ok(false);
        }
    }
    let latest = committed
        .iter()
        .max_by_key(|r| {
            (
                r.commit_order,
                r.operation_id.as_str().to_owned(),
                r.request_digest.clone(),
            )
        })
        .unwrap();
    let is_latest = latest.commit_order == record.commit_order
        && latest.operation_id == record.operation_id
        && latest.request_digest == record.request_digest;
    if is_latest {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_latest",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_superseded",
        );
    }
    Ok(is_latest)
}

/// The independent owner of one canonical-Store availability fact (#1681).
///
/// I14.11 speaks of "the canonical Store is unavailable" as if that were one
/// condition. It is not. Whether a transport is attached, whether the Store
/// process behind it is ready, and whether the Store's semantic truth is
/// fresh under the current request fence are three separately owned facts.
/// Reporting all three as "outage" — or all three as "ready" — destroys the
/// distinction the caller needs in order to know whether to retry, wait, or
/// reconcile. This enum is the vocabulary that keeps them apart.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFactOwner {
    /// The retained Store transport (the Kernel gateway attachment).
    Connectivity,
    /// The Store process behind that transport.
    ProcessReadiness,
    /// The Store's semantic truth under the current request fence.
    SemanticFreshness,
}

#[cfg(windows)]
impl StoreFactOwner {
    /// Bounded owner code carried in refusals and diagnostics (I15.4).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connectivity => "store_connectivity",
            Self::ProcessReadiness => "store_process_readiness",
            Self::SemanticFreshness => "store_semantic_freshness",
        }
    }
}

/// Why one availability fact's owner could not be read.
///
/// An unreadable owner is NOT a clean absence and is NOT readiness. It defers
/// the decision and names itself, so the caller learns which observation is
/// missing instead of learning the word "outage". A poisoned composition
/// mutex and a Store that declined to answer are both unreadable here, and
/// neither may be reported as a proven negative.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOwnerUnreadable {
    /// The composition could not read its own retained-gateway owner.
    GatewayOwnerPoisoned,
    /// The Store did not complete a bounded round trip, so every fact behind
    /// that transport is unknown rather than false.
    StoreDidNotAnswer,
    /// The Store answered with material its own `validate()` rejected, so the
    /// answer is not a usable observation.
    StoreAnswerInvalid,
    /// There is no transport to ask the Store through, so nothing was
    /// observed about this owner. This is distinct from a measured negative:
    /// the fact was never reachable, not observed and found false.
    NoTransportToQuery,
}

#[cfg(windows)]
impl StoreOwnerUnreadable {
    /// Bounded reason code (I15.4).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GatewayOwnerPoisoned => "gateway_owner_poisoned",
            Self::StoreDidNotAnswer => "store_did_not_answer",
            Self::StoreAnswerInvalid => "store_answer_invalid",
            Self::NoTransportToQuery => "no_transport_to_query",
        }
    }
}

/// Why one availability fact was read and does not hold.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFactNotEstablished {
    /// The retained-gateway owner was readable and holds no transport. This is
    /// the only fact in this module that is a clean absence, and it is clean
    /// only because the owner answered.
    NoRetainedTransport,
    /// A transport is attached but belongs to a superseded generation. I14.11
    /// item 7: a rebound socket must not reactivate a closed generation's
    /// canonical work, so this is a refusal and not a partial success.
    SupersededGeneration,
    /// The Store process answered a bounded round trip and reported itself
    /// not ready.
    ProcessNotReady,
    /// The Store answered under a State Fence that is not the caller's
    /// current request fence. Its semantic truth is stale, not absent, and
    /// stale truth is refused rather than served.
    SemanticTruthStale,
}

#[cfg(windows)]
impl StoreFactNotEstablished {
    /// Bounded reason code (I15.4).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRetainedTransport => "no_retained_store_transport",
            Self::SupersededGeneration => "store_generation_superseded",
            Self::ProcessNotReady => "store_process_not_ready",
            Self::SemanticTruthStale => "store_semantic_truth_stale",
        }
    }
}

/// The connectivity fact: is a Store transport attached to this composition?
///
/// `Attached` is the only state that carries no claim about the process or its
/// semantic truth. `Detached` is a proven absence, and it is only ever
/// reported by an owner that was actually read. `Fenced` is present-but-closed:
/// the transport exists and belongs to a superseded generation, which I14.11
/// item 7 forbids treating as restored.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreConnectivity {
    /// A retained, unfenced Store gateway is attached.
    Attached,
    /// The retained-gateway owner was read and holds no transport.
    Detached,
    /// The retained gateway belongs to a superseded generation and is fenced
    /// against new canonical work.
    Fenced,
    /// The owner could not be read. Never a clean absence, never readiness.
    Unreadable(StoreOwnerUnreadable),
}

/// The process-readiness fact: is the Store process behind that transport
/// ready to serve?
///
/// **This producer cannot read this fact independently, and the doc must not
/// imply that it can.** Readiness is read from `gateway.health()` — a round
/// trip *through* the attached transport — so `NotReady` is only ever observed
/// while connectivity is `Attached`, and the "process running behind a detached
/// transport" case is unreachable through this observation. The vocabulary
/// keeps the three facts apart because a caller must be able to tell them
/// apart; it does not promise that this producer can read them apart on its
/// own. Connectivity and readiness can still arrive together here, and a
/// caller that needs them independent needs the owner named below.
///
/// The genuinely independent source is the Job peer observation —
/// `observe_named_pipe_peer_process_in_job` against the retained handoff
/// binding — which reads the process without going through the transport.
/// Making that the owner of this fact is a later increment's work; it is named
/// here so the next reader does not read the stronger claim into this type.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreProcessReadiness {
    /// The Store answered a bounded round trip and reported itself ready.
    Ready,
    /// The Store answered and reported itself degraded or unavailable.
    NotReady,
    /// The owner could not be read, so readiness is unknown rather than false.
    Unreadable(StoreOwnerUnreadable),
}

/// The semantic-freshness fact: is the Store's semantic truth fresh under the
/// caller's CURRENT request fence?
///
/// This is the fact a canonical-sensitive decision turns on, and it is the one
/// a running process says nothing about. I14.11 requires stale truth to be
/// refused; `Stale` is therefore a refusal state and never a degraded-but-
/// acceptable one.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreSemanticFreshness {
    /// The Store's own validated snapshot is bound to the current request
    /// fence.
    Fresh,
    /// The Store's snapshot is bound to a different fence than the one the
    /// caller presented.
    Stale,
    /// The owner could not be read, so freshness is unknown rather than stale
    /// and rather than fresh.
    Unreadable(StoreOwnerUnreadable),
}

/// The three independent canonical-Store facts, recorded separately.
///
/// This is deliberately not a `bool` and deliberately not a single `Ready`
/// verdict: each field keeps its own state, and
/// [`Self::refuse_canonical_sensitive_authority`] fails closed by naming the
/// first owner that has not established its fact.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalStoreAvailability {
    /// Whether a Store transport is attached.
    pub connectivity: StoreConnectivity,
    /// Whether the Store process behind it is ready.
    pub process_readiness: StoreProcessReadiness,
    /// Whether its semantic truth is fresh under the current request fence.
    pub semantic_freshness: StoreSemanticFreshness,
}

/// The two owner-issued values a readiness receipt cites once all three Store
/// facts hold.
///
/// Both are the Store's OWN recorded values, taken from the same bounded round
/// trips that proved the facts. Neither is recomputed, re-derived or
/// substituted: the point of carrying them is that a caller can cite the exact
/// evidence the refusal decision was taken against without paying for a second
/// Store read.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreTruthEvidence {
    /// The Store-reported operation-manifest digest from its health
    /// observation.
    pub manifest_digest: eliot_store_api::OperationManifestDigest,
    /// The Store-reported canonical validation revision from the validated
    /// snapshot whose fence matched the current request fence.
    pub validation_revision: u64,
}

/// A fail-closed refusal of canonical-sensitive authority that names the owner
/// whose fact is missing.
///
/// It is a refusal, not a fault: the caller learns exactly which of the three
/// facts could not be established, so a stale-truth refusal is never read as
/// an outage and an unreadable owner is never read as a proven negative.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFactRefusal {
    /// The owner was read and its fact does not hold.
    NotEstablished {
        /// The owner whose fact does not hold.
        owner: StoreFactOwner,
        /// Why it does not hold.
        reason: StoreFactNotEstablished,
    },
    /// The owner could not be read, so the fact is unknown. The decision
    /// defers and names the owner; it never assumes the fact holds and never
    /// assumes it fails.
    OwnerUnreadable {
        /// The owner that could not be read.
        owner: StoreFactOwner,
        /// Why it could not be read.
        reason: StoreOwnerUnreadable,
    },
}

#[cfg(windows)]
impl StoreFactRefusal {
    /// The owner whose fact blocked the decision.
    #[must_use]
    pub const fn owner(self) -> StoreFactOwner {
        match self {
            Self::NotEstablished { owner, .. } | Self::OwnerUnreadable { owner, .. } => owner,
        }
    }

    /// Projects the refusal onto the closed existing Kernel service error
    /// vocabulary.
    ///
    /// The projection is typed, not prose: the owner and the bounded reason
    /// survive as the variant's own fields, and the stale-truth case keeps the
    /// existing `HandshakeMismatch` fence-mismatch shape it already had, so no
    /// consumer learns a new string. Nothing here grants, retries, or
    /// re-observes anything.
    #[must_use]
    pub const fn kernel_service_error(self) -> super::KernelServiceError {
        match self {
            Self::NotEstablished {
                reason: StoreFactNotEstablished::SemanticTruthStale,
                ..
            } => super::KernelServiceError::HandshakeMismatch {
                field: "store_semantic_freshness",
            },
            Self::NotEstablished { owner, reason } => super::KernelServiceError::InvalidField {
                field: owner.as_str(),
                reason: reason.as_str(),
            },
            Self::OwnerUnreadable { owner, reason } => super::KernelServiceError::InvalidField {
                field: owner.as_str(),
                reason: reason.as_str(),
            },
        }
    }
}

#[cfg(windows)]
impl fmt::Display for StoreFactRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEstablished { owner, reason } => {
                write!(
                    formatter,
                    "{} not established: {}",
                    owner.as_str(),
                    reason.as_str()
                )
            }
            Self::OwnerUnreadable { owner, reason } => {
                write!(
                    formatter,
                    "{} owner unreadable: {}",
                    owner.as_str(),
                    reason.as_str()
                )
            }
        }
    }
}

#[cfg(windows)]
impl std::error::Error for StoreFactRefusal {}

#[cfg(windows)]
impl CanonicalStoreAvailability {
    /// Refuses canonical-sensitive authority unless all three facts hold.
    ///
    /// The record is taken by value: the three facts pack into three bytes, so
    /// borrowing it would be the more expensive of the two forms for no gain.
    ///
    /// Connectivity is decided first, then process readiness, then semantic
    /// freshness, because each later fact is only observable through the
    /// earlier one. Every arm fails closed: an unreadable owner defers with
    /// its name and is never treated as "nothing changed", and stale truth is
    /// refused rather than served. There is no arm that returns "probably
    /// fine" and no path that consults only a subset of the three.
    pub const fn refuse_canonical_sensitive_authority(self) -> Result<(), StoreFactRefusal> {
        match self.connectivity {
            StoreConnectivity::Unreadable(reason) => {
                return Err(StoreFactRefusal::OwnerUnreadable {
                    owner: StoreFactOwner::Connectivity,
                    reason,
                });
            }
            StoreConnectivity::Detached => {
                return Err(StoreFactRefusal::NotEstablished {
                    owner: StoreFactOwner::Connectivity,
                    reason: StoreFactNotEstablished::NoRetainedTransport,
                });
            }
            StoreConnectivity::Fenced => {
                return Err(StoreFactRefusal::NotEstablished {
                    owner: StoreFactOwner::Connectivity,
                    reason: StoreFactNotEstablished::SupersededGeneration,
                });
            }
            StoreConnectivity::Attached => {}
        }
        match self.process_readiness {
            StoreProcessReadiness::Unreadable(reason) => {
                return Err(StoreFactRefusal::OwnerUnreadable {
                    owner: StoreFactOwner::ProcessReadiness,
                    reason,
                });
            }
            StoreProcessReadiness::NotReady => {
                return Err(StoreFactRefusal::NotEstablished {
                    owner: StoreFactOwner::ProcessReadiness,
                    reason: StoreFactNotEstablished::ProcessNotReady,
                });
            }
            StoreProcessReadiness::Ready => {}
        }
        match self.semantic_freshness {
            StoreSemanticFreshness::Unreadable(reason) => {
                return Err(StoreFactRefusal::OwnerUnreadable {
                    owner: StoreFactOwner::SemanticFreshness,
                    reason,
                });
            }
            StoreSemanticFreshness::Stale => {
                return Err(StoreFactRefusal::NotEstablished {
                    owner: StoreFactOwner::SemanticFreshness,
                    reason: StoreFactNotEstablished::SemanticTruthStale,
                });
            }
            StoreSemanticFreshness::Fresh => {}
        }
        Ok(())
    }
}
