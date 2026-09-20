//! Kernel control-plane transition and authenticated request handling.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md :: A13.2. Kernel и failure domains` keeps Kernel
//!   as the lifecycle and failure boundary for this control path.
//! - `ELIOT_ARCHITECTURE.md :: A13.5. Bounded resources и Control Reserve`
//!   binds control work to the existing protected-control reserve; this module
//!   exposes its capacity without creating a second budget.
//! - `ELIOT_IMPLEMENTATION.md :: P.3. Kernel control boundary` keeps
//!   front-door request admission and lifecycle transitions in Kernel while
//!   service semantics stay behind the existing `KernelService` gateway.
//! - `ELIOT_IMPLEMENTATION.md :: I1.5. Demand-start, observable use,
//!   supervision and idle shutdown` and `I14.13. Idle drain and cancellation`
//!   constrain shutdown to the existing runtime signal and drain owners.
//! - `ELIOT_IMPLEMENTATION.md :: I14.23. Safe shutdown` leaves the complete
//!   cooperative shutdown sequence in `KernelComposition::shutdown`.
//!
//! The implementation remains an ordinary module so the composition root keeps
//! its public API while the control-plane lifecycle gateway has a bounded home.

use super::*;

/// F-LOG-KERNEL-4 (#903): control-plane boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.control.*` event names
/// plus a bounded stable outcome. Never carries request payloads, digests,
/// peer identities, pipe names, or owner error strings (I15.4, I07.20).
fn observe_control(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "control plane observation"
    );
}

/// Maps one control-transition failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload or embedded state is
/// never logged.
fn control_transition_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "CONTROL_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "CONTROL_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "CONTROL_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "CONTROL_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "CONTROL_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "CONTROL_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "CONTROL_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "CONTROL_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "CONTROL_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "CONTROL_PLATFORM",
        KernelServiceError::Core(_) => "CONTROL_CORE",
    }
}

/// Maps one authenticated control-request failure to its stable diagnostic
/// code.
///
/// Only the variant is emitted; any `String` payload is never logged. The
/// `control_` prefix keeps request-operation terminals distinct from other
/// `TransportError` owners (`frame_*`, `daemon_*`).
fn control_request_terminal_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::InvalidLimits => "control_invalid_limits",
        TransportError::UnauthenticatedPeer => "control_unauthenticated_peer",
        TransportError::PeerIdentityUnavailable => "control_peer_unavailable",
        TransportError::Protocol(_) => "control_protocol",
        TransportError::SessionFenced => "control_fenced",
        TransportError::Backpressure => "control_backpressure",
        TransportError::Timeout => "control_timeout",
        TransportError::Cancelled => "control_cancelled",
        TransportError::InvalidPipeName => "control_invalid_pipe",
        TransportError::UnknownOutcome => "control_unknown_outcome",
        TransportError::Io(_) => "control_io",
        TransportError::PlanGap { .. } => "control_plan_gap",
        TransportError::UnknownRequest => "control_unknown_request",
        TransportError::IdentityConflict => "control_identity_conflict",
        TransportError::RegistryFull => "control_registry_full",
    }
}

/// Observes one protected-control capacity read with its bounded count.
///
/// The count is a small nonsecret integer; it is still routed through the
/// bounded field helper so the observation keeps the `MAX_FIELD` shape.
fn observe_control_capacity(capacity: usize) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field("kernel.control.capacity_observed");
    let capacity_bound = bound_field(&capacity.to_string());
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        capacity = capacity_bound.text(),
        "control capacity observation"
    );
}

/// Verifies the independent-supervision (watchdog) branch backing one Windows
/// `ProbeReady` admission: the candidate's supervision incarnation must carry
/// a usable watchdog epoch, and the renewed ORS head behind this probe's
/// supervision lease must carry that exact same epoch.
///
/// Fail-closed `SessionFenced` otherwise: on Windows the Kernel never authors
/// a ready receipt — and never returns a supervision lease — as
/// independently supervised when the watchdog branch is missing or foreign.
/// Per I1.5, Material work requiring independent supervision is then paused
/// (Host degrades the readiness contour into a human-visible coverage gap)
/// instead of being admitted as supervised. Non-Windows builds have no
/// equivalent gate yet (Linux supervision port, I1.7) and therefore emit no
/// supervised readiness at all: `ProbeReady` fails closed below before any
/// receipt or supervision lease is produced.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the verified-watchdog ProbeReady gate has no non-Windows caller until the Linux supervision port lands (I1.7)"
    )
)]
fn verify_probe_watchdog_branch(
    incarnation_watchdog_sequence: u64,
    binding_watchdog_sequence: u64,
) -> Result<(), TransportError> {
    if incarnation_watchdog_sequence == 0
        || binding_watchdog_sequence == 0
        || incarnation_watchdog_sequence != binding_watchdog_sequence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

impl KernelComposition {
    /// Applies one lifecycle command through the sole Kernel transition gateway.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed transition; the admitted state versus the failure
    /// record stay distinct, and no command or error material is logged.
    pub fn apply_control(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        observe_control("kernel.control.transition_requested", "attempt");
        match self.apply_control_inner(command) {
            Ok(state) => {
                observe_control("kernel.control.transition_committed", "success");
                Ok(state)
            }
            Err(error) => {
                observe_control("kernel.control.transition_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(
                    control_transition_terminal_code(&error),
                );
                Err(error)
            }
        }
    }

    /// Transition sequence; every fence check precedes the single service
    /// application. See [`KernelComposition::apply_control`].
    fn apply_control_inner(
        &self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        if let Some(reason) = self
            .generation_poison
            .lock()
            .map_err(|_| {
                KernelServiceError::Platform("generation poison lock poisoned".to_owned())
            })?
            .clone()
        {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        self.service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .apply(command)
    }

    /// Applies one authenticated Host control request after binding the
    /// transport's handle-proven peer and the approved generation contour.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed request with the request operation's own stable
    /// code; failures already terminaled by the transition gateway below
    /// arrive here transformed into the request error, never re-terminaled
    /// under their original value.
    pub async fn apply_control_request(
        &self,
        request: KernelControlRequest,
        peer: &PeerIdentity,
        expected_sequence: u64,
    ) -> Result<KernelControlResponse, TransportError> {
        observe_control("kernel.control.request_received", "attempt");
        match self
            .apply_control_request_inner(request, peer, expected_sequence)
            .await
        {
            Ok(response) => {
                observe_control("kernel.control.request_admitted", "success");
                Ok(response)
            }
            Err(error) => {
                observe_control("kernel.control.request_denied", "rejected");
                super::kernel_diagnostics::observe_terminal_error(control_request_terminal_code(
                    &error,
                ));
                Err(error)
            }
        }
    }

    /// Authenticated validation and command-order sequence; every admission
    /// check precedes the single transition gateway call. See
    /// [`KernelComposition::apply_control_request`].
    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated control handler preserves one visible validation and command-order boundary"
    )]
    async fn apply_control_request_inner(
        &self,
        request: KernelControlRequest,
        peer: &PeerIdentity,
        expected_sequence: u64,
    ) -> Result<KernelControlResponse, TransportError> {
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        peer.validate()?;
        let observed_peer = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if request.sequence != expected_sequence
            || request.peer_process_id != observed_peer.process_id()
            || request.candidate.pipe_identity.as_str() != self.ipc.name()
            || observed_peer.process_id() != request.candidate.host_process.process_id
            || observed_peer.start_time_100ns() != request.candidate.host_process.start_time_100ns
            || observed_peer.image_path() != request.candidate.host_process.image_path
        {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.validate_candidate_process_binding(&request.candidate)
            .map_err(|_| TransportError::SessionFenced)?;
        let bootstrap = match &request.command {
            KernelControlCommand::BootstrapStore(handoff) => Some(handoff.clone()),
            _ => None,
        };
        #[cfg(windows)]
        let _store_rebind_guard = if matches!(
            &request.command,
            KernelControlCommand::BootstrapStore(_)
                | KernelControlCommand::RebindStore(_)
                | KernelControlCommand::ReconcileRebindStore(_)
                | KernelControlCommand::Reconcile
                | KernelControlCommand::ProbeReady
        ) {
            Some(self.store_rebind_gate.lock().await)
        } else {
            None
        };
        #[cfg(windows)]
        self.validate_store_rebind_admission(&request)?;
        {
            let mut policy = self
                .front_door_policy
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let reconcile = matches!(&request.command, KernelControlCommand::Reconcile);
            let policy_epoch = policy.module_generation.state_fence.authority_epoch.clone();
            let epoch_mismatch = {
                let candidate = &request.candidate.kernel_epoch;
                if candidate.is_same_authority(&policy_epoch) {
                    false
                } else if reconcile
                    && candidate.lineage_id == policy_epoch.lineage_id
                    && candidate.sequence.get() > policy_epoch.sequence.get()
                {
                    false
                } else {
                    true
                }
            };
            if request.generation != policy.module_generation.generation
                || epoch_mismatch
                || self
                    .kernel_artifact_sha256
                    .as_deref()
                    .is_some_and(|digest| request.candidate.artifact_hash.as_str() != digest)
                || self
                    .approved_config_hash
                    .as_deref()
                    .is_some_and(|hash| hash != request.candidate.config_hash.as_str())
            {
                return Err(TransportError::SessionFenced);
            }
            if !request
                .candidate
                .kernel_epoch
                .is_same_authority(&policy_epoch)
            {
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .synchronize_authority_epoch(request.candidate.kernel_epoch.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                policy.module_generation.state_fence =
                    StateFence::new(request.candidate.kernel_epoch.clone(), request.generation);
            }
        }
        if let Some(handoff) = bootstrap {
            self.install_store_bootstrap(handoff.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if let Err(error) = self
                .connect_canonical_store(Duration::from_millis(handoff.requirement.timeout_ms()))
                .await
            {
                let _ = error;
                return Err(TransportError::SessionFenced);
            }
        }
        // I14.23 wake/attach race: a new activation arriving before the
        // `DrainCommit` linearization point cancels the drain and proceeds;
        // after linearization it cannot reuse the drained generation (the
        // service independently fences `Activate` from `Draining`) and must
        // re-establish a fresh generation through the reconcile path.
        if matches!(&request.command, KernelControlCommand::Activate(_)) {
            // Post-linearization activation cannot reuse the drained
            // generation; the caller re-establishes a fresh generation
            // through the reconcile path.
            if coordinator_for(&self.work_root)
                .on_activate_request()
                .fences_old_authority()
            {
                return Err(TransportError::SessionFenced);
            }
        }
        let store_rebind_receipt: Option<eliot_kernel_service::StoreRebindReceipt> = match &request
            .command
        {
            KernelControlCommand::RebindStore(handoff) => {
                let receipt = self
                    .rebind_store(handoff.clone(), request.payload_digest.clone())
                    .await
                    .map_err(|_| TransportError::SessionFenced)?;
                Some(receipt)
            }
            KernelControlCommand::ReconcileRebindStore(query) => {
                let op_id = eliot_ors::OperationIdentity::new(query.operation_id.as_str())
                    .map_err(|_| TransportError::SessionFenced)?;
                let record = self
                    .generation_gateway
                    .ors
                    .load_store_rebind(&op_id, &query.request_digest)
                    .map_err(|_| TransportError::SessionFenced)?;
                match record {
                    Some(record)
                        if record.state == eliot_ors::StoreRebindReplayState::Committed
                            && record.operation_id.as_str() == query.operation_id.as_str()
                            && record.request_digest == query.request_digest
                            && record.receipt.as_deref() == Some(query.request_digest.as_str()) =>
                    {
                        Self::validate_store_rebind_ors_record_admission(&request, query, &record)?;
                        if !is_store_rebind_latest_committed(&self.generation_gateway.ors, &record)
                            .map_err(|_| TransportError::SessionFenced)?
                        {
                            return Err(TransportError::SessionFenced);
                        }
                        let receipt = store_rebind_receipt_from_ors_record(
                            &record,
                            &request.candidate.kernel_epoch,
                        )
                        .map_err(|_| TransportError::SessionFenced)?;
                        self.verify_store_rebind_publication_complete(&receipt)?;
                        // A reconciled commit resolves the matching drain-gate
                        // receipt when a shutdown is waiting on it.
                        coordinator_for(&self.work_root).resolve_pending_receipt(&format!(
                            "store-rebind:{}",
                            query.operation_id.as_str()
                        ));
                        Some(receipt)
                    }
                    Some(record)
                        if record.state == eliot_ors::StoreRebindReplayState::Pending
                            && record.operation_id.as_str() == query.operation_id.as_str()
                            && record.request_digest == query.request_digest =>
                    {
                        // A Pending ORS row has no terminal outcome.  Resolve
                        // it under the same gate before allowing Host to write
                        // an Aborted disposition; a failed compare-delete or
                        // non-terminal readback remains fenced/unknown.
                        let removed = self
                            .generation_gateway
                            .ors
                            .abort_store_rebind(&op_id, &query.request_digest)
                            .map_err(|_| TransportError::SessionFenced)?;
                        let after = self
                            .generation_gateway
                            .ors
                            .load_store_rebind(&op_id, &query.request_digest)
                            .map_err(|_| TransportError::SessionFenced)?;
                        match (removed, after) {
                            (_, None) => {
                                self.rollback_store_rebind_if_exact_query(query)?;
                                // The abort removed the staged row, resolving
                                // the matching drain-gate receipt if any.
                                coordinator_for(&self.work_root).resolve_pending_receipt(&format!(
                                    "store-rebind:{}",
                                    query.operation_id.as_str()
                                ));
                                None
                            }
                            (_, Some(after))
                                if after.state == eliot_ors::StoreRebindReplayState::Committed
                                    && after.operation_id.as_str()
                                        == query.operation_id.as_str()
                                    && after.request_digest == query.request_digest
                                    && after.receipt.as_deref()
                                        == Some(query.request_digest.as_str()) =>
                            {
                                Self::validate_store_rebind_ors_record_admission(
                                    &request, query, &after,
                                )?;
                                if !is_store_rebind_latest_committed(
                                    &self.generation_gateway.ors,
                                    &after,
                                )
                                .map_err(|_| TransportError::SessionFenced)?
                                {
                                    return Err(TransportError::SessionFenced);
                                }
                                let receipt = store_rebind_receipt_from_ors_record(
                                    &after,
                                    &request.candidate.kernel_epoch,
                                )
                                .map_err(|_| TransportError::SessionFenced)?;
                                self.verify_store_rebind_publication_complete(&receipt)?;
                                // A reconciled commit resolves the matching
                                // drain-gate receipt when a shutdown waits.
                                coordinator_for(&self.work_root).resolve_pending_receipt(&format!(
                                    "store-rebind:{}",
                                    query.operation_id.as_str()
                                ));
                                Some(receipt)
                            }
                            _ => return Err(TransportError::SessionFenced),
                        }
                    }
                    Some(_) => return Err(TransportError::SessionFenced),
                    None => {
                        // A service receipt without an exact durable ORS
                        // commit is intentionally not query-visible. In
                        // particular, this closes the window after service
                        // mutation and before ORS begin/commit; the caller
                        // must retain Pending/Unknown and retry the exact
                        // operation instead of terminalizing from volatile
                        // memory.
                        self.rollback_store_rebind_if_exact_query(query)?;
                        None
                    }
                }
            }
            _ => None,
        };
        let is_probe = matches!(&request.command, KernelControlCommand::ProbeReady);
        #[cfg(windows)]
        let supervision_publication = if is_probe {
            Some(
                self.renew_daemon_supervision_for_probe(&request)
                    .map_err(|_| TransportError::SessionFenced)?,
            )
        } else {
            None
        };
        #[cfg(windows)]
        let supervision_lease = supervision_publication
            .as_ref()
            .map(|(snapshot, _)| snapshot.clone());
        #[cfg(not(windows))]
        let supervision_lease = None;
        #[cfg(windows)]
        if let Some((renewed_head, _)) = supervision_publication.as_ref() {
            // I1.5 (#1750, Windows-only gate): the ProbeReady admission never
            // proceeds as independently supervised without the verified
            // watchdog branch. This runs before any ready receipt is authored,
            // and the readbacks below confirm the gated head is still current,
            // so a refusal surfaces as degraded readiness instead of
            // supervised health. Non-Windows builds never reach a supervised
            // admission: ProbeReady fails closed below (I1.7).
            verify_probe_watchdog_branch(
                request
                    .candidate
                    .supervision_incarnation
                    .watchdog_epoch
                    .sequence,
                renewed_head.record.binding.watchdog_epoch.value(),
            )?;
        }
        let receipt = if is_probe {
            #[cfg(windows)]
            {
                Some(
                    self.self_authored_ready_receipt(&request, peer)
                        .await
                        .map_err(|_| TransportError::SessionFenced)?,
                )
            }
            #[cfg(not(windows))]
            {
                // Containment (I1.7): without the verified watchdog-branch gate
                // there is no equivalent supervision proof on this platform, so
                // no ready receipt — and no supervised-readiness claim of any
                // kind — may be emitted here.
                return Err(TransportError::SessionFenced);
            }
        } else {
            None
        };
        #[cfg(windows)]
        if let Some((expected, expected_live_receipt)) = supervision_publication.as_ref() {
            let after = self
                .supervision_lease_authority
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .current_snapshot(
                    &request
                        .candidate
                        .supervision_incarnation
                        .supervision_lease_id,
                )
                .map_err(|_| TransportError::SessionFenced)?;
            if after.as_ref() != Some(expected) {
                return Err(TransportError::SessionFenced);
            }
            self.verify_published_eliotd_live_receipt(expected_live_receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            let after_receipt_readback = self
                .supervision_lease_authority
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .current_snapshot(
                    &request
                        .candidate
                        .supervision_incarnation
                        .supervision_lease_id,
                )
                .map_err(|_| TransportError::SessionFenced)?;
            if after_receipt_readback.as_ref() != Some(expected) {
                return Err(TransportError::SessionFenced);
            }
        }
        #[cfg(windows)]
        let prepared_bridge_profile = if matches!(
            &request.command,
            KernelControlCommand::Activate(_) | KernelControlCommand::ProbeReady
        ) {
            Some(Self::prepare_agent_bridge_admission(
                request.candidate.agent_bridge_admission.as_ref(),
            )?)
        } else {
            None
        };
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::Activate(_)) {
            // A new candidate immediately revokes the prior bridge lineage;
            // it is republished only after this candidate reaches Ready.
            self.promote_agent_bridge_profile(None)?;
        }
        let activation_receipt: Option<KernelActivationReceipt> = match &request.command {
            KernelControlCommand::Activate(permit) => Some(
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .activate_permit(permit, request.generation, request.payload_digest.clone())
                    .map_err(|_| TransportError::SessionFenced)?,
            ),
            KernelControlCommand::ReconcileActivation(query) => self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .reconcile_activation(query)
                .map_err(|_| TransportError::SessionFenced)?,
            _ => None,
        };
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::Activate(_))
            && self
                .active_daemon_launch()
                .map_err(|_| TransportError::SessionFenced)?
                .is_some()
        {
            let launched = self
                .launch_eliotd()
                .await
                .map_err(|_| TransportError::SessionFenced)?;
            self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout)
                .await
                .map_err(|_| TransportError::SessionFenced)?;
        }
        if let Some(receipt) = &receipt {
            self.service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .publish_ready(receipt.clone())
                .map_err(|_| TransportError::SessionFenced)?;
        } else {
            match &request.command {
                KernelControlCommand::Reconcile => self
                    .service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .reconcile(request.candidate.clone())
                    .map_err(|_| TransportError::SessionFenced)?,
                KernelControlCommand::BootstrapStore(_)
                | KernelControlCommand::Activate(_)
                | KernelControlCommand::ReconcileActivation(_)
                | KernelControlCommand::RebindStore(_)
                | KernelControlCommand::ReconcileRebindStore(_) => {}
                command => {
                    self.apply_control(command.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                }
            }
        }
        #[cfg(windows)]
        if matches!(&request.command, KernelControlCommand::ProbeReady)
            && let Some(next) = prepared_bridge_profile
        {
            self.promote_agent_bridge_profile(next)?;
        }
        let state = self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?;
        KernelControlResponse {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id: request.message_id,
            request_digest: request.payload_digest,
            state,
            receipt,
            activation_receipt,
            store_rebind_receipt,
            supervision_lease,
            error: None,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)
    }

    /// Returns the runtime's protected-control capacity.
    ///
    /// Diagnostic read (F-LOG-KERNEL-4, #903): the observed count is emitted
    /// as a bounded nonsecret field; the reserve itself is never acquired,
    /// released, or resized here.
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        let capacity = self
            .runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl);
        observe_control_capacity(capacity);
        capacity
    }

    /// Requests shutdown without starting a second lifecycle owner.
    ///
    /// Records the Kernel-owned I14.23 drain intent (persisted, resumable)
    /// before closing runtime admission, so a later `shutdown()` observes
    /// the request even when admission closure wins the race.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        let _ = coordinator_for(&self.work_root).request_shutdown();
        self.runtime.shutdown_handle().request()
    }
}

#[cfg(test)]
mod control_plane_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903) focused diagnostics proof: stable terminal
    //! codes for the transition gateway and the authenticated request
    //! boundary. Both mappers emit variant vocabulary only; payloads,
    //! digests, and peer material never reach the sink.

    use super::*;

    #[test]
    fn probe_watchdog_branch_requires_exact_nonzero_epoch() {
        assert!(verify_probe_watchdog_branch(7, 7).is_ok());
        assert_eq!(
            verify_probe_watchdog_branch(7, 8),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(
            verify_probe_watchdog_branch(0, 7),
            Err(TransportError::SessionFenced)
        );
        assert_eq!(
            verify_probe_watchdog_branch(7, 0),
            Err(TransportError::SessionFenced)
        );
    }

    #[test]
    fn control_diagnostics_terminal_codes_are_stable() {
        // Transition gateway codes: one fixed code per service failure
        // variant, even when the payload carries a secret-like canary.
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::GenerationFenced),
            "CONTROL_GENERATION_FENCED"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::ReadinessNotProven),
            "CONTROL_READINESS_NOT_PROVEN"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::MissingContainmentEvidence),
            "CONTROL_MISSING_CONTAINMENT"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::RestartBudgetExhausted),
            "CONTROL_RESTART_BUDGET_EXHAUSTED"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::ControlReserveExhausted),
            "CONTROL_RESERVE_EXHAUSTED"
        );
        assert_eq!(
            control_transition_terminal_code(&KernelServiceError::Platform(
                "token=control-canary".to_owned()
            )),
            "CONTROL_PLATFORM"
        );

        // Request boundary codes: every transport failure keeps its own
        // request-operation code; the fenced admission path keeps the exact
        // typed denial without request material.
        assert_eq!(
            control_request_terminal_code(&TransportError::SessionFenced),
            "control_fenced"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::PeerIdentityUnavailable),
            "control_peer_unavailable"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::UnauthenticatedPeer),
            "control_unauthenticated_peer"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Timeout),
            "control_timeout"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Cancelled),
            "control_cancelled"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::UnknownOutcome),
            "control_unknown_outcome"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Backpressure),
            "control_backpressure"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::RegistryFull),
            "control_registry_full"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::Io("pipe-canary".to_owned())),
            "control_io"
        );
        assert_eq!(
            control_request_terminal_code(&TransportError::PlanGap {
                dependency: "dep",
                reason: "reason",
            }),
            "control_plan_gap"
        );
    }
}
