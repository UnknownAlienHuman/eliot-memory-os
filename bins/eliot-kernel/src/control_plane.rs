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

impl KernelComposition {
    /// Applies one lifecycle command through the sole Kernel transition gateway.
    pub fn apply_control(
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
    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated control handler preserves one visible validation and command-order boundary"
    )]
    pub async fn apply_control_request(
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
            let policy_epoch = policy.module_generation.state_fence.authority_epoch;
            if request.generation != policy.module_generation.generation
                || request.candidate.kernel_epoch.value() < policy_epoch.value()
                || (!reconcile && request.candidate.kernel_epoch != policy_epoch)
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
            if request.candidate.kernel_epoch != policy_epoch {
                self.service
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .synchronize_authority_epoch(request.candidate.kernel_epoch)
                    .map_err(|_| TransportError::SessionFenced)?;
                policy.module_generation.state_fence =
                    StateFence::new(request.candidate.kernel_epoch, request.generation);
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
                        let receipt = store_rebind_receipt_from_ors_record(&record)
                            .map_err(|_| TransportError::SessionFenced)?;
                        self.verify_store_rebind_publication_complete(&receipt)?;
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
                                let receipt = store_rebind_receipt_from_ors_record(&after)
                                    .map_err(|_| TransportError::SessionFenced)?;
                                self.verify_store_rebind_publication_complete(&receipt)?;
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
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }

    /// Requests shutdown without starting a second lifecycle owner.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        self.runtime.shutdown_handle().request()
    }
}
