use super::*;

impl HostComposition {
    #[cfg(windows)]
    pub fn handle_store_recovery_request(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        if request.operation == HostRuntimeControlOperation::ReconcileStoreRecovery {
            return self.reconcile_store_recovery_request(request);
        }
        if self.store_recovery_startup_fence.is_fenced() {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref(STORE_RECOVERY_CRASH_FENCE_UNKNOWN_REASON, request),
            );
        }
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("store-recovery", request),
            );
        }
        let result = self.execute_store_recovery(request);
        match result {
            Ok(receipt) => HostRuntimeControlResponse::store_recovered_for(request, receipt),
            Err(_error) => HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("store-recovery", request),
            ),
        }
    }

    /// Builds the deterministic request identity used by the Host-owned SCM
    /// dead-Store trigger.  This is an internal typed caller of the same
    /// durable operation used by the authenticated runtime-control endpoint;
    /// it does not pass through the external Builtin-Administrators pipe.
    #[cfg(windows)]
    pub(super) fn scm_store_recovery_request(
        &self,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
    ) -> Result<HostRuntimeControlRequest, HostError> {
        host_owned_store_recovery_request(
            &self.host,
            &self.activation_id,
            &self.activation_generation,
            generation,
            config_digest,
        )
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    fn reconcile_committed_store_recovery(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> Result<Option<HostStoreRecoveryReceipt>, HostError> {
        if self.store_recovery_startup_fence.is_fenced()
            && request.operation != HostRuntimeControlOperation::ReconcileStoreRecovery
        {
            return Err(HostError::RecoveryRequired(
                "RecoverStore cannot bypass an unresolved startup fence; reconcile is required"
                    .to_owned(),
            ));
        }
        let key = request.mutation_digest.as_str().to_owned();
        let pending = read_store_recovery_pending_identity(&store_recovery_pending_path(
            self.launch_options.host_state_root(),
            &key,
        ))?;
        let Some(pending) = pending else {
            // A committed inner rebind is only admissible for the exact outer
            // recovery intent.  Without that intent this is an unrelated
            // destination observation, not proof for this request.
            return Ok(None);
        };
        pending.validate_current_request(request)?;
        if pending.host_epoch != self.host.epoch.current.sequence
            || pending.host_lineage != self.host.epoch.current.lineage.as_str()
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery pending identity belongs to another live Host epoch".to_owned(),
            ));
        }
        let termination =
            read_store_recovery_termination_evidence(self.launch_options.host_state_root(), &key)?
                .ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store recovery has no durable exact termination evidence".to_owned(),
                    )
                })?;
        termination.validate_for_pending(&pending)?;
        let inner_binding =
            read_store_recovery_inner_binding(self.launch_options.host_state_root(), &key)?
                .ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store recovery has no durable canonical inner request binding".to_owned(),
                    )
                })?;
        inner_binding.validate_for_pending(&pending, &termination)?;

        let snapshot = self.journal.snapshot()?;
        let kernel = snapshot.kernel.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no durable Kernel record".to_owned(),
            )
        })?;
        if kernel.state != KernelActivationState::Active
            || kernel.one_time_nonce.state() != NonceState::Consumed
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery reconciliation requires the unchanged Active Kernel contour"
                    .to_owned(),
            ));
        }
        let candidate = self.jobs.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no retained Kernel candidate".to_owned(),
            )
        })?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let candidate_authority_epoch = candidate.kernel_epoch;
        let launch = self.jobs.launch.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no runtime launch descriptor".to_owned(),
            )
        })?;
        let active_fence =
            record_fence(&self.host, &self.activation_id, &self.activation_generation);
        let mut committed = snapshot.store_rebinds.iter().filter(|record| {
            record.state == StoreRebindState::Committed
                && record.operation_id.as_str() == inner_binding.store_rebind_operation_id
                && record.request_digest.as_str() == inner_binding.store_rebind_request_digest
                && record.fence == active_fence
                && record.generation == launch.authority_generation.value()
                && record.authority_epoch == candidate_authority_epoch.value()
                && record.candidate_binding_digest.as_str() == candidate_digest
        });
        let Some(record) = committed.next() else {
            return Ok(None);
        };
        if committed.next().is_some() {
            return Err(HostError::RecoveryRequired(
                "Store recovery reconciliation found multiple committed inner rebinds".to_owned(),
            ));
        }
        if record.process_id == termination.process_id
            && record.process_start_time_100ns == termination.process_start_time_100ns
            && record.process_image_path.as_str() == termination.process_image_path
            && record.job_name.as_str() == termination.job_name
        {
            return Err(HostError::RecoveryRequired(
                "committed Store rebind points at the terminated predecessor".to_owned(),
            ));
        }

        let requirement = self
            .jobs
            .store_bootstrap_requirement
            .as_ref()
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store recovery reconciliation has no retained Store requirement".to_owned(),
                )
            })?;
        let inner = committed_store_rebind_receipt(record, requirement, &candidate_digest)?;
        if inner.request_digest != inner_binding.store_rebind_request_digest {
            return Err(HostError::RecoveryRequired(
                "committed Store rebind differs from the durable inner request binding".to_owned(),
            ));
        }
        let live_store = self.jobs.store.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no relaunched Store process".to_owned(),
            )
        })?;
        let live_process = live_store.evidence().process();
        if live_process.process_id != inner.process_binding.process.process_id
            || live_process.start_time_100ns != inner.process_binding.process.start_time_100ns
            || live_process.image_path != inner.process_binding.process.image_path
            || live_store.job_identity().name() != inner.process_binding.job.as_str()
            || !live_store
                .job_processes()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
                .iter()
                .any(|observed| observed == live_process)
        {
            return Err(HostError::RecoveryRequired(
                "live Store process/Job does not match the committed inner rebind".to_owned(),
            ));
        }
        let active = self.registry.active().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no active approved generation".to_owned(),
            )
        })?;
        let phase_b = self.phase_b.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no current Phase-B materialization".to_owned(),
            )
        })?;
        let launch = self.jobs.launch.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no retained launch descriptor".to_owned(),
            )
        })?;
        let launch_authority_generation = launch.authority_generation;
        if self.jobs.approved_generation.as_ref() != Some(&active.manifest.generation)
            || phase_b.manifest_digest != phase_b_manifest_digest(&active.manifest)?
            || &phase_b.launch != launch
            || self.jobs.config_digest.as_ref() != Some(&phase_b.config_file_digest)
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery generation/config/Phase-B binding is stale".to_owned(),
            ));
        }
        let config_lease = self.jobs.config_lease.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired("Store recovery has no retained config lease".to_owned())
        })?;
        config_lease.verify().map_err(HostError::RecoveryRequired)?;
        verify_launch_digest(config_lease, &phase_b.config_file_digest, "runtime.config")?;
        let store_lease = self.jobs.store_lease.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery has no retained Store image lease".to_owned(),
            )
        })?;
        store_lease.verify().map_err(HostError::RecoveryRequired)?;
        verify_launch_digest(
            store_lease,
            &launch.store_bridge_artifact_digest,
            "runtime.store_artifact",
        )?;
        let eliotd_config_lease = self.jobs.eliotd_config_lease.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery has no retained eliotd config lease".to_owned(),
            )
        })?;
        eliotd_config_lease
            .verify()
            .map_err(HostError::RecoveryRequired)?;
        verify_launch_digest(
            eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_lease =
            self.jobs.eliotd_descriptor_lease.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store recovery has no retained eliotd descriptor lease".to_owned(),
                )
            })?;
        eliotd_descriptor_lease
            .verify()
            .map_err(HostError::RecoveryRequired)?;
        verify_launch_digest(
            eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            "runtime.eliotd_descriptor",
        )?;
        validate_eliotd_launch_descriptor(
            eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let generation_handle = self.jobs.approved_generation.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no approved generation".to_owned(),
            )
        })?;
        let readiness_contour = self.persist_fresh_authenticated_readiness(&generation_handle)?;
        let readiness_observation = self
            .journal
            .snapshot()?
            .readiness_observations
            .last()
            .cloned()
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "fresh Kernel ProbeReady did not produce a readiness observation".to_owned(),
                )
            })?;
        let store_fence = PlatformHandle::new(inner.store_fence.clone())
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let config_digest = self.jobs.config_digest.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery reconciliation has no materialized config digest".to_owned(),
            )
        })?;
        if readiness_contour.store_proof_fence.as_ref() != Some(&store_fence)
            || readiness_observation.store_fence != store_fence
            || readiness_observation.config_digest != *config_digest
        {
            return Err(HostError::RecoveryRequired(
                "fresh readiness observation is not bound to the committed Store rebind".to_owned(),
            ));
        }
        let kernel_generation = kernel.kernel_generation.clone();
        let kernel_generation_digest = PlatformHandle::new(sha256_json(&kernel_generation)?)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let activation_receipt = self
            .jobs
            .kernel_activation_receipt
            .as_ref()
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "durable Kernel activation receipt is missing during Store reconciliation"
                        .to_owned(),
                )
            })?;
        if activation_receipt.candidate_binding_digest != candidate_digest
            || activation_receipt.generation != launch_authority_generation
            || activation_receipt.authority_epoch != candidate_authority_epoch
        {
            return Err(HostError::RecoveryRequired(
                "Kernel consumed-nonce receipt is not bound to the durable Active candidate"
                    .to_owned(),
            ));
        }
        let activation_nonce_digest =
            PlatformHandle::new(activation_receipt.activation_nonce_digest.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?;
        let new_store_process_id = PlatformHandle::new(format!(
            "pid:{}:start:{}",
            inner.process_binding.process.process_id,
            inner.process_binding.process.start_time_100ns
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut receipt = HostStoreRecoveryReceipt {
            external_control_mutation_digest: request.mutation_digest.clone(),
            request_digest: pending.recover_request()?.request_digest,
            store_rebind_request_digest: PlatformHandle::new(inner.request_digest.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
            store_fence,
            new_store_process_id,
            kernel_generation: kernel_generation_digest,
            activation_nonce_digest,
            ready_receipt_digest: readiness_observation.ready_receipt_digest.clone(),
            receipt_digest: PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        receipt.receipt_digest = receipt.computed_digest().map_err(HostError::Platform)?;
        receipt.validate().map_err(HostError::Platform)?;
        persist_store_recovery_receipt(self.launch_options.host_state_root(), &receipt)?;
        if !self.readiness_gate.grant(readiness_contour, Instant::now()) {
            return Err(HostError::RecoveryRequired(
                "fresh Store readiness did not produce an admissible lease".to_owned(),
            ));
        }
        if self.store_recovery_startup_fence.is_fenced() {
            // Receipt publication and supporting-evidence removal form the
            // durable resolution boundary.  The in-memory fence is cleared
            // only after both exact receipt readback and no-replace cleanup
            // succeed; any failure leaves Unknown and blocks admission.
            cleanup_store_recovery_supporting_evidence_for(
                self.launch_options.host_state_root(),
                request.mutation_digest.as_str(),
            )?;
            let remaining = self
                .store_recovery_startup_fence
                .bindings()
                .iter()
                .filter(|binding| binding.mutation_digest != request.mutation_digest.as_str())
                .cloned()
                .collect::<Vec<_>>();
            self.store_recovery_startup_fence = if remaining.is_empty() {
                StoreRecoveryStartupFence::Clear
            } else {
                StoreRecoveryStartupFence::Unresolved(remaining)
            };
        }
        let response_receipt =
            if request.operation == HostRuntimeControlOperation::ReconcileStoreRecovery {
                rebind_store_recovery_receipt(&receipt, request)?
            } else {
                receipt
            };
        Ok(Some(response_receipt))
    }

    /// A receipt-only retry is valid only while this exact Host still owns
    /// the committed Store contour.  The file is response-loss evidence, not
    /// authority: after Host death the kill-on-close Job is gone, a fresh Host
    /// epoch has a different fence, and this check must refuse positive
    /// adoption even if the receipt file remains on disk.
    #[cfg(windows)]
    fn store_recovery_receipt_matches_current_contour(
        &self,
        receipt: &HostStoreRecoveryReceipt,
    ) -> Result<bool, HostError> {
        let snapshot = self.journal.snapshot()?;
        let active_fence =
            record_fence(&self.host, &self.activation_id, &self.activation_generation);
        let mut committed = snapshot.store_rebinds.iter().filter(|record| {
            record.state == StoreRebindState::Committed
                && record.fence == active_fence
                && record.request_digest == receipt.store_rebind_request_digest
                && record.receipt_request_digest.as_ref()
                    == Some(&receipt.store_rebind_request_digest)
                && record.receipt_store_fence.as_ref() == Some(&receipt.store_fence)
                && record.store_fence == receipt.store_fence
        });
        let Some(record) = committed.next() else {
            return Ok(false);
        };
        if committed.next().is_some() {
            return Err(HostError::RecoveryRequired(
                "Store recovery receipt matches multiple current committed rebinds".to_owned(),
            ));
        }
        let Some(store) = self.jobs.store.as_ref() else {
            return Ok(false);
        };
        let process = store.evidence().process();
        let process_identity = format!(
            "pid:{}:start:{}",
            process.process_id, process.start_time_100ns
        );
        if receipt.new_store_process_id.as_str() != process_identity
            || record.process_id != process.process_id
            || record.process_start_time_100ns != process.start_time_100ns
            || record.process_image_path.as_str() != process.image_path
            || record.job_name.as_str() != store.job_identity().name()
        {
            return Ok(false);
        }
        if !store
            .job_processes()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
            .iter()
            .any(|observed| observed == process)
        {
            return Ok(false);
        }
        Ok(snapshot.readiness_observations.iter().any(|observation| {
            observation.fence == active_fence
                && observation.store_fence == receipt.store_fence
                && observation.ready_receipt_digest == receipt.ready_receipt_digest
        }))
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    pub fn reconcile_store_recovery_request(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("store-recovery-reconcile", request),
            );
        }
        if request.validate().is_err()
            || request.operation != HostRuntimeControlOperation::ReconcileStoreRecovery
        {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref("store-recovery-reconcile", request),
            );
        }
        if self.store_recovery_startup_fence.is_fenced() {
            return HostRuntimeControlResponse::unknown_for(
                request,
                runtime_control_unknown_ref(STORE_RECOVERY_CRASH_FENCE_UNKNOWN_REASON, request),
            );
        }
        let key = request.mutation_digest.as_str().to_owned();
        match self.reconcile_committed_store_recovery(request) {
            Ok(Some(receipt)) => {
                return HostRuntimeControlResponse::store_recovered_for(request, receipt);
            }
            Ok(None) => {}
            Err(_) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("store-recovery-reconcile-unknown", request),
                );
            }
        }
        match has_store_recovery_pending(self.launch_options.host_state_root(), &key) {
            Ok(true) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("store-recovery-pending", request),
                );
            }
            Err(_) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("store-recovery-reconcile-snapshot", request),
                );
            }
            Ok(false) => {}
        }
        // Once the exact supporting evidence has been removed, the durable
        // outer receipt can answer response loss only after the current Host
        // journal, live Store Job/process, and readiness observation prove
        // that this same process still owns the contour. It is never adopted
        // after Host death.
        match read_store_recovery_receipt(self.launch_options.host_state_root(), &key) {
            Ok(Some(receipt)) => {
                match self.store_recovery_receipt_matches_current_contour(&receipt) {
                    Ok(true) => match rebind_store_recovery_receipt(&receipt, request) {
                        Ok(rebound) => {
                            return HostRuntimeControlResponse::store_recovered_for(
                                request, rebound,
                            );
                        }
                        Err(_) => {
                            return HostRuntimeControlResponse::unknown_for(
                                request,
                                runtime_control_unknown_ref(
                                    "store-recovery-reconcile-conflict",
                                    request,
                                ),
                            );
                        }
                    },
                    Ok(false) => {
                        return HostRuntimeControlResponse::unknown_for(
                            request,
                            runtime_control_unknown_ref(
                                STORE_RECOVERY_CRASH_FENCE_UNKNOWN_REASON,
                                request,
                            ),
                        );
                    }
                    Err(_) => {
                        return HostRuntimeControlResponse::unknown_for(
                            request,
                            runtime_control_unknown_ref(
                                "store-recovery-reconcile-snapshot",
                                request,
                            ),
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(_) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("store-recovery-reconcile-snapshot", request),
                );
            }
        }
        let active_fence =
            record_fence(&self.host, &self.activation_id, &self.activation_generation);
        match self.journal.snapshot() {
            Ok(snapshot) => {
                if snapshot.store_rebinds.iter().any(|r| {
                    r.fence == active_fence
                        && matches!(
                            r.state,
                            StoreRebindState::Pending | StoreRebindState::Unknown
                        )
                }) {
                    return HostRuntimeControlResponse::unknown_for(
                        request,
                        runtime_control_unknown_ref("store-recovery-pending", request),
                    );
                }
            }
            Err(_) => {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    runtime_control_unknown_ref("store-recovery-reconcile-snapshot", request),
                );
            }
        }
        HostRuntimeControlResponse::unknown_for(
            request,
            runtime_control_unknown_ref("store-recovery-reconcile-unknown", request),
        )
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    pub(super) fn execute_store_recovery(
        &mut self,
        request: &HostRuntimeControlRequest,
    ) -> Result<HostStoreRecoveryReceipt, HostError> {
        request.validate().map_err(HostError::ProcessContour)?;
        if request.operation != HostRuntimeControlOperation::RecoverStore {
            return Err(HostError::ProcessContour(
                "unsupported runtime-control operation for store recovery".to_owned(),
            ));
        }
        let key = request.mutation_digest.as_str().to_owned();
        if let Some(receipt) = self.reconcile_committed_store_recovery(request)? {
            return Ok(receipt);
        }
        if has_store_recovery_pending(self.launch_options.host_state_root(), &key)? {
            return Err(HostError::RecoveryRequired(
                "Store recovery intent is pending and outcome is unknown; reconcile required"
                    .to_owned(),
            ));
        }
        if read_store_recovery_termination_evidence(self.launch_options.host_state_root(), &key)?
            .is_some()
        {
            return Err(HostError::RecoveryRequired(
                "Store termination evidence is retained without a receipt; reconcile required"
                    .to_owned(),
            ));
        }
        if let Some(receipt) =
            read_store_recovery_receipt(self.launch_options.host_state_root(), &key)?
        {
            if receipt.request_digest == request.request_digest
                && self.store_recovery_receipt_matches_current_contour(&receipt)?
            {
                return Ok(receipt);
            }
            return Err(HostError::RecoveryRequired(
                "durable Store recovery receipt is not bound to this live Host contour; manual new-lineage recovery is required".to_owned(),
            ));
        }
        let active_fence =
            record_fence(&self.host, &self.activation_id, &self.activation_generation);
        if self.journal.snapshot()?.store_rebinds.iter().any(|r| {
            r.fence == active_fence
                && matches!(
                    r.state,
                    StoreRebindState::Pending | StoreRebindState::Unknown
                )
        }) {
            return Err(HostError::RecoveryRequired(
                "Store recovery journal intent is pending; reconcile required".to_owned(),
            ));
        }
        self.ensure_admission_open()?;
        if self.jobs.store_restart_attempts >= 1 {
            return Err(HostError::RecoveryRequired(
                "Store recovery restart budget is exhausted; reconcile required".to_owned(),
            ));
        }
        // A recovery intent is itself a state mutation. Invalidate the
        // current lease before publishing it so no caller can observe the
        // old Healthy contour while Store recovery is being committed.
        self.readiness_gate.branch_degraded();
        let capability = self.owner_lease.activation_capability();
        let guard = capability
            .live_guard()
            .map_err(|e| HostError::Platform(e.to_string()))?;
        if persist_store_recovery_pending(
            self.launch_options.host_state_root(),
            request,
            &self.host,
        )? == StoreRecoveryPendingPublication::Replay
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery intent is already pending; reconcile required".to_owned(),
            ));
        }
        drop(guard);
        let snapshot_before = self.journal.snapshot()?;
        let kernel_before = snapshot_before.kernel.clone().ok_or_else(|| {
            HostError::ProcessContour("no active Kernel for store recovery".to_owned())
        })?;
        if kernel_before.state != KernelActivationState::Active {
            return Err(HostError::ProcessContour(
                "Kernel is not Active; store recovery requires Active".to_owned(),
            ));
        }
        let host_epoch_before = self.host.epoch.clone();
        let kernel_generation_before = kernel_before.kernel_generation.clone();
        let activation_nonce_before = kernel_before.one_time_nonce.clone();
        let kernel_process_before = kernel_before.process.clone().ok_or_else(|| {
            HostError::ProcessContour("Kernel process missing before store recovery".to_owned())
        })?;
        let kernel_job_before = kernel_before.candidate_job_binding.clone().ok_or_else(|| {
            HostError::ProcessContour("Kernel job missing before store recovery".to_owned())
        })?;
        let old_store = self.jobs.store.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Store process missing before recovery".to_owned())
        })?;
        let old_proc = old_store.evidence().process().clone();
        if old_proc.process_id == 0
            || old_proc.start_time_100ns == 0
            || old_proc.image_path.is_empty()
        {
            return Err(HostError::ProcessContour(
                "old Store PID/start/image invalid before containment".to_owned(),
            ));
        }
        let old_job_name = old_store.job_identity().name().to_owned();
        if old_job_name.trim().is_empty() {
            return Err(HostError::ProcessContour(
                "old Store Job name missing before containment".to_owned(),
            ));
        }
        let members = old_store
            .job_processes()
            .map_err(|e| HostError::ProcessContour(e.to_string()))?;
        if !members.iter().any(|m| m == &old_proc) {
            return Err(HostError::ProcessContour(
                "old Store Job does not contain exact process before relaunch".to_owned(),
            ));
        }
        self.jobs.store_restart_attempts = self
            .jobs
            .store_restart_attempts
            .checked_add(1)
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store recovery restart attempt counter overflowed".to_owned(),
                )
            })?;
        let terminated_store = {
            let store_mut = self.jobs.store.as_mut().ok_or_else(|| {
                HostError::ProcessContour("Store Job is missing before termination".to_owned())
            })?;
            store_mut
                .terminate_in_place(0xE017_0002)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
        };
        if !terminated_store.job_empty() || !terminated_store.root_reaped() {
            return Err(HostError::RecoveryRequired(
                "Store termination did not produce job-empty/root-reaped evidence".to_owned(),
            ));
        }
        persist_store_recovery_termination_evidence(
            self.launch_options.host_state_root(),
            request,
            &self.host,
            &terminated_store,
            &old_job_name,
        )?;
        let termination =
            read_store_recovery_termination_evidence(self.launch_options.host_state_root(), &key)?
                .ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store termination evidence disappeared before relaunch".to_owned(),
                    )
                })?;
        let pending = read_store_recovery_pending_identity(&store_recovery_pending_path(
            self.launch_options.host_state_root(),
            &key,
        ))?
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery intent disappeared after termination".to_owned(),
            )
        })?;
        pending.validate_current_request(request)?;
        termination.validate_for_pending(&pending)?;
        if termination.process_id != old_proc.process_id
            || termination.process_start_time_100ns != old_proc.start_time_100ns
            || termination.process_image_path != old_proc.image_path
            || termination.job_name != old_job_name
            || !termination.job_empty
            || !termination.root_reaped
            || termination.restart_attempt != 1
        {
            return Err(HostError::RecoveryRequired(
                "Store termination evidence does not match the contained Store".to_owned(),
            ));
        }
        self.jobs.store.take();
        let generation =
            self.jobs.approved_generation.clone().ok_or_else(|| {
                HostError::ProcessContour("approved generation missing".to_owned())
            })?;
        let config_digest = self
            .jobs
            .config_digest
            .clone()
            .ok_or_else(|| HostError::ProcessContour("config digest missing".to_owned()))?;
        let config_path = self
            .jobs
            .config_path
            .clone()
            .ok_or_else(|| HostError::ProcessContour("config path missing".to_owned()))?;
        let store_artifact = self
            .jobs
            .store_artifact_digest
            .clone()
            .ok_or_else(|| HostError::ProcessContour("store artifact missing".to_owned()))?;
        let approved_store_path = PlatformHandle::new(
            self.jobs
                .store_bridge_executable
                .as_ref()
                .ok_or_else(|| HostError::ProcessContour("store image missing".to_owned()))?
                .to_string_lossy()
                .to_string(),
        )
        .map_err(|e| HostError::Platform(e.to_string()))?;
        let approved_config_path = PlatformHandle::new(config_path.to_string_lossy().to_string())
            .map_err(|e| HostError::Platform(e.to_string()))?;
        let new_child = self.jobs.relaunch_store(
            &generation,
            &config_digest,
            &config_path,
            &store_artifact,
            &approved_store_path,
            &approved_config_path,
            &self.host,
        )?;
        self.jobs.store = Some(new_child);
        let (new_proc, new_store_job_name) = {
            let new_store = self.jobs.store.as_ref().ok_or_else(|| {
                HostError::ProcessContour("relaunched Store Job is missing".to_owned())
            })?;
            let new_proc = new_store.evidence().process().clone();
            if new_proc == old_proc {
                return Err(HostError::ProcessContour(
                    "relaunched Store reused the terminated PID/start/image contour".to_owned(),
                ));
            }
            if !new_store
                .job_processes()
                .map_err(|e| HostError::ProcessContour(e.to_string()))?
                .iter()
                .any(|m| m == &new_proc)
            {
                return Err(HostError::ProcessContour(
                    "new Store Job does not contain exact relaunched process".to_owned(),
                ));
            }
            match new_store
                .observe()
                .map_err(|e| HostError::ProcessContour(e.to_string()))?
            {
                eliot_platform_windows::RunningJobObservation::Running { active_processes }
                    if active_processes > 0 => {}
                _ => {
                    return Err(HostError::ProcessContour(
                        "new Store Job is not live after relaunch".to_owned(),
                    ));
                }
            }
            (new_proc, new_store.job_identity().name().to_owned())
        };
        let snapshot_after_relaunch = self.journal.snapshot()?;
        let kernel_after = snapshot_after_relaunch.kernel.clone().ok_or_else(|| {
            HostError::ProcessContour("Kernel missing after store relaunch".to_owned())
        })?;
        if kernel_after.kernel_generation != kernel_generation_before {
            return Err(HostError::ProcessContour(
                "Kernel generation changed during store-only recovery".to_owned(),
            ));
        }
        if kernel_after.process != Some(kernel_process_before.clone()) {
            return Err(HostError::ProcessContour(
                "Kernel process changed during store-only recovery".to_owned(),
            ));
        }
        if kernel_after.candidate_job_binding != Some(kernel_job_before.clone()) {
            return Err(HostError::ProcessContour(
                "Kernel job changed during store-only recovery".to_owned(),
            ));
        }
        if kernel_after.one_time_nonce != activation_nonce_before {
            return Err(HostError::ProcessContour(
                "Kernel activation nonce changed during store-only recovery".to_owned(),
            ));
        }
        if snapshot_after_relaunch.host.epoch != host_epoch_before {
            return Err(HostError::ProcessContour(
                "Host epoch changed during store-only recovery".to_owned(),
            ));
        }
        let store_rebind_receipt = self.jobs.rebind_store_control(
            &generation,
            &self.journal,
            &self.host,
            &self.activation_id,
            &self.activation_generation,
            Some((self.launch_options.host_state_root(), request)),
        )?;
        store_rebind_receipt
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let approved_config = config_digest.clone();
        let readiness_contour = self.persist_fresh_authenticated_readiness(&generation)?;
        let readiness_observation = self
            .journal
            .snapshot()?
            .readiness_observations
            .last()
            .cloned()
            .ok_or_else(|| {
                HostError::ProcessContour(
                    "fresh Kernel ProbeReady did not produce a journal observation".to_owned(),
                )
            })?;
        let store_fence = store_rebind_receipt.store_fence.clone();
        let store_fence_handle = PlatformHandle::new(store_fence.clone())
            .map_err(|e| HostError::Platform(e.to_string()))?;
        if readiness_contour.store_proof_fence.as_ref() != Some(&store_fence_handle)
            || readiness_observation.store_fence != store_fence_handle
            || readiness_observation.config_digest != approved_config
        {
            return Err(HostError::ProcessContour(
                "fresh readiness observation is not bound to the authoritative Store rebind"
                    .to_owned(),
            ));
        }
        let rebound_process = &store_rebind_receipt.process_binding.process;
        if rebound_process.process_id != new_proc.process_id
            || rebound_process.start_time_100ns != new_proc.start_time_100ns
            || rebound_process.image_path != new_proc.image_path
            || store_rebind_receipt.process_binding.job.as_str() != new_store_job_name
        {
            return Err(HostError::ProcessContour(
                "authoritative Store rebind receipt changed the relaunched process".to_owned(),
            ));
        }
        let new_store_pid_handle = PlatformHandle::new(format!(
            "pid:{}:start:{}",
            rebound_process.process_id, rebound_process.start_time_100ns
        ))
        .map_err(|e| HostError::Platform(e.to_string()))?;
        let kernel_gen_handle = PlatformHandle::new(sha256_json(&kernel_generation_before)?)
            .map_err(|e| HostError::Platform(e.to_string()))?;
        let activation_nonce_digest = PlatformHandle::new(
            self.jobs
                .kernel_activation_receipt
                .as_ref()
                .ok_or_else(|| {
                    HostError::ProcessContour(
                        "durable Kernel activation receipt is missing after ProbeReady".to_owned(),
                    )
                })?
                .activation_nonce_digest
                .clone(),
        )
        .map_err(|e| HostError::Platform(e.to_string()))?;
        let ready_digest = readiness_observation.ready_receipt_digest.clone();
        let mut receipt = HostStoreRecoveryReceipt {
            external_control_mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            store_rebind_request_digest: PlatformHandle::new(
                store_rebind_receipt.request_digest.clone(),
            )
            .map_err(|e| HostError::Platform(e.to_string()))?,
            store_fence: store_fence_handle,
            new_store_process_id: new_store_pid_handle,
            kernel_generation: kernel_gen_handle,
            activation_nonce_digest,
            ready_receipt_digest: ready_digest,
            receipt_digest: PlatformHandle::new("0".repeat(64))
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        receipt.receipt_digest = receipt.computed_digest().map_err(HostError::Platform)?;
        receipt.validate().map_err(HostError::Platform)?;
        persist_store_recovery_receipt(self.launch_options.host_state_root(), &receipt)?;
        if !self.readiness_gate.grant(readiness_contour, Instant::now()) {
            return Err(HostError::ProcessContour(
                "fresh Store readiness did not produce an admissible lease".to_owned(),
            ));
        }
        Ok(receipt)
    }
}
