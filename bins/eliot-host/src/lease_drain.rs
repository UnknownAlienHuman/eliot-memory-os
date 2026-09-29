//! Exact-generation lease census and retirement admission.
//!
//! Ported from #1751 donor 552ee79a (`bins/eliot-host/src/lease_drain.rs`),
//! via donor `origin/codex/961-owner-readback-20260923@53801ae0` (M2
//! integration copy; no authorship change, no duplicate owner).
//! Adaptation: the two `runtime_lease.is_some()` response guards from the
//! donor are dropped because this copy's `KernelControlResponse` carries no
//! `runtime_lease` field; the census-exclusivity validation in
//! `protocol.rs` owns that separation here. Transport send/receive errors
//! map through `HostError::ProcessContour` per this copy's front-door
//! convention (no `From<TransportError>` here).
//!
//! The Host journal establishes the committed drain fence; the authenticated
//! Kernel control owner supplies the durable exact-fence ORS census. Journal
//! lease references are checked for consistency, never used as the census.

use super::*;

/// Complete identity of the Host activation generation whose retirement is
/// being admitted.
///
/// The fields are crate-private on purpose. Outside `eliot_host` there is no
/// constructor and no field a caller can name, so a fence can only originate
/// from [`HostComposition::owner_generation_retirement_fence`], which reads it
/// from the durable Host activation and the approved-launch authority
/// generation. `require_generation_retirement_barrier` compares this value
/// against those same owner facts, so a fence a caller could simply state
/// would turn that comparison into a shape check over the caller's own words
/// instead of an owner-vs-owner agreement; keeping the fields out of reach is
/// what keeps it the latter. There is deliberately no `Deserialize`: a fence
/// never crosses a wire, a command line or any other caller-supplied value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationRetirementFence {
    /// Durable Host journal activation identity of the generation being retired.
    pub(crate) activation_id: PlatformHandle,
    /// Durable Host journal activation generation of the retired generation.
    pub(crate) activation_generation: eliot_contracts::EpochTransition,
    /// `StateFence::new(activation lineage kernel epoch, approved-launch
    /// authority generation)` for exactly this activation - the same value
    /// `require_generation_retirement_barrier` recomputes from the same owners.
    pub(crate) state_fence: StateFence,
}

/// Opaque owner-produced proof that the exact committed Host drain has no
/// active `RuntimeLease` or `SupervisionLease` in canonical ORS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationRetirementBarrier {
    fence: GenerationRetirementFence,
    drain_commit_operation: eliot_host_state::IdempotencyIdentity,
    runtime_lease_census: eliot_kernel_service::RuntimeLeaseCensus,
    kernel_process_id: u32,
    kernel_process_start_time_100ns: u64,
}

impl GenerationRetirementBarrier {
    /// Returns the exact generation accepted by this barrier.
    #[must_use]
    pub const fn fence(&self) -> &GenerationRetirementFence {
        &self.fence
    }

    /// Returns the durable Host drain-commit identity.
    #[must_use]
    pub const fn drain_commit_operation(&self) -> &eliot_host_state::IdempotencyIdentity {
        &self.drain_commit_operation
    }

    /// Returns the authenticated Kernel readback used by this barrier.
    #[must_use]
    pub const fn runtime_lease_census(&self) -> &eliot_kernel_service::RuntimeLeaseCensus {
        &self.runtime_lease_census
    }

    /// Returns the OS-observed Kernel PID from the authenticated peer.
    #[must_use]
    pub const fn kernel_process_id(&self) -> u32 {
        self.kernel_process_id
    }

    /// Returns the OS-observed Kernel process start identity.
    #[must_use]
    pub const fn kernel_process_start_time_100ns(&self) -> u64 {
        self.kernel_process_start_time_100ns
    }
}

impl HostComposition {
    /// Persists a protected recovery gap bound to the current activation and
    /// drain commit. The caller must keep the Kernel process alive until a
    /// later exact-fence owner census proves termination safe.
    ///
    /// Ported from #1751 donor b2566e47 (M2 integration copy; divergence
    /// record primitive for the corrected refusal path, no authorship
    /// change, no duplicate owner).
    pub fn record_drain_recovery_gap(
        &mut self,
        reason_ref: &str,
        disposition: GapDisposition,
        extra_evidence: &[PlatformHandle],
    ) -> Result<(), HostError> {
        let state = self.journal.snapshot()?;
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "drain recovery observation has no durable activation".to_owned(),
            )
        })?;
        let mut evidence = vec![
            PlatformHandle::new(format!("drain-recovery-reason:{reason_ref}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(format!("activation:{}", activation.activation_id.as_str()))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(format!(
                "activation-fence:{}",
                sha256_json(&activation.fence)?
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        if let Some(commit) = state.drain_commit.as_ref() {
            evidence.push(
                PlatformHandle::new(format!(
                    "drain-commit:{}",
                    commit.operation.operation_id.as_str()
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            );
        }
        evidence.extend(extra_evidence.iter().cloned());
        evidence.sort();
        evidence.dedup();
        if state.observations.iter().any(|record| {
            record.fence == activation.fence
                && record.binding_evidence_refs == evidence
                && record
                    .observation
                    .coverage_gap
                    .as_ref()
                    .is_some_and(|gap| gap.reason_ref == reason_ref && gap.protected)
        }) {
            return Ok(());
        }
        let record_id = fresh_identity("host-drain-recovery-gap")?;
        self.append_record(HostStateRecord::Observation(HostObservationRecord {
            fence: activation.fence.clone(),
            operation: operation("host-drain-recovery-observation")?,
            observation: ObservationRecordEnvelope {
                record_id: record_id.as_str().to_owned(),
                kind: ObservationRecordKind::CoverageGap,
                event: None,
                coverage_gap: Some(CoverageGap {
                    gap_id: record_id.as_str().to_owned(),
                    obligation_profile_ref: "windows-host-generation-retirement-v1".to_owned(),
                    reason_ref: reason_ref.to_owned(),
                    affected_interval: None,
                    disposition,
                    protected: true,
                    evidence_refs: evidence
                        .iter()
                        .map(|item| item.as_str().to_owned())
                        .collect(),
                }),
                journal_control_event: false,
                parent_record_id: None,
            },
            binding_evidence_refs: evidence,
        }))?;
        Ok(())
    }

    /// Requires an exact durable Host drain and a current authenticated
    /// Kernel/ORS readback proving that the fenced generation has no active
    /// `RuntimeLease` or `SupervisionLease`.
    ///
    /// This method never infers absence from activation references. The Host
    /// commit must bind the requested activation, and the Kernel census reads
    /// every canonical `RuntimeLease` row for the complete `StateFence`
    /// together with the exact current supervision row in one ORS snapshot.
    #[allow(
        clippy::too_many_lines,
        reason = "the retirement barrier keeps the durable drain proof, the authenticated census transport, and the fail-closed gap record in one boundary"
    )]
    pub fn require_generation_retirement_barrier(
        &mut self,
        expected: &GenerationRetirementFence,
    ) -> Result<GenerationRetirementBarrier, HostError> {
        let state = self.journal.snapshot()?;
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "generation retirement has no durable Host activation".to_owned(),
            )
        })?;
        let drain = state.drain.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "generation retirement has no durable Host drain".to_owned(),
            )
        })?;
        let commit = state.drain_commit.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "generation retirement has no durable DrainCommit".to_owned(),
            )
        })?;

        if activation.activation_id != expected.activation_id
            || activation.fence.activation_generation != expected.activation_generation
            || !matches!(
                activation.state,
                eliot_host_state::ActivationState::Draining
                    | eliot_host_state::ActivationState::StoppedClean
            )
            || drain.fence != activation.fence
            || drain.state != eliot_host_state::DrainState::Draining
            || drain.drain_generation != expected.activation_generation
            || commit.fence != activation.fence
            || commit.drain_generation != expected.activation_generation
            || !commit
                .authority_epochs_fenced
                .contains(&activation.lineage.kernel_epoch)
        {
            return Err(HostError::RecoveryRequired(
                "Host activation, drain, and DrainCommit do not prove the requested generation"
                    .to_owned(),
            ));
        }

        let launch = self.jobs.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "generation retirement has no current approved Kernel launch".to_owned(),
            )
        })?;
        let kernel_state_fence = StateFence::new(
            activation.lineage.kernel_epoch.clone(),
            launch.authority_generation,
        );
        if expected.state_fence != kernel_state_fence {
            return Err(HostError::RecoveryRequired(
                "requested retirement StateFence differs from the durable activation contour"
                    .to_owned(),
            ));
        }

        for lease_ref in activation
            .runtime_lease_refs
            .iter()
            .chain(&activation.supervision_lease_refs)
        {
            if !commit
                .lease_and_pending_operation_snapshot
                .contains(lease_ref)
            {
                return Err(HostError::RecoveryRequired(
                    "DrainCommit omitted a lease reference in the activation projection".to_owned(),
                ));
            }
        }
        let [supervision_lease_ref] = activation.supervision_lease_refs.as_slice() else {
            return Err(HostError::RecoveryRequired(
                "generation retirement requires one exact current supervision lease reference"
                    .to_owned(),
            ));
        };

        let candidate = self.jobs.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "generation retirement has no approved Kernel candidate binding".to_owned(),
            )
        })?;
        if candidate.activation_id != expected.activation_id
            || candidate.kernel_epoch != expected.state_fence.authority_epoch
        {
            return Err(HostError::RecoveryRequired(
                "authenticated Kernel candidate does not match the retirement fence".to_owned(),
            ));
        }
        let kernel = self.jobs.kernel.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "generation retirement requires the live authenticated Kernel process".to_owned(),
            )
        })?;
        let kernel_process = kernel.evidence().process().clone();
        let expected_kernel_image = self.jobs.kernel_executable.as_ref().ok_or_else(|| {
            HostError::ProcessContour("approved Kernel image is missing".to_owned())
        })?;
        let query = eliot_kernel_service::RuntimeLeaseCensusQuery {
            state_fence: expected.state_fence.clone(),
            supervision_lease_id: supervision_lease_ref.as_str().to_owned(),
        };
        query
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let drain_request = kernel_control_request(
            candidate,
            launch.authority_generation,
            KernelControlCommand::Drain,
            1,
        )?;
        let request = kernel_control_request(
            candidate,
            launch.authority_generation,
            KernelControlCommand::ReadRuntimeLeaseCensus(query.clone()),
            2,
        )?;
        let connection_id = format!(
            "host-retirement:{}:{}",
            expected.activation_id.as_str(),
            expected.state_fence.resource_generation.value()
        );
        let drain_frame =
            eliot_kernel_service::control_request_frame(connection_id.clone(), &drain_request)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let request_frame = eliot_kernel_service::control_request_frame(connection_id, &request)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let (drain_refused, response) = runtime.block_on(async {
            let mut transport =
                connect_authenticated_kernel_front_door(candidate, &kernel_process).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                kernel_process.process_id,
                kernel_process.start_time_100ns,
                expected_kernel_image,
            )?;
            let limits = TransportLimits::default();
            match transport
                .send_frame(&drain_frame, limits)
                .await
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
            {
                eliot_ipc::DeliveryOutcome::Delivered => {}
                eliot_ipc::DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel admission-drain delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let frame = transport
                .receive_frame(limits)
                .await
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let drain_response = eliot_kernel_service::decode_control_response_frame(&frame)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            drain_response
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            // Corrected refusal guard (b2566e47): the ONLY accepted error is
            // the typed `runtime_lease_owner_active` owner refusal. All
            // unrelated receipt/health/activation/store-rebind/supervision
            // fields plus the census must be absent. (This copy's response
            // carries no `runtime_lease` field, so that absence is
            // structural; the protocol exclusivity validation owns it.)
            let drain_refused =
                drain_response.error.as_deref() == Some("runtime_lease_owner_active");
            if drain_response.message_id != drain_request.message_id
                || drain_response.request_digest != drain_request.payload_digest
                || drain_response.state != KernelServiceState::Draining
                || (drain_response.error.is_some() && !drain_refused)
                || drain_response.receipt.is_some()
                || drain_response.runtime_health.is_some()
                || drain_response.activation_receipt.is_some()
                || drain_response.store_rebind_receipt.is_some()
                || drain_response.supervision_lease.is_some()
                || drain_response.runtime_lease_census.is_some()
            {
                return Err(HostError::RecoveryRequired(
                    "Kernel did not durably acknowledge closed admission before census".to_owned(),
                ));
            }
            match transport
                .send_frame(&request_frame, limits)
                .await
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?
            {
                eliot_ipc::DeliveryOutcome::Delivered => {}
                eliot_ipc::DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel retirement census delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let frame = transport
                .receive_frame(limits)
                .await
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            let response = eliot_kernel_service::decode_control_response_frame(&frame)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            Ok((drain_refused, response))
        })?;
        response
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if response.message_id != request.message_id
            || response.request_digest != request.payload_digest
            || response.state != KernelServiceState::Draining
            || response.error.is_some()
            || response.receipt.is_some()
            || response.runtime_health.is_some()
            || response.activation_receipt.is_some()
            || response.store_rebind_receipt.is_some()
            || response.supervision_lease.is_some()
        {
            return Err(HostError::RecoveryRequired(
                "Kernel retirement census response binding was not exact".to_owned(),
            ));
        }
        let census = response.runtime_lease_census.ok_or_else(|| {
            HostError::RecoveryRequired(
                "Kernel omitted the canonical ORS retirement census".to_owned(),
            )
        })?;
        census
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let supervision = &census.supervision_lease;
        if census.state_fence != expected.state_fence
            || census.supervision_lease_id != supervision_lease_ref.as_str()
            || supervision.record.binding.activation_id.as_str() != expected.activation_id.as_str()
            || supervision.record.binding.activation_generation
                != expected.state_fence.resource_generation
            || supervision.record.binding.kernel_epoch != expected.state_fence.authority_epoch
            || supervision.record.binding.state_fence != expected.state_fence
        {
            return Err(HostError::RecoveryRequired(
                "canonical ORS census is not bound to the committed generation".to_owned(),
            ));
        }
        if !census.is_fully_retired() {
            let census_digest = sha256_json(&census)?;
            let evidence = PlatformHandle::new(format!("runtime-census-sha256:{census_digest}"))
                .map_err(|error| HostError::Platform(error.to_string()))?;
            self.record_drain_recovery_gap(
                if drain_refused {
                    "kernel-drain-refused-active-owner"
                } else {
                    "kernel-retirement-census-active-owner"
                },
                GapDisposition::BlockDependentTransition,
                &[evidence],
            )?;
            return Err(HostError::RecoveryRequired(
                "committed drain retained: exact-fence ORS still has a live owner obligation; Kernel and Store remain running"
                    .to_owned(),
            ));
        }
        if drain_refused {
            let census_digest = sha256_json(&census)?;
            let evidence = PlatformHandle::new(format!("runtime-census-sha256:{census_digest}"))
                .map_err(|error| HostError::Platform(error.to_string()))?;
            self.record_drain_recovery_gap(
                "kernel-drain-refusal-requires-new-owner-pass",
                GapDisposition::BlockDependentTransition,
                &[evidence],
            )?;
            return Err(HostError::RecoveryRequired(
                "Kernel refused the current owner pass; the raw ORS census cannot clear that typed refusal. Retry the same committed fence for a new Kernel owner readback before termination"
                    .to_owned(),
            ));
        }

        Ok(GenerationRetirementBarrier {
            fence: expected.clone(),
            drain_commit_operation: commit.operation.clone(),
            runtime_lease_census: census,
            kernel_process_id: kernel_process.process_id,
            kernel_process_start_time_100ns: kernel_process.start_time_100ns,
        })
    }

    /// Produces the exact [`GenerationRetirementFence`] for the activation
    /// generation this Host composition is running, from the owners it already
    /// holds (#961).
    ///
    /// Both facts are owner reads; nothing here is supplied by a caller:
    ///
    /// * `activation_id` and `activation_generation` are the durable Host
    ///   activation the journal owner resolves, through the same
    ///   `HostStateJournal::snapshot` read `require_generation_retirement_barrier`
    ///   validates against; and
    /// * `state_fence` is `StateFence::new(activation.lineage.kernel_epoch,
    ///   launch.authority_generation)` over that activation's durable lineage
    ///   and the authority generation of this composition's current approved
    ///   launch.
    ///
    /// `require_generation_retirement_barrier` recomputes exactly that
    /// `StateFence` from the same two owner records, so its comparison is an
    /// owner-vs-owner agreement rather than a caller-stated shape. The
    /// cross-checks below are what make that hold instead of assuming it. The
    /// composition's own activation identity and generation are the pair this
    /// composition hands `complete_kernel_control`, which re-checks it against
    /// the durable activation record before admitting a Kernel (`lib.rs:2900`),
    /// and the pair the readiness contour requires the journal's current
    /// activation to carry (`lib.rs:9763`). Through the Kernel candidate
    /// binding `require_generation_retirement_barrier` re-checks against
    /// `expected.activation_id`, the identity check below is therefore already
    /// implied by the barrier's own admission: a fence that disagreed with this
    /// composition could never have been admitted. The generation check
    /// restates the requirement the readiness contour already places on the
    /// journal's current activation, so it grants nothing new - it only refuses
    /// earlier and with a named cause instead of letting a fence that pairs two
    /// generations reach the barrier.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::OwnerLeaseRecovery`] when the journal owner holds
    /// no durable activation, [`HostError::ProcessContour`] when this
    /// composition has no current approved Kernel launch or the journal's
    /// activation identity is not the activation this composition is running,
    /// and [`HostError::RecoveryRequired`] when the journal's activation
    /// generation is not the generation this composition is running. The fence
    /// is constructed only after every read and every check has succeeded, so a
    /// partially-filled fence is never returned.
    pub fn owner_generation_retirement_fence(
        &self,
    ) -> Result<GenerationRetirementFence, HostError> {
        let state = self.journal.snapshot()?;
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery(
                "generation retirement has no durable Host activation".to_owned(),
            )
        })?;
        let launch = self.jobs.launch.as_ref().ok_or_else(|| {
            HostError::ProcessContour(
                "generation retirement has no current approved Kernel launch".to_owned(),
            )
        })?;
        if activation.activation_id != self.activation_id {
            return Err(HostError::ProcessContour(
                "durable Host activation is not the activation this Host composition is running"
                    .to_owned(),
            ));
        }
        if activation.fence.activation_generation != self.activation_generation {
            return Err(HostError::RecoveryRequired(
                "durable Host activation generation is not the generation this Host composition is running"
                    .to_owned(),
            ));
        }
        Ok(GenerationRetirementFence {
            activation_id: activation.activation_id.clone(),
            activation_generation: activation.fence.activation_generation.clone(),
            state_fence: StateFence::new(
                activation.lineage.kernel_epoch.clone(),
                launch.authority_generation,
            ),
        })
    }
}
