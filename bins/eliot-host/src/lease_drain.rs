//! Exact-generation lease census and retirement admission.
//!
//! The Host journal establishes the committed drain fence; the authenticated
//! Kernel control owner supplies the durable exact-fence ORS census. Journal
//! lease references are checked for consistency, never used as the census.

use super::*;

/// Complete identity of the Host activation generation whose retirement is
/// being admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationRetirementFence {
    pub activation_id: PlatformHandle,
    pub activation_generation: eliot_contracts::EpochTransition,
    pub state_fence: StateFence,
}

/// Opaque owner-produced proof that the exact committed Host drain has no
/// active RuntimeLease or SupervisionLease in canonical ORS.
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
    /// Requires an exact durable Host drain and a current authenticated
    /// Kernel/ORS readback proving that the fenced generation has no active
    /// RuntimeLease or SupervisionLease.
    ///
    /// This method never infers absence from activation references. The Host
    /// commit must bind the requested activation, and the Kernel census reads
    /// every canonical RuntimeLease row for the complete StateFence together
    /// with the exact current supervision row in one ORS snapshot.
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
                    "DrainCommit omitted a lease reference in the activation projection"
                        .to_owned(),
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
        let drain_frame = eliot_kernel_service::control_request_frame(
            connection_id.clone(),
            &drain_request,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let request_frame = eliot_kernel_service::control_request_frame(
            connection_id,
            &request,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let response = runtime.block_on(async {
            let mut transport =
                connect_authenticated_kernel_front_door(candidate, &kernel_process).await?;
            validate_authenticated_kernel_peer(
                transport.peer_identity(),
                kernel_process.process_id,
                kernel_process.start_time_100ns,
                expected_kernel_image,
            )?;
            let limits = TransportLimits::default();
            match transport.send_frame(&drain_frame, limits).await? {
                eliot_ipc::DeliveryOutcome::Delivered => {}
                eliot_ipc::DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel admission-drain delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let frame = transport.receive_frame(limits).await?;
            let drain_response = eliot_kernel_service::decode_control_response_frame(&frame)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            drain_response
                .validate()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            if drain_response.message_id != drain_request.message_id
                || drain_response.request_digest != drain_request.payload_digest
                || drain_response.state != KernelServiceState::Draining
                || drain_response.error.is_some()
                || drain_response.receipt.is_some()
                || drain_response.runtime_health.is_some()
                || drain_response.activation_receipt.is_some()
                || drain_response.store_rebind_receipt.is_some()
                || drain_response.supervision_lease.is_some()
                || drain_response.runtime_lease.is_some()
                || drain_response.runtime_lease_census.is_some()
            {
                return Err(HostError::RecoveryRequired(
                    "Kernel did not durably acknowledge closed admission before census".to_owned(),
                ));
            }
            match transport.send_frame(&request_frame, limits).await? {
                eliot_ipc::DeliveryOutcome::Delivered => {}
                eliot_ipc::DeliveryOutcome::UnknownOutcome => {
                    return Err(HostError::RecoveryRequired(
                        "Kernel retirement census delivery outcome is unknown".to_owned(),
                    ));
                }
            }
            let frame = transport.receive_frame(limits).await?;
            eliot_kernel_service::decode_control_response_frame(&frame)
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))
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
            || response.runtime_lease.is_some()
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
            || census
                .runtime_leases
                .iter()
                .any(|lease| lease.state == eliot_runtime_contracts::LeaseState::Active)
            || supervision.record.state == eliot_runtime_contracts::LeaseState::Active
            || supervision.record.projection != eliot_ors::SupervisionLeaseProjection::Terminal
            || supervision.record.binding.activation_id.as_str()
                != expected.activation_id.as_str()
            || supervision.record.binding.activation_generation
                != expected.state_fence.resource_generation
            || supervision.record.binding.kernel_epoch != expected.state_fence.authority_epoch
            || supervision.record.binding.state_fence != expected.state_fence
        {
            return Err(HostError::RecoveryRequired(
                "canonical ORS still has active or foreign generation lease authority".to_owned(),
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
}
