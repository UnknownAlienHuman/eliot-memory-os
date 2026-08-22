use eliot_runtime_contracts::{
    KernelActivationState, RegisteredActivityWakePolicy, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionLeasePredecessorIdentity,
    SupervisionObservationScope,
};

use crate::{
    ActivationState, HostState, HostStateRecord, JournalError, PriorKernelDisposition,
    record_checksum,
};

/// Reconstructs the exact current supervision incarnation from the retained
/// Host journal and the installer-approved immutable authority policy.
///
/// The latest readiness observation selects only the current ORS receipt. The
/// incarnation predecessor is the last observation before the first readiness
/// record bound to the current Kernel checksum, so repeat probes cannot become
/// a synthetic predecessor.
#[allow(
    clippy::too_many_lines,
    reason = "the reconstruction keeps every journal lineage, predecessor, and policy check in one auditable fail-closed projection"
)]
pub fn reconstruct_current_supervision_incarnation(
    state: &HostState,
    supervision_lease_scope_id: &str,
    observation_scope: &SupervisionObservationScope,
    wake_policy: &RegisteredActivityWakePolicy,
) -> Result<
    (
        SupervisionLeaseIncarnationBinding,
        SupervisionLeasePredecessorIdentity,
    ),
    JournalError,
> {
    if state.prior_kernel_unknown {
        return Err(JournalError::Invalid(
            "unknown prior Kernel state cannot reconstruct a supervision incarnation".to_owned(),
        ));
    }
    let activation = state
        .activation
        .as_ref()
        .ok_or_else(|| JournalError::Invalid("current activation is missing".to_owned()))?;
    let kernel = state
        .kernel
        .as_ref()
        .filter(|kernel| kernel.state == KernelActivationState::Active)
        .ok_or_else(|| JournalError::Invalid("current Kernel is not active".to_owned()))?;
    if !matches!(
        activation.state,
        ActivationState::Starting | ActivationState::ControlReady | ActivationState::Active
    ) || activation.fence != kernel.fence
        || activation.activation_id != kernel.fence.activation_id
        || activation.fence.host != state.host
    {
        return Err(JournalError::StaleFence);
    }

    let current_kernel_checksum = record_checksum(&HostStateRecord::Kernel(kernel.clone()))?;
    let first_current_index = state
        .readiness_observations
        .iter()
        .position(|observation| {
            observation.active_kernel_record_checksum.as_str() == current_kernel_checksum
        })
        .ok_or_else(|| {
            JournalError::Invalid("current Kernel has no admitted readiness observation".to_owned())
        })?;
    let current_readiness = state
        .readiness_observations
        .last()
        .ok_or_else(|| JournalError::Invalid("readiness history is empty".to_owned()))?;
    if current_readiness.active_kernel_record_checksum.as_str() != current_kernel_checksum
        || current_readiness.fence != kernel.fence
        || state.readiness_observations[first_current_index..]
            .iter()
            .any(|observation| {
                observation.active_kernel_record_checksum.as_str() != current_kernel_checksum
                    || observation.fence != kernel.fence
            })
    {
        return Err(JournalError::StaleFence);
    }
    let current_identity = current_readiness
        .active_supervision_lease
        .clone()
        .ok_or_else(|| {
            JournalError::Invalid("current readiness has no supervision identity".to_owned())
        })?;
    current_identity
        .validate()
        .map_err(|error| JournalError::Invalid(error.to_string()))?;

    let predecessor = state.readiness_observations[..first_current_index]
        .last()
        .map(|observation| {
            observation.active_supervision_lease.clone().ok_or_else(|| {
                JournalError::Invalid(
                    "prior Kernel readiness has no supervision identity".to_owned(),
                )
            })
        })
        .transpose()?;
    if let Some(predecessor) = &predecessor {
        predecessor
            .validate()
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
    }
    match (&kernel.prior_kernel_disposition, &predecessor) {
        (PriorKernelDisposition::NoPriorKernel, None)
        | (PriorKernelDisposition::Running(_) | PriorKernelDisposition::Terminated(_), Some(_)) => {
        }
        (PriorKernelDisposition::NoPriorKernel, Some(_)) | (_, None) => {
            return Err(JournalError::Invalid(
                "Kernel predecessor disposition conflicts with readiness history".to_owned(),
            ));
        }
        (PriorKernelDisposition::Unknown(_), Some(_)) => {
            return Err(JournalError::Invalid(
                "unknown prior Kernel disposition cannot select a supervision predecessor"
                    .to_owned(),
            ));
        }
    }

    let incarnation = SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: supervision_lease_scope_id.to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: state.host.installation.as_str().to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: state.host.epoch.current.lineage.as_str().to_owned(),
            sequence: state.host.epoch.current.sequence,
        },
        activation_id: activation.activation_id.as_str().to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: activation
                .fence
                .activation_generation
                .current
                .lineage
                .as_str()
                .to_owned(),
            sequence: activation.fence.activation_generation.current.sequence,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: kernel.kernel_generation.current.lineage.as_str().to_owned(),
            sequence: kernel.kernel_generation.current.sequence,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: activation
                .lineage
                .watchdog_epoch
                .lineage
                .as_str()
                .to_owned(),
            sequence: activation.lineage.watchdog_epoch.sequence,
        },
        observation_scope: observation_scope.clone(),
        wake_policy: wake_policy.clone(),
        predecessor,
    }
    .with_derived_ids()
    .map_err(|error| JournalError::Invalid(error.to_string()))?;
    incarnation
        .validate()
        .map_err(|error| JournalError::Invalid(error.to_string()))?;
    if incarnation.supervision_lease_id != current_identity.supervision_lease_id {
        return Err(JournalError::Invalid(
            "journaled supervision ID does not match the reconstructed incarnation".to_owned(),
        ));
    }
    Ok((incarnation, current_identity))
}
