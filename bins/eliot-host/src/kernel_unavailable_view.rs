//! Host-owned projection for the authenticated Kernel-unavailable status
//! response. This reads only `HostStateJournal` and Host's persisted heartbeat
//! observation; it never opens ORS or infers process termination.

use std::path::Path;

use eliot_host_state::HostState;

use crate::{
    ExternalToolEnforcement, HostError, KernelUnavailableRecoveryView, RecoveryAvailability,
    RecoveryBuildSummary, RecoveryGeneration, RecoveryGenerationSummary, RecoveryIncidentSummary,
    RecoveryObservationOwner, RecoveryObservationSource, RecoveryOrsSummary,
    RecoveryOwnerObservation, RecoveryTerminationOutcome, watchdog_heartbeat,
};

/// Projects the bounded recovery categories from observations owned by Host.
///
/// No retained ORS projection is available from `HostStateJournal`, so the
/// current ORS remains unavailable and `retained` stays absent. A saved
/// Watchdog heartbeat is carried as historical Host-observed evidence only.
pub(crate) fn build_kernel_unavailable_view(
    state: &HostState,
    host_state_root: &Path,
    observed_at_unix_ms: u64,
) -> Result<KernelUnavailableRecoveryView, HostError> {
    let host_observation = RecoveryOwnerObservation {
        observer: RecoveryObservationOwner::Host,
        subject: RecoveryObservationOwner::Host,
        source: RecoveryObservationSource::HostStateJournal,
        generation: Some(RecoveryGeneration::Host {
            lineage_id: state.host.epoch.current.lineage_id.as_str().to_owned(),
            sequence: state.host.epoch.current.sequence.get(),
        }),
        observed_at_unix_ms: Some(observed_at_unix_ms),
        availability: RecoveryAvailability::Available,
        stale: false,
    };
    let watchdog_observation =
        watchdog_heartbeat::load_prior_heartbeat_observation(host_state_root).map_or(
            RecoveryOwnerObservation {
                observer: RecoveryObservationOwner::Host,
                subject: RecoveryObservationOwner::Watchdog,
                source: RecoveryObservationSource::HostObservedWatchdogHeartbeat,
                generation: None,
                observed_at_unix_ms: None,
                availability: RecoveryAvailability::Unknown,
                stale: true,
            },
            |heartbeat| RecoveryOwnerObservation {
                observer: RecoveryObservationOwner::Host,
                subject: RecoveryObservationOwner::Watchdog,
                source: RecoveryObservationSource::HostObservedWatchdogHeartbeat,
                generation: Some(RecoveryGeneration::Watchdog {
                    epoch: heartbeat.watchdog_epoch,
                }),
                observed_at_unix_ms: Some(heartbeat.host_receive_wall_ms),
                availability: RecoveryAvailability::Unknown,
                stale: true,
            },
        );
    let retained_kernel_generation =
        state
            .kernel
            .as_ref()
            .map(|kernel| RecoveryGeneration::Kernel {
                lineage_id: kernel
                    .kernel_generation
                    .current
                    .lineage_id
                    .as_str()
                    .to_owned(),
                sequence: kernel.kernel_generation.current.sequence.get(),
            });
    let view = KernelUnavailableRecoveryView {
        build: RecoveryBuildSummary {
            host_package_version: env!("CARGO_PKG_VERSION").to_owned(),
            host_runtime_control_wire:
                eliot_host_service::runtime_control::HOST_RUNTIME_CONTROL_WIRE.to_owned(),
            last_approved_kernel_artifact_sha256: state
                .kernel
                .as_ref()
                .map(|kernel| kernel.approved_artifact_hash.as_str().to_owned()),
        },
        generation: RecoveryGenerationSummary {
            host_observation,
            host_journal_sequence: state.sequence,
            kernel_current_availability: RecoveryAvailability::Unavailable,
            kernel_termination: RecoveryTerminationOutcome::OutcomeUnknown,
            retained_kernel_generation,
        },
        ors: RecoveryOrsSummary {
            current_availability: RecoveryAvailability::Unavailable,
            retained: None,
        },
        incident: RecoveryIncidentSummary {
            watchdog_observation,
            host_prior_kernel_unknown: state.prior_kernel_unknown,
            external_tool_enforcement: ExternalToolEnforcement::EnforcementUnobserved,
            external_tool_termination: RecoveryTerminationOutcome::OutcomeUnknown,
            semantic_task_recovery_deferred: true,
        },
    };
    view.validate().map_err(HostError::Platform)?;
    Ok(view)
}
