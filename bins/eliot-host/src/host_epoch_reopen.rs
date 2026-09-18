use std::path::Path;

use super::{
    ActivationState, ActivePhaseBRebindRecoveryKind, ApprovedGenerationRegistry, EpochTransition,
    HostError, HostInstallationEpoch, HostStateJournalService, HostStateRecord, JournalBackend,
    JournalError, PendingActivationState, PlatformHandle, ProductionHostStateJournal,
    ReconcileOutcome, RedbJournalBackend, StoreRecoveryReopenFence, StoreRecoveryStartupFence,
    active_phase_b_rebind_recovery_kind, append_reconciled, child_host_epoch, epoch_contract_error,
    fresh_host_epoch, fresh_identity, fresh_lineage_id, initial_activation_record, root_epoch,
};

// F-LOG-HOST-6 (#981) epoch-reopen observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never epochs,
// digests, installation handles, or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). These primitives own no terminal: a
// single terminal per failed open operation is enforced by the outermost
// `Host::open` boundary in `lib.rs` (#891, `host-open-failed`), while these
// phases correlate by stage order only. Replayed committed state is observed
// as readback, never as a second effect. Sink outcome never alters
// result/order/cleanup.
fn host_epoch_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

pub(super) fn reopen_existing_epoch<B: JournalBackend>(
    current: HostStateJournalService<B>,
    last_host: &HostInstallationEpoch,
    installation: &PlatformHandle,
    pending: Option<&eliot_installation::PendingActivation>,
    active_phase_b_rebind: Option<&eliot_installation::ActivePhaseBRebind>,
    store_recovery_fences: &[StoreRecoveryReopenFence],
) -> Result<
    (
        HostStateJournalService<B>,
        HostInstallationEpoch,
        EpochTransition,
        StoreRecoveryStartupFence,
        ActivePhaseBRebindRecoveryKind,
    ),
    HostError,
> {
    host_epoch_observe("host.epoch reopen existing requested");
    if last_host.installation != *installation {
        host_epoch_observe("host.epoch install mismatch observed");
        return Err(HostError::OwnerLeaseRecovery(
            "Host journal installation identity does not match admission".to_owned(),
        ));
    }
    for pending in current.pending_transactions()? {
        match current.reconcile(&pending.transaction_id)? {
            ReconcileOutcome::Committed => {}
            ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id: pending.transaction_id,
                }));
            }
        }
    }
    let replayed = current.snapshot()?;
    host_epoch_observe("host.epoch pending reconcile observed");
    // An exact unresolved Store recovery contour outranks the shutdown marker:
    // a Host crash can occur between any two durable publications, and a
    // clean marker is never permission to attach a lost kill-on-close Job.
    let store_recovery_startup_fence = !store_recovery_fences.is_empty();
    let store_recovery_startup_fence = if store_recovery_startup_fence {
        for fence in store_recovery_fences {
            fence.validate_for_reopen(last_host, &replayed)?;
        }
        StoreRecoveryStartupFence::Unresolved(store_recovery_fences.to_vec())
    } else {
        StoreRecoveryStartupFence::Clear
    };
    host_epoch_observe("host.epoch reopen fence observed");
    let active_phase_b_rebind_recovery = active_phase_b_rebind_recovery_kind(active_phase_b_rebind);
    if pending.is_none()
        && active_phase_b_rebind.is_none()
        && replayed.clean_marker.is_none()
        && !store_recovery_startup_fence.is_fenced()
    {
        host_epoch_observe("host.epoch unclean observed");
        return Err(HostError::OwnerLeaseRecovery(
            "current Host journal epoch is unclean; explicit new-lineage recovery is required"
                .to_owned(),
        ));
    }
    // Host-owned kill-on-close Jobs terminate their children when the prior
    // Host process dies. Historical Active records therefore authorize only
    // a fresh direct-child recovery attempt, never a registry commit. A
    // prepared Phase-B record is the narrow exception: its exact Host epoch
    // and nonce are durable recovery bindings, so the new owner re-enters the
    // same fenced publication contour without rewriting its four destinations.
    let activation_generation = if store_recovery_startup_fence.is_fenced() {
        replayed
            .activation
            .as_ref()
            .map(|activation| activation.fence.activation_generation.clone())
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store recovery fence has no retained activation generation".to_owned(),
                )
            })?
    } else {
        replayed
            .activation
            .as_ref()
            .map(|activation| {
                EpochTransition::direct_child(&activation.fence.activation_generation.current)
                    .map_err(|error| epoch_contract_error(&error))
            })
            .transpose()?
            .unwrap_or(root_epoch(fresh_lineage_id()?))
    };
    let host = if store_recovery_startup_fence.is_fenced()
        || pending.is_some_and(|pending| pending.phase_b_prepared.is_some())
    {
        last_host.clone()
    } else {
        child_host_epoch(last_host)?
    };
    if store_recovery_startup_fence.is_fenced()
        || pending.is_some_and(|pending| pending.phase_b_prepared.is_some())
    {
        host_epoch_observe("host.epoch owner epoch retained");
    } else {
        host_epoch_observe("host.epoch owner child epoch observed");
    }
    let backend = current.into_backend()?;
    Ok((
        HostStateJournalService::from_backend(backend, host.clone())?,
        host,
        activation_generation,
        store_recovery_startup_fence,
        active_phase_b_rebind_recovery,
    ))
}

pub(super) fn persist_pending_recovery(
    host_state_root: &Path,
    registry: &mut ApprovedGenerationRegistry,
    host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    pending: &eliot_installation::PendingActivation,
    reason: &str,
) -> Result<(), HostError> {
    host_epoch_observe("host.epoch pending recovery requested");
    let expected_revision = registry.revision();
    let expected_post_revision = if registry.pending_activation().is_some_and(|current| {
        current.approval == pending.approval
            && matches!(
                &current.state,
                PendingActivationState::RecoveryRequired { reason: current_reason }
                    if current_reason == reason
            )
    }) {
        expected_revision
    } else {
        expected_revision.checked_add(1).ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "{reason}; durable recovery disposition revision overflow"
            ))
        })?
    };
    let outcome = {
        // #1339, A13.9: short-lived open-use-drop CAS; the handle is dropped
        // before the readback open below, so concurrent Watchdog/installer
        // readers never observe a Host-held exclusive lock.
        let store = crate::open_registry_store_at(host_state_root)?;
        store.mark_pending_recovery(
            host_capability,
            expected_revision,
            &pending.approval,
            reason,
        )
    };
    let durable = {
        let store = crate::open_registry_store_at(host_state_root)?;
        store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "{reason}; recovery disposition outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?
    };
    let exact_readback = durable.revision() == expected_post_revision
        && durable.pending_activation().is_some_and(|current| {
            current.transaction_id == pending.transaction_id
                && current.plan_digest == pending.plan_digest
                && current.approval == pending.approval
                && matches!(
                    &current.state,
                    PendingActivationState::RecoveryRequired { reason: current_reason }
                        if current_reason == reason
                )
        });
    *registry = durable;
    host_epoch_observe("host.epoch recovery readback observed");
    match outcome {
        Ok(()) if exact_readback => {
            host_epoch_observe("host.epoch recovery exact readback confirmed");
            Ok(())
        }
        Ok(()) => {
            host_epoch_observe("host.epoch recovery readback mismatch observed");
            Err(HostError::RecoveryRequired(format!(
                "{reason}; recovery disposition succeeded but exact registry readback failed"
            )))
        }
        Err(_error) if exact_readback => {
            host_epoch_observe("host.epoch recovery exact readback confirmed");
            Ok(())
        }
        Err(error) => {
            host_epoch_observe("host.epoch recovery disposition failed observed");
            Err(HostError::RecoveryRequired(format!(
                "{reason}; durable recovery disposition failed and exact readback did not confirm it: {error}"
            )))
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn open_production_epoch(
    path: &Path,
    installation: PlatformHandle,
    pending: Option<&eliot_installation::PendingActivation>,
    active_phase_b_rebind: Option<&eliot_installation::ActivePhaseBRebind>,
    store_recovery_fences: &[StoreRecoveryReopenFence],
) -> Result<
    (
        ProductionHostStateJournal,
        HostInstallationEpoch,
        EpochTransition,
        PlatformHandle,
        StoreRecoveryStartupFence,
        ActivePhaseBRebindRecoveryKind,
    ),
    HostError,
> {
    host_epoch_observe("host.epoch production open requested");
    let backend = RedbJournalBackend::open_at(path).map_err(JournalError::Backend)?;
    host_epoch_observe("host.epoch backend open observed");
    open_production_epoch_from_backend(
        backend,
        installation,
        pending,
        active_phase_b_rebind,
        store_recovery_fences,
    )
}

pub(super) fn open_production_epoch_from_backend(
    mut backend: RedbJournalBackend,
    installation: PlatformHandle,
    pending: Option<&eliot_installation::PendingActivation>,
    active_phase_b_rebind: Option<&eliot_installation::ActivePhaseBRebind>,
    store_recovery_fences: &[StoreRecoveryReopenFence],
) -> Result<
    (
        ProductionHostStateJournal,
        HostInstallationEpoch,
        EpochTransition,
        PlatformHandle,
        StoreRecoveryStartupFence,
        ActivePhaseBRebindRecoveryKind,
    ),
    HostError,
> {
    let last_host = backend
        .load()
        .map_err(JournalError::Backend)?
        .epochs
        .last()
        .map(|epoch| epoch.host.clone());
    host_epoch_observe("host.epoch last host observed");

    let (
        journal,
        host,
        activation_generation,
        activation_id,
        store_recovery_startup_fence,
        active_phase_b_rebind_recovery,
    ) = if let Some(last_host) = last_host {
        let current = HostStateJournalService::from_backend(backend, last_host.clone())?;
        let retained_activation_id = current
            .snapshot()?
            .activation
            .as_ref()
            .map(|activation| activation.activation_id.clone());
        let (
            journal,
            host,
            activation_generation,
            store_recovery_startup_fence,
            active_phase_b_rebind_recovery,
        ) = reopen_existing_epoch(
            current,
            &last_host,
            &installation,
            pending,
            active_phase_b_rebind,
            store_recovery_fences,
        )?;
        let activation_id = if store_recovery_startup_fence.is_fenced() {
            retained_activation_id.ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store recovery fence has no retained activation identity".to_owned(),
                )
            })?
        } else {
            fresh_identity("activation")?
        };
        if store_recovery_startup_fence.is_fenced() {
            host_epoch_observe("host.epoch activation retained");
        } else {
            host_epoch_observe("host.epoch activation fresh observed");
        }
        (
            journal,
            host,
            activation_generation,
            activation_id,
            store_recovery_startup_fence,
            active_phase_b_rebind_recovery,
        )
    } else if !store_recovery_fences.is_empty() {
        host_epoch_observe("host.epoch fence without prior observed");
        return Err(HostError::RecoveryRequired(
            "Store recovery fence has no prior Host epoch; manual new-lineage recovery is required"
                .to_owned(),
        ));
    } else {
        let host = fresh_host_epoch(installation, None)?;
        (
            HostStateJournalService::from_backend(backend, host.clone())?,
            host,
            root_epoch(fresh_lineage_id()?),
            fresh_identity("activation")?,
            StoreRecoveryStartupFence::Clear,
            ActivePhaseBRebindRecoveryKind::None,
        )
    };
    if store_recovery_startup_fence.is_fenced() {
        host_epoch_observe("host.epoch activation replay observed");
    } else {
        append_reconciled(
            &journal,
            HostStateRecord::Activation(initial_activation_record(
                &host,
                &activation_id,
                &activation_generation,
                ActivationState::Stopped,
                "host-open",
            )?),
        )?;
        host_epoch_observe("host.epoch activation appended");
    }
    Ok((
        journal,
        host,
        activation_generation,
        activation_id,
        store_recovery_startup_fence,
        active_phase_b_rebind_recovery,
    ))
}

#[cfg(all(windows, test))]
pub(super) fn open_test_support_epoch(
    path: &Path,
    installation: PlatformHandle,
    pending: Option<&eliot_installation::PendingActivation>,
    active_phase_b_rebind: Option<&eliot_installation::ActivePhaseBRebind>,
) -> Result<
    (
        ProductionHostStateJournal,
        HostInstallationEpoch,
        EpochTransition,
        PlatformHandle,
        ActivePhaseBRebindRecoveryKind,
    ),
    HostError,
> {
    let backend =
        RedbJournalBackend::open_unprotected_for_test(path).map_err(JournalError::Backend)?;
    let (journal, host, activation_generation, activation_id, startup_fence, recovery_kind) =
        open_production_epoch_from_backend(
            backend,
            installation,
            pending,
            active_phase_b_rebind,
            &[],
        )?;
    if startup_fence.is_fenced() {
        return Err(HostError::RecoveryRequired(
            "test-support Phase-B epoch unexpectedly opened behind a Store recovery fence"
                .to_owned(),
        ));
    }
    Ok((
        journal,
        host,
        activation_generation,
        activation_id,
        recovery_kind,
    ))
}
