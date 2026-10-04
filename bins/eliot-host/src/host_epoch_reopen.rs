use std::path::Path;

use super::{
    ActivationState, ActivePhaseBRebindRecoveryKind, ApprovedGenerationRegistry, EpochTransition,
    HostError, HostInstallationEpoch, HostState, HostStateJournalService, HostStateRecord,
    JournalBackend, JournalError, KernelActivationState, PendingActivationState, PlatformHandle,
    PriorKernelDisposition, ProductionHostStateJournal, ReconcileOutcome, RedbJournalBackend,
    StoreRecoveryReopenFence, StoreRecoveryStartupFence, active_phase_b_rebind_recovery_kind,
    append_reconciled, child_host_epoch, epoch_contract_error, fresh_host_epoch, fresh_identity,
    fresh_lineage_id, initial_activation_record, root_epoch,
};
use crate::activation_lifecycle::{ActivationTriggerClass, control_contour_capabilities};
use crate::journal_append::{
    ActivationIngress, HostJournalDisposition, HostJournalObservation,
    observe_host_journal_boundary,
};

/// Durable `trigger_class` of an activation generation that Host itself opened
/// without an installer-approved pending transaction.
///
/// I1.5's observable-use vocabulary covers authenticated requests; a bare SCM
/// demand-start is none of those, it is the Host lifecycle opening its own
/// control contour. The spelling is frozen here so the creation record and every
/// reader of it agree, and it is only ever used when no approved transaction
/// exists to name instead.
const HOST_LIFECYCLE_TRIGGER_CLASS: &str = "host-runtime-lifecycle";
/// Durable `requester_principal_session_or_scheduler` of that same
/// no-transaction Host lifecycle activation.
const HOST_COMPOSITION_REQUESTER: &str = "host-composition";

/// Derives the I1.5 ingress of the activation generation this open creates.
///
/// The record's `trigger_class` and `requester` come from the admission evidence
/// the open actually holds rather than from one fixed spelling: an
/// installer-approved activation names the approved transaction that started
/// it, while a plain SCM demand-start has no approved transaction to name and
/// stays the Host lifecycle opening its own control contour.
///
/// Each arm records the capability set of the admission it actually holds.
/// The installer-pending arm records the admitted
/// [`ActivationTriggerClass::ApprovedMaintenanceJob`] set — the authenticated
/// request the pending transaction carries — not the bootstrap full contour,
/// so a generation created for that request is never bound to a broader
/// requirement no admitted request stated. The bare SCM arm has no admitted
/// request to record, so it keeps the bootstrap control contour the Host
/// readiness fence needs; narrower or broader observable-use classes that join
/// later contribute their own [`ActivationTriggerClass::requested_capabilities`]
/// set through the coalescing append path, which only ever unions admitted
/// trigger sets into the durable record and never rewrites this creation
/// ingress.
fn activation_ingress(
    pending: Option<&eliot_installation::PendingActivation>,
) -> ActivationIngress {
    match pending {
        Some(pending) => ActivationIngress {
            trigger_class: ActivationTriggerClass::ApprovedMaintenanceJob.as_str(),
            requester: format!("pending-activation:{}", pending.transaction_id.as_str()),
            capabilities: ActivationTriggerClass::ApprovedMaintenanceJob.requested_capabilities(),
        },
        None => ActivationIngress {
            trigger_class: HOST_LIFECYCLE_TRIGGER_CLASS,
            requester: HOST_COMPOSITION_REQUESTER.to_owned(),
            capabilities: control_contour_capabilities(),
        },
    }
}

// F-LOG-HOST-6 (#981) epoch-reopen observation helper.
//
// The per-file seam of the family's shared closed vocabulary: it names the epoch
// reopen boundary set and delegates to the one shared emitter. These primitives
// own no terminal: the single terminal per failed open operation belongs to the
// outermost `Host::open` boundary in `lib.rs` (#891, `host-open-failed`), so
// every record here is a subordinate observation of a fact the epoch owner
// already decided. The exact owner identities the reopen already holds —
// installation, Host epoch, lineage, activation generation, and each pending
// transaction's own identity, record checksum and Host epoch — travel with the
// record instead of the record relying on stage order alone. Replayed committed
// state is observed as readback, never as a second effect, and the live Event
// Log disposition is observed through the facade's canonical bounded helper
// rather than a discarded probe (I15.4).
fn host_epoch_observe(observation: &HostJournalObservation) {
    observe_host_journal_boundary(observation);
}

/// I14.16 step 6 (issue #1953 W5): verifies the retired Kernel contour left
/// no unproven authority behind before Host records a new installation epoch
/// with a fresh one-time host-process nonce.
///
/// This is the epoch-owner half of the cutover ordering the activation
/// driver enforces live (`handoff_prepared` ->
/// `prior_disposition_committed`, the sole transition to `OldTerminated`,
/// -> `issue_nonce`, which refuses before `OldTerminated`): a new
/// `HostInstallationEpoch` must not be recorded while the replayed journal
/// still carries a prior Kernel that never reached a proven-terminated
/// disposition or a terminal activation state. Such a record means process
/// termination and exclusive lock release were never proven, so minting a
/// fresh epoch and nonce here would fork an ambiguous owner lineage; the
/// open stops in manual recovery instead, and the retained record stays
/// queryable.
///
/// The live operating-system proof half (`prove_released` on the retired
/// contour's exclusive owner object) lives in the activation driver
/// (`kernel_activation_driver.rs` via `kernel_owner_exclusivity.rs`) and is
/// not re-probed here: by the time a new Host process reaches this path, a
/// Host-owned kill-on-close Job has already terminated the old children, so
/// only the durable disposition is re-checked, never re-proven.
///
/// Accepted unchanged: no retained Kernel record; a retained record in
/// `OldTerminated` (whose durable transition already ran the release proof),
/// `Active` (clean-shutdown path: the shutdown manifest observed child
/// termination before exit), `Failed`, `ManualRecovery` or `Idle`; and a
/// `NoPriorKernel`/`Terminated` durable disposition. Refused: unknown
/// prior-Kernel authority, a `Running`/`Unknown` durable disposition, or a
/// retained record still in a pre-termination live state
/// (`ShadowNoAuthority`, `HandoffPrepared`, `NonceIssued`, `Activating`).
fn require_prior_kernel_released_for_new_epoch(replayed: &HostState) -> Result<(), HostError> {
    if replayed.prior_kernel_unknown {
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch prior kernel unknown observed",
                HostJournalDisposition::BoundaryReached,
            )
            .with_host(&replayed.host),
        );
        return Err(HostError::RecoveryRequired(
            "new Host installation epoch requires a known prior-Kernel disposition; unknown observations stop activation but remain queryable".to_owned(),
        ));
    }
    let Some(kernel) = replayed.kernel.as_ref() else {
        return Ok(());
    };
    match &kernel.prior_kernel_disposition {
        PriorKernelDisposition::NoPriorKernel | PriorKernelDisposition::Terminated(_) => {}
        PriorKernelDisposition::Running(_) | PriorKernelDisposition::Unknown(_) => {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch prior kernel unverified observed",
                    HostJournalDisposition::BoundaryReached,
                )
                .with_record_fence(&kernel.fence),
            );
            return Err(HostError::RecoveryRequired(
                "new Host installation epoch requires a terminated prior-Kernel disposition; the retained disposition is still live or unknown".to_owned(),
            ));
        }
    }
    match kernel.state {
        KernelActivationState::ShadowNoAuthority
        | KernelActivationState::HandoffPrepared
        | KernelActivationState::NonceIssued
        | KernelActivationState::Activating => {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch prior kernel retained live observed",
                    HostJournalDisposition::BoundaryReached,
                )
                .with_record_fence(&kernel.fence),
            );
            Err(HostError::RecoveryRequired(
                "new Host installation epoch requires prior Kernel termination and exclusive lock release; the retained Kernel never reached OldTerminated".to_owned(),
            ))
        }
        KernelActivationState::Idle
        | KernelActivationState::OldTerminated
        | KernelActivationState::Active
        | KernelActivationState::Failed
        | KernelActivationState::ManualRecovery => Ok(()),
    }
}

#[allow(clippy::too_many_lines)]
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
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch reopen existing requested",
            HostJournalDisposition::BoundaryReached,
        )
        .with_host(last_host),
    );
    if last_host.installation != *installation {
        // The requested installation is the entire subject of this refusal, so
        // only that side is bound here. `with_host` writes `installation` as
        // well and the emitter is last-write-wins, so chaining it would
        // overwrite the requested value with the retained epoch's matching one
        // and the mismatch could never be read. The retained side is already
        // reported by the `host.epoch reopen existing requested` record emitted
        // immediately above this check, which binds `with_host(last_host)`: one
        // slot cannot carry both sides and a second installation slot is outside
        // this issue's vocabulary. The later `host.epoch reopen fence observed`
        // record binds the same retained value but is unreachable from this arm,
        // because this refusal returns before the reconciliation and fence loop
        // that precedes it.
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch install mismatch observed",
                HostJournalDisposition::BoundaryReached,
            )
            .with_installation(installation.as_str()),
        );
        return Err(HostError::OwnerLeaseRecovery(
            "Host journal installation identity does not match admission".to_owned(),
        ));
    }
    // Every prepared append is reconciled under its own transaction identity
    // before this reopen is allowed to read a snapshot: a readable snapshot is
    // never read as a pending reconciliation, and each answer carries the exact
    // operation, transaction, record checksum and Host epoch the journal itself
    // prepared. Both unresolved answers stay fail-closed here, as before; what
    // changes is that a proven noncommit can no longer be read as an unknown
    // outcome (I14.21).
    let prepared_appends = current.pending_transactions()?;
    let prepared_total = u64::try_from(prepared_appends.len()).unwrap_or(u64::MAX);
    let mut committed_total = 0_u64;
    for prepared in &prepared_appends {
        match current.reconcile(&prepared.transaction_id)? {
            ReconcileOutcome::Committed => {
                committed_total += 1;
                host_epoch_observe(
                    &HostJournalObservation::new(
                        "host.epoch pending transaction reconciled observed",
                        HostJournalDisposition::ReconcileCommitted,
                    )
                    .with_prepared_append(prepared),
                );
            }
            ReconcileOutcome::NotCommitted => {
                host_epoch_observe(
                    &HostJournalObservation::new(
                        "host.epoch pending transaction not committed observed",
                        HostJournalDisposition::ReconcileNotCommitted,
                    )
                    .with_prepared_append(prepared),
                );
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id: prepared.transaction_id.clone(),
                }));
            }
            ReconcileOutcome::StillUnknown => {
                host_epoch_observe(
                    &HostJournalObservation::new(
                        "host.epoch pending transaction unknown observed",
                        HostJournalDisposition::ReconcileStillUnknown,
                    )
                    .with_prepared_append(prepared),
                );
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id: prepared.transaction_id.clone(),
                }));
            }
        }
    }
    let replayed = current.snapshot()?;
    // Both unresolved reconciliation answers returned above, so reaching this
    // record with a non-zero denominator means every prepared append of this
    // reopen reconciled as committed; a zero denominator is never read as a
    // reconciled pending work and never as a fresh epoch increment.
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch pending reconcile observed",
            if prepared_total == 0 {
                HostJournalDisposition::DenominatorEmpty
            } else {
                HostJournalDisposition::DenominatorReconciled
            },
        )
        .with_host(last_host)
        .with_cardinality(prepared_total)
        .with_committed(committed_total),
    );
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
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch reopen fence observed",
            if store_recovery_startup_fence.is_fenced() {
                HostJournalDisposition::FenceUnresolved
            } else {
                HostJournalDisposition::FenceClear
            },
        )
        .with_host(last_host)
        .with_cardinality(u64::try_from(store_recovery_fences.len()).unwrap_or(u64::MAX)),
    );
    let active_phase_b_rebind_recovery = active_phase_b_rebind_recovery_kind(active_phase_b_rebind);
    if pending.is_none()
        && active_phase_b_rebind.is_none()
        && replayed.clean_marker.is_none()
        && !store_recovery_startup_fence.is_fenced()
    {
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch unclean observed",
                HostJournalDisposition::BoundaryReached,
            )
            .with_host(last_host),
        );
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
        // I14.16 step 6 (#1953 W5): Host verification of prior termination
        // and exclusive lock release comes before recording the new
        // installation epoch and its one-time host-process nonce. The fenced
        // and prepared arms above retain the exact prior epoch; only this
        // advancing arm mints fresh lineage, so only it takes the gate.
        require_prior_kernel_released_for_new_epoch(&replayed)?;
        child_host_epoch(last_host)?
    };
    if store_recovery_startup_fence.is_fenced()
        || pending.is_some_and(|pending| pending.phase_b_prepared.is_some())
    {
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch owner epoch retained",
                HostJournalDisposition::OwnerEpochRetained,
            )
            .with_host(&host)
            .with_activation_generation(&activation_generation),
        );
    } else {
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch owner child epoch observed",
                HostJournalDisposition::OwnerEpochChildCreated,
            )
            .with_host(&host)
            .with_activation_generation(&activation_generation),
        );
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

#[allow(clippy::too_many_lines)]
pub(super) fn persist_pending_recovery(
    host_state_root: &Path,
    registry: &mut ApprovedGenerationRegistry,
    host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    pending: &eliot_installation::PendingActivation,
    reason: &str,
) -> Result<(), HostError> {
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch pending recovery requested",
            HostJournalDisposition::BoundaryReached,
        )
        .with_recovery_binding(pending.transaction_id.as_str())
        .with_contour(pending.plan_digest.as_str()),
    );
    pending
        .manifest
        .runtime_launch
        .validate()
        .map_err(HostError::Installation)?;
    if !crate::windows_paths_equal(
        Path::new(
            pending
                .manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        host_state_root,
    ) {
        return Err(HostError::ProcessContour(
            "pending recovery profile does not bind the selected Host root".to_owned(),
        ));
    }
    let profile = pending.manifest.runtime_launch.profile;
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
        let store = crate::open_registry_store_at_profile(host_state_root, profile)?;
        store.mark_pending_recovery(
            host_capability,
            expected_revision,
            &pending.approval,
            reason,
        )
    };
    let durable = {
        let store = crate::open_registry_store_at_profile(host_state_root, profile)?;
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
    // One record per readback outcome. This record is the observation of the
    // load itself: it says the registry was durably assigned from this
    // snapshot and it binds only that transaction and its plan-digest contour,
    // never the comparison verdict. Each arm below then emits exactly one
    // distinct verdict record, and because the four arms are mutually
    // exclusive the verdict is reported once and only once. The pending
    // transaction identity and its contour are bound on every arm as well, so
    // no record is left without them.
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch recovery readback observed",
            HostJournalDisposition::BoundaryReached,
        )
        .with_recovery_binding(pending.transaction_id.as_str())
        .with_contour(pending.plan_digest.as_str()),
    );
    match outcome {
        Ok(()) if exact_readback => {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch recovery exact readback confirmed",
                    HostJournalDisposition::EvidenceValidated,
                )
                .with_recovery_binding(pending.transaction_id.as_str())
                .with_contour(pending.plan_digest.as_str()),
            );
            Ok(())
        }
        Ok(()) => {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch recovery readback mismatch observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_recovery_binding(pending.transaction_id.as_str())
                .with_contour(pending.plan_digest.as_str()),
            );
            Err(HostError::RecoveryRequired(format!(
                "{reason}; recovery disposition succeeded but exact registry readback failed"
            )))
        }
        Err(_error) if exact_readback => {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch recovery exact readback confirmed",
                    HostJournalDisposition::EvidenceValidated,
                )
                .with_recovery_binding(pending.transaction_id.as_str())
                .with_contour(pending.plan_digest.as_str()),
            );
            Ok(())
        }
        Err(error) => {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch recovery disposition failed observed",
                    HostJournalDisposition::EvidenceUnusable,
                )
                .with_recovery_binding(pending.transaction_id.as_str())
                .with_contour(pending.plan_digest.as_str()),
            );
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
    profile: eliot_installation::InstallationProfile,
    profile_selection: Option<
        &eliot_platform_windows::profile_supervision::ProfileSelectionReceipt,
    >,
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
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch production open requested",
            HostJournalDisposition::BoundaryReached,
        )
        .with_installation(installation.as_str()),
    );
    let backend = match profile {
        eliot_installation::InstallationProfile::SystemService => {
            if profile_selection.is_some() {
                return Err(HostError::ProcessContour(
                    "SystemService journal reopen cannot accept a current-user root receipt"
                        .to_owned(),
                ));
            }
            RedbJournalBackend::open_at(path)
        }
        eliot_installation::InstallationProfile::UserMode
        | eliot_installation::InstallationProfile::PortableDev => {
            let selection = profile_selection.ok_or_else(|| {
                HostError::ProcessContour(
                    "current-user journal reopen requires the descriptor-validated root receipt"
                        .to_owned(),
                )
            })?;
            let profile_matches_selection = matches!(
                (profile, selection.profile),
                (
                    eliot_installation::InstallationProfile::UserMode,
                    eliot_platform_windows::profile_supervision::ProfileSelection::UserMode
                ) | (
                    eliot_installation::InstallationProfile::PortableDev,
                    eliot_platform_windows::profile_supervision::ProfileSelection::PortableDev
                )
            );
            if !profile_matches_selection {
                return Err(HostError::ProcessContour(
                    "current-user journal root receipt does not match the selected profile"
                        .to_owned(),
                ));
            }
            RedbJournalBackend::open_user_owned_at(path, selection)
        }
    }
    .map_err(JournalError::Backend)?;
    host_epoch_observe(&HostJournalObservation::new(
        "host.epoch backend open observed",
        HostJournalDisposition::BoundaryReached,
    ));
    open_production_epoch_from_backend(
        backend,
        installation,
        pending,
        active_phase_b_rebind,
        store_recovery_fences,
    )
}

#[allow(clippy::too_many_lines)]
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
    let last_host_present = last_host.is_some();
    host_epoch_observe(
        &HostJournalObservation::new(
            "host.epoch last host observed",
            if last_host_present {
                HostJournalDisposition::BoundaryReached
            } else {
                HostJournalDisposition::DenominatorEmpty
            },
        )
        .with_installation(installation.as_str())
        .with_cardinality(u64::from(last_host_present)),
    );

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
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch activation retained",
                    HostJournalDisposition::OwnerEpochRetained,
                )
                .with_operation(activation_id.as_str())
                .with_host(&host)
                .with_activation_generation(&activation_generation),
            );
        } else {
            host_epoch_observe(
                &HostJournalObservation::new(
                    "host.epoch activation fresh observed",
                    HostJournalDisposition::OwnerEpochChildCreated,
                )
                .with_operation(activation_id.as_str())
                .with_host(&host)
                .with_activation_generation(&activation_generation),
            );
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
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch fence without prior observed",
                HostJournalDisposition::FenceUnresolved,
            )
            .with_installation(installation.as_str())
            .with_cardinality(u64::try_from(store_recovery_fences.len()).unwrap_or(u64::MAX)),
        );
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
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch activation replay observed",
                HostJournalDisposition::PublicationReplayed,
            )
            .with_operation(activation_id.as_str())
            .with_host(&host)
            .with_activation_generation(&activation_generation),
        );
    } else {
        let receipt = append_reconciled(
            &journal,
            HostStateRecord::Activation(initial_activation_record(
                &host,
                &activation_id,
                &activation_generation,
                ActivationState::Stopped,
                "host-open",
                &activation_ingress(pending),
            )?),
        )?;
        // The applied/replayed disposition of this exact append is the journal
        // owner's correlated lower-stage detail and is reported there once. This
        // subordinate record carries only what the epoch owner holds: the
        // activation identity, the owner-issued Host epoch and generation, and
        // the journal transaction and sequence this publication produced.
        host_epoch_observe(
            &HostJournalObservation::new(
                "host.epoch activation appended",
                HostJournalDisposition::BoundaryReached,
            )
            .with_operation(activation_id.as_str())
            .with_host(&host)
            .with_activation_generation(&activation_generation)
            .with_receipt(&receipt),
        );
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
