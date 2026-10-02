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
use crate::journal_append::ActivationIngress;

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

// F-LOG-HOST-6 (#981) epoch-reopen observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Frozen boundary labels are static literals, and the
// identity slots they carry are the exact owner-held nonsecret handles this
// reopen already has in hand (see [`HostEpochReopenObservation`]) — never a
// nonce, capability, MAC/digest, record byte, raw path, payload, credential or
// arbitrary error text — so bounding limits size, not sensitivity (I15.4).
// These primitives own no terminal: a single terminal per failed open
// operation is enforced by the outermost `Host::open` boundary in `lib.rs`
// (#891, `host-open-failed`), while these phases never emit one. Replayed
// committed state is observed as readback, never as a second effect. Sink
// outcome never alters result/order/cleanup.
fn host_epoch_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

/// Owner identities bound to one epoch-reopen observation (F-LOG-HOST-6, #981
/// blocking defect 4).
///
/// Every slot projects a fact this reopen already holds: the admission-held
/// installation identity, the owner-issued sequence and lineage of the LAST
/// durable Host epoch being resumed, the owner-issued sequence and lineage of
/// the RESULTING epoch this reopen retained or created, the startup fence
/// disposition the owner just decided, and the exact cardinality the owner
/// itself produced. A slot the owner does not hold at that point renders EMPTY
/// with its `key=<key>_missing` disposition — the explicit missing-evidence
/// projection the sibling `backup_cutover` correlation and the
/// `host_composition_store_recovery` observation use for exactly this — so an
/// absent identity can never be read as a value this boundary did not hold, and
/// never has to be inferred from a neighbouring record or from temporal order
/// (I14.20).
///
/// Denominators are counted from the reconciliation loop itself, never
/// inferred from the fact that a snapshot was readable: an empty pending
/// denominator and an all-committed denominator are different records.
///
/// Cost: copies of handles already in hand. No owner read, no digest
/// computation, no resource acquisition, no retry and no mutation. The
/// composed detail stays under [`crate::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES`]
/// for the pinned handle shapes used here; the facade's own bound remains the
/// final cut with its truncation honesty record.
struct HostEpochReopenObservation<'a> {
    label: &'static str,
    installation: Option<&'a str>,
    /// Owner-issued sequence of the last durable Host epoch.
    epoch: Option<u64>,
    /// Owner-issued lineage of the last durable Host epoch.
    lineage: Option<&'a str>,
    /// Owner-issued sequence of the resulting retained/created epoch.
    owner_epoch: Option<u64>,
    /// Owner-issued lineage of the resulting retained/created epoch.
    owner_lineage: Option<&'a str>,
    /// Frozen disposition of the owner's `StoreRecoveryStartupFence`.
    fence: Option<&'static str>,
    /// Exact number of unresolved Store recovery bindings behind an
    /// `Unresolved` fence; absent for a `Clear` fence.
    fence_bindings: Option<u64>,
    /// Exact pending-transaction denominator this reopen iterated.
    pending: Option<u64>,
    /// Exact number of those pending transactions the owner reported as
    /// committed.
    pending_committed: Option<u64>,
}

impl<'a> HostEpochReopenObservation<'a> {
    /// Binds the admission-held installation identity and the last durable
    /// owner-issued Host epoch this reopen is resuming. The resulting epoch
    /// slots stay missing: no resulting epoch has been decided yet.
    fn for_last_epoch(label: &'static str, last_host: &'a HostInstallationEpoch) -> Self {
        Self {
            label,
            installation: Some(last_host.installation.as_str()),
            epoch: Some(last_host.epoch.current.sequence.get()),
            lineage: Some(last_host.epoch.current.lineage_id.as_str()),
            owner_epoch: None,
            owner_lineage: None,
            fence: None,
            fence_bindings: None,
            pending: None,
            pending_committed: None,
        }
    }

    /// Binds the exact cardinality the pending-transaction loop itself
    /// produced: the total it iterated and how many of those the owner reported
    /// committed. Both come from the loop, never from snapshot readability.
    fn with_pending_reconcile(mut self, pending: u64, pending_committed: u64) -> Self {
        self.pending = Some(pending);
        self.pending_committed = Some(pending_committed);
        self
    }

    /// Binds the owner's decided startup-fence disposition. An `Unresolved`
    /// fence additionally carries the exact number of validated bindings; a
    /// `Clear` fence carries no binding count because the owner holds none.
    fn with_startup_fence(mut self, startup_fence: &StoreRecoveryStartupFence) -> Self {
        let (fence, fence_bindings) = match startup_fence {
            StoreRecoveryStartupFence::Clear => ("clear", None),
            StoreRecoveryStartupFence::Unresolved(bindings) => (
                "unresolved",
                Some(u64::try_from(bindings.len()).unwrap_or(u64::MAX)),
            ),
        };
        self.fence = Some(fence);
        self.fence_bindings = fence_bindings;
        self
    }

    /// Binds the resulting owner-issued epoch: the retained prior epoch or the
    /// newly created direct child, exactly as the owner decided it.
    fn with_resulting_epoch(mut self, host: &'a HostInstallationEpoch) -> Self {
        self.owner_epoch = Some(host.epoch.current.sequence.get());
        self.owner_lineage = Some(host.epoch.current.lineage_id.as_str());
        self
    }
}

/// Appends one `key=value` pair, or the explicit `key=<key>_missing`
/// disposition when the owner holds no value for that slot. Both forms go
/// through the facade's own bounding helper, so a longer handle is cut with the
/// facade's truncation honesty rather than emitted whole.
fn push_epoch_observation_field(detail: &mut String, key: &str, value: Option<&str>) {
    let text = value.map_or_else(
        || {
            let mut missing = String::from(key);
            missing.push_str("_missing");
            missing
        },
        |text| crate::host_diagnostics::bound_field(text).text().to_owned(),
    );
    detail.push(' ');
    detail.push_str(key);
    detail.push('=');
    detail.push_str(&text);
}

/// The counting sibling of [`push_epoch_observation_field`]: an owner-issued
/// count is rendered as its decimal text through the same bounding helper, or
/// as the explicit `<key>_missing` disposition when the owner holds none. A
/// count is only ever rendered when the owner itself produced it.
fn push_epoch_observation_count(detail: &mut String, key: &str, value: Option<u64>) {
    let text = value.map(|count| count.to_string());
    push_epoch_observation_field(detail, key, text.as_deref());
}

/// Emits one identity-bound epoch-reopen observation through the #889 facade.
///
/// The frozen boundary label stays first so label-prefix consumers keep
/// matching; the owner identities follow as `k=v` pairs, with `k=k_missing`
/// for every slot the owner does not hold at this point.
fn host_epoch_observe_reopen(observation: &HostEpochReopenObservation<'_>) {
    let mut detail = String::from(observation.label);
    push_epoch_observation_field(&mut detail, "installation", observation.installation);
    push_epoch_observation_count(&mut detail, "epoch", observation.epoch);
    push_epoch_observation_field(&mut detail, "lineage", observation.lineage);
    push_epoch_observation_count(&mut detail, "owner_epoch", observation.owner_epoch);
    push_epoch_observation_field(&mut detail, "owner_lineage", observation.owner_lineage);
    push_epoch_observation_field(&mut detail, "fence", observation.fence);
    push_epoch_observation_count(&mut detail, "fence_bindings", observation.fence_bindings);
    push_epoch_observation_count(&mut detail, "pending", observation.pending);
    push_epoch_observation_count(&mut detail, "pending_committed", observation.pending_committed);
    host_epoch_observe(&detail);
}

/// Reconciles every pending transaction this owner currently holds and returns
/// the exact denominator it iterated together with the number the owner itself
/// reported committed.
///
/// The counts are the ONLY source for the pending-reconcile observation: they
/// come from the loop, so an empty denominator can never be confused with a
/// reconciled one and neither is ever inferred from a readable snapshot. The
/// owner's own outcome mapping, the fail-closed `OutcomeUnknown` error and its
/// transaction identity are unchanged: a known noncommit and a still-unknown
/// outcome keep the single owner-chosen refusal this caller always returned.
fn reconcile_pending_transactions<B: JournalBackend>(
    current: &HostStateJournalService<B>,
) -> Result<(u64, u64), HostError> {
    let pending_transactions = current.pending_transactions()?;
    let pending_total = u64::try_from(pending_transactions.len()).unwrap_or(u64::MAX);
    let mut pending_committed = 0_u64;
    for pending in &pending_transactions {
        match current.reconcile(&pending.transaction_id)? {
            ReconcileOutcome::Committed => pending_committed = pending_committed.saturating_add(1),
            ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                return Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id: pending.transaction_id.clone(),
                }));
            }
        }
    }
    Ok((pending_total, pending_committed))
}

/// Observes the exact pending-transaction denominator this reopen iterated.
///
/// An EMPTY denominator is a different fact from a denominator the owner
/// reconciled and reported committed, so it is a different record: with zero
/// pending transactions no pending reconciliation was observed at all, and only
/// the loop's own counts can tell the two apart. Snapshot readability is never
/// the evidence for either.
fn observe_epoch_pending_reconcile(
    last_host: &HostInstallationEpoch,
    pending: u64,
    pending_committed: u64,
) {
    let label = if pending == 0 {
        "host.epoch no pending transactions observed"
    } else {
        "host.epoch pending reconcile committed observed"
    };
    host_epoch_observe_reopen(
        &HostEpochReopenObservation::for_last_epoch(label, last_host)
            .with_pending_reconcile(pending, pending_committed),
    );
}

/// Observes the startup-fence disposition the owner just decided.
///
/// `Clear` and `Unresolved` are different owner dispositions and must not
/// share one undifferentiated label: only `Unresolved` holds validated Store
/// recovery bindings, and only it leaves the startup fenced.
fn observe_epoch_reopen_fence(
    last_host: &HostInstallationEpoch,
    startup_fence: &StoreRecoveryStartupFence,
) {
    let label = match startup_fence {
        StoreRecoveryStartupFence::Clear => "host.epoch reopen fence clear observed",
        StoreRecoveryStartupFence::Unresolved(_) => "host.epoch reopen fence unresolved observed",
    };
    host_epoch_observe_reopen(
        &HostEpochReopenObservation::for_last_epoch(label, last_host)
            .with_startup_fence(startup_fence),
    );
}

/// Observes the epoch the owner actually retained or created, bound to the
/// owner-issued epoch/lineage it decided and to the fence disposition that
/// decided it. Retained and created stay different labels, and neither ever
/// carries an inferred or ownerless epoch.
fn observe_epoch_owner_outcome(
    label: &'static str,
    last_host: &HostInstallationEpoch,
    startup_fence: &StoreRecoveryStartupFence,
    host: &HostInstallationEpoch,
) {
    host_epoch_observe_reopen(
        &HostEpochReopenObservation::for_last_epoch(label, last_host)
            .with_startup_fence(startup_fence)
            .with_resulting_epoch(host),
    );
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
        host_epoch_observe("host.epoch prior kernel unknown observed");
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
            host_epoch_observe("host.epoch prior kernel unverified observed");
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
            host_epoch_observe("host.epoch prior kernel unverified observed");
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
    // The exact pending denominator is whatever THIS reconciliation iterates,
    // counted as it iterates. Snapshot readability is never evidence of a
    // pending reconciliation, so the readable snapshot below cannot stand in
    // for it.
    let (pending_total, pending_committed) = reconcile_pending_transactions(&current)?;
    let replayed = current.snapshot()?;
    observe_epoch_pending_reconcile(last_host, pending_total, pending_committed);
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
    observe_epoch_reopen_fence(last_host, &store_recovery_startup_fence);
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
        // I14.16 step 6 (#1953 W5): Host verification of prior termination
        // and exclusive lock release comes before recording the new
        // installation epoch and its one-time host-process nonce. The fenced
        // and prepared arms above retain the exact prior epoch; only this
        // advancing arm mints fresh lineage, so only it takes the gate.
        require_prior_kernel_released_for_new_epoch(&replayed)?;
        child_host_epoch(last_host)?
    };
    // Retained and created are different outcomes, and each record names the
    // owner-issued epoch/lineage it actually decided plus the fence identity
    // that decided it — never an inferred or ownerless epoch.
    if store_recovery_startup_fence.is_fenced()
        || pending.is_some_and(|pending| pending.phase_b_prepared.is_some())
    {
        observe_epoch_owner_outcome(
            "host.epoch owner epoch retained",
            last_host,
            &store_recovery_startup_fence,
            &host,
        );
    } else {
        observe_epoch_owner_outcome(
            "host.epoch owner child epoch observed",
            last_host,
            &store_recovery_startup_fence,
            &host,
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

pub(super) fn persist_pending_recovery(
    host_state_root: &Path,
    registry: &mut ApprovedGenerationRegistry,
    host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    pending: &eliot_installation::PendingActivation,
    reason: &str,
) -> Result<(), HostError> {
    host_epoch_observe("host.epoch pending recovery requested");
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
    host_epoch_observe("host.epoch production open requested");
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
                &activation_ingress(pending),
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
