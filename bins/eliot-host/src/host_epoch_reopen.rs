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

#[cfg(test)]
mod store_recovery_fence_reopen_case_tests {
    use std::path::{Path, PathBuf};

    use eliot_host_state::MemoryBackend;
    use uuid::Uuid;

    use super::*;
    use crate::TestResult;

    fn temp_root(label: &str) -> Result<PathBuf, crate::TestError> {
        let root = std::env::temp_dir().join(format!(
            "eliot-host-reopen-fence-{label}-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    /// Runs `emit` under a scoped `tracing` subscriber whose only sink is a
    /// file inside the test's own isolated directory, then returns what the
    /// production path emitted plus the value it produced.
    fn capture<T>(dir: &Path, emit: impl FnOnce() -> T) -> (T, String) {
        let path = dir.join("diagnostic-capture.log");
        let file = std::fs::File::create(&path).unwrap_or_else(|_| unreachable!());
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(file)
            .finish();
        let mut outcome = None;
        tracing::subscriber::with_default(subscriber, || {
            outcome = Some(emit());
        });
        let captured = std::fs::read_to_string(&path).unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_file(&path);
        (outcome.unwrap_or_else(|| unreachable!()), captured)
    }

    /// The bounded `detail` values the #889 facade emitted, in emission order.
    fn details(captured: &str) -> Vec<String> {
        const KEY: &str = "detail=\"";
        let mut fields = Vec::new();
        let mut rest = captured;
        while let Some(index) = rest.find(KEY) {
            rest = &rest[index + KEY.len()..];
            let end = rest.find('"').unwrap_or_else(|| unreachable!());
            fields.push(rest[..end].to_owned());
            rest = &rest[end..];
        }
        fields
    }

    /// One reopened-epoch fixture: the exact durable owner epoch, the
    /// activation generation its clean journal retains, and the durable
    /// backend those records actually landed in.
    fn fixture(
        installation: PlatformHandle,
    ) -> Result<(HostInstallationEpoch, EpochTransition, MemoryBackend), crate::TestError> {
        let host = crate::fresh_host_epoch(installation, None)?;
        let activation_generation = root_epoch(fresh_lineage_id()?);
        let activation_id = fresh_identity("reopen-case-10-activation")?;
        let journal =
            HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
        append_reconciled(
            &journal,
            HostStateRecord::Activation(initial_activation_record(
                &host,
                &activation_id,
                &activation_generation,
                ActivationState::Stopped,
                "reopen-case-10-stopped",
                &crate::journal_append::test_activation_ingress(),
            )?),
        )?;
        // The clean marker is the owner's own proof that this epoch closed, so
        // the reopen reaches the fence decision instead of the unclean stop.
        crate::append_clean_marker(&journal, &host, &activation_id, &activation_generation)?;
        Ok((host, activation_generation, journal.into_backend()?))
    }

    // WORK_UNIT_CASE: 981/10
    #[test]
    fn recovery_fence_stays_fenced_until_the_owner_actually_clears_it() -> TestResult {
        let root = temp_root("case-10")?;
        let installation = PlatformHandle::new("installation:reopen-case-10")?;

        // With the exact unresolved fence present, the reopen must stay fenced
        // and retain the durable owner epoch.
        let (fenced_host, fenced_generation, fenced_backend) = fixture(installation.clone())?;
        let fence = StoreRecoveryReopenFence {
            mutation_digest: "9a".repeat(32),
            request_id: "reopen-case-10-request".to_owned(),
            request_digest: "9b".repeat(64),
            host_epoch: fenced_host.epoch.current.sequence.get(),
            host_lineage: fenced_host.epoch.current.lineage_id.as_str().to_owned(),
            termination: None,
            inner: None,
        };
        let (fenced, fenced_records) = capture(&root, || {
            reopen_existing_epoch(
                HostStateJournalService::from_backend(fenced_backend, fenced_host.clone())?,
                &fenced_host,
                &installation,
                None,
                None,
                std::slice::from_ref(&fence),
            )
        });
        let (_, retained_host, retained_generation, startup_fence, _) = fenced?;
        assert!(
            startup_fence.is_fenced(),
            "an unresolved recovery fence must keep startup fenced"
        );
        assert_eq!(
            startup_fence.bindings().len(),
            1,
            "the exact fence is retained verbatim, never narrowed"
        );
        assert_eq!(
            retained_host, fenced_host,
            "a fenced reopen retains the exact owner epoch"
        );
        assert_eq!(
            retained_generation, fenced_generation,
            "a fenced reopen retains the exact activation generation"
        );
        assert_eq!(
            details(&fenced_records),
            vec![
                "host.epoch reopen existing requested".to_owned(),
                "host.epoch pending reconcile observed".to_owned(),
                "host.recovery fence no inner observed".to_owned(),
                "host.epoch reopen fence observed".to_owned(),
                "host.epoch owner epoch retained".to_owned(),
            ],
            "the fenced reopen reports retention, never a child epoch: {fenced_records}"
        );

        // The same durable epoch with no unresolved fence is the owner
        // clearance: the fence lifts and the epoch advances.
        let (clear_host, _, clear_backend) = fixture(installation.clone())?;
        let (clear, clear_records) = capture(&root, || {
            reopen_existing_epoch(
                HostStateJournalService::from_backend(clear_backend, clear_host.clone())?,
                &clear_host,
                &installation,
                None,
                None,
                &[],
            )
        });
        let (_, child_host, _, startup_fence, _) = clear?;
        assert!(
            !startup_fence.is_fenced(),
            "an absent fence is clearance, not an unresolved unknown"
        );
        assert!(startup_fence.bindings().is_empty());
        assert_eq!(
            child_host.epoch.current.sequence.get(),
            clear_host.epoch.current.sequence.get() + 1,
            "only actual clearance advances the owner epoch"
        );
        assert_eq!(
            child_host.epoch.current.lineage_id.as_str(),
            clear_host.epoch.current.lineage_id.as_str(),
            "the advancing arm keeps one lineage"
        );
        assert_eq!(
            details(&clear_records),
            vec![
                "host.epoch reopen existing requested".to_owned(),
                "host.epoch pending reconcile observed".to_owned(),
                "host.epoch reopen fence observed".to_owned(),
                "host.epoch owner child epoch observed".to_owned(),
            ],
            "the clear reopen reports the child epoch, never retention: {clear_records}"
        );
        assert_eq!(
            fenced_records.matches("host.terminal_error").count()
                + clear_records.matches("host.terminal_error").count(),
            0,
            "a reopen owns no terminal: {fenced_records} / {clear_records}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }
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
