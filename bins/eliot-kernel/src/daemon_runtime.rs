//! Kernel daemon runtime and status lifecycle closure.
//!
//! Owns the `eliotd` launch descriptor and runtime status transitions with bounded recovery.
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04.
//! Implementation: I1.4, I1.5, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15; extraction topology I2.23.
//! Forbidden: no semantic readiness oracle, alternate authority, unbounded restart, or fabricated launch success.

use std::sync::atomic::Ordering;
use std::time::Duration;

use eliot_kernel_core::RouteScope;
use eliot_kernel_service::{
    EliotdLaunchDescriptor, KernelControlCommand, KernelServiceError, KernelServiceState,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    current_process_named_pipe_expectation, observe_named_pipe_peer_process,
};
use eliot_process::{
    CancellationStatus, Generation, ProcessExecutionError, ProcessExecutionView, ProcessLifecycle,
    ProcessOwnerBinding, ProcessStartReceipt,
};

#[cfg(windows)]
use super::DaemonRestartRefusal;
use super::diagnostic_brief::DiagnosticTrigger;
use super::kernel_audit::{AuditEventDraft, AuditEventKind};
use super::{
    ACTIVE_DAEMON_CALLER, DaemonRuntimeStatus, KernelBuildError, KernelComposition,
    daemon_class_withholds_replacement, daemon_refuses_replacement, daemon_restart_refusal_reason,
    daemon_status_proves_ready, eliotd_launch_attempt_identity, eliotd_operation_id,
    fresh_eliotd_launch_descriptor, probe_ready_state_admitted, sha256_hex,
    stable_owner_principal_digest,
};

/// F-LOG-KERNEL-4 (#903): daemon-runtime boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.daemon.*` event names
/// plus a bounded stable outcome. Never carries launch descriptors, nonces,
/// receipts, digests, paths, supervision material, or owner error strings
/// (I15.4, I07.20).
fn observe_daemon_runtime(event: &'static str, outcome: &'static str) {
    observe_daemon_runtime_in_context(event, outcome, &tracing::Span::current());
}

fn observe_daemon_runtime_in_context(
    event: &'static str,
    outcome: &'static str,
    context: &tracing::Span,
) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        parent: context,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon runtime observation"
    );
}

/// Maps one daemon-recovery failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload is never logged. The
/// `RECOVERY_` prefix keeps recovery-operation terminals distinct from the
/// launch-operation codes (`daemon_process_launch.rs`).
#[cfg(windows)]
fn daemon_recovery_terminal_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "RECOVERY_PLATFORM",
        KernelBuildError::Transport(_) => "RECOVERY_TRANSPORT",
        KernelBuildError::Runtime(_) => "RECOVERY_RUNTIME",
        KernelBuildError::Ors(_) => "RECOVERY_ORS",
        KernelBuildError::Core(_) => "RECOVERY_CORE",
        KernelBuildError::Service(_) => "RECOVERY_SERVICE",
        KernelBuildError::StoreBootstrapRequired => "RECOVERY_STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "RECOVERY_STORE_ALREADY_CONNECTED",
        KernelBuildError::Principal(_) => "RECOVERY_PRINCIPAL",
    }
}

/// The manifest-bound outcome of one automatic `eliotd` restart attempt
/// (issue #1884; I1.9).
///
/// `Admitted` carries the sealed
/// [`eliot_ors::BoundKernelExecutionManifest`] the ORS verifier issued for this
/// exact module and generation, so the artifact/config identity and the bounded
/// restart budget this attempt is decided under are read out of the immutable
/// manifest rather than out of contemporaneous configuration. It is the only
/// value a launch may take its recorded identity from: the type has no public
/// constructor, so this file cannot assemble one. `Refused` carries the daemon's
/// own typed restart refusal, mapped from the ORS reconciliation cause so that
/// cause survives the layer boundary instead of being flattened into one
/// refusal.
#[cfg(windows)]
enum DaemonRestartManifestAdmission {
    /// The verifier admitted a restart under the sealed immutable manifest.
    ///
    /// Boxed because the sealed binding is far larger than the refusal beside it,
    /// and this enum crosses the restart path by value.
    Admitted(Box<eliot_ors::BoundKernelExecutionManifest>),
    /// A typed refusal withholds the replacement.
    Refused(DaemonRestartRefusal),
}

/// Projects one recorded ORS restart cause onto the daemon's own typed restart
/// refusal.
///
/// The recorded budget exhaustion keeps the existing
/// [`DaemonRestartRefusal::RestartBudgetExhausted`], which is exactly what it
/// is. Every other manifest-side cause keeps its own bounded reason code, so an
/// absent, receipt-less, stale, incompatible, revoked or identity-mismatched
/// manifest is never reported as a spent budget, and a refusal that IS a spent
/// budget is never reported as one of those. The codes are a fixed vocabulary
/// derived only from the ORS cause, so no recorded payload can reach an
/// observation.
///
/// The effect-lease family of causes belongs to the effect-replay verifier and
/// cannot be produced by the restart verifier, so those variants share one
/// bounded code rather than each claiming a restart-specific meaning.
#[cfg(windows)]
const fn daemon_restart_refusal_for_manifest_cause(
    kind: eliot_ors::KernelReconciliationKind,
) -> DaemonRestartRefusal {
    use eliot_ors::KernelReconciliationKind as Cause;
    match kind {
        Cause::ManifestRestartBudgetExhausted => DaemonRestartRefusal::RestartBudgetExhausted,
        Cause::ManifestAbsent => DaemonRestartRefusal::ClassWithholds("restart_manifest_absent"),
        Cause::ManifestIdentityMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_identity_mismatch")
        }
        Cause::ManifestCandidateBindingMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_candidate_binding_mismatch")
        }
        Cause::ManifestIncompatible => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_incompatible")
        }
        Cause::ManifestRevoked => DaemonRestartRefusal::ClassWithholds("restart_manifest_revoked"),
        Cause::ManifestReceiptless => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_receiptless")
        }
        Cause::ManifestForeignEpoch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_foreign_epoch")
        }
        Cause::ManifestInvalid => DaemonRestartRefusal::ClassWithholds("restart_manifest_invalid"),
        Cause::ManifestCatalogPolicyStale => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_catalog_policy_stale")
        }
        Cause::ManifestRevocationUnacknowledged => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_revocation_unacknowledged")
        }
        Cause::ManifestDeliveryGapOpen => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_delivery_gap_open")
        }
        Cause::ManifestNotEffectCapable => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_not_effect_capable")
        }
        // A sealed Governor admission defect is the manifest's own structural
        // refusal, so it keeps its own code rather than being reported as the
        // undifferentiated "not admitted" reading.
        Cause::GovernorAdmissionSealAbsent => {
            DaemonRestartRefusal::ClassWithholds("restart_governor_admission_seal_absent")
        }
        Cause::GovernorAdmissionSealWithheld => {
            DaemonRestartRefusal::ClassWithholds("restart_governor_admission_seal_withheld")
        }
        Cause::GovernorAdmissionSealMalformed => {
            DaemonRestartRefusal::ClassWithholds("restart_governor_admission_seal_malformed")
        }
        Cause::GovernorAdmissionSealIdentityMismatch => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_identity_mismatch",
        ),
        Cause::GovernorAdmissionSealRevisionMismatch => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_revision_mismatch",
        ),
        Cause::GovernorAdmissionSealStateFenceAbsent => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_state_fence_absent",
        ),
        Cause::GovernorAdmissionSealOwnerDigestMismatch => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_owner_digest_mismatch",
        ),
        _ => DaemonRestartRefusal::ClassWithholds("restart_manifest_not_admitted"),
    }
}

#[cfg(windows)]
fn record_daemon_recovery_operation_context(
    context: &tracing::Span,
    receipt: Option<&ProcessStartReceipt>,
) {
    let receipt = receipt.filter(|receipt| receipt.validate().is_ok());
    let generation = receipt.map(|receipt| receipt.accepted_generation().get().to_string());
    let epoch = receipt.and_then(|receipt| {
        eliot_contracts::StateFence::canonical_epoch_digest(receipt.binding().authority_epoch())
            .ok()
    });
    let state_fence = receipt.zip(epoch.as_ref()).map(|(receipt, epoch)| {
        format!(
            "epoch={};resource_generation={}",
            epoch.as_str(),
            receipt.binding().state_fence().generation().get()
        )
    });
    for (field, original) in [
        (
            "operation",
            receipt.map(|receipt| receipt.operation_id().as_str()),
        ),
        ("generation", generation.as_deref()),
        ("state_fence", state_fence.as_deref()),
        (
            "authority_epoch",
            epoch.as_ref().map(eliot_contracts::LowercaseSha256::as_str),
        ),
    ] {
        if let Some(original) = original {
            let value = super::kernel_diagnostics::bound_field(original);
            context.record(field, value.text());
        }
    }
    if let Some(receipt) = receipt {
        super::daemon_live_receipt::record_process_receipt_context(context, receipt);
        let process_tree =
            super::kernel_diagnostics::bound_field(receipt.binding().process_tree_id().as_str());
        context.record("process_tree", process_tree.text());
    }
}

impl KernelComposition {
    /// Returns the immutable approved child contour, if integrated startup
    /// supplied one.  Absence is an integration error, not a permission to
    /// infer a sibling executable.
    ///
    /// Diagnostic read (F-LOG-KERNEL-4, #903): only contour presence is
    /// observed; the descriptor itself is never logged.
    #[must_use]
    pub fn daemon_launch(&self) -> Option<&EliotdLaunchDescriptor> {
        let launch = self.daemon_launch.as_ref();
        observe_daemon_runtime(
            "kernel.daemon.contour_observed",
            if launch.is_some() {
                "present"
            } else {
                "absent"
            },
        );
        launch
    }

    pub(crate) fn active_daemon_launch(
        &self,
    ) -> Result<Option<EliotdLaunchDescriptor>, KernelServiceError> {
        self.daemon_active_launch
            .lock()
            .map(|launch| launch.clone())
            .map_err(|_| KernelServiceError::Platform("daemon launch lock poisoned".to_owned()))
    }

    /// Returns whether `eliotd` has completed its authenticated ready report.
    #[must_use]
    pub fn daemon_ready(&self) -> bool {
        self.daemon_runtime
            .lock()
            .is_ok_and(|state| daemon_status_proves_ready(&state.status))
    }

    fn daemon_failure_error(&self, reason: String) -> KernelBuildError {
        let mut terminal = reason;
        if let Err(error) = self.mark_daemon_failed(terminal.clone()) {
            terminal.push_str("; failed to record and fence eliotd failure: ");
            terminal.push_str(&error.to_string());
        }
        KernelBuildError::Service(terminal)
    }

    #[cfg(windows)]
    fn revoke_daemon_agent_bridge_profile(&self) -> Result<(), KernelServiceError> {
        self.promote_agent_bridge_profile(None).map_err(|error| {
            KernelServiceError::Platform(format!(
                "eliotd agent-bridge profile revocation failed: {error}"
            ))
        })
    }

    #[cfg(windows)]
    pub(crate) async fn await_daemon_ready(
        &self,
        launched: &ProcessStartReceipt,
        timeout: Duration,
        context: &tracing::Span,
    ) -> Result<(), KernelBuildError> {
        enum AwaitDecision {
            Ready,
            Running,
            Rejected(&'static str, KernelBuildError),
        }

        // F-LOG-KERNEL-4 (#903): readiness-rendezvous observations. This
        // rendezvous is always a subordinate phase of a larger operation
        // (recovery, control request, or probe), so every outcome here is an
        // info; the owning operation emits the single terminal. Liveness
        // (a running process) is never logged as readiness.
        observe_daemon_runtime_in_context("kernel.daemon.await_requested", "attempt", context);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.daemon_status_changed.notified();
            let decision = {
                let state = self.daemon_runtime.lock().map_err(|_| {
                    KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
                })?;
                if state.receipt.as_ref() == Some(launched) {
                    match &state.status {
                        DaemonRuntimeStatus::Ready => AwaitDecision::Ready,
                        DaemonRuntimeStatus::Running => AwaitDecision::Running,
                        DaemonRuntimeStatus::Degraded(reason) => AwaitDecision::Rejected(
                            "degraded_before_ready",
                            KernelBuildError::Service(format!(
                                "eliotd degraded before authenticated readiness: {reason}"
                            )),
                        ),
                        DaemonRuntimeStatus::Failed(reason) => AwaitDecision::Rejected(
                            "failed_before_ready",
                            KernelBuildError::Service(format!(
                                "eliotd failed before authenticated readiness: {reason}"
                            )),
                        ),
                        DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Launching => {
                            AwaitDecision::Rejected(
                                "not_launched",
                                KernelBuildError::Service(
                                    "eliotd readiness wait has no launched process".to_owned(),
                                ),
                            )
                        }
                    }
                } else {
                    AwaitDecision::Rejected(
                        "receipt_mismatch",
                        KernelBuildError::Service(
                            "eliotd readiness is not bound to the exact launched process receipt"
                                .to_owned(),
                        ),
                    )
                }
            };
            match decision {
                AwaitDecision::Ready => {
                    observe_daemon_runtime_in_context(
                        "kernel.daemon.await_satisfied",
                        "success",
                        context,
                    );
                    return Ok(());
                }
                AwaitDecision::Running => {}
                AwaitDecision::Rejected(outcome, error) => {
                    observe_daemon_runtime_in_context(
                        "kernel.daemon.await_rejected",
                        outcome,
                        context,
                    );
                    return Err(error);
                }
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                observe_daemon_runtime_in_context(
                    "kernel.daemon.await_rejected",
                    "timeout",
                    context,
                );
                let reason = format!(
                    "eliotd did not complete authenticated Governor recovery and report_ready within {} ms",
                    timeout.as_millis()
                );
                return Err(self.daemon_failure_error(reason));
            }
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "recovery closure keeps exact disposition inspection and terminal proof ordered"
    )]
    pub(super) async fn close_previous_daemon_process(
        &self,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<ProcessExecutionView, KernelBuildError> {
        let gateway = self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required for eliotd recovery".to_owned(),
            )
        })?;
        receipt
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let launch_identity = eliotd_launch_attempt_identity(
            launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )?;
        let expected_operation = eliotd_operation_id(generation, &launch_identity)?;
        // INTENDED EpochId shape (B→A→C): exact-tuple is_same_authority, no
        // scalar !=, no .value() coercion.
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation().get() != launch.generation.value()
            || !receipt
                .binding()
                .state_fence()
                .authority_epoch()
                .is_same_authority(&launch.authority_epoch)
            || receipt.binding().state_fence().generation() != generation
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || !receipt
                .identity()
                .physical()
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            return Err(KernelBuildError::Service(
                "eliotd recovery refused a stale or substituted process receipt".to_owned(),
            ));
        }
        let kernel_expectation = current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let owner = ProcessOwnerBinding::new(
            ACTIVE_DAEMON_CALLER,
            stable_owner_principal_digest(
                kernel_expectation.expected_sid(),
                ACTIVE_DAEMON_CALLER,
                &launch.authority_epoch,
                generation,
            ),
            launch.authority_epoch.clone(),
            generation,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let view = match gateway
            .inspect_in_context(&owner, receipt.operation_id().clone(), context)
            .await
        {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        if view.binding() != receipt.binding() || view.identity() != Some(receipt.identity()) {
            return Err(KernelBuildError::Service(
                "eliotd previous process inspection does not match its receipt".to_owned(),
            ));
        }
        match view.lifecycle() {
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled => {
                let closed = self
                    .reconcile_closed_daemon_process(
                        gateway,
                        &owner,
                        launch,
                        receipt,
                        context,
                        child_terminal_owned,
                    )
                    .await?;
                self.close_restarted_daemon_descendant(
                    gateway,
                    &owner,
                    receipt,
                    context,
                    child_terminal_owned,
                )
                .await?;
                Ok(closed)
            }
            ProcessLifecycle::Running => {
                let cancellation = gateway
                    .cancel_in_context(&owner, receipt.operation_id().clone(), context)
                    .await
                    .map_err(|error| {
                        *child_terminal_owned = true;
                        KernelBuildError::Service(error.to_string())
                    })?;
                if cancellation.binding() != receipt.binding() {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process cancellation binding changed".to_owned(),
                    ));
                }
                let cancelled = gateway
                    .inspect_in_context(&owner, receipt.operation_id().clone(), context)
                    .await
                    .map_err(|error| {
                        *child_terminal_owned = true;
                        KernelBuildError::Service(error.to_string())
                    })?;
                if cancelled.binding() != receipt.binding()
                    || cancelled.identity() != Some(receipt.identity())
                    || cancelled.lifecycle() != ProcessLifecycle::Exited
                    || cancelled.cancellation() != CancellationStatus::Completed
                    || !cancelled.descendants().is_some_and(|descendants| {
                        descendants.complete() && descendants.tree_terminated()
                    })
                {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process tree closure was not proven".to_owned(),
                    ));
                }
                let closed = self
                    .reconcile_closed_daemon_process(
                        gateway,
                        &owner,
                        launch,
                        receipt,
                        context,
                        child_terminal_owned,
                    )
                    .await?;
                self.close_restarted_daemon_descendant(
                    gateway,
                    &owner,
                    receipt,
                    context,
                    child_terminal_owned,
                )
                .await?;
                Ok(closed)
            }
            ProcessLifecycle::Quarantined => {
                // Issue #1839 (I16.4 quarantine): the previous lineage is
                // fenced for manual recovery, so restart recovery refuses it
                // instead of adopting a quarantined process.
                self.audit_observe(AuditEventDraft::process_daemon_status(
                    AuditEventKind::PROCESS_QUARANTINED,
                    Some(receipt),
                    "previous_process_quarantined:restart_refused",
                    self.current_state_fence().as_ref(),
                ));
                Err(KernelBuildError::Service(
                    "eliotd previous process is quarantined for manual recovery".to_owned(),
                ))
            }
            ProcessLifecycle::Created
            | ProcessLifecycle::Starting
            | ProcessLifecycle::Cancelling
            | ProcessLifecycle::UnknownOutcome => Err(KernelBuildError::Service(
                "eliotd previous process is not in a known terminal state".to_owned(),
            )),
        }
    }

    /// Produces the descendant-closure receipt for one restarted daemon
    /// generation as durable audit evidence (CHILD-1/CHILD-2, #1918). The
    /// restart proof above already established tree closure; a close fault
    /// here fails the restart instead of asserting an unrecorded closure.
    #[cfg(windows)]
    async fn close_restarted_daemon_descendant(
        &self,
        gateway: &std::sync::Arc<super::process_execution::ProcessExecutionGateway>,
        owner: &ProcessOwnerBinding,
        receipt: &ProcessStartReceipt,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<(), KernelBuildError> {
        let closure = gateway
            .close_registered_descendant_in_context(owner, receipt.operation_id().clone(), context)
            .await
            .map_err(|error| {
                *child_terminal_owned = true;
                KernelBuildError::Service(error.to_string())
            })?;
        self.audit_observe(AuditEventDraft::descendant_closure(&closure));
        Ok(())
    }

    /// Reconciles one already-closed supervised `eliotd` generation by its
    /// original operation identity and links the ORS cutover readback.
    ///
    /// T2-S08K (Implements #100): the close path observes (`inspect`) and
    /// cancels (`cancel`) the exact supervised generation, then reconciles it
    /// without minting a fresh operation identity. Unknown keeps its original
    /// identity and fails fenced for bounded drain instead of blind retry.
    /// The durable link is a read-only ORS projection through the existing
    /// generation coordinator contour (`reconcile_staged_*` +
    /// `latest_generation_cutovers`, as seeded by `recover` at startup) plus
    /// the active daemon-route projection check. No new launcher, no new
    /// public process signature, no Doctor/epoch edits.
    #[cfg(windows)]
    async fn reconcile_closed_daemon_process(
        &self,
        gateway: &super::ProcessExecutionGateway,
        owner: &ProcessOwnerBinding,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<ProcessExecutionView, KernelBuildError> {
        let evidence = match gateway
            .reconcile_in_context(owner, receipt.operation_id().clone(), context)
            .await
        {
            Ok(evidence) => evidence,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        if evidence.operation_id() != receipt.operation_id()
            || evidence.binding() != receipt.binding()
        {
            return Err(KernelBuildError::Service(
                "eliotd previous process reconcile binding changed".to_owned(),
            ));
        }
        if evidence.view().identity() != Some(receipt.identity()) {
            return Err(KernelBuildError::Service(
                "eliotd previous process reconcile identity changed".to_owned(),
            ));
        }
        if !matches!(
            evidence.view().lifecycle(),
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled
        ) {
            return Err(KernelBuildError::Service(
                "eliotd previous process reconcile was not terminal".to_owned(),
            ));
        }
        self.generation_gateway
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd ORS staged cutover reconciliation failed: {error}"
                ))
            })?;
        self.generation_gateway
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                KernelBuildError::Service(format!("eliotd ORS cutover readback failed: {error}"))
            })?;
        let scope = RouteScope::new("daemon")
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let generations = self
            .generations
            .lock()
            .map_err(|_| KernelBuildError::Service("generation lock poisoned".to_owned()))?;
        // The canonical router owns this admission rule (Implements #64), so the
        // route is not compared inline here any more. The launch descriptor
        // carries no physical process generation and no fence nonce, so it is
        // presented to the router's supervised-generation entry point, which
        // applies the same exact-tuple epoch guard and the same exact
        // generation comparison as the `RouteFence` path: a supervised launch
        // from a different lineage at the same sequence is not the active
        // daemon route, and a fenced or unactivated epoch cannot match the
        // route either.
        generations
            .route_for_supervised_generation(&scope, launch.generation, &launch.authority_epoch)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd supervised generation is not the active daemon route: {error}"
                ))
            })?;
        // The reconciled terminal view is returned so the caller's declared
        // restart class is evaluated against the exact exit evidence the
        // process owner recorded for this generation, not against a guess.
        Ok(evidence.view().clone())
    }

    /// Decides one automatic restart attempt against the owner's DURABLE
    /// restart record and the immutable execution manifest bound to the
    /// admitted generation, and returns either the sealed manifest-bound
    /// authority the replacement may run under or the refusal that withholds it.
    ///
    /// `attempt` is the Kernel's restart ordinal for this process lifetime and
    /// is NOT the budget: it names the replacement generation and is compared
    /// against the threshold the admitted declaration itself declares. The
    /// decision that must survive a daemon restart is the durable one, and it
    /// is read from this owner's retained ORS restart record - keyed to the
    /// supervised child's stable identity (`ACTIVE_DAEMON_CALLER`) and to the
    /// admitted generation being replaced.
    ///
    /// The refusals that can arise here are absences rather than defaults:
    ///
    /// * no admitted restart policy means this child has no declared restart
    ///   budget at all, so its replacement is refused as
    ///   `DaemonRestartRefusal::PolicyNotAdmitted` BEFORE the previous
    ///   generation is closed. That ordering matters: a withheld replacement
    ///   must never destroy a child it cannot replace.
    /// * a durable record that already exists under this child's identity and
    ///   admitted generation means the restart disposition for this lineage was
    ///   already decided durably, so the attempt is refused and no fresh window
    ///   is opened. That record is what a recreated supervisor reads back, and
    ///   it is read back as the decision it is: the recorded cause is projected
    ///   through [`daemon_restart_refusal_for_manifest_cause`], so a recorded
    ///   manifest defect keeps its own reason instead of being reported as a
    ///   spent budget. This boundary never rewrites a row it did not read as
    ///   absent: an existing durable disposition is never treated as permission
    ///   and never replaced by a locally recomputed one.
    ///
    /// The remaining outcomes are an unreadable or invalid durable record and
    /// an unreadable manifest row, both of which are returned as mechanical
    /// failures: an unreadable record is never read as an absent one and never
    /// as permission.
    #[cfg(windows)]
    fn admit_daemon_restart_attempt(
        &self,
        launch: &EliotdLaunchDescriptor,
        attempt: u64,
        previous_receipt: Option<&ProcessStartReceipt>,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        let admitted_generation = launch.generation;
        let admitted_state_fence =
            eliot_contracts::StateFence::new(launch.authority_epoch.clone(), admitted_generation);
        let Some(admitted) = self.daemon_restart_policy.as_ref() else {
            return Ok(DaemonRestartManifestAdmission::Refused(
                DaemonRestartRefusal::PolicyNotAdmitted,
            ));
        };
        // The threshold is read only while the retained binding still proves
        // the exact admitted generation and fence the caller observed. A
        // binding that does not prove them is the same defect the class rule
        // already names for this identity, so it is refused with that same
        // reason instead of being reported as a budget of its own.
        let Ok(declared_threshold) =
            admitted.declared_attempt_threshold(admitted_generation, &admitted_state_fence)
        else {
            return Ok(DaemonRestartManifestAdmission::Refused(
                DaemonRestartRefusal::PolicyNotBoundToAdmittedGeneration,
            ));
        };
        let store = self.generation_gateway.ors.as_ref();
        let recorded = store
            .load_kernel_restart_reconciliation(ACTIVE_DAEMON_CALLER, admitted_generation.value())
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd durable restart record is unreadable: {error}"
                ))
            })?;
        // A durable row under this child's identity and generation is the
        // decision it was committed as, read back unchanged and never replaced
        // by a locally recomputed one. Its recorded CAUSE is projected through
        // the shared mapping, so a recorded manifest defect keeps its own
        // reason instead of every cause collapsing into one budget refusal.
        if let Some(recorded) = recorded {
            return Ok(DaemonRestartManifestAdmission::Refused(
                daemon_restart_refusal_for_manifest_cause(recorded.kind),
            ));
        }
        // Issue #1884 (I1.9): the restart disposition is decided against the
        // immutable `KernelExecutionManifest` recorded for this exact module
        // and generation, and never against contemporaneous configuration.
        // `load_and_verify_kernel_execution_restart` loads that manifest by the
        // request's own identity, re-verifies its recorded bound digest on
        // readback, and then runs the pure verifier over the exact candidate,
        // Authority Epoch, I1.12 evidence, recorded restart budget and recorded
        // launch binding. A missing, receipt-less, stale, incompatible, revoked
        // or identity-mismatched manifest therefore refuses the restart instead
        // of admitting it, and the ORS owner persists that refusal's
        // reconciliation item before returning, so the affected generation stays
        // visibly degraded.
        //
        // `restarts_spent` is the durably recorded spend, which is exactly zero
        // on this arm: the durable record above is the spend record and it was
        // read back as absent. The process-local `attempt` ordinal is NOT spent
        // and is never substituted for it; the recorded budget ceiling is read
        // from the immutable manifest inside the verifier.
        let bound = match self.admit_daemon_restart_under_manifest(launch, 0)? {
            DaemonRestartManifestAdmission::Admitted(bound) => bound,
            DaemonRestartManifestAdmission::Refused(refusal) => {
                return Ok(DaemonRestartManifestAdmission::Refused(refusal));
            }
        };
        if attempt < u64::from(declared_threshold) {
            return Ok(DaemonRestartManifestAdmission::Admitted(bound));
        }
        let observed_at_ms = i64::try_from(super::unix_ms()).unwrap_or(i64::MAX);
        store
            .persist_kernel_restart_reconciliation(&eliot_ors::KernelReconciliationItem {
                kind: eliot_ors::KernelReconciliationKind::ManifestRestartBudgetExhausted,
                module_id: ACTIVE_DAEMON_CALLER.to_owned(),
                generation: admitted_generation,
                bound_manifest_sha256: Some(bound.manifest_sha256().to_owned()),
                recorded_manifest_sha256: Some(bound.manifest_sha256().to_owned()),
                lease_id: None,
                operation_id: None,
                observed_at_ms,
            })
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd durable restart record could not be persisted: {error}"
                ))
            })?;
        // Issue #1839 (I16.4 restart-intensity exhaustion): the bounded
        // recovery budget admitted no further restart for this child identity.
        // The observation is subordinate; the refusal above owns the terminal.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_RESTART_INTENSITY_EXHAUSTED,
            previous_receipt,
            "eliotd bounded restart budget is spent for this child identity",
            self.current_state_fence().as_ref(),
        ));
        Ok(DaemonRestartManifestAdmission::Refused(
            DaemonRestartRefusal::RestartBudgetExhausted,
        ))
    }

    /// Reads the immutable execution manifest recorded for this exact module and
    /// generation and asks its owner in ORS to verify this restart against it
    /// (issue #1884; I1.9, W1.5).
    ///
    /// `restarts_spent` is the durably recorded restart spend this attempt is
    /// decided under; the recorded budget CEILING is never supplied here, it is
    /// read from the immutable manifest by the verifier itself.
    ///
    /// Every other request field is stated from a durable record or from an
    /// explicit fail-closed reading, and nothing here rebuilds, defaults or
    /// reconstructs a manifest:
    ///
    /// * the module identity is this supervised child's stable identity, the
    ///   same identity an admitted restart policy's `subject_id` must name, and
    ///   the generation is the admitted generation being replaced;
    /// * the bound manifest digest and the candidate launch binding are the ones
    ///   the immutable manifest records for exactly this module and generation,
    ///   read back from the Generation Registry row. Naming the recorded
    ///   candidate here does not make the recorded hashes self-confirming: the
    ///   descriptor this owner would actually launch from is an INDEPENDENT
    ///   record, and `recover_eliotd_inner` refuses the replacement unless its
    ///   artifact and config digests equal this binding's. A substituted
    ///   descriptor is therefore refused after this call, not before it;
    /// * `current_authority_epoch` is this child's own retained launch epoch read
    ///   as the Kernel authority epoch counter, exactly as this owner's process
    ///   execution gate reads it for an exact effect replay
    ///   (`require_effect_replay_authority`);
    /// * `current_catalog_revision` and `current_policy_revision` are the
    ///   recorded admission's accepted revisions, and `catalog_view` is
    ///   [`eliot_ors::CatalogPolicyView::Unavailable`] because this owner holds
    ///   no Module Catalog/Policy view at all. An unavailable view is the
    ///   fail-closed reading, so an effect-capable manifest is capped at shadow
    ///   diagnostics and is refused below rather than opened as normal-effect
    ///   service;
    /// * `revocation` is
    ///   [`eliot_ors::RevocationAcknowledgement::Unacknowledged`] and `delivery`
    ///   is [`eliot_ors::EffectDeliveryAcknowledgement::GapOpen`] because this
    ///   owner has no revocation-event or delivery-state readback. Those are the
    ///   same non-fabricated readings ORS itself states for its exact-effect
    ///   replay gate (`authorize_effect_replay_for_operation`): an unobservable
    ///   clearance is not a clearance;
    /// * `compatibility` is the I1.12 verdict recorded for this exact module and
    ///   generation, read back from the durable versioned-artifact registry. A
    ///   generation with no recorded verdict is refused and never given a
    ///   synthesised one.
    #[cfg(windows)]
    fn admit_daemon_restart_under_manifest(
        &self,
        launch: &EliotdLaunchDescriptor,
        restarts_spent: u32,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        let store = self.generation_gateway.ors.as_ref();
        let observed_at_ms = i64::try_from(super::unix_ms()).unwrap_or(i64::MAX);
        let generation = launch.generation;
        let manifest = store
            .load_kernel_execution_manifest(ACTIVE_DAEMON_CALLER, generation.value())
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd immutable execution manifest is unreadable: {error}"
                ))
            })?;
        // A generation with no recorded manifest can name no bound manifest
        // digest, so no request can be stated for it at all. The absence is
        // recorded durably under ORS's own typed kind and refused, so the
        // affected generation stays visibly degraded instead of restarting.
        let Some(manifest) = manifest else {
            return self.refuse_daemon_restart_under_manifest(
                eliot_ors::KernelReconciliationKind::ManifestAbsent,
                generation,
                None,
                None,
                observed_at_ms,
            );
        };
        // A receipt-less manifest records no accepted Catalog/Policy revision,
        // so this owner can state no current one and cannot construct the request
        // at all. It is refused under ORS's own receipt-less kind rather than
        // being given a synthesised revision.
        if !manifest.has_governor_admission() {
            return self.refuse_daemon_restart_under_manifest(
                eliot_ors::KernelReconciliationKind::ManifestReceiptless,
                generation,
                None,
                Some(manifest.manifest_sha256.as_str()),
                observed_at_ms,
            );
        }
        let compatibility = store
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd recorded I1.12 verdicts are unreadable: {error}"
                ))
            })?
            .compatibility(ACTIVE_DAEMON_CALLER, generation.value())
            .cloned();
        let Some(compatibility) = compatibility else {
            // No recorded I1.12 verdict means this owner can state no
            // compatibility evidence, so no request can be built for this
            // generation. It is refused under ORS's own incompatible kind, which
            // is the cause its verifier produces for a candidate that fails
            // I1.12 evidence, and the refusal is recorded durably so the
            // affected generation stays visibly degraded instead of restarting.
            return self.refuse_daemon_restart_under_manifest(
                eliot_ors::KernelReconciliationKind::ManifestIncompatible,
                generation,
                None,
                Some(manifest.manifest_sha256.as_str()),
                observed_at_ms,
            );
        };
        let current_authority_epoch = eliot_contracts::AuthorityEpoch::new(
            launch.authority_epoch.sequence.get(),
        )
        .map_err(|error| {
            KernelBuildError::Service(format!(
                "eliotd retained epoch is not a Kernel authority epoch: {error}"
            ))
        })?;
        let request = eliot_ors::KernelExecutionRestartRequest {
            module_id: ACTIVE_DAEMON_CALLER.to_owned(),
            generation,
            bound_manifest_sha256: manifest.manifest_sha256.clone(),
            candidate: manifest.launch_binding(),
            current_authority_epoch,
            current_catalog_revision: manifest.admission.catalog_revision,
            current_policy_revision: manifest.admission.policy_revision,
            catalog_view: eliot_ors::CatalogPolicyView::Unavailable,
            revocation: eliot_ors::RevocationAcknowledgement::Unacknowledged,
            delivery: eliot_ors::EffectDeliveryAcknowledgement::GapOpen,
            compatibility,
            restarts_spent,
            observed_at_ms,
        };
        let decision = store
            .load_and_verify_kernel_execution_restart(&request)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd manifest-bound restart verification failed: {error}"
                ))
            })?;
        match &decision.admission {
            // Only a normal-service admission carries restart authority, and it
            // carries the sealed manifest the replacement must be bound to.
            eliot_ors::KernelServiceAdmission::ReadRebuildService(bound)
            | eliot_ors::KernelServiceAdmission::EffectService(bound) => Ok(
                DaemonRestartManifestAdmission::Admitted(Box::new(bound.clone())),
            ),
            // `None` starts nothing, and shadow diagnostics carry no external
            // effect and no canonical write admission, so neither is a normal
            // restart. Both are refused with the decision's own recorded cause,
            // which the ORS owner has already persisted.
            eliot_ors::KernelServiceAdmission::ShadowDiagnosticsOnly(_)
            | eliot_ors::KernelServiceAdmission::None => {
                Ok(DaemonRestartManifestAdmission::Refused(
                    Self::daemon_manifest_restart_cause(&decision),
                ))
            }
        }
    }

    /// The typed refusal one refused manifest-bound decision carries.
    ///
    /// The decision's own first durable reconciliation item is the cause, so the
    /// ORS refusal survives the layer boundary instead of being reported as an
    /// unrelated budget or class verdict. The admission-derived codes below are
    /// only reached if a decision ever refused without recording a cause.
    #[cfg(windows)]
    fn daemon_manifest_restart_cause(
        decision: &eliot_ors::KernelRestartDecision,
    ) -> DaemonRestartRefusal {
        if let Some(item) = decision.reconciliation.first() {
            return daemon_restart_refusal_for_manifest_cause(item.kind);
        }
        match decision.admission {
            eliot_ors::KernelServiceAdmission::ShadowDiagnosticsOnly(_) => {
                DaemonRestartRefusal::ClassWithholds("restart_manifest_shadow_diagnostics_only")
            }
            eliot_ors::KernelServiceAdmission::None => {
                DaemonRestartRefusal::ClassWithholds("restart_manifest_declined")
            }
            eliot_ors::KernelServiceAdmission::ReadRebuildService(_)
            | eliot_ors::KernelServiceAdmission::EffectService(_) => {
                DaemonRestartRefusal::ClassWithholds("restart_manifest_cause_unrecorded")
            }
        }
    }

    /// Records one manifest-bound restart refusal durably and returns it as this
    /// file's typed refusal carrying the ORS kind's own bounded reason code.
    #[cfg(windows)]
    fn refuse_daemon_restart_under_manifest(
        &self,
        kind: eliot_ors::KernelReconciliationKind,
        generation: eliot_contracts::ResourceGeneration,
        bound_manifest_sha256: Option<&str>,
        recorded_manifest_sha256: Option<&str>,
        observed_at_ms: i64,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        self.generation_gateway
            .ors
            .as_ref()
            .persist_kernel_restart_reconciliation(&eliot_ors::KernelReconciliationItem {
                kind,
                module_id: ACTIVE_DAEMON_CALLER.to_owned(),
                generation,
                bound_manifest_sha256: bound_manifest_sha256.map(str::to_owned),
                recorded_manifest_sha256: recorded_manifest_sha256.map(str::to_owned),
                lease_id: None,
                operation_id: None,
                observed_at_ms,
            })
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd manifest-bound restart refusal could not be persisted: {error}"
                ))
            })?;
        Ok(DaemonRestartManifestAdmission::Refused(
            daemon_restart_refusal_for_manifest_cause(kind),
        ))
    }

    /// Performs one Kernel-owned bounded recovery of a failed daemon
    /// attempt. The old process effect must be known terminal before the
    /// active descriptor, nonce, and operation identity are replaced.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): each failed recovery has
    /// one terminal owner. Recovery-owned failures use the recovery code;
    /// launch, readiness, and process-gateway failures propagate their
    /// already-owned terminal without emitting a second one here.
    #[cfg(windows)]
    pub async fn recover_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        let parent = tracing::Span::current();
        let parent = if parent.is_none() {
            super::kernel_diagnostics::operation_context(None, None, None, None)
        } else {
            parent
        };
        let mut terminal_owned = false;
        self.recover_eliotd_in_context(&parent, &mut terminal_owned)
            .await
    }

    #[cfg(windows)]
    async fn recover_eliotd_in_context(
        &self,
        parent: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        let context = parent;
        observe_daemon_runtime_in_context("kernel.daemon.recovery_requested", "attempt", context);
        let mut child_terminal_owned = false;
        match self
            .recover_eliotd_inner(context, &mut child_terminal_owned)
            .await
        {
            Ok(receipt) => {
                *terminal_owned = false;
                observe_daemon_runtime_in_context(
                    "kernel.daemon.recovery_committed",
                    "success",
                    context,
                );
                Ok(receipt)
            }
            Err(error) => {
                observe_daemon_runtime_in_context(
                    "kernel.daemon.recovery_failed",
                    "rejected",
                    context,
                );
                *terminal_owned = true;
                if !child_terminal_owned {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        daemon_recovery_terminal_code(&error),
                        context,
                    );
                }
                Err(error)
            }
        }
    }

    /// Bounded disposition, fresh binding, and readiness rendezvous; every
    /// disposition check precedes the single relaunch. See
    /// [`KernelComposition::recover_eliotd`].
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "bounded recovery keeps disposition, fresh binding, and readiness rendezvous ordered"
    )]
    async fn recover_eliotd_inner(
        &self,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        let _recovery_gate = self.daemon_recovery_gate.lock().await;
        let service_state = self
            .service_state()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if !probe_ready_state_admitted(service_state) {
            return Err(KernelBuildError::Service(
                "eliotd recovery requires an admitted Activating, Ready, or Degraded Kernel state"
                    .to_owned(),
            ));
        }
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        let (status, previous_receipt, recovery_fenced) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            (
                state.status.clone(),
                state.receipt.clone(),
                state.recovery_fenced,
            )
        };
        record_daemon_recovery_operation_context(context, previous_receipt.as_ref());
        if recovery_fenced {
            return Err(KernelBuildError::Service(
                "eliotd previous process start has an unknown outcome; recovery is fenced"
                    .to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Ready) {
            if let Some(receipt) = previous_receipt {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, &receipt, context, true)
                    .await
                    .is_err()
                {
                    *child_terminal_owned = true;
                    return Err(KernelBuildError::Service(
                        "eliotd Ready receipt is no longer physically proven".to_owned(),
                    ));
                }
                return Ok(receipt);
            }
            return Err(KernelBuildError::Service(
                "eliotd Ready state has no exact process receipt".to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Launching) && previous_receipt.is_none() {
            return Err(KernelBuildError::Service(
                "eliotd launch is still awaiting its process receipt".to_owned(),
            ));
        }
        let attempt = self.daemon_recovery_attempts.fetch_add(1, Ordering::AcqRel);
        // I14.10 / I08.12 / #1682 W4: the bounded restart budget is a DURABLE
        // operational fact of the supervised child, not process-local state.
        // `attempt` above is only the ordinal that names the replacement
        // generation; it is not a budget, and the budget is not recomputed from
        // it. The decision below is read from this owner's retained ORS
        // restart record, which is keyed to the child's stable identity
        // (`ACTIVE_DAEMON_CALLER`, the very identity an admitted restart
        // policy's `subject_id` must name) and to the admitted generation being
        // replaced, and is written through that same ORS owner before the
        // refusal is returned. A daemon restart therefore cannot hand out a
        // fresh window: the record IS the window.
        //
        // Absence stays absence. An admitted disposition means this child's
        // declared budget was never recorded as spent and that the immutable
        // manifest bound to the admitted generation admitted the replacement;
        // neither is ever widened into an unlimited budget, and an unreadable
        // or invalid record is a mechanical failure, not a permission. The
        // declared THRESHOLD is read only from an admitted policy, and a child
        // with no admitted policy has no declared budget at all, so its
        // replacement is refused as `PolicyNotAdmitted` rather than being given
        // a synthesised default.
        //
        // Issue #1884 (I1.9): the admitted disposition carries the sealed
        // `BoundKernelExecutionManifest` the ORS verifier issued, and that is
        // the only value the replacement below may take launch identity from.
        let mut bound_restart_manifest = None;
        if previous_receipt.is_some() {
            match self.admit_daemon_restart_attempt(&launch, attempt, previous_receipt.as_ref())? {
                DaemonRestartManifestAdmission::Admitted(bound) => {
                    bound_restart_manifest = Some(bound);
                }
                DaemonRestartManifestAdmission::Refused(refusal) => {
                    let reason = daemon_restart_refusal_reason(&refusal);
                    observe_daemon_runtime("kernel.daemon.restart_refused", reason);
                    return Err(self.daemon_failure_error(format!(
                        "eliotd automatic restart refused: {reason}"
                    )));
                }
            }
        }
        // The two refusals that no declared restart class may bypass (I14.10)
        // are decided here, on the exact reconciled evidence of the generation
        // being replaced: after its process is proven terminal and before any
        // replacement is launched. An exit the process owner could not
        // classify is not read as a normal exit and cannot buy a replacement.
        //
        // A classifiable exit is the other case: the process owner did establish
        // what happened, so the admitted restart class for this child decides
        // whether that class of exit may buy a replacement. The rule is the
        // shared `decide_automatic_restart`, read from the admission retained on
        // this composition; this module only supplies the owner lifecycle and
        // the exit/health evidence. No policy means no class, and an absent
        // declaration is refused rather than widened into an unlimited budget.
        if let Some(receipt) = previous_receipt.as_ref() {
            let closed = match self
                .close_previous_daemon_process(&launch, receipt, context, child_terminal_owned)
                .await
            {
                Ok(closed) => closed,
                Err(error) => return Err(self.daemon_failure_error(error.to_string())),
            };
            if let Some(refusal) = daemon_refuses_replacement(service_state, &closed) {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
                let reason = format!("eliotd automatic restart refused: {reason}");
                return Err(self.daemon_failure_error(reason));
            }
            // The class is read only under a policy digest still bound to the
            // admitted generation this replacement would take. That generation
            // and its fence are taken from the Host-approved launch descriptor
            // that produced the process being reconciled, which is an
            // independent record of the admitted identity: a policy admitted
            // for one generation cannot buy a replacement of another. An
            // admitted digest whose binding no longer matches is refused here,
            // not defaulted to a wider authority.
            let admitted_generation = launch.generation;
            let admitted_state_fence = eliot_contracts::StateFence::new(
                launch.authority_epoch.clone(),
                admitted_generation,
            );
            let restart_policy = self.daemon_restart_policy.as_ref();
            if let Some(refusal) = daemon_class_withholds_replacement(
                restart_policy,
                admitted_generation,
                &admitted_state_fence,
                service_state,
                &status,
                &closed,
            ) {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
                let reason = format!("eliotd automatic restart refused: {reason}");
                return Err(self.daemon_failure_error(reason));
            }
        } else if !matches!(
            status,
            DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Failed(_)
        ) {
            let reason = "eliotd recovery has no exact prior process disposition".to_owned();
            return Err(self.daemon_failure_error(reason));
        }
        let next_launch = fresh_eliotd_launch_descriptor(&launch, attempt + 1)?;
        // Issue #1884 (I1.9): a replacement of a supervised child is launched
        // only under the exact launch identity the sealed manifest records. The
        // immutable bytes and the exact daemon configuration this replacement
        // would start are compared against the bound launch binding, never
        // against the retained descriptor alone, so a descriptor whose recorded
        // digests no longer stand for the admitted manifest is refused instead
        // of being launched. The binding is absent on a first launch that has no
        // previous generation to replace; that path is not a restart and is not
        // decided here.
        if let Some(bound) = bound_restart_manifest.as_ref() {
            let binding = bound.launch_binding();
            if next_launch.executable_sha256 != binding.artifact_sha256
                || next_launch.config_descriptor_sha256 != binding.config_sha256
            {
                let refusal = DaemonRestartRefusal::ClassWithholds(
                    "restart_launch_identity_not_the_recorded_manifest",
                );
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
                return Err(self
                    .daemon_failure_error(format!("eliotd automatic restart refused: {reason}")));
            }
        }
        {
            let mut policy = self.front_door_policy.lock().map_err(|_| {
                KernelBuildError::Service("front-door policy lock poisoned".to_owned())
            })?;
            if policy.module_generation.generation != next_launch.generation
                || !policy
                    .module_generation
                    .state_fence
                    .authority_epoch
                    .is_same_authority(&next_launch.authority_epoch)
            {
                return Err(KernelBuildError::Service(
                    "eliotd recovery descriptor has the wrong generation or authority".to_owned(),
                ));
            }
            next_launch
                .launch_nonce
                .as_str()
                .clone_into(&mut policy.launch_nonce);
        }
        *self
            .daemon_active_launch
            .lock()
            .map_err(|_| KernelBuildError::Service("daemon launch lock poisoned".to_owned()))? =
            Some(next_launch);
        {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            state.status = DaemonRuntimeStatus::NotLaunched;
            state.receipt = None;
            state.recovery_fenced = false;
            state.supervision = None;
            state.live_ready = None;
        }
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        let launched = match self.launch_eliotd_in_context(context).await {
            Ok(receipt) => receipt,
            Err(error) => {
                *child_terminal_owned = true;
                return Err(self.daemon_failure_error(error.to_string()));
            }
        };
        self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout, context)
            .await?;
        // Issue #1839 (I16.4 restart): the recovered generation restarted
        // after its previous process closed; the launch commit itself stays
        // on `process.launch_committed`.
        let detail = format!(
            "recovered_generation={}",
            launched.accepted_generation().get()
        );
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_RESTARTED,
            Some(&launched),
            &detail,
            self.current_state_fence().as_ref(),
        ));
        Ok(launched)
    }

    #[cfg(windows)]
    pub(crate) async fn ensure_daemon_ready_for_probe_in_context(
        &self,
        parent: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelServiceError> {
        *terminal_owned = false;
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let (status, receipt) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            (state.status.clone(), state.receipt.clone())
        };
        if let Some(receipt) = receipt.as_ref() {
            if status == DaemonRuntimeStatus::Ready {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, receipt, parent, false)
                    .await
                    .is_ok()
                {
                    return Ok(receipt.clone());
                }
                // A rejected proof is a subordinate phase while bounded
                // recovery may still complete this operation successfully.
            } else if status == DaemonRuntimeStatus::Running
                && self
                    .await_daemon_ready(receipt, self.ipc_limits().operation_timeout, parent)
                    .await
                    .is_ok()
            {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, receipt, parent, true)
                    .await
                    .is_err()
                {
                    *terminal_owned = true;
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                return Ok(receipt.clone());
            }
        }
        let mut recovery_terminal_owned = false;
        let Ok(recovered) = self
            .recover_eliotd_in_context(parent, &mut recovery_terminal_owned)
            .await
        else {
            *terminal_owned = recovery_terminal_owned;
            return Err(KernelServiceError::ReadinessNotProven);
        };
        *terminal_owned = false;
        let current_launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if self
            .validate_daemon_process_readiness_in_context(&current_launch, &recovered, parent, true)
            .await
            .is_err()
        {
            *terminal_owned = true;
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(recovered)
    }

    /// Records an authenticated daemon-ready report after generation checks
    /// have been performed by the front-door dispatcher.
    ///
    /// Subordinate boundary (F-LOG-KERNEL-4, #903): the ready report is
    /// always a phase of the authenticated daemon request, so every outcome
    /// here is an info; the request dispatcher owns the single terminal for
    /// the mapped failure. Ready versus running versus liveness stay
    /// distinct: only an exact already-ready receipt is read back, never
    /// promoted from a merely running process.
    pub fn mark_daemon_ready(&self) -> Result<(), KernelServiceError> {
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        #[cfg(windows)]
        if state.receipt.is_some()
            && state.status == DaemonRuntimeStatus::Ready
            && state.supervision.is_some()
        {
            drop(state);
            observe_daemon_runtime("kernel.daemon.ready_reported", "already_ready");
            return Ok(());
        }
        #[cfg(windows)]
        if state.supervision.is_none() {
            drop(state);
            observe_daemon_runtime("kernel.daemon.ready_reported", "supervision_unproven");
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {
            drop(state);
            observe_daemon_runtime("kernel.daemon.ready_reported", "readiness_unproven");
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Ready;
        let receipt = state.receipt.clone();
        drop(state);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        observe_daemon_runtime("kernel.daemon.ready_proven", "success");
        // Issue #1837: durable audit evidence for process lifecycle.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_READY_PROVEN,
            receipt.as_ref(),
            "ready",
            self.current_state_fence().as_ref(),
        ));
        Ok(())
    }

    /// Records a bounded authenticated daemon degradation.
    pub fn mark_daemon_degraded(&self, reason: String) -> Result<(), KernelServiceError> {
        {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_none() {
                return Err(KernelServiceError::ReadinessNotProven);
            }
        }
        #[cfg(windows)]
        self.revoke_daemon_agent_bridge_profile()?;
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        if state.receipt.is_none() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let receipt = state.receipt.clone();
        let detail = reason.clone();
        state.status = DaemonRuntimeStatus::Degraded(reason);
        drop(state);
        self.daemon_status_changed.notify_one();
        // Issue #1837: durable audit evidence for process lifecycle.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_DEGRADED,
            receipt.as_ref(),
            &detail,
            self.current_state_fence().as_ref(),
        ));
        // Issue #1844: a degradation opens a problem; compile its brief.
        self.observe_diagnostic_problem(DiagnosticTrigger::ProblemOpenedOrUpdated);
        Ok(())
    }

    /// Records a bounded authenticated daemon fatal disposition and closes
    /// normal admission without fencing the generation. Kernel remains the
    /// sole lifecycle owner and may consume its one fresh recovery attempt.
    pub fn mark_daemon_failed(&self, reason: impl Into<String>) -> Result<(), KernelServiceError> {
        let reason = reason.into();
        self.record_daemon_failed(&reason, false)
    }

    pub(crate) fn record_daemon_failed(
        &self,
        reason: &str,
        recovery_fenced: bool,
    ) -> Result<(), KernelServiceError> {
        #[cfg(windows)]
        self.revoke_daemon_agent_bridge_profile()?;
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        let receipt = state.receipt.clone();
        state.status = DaemonRuntimeStatus::Failed(reason.to_owned());
        state.recovery_fenced |= recovery_fenced;
        #[cfg(windows)]
        {
            state.supervision = None;
            state.live_ready = None;
        }
        drop(state);
        self.daemon_status_changed.notify_one();
        let mut service = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
        if matches!(
            service.state(),
            KernelServiceState::Activating
                | KernelServiceState::Ready
                | KernelServiceState::Degraded
        ) {
            let reason_handle =
                PlatformHandle::new(format!("eliotd-failed:{}", sha256_hex(reason.as_bytes())))
                    .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
            service.apply(KernelControlCommand::Degrade(reason_handle))?;
        }
        // Issue #1837: durable audit evidence for process lifecycle.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_FAILED,
            receipt.as_ref(),
            reason,
            self.current_state_fence().as_ref(),
        ));
        // Issue #1839 (I16.4 crash): the same observed failure is a crash
        // transition, distinct from the failure disposition above.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_CRASHED,
            receipt.as_ref(),
            reason,
            self.current_state_fence().as_ref(),
        ));
        // Issue #1844: a daemon crash compiles its brief.
        self.observe_diagnostic_problem(DiagnosticTrigger::ModuleCrashOrRestartExhaustion);
        Ok(())
    }
}
