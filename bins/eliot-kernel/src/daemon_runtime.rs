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

use super::diagnostic_brief::DiagnosticTrigger;
use super::kernel_audit::{AuditEventDraft, AuditEventKind};
use super::{
    ACTIVE_DAEMON_CALLER, DaemonRuntimeStatus, ELIOTD_MAX_RECOVERY_ATTEMPTS, KernelBuildError,
    KernelComposition, daemon_class_withholds_replacement, daemon_refuses_replacement,
    daemon_restart_refusal_reason, daemon_status_proves_ready, eliotd_launch_attempt_identity,
    eliotd_operation_id, fresh_eliotd_launch_descriptor, probe_ready_state_admitted, sha256_hex,
    stable_owner_principal_digest,
};

/// F-LOG-KERNEL-4 (#903): daemon-runtime boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.daemon.*` event names
/// plus a bounded stable outcome. Never carries launch descriptors, nonces,
/// receipts, digests, paths, supervision material, or owner error strings
/// (I15.4, I07.20).
fn observe_daemon_runtime(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
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

#[cfg(windows)]
fn daemon_recovery_operation_context(
    parent: &tracing::Span,
    receipt: Option<&ProcessStartReceipt>,
) -> tracing::Span {
    let receipt = receipt.filter(|receipt| receipt.validate().is_ok());
    let generation = receipt.map(|receipt| receipt.accepted_generation().get().to_string());
    let epoch = receipt.and_then(|receipt| {
        eliot_contracts::StateFence::canonical_epoch_digest(
            receipt.binding().authority_epoch(),
        )
        .ok()
    });
    let state_fence = receipt.zip(epoch.as_ref()).map(|(receipt, epoch)| {
        format!(
            "epoch={};resource_generation={}",
            epoch.as_str(),
            receipt.binding().state_fence().generation().get()
        )
    });
    let context = parent.in_scope(|| {
        super::kernel_diagnostics::operation_context(
            receipt.map(|receipt| receipt.operation_id().as_str()),
            generation.as_deref(),
            state_fence.as_deref(),
            epoch.as_deref(),
        )
    });
    if let Some(receipt) = receipt {
        let process_tree = super::kernel_diagnostics::bound_field(
            receipt.binding().process_tree_id().as_str(),
        );
        context.record("process_tree", process_tree.text());
    }
    context
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
        observe_daemon_runtime("kernel.daemon.await_requested", "attempt");
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
                    observe_daemon_runtime("kernel.daemon.await_satisfied", "success");
                    return Ok(());
                }
                AwaitDecision::Running => {}
                AwaitDecision::Rejected(outcome, error) => {
                    observe_daemon_runtime("kernel.daemon.await_rejected", outcome);
                    return Err(error);
                }
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                observe_daemon_runtime("kernel.daemon.await_rejected", "timeout");
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
            .close_registered_descendant_in_context(
                owner,
                receipt.operation_id().clone(),
                context,
            )
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
        observe_daemon_runtime("kernel.daemon.recovery_requested", "attempt");
        let original_receipt = self
            .daemon_runtime
            .lock()
            .ok()
            .and_then(|state| state.receipt.clone());
        let context = daemon_recovery_operation_context(parent, original_receipt.as_ref());
        let mut child_terminal_owned = false;
        match self
            .recover_eliotd_inner(&context, &mut child_terminal_owned)
            .await
        {
            Ok(receipt) => {
                *terminal_owned = false;
                observe_daemon_runtime("kernel.daemon.recovery_committed", "success");
                Ok(receipt)
            }
            Err(error) => {
                observe_daemon_runtime("kernel.daemon.recovery_failed", "rejected");
                *terminal_owned = child_terminal_owned;
                if !child_terminal_owned {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        daemon_recovery_terminal_code(&error),
                        &context,
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
        if recovery_fenced {
            return Err(KernelBuildError::Service(
                "eliotd previous process start has an unknown outcome; recovery is fenced"
                    .to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Ready) {
            if let Some(receipt) = previous_receipt {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, &receipt, context)
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
        if attempt >= ELIOTD_MAX_RECOVERY_ATTEMPTS {
            let reason = "eliotd bounded recovery budget is exhausted".to_owned();
            // Issue #1839 (I16.4 restart-intensity exhaustion): the bounded
            // recovery budget admitted no further restart for this lineage.
            let detail = format!(
                "recovery_budget_exhausted:attempt={attempt}:maximum={ELIOTD_MAX_RECOVERY_ATTEMPTS}"
            );
            self.audit_observe(AuditEventDraft::process_daemon_status(
                AuditEventKind::PROCESS_RESTART_INTENSITY_EXHAUSTED,
                previous_receipt.as_ref(),
                &detail,
                self.current_state_fence().as_ref(),
            ));
            return Err(self.daemon_failure_error(reason));
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
                .close_previous_daemon_process(
                    &launch,
                    receipt,
                    context,
                    child_terminal_owned,
                )
                .await
            {
                Ok(closed) => closed,
                Err(error) => return Err(self.daemon_failure_error(error.to_string())),
            };
            if let Some(refusal) = daemon_refuses_replacement(service_state, &closed) {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime("kernel.daemon.restart_refused", reason);
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
                observe_daemon_runtime("kernel.daemon.restart_refused", reason);
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
        self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout)
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
                    .validate_daemon_process_readiness_in_context(&launch, receipt, parent)
                    .await
                    .is_ok()
                {
                    return Ok(receipt.clone());
                }
                // This failed proof is consumed to trigger bounded recovery;
                // retain its ownership if a later phase also refuses.
                *terminal_owned = true;
            } else if status == DaemonRuntimeStatus::Running
                && self
                    .await_daemon_ready(receipt, self.ipc_limits().operation_timeout)
                    .await
                    .is_ok()
            {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, receipt, parent)
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
        let recovered = match self
            .recover_eliotd_in_context(parent, &mut recovery_terminal_owned)
            .await
        {
            Ok(receipt) => receipt,
            Err(_) => {
                *terminal_owned |= recovery_terminal_owned;
                return Err(KernelServiceError::ReadinessNotProven);
            }
        };
        let current_launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if self
            .validate_daemon_process_readiness_in_context(&current_launch, &recovered, parent)
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
