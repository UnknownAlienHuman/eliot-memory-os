//! Kernel daemon runtime and status lifecycle closure.
//!
//! Owns the `eliotd` launch descriptor and runtime status transitions with bounded recovery.
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04.
//! Implementation: I1.4, I1.5, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15; extraction topology I2.23.
//! Forbidden: no semantic readiness oracle, alternate authority, unbounded restart, or fabricated launch success.

use std::sync::atomic::Ordering;
use std::time::Duration;

use eliot_kernel_service::{
    EliotdLaunchDescriptor, KernelControlCommand, KernelServiceError, KernelServiceState,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    current_process_named_pipe_expectation, observe_named_pipe_peer_process,
};
use eliot_kernel_core::RouteScope;
use eliot_process::{
    CancellationStatus, Generation, ProcessExecutionError, ProcessLifecycle, ProcessOwnerBinding,
    ProcessStartReceipt,
};

use super::{
    ACTIVE_DAEMON_CALLER, DaemonRuntimeStatus, ELIOTD_MAX_RECOVERY_ATTEMPTS, KernelBuildError,
    KernelComposition, daemon_status_proves_ready, eliotd_launch_attempt_identity,
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
        // F-LOG-KERNEL-4 (#903): readiness-rendezvous observations. This
        // rendezvous is always a subordinate phase of a larger operation
        // (recovery, control request, or probe), so every outcome here is an
        // info; the owning operation emits the single terminal. Liveness
        // (a running process) is never logged as readiness.
        observe_daemon_runtime("kernel.daemon.await_requested", "attempt");
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.daemon_status_changed.notified();
            {
                let state = self.daemon_runtime.lock().map_err(|_| {
                    KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
                })?;
                if state.receipt.as_ref() != Some(launched) {
                    observe_daemon_runtime("kernel.daemon.await_rejected", "receipt_mismatch");
                    return Err(KernelBuildError::Service(
                        "eliotd readiness is not bound to the exact launched process receipt"
                            .to_owned(),
                    ));
                }
                match &state.status {
                    DaemonRuntimeStatus::Ready => {
                        observe_daemon_runtime("kernel.daemon.await_satisfied", "success");
                        return Ok(());
                    }
                    DaemonRuntimeStatus::Running => {}
                    DaemonRuntimeStatus::Degraded(reason) => {
                        observe_daemon_runtime(
                            "kernel.daemon.await_rejected",
                            "degraded_before_ready",
                        );
                        return Err(KernelBuildError::Service(format!(
                            "eliotd degraded before authenticated readiness: {reason}"
                        )));
                    }
                    DaemonRuntimeStatus::Failed(reason) => {
                        observe_daemon_runtime(
                            "kernel.daemon.await_rejected",
                            "failed_before_ready",
                        );
                        return Err(KernelBuildError::Service(format!(
                            "eliotd failed before authenticated readiness: {reason}"
                        )));
                    }
                    DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Launching => {
                        observe_daemon_runtime("kernel.daemon.await_rejected", "not_launched");
                        return Err(KernelBuildError::Service(
                            "eliotd readiness wait has no launched process".to_owned(),
                        ));
                    }
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
    ) -> Result<(), KernelBuildError> {
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
            .inspect(&owner, receipt.operation_id().clone())
            .await
        {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => return Err(KernelBuildError::Service(error.to_string())),
        };
        if view.binding() != receipt.binding() || view.identity() != Some(receipt.identity()) {
            return Err(KernelBuildError::Service(
                "eliotd previous process inspection does not match its receipt".to_owned(),
            ));
        }
        match view.lifecycle() {
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled => {
                self.reconcile_closed_daemon_process(gateway, &owner, launch, receipt)
                    .await
            }
            ProcessLifecycle::Running => {
                let cancellation = gateway
                    .cancel(&owner, receipt.operation_id().clone())
                    .await
                    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
                if cancellation.binding() != receipt.binding() {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process cancellation binding changed".to_owned(),
                    ));
                }
                let closed = gateway
                    .inspect(&owner, receipt.operation_id().clone())
                    .await
                    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
                if closed.binding() != receipt.binding()
                    || closed.identity() != Some(receipt.identity())
                    || closed.lifecycle() != ProcessLifecycle::Exited
                    || closed.cancellation() != CancellationStatus::Completed
                    || !closed.descendants().is_some_and(|descendants| {
                        descendants.complete() && descendants.tree_terminated()
                    })
                {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process tree closure was not proven".to_owned(),
                    ));
                }
                self.reconcile_closed_daemon_process(gateway, &owner, launch, receipt)
                    .await
            }
            ProcessLifecycle::Created
            | ProcessLifecycle::Starting
            | ProcessLifecycle::Cancelling
            | ProcessLifecycle::UnknownOutcome
            | ProcessLifecycle::Quarantined => Err(KernelBuildError::Service(
                "eliotd previous process is not in a known terminal state".to_owned(),
            )),
        }
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
    ) -> Result<(), KernelBuildError> {
        let evidence = match gateway
            .reconcile(owner, receipt.operation_id().clone())
            .await
        {
            Ok(evidence) => evidence,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => return Err(KernelBuildError::Service(error.to_string())),
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
        let scope =
            RouteScope::new("daemon").map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let generations = self
            .generations
            .lock()
            .map_err(|_| KernelBuildError::Service("generation lock poisoned".to_owned()))?;
        let route = generations
            .route(&scope)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if route.active_generation().value() != launch.generation.value()
            || route.authority_epoch().value() != launch.authority_epoch.sequence.get()
        {
            return Err(KernelBuildError::Service(
                "eliotd supervised generation is not the active daemon route".to_owned(),
            ));
        }
        Ok(())
    }

    /// Performs one Kernel-owned bounded recovery of a failed daemon
    /// attempt. The old process effect must be known terminal before the
    /// active descriptor, nonce, and operation identity are replaced.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed recovery with the recovery operation's own stable
    /// code. Subordinate rendezvous/launch/readiness phases keep correlation
    /// infos only; a failure already terminaled below arrives here
    /// transformed into the recovery error, while the unchanged rendezvous
    /// error is terminaled here for the first time.
    #[cfg(windows)]
    pub async fn recover_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        observe_daemon_runtime("kernel.daemon.recovery_requested", "attempt");
        match self.recover_eliotd_inner().await {
            Ok(receipt) => {
                observe_daemon_runtime("kernel.daemon.recovery_committed", "success");
                Ok(receipt)
            }
            Err(error) => {
                observe_daemon_runtime("kernel.daemon.recovery_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(
                    daemon_recovery_terminal_code(&error),
                );
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
    async fn recover_eliotd_inner(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
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
                self.validate_daemon_process_readiness(&launch, &receipt)
                    .await
                    .map_err(|_| {
                        KernelBuildError::Service(
                            "eliotd Ready receipt is no longer physically proven".to_owned(),
                        )
                    })?;
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
            return Err(self.daemon_failure_error(reason));
        }
        if let Some(receipt) = previous_receipt.as_ref() {
            if let Err(error) = self.close_previous_daemon_process(&launch, receipt).await {
                return Err(self.daemon_failure_error(error.to_string()));
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
        let launched = match self.launch_eliotd().await {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.daemon_failure_error(error.to_string())),
        };
        self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout)
            .await?;
        Ok(launched)
    }

    #[cfg(windows)]
    pub(crate) async fn ensure_daemon_ready_for_probe(
        &self,
    ) -> Result<ProcessStartReceipt, KernelServiceError> {
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
                    .validate_daemon_process_readiness(&launch, receipt)
                    .await
                    .is_ok()
                {
                    return Ok(receipt.clone());
                }
            } else if status == DaemonRuntimeStatus::Running
                && self
                    .await_daemon_ready(receipt, self.ipc_limits().operation_timeout)
                    .await
                    .is_ok()
            {
                self.validate_daemon_process_readiness(&launch, receipt)
                    .await?;
                return Ok(receipt.clone());
            }
        }
        let recovered = self
            .recover_eliotd()
            .await
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let current_launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        self.validate_daemon_process_readiness(&current_launch, &recovered)
            .await?;
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
            observe_daemon_runtime("kernel.daemon.ready_reported", "already_ready");
            return Ok(());
        }
        #[cfg(windows)]
        if state.supervision.is_none() {
            observe_daemon_runtime("kernel.daemon.ready_reported", "supervision_unproven");
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {
            observe_daemon_runtime("kernel.daemon.ready_reported", "readiness_unproven");
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Ready;
        drop(state);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        observe_daemon_runtime("kernel.daemon.ready_proven", "success");
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
        state.status = DaemonRuntimeStatus::Degraded(reason);
        drop(state);
        self.daemon_status_changed.notify_one();
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
        Ok(())
    }
}
