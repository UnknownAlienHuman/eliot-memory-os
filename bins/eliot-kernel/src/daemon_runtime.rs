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

impl KernelComposition {
    /// Returns the immutable approved child contour, if integrated startup
    /// supplied one.  Absence is an integration error, not a permission to
    /// infer a sibling executable.
    #[must_use]
    pub fn daemon_launch(&self) -> Option<&EliotdLaunchDescriptor> {
        self.daemon_launch.as_ref()
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
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.daemon_status_changed.notified();
            {
                let state = self.daemon_runtime.lock().map_err(|_| {
                    KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
                })?;
                if state.receipt.as_ref() != Some(launched) {
                    return Err(KernelBuildError::Service(
                        "eliotd readiness is not bound to the exact launched process receipt"
                            .to_owned(),
                    ));
                }
                match &state.status {
                    DaemonRuntimeStatus::Ready => return Ok(()),
                    DaemonRuntimeStatus::Running => {}
                    DaemonRuntimeStatus::Degraded(reason) => {
                        return Err(KernelBuildError::Service(format!(
                            "eliotd degraded before authenticated readiness: {reason}"
                        )));
                    }
                    DaemonRuntimeStatus::Failed(reason) => {
                        return Err(KernelBuildError::Service(format!(
                            "eliotd failed before authenticated readiness: {reason}"
                        )));
                    }
                    DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Launching => {
                        return Err(KernelBuildError::Service(
                            "eliotd readiness wait has no launched process".to_owned(),
                        ));
                    }
                }
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
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
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation().get() != launch.generation.value()
            || receipt.binding().state_fence().authority_epoch() != launch.authority_epoch.value()
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
                launch.authority_epoch.value(),
                generation,
            ),
            launch.authority_epoch.value(),
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
                Ok(())
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
                Ok(())
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

    /// Performs one Kernel-owned bounded recovery of a failed daemon
    /// attempt. The old process effect must be known terminal before the
    /// active descriptor, nonce, and operation identity are replaced.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "bounded recovery keeps disposition, fresh binding, and readiness rendezvous ordered"
    )]
    pub async fn recover_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
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
                || policy.module_generation.state_fence.authority_epoch
                    != next_launch.authority_epoch
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
            return Ok(());
        }
        #[cfg(windows)]
        if state.supervision.is_none() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Ready;
        drop(state);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
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
