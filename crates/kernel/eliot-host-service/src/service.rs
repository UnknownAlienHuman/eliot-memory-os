//! Host lifecycle orchestration over provider-neutral platform ports.

use std::fmt;

use eliot_contracts::{RequestId, RequestMetadata};
use eliot_kernel_service::{HostKernelHandshake, KernelReadyReceipt};
use eliot_platform::{
    HostActivationTransition, HostProcessRecoveryBinding, HostShutdownMarker, HostStateError,
    HostStateStore, PlatformHandle, PortError, PortOutcome, ServiceObservation, ServiceOperation,
    ServicePort, ServiceRequest, ServiceState,
};
use eliot_platform_windows::HostOwnerLease;
use eliot_runtime_contracts::ServiceProcessRecord;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Host activation states. These are the operational states persisted by the
/// Host state owner; they never imply semantic or project authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostServiceState {
    /// Host has not observed a running managed process.
    Stopped,
    /// Host is executing a bounded start operation.
    Starting,
    /// Kernel process is ready for the control handshake, but not active yet.
    ControlReady,
    /// Kernel ready receipt has been accepted.
    Active,
    /// Host is closing new starts and stopping managed processes.
    Draining,
    /// Host recorded a clean stop.
    StoppedClean,
    /// An observation/effect was incomplete or unknown.
    DegradedRecovery,
    /// A bounded lifecycle operation failed.
    Failed,
}

impl fmt::Display for HostServiceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stopped => "STOPPED",
            Self::Starting => "STARTING",
            Self::ControlReady => "CONTROL_READY",
            Self::Active => "ACTIVE",
            Self::Draining => "DRAINING",
            Self::StoppedClean => "STOPPED_CLEAN",
            Self::DegradedRecovery => "DEGRADED_RECOVERY",
            Self::Failed => "FAILED",
        })
    }
}

/// A dependency that Host may start in its independent failure domain.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDependencyPlan {
    /// Stable service identity registered by installation policy.
    pub service: PlatformHandle,
    /// Exact process owner expected in the returned observation.
    pub expected_owner: String,
}

impl HostDependencyPlan {
    fn validate(&self) -> Result<(), HostServiceError> {
        validate_handle(&self.service, "dependency.service")?;
        validate_text(&self.expected_owner, "dependency.expected_owner")
    }
}

/// Receipt for a Kernel start that has an observed process lineage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelStartReceipt {
    /// The service identity that was started or reused.
    pub service: PlatformHandle,
    /// Exact observed process record persisted by HostStateStore.
    pub process: ServiceProcessRecord,
    /// Exact PID/image/Job recovery binding committed with the process record.
    pub process_recovery: HostProcessRecoveryBinding,
    /// Whether the operation reused an already-running process.
    pub reused: bool,
}

/// Receipt for a cleanly observed service stop.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStopReceipt {
    /// The service identity that was stopped.
    pub service: PlatformHandle,
    /// The process lineage that was observed before the stop.
    pub prior_process: ServiceProcessRecord,
}

/// Outcome of a bounded candidate-generation restart.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundedRestartOutcome {
    /// Candidate generation became ready.
    CandidateActive,
    /// Candidate failed and the prior generation was restored.
    RolledBack,
}

/// Host failure classification without raw provider output.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostFailure {
    /// Provider could not establish the current process outcome.
    UnknownOutcome,
    /// Provider returned an incomplete observation.
    IncompleteObservation,
    /// The returned service/process identity did not match the request.
    IdentityMismatch,
    /// The process was present but did not prove readiness.
    ReadinessNotProven,
    /// The Host state owner rejected a lineage update.
    StateStore(String),
    /// A platform contract rejected the request.
    Platform(String),
    /// Kernel handoff or readiness validation failed.
    KernelHandoff(String),
}

/// Host lifecycle error. Unknown outcomes remain explicit and never become success.
#[derive(Debug, Error)]
pub enum HostServiceError {
    /// A required identity or owner field is malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// The requested lifecycle transition is not legal.
    #[error("illegal Host transition from {from} to {to}")]
    IllegalTransition {
        /// Current state.
        from: HostServiceState,
        /// Requested state.
        to: HostServiceState,
    },
    /// Host refuses normal operation until recovery reconciles an unknown result.
    #[error("Host lifecycle outcome is unknown and requires reconciliation")]
    UnknownOutcome,
    /// A provider returned a partial observation that cannot prove a postcondition.
    #[error("Host lifecycle observation is incomplete")]
    IncompleteObservation,
    /// The service observation did not identify the requested service/process.
    #[error("Host lifecycle observation identity mismatch")]
    IdentityMismatch,
    /// A process was observed but was not ready for the requested boundary.
    #[error("Host process readiness was not proven")]
    ReadinessNotProven,
    /// The host state owner rejected a transition.
    #[error("Host state store: {0}")]
    StateStore(#[from] HostStateError),
    /// A platform contract rejected the operation.
    #[error("platform contract: {0}")]
    Platform(#[from] PortError),
    /// The caller supplied invalid request metadata.
    #[error("request metadata: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
    /// Kernel handoff/readiness was not accepted.
    #[error("Kernel handoff: {0}")]
    KernelHandoff(String),
    /// The installation-wide Host owner lease could not be acquired or
    /// released by this service instance.
    #[error("Host owner lease: {0}")]
    OwnerLease(String),
}

/// The external Host Supervisor over a platform service port and host state owner.
pub struct HostService<P, S>
where
    S: HostStateStore,
{
    platform: P,
    state_store: S,
    installation: PlatformHandle,
    state: HostServiceState,
    failure: Option<HostFailure>,
    pending_release: Option<S::ReleaseToken>,
    durable_finalized: bool,
    owner_lease: HostOwnerLease,
    owner_released: bool,
    admission_closed: bool,
}

impl<P, S> HostService<P, S>
where
    P: ServicePort,
    S: HostStateStore,
{
    /// Opens Host against one installation and revalidates the state-store snapshot.
    ///
    /// A previously active process is not adopted as healthy. It enters
    /// `DEGRADED_RECOVERY` until a fresh provider observation proves ownership
    /// and readiness.
    pub fn open(
        platform: P,
        state_store: S,
        installation: PlatformHandle,
    ) -> Result<Self, HostServiceError> {
        validate_handle(&installation, "installation")?;
        let owner_lease = HostOwnerLease::acquire(&installation)
            .map_err(|error| HostServiceError::OwnerLease(error.to_string()))?;
        let snapshot = state_store.load_installation()?;
        if snapshot.installation != installation {
            return Err(HostServiceError::IdentityMismatch);
        }
        let state = if snapshot.active_process.is_some()
            || snapshot.disposition.is_release_pending()
            || snapshot.recovery_fence.is_some()
        {
            HostServiceState::DegradedRecovery
        } else if snapshot.last_clean_shutdown.is_some()
            || snapshot.last_recovery_evidence.is_some()
        {
            HostServiceState::StoppedClean
        } else {
            HostServiceState::Stopped
        };
        Ok(Self {
            platform,
            state_store,
            installation,
            state,
            failure: None,
            pending_release: None,
            durable_finalized: false,
            owner_lease,
            owner_released: false,
            admission_closed: snapshot.active_process.is_some()
                || snapshot.disposition.is_release_pending()
                || snapshot.recovery_fence.is_some(),
        })
    }

    /// Returns the current Host lifecycle state.
    pub const fn state(&self) -> HostServiceState {
        self.state
    }

    /// Returns the installation identity owned by this Host instance.
    pub fn installation(&self) -> &PlatformHandle {
        &self.installation
    }

    /// Returns the last typed failure, if one was recorded.
    pub fn failure(&self) -> Option<&HostFailure> {
        self.failure.as_ref()
    }

    /// Starts or reuses the exact approved Kernel service and persists its process lineage.
    pub fn start_kernel(
        &mut self,
        context: &RequestMetadata,
        service: PlatformHandle,
        process_recovery: HostProcessRecoveryBinding,
    ) -> Result<KernelStartReceipt, HostServiceError> {
        validate_context(context)?;
        validate_handle(&service, "kernel.service")?;
        process_recovery.validate()?;
        self.transition(HostServiceState::Starting)?;
        let inspect = self.execute(
            context,
            "kernel-inspect",
            service.clone(),
            ServiceOperation::Inspect,
        )?;
        let (process, reused) = match inspect {
            PortOutcome::Known(observation)
                if is_ready_process(&observation, &service, "Kernel") =>
            {
                (
                    observation
                        .process
                        .ok_or(HostServiceError::ReadinessNotProven)?,
                    true,
                )
            }
            PortOutcome::Known(observation)
                if matches!(
                    observation.state,
                    ServiceState::Stopped | ServiceState::Absent
                ) =>
            {
                let started = self.execute(
                    context,
                    "kernel-start",
                    service.clone(),
                    ServiceOperation::Start,
                )?;
                let process = match ready_process(started, &service, "Kernel") {
                    Ok(process) => process,
                    Err(error) => {
                        self.fail(HostFailure::ReadinessNotProven);
                        return Err(error);
                    }
                };
                (process, false)
            }
            PortOutcome::Known(_) => {
                self.fail(HostFailure::ReadinessNotProven);
                return Err(HostServiceError::ReadinessNotProven);
            }
            PortOutcome::Partial { .. } => {
                self.fail(HostFailure::IncompleteObservation);
                return Err(HostServiceError::IncompleteObservation);
            }
            PortOutcome::Unknown(_) => {
                self.fail(HostFailure::UnknownOutcome);
                return Err(HostServiceError::UnknownOutcome);
            }
            PortOutcome::Error(error) => {
                self.fail(HostFailure::Platform(error.to_string()));
                return Err(HostServiceError::Platform(error));
            }
        };
        if !process_recovery.binds_to(&self.installation, &process) {
            self.admission_closed = true;
            self.fail(HostFailure::IdentityMismatch);
            if !reused {
                self.cleanup_started_kernel(context, &service)?;
            }
            return Err(HostServiceError::IdentityMismatch);
        }
        let transition = HostActivationTransition {
            context: derived_context(context, "kernel-activation")?,
            installation: self.installation.clone(),
            process: process.clone(),
        };
        if let Err(error) = self
            .state_store
            .commit_activation(transition, process_recovery.clone())
        {
            self.admission_closed = true;
            if !reused {
                self.cleanup_started_kernel(context, &service)?;
            }
            self.fail(HostFailure::StateStore(error.to_string()));
            return Err(HostServiceError::StateStore(error));
        }
        self.state = HostServiceState::ControlReady;
        self.failure = None;
        self.admission_closed = false;
        Ok(KernelStartReceipt {
            service,
            process,
            process_recovery,
            reused,
        })
    }

    /// Accepts a Kernel ready receipt and opens Host's active control contour.
    pub fn accept_kernel_ready(
        &mut self,
        handshake: &HostKernelHandshake,
        receipt: KernelReadyReceipt,
    ) -> Result<(), HostServiceError> {
        if self.state != HostServiceState::ControlReady {
            return Err(HostServiceError::IllegalTransition {
                from: self.state,
                to: HostServiceState::Active,
            });
        }
        if handshake.installation_id != self.installation {
            self.fail(HostFailure::IdentityMismatch);
            return Err(HostServiceError::IdentityMismatch);
        }
        if let Err(error) = receipt.validate(handshake) {
            self.fail(HostFailure::KernelHandoff(error.to_string()));
            return Err(HostServiceError::KernelHandoff(error.to_string()));
        }
        self.state = HostServiceState::Active;
        self.failure = None;
        Ok(())
    }

    /// Attempts one approved candidate service a bounded number of times and
    /// restores the prior service when the candidate cannot prove readiness.
    pub fn restart_kernel_bounded(
        &mut self,
        context: &RequestMetadata,
        prior_service: PlatformHandle,
        candidate_service: PlatformHandle,
        prior_recovery: HostProcessRecoveryBinding,
        candidate_recovery: HostProcessRecoveryBinding,
        max_attempts: u32,
    ) -> Result<(BoundedRestartOutcome, KernelStartReceipt), HostServiceError> {
        validate_context(context)?;
        if max_attempts == 0 {
            return Err(HostServiceError::KernelHandoff(
                "restart budget must be non-zero".to_owned(),
            ));
        }
        let mut last_error = None;
        for _ in 0..max_attempts {
            if matches!(
                self.state,
                HostServiceState::ControlReady
                    | HostServiceState::Active
                    | HostServiceState::DegradedRecovery
                    | HostServiceState::Failed
            ) {
                let _ = self.stop_kernel(context, prior_service.clone());
            }
            match self.start_kernel(
                context,
                candidate_service.clone(),
                candidate_recovery.clone(),
            ) {
                Ok(receipt) => return Ok((BoundedRestartOutcome::CandidateActive, receipt)),
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        if candidate_service != prior_service {
            let rollback = self.start_kernel(context, prior_service, prior_recovery);
            if let Ok(receipt) = rollback {
                return Ok((BoundedRestartOutcome::RolledBack, receipt));
            }
        }
        Err(HostServiceError::KernelHandoff(last_error.unwrap_or_else(
            || "candidate generation did not start".to_owned(),
        )))
    }

    /// Starts one independent managed dependency and records its observed process lineage.
    pub fn start_dependency(
        &mut self,
        context: &RequestMetadata,
        plan: HostDependencyPlan,
    ) -> Result<ServiceProcessRecord, HostServiceError> {
        validate_context(context)?;
        plan.validate()?;
        if !matches!(
            self.state,
            HostServiceState::ControlReady | HostServiceState::Active
        ) {
            return Err(HostServiceError::IllegalTransition {
                from: self.state,
                to: HostServiceState::Starting,
            });
        }
        let observation = self.execute(
            context,
            "dependency-inspect",
            plan.service.clone(),
            ServiceOperation::Inspect,
        )?;
        let (process, reused) = match observation {
            PortOutcome::Known(observation)
                if is_ready_process(&observation, &plan.service, &plan.expected_owner) =>
            {
                (
                    observation
                        .process
                        .ok_or(HostServiceError::ReadinessNotProven)?,
                    true,
                )
            }
            PortOutcome::Known(observation)
                if matches!(
                    observation.state,
                    ServiceState::Stopped | ServiceState::Absent
                ) =>
            {
                let started = self.execute(
                    context,
                    "dependency-start",
                    plan.service.clone(),
                    ServiceOperation::Start,
                )?;
                (
                    ready_process(started, &plan.service, &plan.expected_owner)?,
                    false,
                )
            }
            PortOutcome::Known(_) => return Err(HostServiceError::ReadinessNotProven),
            PortOutcome::Partial { .. } => return Err(HostServiceError::IncompleteObservation),
            PortOutcome::Unknown(_) => return Err(HostServiceError::UnknownOutcome),
            PortOutcome::Error(error) => {
                self.fail(HostFailure::Platform(error.to_string()));
                return Err(HostServiceError::Platform(error));
            }
        };
        let transition = eliot_platform::ManagedDependencyTransition {
            context: derived_context(context, "dependency-lineage")?,
            installation: self.installation.clone(),
            dependency: process.clone(),
        };
        if let Err(error) = self.state_store.record_dependency(transition) {
            self.admission_closed = true;
            if !reused {
                if let Err(cleanup_error) = self.cleanup_started_service(context, &plan.service) {
                    self.fail(HostFailure::Platform(format!(
                        "dependency persistence failed ({error}); cleanup failed: {cleanup_error}"
                    )));
                    return Err(cleanup_error);
                }
            }
            self.fail(HostFailure::StateStore(error.to_string()));
            return Err(HostServiceError::StateStore(error));
        }
        Ok(process)
    }

    /// Stops Kernel after closing normal admission and records a clean Host stop.
    pub fn stop_kernel(
        &mut self,
        context: &RequestMetadata,
        service: PlatformHandle,
    ) -> Result<ServiceStopReceipt, HostServiceError> {
        validate_context(context)?;
        validate_handle(&service, "kernel.service")?;
        if !matches!(
            self.state,
            HostServiceState::ControlReady
                | HostServiceState::Active
                | HostServiceState::DegradedRecovery
                | HostServiceState::Failed
        ) {
            return Err(HostServiceError::IllegalTransition {
                from: self.state,
                to: HostServiceState::Draining,
            });
        }
        self.state = HostServiceState::Draining;
        let observation = self.execute(
            context,
            "kernel-stop-inspect",
            service.clone(),
            ServiceOperation::Inspect,
        )?;
        let prior_process = match observation {
            PortOutcome::Known(observation) => match observation.process {
                Some(process) => process,
                None => {
                    self.fail(HostFailure::ReadinessNotProven);
                    return Err(HostServiceError::ReadinessNotProven);
                }
            },
            PortOutcome::Partial { .. } => return self.unknown_stop(),
            PortOutcome::Unknown(_) => return self.unknown_stop(),
            PortOutcome::Error(error) => {
                self.fail(HostFailure::Platform(error.to_string()));
                return Err(HostServiceError::Platform(error));
            }
        };
        let stopped = self.execute(
            context,
            "kernel-stop",
            service.clone(),
            ServiceOperation::Stop,
        )?;
        match stopped {
            PortOutcome::Known(observation)
                if observation.service == service
                    && matches!(
                        observation.state,
                        ServiceState::Stopped | ServiceState::Absent
                    )
                    && observation.process.is_none() => {}
            PortOutcome::Partial { .. } | PortOutcome::Unknown(_) => return self.unknown_stop(),
            PortOutcome::Known(_) => {
                self.fail(HostFailure::ReadinessNotProven);
                return Err(HostServiceError::ReadinessNotProven);
            }
            PortOutcome::Error(error) => {
                self.fail(HostFailure::Platform(error.to_string()));
                return Err(HostServiceError::Platform(error));
            }
        }
        let marker = HostShutdownMarker {
            context: derived_context(context, "kernel-clean-stop")?,
            installation: self.installation.clone(),
            process: prior_process.clone(),
        };
        let token = match self.state_store.prepare_release_pending(marker) {
            Ok(token) => token,
            Err(error) => {
                self.fail(HostFailure::StateStore(error.to_string()));
                return Err(HostServiceError::StateStore(error));
            }
        };
        self.pending_release = Some(token);
        self.durable_finalized = false;
        // The platform process is stopped, but the owner-release proof has not
        // completed yet. Keep Host in recovery until the caller proves release
        // and invokes `finalize_clean_shutdown`.
        self.state = HostServiceState::DegradedRecovery;
        self.failure = None;
        Ok(ServiceStopReceipt {
            service,
            prior_process,
        })
    }

    /// Releases this service's installation-wide owner capability and then
    /// finalizes a previously prepared clean stop. The token is retained when
    /// either phase fails, so a retry cannot bypass the durable pending gate.
    pub fn finalize_clean_shutdown(&mut self) -> Result<(), HostServiceError> {
        let token = self
            .pending_release
            .take()
            .ok_or(HostServiceError::IllegalTransition {
                from: self.state,
                to: HostServiceState::StoppedClean,
            })?;
        if !self.owner_lease.is_for_installation(&self.installation) {
            self.pending_release = Some(token);
            self.admission_closed = true;
            return Err(HostServiceError::OwnerLease(
                "owner capability is bound to another installation".to_owned(),
            ));
        }
        if !self.durable_finalized {
            if let Err(error) = self.state_store.finalize_clean_shutdown(token.clone()) {
                self.pending_release = Some(token);
                self.fail(HostFailure::StateStore(error.to_string()));
                self.admission_closed = true;
                return Err(HostServiceError::StateStore(error));
            }
            self.durable_finalized = true;
        }
        if !self.owner_released {
            if let Err(error) = self.owner_lease.release() {
                self.pending_release = Some(token);
                let error = HostServiceError::OwnerLease(error.to_string());
                self.fail(HostFailure::Platform(error.to_string()));
                self.admission_closed = true;
                return Err(error);
            }
            self.owner_released = true;
        }
        self.state = HostServiceState::StoppedClean;
        self.failure = None;
        self.admission_closed = false;
        Ok(())
    }

    fn cleanup_started_kernel(
        &mut self,
        context: &RequestMetadata,
        service: &PlatformHandle,
    ) -> Result<(), HostServiceError> {
        self.cleanup_started_service(context, service)
    }

    fn cleanup_started_service(
        &mut self,
        context: &RequestMetadata,
        service: &PlatformHandle,
    ) -> Result<(), HostServiceError> {
        let stopped = self.execute(
            context,
            "service-cleanup",
            service.clone(),
            ServiceOperation::Stop,
        )?;
        match stopped {
            PortOutcome::Known(observation)
                if observation.service == *service
                    && matches!(
                        observation.state,
                        ServiceState::Stopped | ServiceState::Absent
                    )
                    && observation.process.is_none() =>
            {
                Ok(())
            }
            PortOutcome::Known(_) => Err(HostServiceError::ReadinessNotProven),
            PortOutcome::Partial { .. } => Err(HostServiceError::IncompleteObservation),
            PortOutcome::Unknown(_) => Err(HostServiceError::UnknownOutcome),
            PortOutcome::Error(error) => Err(HostServiceError::Platform(error)),
        }
    }

    fn execute(
        &mut self,
        context: &RequestMetadata,
        suffix: &str,
        service: PlatformHandle,
        operation: ServiceOperation,
    ) -> Result<PortOutcome<ServiceObservation>, HostServiceError> {
        let request = ServiceRequest {
            context: derived_context(context, suffix)?,
            service,
            operation,
        };
        Ok(self.platform.execute(&request))
    }

    fn unknown_stop(&mut self) -> Result<ServiceStopReceipt, HostServiceError> {
        self.fail(HostFailure::UnknownOutcome);
        Err(HostServiceError::UnknownOutcome)
    }

    fn fail(&mut self, failure: HostFailure) {
        let recovery_only = matches!(
            failure.clone(),
            HostFailure::UnknownOutcome | HostFailure::IncompleteObservation
        );
        self.failure = Some(failure);
        self.state = if recovery_only {
            HostServiceState::DegradedRecovery
        } else {
            HostServiceState::Failed
        };
    }

    fn transition(&mut self, next: HostServiceState) -> Result<(), HostServiceError> {
        if next == HostServiceState::Starting
            && (self.pending_release.is_some() || self.admission_closed)
        {
            return Err(HostServiceError::IllegalTransition {
                from: self.state,
                to: next,
            });
        }
        let legal = matches!(
            (self.state, next),
            (
                HostServiceState::Stopped | HostServiceState::StoppedClean,
                HostServiceState::Starting
            ) | (
                HostServiceState::DegradedRecovery,
                HostServiceState::Starting
            ) | (HostServiceState::Failed, HostServiceState::Starting)
                | (
                    HostServiceState::Starting,
                    HostServiceState::ControlReady | HostServiceState::DegradedRecovery
                )
                | (
                    HostServiceState::ControlReady,
                    HostServiceState::Active
                        | HostServiceState::Draining
                        | HostServiceState::DegradedRecovery
                )
                | (
                    HostServiceState::Active,
                    HostServiceState::Draining | HostServiceState::DegradedRecovery
                )
                | (
                    HostServiceState::DegradedRecovery,
                    HostServiceState::Draining | HostServiceState::Starting
                )
                | (
                    HostServiceState::Failed,
                    HostServiceState::Draining | HostServiceState::Starting
                )
                | (
                    HostServiceState::Draining,
                    HostServiceState::StoppedClean | HostServiceState::DegradedRecovery
                )
        );
        if legal {
            self.state = next;
            Ok(())
        } else {
            Err(HostServiceError::IllegalTransition {
                from: self.state,
                to: next,
            })
        }
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), HostServiceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(HostServiceError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn validate_handle(value: &PlatformHandle, field: &'static str) -> Result<(), HostServiceError> {
    validate_text(value.as_str(), field)
}

fn validate_context(context: &RequestMetadata) -> Result<(), HostServiceError> {
    context.validate()?;
    Ok(())
}

fn derived_context(
    context: &RequestMetadata,
    suffix: &str,
) -> Result<RequestMetadata, HostServiceError> {
    let request_id = RequestId::new(format!("{}:{suffix}", context.request_id.as_str()))?;
    let mut derived = context.clone();
    derived.request_id = request_id;
    Ok(derived)
}

fn is_ready_process(
    observation: &ServiceObservation,
    service: &PlatformHandle,
    expected_owner: &str,
) -> bool {
    observation.service == *service
        && observation.state == ServiceState::Running
        && observation.process.as_ref().is_some_and(|process| {
            process.owner == expected_owner
                && process.state == eliot_runtime_contracts::ServiceProcessState::Ready
                && process.health.is_fully_healthy()
        })
}

fn ready_process(
    outcome: PortOutcome<ServiceObservation>,
    service: &PlatformHandle,
    expected_owner: &str,
) -> Result<ServiceProcessRecord, HostServiceError> {
    match outcome {
        PortOutcome::Known(observation)
            if is_ready_process(&observation, service, expected_owner) =>
        {
            observation
                .process
                .ok_or(HostServiceError::ReadinessNotProven)
        }
        PortOutcome::Known(_) => Err(HostServiceError::ReadinessNotProven),
        PortOutcome::Partial { .. } => Err(HostServiceError::IncompleteObservation),
        PortOutcome::Unknown(_) => Err(HostServiceError::UnknownOutcome),
        PortOutcome::Error(error) => Err(HostServiceError::Platform(error)),
    }
}
