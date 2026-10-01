//! Kernel approved `eliotd` launch contour.
//!
//! Architecture: ARCH-MOD-01, A13.2, A13.3 (Kernel and failure domains).
//! Implementation: R1 and I2.23 capability-family topology and crate extraction.
//! Forbidden authority: no Store/Governor/Host semantic authority, no route/default/retry/adoption/mint.
//! This module owns exactly `KernelComposition::launch_eliotd` and `KernelComposition::retain_eliotd_path_proof` and no additional route, default, retry, adoption, or mint authority.
//! Keeps signatures, bodies, ordering, visibility, routes, protocol and authority unchanged; `control_plane.rs` and `daemon_runtime.rs` callers remain untouched.
//! No Store/Governor/Host semantic decisions, no alternate lease or oracle, no unbounded recovery.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use eliot_platform_windows::WindowsPlatform;

use super::ACTIVE_DAEMON_CALLER;
use super::ActionLeaseRef;
use super::DaemonRuntimeStatus;
use super::EliotdLaunchDescriptor;
use super::EnvironmentInheritance;
use super::EnvironmentProjection;
use super::FencingToken;
use super::Generation;
use super::ImageId;
use super::JobId;
use super::KernelBuildError;
use super::KernelComposition;
use super::ProcessCallerSession;
use super::ProcessExecutionAdmissionRequest;
use super::ProcessExecutionError;
use super::ProcessIntent;
use super::ProcessOwnerBinding;
use super::ProcessPathProof;
use super::ProcessSessionClass;
use super::ProcessStartReceipt;
use super::ProcessTreeId;
use super::ResourceLimits;
use super::SessionId;
use super::current_process_named_pipe_expectation;
use super::diagnostic_brief::DiagnosticTrigger;
use super::eliotd_launch_attempt_identity;
use super::eliotd_operation_id;
use super::kernel_audit::AuditEventDraft;
use super::observe_named_pipe_peer_process;
use super::stable_owner_principal_digest;
use super::unix_ms;

/// F-LOG-KERNEL-3 (#901): daemon-launch boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.daemon.*` event names
/// plus a bounded stable outcome. The shared parent span carries only screened
/// operation/generation/fence/process-tree/lease correlation; no executable
/// paths, argv/env, fence nonce, or owner error strings are attached (I15.4).
#[cfg(windows)]
fn observe_daemon_launch(event: &'static str, outcome: &'static str, context: &tracing::Span) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        parent: context,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon launch observation"
    );
}

/// Records one authenticated correlation identity on the shared launch span.
#[cfg(windows)]
fn record_launch_context_field(context: &tracing::Span, field: &'static str, original: &str) {
    let value = super::kernel_diagnostics::bound_field(original);
    context.record(field, value.text());
}

/// Maps one daemon-launch build failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload is never logged.
#[cfg(windows)]
fn daemon_launch_terminal_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "PLATFORM",
        KernelBuildError::Transport(_) => "TRANSPORT",
        KernelBuildError::Runtime(_) => "RUNTIME",
        KernelBuildError::Ors(_) => "ORS",
        KernelBuildError::Core(_) => "CORE",
        KernelBuildError::Service(_) => "SERVICE",
        KernelBuildError::StoreBootstrapRequired => "STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "STORE_ALREADY_CONNECTED",
        KernelBuildError::StoreRouteOwnerRefused(_) => "STORE_ROUTE_OWNER_REFUSED",
        KernelBuildError::Principal(_) => "PRINCIPAL",
    }
}

impl KernelComposition {
    /// Launches the approved `eliotd` through the existing Kernel process
    /// authority.  Store bootstrap must already be connected; the child is
    /// never spawned from a raw command or an ambient environment.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-3, #901): exactly one terminal is
    /// emitted per failed launch; the admitted receipt versus the failure
    /// record stay distinct, and no raw launch material is logged.
    #[cfg(windows)]
    pub async fn launch_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        let context = super::kernel_diagnostics::operation_context(None, None, None, None);
        self.launch_eliotd_in_context(&context).await
    }

    #[cfg(windows)]
    pub(crate) async fn launch_eliotd_in_context(
        &self,
        context: &tracing::Span,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        // ProcessExecutionGateway owns failures returned by start_in_context;
        // every other error remains owned by this public launch boundary.
        let mut process_owns_terminal = false;
        observe_daemon_launch("kernel.daemon.launch_requested", "attempt", context);
        match self
            .launch_eliotd_inner(context, &mut process_owns_terminal)
            .await
        {
            Ok(receipt) => {
                observe_daemon_launch("kernel.daemon.launch_committed", "success", context);
                // Issue #1837: durable audit evidence for process lifecycle.
                self.audit_observe(AuditEventDraft::process_launch_committed(&receipt));
                Ok(receipt)
            }
            Err(error) => {
                observe_daemon_launch("kernel.daemon.launch_failed", "rejected", context);
                if !process_owns_terminal {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        daemon_launch_terminal_code(&error),
                        context,
                    );
                }
                // Issue #1837: durable audit evidence for process lifecycle.
                self.audit_observe(AuditEventDraft::process_launch_failed(
                    daemon_launch_terminal_code(&error),
                    self.current_state_fence().as_ref(),
                ));
                // Issue #1844: a launch failure compiles its brief.
                self.observe_diagnostic_problem(DiagnosticTrigger::ModuleCrashOrRestartExhaustion);
                Err(error)
            }
        }
    }

    /// Admitted-launch sequence; every authority check precedes the single
    /// process start. See [`KernelComposition::launch_eliotd`].
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the launch admission sequence is intentionally contiguous so every authority check precedes the single process start"
    )]
    async fn launch_eliotd_inner(
        &self,
        context: &tracing::Span,
        process_owns_terminal: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        launch
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let gateway = self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required before eliotd launch".to_owned(),
            )
        })?;
        {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_some() {
                return Err(KernelBuildError::Service(
                    "eliotd launch was already admitted for this Kernel generation".to_owned(),
                ));
            }
        }
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let launch_identity = eliotd_launch_attempt_identity(
            &launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )?;
        let operation_id = eliotd_operation_id(generation, &launch_identity)?;
        let process_tree_id = ProcessTreeId::new(format!("eliotd-tree-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let job_id = JobId::new(format!("eliotd-job-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let image_id = ImageId::new(format!("eliotd-image-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let session_id = SessionId::new(format!("eliotd-session-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let arguments = launch
            .arguments
            .iter()
            .map(|argument| argument.as_str().to_owned())
            .collect::<Vec<_>>();
        let intent = ProcessIntent::new(
            operation_id.clone(),
            process_tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            launch.executable.as_str(),
            launch.executable_sha256.clone(),
            arguments,
            launch.working_directory.as_str(),
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            ResourceLimits::new(86_400_000, None, None, 64 * 1024, 64 * 1024, 4)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        // INTENDED EpochId shape (Split A/B cutover, B→A→C): FencingToken::new
        // takes EpochId, getter &EpochId, is_same_authority. Do not edit A/B
        // files to make this compile in isolation.
        let state_fence = FencingToken::new(
            launch.authority_epoch.clone(),
            generation,
            format!("eliotd-launch-fence-{launch_identity}"),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let admission = ProcessExecutionAdmissionRequest::new(
            ACTIVE_DAEMON_CALLER,
            intent,
            ActionLeaseRef::new(format!("eliotd-kernel-launch-{launch_identity}"))
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            state_fence,
            unix_ms().saturating_add(60_000),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        record_launch_context_field(
            context,
            "operation",
            admission.intent().operation_id().as_str(),
        );
        let generation_text = admission.intent().generation().get().to_string();
        record_launch_context_field(context, "generation", &generation_text);
        if let Some(epoch_digest) = admission.state_fence().canonical_epoch_digest() {
            record_launch_context_field(context, "state_fence", &epoch_digest);
            record_launch_context_field(context, "authority_epoch", &epoch_digest);
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
        let proof = Self::retain_eliotd_path_proof(&launch, &admission)?;
        // Issue #79: the service-owned launch joins the same typed session
        // validation the frame gateway enforces. The admitted caller session
        // carries the just-minted intent session under the daemon-generation
        // class (server-minted, never wire-supplied); any future mint skew
        // between intent, owner, and fence fails here instead of spawning an
        // unbound process.
        let caller_session = ProcessCallerSession::new(
            ProcessSessionClass::EliotdGeneration,
            owner.clone(),
            admission.intent().session_id().clone(),
        )
        .map_err(|error| {
            KernelBuildError::Service(format!("eliotd caller session binding failed: {error}"))
        })?;
        eliot_process::validate_process_intent_session(
            admission.intent(),
            &caller_session,
            &owner,
            admission.state_fence(),
        )
        .map_err(|error| {
            KernelBuildError::Service(format!("eliotd intent session binding failed: {error}"))
        })?;
        let (candidate, activation) = {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if service.generation_fenced()
                || !matches!(
                    service.state(),
                    super::KernelServiceState::Activating | super::KernelServiceState::Ready
                )
            {
                return Err(KernelBuildError::Service(
                    "eliotd launch has no current authenticated activation".to_owned(),
                ));
            }
            let candidate = service.candidate_binding().cloned().ok_or_else(|| {
                KernelBuildError::Service(
                    "eliotd launch has no current Host Kernel candidate binding".to_owned(),
                )
            })?;
            let activation = service.activation_receipt().cloned().ok_or_else(|| {
                KernelBuildError::Service(
                    "eliotd launch has no authenticated activation receipt".to_owned(),
                )
            })?;
            (candidate, activation)
        };
        candidate
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.authority_epoch != launch.authority_epoch
            || activation.generation != launch.generation
            || candidate.kernel_epoch != launch.authority_epoch
            || admission.state_fence().authority_epoch() != &activation.authority_epoch
            || admission.state_fence().generation().get() != activation.generation.value()
        {
            return Err(KernelBuildError::Service(
                "eliotd launch candidate differs from its authenticated activation".to_owned(),
            ));
        }
        self.validate_candidate_process_binding(&candidate)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let outer_binding = candidate;
        {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_some() || state.status != DaemonRuntimeStatus::NotLaunched {
                return Err(KernelBuildError::Service(
                    "eliotd launch state changed before process resume".to_owned(),
                ));
            }
            state.status = DaemonRuntimeStatus::Launching;
            state.supervision = None;
            state.live_ready = None;
        }
        *process_owns_terminal = true;
        let receipt = match gateway
            .start_in_context(&owner, admission, proof, outer_binding, context)
            .await
        {
            Ok(receipt) => {
                *process_owns_terminal = false;
                receipt
            }
            Err(error) => {
                let reason = format!("eliotd process start failed: {error}");
                let unknown_outcome = matches!(&error, ProcessExecutionError::UnknownOutcome);
                let _ = self.record_daemon_failed(&reason, unknown_outcome);
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        // The gateway has validated this original receipt. Project its existing
        // OS identity and image digest without another handle/PID/image query.
        let physical = receipt.identity().physical();
        record_launch_context_field(context, "process_id", &physical.process_id().to_string());
        record_launch_context_field(
            context,
            "process_start_100ns",
            &physical.start_time_100ns().to_string(),
        );
        record_launch_context_field(
            context,
            "image_sha256",
            receipt.identity().executable_sha256(),
        );
        observe_daemon_launch(
            "kernel.daemon.launch_identity_observed",
            "validated_receipt",
            context,
        );
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelBuildError::Service("daemon runtime lock poisoned".to_owned()))?;
        state.status = DaemonRuntimeStatus::Running;
        state.receipt = Some(receipt.clone());
        drop(state);
        self.note_agent_bridge_peer_set_change();
        Ok(receipt)
    }

    #[cfg(windows)]
    fn retain_eliotd_path_proof(
        launch: &EliotdLaunchDescriptor,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> Result<ProcessPathProof, KernelBuildError> {
        let executable = PathBuf::from(launch.executable.as_str());
        let working_directory = PathBuf::from(launch.working_directory.as_str());
        let daemon_platform =
            WindowsPlatform::new(working_directory.clone()).map_err(KernelBuildError::Platform)?;
        let lease = daemon_platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .map_err(KernelBuildError::Platform)?;
        Ok(ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        })
    }
}
