//! Kernel approved `eliotd` launch contour.
//!
//! Architecture: ARCH-MOD-01, A13.2, A13.3 (Kernel and failure domains).
//! Implementation: R1 and I2.23 capability-family topology and crate extraction.
//! Forbidden authority: no Store/Governor/Host semantic authority, no route/default/retry/adoption/mint.
//! This module owns exactly `KernelComposition::launch_eliotd_in_context` and `KernelComposition::retain_eliotd_path_proof` and no additional route, default, retry, adoption, or mint authority.
//! Issue #1884 removed the ungated `KernelComposition::launch_eliotd` wrapper. `control_plane.rs` and `daemon_runtime.rs` launch routes were rerouted by this issue through manifest-bound launch gates, and `launch_eliotd_in_context` now takes the sealed `eliot_ors::BoundKernelExecutionManifest` as a required parameter and threads it to the Job-limit projection unchanged. That parameter is the compile-time/source guard this contour needed: `BoundKernelExecutionManifest` has a private field, a private `const fn verified` constructor and no `Deserialize`, so the primitive cannot be called without a binding the ORS verifier issued, and the tree has exactly one production call site (`daemon_runtime.rs::launch_eliotd_under_manifest`).
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
        KernelBuildError::Principal(_) => "PRINCIPAL",
    }
}

impl KernelComposition {
    /// Launches the approved `eliotd` through the existing Kernel process
    /// authority.  Store bootstrap must already be connected; the child is
    /// never spawned from a raw command or an ambient environment.
    ///
    /// `bound` is the sealed `eliot_ors::BoundKernelExecutionManifest` this
    /// launch is admitted under, carried as a parameter and forwarded
    /// unchanged: the applied Job Object/resource ceilings are projected from
    /// it, never from a re-read of the ACTIVE Host-approved descriptor. A
    /// descriptor swapped into the active slot after the launch gate compared
    /// it therefore cannot make this launch apply ceilings the gate never
    /// compared.
    ///
    /// That parameter is the compile-time/source guard for this primitive
    /// (issue #1884; I1.9, AUD3.5). `BoundKernelExecutionManifest` has one
    /// private field, a private `const fn verified` constructor and NO
    /// `Deserialize`, so no caller outside the ORS verifier's own reach can
    /// produce this argument; and there is exactly ONE production call site in
    /// the tree, `daemon_runtime.rs::launch_eliotd_under_manifest`, which holds
    /// the binding it received from the manifest admission. No production path
    /// reaches the process primitive without a sealed binding.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-3, #901): exactly one terminal is
    /// emitted per failed launch; the admitted receipt versus the failure
    /// record stay distinct, and no raw launch material is logged.
    #[cfg(windows)]
    pub(crate) async fn launch_eliotd_in_context(
        &self,
        context: &tracing::Span,
        bound: &eliot_ors::BoundKernelExecutionManifest,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        // ProcessExecutionGateway owns failures returned by start_in_context;
        // every other error remains owned by this public launch boundary.
        let mut process_owns_terminal = false;
        observe_daemon_launch("kernel.daemon.launch_requested", "attempt", context);
        match self
            .launch_eliotd_inner(context, bound, &mut process_owns_terminal)
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
    /// process start. Reached only through the sealed
    /// `launch_eliotd_under_manifest` gate in `daemon_runtime.rs`, which
    /// requires a `BoundKernelExecutionManifest` argument, and only through
    /// [`KernelComposition::launch_eliotd_in_context`], which receives that same
    /// binding as a parameter and forwards it here unchanged.
    ///
    /// The child's OS-level resource ceilings are not a literal of this file
    /// any more: they are applied from the sealed
    /// `&eliot_ors::BoundKernelExecutionManifest` this launch is admitted
    /// under, by `eliotd_manifest_bound_resource_limits`, which reads them out
    /// of `bound.resource_limits()` rather than out of the ACTIVE descriptor
    /// read above. A recorded ceiling the applied Job cannot express refuses
    /// the launch here, before the process intent is built and before any path
    /// proof is retained, and the ceilings that no manifest record states are
    /// named in that function as the residual they are.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the launch admission sequence is intentionally contiguous so every authority check precedes the single process start"
    )]
    async fn launch_eliotd_inner(
        &self,
        context: &tracing::Span,
        bound: &eliot_ors::BoundKernelExecutionManifest,
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
            self.eliotd_manifest_bound_resource_limits(bound)?,
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
        // #1678 W8: the daemon launch passes the ONE admission-reservation
        // launch gate before the process start. The `eliotd` contour stages no
        // admission reservation, so this resolves none and passes unchanged; but
        // if a reservation is ever bound to this launch's own operation identity
        // and is not `Active`, the gate refuses the launch by name rather than
        // letting a staged/released/expired/reconciling reservation reach the
        // gateway. The gate is a pure read plus the ORS owner's verifier: it
        // stages nothing, launches nothing and mutates no lifecycle position.
        self.require_eliotd_launch_reservation(&operation_id)?;
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

    /// Builds the child's OS-level resource ceilings from the Job Object and
    /// resource limits of the sealed manifest binding this launch is admitted
    /// under, and refuses the launch for a recorded coordinate the applied Job
    /// cannot install (issue #1884; I1.9, AUD3).
    ///
    /// WHERE THE VALUES COME FROM, AND WHAT THIS FUNCTION DOES NOT COVER. This
    /// function reads the three numeric coordinates out of `bound.resource_limits()`
    /// — the `&eliot_ors::BoundKernelExecutionManifest` parameter — and reads nothing
    /// out of the ACTIVE Host-approved `EliotdLaunchDescriptor`. The applied
    /// CEILINGS are therefore projected from the sealed binding, not from a second
    /// read of a mutable slot, so a descriptor swapped into the active slot cannot
    /// change what this launch applies as a ceiling.
    ///
    /// That statement is about the CEILINGS and this function only. It is NOT a
    /// claim about the whole launch: `launch_eliotd_inner` above reads the active
    /// descriptor for the executable, the canonical argv and the working directory,
    /// and builds the child's `ProcessIntent` from it. What closes that gap is the
    /// launch-identity re-check the primitive performs immediately before the
    /// process handoff, in `KernelComposition::require_recorded_launch_identity`
    /// (`daemon_runtime.rs`), which compares the launch identity it is about to
    /// spawn against the sealed binding's own recorded one. The two are distinct
    /// facts and are never substituted for one another: this projection answers
    /// "which ceilings are installed", that check answers "is this the contour the
    /// manifest records".
    ///
    /// The comparison this projection relies on is NOT a second read of the
    /// descriptor here. `KernelComposition::verify_daemon_launch_under_manifest` in
    /// `daemon_runtime.rs` reads the launch's observed `job_object_limits` and
    /// `health_readiness_contract_ref` off the approved descriptor, forwards them
    /// into `eliot_ors::KernelExecutionRestartRequest`, and ORS refuses the launch
    /// under `ManifestResourceLimitsMismatch` when they differ from the sealed
    /// manifest's own and under `ManifestResourceLimitsUnobserved` when the
    /// descriptor states none. A descriptor whose policy token, process ceiling,
    /// working-set ceiling or CPU rate-control percentage differs from the sealed
    /// binding is refused there, durably, and never reaches this function. An
    /// earlier version of this file ALSO re-read the active descriptor here and
    /// compared it again; that second read was the TOCTOU it appeared to close -
    /// a descriptor swapped between two reads - and it is gone.
    ///
    /// The immutable manifest row is deliberately NOT read here either: a re-read
    /// could disagree with the binding this launch was admitted under, and that
    /// sealed binding, not a re-read, not a constant and not a default, is the only
    /// admitted authority for a launch.
    ///
    /// FIELD MAPPING, one coordinate at a time. Each bullet names the
    /// `ManifestResourceLimits` field it reads through `bound.resource_limits()`
    /// and the applied `ResourceLimits` field it produces.
    ///
    /// * `max_working_set_bytes` -> `ResourceLimits::memory_bytes`, which the
    ///   process executor installs as the Job Object memory ceiling. APPLIED.
    ///   Note the precision: the platform field is the Job's total memory
    ///   limit, so this is the manifest ceiling applied as a Job memory charge
    ///   ceiling, not as a per-process working-set trim.
    /// * `max_processes` -> `ResourceLimits::max_descendants`, which the
    ///   process executor installs as the Job Object `active_process_limit`
    ///   after adding the root process back, because the Job's active-process
    ///   count includes the process it owns. APPLIED.
    /// * `cpu_rate_control_percent` ->
    ///   `ResourceLimits::cpu_rate_control_percent`, which the platform Job
    ///   installer writes as the Job's `JOB_OBJECT_CPU_RATE_CONTROL` hard cap,
    ///   through `with_cpu_rate_control_percent(Some(..))` so a stated
    ///   percentage is never dropped by default. APPLIED.
    ///   `eliot_ors::ManifestResourceLimits::validate` requires `1..=100`, and
    ///   both the contract and the Job Object constructor refuse anything
    ///   outside that range, so the stated percentage reaches the Job verbatim
    ///   and is never clamped, rounded or dropped.
    /// * `job_object_policy` -> NOT READ HERE, AND NONE NEEDED. It is a policy
    ///   identity token: nothing in this tree maps a token to Job Object limit
    ///   flags or any other OS setting, so there is no mechanism to apply and
    ///   none to substitute. This projection never names the field at all.
    ///   It is handled exactly like `health_readiness_contract_ref`: compared
    ///   in full against the sealed binding by the gate above, and recorded on
    ///   the launch span by that gate (`daemon_runtime.rs` records
    ///   `job_object_policy` alongside the applied ceilings). It is neither
    ///   substituted with a value the manifest does not record nor dropped on
    ///   the floor, and its non-blank shape is required by the manifest's own
    ///   `validate`, which is where that check lives. Nothing here
    ///   re-implements or duplicates it.
    ///
    /// `health_readiness_contract_ref` is inert text with no OS representation
    /// and is not a resource ceiling: it is compared against the binding and
    /// recorded on the launch span by the gate that admits this launch, and
    /// nothing here applies or discards it.
    ///
    /// NOT BOUND TO THE MANIFEST: the residual, stated at the only site that
    /// applies it. The ceilings below have no coordinate in
    /// `eliot_ors::ManifestResourceLimits` or in any other field of the
    /// recorded manifest, so they are composition values of this contour and not
    /// admitted ceilings; the two vocabularies are disjoint in this direction.
    /// No manifest coordinate is invented for them here, and they are never
    /// described as if the manifest governed them: `wall_timeout_ms`
    /// (86 400 000 ms), `cpu_time_ms` (`None`), `stdout_bytes` (65 536) and
    /// `stderr_bytes` (65 536). The manifest's CPU rate-control percentage is
    /// NOT this `cpu_time_ms`: the first is a share of a CPU and the second a
    /// total, and only the first is a manifest coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`KernelBuildError::Service`] naming the one refused coordinate
    /// in the reason: a `max_processes` that admits no root process. That
    /// refusal is arithmetic on a sealed coordinate, not an observation of the
    /// Host descriptor, so it is not a second owner of the observation seam: an
    /// UNOBSERVED coordinate cannot arrive here at all, because
    /// `daemon_candidate_observed_job_object_limits_and_readiness` in
    /// `daemon_runtime.rs` already forwards a descriptor that states no
    /// `job_object_limits` to the ORS decision under
    /// `ManifestResourceLimitsUnobserved`, and no sealed binding is issued for
    /// a request whose limits were never observed. There is deliberately no
    /// local re-check of that absence here. The one refusal that remains
    /// withholds the launch instead of substituting a value the admitted
    /// manifest does not record, and there is no other coordinate on this
    /// contour that the applied Job cannot install, so no other coordinate is
    /// refused by name here.
    #[cfg(windows)]
    fn eliotd_manifest_bound_resource_limits(
        &self,
        bound: &eliot_ors::BoundKernelExecutionManifest,
    ) -> Result<ResourceLimits, KernelBuildError> {
        // The sealed binding, read once: every applied ceiling below is one of
        // its own recorded coordinates. The ACTIVE descriptor is not consulted.
        let limits = bound.resource_limits();
        // The Job's active-process count includes the process it owns, so the
        // manifest's hard process-count ceiling is the descendant ceiling plus
        // that one root process. A ceiling below one admits no process at all
        // and is refused rather than clamped.
        let Some(max_descendants) = limits.max_processes.checked_sub(1) else {
            return Err(KernelBuildError::Service(format!(
                "eliotd launch refused: the admitted manifest field max_processes is {}, which admits no process for this launch",
                limits.max_processes
            )));
        };
        // These three constants, and the absent `cpu_time_ms` below, are NOT
        // coordinates of the admitted manifest. See this function's
        // documentation: no manifest record states a wall-clock timeout, a
        // CPU-time total, a stdout cap or a stderr cap for this contour, and
        // none is invented for them here.
        let wall_timeout_ms = 86_400_000_u64;
        let stdout_bytes = 64 * 1024_u64;
        let stderr_bytes = 64 * 1024_u64;
        ResourceLimits::new(
            wall_timeout_ms,
            None,
            Some(limits.max_working_set_bytes),
            stdout_bytes,
            stderr_bytes,
            max_descendants,
        )
        .and_then(|resource_limits| {
            resource_limits.with_cpu_rate_control_percent(Some(limits.cpu_rate_control_percent))
        })
        .map_err(|error| KernelBuildError::Service(error.to_string()))
    }

    /// Applies the #1678 admission-reservation launch gate to the `eliotd`
    /// process start (W8).
    ///
    /// This is the production caller of
    /// [`admission_reservation_saga::require_bound_admission_reservation_launch`]
    /// for the daemon contour, reached from
    /// [`KernelComposition::launch_eliotd_inner`] immediately before the single
    /// `gateway.start`.
    ///
    /// It runs after the live activation checks and BEFORE the gateway, so a
    /// launch it refuses has staged nothing, mutated no lifecycle position and
    /// contacted no executor. The process intent and the retained path proof
    /// are built earlier in the same sequence; they are values local to this
    /// attempt and are dropped with the refused launch, and no process was
    /// started under them. The `eliotd` contour stages no admission
    /// reservation today, so this resolves no reservation and passes; the gate
    /// exists so that a reservation bound to this launch's own operation
    /// identity can never reach a spawn while `STAGED`, `RELEASED`, `EXPIRED`,
    /// `RECONCILING`, `STALE_FENCE`, `FOREIGN_OWNER`, `IDENTITY_CONFLICT`,
    /// `MISSING`, or unreadable. It never stages a reservation.
    ///
    /// # Errors
    ///
    /// Returns [`KernelBuildError::Service`] carrying the owner's own refusal
    /// discriminant, so the diagnostic names the state that blocked the launch
    /// instead of a generic "launch denied".
    #[cfg(windows)]
    fn require_eliotd_launch_reservation(
        &self,
        operation_id: &eliot_process::OperationId,
    ) -> Result<(), KernelBuildError> {
        use eliot_ors::{OperationIdentity, StateFenceSnapshot, epoch_lineage_for};
        // The launch's OWN operation identity is the work item and attempt the
        // gate searches under: a reservation is only ever resolved for the exact
        // launch identity that produced it.
        let work_item = OperationIdentity::new(operation_id.as_str())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let proposed_attempt = work_item.clone();
        // The live authority epoch/fence come from the composition's own current
        // fence, validated by the ORS owner before the store is searched.
        let state_fence = self.current_state_fence().ok_or_else(|| {
            KernelBuildError::Service("eliotd launch has no current State Fence".to_owned())
        })?;
        let authority_epoch = {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            service.authority_epoch().clone()
        };
        let lineage = epoch_lineage_for(&authority_epoch, None)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let fence_snapshot =
            StateFenceSnapshot::capture(&state_fence, authority_epoch.sequence.get())
                .and_then(|snapshot| {
                    snapshot
                        .validate_against_epoch(&authority_epoch)
                        .map(|()| snapshot)
                })
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let now_unix_ms = i64::try_from(unix_ms())
            .map_err(|_| KernelBuildError::Service("eliotd launch clock is unusable".to_owned()))?;
        super::admission_reservation_saga::require_bound_admission_reservation_launch(
            self.generation_gateway.ors.as_ref(),
            &work_item,
            &proposed_attempt,
            &lineage,
            &fence_snapshot,
            now_unix_ms,
        )
        .map(|_| ())
        .map_err(|refusal| KernelBuildError::Service(refusal.to_string()))
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

#[cfg(all(test, windows))]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_platform::PlatformHandle;

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            std::num::NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn manifest_limits(
        job_object_policy: &str,
        cpu_rate_control_percent: u16,
    ) -> eliot_ors::ManifestResourceLimits {
        eliot_ors::ManifestResourceLimits {
            job_object_policy: job_object_policy.to_owned(),
            max_processes: 8,
            max_working_set_bytes: 2_097_152,
            cpu_rate_control_percent,
        }
    }

    fn descriptor_with_limits(
        job_object_limits: Option<eliot_ors::ManifestResourceLimits>,
    ) -> EliotdLaunchDescriptor {
        let handle = |value: &str| PlatformHandle::new(value).expect("descriptor handle");
        let executable_sha256 = "a".repeat(64);
        let config_sha256 = "b".repeat(64);
        let nonce = handle("eliotd:0123456789abcdef0123456789abcdef");
        let config = handle("C:/eliot/eliotd-governor.json");
        EliotdLaunchDescriptor {
            wire_id: "eliot.kernel.eliotd-launch".to_owned(),
            wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
            executable: handle("C:/eliot/eliotd.exe"),
            executable_sha256: executable_sha256.clone(),
            arguments: vec![
                handle("--executable-sha256"),
                handle(&executable_sha256),
                handle("--config-descriptor"),
                config.clone(),
            ],
            working_directory: handle("C:/eliot"),
            config_descriptor: config,
            config_descriptor_sha256: config_sha256,
            protected_snapshot_digest: "c".repeat(64),
            launch_nonce: nonce,
            authority_epoch: test_epoch(1),
            generation: ResourceGeneration::genesis(),
            restart_policy: None,
            job_object_limits,
            health_readiness_contract_ref: Some("eliotd.readiness.v1".to_owned()),
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("descriptor digest")
    }

    /// This file's own source, resolved at compile time, so a running Kernel
    /// never locates a file to read it.
    const THIS_FILE: &str = include_str!("daemon_process_launch.rs");

    /// The DEFINITION of `eliotd_manifest_bound_resource_limits` — its parameter
    /// list and its body — sliced from its own `fn` line up to the next
    /// documented item in the same `impl` block.
    ///
    /// Both boundaries are exact spellings, so a moved or renamed function
    /// fails the lookup instead of silently proving an empty slice. The slice
    /// starts AT the `fn` line, so the function's own doc comment is excluded:
    /// the claim under test is about what the code does, not about what the
    /// prose beside it says.
    fn projection_signature_source() -> &'static str {
        let start = THIS_FILE
            .find("    fn eliotd_manifest_bound_resource_limits(")
            .expect("the projection is defined in this file");
        let end = THIS_FILE[start..]
            .find("\n    /// Applies the #1678 admission-reservation launch gate")
            .map(|offset| start + offset)
            .expect("the admission-reservation gate follows the projection");
        &THIS_FILE[start..end]
    }

    /// The definition of `launch_eliotd_in_context`, up to the private
    /// `launch_eliotd_inner` it delegates to.
    fn launch_boundary_source() -> &'static str {
        let start = THIS_FILE
            .find("    pub(crate) async fn launch_eliotd_in_context(")
            .expect("the launch boundary is defined in this file");
        let end = THIS_FILE[start..]
            .find("\n    /// Admitted-launch sequence;")
            .map(|offset| start + offset)
            .expect("the launch sequence follows the launch boundary");
        &THIS_FILE[start..end]
    }

    /// The manifest's CPU rate-control percentage reaches the applied limits
    /// verbatim from the SEALED binding, never from the ACTIVE descriptor.
    ///
    /// WHY THIS IS A SOURCE-LEVEL PROOF AND NOT A CALL.
    /// `eliot_ors::BoundKernelExecutionManifest` is sealed: one private field,
    /// a private `const fn verified` constructor and NO `Deserialize`. A test
    /// in this crate therefore cannot construct one, and the correct fix is not
    /// to fake a manifest or to add a `#[cfg(test)]` constructor to the ORS
    /// type — either would invent an authority the ORS owner deliberately does
    /// not expose. So the projection is asserted on its own source text
    /// instead, in the same style as the sibling `daemon_runtime.rs` gate
    /// tests, and the numeric contract it is asserted against is checked
    /// through the ORS owner's own public `ManifestResourceLimits::validate`.
    ///
    /// The claim: every applied ceiling is a read of the binding's own
    /// coordinates, the descriptor is not an operand, and the binding is
    /// forwarded unchanged from the primitive's parameter to the projection's.
    #[test]
    fn the_manifest_cpu_rate_control_percentage_reaches_the_applied_limits() {
        // The coordinate is a legal recorded percentage, so the manifest's own
        // rule admits it; this is the public accessor path, and it is the rule
        // that makes the applied value reach the Job verbatim and unclamped.
        let limits = manifest_limits("eliotd-job-policy-v1", 37);
        assert_eq!(limits.cpu_rate_control_percent, 37);
        limits
            .validate()
            .expect("a percentage inside 1..=100 is a legal recorded coordinate");

        let signature = projection_signature_source();
        assert!(
            signature.contains("bound: &eliot_ors::BoundKernelExecutionManifest"),
            "the projection no longer takes the sealed binding, so it cannot read the manifest's own coordinates"
        );
        assert!(
            !signature.contains("EliotdLaunchDescriptor"),
            "the projection takes the ACTIVE descriptor again, which is the re-read the binding argument removed"
        );
        let body = signature
            .split_once(") -> Result<ResourceLimits, KernelBuildError> {")
            .map(|(_parameters, body)| body)
            .expect("the projection has a body after its signature");
        for read in [
            "let limits = bound.resource_limits();",
            "limits.max_processes.checked_sub(1)",
            "Some(limits.max_working_set_bytes)",
            ".with_cpu_rate_control_percent(Some(limits.cpu_rate_control_percent))",
        ] {
            assert!(
                body.contains(read),
                "the applied ceiling `{read}` is gone or weakened in the projection"
            );
        }
        assert!(
            !body.contains("job_object_limits"),
            "the projection reads the descriptor's optional limits slot again instead of the sealed binding"
        );

        // The binding is THREADED, not reconstructed: the launch boundary
        // forwards the very parameter it received, and the sequence hands that
        // same reference to the projection. A contour that rebuilt a value here
        // could disagree with what the gate compared.
        let boundary = launch_boundary_source();
        assert!(
            boundary.contains("launch_eliotd_inner(context, bound,"),
            "the launch boundary no longer forwards the sealed binding unchanged"
        );
        let sequence = THIS_FILE
            .find("    async fn launch_eliotd_inner(")
            .expect("the launch sequence is defined in this file");
        let projection_call = THIS_FILE
            .find("Self::eliotd_manifest_bound_resource_limits(bound)?")
            .expect("the launch sequence no longer projects from the sealed binding");
        assert!(
            sequence < projection_call,
            "the projection call must sit inside the launch sequence, after the binding arrives"
        );
        // Counted over the SLICE, not over the whole file: the whole file also
        // contains this test's own search literals, which would make the count
        // self-fulfilling. The slice is production code only.
        let delegations = boundary
            .matches("launch_eliotd_inner(context, bound,")
            .count();
        assert_eq!(
            delegations, 1,
            "the launch boundary delegates into the launch sequence {delegations} times; exactly one delegation exists, and it carries the binding"
        );
    }

    /// A stated policy token is inert: it is neither substituted into an
    /// applied ceiling nor allowed to change one. Substituting it would be a
    /// fabricated Job limit the admitted manifest does not record.
    #[test]
    fn a_stated_job_object_policy_token_is_never_substituted_into_an_applied_ceiling() {
        // Value level, through the public `ManifestResourceLimits` only: the
        // token is data beside the three numeric coordinates, and changing it
        // changes nothing else in the record the projection reads.
        let first = manifest_limits("eliotd-job-policy-v1", 37);
        let mut substituted = first.clone();
        substituted.job_object_policy = "eliotd-job-policy-v2".to_owned();
        assert_eq!(substituted.max_processes, first.max_processes);
        assert_eq!(
            substituted.max_working_set_bytes,
            first.max_working_set_bytes
        );
        assert_eq!(
            substituted.cpu_rate_control_percent,
            first.cpu_rate_control_percent
        );

        // Source level, because the projection needs a sealed binding this
        // crate cannot construct (see the case above): the token is not named
        // anywhere in the projection's code, so there is no site at which it
        // could become a ceiling.
        let signature = projection_signature_source();
        let body = signature
            .split_once(") -> Result<ResourceLimits, KernelBuildError> {")
            .map(|(_parameters, body)| body)
            .expect("the projection has a body after its signature");
        assert!(
            !body.contains("job_object_policy"),
            "the projection now reads the policy token, which would be substituting it into a ceiling"
        );
    }

    /// The launch gate compares the whole admitted limits record, so a
    /// descriptor whose policy token differs from the sealed binding's token is
    /// non-equal and is refused by
    /// `KernelComposition::launch_eliotd_under_manifest` in `daemon_runtime.rs`
    /// before this adapter is reached. This proves the operand that comparison
    /// runs on is total over the policy token and not only over the numeric
    /// ceilings.
    #[test]
    fn a_descriptor_whose_policy_token_differs_from_the_binding_is_not_the_recorded_manifest() {
        let bound = manifest_limits("eliotd-job-policy-v1", 37);
        let mut substituted = bound.clone();
        substituted.job_object_policy = "eliotd-job-policy-v2".to_owned();
        assert_ne!(
            substituted, bound,
            "a different policy token must not compare equal to the sealed binding"
        );
        let admitted = descriptor_with_limits(Some(bound.clone()));
        assert_eq!(
            admitted.job_object_limits.as_ref(),
            Some(&bound),
            "the admitted descriptor states exactly the sealed binding's limits"
        );
        let refused = descriptor_with_limits(Some(substituted));
        assert_ne!(
            refused.job_object_limits.as_ref(),
            Some(&bound),
            "the launch gate refuses this descriptor on its policy token alone"
        );
    }

    /// The projection refuses exactly one coordinate, and it refuses it for
    /// arithmetic rather than for an observation.
    ///
    /// An ABSENT limits record is no longer refused here: that absence is the
    /// ORS decision's own refusal (`ManifestResourceLimitsUnobserved`, forwarded
    /// by `daemon_candidate_observed_job_object_limits_and_readiness` in
    /// `daemon_runtime.rs`), and no sealed binding is issued for a request whose
    /// limits were never observed. A second local refusal here would be a second
    /// owner of that one observation seam, so the source below must not contain
    /// one. What remains is the arithmetic arm: a process ceiling that admits no
    /// root process is refused rather than clamped. ORS's own
    /// `ManifestResourceLimits::validate` already refuses `max_processes == 0`, so
    /// that arm is a guard on the sealed coordinate rather than a reachable
    /// outcome for an ORS-validated manifest — and it is the only local refusal,
    /// which the source slice asserts.
    #[test]
    fn an_absent_or_unusable_manifest_ceiling_is_refused_by_name() {
        // Value level, through the public `ManifestResourceLimits` rule the ORS
        // owner applies to every recorded projection: a zero process ceiling is
        // not a recordable coordinate at all.
        let mut no_process = manifest_limits("eliotd-job-policy-v1", 37);
        no_process.max_processes = 0;
        let refusal = no_process
            .validate()
            .expect_err("a zero process ceiling is refused by the manifest's own rule");
        assert!(
            refusal.to_string().contains("max_processes"),
            "the zero-ceiling refusal must name the coordinate it refuses"
        );
        manifest_limits("eliotd-job-policy-v1", 37)
            .validate()
            .expect("the ordinary limits record stays valid");

        // Source level, because the projection needs a sealed binding this crate
        // cannot construct (see the case above): exactly one local refusal, it
        // names the arithmetic coordinate, and the observation refusal is absent.
        let signature = projection_signature_source();
        let body = signature
            .split_once(") -> Result<ResourceLimits, KernelBuildError> {")
            .map(|(_parameters, body)| body)
            .expect("the projection has a body after its signature");
        assert_eq!(
            body.matches("return Err(KernelBuildError::Service(")
                .count(),
            1,
            "the projection must carry exactly one local refusal: the arithmetic one"
        );
        assert!(
            body.contains("which admits no process for this launch"),
            "the surviving refusal no longer names the arithmetic coordinate"
        );
        assert!(
            !body.contains("job_object_limits"),
            "the projection re-introduces a second owner of the unobserved-coordinate refusal"
        );
    }
}
