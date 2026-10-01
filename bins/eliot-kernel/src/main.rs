#![forbid(unsafe_code)]

//! `eliot-kernel` binary entry: thin orchestration over ROOT inputs.
//!
//! `main` keeps parse → build → construct → run → shutdown only. The startup
//! contour lives in `startup_binding` (ROOT inputs) and the authenticated
//! front-door loop lives in `front_door_driver` (cell 1); both are
//! binary-private. Terminal receipt/status projection (`exit_*`,
//! `write_error`) stays here.
//!
//! Capability cells (§15 req.1; I01-02; #13 thin bridge surface):
//! cell 1 front-door/IPC admission — `agent_bridge`, `front_door_listener`,
//!   `front_door_session`, `frame_dispatch` (+6), `host_request_route` (+6),
//!   `daemon_session_guard` (+2), `runtime_identity` (+8), and this binary's
//!   `front_door_driver` loop;
//! cell 2 epochs/fencing/leases — `supervision_lease_authority`,
//!   `daemon_session_guard` (+1), `daemon_supervision` (+8);
//! cell 3 ORS/generation state — `generation_recovery` (+5);
//! cell 4 control reserve/lifecycle gateway — `control_plane` (+6);
//! cell 5 generation routing — `generation_control`, `generation_recovery` (+3);
//! cell 6 daemon/store-rebind dispatch — `daemon_request_dispatch` (+7),
//!   `store_receipt_dispatch`, `control_plane` (+4), `frame_dispatch` (+1),
//!   `host_request_route` (+1);
//! cell 7 health/readiness view — `health_view`, `daemon_request_dispatch` (+6);
//! cell 8 process/daemon/store runtime — `process_execution`,
//!   `process_execution_client`, `daemon_runtime`, `daemon_process_launch`,
//!   `daemon_live_receipt`, `daemon_supervision` (+2), `runtime_identity` (+1),
//!   `canonical_store_runtime`;
//! ROOT composition/entry — `lib` (`KernelComposition`), this `main` plus
//!   `startup_binding`, `composition_bootstrap`, `kernel_build_contract`,
//!   `kernel_config`;
//! debt/out-of-scope for #15 — `r13_os_harness`, `r13_two_token_harness`,
//!   `tests`, `tests/`; agent-bridge admission honors the #13 thin-surface
//!   boundary, and process ownership follows I01-02.

use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use eliot_kernel::kernel_diagnostics::{
    EntrypointStage, install_kernel_diagnostics, observe_entrypoint,
    observe_entrypoint_with_detail, observe_terminal_error,
};
use eliot_kernel::{
    AuditAnchorBinding, EliotdReceiptRootBinding, KernelBuildError, KernelComposition,
    KernelConfig, KernelDoctorRecoveryLedger, compose_dispatch_contour,
    compose_production_doctor_front_door, compose_production_native_worker_front_door,
    compose_production_testd_front_door,
};
use eliot_observability_runtime::{
    ObservabilityConfig, RollingLogPolicy, RuntimeProfile, SpoolPolicy,
};

#[cfg(windows)]
mod front_door_driver;
mod crash_context;
mod startup_binding;

/// Stable operational-log stem for this process. The generation name carries
/// the exit code, so a fresh process start is distinguishable from a rolling
/// rotation without any second naming scheme.
const OPERATIONAL_LOG_STEM: &str = "eliot-kernel";

/// Bounded protected spool generation count, at the same declared ceiling.
const OPERATIONAL_SPOOL_GENERATIONS: u32 =
    eliot_observability_runtime::config::MAX_ROLLING_GENERATIONS;

/// Largest accepted single spooled critical record, in bytes, at the crate's
/// declared ceiling (`MAX_SPOOL_RECORD_BYTES`).
const OPERATIONAL_SPOOL_RECORD_BYTES: u64 =
    eliot_observability_runtime::config::MAX_SPOOL_RECORD_BYTES;

/// Derives the process observability configuration from the two roots the
/// Host already injected into this exact process.
///
/// `receipt_root` and `kernel_ors_root` come from
/// `startup_binding::KernelStartupBinding::from_environment`
/// (`ELIOT_KERNEL_RECEIPT_ROOT`, `ELIOT_KERNEL_ORS_ROOT`) and are the same
/// validated values the Kernel opens with `ProtectedRootLease` in
/// `eliot-kernel/src/lib.rs`. The profile contour is the same one the Kernel
/// already resolves for its own authority descriptor:
/// `startup_binding::authority_contour` maps an authority descriptor inside
/// the work root to the portable current-user contour and anything else to
/// `ProgramData`, so the last-resort sink is the surface this process actually
/// runs on rather than an assumed installation profile.
///
/// `metrics_listen` and `otlp_endpoint` stay at the crate's own
/// `None`: no canonical `OpenMetrics` bind address and no approved OTLP
/// collector endpoint exist in the tree, and I16.2 requires the OTLP bridge to
/// stay disabled by default.
fn observability_config(
    receipt_root: &Path,
    ors_root: &Path,
    contour: &eliot_kernel::AuthorityDescriptorContour,
) -> ObservabilityConfig {
    let profile = match contour {
        eliot_kernel::AuthorityDescriptorContour::PortableCurrentUser { .. } => {
            RuntimeProfile::Portable
        }
        eliot_kernel::AuthorityDescriptorContour::ProgramData => RuntimeProfile::SystemService,
    };
    // `SystemService` uses the Windows Event Log as its last resort
    // (`bootstrap::sinks_for`); the portable contour needs the protected
    // event spool, so the spool sits beside the ORS root the Kernel owns.
    let spool = match profile {
        RuntimeProfile::SystemService => None,
        RuntimeProfile::UserMode | RuntimeProfile::Portable => Some(SpoolPolicy {
            directory: ors_root.join("spool"),
            file_stem: "critical-events".to_owned(),
            max_generations: OPERATIONAL_SPOOL_GENERATIONS,
            max_record_bytes: OPERATIONAL_SPOOL_RECORD_BYTES,
        }),
    };
    ObservabilityConfig {
        profile,
        rolling_log: RollingLogPolicy::declared_bounded(
            receipt_root.join("logs"),
            OPERATIONAL_LOG_STEM,
            0,
        ),
        spool,
        metrics_listen: None,
        otlp_endpoint: None,
    }
}

/// Keeps startup, authenticated listener rotation, and fenced shutdown in one
/// ordered authority path.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    // F-LOG-KERNEL-0 (#895): install the process-global diagnostics
    // subscriber before any entrypoint observation. Best-effort by
    // contract: diagnostics never gate startup, so both the first install
    // and an AlreadyOwned re-init continue into the launch funnel.
    let _ = install_kernel_diagnostics();
    #[cfg(windows)]
    let mut crash_reporter = match eliot_observability_runtime::install_crash_reporter(
        eliot_observability_runtime::CrashReporterConfig {
            process: "eliot-kernel".to_owned(),
            package_version: env!("CARGO_PKG_VERSION").to_owned(),
            runtime_profile: None,
            symbol_artifact: None,
            retention_policy: None,
            initial_context: crash_context::unavailable_context(),
        },
    ) {
        Ok(reporter) => {
            reporter.invalidate_runtime_context();
            Some(reporter)
        }
        Err(_) => {
            tracing::warn!(
                target: "eliot::crash_reporter",
                event = "kernel_reporter_install_failed",
                "Kernel crash reporter could not be installed; crash capture is unavailable"
            );
            None
        }
    };
    observe_entrypoint(EntrypointStage::Startup);
    let options = match startup_binding::parse_launch_options(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    observe_entrypoint(EntrypointStage::LaunchConfig);
    #[cfg(windows)]
    let startup_binding = match startup_binding::KernelStartupBinding::from_environment() {
        Ok(binding) => binding,
        Err(error) => exit_error("PRINCIPAL_FAILURE", &error),
    };
    #[cfg(windows)]
    let profile_root_leases =
        match startup_binding::retain_profile_root_binding(&options, &startup_binding) {
            Ok(leases) => leases,
            Err(error) => exit_error("PRINCIPAL_FAILURE", &error),
        };
    #[cfg(windows)]
    let (supervision_profile, portable_dev_repository_root) = startup_binding
        .supervision_profile_binding(profile_root_leases.as_ref())
        .unwrap_or_else(|error| exit_error("PRINCIPAL_FAILURE", &error));
    #[cfg(windows)]
    observe_entrypoint(EntrypointStage::HostStartupBinding);
    let authority_path = options.authority_descriptor.clone();
    let authority_contour = startup_binding::authority_contour(&options.work_root, &authority_path);
    #[cfg(windows)]
    if startup_binding.is_system_service() {
        // This fixed event records an entered startup attempt under the parsed
        // Host-selected profile. It proves neither descriptor ownership nor
        // readiness and never changes a later lifecycle validation result.
        let _ = eliot_kernel::windows_event_log::start_and_enqueue_startup();
    }
    // Issue #1836 (W1): install the shared observability runtime from the
    // roots the Host injected, before the store bootstrap, the launch
    // contract, the composition, and the front-door loop start. Best-effort
    // by the same contract as the subscriber above: a refused configuration
    // leaves the launch funnel untouched and is never turned into a startup
    // failure.
    #[cfg(windows)]
    let kernel_observability_config = observability_config(
        &startup_binding.receipt_root,
        &startup_binding.kernel_ors_root,
        &authority_contour,
    );
    #[cfg(windows)]
    let _observability =
        eliot_observability_runtime::install(&kernel_observability_config);
    #[cfg(windows)]
    let mut reporter_binding_incomplete = false;
    #[cfg(windows)]
    if let Some(reporter) = &crash_reporter {
        let runtime_profile = match supervision_profile {
            eliot_installation::InstallationProfile::SystemService => "system_service",
            eliot_installation::InstallationProfile::UserMode => "user_mode",
            eliot_installation::InstallationProfile::PortableDev => "portable_dev",
        };
        if reporter.update_runtime_profile(runtime_profile).is_err() {
            reporter_binding_incomplete = true;
        }
        match crash_context::kernel_symbol_artifact(startup_binding.admitted_symbol_binding()) {
            Ok(Some(artifact)) => {
                if reporter.update_symbol_artifact(artifact).is_err() {
                    reporter_binding_incomplete = true;
                }
            }
            Ok(None) => {}
            Err(_) => reporter_binding_incomplete = true,
        }
        if reporter_binding_incomplete {
            reporter.invalidate_runtime_context();
            tracing::warn!(
                target: "eliot::crash_reporter",
                event = "kernel_reporter_binding_incomplete",
                "Kernel crash reporter identity is incomplete; later capture will record gaps"
            );
        }
    }
    let prepared_store = match startup_binding::prepare_store_bootstrap(&options) {
        Ok(prepared) => prepared,
        Err(error) => exit_error("INVALID_STORE_BOOTSTRAP", &error),
    };
    observe_entrypoint(EntrypointStage::StoreBootstrap);
    let daemon_launch = match startup_binding::prepare_eliotd_launch(&options) {
        Ok(Some(launch)) => Some(launch),
        Ok(None) => exit_error(
            "ELIOTD_LAUNCH_CONTRACT_REQUIRED",
            "Host launch must inject the exact approved eliotd descriptor and digest",
        ),
        Err(error) => exit_error("INVALID_ELIOTD_LAUNCH", &error),
    };
    observe_entrypoint(EntrypointStage::EliotdLaunch);
    let mut kernel_config =
        KernelConfig::new(options.work_root.clone()).require_descriptor_supervision_authority();
    #[cfg(windows)]
    {
        kernel_config = kernel_config.with_supervision_installation_profile(
            supervision_profile,
            portable_dev_repository_root,
        );
    }
    #[cfg(windows)]
    let pipe_name = startup_binding.control_pipe.clone();
    #[cfg(not(windows))]
    let pipe_name = std::env::var("ELIOT_KERNEL_CONTROL_PIPE").unwrap_or_default();
    kernel_config = kernel_config.with_pipe_name(pipe_name);
    #[cfg(windows)]
    {
        let receipt_binding = EliotdReceiptRootBinding::new(
            startup_binding.receipt_root.clone(),
            startup_binding.kernel_ors_root.clone(),
            startup_binding.runtime_state_roots_digest.clone(),
            startup_binding.installation_id.clone(),
            startup_binding.approved_generation.clone(),
        )
        .unwrap_or_else(|error| exit_error("PRINCIPAL_FAILURE", &error));
        kernel_config = kernel_config.with_eliotd_receipt_binding(receipt_binding);
        // I16.10 (issue #1837): bind the periodic digest-anchor sink to the
        // Watchdog failure domain. The bound directory is the
        // installer-owned `watchdog_state_root` the Host injected with this
        // same launch contour, under the same `runtime_state_roots_digest`
        // that covers it — never a path this binary derives from its own work
        // root. `AuditAnchorBinding::new` requires an absolute, already
        // existing directory (the Kernel never creates the foreign one), and
        // `set_anchor_sink` refuses a sink inside the work root, so the
        // periodic `export_anchor` now lands where a rollback or loss of the
        // Kernel work root cannot take it (A13.8).
        let anchor_binding = AuditAnchorBinding::new(startup_binding.watchdog_state_root.clone())
            .unwrap_or_else(|error| exit_error("PRINCIPAL_FAILURE", &error.to_string()));
        kernel_config = kernel_config.with_audit_anchor_binding(anchor_binding);
    }
    if let Some(prepared) = &prepared_store {
        kernel_config = kernel_config.with_store_bootstrap(prepared.requirement.clone());
    }
    if let Some(daemon_launch) = daemon_launch {
        // I14.10 / I8.12 (#1682 W1, A7): the admitted versioned restart policy
        // for the supervised `eliotd` child travels on the Host-approved,
        // digest-bound launch descriptor that admits this launch, so the Kernel
        // reads the declaration the operator's approved profile published rather
        // than choosing one locally. This is the ONLY caller of
        // `KernelConfig::with_daemon_restart_policy`; without it the composition
        // admits no restart class and `AdmittedDaemonRestartPolicy` is always
        // absent, which is precisely the unresolved-policy gap A1 requires to be
        // named rather than hidden. An absent declaration stays absent and
        // withholds automatic restart for the child; it is never widened into an
        // unlimited budget.
        if let Some(policy) = daemon_launch.restart_policy.clone() {
            kernel_config = kernel_config.with_daemon_restart_policy(policy);
        }
        kernel_config = kernel_config.with_daemon_launch(daemon_launch);
    }
    let Some(kernel_artifact_sha256) = options.kernel_artifact_sha256.clone() else {
        exit_error(
            "KERNEL_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the independent Kernel executable digest",
        );
    };
    kernel_config = kernel_config.with_kernel_artifact_sha256(kernel_artifact_sha256);
    let Some(eliotd_descriptor_artifact_sha256) = options.daemon_sha256.clone() else {
        exit_error(
            "ELIOTD_LAUNCH_CONTRACT_REQUIRED",
            "Host launch must inject the exact eliotd descriptor file digest",
        );
    };
    kernel_config =
        kernel_config.with_eliotd_descriptor_artifact_sha256(eliotd_descriptor_artifact_sha256);
    let Some(doctor_artifact_sha256) = options.doctor_artifact_sha256.clone() else {
        exit_error(
            "DOCTOR_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the independent Doctor executable digest",
        );
    };
    kernel_config = kernel_config.with_doctor_artifact_sha256(doctor_artifact_sha256);
    let Some(doctor_executable_path) = options.doctor_executable_path.clone() else {
        exit_error(
            "DOCTOR_PATH_CONTRACT_REQUIRED",
            "Host launch must inject the exact Doctor executable path bound to the digested doctor role",
        );
    };
    kernel_config = kernel_config.with_doctor_executable_path(doctor_executable_path);
    let Some(testd_artifact_sha256) = options.testd_artifact_sha256.clone() else {
        exit_error(
            "TESTD_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the independent Testd executable digest",
        );
    };
    kernel_config = kernel_config.with_testd_artifact_sha256(testd_artifact_sha256);
    let Some(native_worker_artifact_sha256) = options.native_worker_artifact_sha256.clone() else {
        exit_error(
            "NATIVE_WORKER_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the independent native worker executable digest",
        );
    };
    kernel_config = kernel_config.with_native_worker_artifact_sha256(native_worker_artifact_sha256);
    let Some(user_broker_executable_path) = options.user_broker_executable_path.clone() else {
        exit_error(
            "USER_BROKER_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the exact User Broker executable path",
        );
    };
    let Some(user_broker_artifact_sha256) = options.user_broker_artifact_sha256.clone() else {
        exit_error(
            "USER_BROKER_ARTIFACT_CONTRACT_REQUIRED",
            "Host launch must inject the installer-approved User Broker executable digest",
        );
    };
    kernel_config = kernel_config.with_user_broker_artifact_binding(
        user_broker_executable_path,
        user_broker_artifact_sha256,
    );
    // I16.2/I16.5 (issue #1841): install the bounded-label OpenMetrics stack
    // and publish the local scrape surface. Best-effort by contract (A13.10):
    // a refused configuration is reported and the launch funnel continues, so
    // telemetry can never become a reason the Kernel refuses to run. The
    // install is placed after the authority contour is known, because the
    // installation profile is that admitted contour and not an inference.
    match eliot_kernel::execution_metrics::install_kernel_execution_metrics(
        &kernel_config,
        &authority_contour,
    ) {
        Ok(observability) => {
            observability.publish_runtime_counters();
            observe_entrypoint_with_detail(EntrypointStage::Composition, observability.describe());
        }
        Err(error) => observe_terminal_error(&error.to_string()),
    }
    #[cfg(windows)]
    if let Some(leases) = &profile_root_leases {
        leases
            .verify_stable_identity()
            .unwrap_or_else(|error| exit_error("PRINCIPAL_FAILURE", &error.to_string()));
    }
    let kernel = Arc::new(
        match KernelComposition::new_with_authority_descriptor(
            kernel_config,
            &authority_path,
            &options.authority_sha256,
            authority_contour,
        ) {
            Ok(kernel) => kernel,
            Err(error) => exit_build_error(&error),
        },
    );
    observe_entrypoint(EntrypointStage::Composition);
    #[cfg(windows)]
    if let Some(reporter) = crash_reporter {
        let retention_result = reporter.update_retention_policy(
            crash_context::incident_retention_policy(
                kernel_observability_config.rolling_log.clone(),
                &startup_binding.receipt_root,
            ),
        );
        if retention_result.is_err() {
            reporter.invalidate_runtime_context();
        }
        let attachment_result = if retention_result.is_err() || reporter_binding_incomplete {
            reporter.invalidate_runtime_context();
            None
        } else {
            Some(kernel.attach_crash_reporter(
                reporter.clone(),
                Some(startup_binding.approved_generation.clone()),
            ))
        };
        let attachment_failed = attachment_result.is_some_and(|result| result.is_err());
        if attachment_failed {
            reporter.invalidate_runtime_context();
        }
        if retention_result.is_err()
            || reporter_binding_incomplete
            || attachment_failed
        {
            tracing::warn!(
                target: "eliot::crash_reporter",
                event = "kernel_reporter_attachment_incomplete",
                "Kernel crash reporter attachment is incomplete; later capture will record gaps"
            );
        }
    }
    #[cfg(windows)]
    {
        // DISPATCH-WIRE E1 (issue #461): compose the production
        // dispatch contour with the principal from the authenticated Host
        // startup binding (the installation identity — never a
        // request-envelope value). This answers the #1467 residual of zero
        // production callers: the testd/native admit sides go live here.
        // The 24-value contour now carries the installed
        // doctor/testd/native-worker digests (fail-closed above, threaded
        // through `KernelConfig` with no defaults), so all three sides
        // compose here: the Doctor side through
        // `compose_production_doctor_front_door` (durable
        // `KernelDoctorRecoveryLedger` plus
        // `DoctorRecipeRegistry::production_health_probe`), and the testd
        // plus native-worker sides through
        // `compose_production_testd_front_door` /
        // `compose_production_native_worker_front_door` (verified installed
        // digests recorded on the contour; testd admission stays stateless
        // and native admission stays with live service plus the ORS claim
        // table). A malformed installed digest on any side keeps its
        // advertisement fail-closed instead of composing.
        if let Err(error) = compose_dispatch_contour(startup_binding.installation_id.clone()) {
            exit_error("DISPATCH_COMPOSITION_FAILURE", &error.to_string());
        }
        let Some(doctor_digest) = options.doctor_artifact_sha256.clone() else {
            exit_error(
                "DOCTOR_ARTIFACT_CONTRACT_REQUIRED",
                "Host launch must inject the independent Doctor executable digest",
            );
        };
        let doctor_ledger = Arc::new(
            KernelDoctorRecoveryLedger::open(&options.work_root)
                .unwrap_or_else(|error| exit_error("DOCTOR_LEDGER_FAILURE", &error.to_string())),
        );
        if let Err(error) = compose_production_doctor_front_door(doctor_ledger, &doctor_digest) {
            exit_error("DISPATCH_COMPOSITION_FAILURE", &error.to_string());
        }
        let Some(testd_digest) = options.testd_artifact_sha256.clone() else {
            exit_error(
                "TESTD_ARTIFACT_CONTRACT_REQUIRED",
                "Host launch must inject the independent Testd executable digest",
            );
        };
        if let Err(error) = compose_production_testd_front_door(&testd_digest) {
            exit_error("DISPATCH_COMPOSITION_FAILURE", &error.to_string());
        }
        let Some(native_worker_digest) = options.native_worker_artifact_sha256.clone() else {
            exit_error(
                "NATIVE_WORKER_ARTIFACT_CONTRACT_REQUIRED",
                "Host launch must inject the independent native worker executable digest",
            );
        };
        if let Err(error) = compose_production_native_worker_front_door(&native_worker_digest) {
            exit_error("DISPATCH_COMPOSITION_FAILURE", &error.to_string());
        }
    }
    #[cfg(windows)]
    observe_entrypoint(EntrypointStage::DispatchComposition);
    if !kernel.process_execution_configured() {
        exit_error(
            "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the external process authority handoff before Kernel readiness",
        );
    }
    observe_entrypoint(EntrypointStage::ProcessAuthority);
    if kernel.supervision_lease_authority().is_none() {
        exit_error(
            "SUPERVISION_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the installer-provisioned supervision authority before Kernel readiness",
        );
    }
    observe_entrypoint(EntrypointStage::SupervisionAuthority);
    #[cfg(windows)]
    observe_entrypoint(EntrypointStage::FrontDoorLoop);
    #[cfg(windows)]
    front_door_driver::run_front_door_loop(Arc::clone(&kernel), &startup_binding).await;
    #[cfg(not(windows))]
    {
        let _ = kernel;
        exit_error(
            "AUTHENTICATED_CONTROL_UNSUPPORTED",
            "Host/Kernel control requires the Windows authenticated named-pipe boundary",
        );
    }
    match kernel.shutdown().await {
        Ok(outcome) if outcome.no_orphans => {
            observe_entrypoint(EntrypointStage::ShutdownDrain);
        }
        Ok(outcome) => exit_error(
            "SHUTDOWN_INCOMPLETE",
            &format!("runtime shutdown outcome: {outcome:?}"),
        ),
        Err(error) => exit_error("SHUTDOWN_FAILURE", &error.to_string()),
    }
}

pub(crate) fn exit_build_error(error: &KernelBuildError) -> ! {
    exit_error("COMPOSITION_FAILURE", &error.to_string())
}

pub(crate) fn exit_error(code: &str, detail: &str) -> ! {
    // F-LOG-KERNEL-0 (#895): the single terminal error boundary. One
    // underlying failed operation yields exactly one terminal diagnostic
    // record here; receipt framing and the exit below are unchanged.
    // W6 correlation is single-funnel adjacency: a lower phase emits its
    // one correlated observation (e.g. the fenced listener bind) and this
    // funnel emits the one terminal record. No op identity is threaded
    // through `KernelBuildError` by design.
    observe_terminal_error(code);
    write_error(code, detail);
    std::process::exit(1);
}

pub(crate) fn write_error(code: &str, detail: &str) {
    // F-LOG-KERNEL-0 (#895 W2): no-event reason — stderr is the terminal
    // sink itself, so a failed write here is unobservable by design and,
    // per W5, must not fail the process. No behavior change.
    let _ = writeln!(
        io::stderr().lock(),
        "{{\"error\":\"{code}\",\"detail\":{detail:?}}}"
    );
}
