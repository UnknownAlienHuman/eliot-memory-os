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
    EntrypointStage, bound_detail, observability_install_refused_code, observe_entrypoint,
    observe_entrypoint_with_detail, observe_observability_install_refused, observe_terminal_error,
};
// F-LOG-KERNEL-0 (#895): the facade install and the projection of the accepted
// owner's real outcome are reached only where the observability owner can
// produce one (the Windows launch contour below), so both imports are gated
// with their only call site. There is no second, private subscriber behind them
// on any target.
#[cfg(windows)]
use eliot_kernel::kernel_diagnostics::{DiagnosticSubscriberOwner, install_kernel_diagnostics};
use eliot_kernel::{
    AuditAnchorBinding, EliotdReceiptRootBinding, KernelBuildError, KernelComposition,
    KernelConfig, KernelDoctorRecoveryLedger, ProcessCapacityReserveComposition,
    compose_dispatch_contour, compose_process_capacity_reserve_from_profile,
    compose_production_doctor_front_door, compose_production_native_worker_front_door,
    compose_production_testd_front_door,
};
use eliot_observability_runtime::{
    ObservabilityConfig, RollingLogPolicy, RuntimeProfile, SpoolPolicy,
};

#[cfg(windows)]
mod front_door_driver;
mod startup_binding;

/// Stable operational-log stem for this process. The generation name carries
/// the exit code, so a fresh process start is distinguishable from a rolling
/// rotation without any second naming scheme.
const OPERATIONAL_LOG_STEM: &str = "eliot-kernel";

/// Bounded operational-log generation size, in bytes.
///
/// I16.2/I16.9 make the operational log a rolling, non-authoritative surface,
/// and the crate's own declared ceiling for one generation is
/// `MAX_ROLLING_BYTES` (`eliot-observability-runtime::config`). The Kernel is
/// the busiest shipped surface, so it runs at the declared ceiling rather than
/// a smaller private number.
const OPERATIONAL_LOG_GENERATION_BYTES: u64 =
    eliot_observability_runtime::config::MAX_ROLLING_BYTES;

/// Bounded operational-log generation count, at the same declared ceiling.
const OPERATIONAL_LOG_GENERATIONS: u32 =
    eliot_observability_runtime::config::MAX_ROLLING_GENERATIONS;

/// Bounded writer-queue depth, in records, before admission starts dropping and
/// the visible dropped-records gauge advances (I16.11 forbids hidden loss), at
/// the crate's own declared ceiling.
const OPERATIONAL_LOG_QUEUED_RECORDS: usize =
    eliot_observability_runtime::config::MAX_ROLLING_QUEUED_RECORDS;

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
        rolling_log: RollingLogPolicy {
            directory: receipt_root.join("logs"),
            file_stem: OPERATIONAL_LOG_STEM.to_owned(),
            max_bytes_per_generation: OPERATIONAL_LOG_GENERATION_BYTES,
            max_generations: OPERATIONAL_LOG_GENERATIONS,
            max_buffered_records: OPERATIONAL_LOG_QUEUED_RECORDS,
            exit_code: 0,
        },
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
    // F-LOG-KERNEL-0 (#895): the one process-global `tracing` subscriber owner
    // in this process is `eliot_observability_runtime::install` (issue #1836),
    // not this binary. The facade no longer performs any `try_init` of its own;
    // it is told the real owner outcome once that owner answered, below, so
    // two components can never both claim the one global subscriber.
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
    // by the same contract as the diagnostics below: a refused configuration
    // leaves the launch funnel untouched and is never turned into a startup
    // failure.
    //
    // F-LOG-KERNEL-0 (#895): this is the first and only process-global
    // subscriber attempt, so the facade is told the real owner outcome
    // immediately after it instead of preempting it. A refused configuration
    // produces no owner outcome at all, and the facade is simply not installed
    // on that path rather than being handed a fabricated one.
    //
    // The facade emits through the owner this process already established; it
    // never installs a competing subscriber. Its answer is non-gating by
    // contract: both the first install and an `AlreadyInstalled` re-init
    // continue into the launch funnel and neither result exits the process.
    // Protocol stdout is untouched.
    //
    // Non-Windows targets install no observability owner at all, so there is no
    // real outcome to project there and no facade install either; that target is
    // not a first-line supported one (I1.7) and its funnel still terminates
    // through the single `exit_error` boundary.
    #[cfg(windows)]
    let _observability = match eliot_observability_runtime::install(&observability_config(
        &startup_binding.receipt_root,
        &startup_binding.kernel_ors_root,
        &authority_contour,
    )) {
        Ok(outcome) => {
            let _ = install_kernel_diagnostics(DiagnosticSubscriberOwner::observed(&outcome));
            Some(outcome)
        }
        // A refused configuration is not a startup failure: there is no
        // accepted owner outcome to project, so the facade is not installed
        // and the funnel continues exactly as before.
        Err(_) => None,
    };
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
        let (supervision_profile, portable_dev_repository_root) = startup_binding
            .supervision_profile_binding(profile_root_leases.as_ref())
            .unwrap_or_else(|error| exit_error("PRINCIPAL_FAILURE", &error));
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
        // F-LOG-KERNEL-0 (#895): a refused observability install is documented
        // as never gating startup, so it is a non-terminal degraded observation
        // carrying one fixed owner-issued static code, projected from the typed
        // error by the facade's single owner of that vocabulary. The owner
        // requires that "only `exit_error` may emit the process terminal
        // record", so this arm emits no terminal record at all: it can no
        // longer produce the second `kernel.terminal_error` for one launch
        // attempt that defect 4 named, and the code is never the failure's
        // `Display` prose. Within this entrypoint funnel `exit_error` is
        // therefore the sole terminal emitter; the library modules keep their
        // own per-operation terminal records and stay the deferred leaves'
        // scope. The arm still falls through into composition and the
        // front-door launch.
        Err(error) => {
            observe_observability_install_refused(observability_install_refused_code(error));
        }
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
        // DISPATCH-WIRE (issue #1679 W11/W4): compose the contour-owned
        // process-capacity reserve from the composition's own compiled
        // control-reserve profile. Bounds come only from the profile's
        // claimed process rows — nothing is invented here. An
        // unestablished profile skips fail-closed (the defined
        // Uncomposed path: dispatch carries no capacity section and the
        // consumer refuses fail-closed); a miscomposed bound fails the
        // launch instead of issuing under a guess.
        match compose_process_capacity_reserve_from_profile(kernel.control_reserve_profile()) {
            Ok(
                ProcessCapacityReserveComposition::Composed
                | ProcessCapacityReserveComposition::SkippedUnestablished,
            ) => {}
            Err(error) => exit_error("DISPATCH_COMPOSITION_FAILURE", &error.to_string()),
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
    //
    // F-LOG-KERNEL-0 (#895 residual): `detail` reaches this funnel as a whole
    // error `Display` string, so it is bound here — once, at the only in-file
    // lever — through the facade's existing detail owner, `bound_detail`. No
    // second bound, truncation scheme or validator is introduced here; the raw
    // protected evidence stays with its owner. The receipt shape (`error`,
    // `detail`), the escaped `{:?}` string form, the stderr write and its
    // deliberately ignored result are unchanged.
    //
    // WHICH limit actually binds here, measured rather than assumed: the shared
    // telemetry field policy screens any value longer than
    // `MAX_LABEL_VALUE_CHARS` (256 characters) to an immutable redacted
    // evidence handle, and that threshold is reached first, so at this call
    // site the POLICY is the operative limit and the detail is redacted rather
    // than truncated. `MAX_DIAGNOSTIC_DETAIL_BYTES` (1024) is the owner's
    // ceiling and `bound_detail` still applies it, but this funnel never
    // reaches it. Both are the existing owner's; neither is redefined here.
    let bounded = bound_detail(detail);
    let bounded_detail = bounded.text();
    let _ = writeln!(
        io::stderr().lock(),
        "{{\"error\":\"{code}\",\"detail\":{bounded_detail:?}}}"
    );
}

/// F-LOG-KERNEL-0 (#895) private inline proof for the two entrypoint-funnel
/// diagnostics this binary owns.
///
/// `exit_error` and `write_error` are `pub(crate)` items of a binary target, so
/// no file under `tests/` can reach them; this module is the only honest place
/// to prove the refused-install code mapping and the bounded receipt detail. It
/// asserts through the facade's exported owners and the pinned contract fixture
/// rather than restating their vocabulary, so nothing here can drift into a
/// second refusal code, a second bound, or a second validator.
#[cfg(test)]
mod entry_funnel_diagnostics_tests {
    use eliot_kernel::execution_metrics::KernelObservabilityError;
    use eliot_kernel::kernel_diagnostics::{
        MAX_DIAGNOSTIC_DETAIL_BYTES, bound_detail, observability_install_refused_code,
    };

    /// The pinned #895 contract fixture, compiled in so this proof and the
    /// fixture can never drift apart silently.
    const CONTRACT_FIXTURE: &str = include_str!("../tests/data/kernel_diagnostics_contract.json");

    /// A refused metrics install records one fixed non-terminal code and never
    /// a terminal record; the codes are the pinned static vocabulary, not the
    /// failure's own `Display` prose.
    #[test]
    fn refused_observability_install_maps_to_the_pinned_static_codes() {
        let Ok(contract) = serde_json::from_str::<serde_json::Value>(CONTRACT_FIXTURE) else {
            panic!("the pinned kernel diagnostics contract fixture must parse");
        };
        let Some(pinned) = contract
            .get("observability_refusal_codes")
            .and_then(serde_json::Value::as_object)
        else {
            panic!("the pinned contract fixture must carry observability_refusal_codes");
        };

        for (variant_path, variant) in [
            (
                "KernelObservabilityError::Config",
                KernelObservabilityError::Config,
            ),
            (
                "KernelObservabilityError::EndpointNotLoopback",
                KernelObservabilityError::EndpointNotLoopback,
            ),
        ] {
            let Some(expected) = pinned.get(variant_path).and_then(serde_json::Value::as_str)
            else {
                panic!("the pinned contract fixture must pin {variant_path}");
            };
            let code = observability_install_refused_code(variant);
            assert_eq!(
                code, expected,
                "the Rust mapping and the pinned fixture must agree for {variant_path}"
            );
            // A code is fixed vocabulary, never a failure rendering: no
            // whitespace and no lowercase word can come from `Display`, so
            // neither typed variant can project prose as its code.
            assert!(
                !code.chars().any(char::is_whitespace),
                "{variant_path} must project a whitespace-free code"
            );
            assert!(
                !code.chars().any(char::is_lowercase),
                "{variant_path} must project an upper-case code"
            );
            assert_ne!(
                code,
                variant.to_string(),
                "{variant_path} must never project its own Display rendering"
            );
        }

        // A refused observability install is not the terminal event, and this
        // funnel's one terminal record comes from `exit_error` alone. That is
        // asserted against PRODUCTION SOURCE below, not against the pinned
        // fixture: two strings read out of the fixture compare the fixture with
        // itself, so no mutation of this crate - a refusal that starts emitting
        // a terminal record, a moved call site, an emptied body - could ever
        // turn them red.
        let source = include_str!("main.rs");
        // The needle is assembled at compile time so this assertion cannot
        // match its own literal in the source it scans.
        let terminal_call = concat!("observe_terminal_error", "(");
        // Uniqueness alone proves nothing about POSITION: moving the call from
        // `exit_error` into `write_error` would keep the count at 1 and make
        // every non-terminal driver failure emit a terminal record. So slice
        // the two function bodies out of this file's own source and require the
        // call to sit inside the designated boundary and nowhere else.
        let exit_error_body = function_body(source, "pub(crate) fn exit_error");
        let write_error_body = function_body(source, "pub(crate) fn write_error");
        assert!(
            exit_error_body.contains(terminal_call),
            "`exit_error` is the designated terminal boundary and must emit the record"
        );
        assert!(
            !write_error_body.contains(terminal_call),
            "`write_error` is not a terminal boundary and must never emit a terminal record"
        );

        // The refusal emitter is held to the same contract, in its OWN owner's
        // source. It does not live in this file: `main.rs` only imports and
        // calls it, so scanning this file's source can never see a regression
        // that adds a terminal record inside the facade function that emits
        // `kernel.observability_install_refused`.
        let refusal_source = include_str!("kernel_diagnostics.rs");
        let refusal_body = function_body(
            refusal_source,
            "pub fn observe_observability_install_refused",
        );
        // The needle is the BARE emitter name, not the call form: the facade
        // also owns `observe_terminal_error_in_context`, and a needle ending at
        // `(` would miss a terminal emission made through that variant. The
        // function's own doc comment is above its signature, so it is outside
        // the sliced body and cannot produce a false positive here.
        let terminal_name = concat!("observe_terminal", "_error");
        assert!(
            !refusal_body.contains(terminal_name),
            "a refused install is non-terminal: its emitter must not emit a terminal record"
        );
        // The positive, so the negative above cannot be satisfied by a body
        // that is empty, stubbed or deleted: the emitter must still make the
        // one degraded observation it exists to make.
        let refusal_warn = concat!("tracing::warn", "!");
        assert!(
            refusal_body.contains(refusal_warn),
            "the refusal emitter must still emit its own non-terminal observation"
        );
    }

    /// The stderr receipt detail is bounded by the facade's existing owner, so
    /// no whole-error `Display` string reaches the operational surface.
    #[test]
    fn terminal_receipt_detail_is_bounded_by_the_facade_owner() {
        let in_bound = "launch descriptor digest mismatch";
        let admitted = bound_detail(in_bound);
        assert_eq!(
            admitted.text(),
            in_bound,
            "an in-bound detail must pass through byte-identical"
        );
        assert!(!admitted.truncated());
        assert!(admitted.redaction_status().is_none());
        assert_eq!(admitted.original_bytes(), in_bound.len());

        let oversized = "x".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
        let screened = bound_detail(&oversized);
        assert!(
            screened.text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
            "the emitted detail must stay inside the owner's byte bound"
        );
        assert!(
            !screened.text().contains('x'),
            "no fragment of the oversized detail may reach the operational surface"
        );
        // Screening is first and fail-closed in the shared field policy, so an
        // over-long detail becomes an immutable evidence handle rather than a
        // truncated prefix: nothing of the input survives, while the honesty
        // record keeps the byte length that was actually presented.
        assert!(
            screened.redaction_status().is_some(),
            "the shared field policy must screen an over-long detail to a handle"
        );
        assert!(
            !screened.truncated(),
            "a screened detail never reaches the bounding path"
        );
        assert_eq!(screened.original_bytes(), oversized.len());

        let source = include_str!("main.rs");
        // Proving that `bound_detail` is CALLED proves nothing about what the
        // receipt actually emits: the bound value can be computed, bound to an
        // unused local, and the raw `Display` detail interpolated anyway. So
        // pin the emitting line itself - the receipt must interpolate the
        // BOUND value and must no longer interpolate the raw one.
        let write_error_body = function_body(source, "pub(crate) fn write_error");
        let raw_detail = concat!("{detail", ":?}");
        // The emitting literal is matched as TEXT in the scanned source, so the
        // needle is assembled at compile time; naming `bounded_detail` in a
        // format! here would look the variable up in this test, not in the
        // slice being scanned.
        let bounded_detail_interpolation = concat!("{bounded_detail", ":?}");
        assert!(
            !write_error_body.contains(raw_detail),
            "the terminal receipt must not interpolate the raw `Display` detail"
        );
        assert!(
            write_error_body.contains(bounded_detail_interpolation),
            "the terminal receipt must interpolate the BOUND detail value"
        );
    }

    /// Returns one function's body by slicing its owner's source between its
    /// signature and the EARLIEST boundary that follows it: the start of the
    /// next top-level item - a free `fn`, a `pub fn`, a `pub(crate) fn`, or any
    /// attribute line such as `#[must_use]`, `#[cfg(test)]` or the `#[test]`
    /// block this module ends with.
    ///
    /// The attribute boundary is load-bearing, not decoration: a LAST
    /// top-level item has no next `fn` to stop at, so without it the slice ran
    /// to end-of-file and swallowed `#[cfg(test)] mod
    /// entry_funnel_diagnostics_tests` - the very text these assertions scan,
    /// which would let a future needle match the assertion that uses it. It
    /// also keeps the NEXT item's doc comment out of this item's body, so a
    /// neighbouring doc that merely names an emitter cannot turn a negative
    /// assertion red.
    ///
    /// The needles used against the result are assembled with `concat!` by the
    /// caller, so an assertion can never match its own literal in the text it
    /// scans.
    fn function_body(source: &str, signature: &str) -> String {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} must be declared in this file"));
        let rest = &source[start..];
        let end = ["\nfn ", "\npub fn ", "\npub(crate) fn ", "\n#["]
            .iter()
            .copied()
            .filter_map(|boundary| rest.find(boundary))
            .min()
            .unwrap_or(rest.len());
        rest[..end].to_owned()
    }
}
