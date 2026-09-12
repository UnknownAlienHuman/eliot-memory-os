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
use std::sync::Arc;

use eliot_kernel::{EliotdReceiptRootBinding, KernelBuildError, KernelComposition, KernelConfig};

#[cfg(windows)]
mod front_door_driver;
mod startup_binding;

/// Keeps startup, authenticated listener rotation, and fenced shutdown in one
/// ordered authority path.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    let options = match startup_binding::parse_launch_options(std::env::args_os().skip(1)) {
        Ok(options) => options,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    #[cfg(windows)]
    let startup_binding = match startup_binding::KernelStartupBinding::from_environment() {
        Ok(binding) => binding,
        Err(error) => exit_error("PRINCIPAL_FAILURE", &error),
    };
    let prepared_store = match startup_binding::prepare_store_bootstrap(&options) {
        Ok(prepared) => prepared,
        Err(error) => exit_error("INVALID_STORE_BOOTSTRAP", &error),
    };
    let daemon_launch = match startup_binding::prepare_eliotd_launch(&options) {
        Ok(Some(launch)) => Some(launch),
        Ok(None) => exit_error(
            "ELIOTD_LAUNCH_CONTRACT_REQUIRED",
            "Host launch must inject the exact approved eliotd descriptor and digest",
        ),
        Err(error) => exit_error("INVALID_ELIOTD_LAUNCH", &error),
    };
    let mut kernel_config =
        KernelConfig::new(options.work_root.clone()).require_descriptor_supervision_authority();
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
    }
    if let Some(prepared) = &prepared_store {
        kernel_config = kernel_config.with_store_bootstrap(prepared.requirement.clone());
    }
    if let Some(daemon_launch) = daemon_launch {
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
    let authority_path = options.authority_descriptor.clone();
    let authority_contour = startup_binding::authority_contour(&options.work_root, &authority_path);
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
    if !kernel.process_execution_configured() {
        exit_error(
            "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the external process authority handoff before Kernel readiness",
        );
    }
    if kernel.supervision_lease_authority().is_none() {
        exit_error(
            "SUPERVISION_AUTHORITY_CONFIGURATION_REQUIRED",
            "Host/installation must inject the installer-provisioned supervision authority before Kernel readiness",
        );
    }
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
        Ok(outcome) if outcome.no_orphans => {}
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
    write_error(code, detail);
    std::process::exit(1);
}

pub(crate) fn write_error(code: &str, detail: &str) {
    let _ = writeln!(
        io::stderr().lock(),
        "{{\"error\":\"{code}\",\"detail\":{detail:?}}}"
    );
}
