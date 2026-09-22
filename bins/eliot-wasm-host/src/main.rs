#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_wasm_host::{
    CliError, GrantLaunchArgs, TypedWorld, default_experimental_limits, drive_dispatch,
    execute_describe_experimental, parse_args, read_bounded_artifact, resolve_kernel_port_grant,
    run_grant_launch, run_guest_exec,
};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const ADMISSION_REQUIRED_EXIT: i32 = 1;

fn emit_error(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
}

fn emit_receipt(fields: &[(&str, &str)]) {
    let mut stdout = io::stdout().lock();
    let mut first = true;
    let _ = write!(stdout, "{{");
    for (key, value) in fields {
        if !first {
            let _ = write!(stdout, ",");
        }
        first = false;
        let _ = write!(stdout, "\"{key}\":\"{value}\"");
    }
    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "}}");
}

fn emit_stderr_receipt(fields: &[(&str, &str)]) {
    let mut stderr = io::stderr().lock();
    let mut first = true;
    let _ = write!(stderr, "{{");
    for (key, value) in fields {
        if !first {
            let _ = write!(stderr, ",");
        }
        first = false;
        let _ = write!(stderr, "\"{key}\":\"{value}\"");
    }
    let _ = writeln!(stderr);
    let _ = writeln!(stderr, "}}");
}

/// Runs the owner-dispatched parent drive branch: exactly one admitted
/// operation to the canonical response. Returns true when a dispatch file
/// was staged (success emitted, raw guest bytes on stdout, receipt on
/// stderr); false on absence so the caller falls through to CLI modes.
/// Any other denial exits the process fail-closed.
fn run_dispatch_drive_branch() -> bool {
    use eliot_wasm_host::DriveError;
    match drive_dispatch() {
        Ok(response) => {
            let _ = io::stdout().lock().write_all(&response.output);
            let output_bytes = response.output.len().to_string();
            let fuel = response.fuel_consumed.to_string();
            let peak = response.peak_memory_bytes.to_string();
            let tables = response.table_elements.to_string();
            let ticks = response.epoch_ticks.to_string();
            emit_stderr_receipt(&[
                ("status", "dispatch-drive-complete"),
                ("operation", &response.operation_id),
                ("component", &response.component_id),
                ("artifact_digest", &response.artifact_digest),
                ("input_digest", &response.input_digest),
                ("host_artifact_digest", &response.host_artifact_digest),
                ("output_digest", &response.output_digest),
                ("output_bytes", &output_bytes),
                ("fuel_consumed", &fuel),
                ("peak_memory_bytes", &peak),
                ("table_elements", &tables),
                ("epoch_ticks", &ticks),
            ]);
            true
        }
        Err(DriveError::NoMaterial) => false,
        Err(error) => {
            emit_error("DISPATCH_DRIVE_DENIED", &error.to_string());
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
    }
}

/// Runs the governed grant-launch branch: full pipeline, staged receipt on
/// stdout on success, stage-taxonomy denial on stderr otherwise. Returns on
/// success; exits the process on denial or argument failure upstream.
fn run_grant_launch_branch(grant: &GrantLaunchArgs) {
    match run_grant_launch(grant) {
        Ok(receipt) => {
            let deadline = receipt.deadline_unix_ms.to_string();
            emit_receipt(&[
                ("status", "grant-launch-staged"),
                ("component", &receipt.component_id),
                ("artifact_digest", &receipt.artifact_digest),
                ("interface_digest", &receipt.interface_digest),
                ("host_artifact_digest", &receipt.host_artifact_digest),
                ("engine", &receipt.engine_implementation_id),
                ("engine_artifact_digest", &receipt.engine_artifact_digest),
                ("nonce", &receipt.nonce),
                ("deadline_unix_ms", &deadline),
            ]);
        }
        Err(error) => {
            emit_error("GRANT_LAUNCH_DENIED", &error.to_string());
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
    }
}

fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            let (code, detail) = match error {
                CliError::MissingProfile => ("MISSING_PROFILE", "--profile is required".to_owned()),
                CliError::UnsupportedProfile(profile) => ("UNSUPPORTED_PROFILE", profile),
                CliError::MalformedArgument(argument) => ("MALFORMED_ARGUMENT", argument),
                CliError::RemoteTransportForbidden(transport) => {
                    ("REMOTE_TRANSPORT_FORBIDDEN", transport)
                }
                CliError::MissingExperimentalComponent => (
                    "MISSING_EXPERIMENTAL_COMPONENT",
                    "--world requires --experimental-typed-component".to_owned(),
                ),
                CliError::MissingExperimentalWorld => (
                    "MISSING_EXPERIMENTAL_WORLD",
                    "--experimental-typed-component requires --world".to_owned(),
                ),
                CliError::UnknownWorld(world) => ("UNKNOWN_WORLD", world),
            };
            emit_error(code, &detail);
            std::process::exit(INVALID_ARGUMENT_EXIT);
        }
    };

    // One-shot P03-admitted guest execution: the reaped child runs the
    // admitted guest inside containment and emits raw output bytes on
    // stdout. This branch runs before anything else once parsed: no
    // experimental describe, no grant path, and no other output may
    // contaminate stdout.
    if let Some(guest) = &config.guest_exec {
        std::process::exit(run_guest_exec(guest));
    }

    // Owner-dispatched parent drive: a staged dispatch file beside this
    // image means the Kernel admitted exactly one operation. The reaped
    // child runs the guest; this branch reaps it and emits the canonical
    // response (raw guest bytes on stdout, receipt on stderr). Absence
    // falls through to the CLI modes below. Guest-exec stays first so a
    // reaped child never drives as a parent.
    if run_dispatch_drive_branch() {
        return;
    }

    // Governed grant launch: the dedicated executable consumer path. Runs
    // the full pipeline — channel binding, bundle from real bytes,
    // authenticated transport request, descriptor authorization, installed
    // binary resolution, engine staging — and emits the staged receipt on
    // success. Every denial stays fail-closed with a stage-taxonomy code.
    if let Some(grant) = &config.grant_launch {
        run_grant_launch_branch(grant);
    }

    if let (Some(component_path), Some(world_name)) = (
        config.experimental_typed_component,
        config.experimental_world,
    ) {
        let Some(world) = TypedWorld::parse(&world_name) else {
            emit_error("UNKNOWN_WORLD", &world_name);
            std::process::exit(INVALID_ARGUMENT_EXIT);
        };
        let (artifact, preflight) = match read_bounded_artifact(&component_path) {
            Ok(pair) => pair,
            Err(error) => {
                emit_error("PREFLIGHT_DENIED", &error.to_string());
                std::process::exit(ADMISSION_REQUIRED_EXIT);
            }
        };
        let limits = default_experimental_limits(preflight.digest.clone());
        match execute_describe_experimental(world, &artifact, &limits) {
            Ok((receipt, descriptor)) => {
                let output_bytes = receipt.output_bytes.to_string();
                let artifact_bytes = receipt.artifact_bytes.to_string();
                let abi_revision = descriptor.abi_revision.to_string();
                let elapsed_ms = receipt.elapsed_ms.to_string();
                emit_receipt(&[
                    ("proof", &receipt.proof),
                    ("world", &receipt.world),
                    ("package", &receipt.package_id),
                    ("artifact_digest", receipt.artifact_digest.as_str()),
                    ("artifact_bytes", &artifact_bytes),
                    ("engine", &receipt.engine_version),
                    ("wit_digest", receipt.wit_digest.as_str()),
                    ("descriptor_world", &descriptor.world_name),
                    ("descriptor_package", &descriptor.package_id),
                    ("abi_revision", &abi_revision),
                    ("output_digest", receipt.output_digest.as_str()),
                    ("output_bytes", &output_bytes),
                    ("terminal", &receipt.terminal),
                    ("semantic_digest", receipt.semantic_digest.as_str()),
                    ("elapsed_ms", &elapsed_ms),
                ]);
            }
            Err(error) => {
                emit_error("TYPED_EXECUTION_DENIED", &error.to_string());
                std::process::exit(ADMISSION_REQUIRED_EXIT);
            }
        }
        return;
    }

    // No mode selected: the live governed path requires a Kernel-admitted
    // RuntimePorts grant, and no admission channel is bound here, so
    // resolution fails closed before any engine, runner, or invocation is
    // constructed. Governed work enters through `--grant-launch` above.
    match resolve_kernel_port_grant() {
        Ok(_grant) => {
            emit_error(
                "KERNEL_ADMISSION_REQUIRED",
                "admitted request loop is not bound",
            );
        }
        Err(error) => {
            emit_error("KERNEL_ADMISSION_REQUIRED", &error.to_string());
        }
    }
    std::process::exit(ADMISSION_REQUIRED_EXIT);
}
