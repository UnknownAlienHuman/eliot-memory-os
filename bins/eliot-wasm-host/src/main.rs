#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_wasm_host::{
    CliError, TypedWorld, default_experimental_limits, execute_describe_experimental, parse_args,
    read_bounded_artifact,
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

    let _ = config.transport;
    let _ = config.profile;
    emit_error(
        "KERNEL_ADMISSION_REQUIRED",
        "Kernel RuntimePorts, admitted artifact, authenticated request loop, and live service are not bound",
    );
    std::process::exit(ADMISSION_REQUIRED_EXIT);
}
