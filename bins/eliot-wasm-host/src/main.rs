use std::io::{self, Write};

use eliot_wasm_host::{CliError, Profile, Transport, WasmHostRunner, parse_args};

const PLAN_GAP_EXIT: i32 = 78;
const INVALID_ARGUMENT_EXIT: i32 = 2;

fn emit_error(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
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
            };
            emit_error(code, &detail);
            std::process::exit(INVALID_ARGUMENT_EXIT);
        }
    };

    let runner = match WasmHostRunner::unavailable(config.profile) {
        Ok(runner) => runner,
        Err(error) => {
            emit_error("PLAN_GAP", &error.to_string());
            std::process::exit(PLAN_GAP_EXIT);
        }
    };
    let transport = match config.transport {
        Transport::Stdio => "stdio",
        Transport::Loopback => "loopback",
    };
    let detail = format!(
        "profile={} transport={} missing_provider=KernelGenerationEndpoint; concrete Wasmtime engine and provider surfaces are not admitted",
        Profile::as_str(runner.profile()),
        transport
    );
    emit_error("PLAN_GAP", &detail);
    std::process::exit(PLAN_GAP_EXIT);
}
