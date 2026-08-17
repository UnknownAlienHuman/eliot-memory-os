use std::io::{self, Write};

use eliot_wasm_host::{CliError, parse_args};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const ADMISSION_REQUIRED_EXIT: i32 = 1;

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

    let _ = config;
    emit_error(
        "KERNEL_ADMISSION_REQUIRED",
        "Kernel RuntimePorts, admitted artifact, authenticated request loop, and live service are not bound",
    );
    std::process::exit(ADMISSION_REQUIRED_EXIT);
}
