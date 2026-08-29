use std::io::{self, Write};

use eliot_testd::{PROTOCOL_VERSION, SERVICE_NAME};

const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;
const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const OPERATION: &str = "eliot.instrument.test.execute";

fn main() {
    // The current Kernel does not advertise the Testd execution operation.
    // Do not open an ambient cwd/env-selected state file, accept stdin as an
    // authority surface, or advertise readiness before an authenticated
    // Kernel handshake and one-shot ProcessRequest provider exist.
    let _ = writeln!(io::stderr(), "{}", admission_required_message());
    std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);
}

fn admission_required_message() -> String {
    format!(
        "{KERNEL_ADMISSION_REQUIRED}: service={SERVICE_NAME} protocol={PROTOCOL_VERSION} operation={OPERATION}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_diagnostic_is_stable_and_never_claims_ready() {
        let message = admission_required_message();
        assert_eq!(
            message,
            "KERNEL_ADMISSION_REQUIRED: service=eliot-testd protocol=eliot.testd.v2 operation=eliot.instrument.test.execute"
        );
        assert!(!message.to_ascii_lowercase().contains("ready"));
        assert_ne!(EXIT_KERNEL_ADMISSION_REQUIRED, 0);
    }
}
