#![forbid(unsafe_code)]

use std::io::{self, Write};

const SERVICE_NAME: &str = "eliot-mod-research";
const PROTOCOL_VERSION: &str = "eliot.research.provider.v1";
const OPERATION: &str = "eliot.research.provider.execute";
const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;

fn main() {
    // The standalone process has no authenticated Governor owner or
    // Kernel-issued provider admission. It therefore never accepts a request
    // file, reconstructs a task snapshot, or contacts a bridge speculatively.
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
    fn standalone_diagnostic_is_stable_and_never_claims_readiness() {
        let message = admission_required_message();
        assert_eq!(
            message,
            "KERNEL_ADMISSION_REQUIRED: service=eliot-mod-research protocol=eliot.research.provider.v1 operation=eliot.research.provider.execute"
        );
        assert!(!message.to_ascii_lowercase().contains("ready"));
        assert_ne!(EXIT_KERNEL_ADMISSION_REQUIRED, 0);
    }
}
