#![forbid(unsafe_code)]

//! Governed one-shot Doctor composition root.
//!
//! Argument and config decoding, authenticated Kernel bootstrap, one-shot
//! lifecycle, typed shutdown, and terminal receipt projection live here.
//! Deterministic mechanics live in the owner crates (`eliot-doctor-core`
//! for the closed contract, `eliot-process` for the governed contour); the
//! single narrow adapter lives in the adjacent `admitted_effect` module.
//! This root never launches a native process directly, never accepts
//! recipe or effect authority from argv, stdin, or environment, and never
//! claims a repair: without a Kernel-issued admission it exits 78.

use std::io::Write as _;

use eliot_doctor::admitted_effect::{
    BootstrapAction, EXIT_EVIDENCE_FLUSH_FAILED, EXIT_KERNEL_ADMISSION_REQUIRED,
    UnadvertisedKernelClient, admission_required_line, decode_bootstrap_args, help_text,
    version_line,
};
use eliot_doctor_core::KernelDoctorClient;

fn main() {
    std::process::exit(run(&std::env::args().collect::<Vec<String>>()));
}

fn run(argv: &[String]) -> i32 {
    match decode_bootstrap_args(argv) {
        Ok(BootstrapAction::Help) => emit_text(&help_text()),
        Ok(BootstrapAction::Version) => emit_text(&version_line()),
        Ok(BootstrapAction::Run(_)) => bootstrap_and_run_once(),
        Err(error) => {
            deny(&error.to_string());
            error.exit_code()
        }
    }
}

fn emit_text(text: &str) -> i32 {
    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{text}") {
        Ok(()) => match stdout.flush() {
            Ok(()) => 0,
            Err(_) => EXIT_EVIDENCE_FLUSH_FAILED,
        },
        Err(_) => EXIT_EVIDENCE_FLUSH_FAILED,
    }
}

fn deny(detail: &str) -> i32 {
    let line = admission_required_line(detail);
    let _ = writeln!(std::io::stderr(), "{line}");
    EXIT_KERNEL_ADMISSION_REQUIRED
}

fn bootstrap_and_run_once() -> i32 {
    // Authenticated generation-bound Kernel bootstrap. The admission
    // channel itself is Slice 2 owned, so today this resolves only the
    // advertisement check through the trait abstraction: unadvertised
    // exits 78 without effect, and an advertised-but-unbound channel
    // would do the same rather than invent an admission path.
    let mut client = UnadvertisedKernelClient::current();
    match client.advertise_doctor() {
        Ok(true) => deny(
            "kernel advertises the doctor operation but no authenticated admission channel is bound into this process",
        ),
        Ok(false) => deny("kernel does not advertise the doctor operation"),
        Err(error) => deny(&error.to_string()),
    }
}
