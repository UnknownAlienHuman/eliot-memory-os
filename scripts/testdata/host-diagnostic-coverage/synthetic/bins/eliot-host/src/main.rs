//! Synthetic Host binary entry (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the one binary contour that installs the single
//! process subscriber and owns the exactly-one console terminal emission.

use eliot_host::host_console::admit_console_request;

fn main() {
    eliot_host::host_diagnostics::install_host_diagnostics();
    let request = std::env::args().nth(1).unwrap_or_default();
    match admit_console_request(&request) {
        Ok(_) => {}
        Err(_) => {
            eliot_host::host_diagnostics::observe_terminal_error(
                eliot_host::host_diagnostics::HOST_TERMINAL_CODE_CONSOLE_FAILED,
            );
            std::process::exit(2);
        }
    }
}
