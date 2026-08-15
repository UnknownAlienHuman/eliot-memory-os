use std::io::{self, Write};

use eliot_watchdog::{PLAN_GAP_EXIT, SERVICE_NAME};

fn main() {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "{{\"status\":\"plan_gap\",\"service\":\"{SERVICE_NAME}\",\"detail\":\"KernelWatchdogPort provider is not composed\"}}"
    );
    std::process::exit(PLAN_GAP_EXIT);
}
