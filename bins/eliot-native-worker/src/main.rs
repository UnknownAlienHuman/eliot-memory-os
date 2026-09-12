use std::io::{self, Write};

use eliot_native_worker::{KERNEL_ADMISSION_REQUIRED, KernelNativeWorkerClient, NativeWorkerError};

const KERNEL_ADMISSION_EXIT: i32 = 78;
/// Transport is open but no provider runtime may run here: attaining Ready
/// and executing provider work are owned by issues #22 (worker runtime) and
/// #874 (adapter registry). The worker exits fail-closed without provider
/// work, keeping the exit-78 convention with a distinct payload.
const PROVIDER_RUNTIME_DEFERRED: &str = "PROVIDER_RUNTIME_DEFERRED";

fn main() {
    let (code, error) = match KernelNativeWorkerClient::connect() {
        Ok(_) => (
            PROVIDER_RUNTIME_DEFERRED,
            NativeWorkerError::KernelAdmissionRequired(
                "Kernel transport is open but no session-bound claim and Ready receipt exist; provider execution is owned by #22/#874, so the worker exits fail-closed without provider work"
                    .to_owned(),
            ),
        ),
        Err(error) => (KERNEL_ADMISSION_REQUIRED, error),
    };
    emit(code, &error.to_string());
    std::process::exit(KERNEL_ADMISSION_EXIT);
}

fn emit(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
}
