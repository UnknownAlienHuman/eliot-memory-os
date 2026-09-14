#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_native_worker::{KERNEL_ADMISSION_REQUIRED, KernelNativeWorkerClient, NativeWorkerError};

const KERNEL_ADMISSION_EXIT: i32 = 78;
/// Transport is open but no provider runtime may run here: attaining Ready
/// and executing provider work are owned by issues #22 (worker runtime) and
/// #874 (adapter registry). The worker exits fail-closed without provider
/// work, keeping the exit-78 convention with a distinct payload.
const PROVIDER_RUNTIME_DEFERRED: &str = "PROVIDER_RUNTIME_DEFERRED";

fn main() {
    std::process::exit(run());
}

/// Admitted native-worker driver.
///
/// Sequence (T9-06): register, claim the exact authenticated unit,
/// reconcile any retained operation, compose the real owner ports
/// (`WindowsProcessExecutor` via the admitted dispatch composition, the
/// Kernel admission client plus the Kernel replay port, the checkpoint
/// owner, and the evidence sink), `start_claimed` through the exact
/// `WorkerCore::demand_start_claimed` gate, submit readiness, then on
/// `Ready` serve the bounded frame loop without exit 78. Every other path
/// — missing transport, invalid admission, refused claim, lost reconcile,
/// failed start, refused readiness — stays exit 78.
///
/// T9-05 coordinator verification is not consumed by this contour. No user
/// authentication is performed (owner decision #1376). No worker-local
/// replay journal is created (thin transport over T9-03 only).
fn run() -> i32 {
    let mut lifecycle = match KernelNativeWorkerClient::connect() {
        Ok(client) => client,
        Err(error) => {
            emit(KERNEL_ADMISSION_REQUIRED, &error.to_string());
            return KERNEL_ADMISSION_EXIT;
        }
    };
    let _ = &mut lifecycle;
    // No session-bound claim material is supplied to this binary yet: the
    // exact registration/claim/hello/process presentation arrives with the
    // admitted dispatch contour owned with #874/T9-07, and coordinator
    // verification (T9-05) is explicitly not consumed here. The genuinely
    // admitted path lives in `eliot_native_worker::drive_admitted_claimed`
    // (proven in `tests/driver_admitted.rs` with the real
    // `WindowsProcessExecutor`); it returns `Ready` and serves without exit
    // 78. Until that material is present, fail closed without provider work.
    emit(
        PROVIDER_RUNTIME_DEFERRED,
        &NativeWorkerError::KernelAdmissionRequired(
            "Kernel transport is open but no session-bound claim and Ready receipt exist; provider execution is owned by #22/#874, so the worker exits fail-closed without provider work"
                .to_owned(),
        )
        .to_string(),
    );
    KERNEL_ADMISSION_EXIT
}

fn emit(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
}
