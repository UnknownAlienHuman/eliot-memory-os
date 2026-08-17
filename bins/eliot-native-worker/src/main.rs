use std::io::{self, Write};

use eliot_native_worker::{KERNEL_ADMISSION_REQUIRED, KernelNativeWorkerClient, NativeWorkerError};

const KERNEL_ADMISSION_EXIT: i32 = 78;

fn main() {
    let error = match KernelNativeWorkerClient::connect() {
        Ok(_) => NativeWorkerError::KernelAdmissionRequired(
            "Kernel claim unexpectedly returned without a session-bound process request".to_owned(),
        ),
        Err(error) => error,
    };
    emit(KERNEL_ADMISSION_REQUIRED, &error.to_string());
    std::process::exit(KERNEL_ADMISSION_EXIT);
}

fn emit(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
}
