use std::io::{self, Write};

use eliot_doctor_core::{CONTRACT_NAME, CONTRACT_VERSION, KERNEL_ADMISSION_REQUIRED};

const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;

fn main() {
    // The current Kernel does not advertise the Doctor operation. Do not
    // accept stdin as an authority, and do not claim readiness before IPC
    // authentication and admission have completed.
    let _ = writeln!(
        io::stderr(),
        "{KERNEL_ADMISSION_REQUIRED}: operation={CONTRACT_NAME} version={CONTRACT_VERSION}"
    );
    std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);
}
