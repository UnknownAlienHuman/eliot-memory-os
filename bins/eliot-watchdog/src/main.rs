use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use eliot_contracts::AuthorityEpoch;
use eliot_watchdog::{
    IndependentKernelSensor, SERVICE_NAME, WatchdogComposition, WatchdogConfig, active_lease,
};

fn main() {
    #[cfg(windows)]
    if run_as_scm_service() {
        return;
    }
    run_watchdog();
}

fn run_watchdog() {
    let spool = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Eliot")
        .join("watchdog")
        .join("protected-spool.jsonl");
    let lease = active_lease(
        format!("{SERVICE_NAME}-lease"),
        "eliot-host",
        AuthorityEpoch::new(1).unwrap_or_else(|_| unreachable!()),
        AuthorityEpoch::new(1).unwrap_or_else(|_| unreachable!()),
    );
    let sensor = match IndependentKernelSensor::open(spool, lease.watchdog_epoch.value()) {
        Ok(sensor) => Arc::new(sensor),
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{{\"error\":\"WATCHDOG_SPOOL\",\"detail\":{error:?}}}"
            );
            std::process::exit(1);
        }
    };
    let composition = match WatchdogComposition::start(WatchdogConfig::default(), lease, sensor) {
        Ok(composition) => composition,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{{\"error\":\"WATCHDOG_COMPOSITION\",\"detail\":{error:?}}}"
            );
            std::process::exit(1);
        }
    };
    let readiness = composition.readiness();
    let _ = serde_json::to_writer(&mut io::stdout().lock(), &readiness);
    let _ = writeln!(io::stdout().lock());
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{{\"error\":\"WATCHDOG_RUNTIME\",\"detail\":{error:?}}}"
            );
            std::process::exit(1);
        }
    };
    if let Err(error) = runtime.block_on(composition.run_until_shutdown()) {
        let _ = writeln!(
            io::stderr().lock(),
            "{{\"error\":\"WATCHDOG_SHUTDOWN\",\"detail\":{error:?}}}"
        );
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_as_scm_service() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{SERVICE_TABLE_ENTRYW, StartServiceCtrlDispatcherW};
    let name = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr().cast_mut(),
            lpServiceProc: Some(watchdog_service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: SCM borrows the table only until the dispatcher returns.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) != 0 }
}

#[cfg(windows)]
unsafe extern "system" fn watchdog_service_main(_argc: u32, _argv: *mut *mut u16) {
    run_watchdog();
}
