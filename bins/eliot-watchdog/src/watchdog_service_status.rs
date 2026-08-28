//! Windows SCM service-status publication cell.
//!
//! Architecture: A8.1 Watchdog purpose; ARCH-WDG-01 Independent supervision.
//! Implementation: I8.1 Process and authority; I8.2 Independent observation routes.
//!
//! This private module owns only SCM status serialization and `SetServiceStatus`
//! publication mechanics. It does not choose lifecycle state or perform control
//! flow; SCM registration, control handling, lifecycle, admission, composition,
//! semantic, canonical, authority, and durable-write ownership remain outside.

use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::System::Services::{SERVICE_STATUS, SetServiceStatus};

pub(super) static SERVICE_STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

pub(super) fn set_service_status_running() {
    let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
    if raw != 0 {
        publish_service_status(
            raw as _,
            windows_sys::Win32::System::Services::SERVICE_RUNNING,
            windows_sys::Win32::System::Services::SERVICE_ACCEPT_STOP
                | windows_sys::Win32::System::Services::SERVICE_ACCEPT_SHUTDOWN
                | windows_sys::Win32::System::Services::SERVICE_ACCEPT_PRESHUTDOWN,
            0,
            0,
            0,
        );
    }
}

pub(super) fn set_service_status_stopped() {
    let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
    if raw != 0 {
        publish_service_status(
            raw as _,
            windows_sys::Win32::System::Services::SERVICE_STOPPED,
            0,
            0,
            0,
            0,
        );
    }
}

pub(super) fn publish_service_status(
    handle: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
    state: u32,
    controls: u32,
    error: u32,
    checkpoint: u32,
    wait_hint: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: 0x0000_0010,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    // SAFETY: the handle is either SCM-provided or zero-checked by callers.
    unsafe { SetServiceStatus(handle, &raw const status) };
}
