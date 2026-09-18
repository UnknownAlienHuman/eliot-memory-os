//! Safe Windows SCM entry mechanics for service dispatch, control handling,
//! status publication, and `ServiceMain` argv parsing.
//!
//! This module is the single owner of every `unsafe` operation required by the
//! Windows Service Control Manager (SCM) entry path:
//!
//! - [`run_service_dispatcher`] wraps `StartServiceCtrlDispatcherW` and maps
//!   `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` to the console fallback;
//! - [`register_service_control_handler`] wraps
//!   `RegisterServiceCtrlHandlerExW` with a `NULL` context;
//! - [`report_service_status`] wraps `SetServiceStatus` through the opaque
//!   [`ServiceStatusHandle`], replacing the previous `AtomicIsize`/`isize`
//!   handle smuggling in the composition binaries;
//! - [`parse_service_main_argv`] validates the raw SCM `argc`/`argv` pair and
//!   projects it to one [`std::ffi::OsString`] so callers can run their
//!   existing typed validators on the value.
//!
//! The public surface is 100% safe: every entry point is a plain `pub fn`
//! (never `pub unsafe fn`). All `unsafe` blocks are confined to this file and
//! carry an explicit `SAFETY` justification.
//!
//! # Safety invariants (caller contract)
//!
//! - SCM-owned `argv` memory is borrowed only for the duration of the
//!   `ServiceMain` callback. Callers must forward exactly the `argc`/`argv`
//!   pair SCM passed to their callback (or a null/bad pair to observe the
//!   typed rejection); forwarding any other pointer is a contract violation.
//! - The control-handler function must be a `fn` item (no captures) that lives
//!   for the process lifetime. SCM may invoke it at any time after
//!   registration until the service exits. The bare function-pointer parameter
//!   type enforces the no-capture property; the lifetime property is
//!   documented here because the type system cannot express it.
//! - A [`ServiceStatusHandle`] is valid from successful registration until the
//!   service process exits. It must not be used after SCM reclaims the
//!   service; in practice every user stops reporting once its service-main
//!   returns.
//! - Service names are encoded as NUL-terminated UTF-16. Names containing an
//!   interior NUL are rejected with `ERROR_INVALID_PARAMETER` instead of being
//!   silently truncated at the first NUL.
//!
//! This module never chooses lifecycle state: it transports the caller's
//! [`ServiceStatusReport`] verbatim (with the fixed `SERVICE_WIN32_OWN_PROCESS`
//! service type used by every current caller) and never interprets argv
//! content beyond shape validation.

use std::ffi::OsString;

/// Hard ceiling for one SCM `ServiceMain` argv value, in UTF-16 code units.
///
/// Mirrors the bound historically enforced inline by `eliot-host` and
/// `eliot-watchdog` (`64 * 1024`). The NUL scan in
/// [`parse_service_main_argv`] never reads past this many units from a
/// non-null argv value.
pub const MAX_SERVICE_ARG_UNITS: usize = 64 * 1024;

/// `ServiceMain` entry point invoked by SCM through the dispatch table.
///
/// Equivalent to `windows_sys`'s `LPSERVICE_MAIN_FUNCTIONW` payload without
/// the `Option` wrapper: a dispatch-table entry always names a real callback,
/// so `None` is not representable here.
// SAFETY: StartServiceCtrlDispatcherW dispatch-table ABI — the
// SERVICE_TABLE_ENTRY array and UTF-16 service name are caller-provided
// stack locals that outlive the blocking dispatcher call; the table is
// null-terminated, bounding SCM's walk; this fn item has process lifetime
// with no captures and no borrowed state crossing into SCM; SCM invokes it
// on its own thread, and the argv wide pointer is NUL-terminated UTF-16
// valid for the callback duration under the extern "system" ABI.
pub type ServiceMainFn = unsafe extern "system" fn(u32, *mut *mut u16);

/// Extended service-control handler invoked by SCM.
///
/// Equivalent to `windows_sys`'s `LPHANDLER_FUNCTION_EX` payload without the
/// `Option` wrapper. Must be a `fn` item with process lifetime; see the
/// module-level safety invariants.
// SAFETY: RegisterServiceCtrlHandlerExW handler ABI — a process-lifetime
// fn item with no captures; the NULL context carries no borrowed state
// into SCM; SCM invokes this callback on its control thread, and the
// handler returns promptly with no unwind across the extern boundary.
pub type ServiceControlHandlerFn =
    unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u32;

/// Raw Win32 error code returned by a failed SCM primitive.
///
/// Carries only the numeric code, never argv content, paths, or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32Error {
    code: u32,
}

impl Win32Error {
    /// Wraps the raw code from `GetLastError`.
    #[must_use]
    pub const fn new(code: u32) -> Self {
        Self { code }
    }

    /// Returns the raw Win32 error code.
    #[must_use]
    pub const fn code(self) -> u32 {
        self.code
    }

    /// Win32 error used when the primitive has no Windows implementation.
    ///
    /// `120` is `ERROR_CALL_NOT_IMPLEMENTED`. Returned only by the
    /// non-Windows stubs so the same safe API links on every platform.
    #[cfg(not(windows))]
    const fn not_supported() -> Self {
        Self { code: 120 }
    }
}

impl std::fmt::Display for Win32Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Win32 error {} (0x{:08X})", self.code, self.code)
    }
}

impl std::error::Error for Win32Error {}

/// Outcome of entering the SCM dispatch table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatcherOutcome {
    /// `StartServiceCtrlDispatcherW` accepted the table; SCM now owns the
    /// service lifetime and invoked (or will invoke) the `ServiceMain`.
    Dispatched,
    /// SCM is not present (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`); the
    /// process runs as an interactive console instead.
    Console,
}

/// Opaque SCM service-status handle.
///
/// Replaces the historical `AtomicIsize`/`isize` smuggling between the
/// registration site and status-publication sites. Constructible only via
/// [`register_service_control_handler`], so a live value always names an
/// SCM-registered handle valid until service exit.
///
/// `Copy` is intentional: the token is a plain address-sized value with no
/// drop semantics, and background reporters (e.g. start-pending checkpoint
/// threads) hold their own copy while service-main retains the original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceStatusHandle {
    raw: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
}

// SAFETY: the handle is an opaque SCM token with no interior mutability. Every
// use is a synchronous `SetServiceStatus` call that borrows the token value,
// matching the historical cross-thread reporter pattern.
unsafe impl Send for ServiceStatusHandle {}
// SAFETY: same as `Send`; concurrent `SetServiceStatus` calls on one handle
// are serialized inside SCM.
unsafe impl Sync for ServiceStatusHandle {}

/// Plain-data service-status projection transported to SCM.
///
/// Field-for-field equivalent to `SERVICE_STATUS` minus the service type,
/// which is fixed to `SERVICE_WIN32_OWN_PROCESS` (`0x10`) for every current
/// caller. No `unsafe`, no handles, no secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceStatusReport {
    /// `dwCurrentState` (e.g. `SERVICE_START_PENDING`, `SERVICE_RUNNING`).
    pub current_state: u32,
    /// `dwControlsAccepted` bitmask.
    pub controls_accepted: u32,
    /// `dwWin32ExitCode`.
    pub win32_exit_code: u32,
    /// `dwServiceSpecificExitCode`.
    pub service_specific_exit_code: u32,
    /// `dwCheckPoint`.
    pub check_point: u32,
    /// `dwWaitHint` in milliseconds.
    pub wait_hint: u32,
}

impl ServiceStatusReport {
    /// Builds a status report from its six SCM fields.
    #[must_use]
    pub const fn new(
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    ) -> Self {
        Self {
            current_state,
            controls_accepted,
            win32_exit_code,
            service_specific_exit_code,
            check_point,
            wait_hint,
        }
    }

    /// Projects this report onto the Win32 `SERVICE_STATUS` layout.
    #[cfg(windows)]
    fn to_service_status(self) -> windows_sys::Win32::System::Services::SERVICE_STATUS {
        use windows_sys::Win32::System::Services::SERVICE_WIN32_OWN_PROCESS;
        windows_sys::Win32::System::Services::SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: self.current_state,
            dwControlsAccepted: self.controls_accepted,
            dwWin32ExitCode: self.win32_exit_code,
            dwServiceSpecificExitCode: self.service_specific_exit_code,
            dwCheckPoint: self.check_point,
            dwWaitHint: self.wait_hint,
        }
    }
}

/// Typed rejection of a malformed SCM `ServiceMain` argv pair.
///
/// Messages carry only shapes and bounds, never argv content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceArgvError {
    /// `argc` is not exactly 1.
    BadCount,
    /// The argv vector pointer itself is null.
    NullVector,
    /// The single argv entry pointer is null. Kept distinct from
    /// [`ServiceArgvError::NullVector`] so operators can tell a missing
    /// vector from a missing value.
    NullValue,
    /// The value has no NUL terminator within [`MAX_SERVICE_ARG_UNITS`].
    TooLong,
    /// The value is not valid UTF-16. Unreachable on Windows, where
    /// `OsString::from_wide` is lossless; produced by the UTF-16 validation
    /// on other platforms.
    InvalidUtf16,
}

impl std::fmt::Display for ServiceArgvError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCount => formatter.write_str(
                "SCM ServiceMain argv must contain exactly one entry (the service name)",
            ),
            Self::NullVector => formatter.write_str("SCM provided a null service argv vector"),
            Self::NullValue => formatter.write_str("SCM provided a null service argv value"),
            Self::TooLong => write!(
                formatter,
                "SCM service argv value exceeds {MAX_SERVICE_ARG_UNITS} UTF-16 units without a terminator"
            ),
            Self::InvalidUtf16 => formatter.write_str("SCM service argv value is not valid UTF-16"),
        }
    }
}

impl std::error::Error for ServiceArgvError {}

/// Win32 `ERROR_INVALID_PARAMETER` (`87`), used for an interior-NUL service name.
#[cfg(windows)]
const ERROR_INVALID_PARAMETER: u32 = 87;

/// Encodes a service name as NUL-terminated UTF-16, rejecting interior NULs
/// so SCM never observes a silently truncated name.
#[cfg(windows)]
fn encode_service_name(name: &str) -> Result<Vec<u16>, Win32Error> {
    if name.contains('\0') {
        return Err(Win32Error::new(ERROR_INVALID_PARAMETER));
    }
    Ok(name.encode_utf16().chain(Some(0)).collect())
}

/// Enters the SCM dispatch table for one service.
///
/// Builds the UTF-16 service name and the two-entry `SERVICE_TABLE_ENTRYW`
/// (service entry plus terminating null entry) internally, then calls
/// `StartServiceCtrlDispatcherW`, which blocks until the service stops. The
/// table and name are stack locals that outlive the blocking call, so the SCM
/// borrow ends at return.
///
/// Maps `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` to
/// [`DispatcherOutcome::Console`]; every other failure becomes
/// `Err(Win32Error)`.
pub fn run_service_dispatcher(
    service_name: &str,
    main_fn: ServiceMainFn,
) -> Result<DispatcherOutcome, Win32Error> {
    #[cfg(not(windows))]
    {
        let _ = (service_name, main_fn);
        return Err(Win32Error::not_supported());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, GetLastError,
        };
        use windows_sys::Win32::System::Services::{
            SERVICE_TABLE_ENTRYW, StartServiceCtrlDispatcherW,
        };

        let name = encode_service_name(service_name)?;
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_ptr().cast_mut(),
                lpServiceProc: Some(main_fn),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: the table and UTF-16 name are stack locals that remain live
        // and unmodified for the whole blocking dispatcher call; the
        // terminating null entry bounds SCM's table walk.
        let connected = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0;
        if connected {
            Ok(DispatcherOutcome::Dispatched)
        } else {
            // SAFETY: captured on the calling thread immediately after the
            // failed dispatcher call; no other Win32 call intervenes.
            let code = unsafe { GetLastError() };
            if code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                // The documented interactive-console case is the only
                // condition under which the process may use its console
                // fallback.
                Ok(DispatcherOutcome::Console)
            } else {
                Err(Win32Error::new(code))
            }
        }
    }
}

/// Registers an extended service-control handler with a `NULL` context.
///
/// Returns the opaque [`ServiceStatusHandle`] on success. A null handle from
/// SCM becomes `Err(Win32Error)` with the `GetLastError` code; no null handle
/// ever escapes this function.
pub fn register_service_control_handler(
    service_name: &str,
    handler: ServiceControlHandlerFn,
) -> Result<ServiceStatusHandle, Win32Error> {
    #[cfg(not(windows))]
    {
        let _ = (service_name, handler);
        return Err(Win32Error::not_supported());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Services::RegisterServiceCtrlHandlerExW;

        let name = encode_service_name(service_name)?;
        // SAFETY: the UTF-16 name is NUL-terminated and live for the call;
        // the handler is a caller-provided process-lifetime `fn` item; the
        // NULL context means no borrowed state crosses into SCM.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null())
        };
        if handle.is_null() {
            // SAFETY: captured on the calling thread immediately after the
            // failed registration; no other Win32 call intervenes.
            let code = unsafe { GetLastError() };
            Err(Win32Error::new(code))
        } else {
            Ok(ServiceStatusHandle { raw: handle })
        }
    }
}

/// Publishes one [`ServiceStatusReport`] through an SCM-registered handle.
///
/// Builds the `SERVICE_STATUS` internally (with the fixed
/// `SERVICE_WIN32_OWN_PROCESS` service type) and calls `SetServiceStatus`. A
/// zero return becomes `Err(Win32Error)` with the `GetLastError` code.
pub fn report_service_status(
    handle: &ServiceStatusHandle,
    report: &ServiceStatusReport,
) -> Result<(), Win32Error> {
    #[cfg(not(windows))]
    {
        let _ = (handle, report);
        return Err(Win32Error::not_supported());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Services::SetServiceStatus;

        let status = report.to_service_status();
        // SAFETY: the handle was issued by SCM via
        // `register_service_control_handler` and is valid until service exit;
        // `status` is a fully initialized local borrowed read-only for the
        // duration of the call.
        let succeeded = unsafe { SetServiceStatus(handle.raw, &raw const status) };
        if succeeded == 0 {
            // SAFETY: captured on the calling thread immediately after the
            // failed status call; no other Win32 call intervenes.
            let code = unsafe { GetLastError() };
            Err(Win32Error::new(code))
        } else {
            Ok(())
        }
    }
}

/// Validates the raw SCM `ServiceMain` `argc`/`argv` pair and projects the
/// single argv value to an [`OsString`].
///
/// Accepts exactly `argc == 1` with a non-null vector whose single entry is a
/// non-null NUL-terminated UTF-16 string shorter than
/// [`MAX_SERVICE_ARG_UNITS`] units. Callers run their existing typed
/// service-name validators on the returned value.
///
/// # Safety
///
/// This is a safe function, but the raw pair must be the exact
/// `service_arg_count`/`service_arg_vector` SCM passed to the caller's
/// `ServiceMain` callback: when the count is 1 and
/// the vector is non-null, the vector must point to an array of exactly one entry
/// pointer readable for the call duration, and a non-null entry must point to
/// readable UTF-16 memory. Null vectors, wrong counts, null entries, and
/// over-long values are rejected without further dereference; the NUL scan
/// never advances past [`MAX_SERVICE_ARG_UNITS`] units.
pub fn parse_service_main_argv(
    service_arg_count: u32,
    service_arg_vector: *mut *mut u16,
) -> Result<OsString, ServiceArgvError> {
    if service_arg_count != 1 {
        return Err(ServiceArgvError::BadCount);
    }
    if service_arg_vector.is_null() {
        return Err(ServiceArgvError::NullVector);
    }
    // SAFETY: `service_arg_count == 1` and `service_arg_vector` is non-null
    // per the checks above, and the caller forwards the SCM-owned pair, so
    // `service_arg_vector` addresses exactly one readable entry pointer. Only
    // index 0 is read; nothing is mutated.
    let vector = unsafe {
        std::slice::from_raw_parts(service_arg_vector.cast_const(), service_arg_count as usize)
    };
    let pointer = vector[0];
    if pointer.is_null() {
        return Err(ServiceArgvError::NullValue);
    }
    let mut length = 0_usize;
    while length < MAX_SERVICE_ARG_UNITS {
        // SAFETY: `pointer` is non-null and SCM-owned; `length` is bounded by
        // `MAX_SERVICE_ARG_UNITS` and the scan stops at the first NUL, so
        // every read stays inside the scanned prefix. A missing terminator is
        // reported as `TooLong` instead of scanning further.
        if unsafe { *pointer.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    if length == MAX_SERVICE_ARG_UNITS {
        return Err(ServiceArgvError::TooLong);
    }
    // SAFETY: `[pointer, pointer + length)` is the NUL-delimited prefix just
    // scanned inside the SCM-owned buffer; it holds exactly `length` UTF-16
    // units with no interior NUL and is not mutated during the copy.
    let units = unsafe { std::slice::from_raw_parts(pointer.cast_const(), length) };
    wide_to_os_string(units)
}

/// Copies UTF-16 units into an [`OsString`].
///
/// On Windows the conversion is lossless. Elsewhere the units are validated
/// as UTF-16, producing [`ServiceArgvError::InvalidUtf16`] on failure.
#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the non-Windows twin needs the shared Result shape for UTF-16 validation"
)]
fn wide_to_os_string(units: &[u16]) -> Result<OsString, ServiceArgvError> {
    use std::os::windows::ffi::OsStringExt;
    Ok(OsString::from_wide(units))
}

/// Copies UTF-16 units into an [`OsString`] with UTF-16 validation.
#[cfg(not(windows))]
fn wide_to_os_string(units: &[u16]) -> Result<OsString, ServiceArgvError> {
    String::from_utf16(units)
        .map(OsString::from)
        .map_err(|_| ServiceArgvError::InvalidUtf16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide_nul(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn parse_result(
        service_arg_count: u32,
        service_arg_vector: *mut *mut u16,
    ) -> Result<OsString, ServiceArgvError> {
        parse_service_main_argv(service_arg_count, service_arg_vector)
    }

    #[test]
    fn argv_happy_path_returns_service_name() {
        let mut name = wide_nul("EliotHost");
        let mut vector = [name.as_mut_ptr()];
        match parse_result(1, vector.as_mut_ptr()) {
            Ok(value) => assert_eq!(value, OsString::from("EliotHost")),
            Err(error) => panic!("happy-path argv must parse: {error}"),
        }
    }

    #[test]
    fn argv_empty_name_parses_to_empty_string() {
        let mut name = wide_nul("");
        let mut vector = [name.as_mut_ptr()];
        match parse_result(1, vector.as_mut_ptr()) {
            Ok(value) => assert_eq!(value, OsString::from("")),
            Err(error) => panic!("empty argv value must parse: {error}"),
        }
    }

    #[test]
    fn argv_null_vector_is_typed_error() {
        assert_eq!(
            parse_result(1, std::ptr::null_mut()),
            Err(ServiceArgvError::NullVector)
        );
    }

    #[test]
    fn argv_bad_count_is_typed_error_before_null_checks() {
        let mut name = wide_nul("EliotHost");
        let mut vector = [name.as_mut_ptr()];
        assert_eq!(
            parse_result(0, vector.as_mut_ptr()),
            Err(ServiceArgvError::BadCount)
        );
        assert_eq!(
            parse_result(2, vector.as_mut_ptr()),
            Err(ServiceArgvError::BadCount)
        );
        // A null vector with a bad count reports the count first, keeping the
        // check order deterministic.
        assert_eq!(
            parse_result(0, std::ptr::null_mut()),
            Err(ServiceArgvError::BadCount)
        );
    }

    #[test]
    fn argv_null_value_is_typed_error() {
        let mut vector = [std::ptr::null_mut()];
        assert_eq!(
            parse_result(1, vector.as_mut_ptr()),
            Err(ServiceArgvError::NullValue)
        );
    }

    #[test]
    fn argv_too_long_is_typed_error() {
        let mut units = vec![0x0041_u16; MAX_SERVICE_ARG_UNITS];
        let mut vector = [units.as_mut_ptr()];
        assert_eq!(
            parse_result(1, vector.as_mut_ptr()),
            Err(ServiceArgvError::TooLong)
        );
    }

    #[test]
    fn argv_near_bound_with_terminator_parses() {
        let mut units = vec![0x0041_u16; MAX_SERVICE_ARG_UNITS];
        let last = units.len() - 1;
        units[last] = 0;
        let mut vector = [units.as_mut_ptr()];
        let expected = OsString::from("A".repeat(MAX_SERVICE_ARG_UNITS - 1));
        match parse_result(1, vector.as_mut_ptr()) {
            Ok(value) => assert_eq!(value, expected),
            Err(error) => panic!("terminated near-bound argv must parse: {error}"),
        }
    }

    #[test]
    fn argv_errors_carry_no_input_content() {
        for error in [
            ServiceArgvError::BadCount,
            ServiceArgvError::NullVector,
            ServiceArgvError::NullValue,
            ServiceArgvError::TooLong,
            ServiceArgvError::InvalidUtf16,
        ] {
            let message = error.to_string();
            assert!(!message.is_empty());
            assert!(
                !message.contains("EliotHost"),
                "error messages must not echo argv content: {message}"
            );
        }
    }

    #[test]
    fn status_report_constructor_projects_every_field() {
        let report = ServiceStatusReport::new(4, 5, 1066, 2, 7, 10_000);
        assert_eq!(report.current_state, 4);
        assert_eq!(report.controls_accepted, 5);
        assert_eq!(report.win32_exit_code, 1066);
        assert_eq!(report.service_specific_exit_code, 2);
        assert_eq!(report.check_point, 7);
        assert_eq!(report.wait_hint, 10_000);

        #[cfg(windows)]
        {
            let status = report.to_service_status();
            assert_eq!(status.dwServiceType, 0x0000_0010);
            assert_eq!(status.dwCurrentState, 4);
            assert_eq!(status.dwControlsAccepted, 5);
            assert_eq!(status.dwWin32ExitCode, 1066);
            assert_eq!(status.dwServiceSpecificExitCode, 2);
            assert_eq!(status.dwCheckPoint, 7);
            assert_eq!(status.dwWaitHint, 10_000);
        }
    }

    #[test]
    fn status_handle_is_copy_send_sync() {
        fn assert_copy_send_sync<T: Copy + Send + Sync>() {}
        assert_copy_send_sync::<ServiceStatusHandle>();
    }

    #[test]
    fn win32_error_carries_code_without_secrets() {
        let error = Win32Error::new(1063);
        assert_eq!(error.code(), 1063);
        let message = error.to_string();
        assert!(message.contains("1063"));
        assert!(message.contains("0x00000427"));
    }

    #[test]
    fn dispatcher_outcome_names_console_fallback() {
        assert_ne!(
            DispatcherOutcome::Dispatched,
            DispatcherOutcome::Console,
            "the console fallback must stay distinguishable from dispatch"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn argv_invalid_utf16_is_typed_error_off_windows() {
        let mut units = vec![0xD800_u16, 0];
        let mut vector = [units.as_mut_ptr()];
        assert_eq!(
            parse_result(1, vector.as_mut_ptr()),
            Err(ServiceArgvError::InvalidUtf16)
        );
    }
}
