//! Windows SCM service-status publication cell.
//!
//! Architecture: A8.1 Watchdog purpose; ARCH-WDG-01 Independent supervision.
//! Implementation: I8.1 Process and authority; I8.2 Independent observation routes.
//!
//! This private module owns only SCM status serialization and `SetServiceStatus`
//! publication mechanics plus the typed start-failure taxonomy projected through
//! it. It does not choose lifecycle state or perform control flow; SCM
//! registration, control handling, lifecycle, admission, composition,
//! semantic, canonical, authority, and durable-write ownership remain outside.
//!
//! Start-failure taxonomy (s33.1): every `watchdog_service_main` failure path
//! reports `SERVICE_STOPPED` with `dwWin32ExitCode = 1066`
//! (`ERROR_SERVICE_SPECIFIC_ERROR`) and a stable per-class
//! `dwServiceSpecificExitCode` from [`WatchdogStopCode`], so `sc queryex`
//! names the failure class instead of collapsing every start failure to
//! `exit 1 / specific 0`. Console entry points have no `SERVICE_STATUS_HANDLE`,
//! so they exit the process with [`CONSOLE_PROCESS_EXIT_CODE`] (1066) and
//! carry the typed class in stderr plus the bounded start-failure capsule
//! persisted by [`persist_start_failure`].
//!
//! Capsule ownership note: the Watchdog spool (`watchdog_spool.rs`) carries
//! only the restricted non-semantic Heartbeat/Gap/Recovery envelope behind a
//! `pub(crate)` single writer that the service-entry binary cannot name without
//! touching unowned library files, and no Windows Event Log owner exists in
//! code on `main` (the I08-03:18 norm names the sink, but no owner/type
//! implements it). The capsule is therefore one bounded secret-free JSON file
//! written through the only state root the bootstrap contract already yields:
//! the installer-approved Host state root retained by the Watchdog admission
//! lease. It is a terminal receipt projection, not a logging subsystem: one
//! file, one record, bounded bytes, best-effort write, never a secret.

use std::path::PathBuf;

use eliot_platform_windows::ServiceBootstrapArguments;
use windows_sys::Win32::System::Services::{SERVICE_STATUS, SetServiceStatus};

use eliot_watchdog::{FileWatchdogAdmission, SERVICE_NAME, WatchdogScmLaunchError};

pub(super) static SERVICE_STATUS_HANDLE: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

/// Win32 `ERROR_SERVICE_SPECIFIC_ERROR`: the `dwWin32ExitCode` reported for
/// every typed Watchdog start failure. The per-class detail travels in
/// `dwServiceSpecificExitCode` ([`WatchdogStopCode::specific`]).
pub(super) const WIN32_SERVICE_SPECIFIC_ERROR: u32 = 1066;

/// Process exit code for console start failures. A console run has no
/// `SERVICE_STATUS_HANDLE`, so the 1066 marker is carried as the process exit
/// code while the typed class is carried in stderr and the capsule.
pub(super) const CONSOLE_PROCESS_EXIT_CODE: i32 = 1066;

/// Single bounded start-failure capsule file inside the retained state root.
pub(super) const START_FAILURE_CAPSULE_FILE_NAME: &str = "eliot-watchdog-start-failure.json";
/// Hard ceiling for the serialized capsule; the builder truncates fields first
/// and then trims at a character boundary so output never exceeds this.
pub(super) const START_FAILURE_CAPSULE_MAX_BYTES: usize = 4096;
/// Per-field ceiling for the free-text failure detail.
pub(super) const START_FAILURE_DETAIL_MAX_CHARS: usize = 512;
/// Per-field ceiling for the installation identity echo.
pub(super) const START_FAILURE_IDENTITY_MAX_CHARS: usize = 128;

/// Typed Watchdog service-start failure classes.
///
/// Each variant documents the exact `watchdog_service_main` (`main.rs`) site
/// it classifies and owns one stable `dwServiceSpecificExitCode` (the
/// discriminant). Discriminants are never reused or reordered: operators and
/// installers key runbooks off them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WatchdogStopCode {
    /// `RegisterServiceCtrlHandlerExW` returned NULL (`main.rs` register-null
    /// site). The SCM-provided Win32 error is preserved in stderr and the
    /// capsule; no status handle exists to publish through.
    ScmRegisterNull = 1,
    /// `ServiceMain` argv shape is not exactly the canonical service name
    /// (`service_launch_options` rejection).
    InvalidScmArgv = 2,
    /// The process command-line bootstrap is missing or malformed, so no
    /// installer-approved identity exists to validate
    /// (`validate_registered_process_bootstrap` `InvalidArgv` arms).
    InvalidProcessBootstrap = 3,
    /// The installer-approved Watchdog registration cannot be rebuilt
    /// (`WatchdogScmLaunchError::ApprovalUnavailable`).
    ApprovalUnavailable = 4,
    /// The process bootstrap does not match the installer-approved
    /// registration (`WatchdogScmLaunchError::ApprovalMismatch`).
    ApprovalMismatch = 5,
    /// The read-only SCM runtime inspection is absent, mismatched, or unknown
    /// (`WatchdogScmLaunchError::Registration`).
    RegistrationMismatch = 6,
    /// The current executable, platform root, or platform inspection failed
    /// (`Executable` / `Platform` / `PlatformRoot`).
    PlatformInspection = 7,
    /// `run_watchdog` failed before admission: no usable SCM bootstrap or Host
    /// state root.
    RuntimeBootstrapMissing = 8,
    /// `run_watchdog` admission failed: registry, installer approval, Host
    /// registration readback, supervision lease, spool, sensor, or composition.
    RuntimeAdmission = 9,
    /// The bounded SCM self-admission gate rejected the start (identity
    /// unavailable/mismatched, service stopped/stopping, or deadline timeout).
    RuntimeSelfAdmission = 10,
    /// `run_watchdog` failed past admission: readiness publication, async
    /// runtime construction, or the supervision loop. Catch-all for runtime
    /// strings that match no narrower class.
    RuntimeSupervision = 11,
    /// `StartServiceCtrlDispatcherW` failed in the console entry path. The
    /// SCM-provided Win32 error is preserved in stderr and the capsule.
    DispatcherFailed = 12,
}

impl WatchdogStopCode {
    /// Stable per-class `dwServiceSpecificExitCode` (`sc queryex` names this).
    #[must_use]
    pub(super) const fn specific(self) -> u32 {
        self as u32
    }

    /// Stable machine-readable class name recorded in the capsule.
    #[must_use]
    pub(super) const fn failure_class(self) -> &'static str {
        match self {
            Self::ScmRegisterNull => "scm_register_null",
            Self::InvalidScmArgv => "invalid_scm_argv",
            Self::InvalidProcessBootstrap => "invalid_process_bootstrap",
            Self::ApprovalUnavailable => "approval_unavailable",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::RegistrationMismatch => "registration_mismatch",
            Self::PlatformInspection => "platform_inspection",
            Self::RuntimeBootstrapMissing => "runtime_bootstrap_missing",
            Self::RuntimeAdmission => "runtime_admission",
            Self::RuntimeSelfAdmission => "runtime_self_admission",
            Self::RuntimeSupervision => "runtime_supervision",
            Self::DispatcherFailed => "dispatcher_failed",
        }
    }
}

/// Maps a bootstrap-stage launch error to its stop class.
///
/// The `ServiceMain`-argv stage (`service_launch_options`) only ever yields
/// `InvalidArgv` and is classified at the call site as [`WatchdogStopCode::InvalidScmArgv`];
/// this function classifies the second stage (process bootstrap, installer
/// approval, read-only registration, platform inspection).
#[must_use]
pub(super) fn classify_bootstrap_launch_error(error: &WatchdogScmLaunchError) -> WatchdogStopCode {
    match error {
        WatchdogScmLaunchError::InvalidArgv(_) => WatchdogStopCode::InvalidProcessBootstrap,
        WatchdogScmLaunchError::ApprovalUnavailable(_) => WatchdogStopCode::ApprovalUnavailable,
        WatchdogScmLaunchError::ApprovalMismatch => WatchdogStopCode::ApprovalMismatch,
        WatchdogScmLaunchError::Registration(_) => WatchdogStopCode::RegistrationMismatch,
        WatchdogScmLaunchError::Executable(_)
        | WatchdogScmLaunchError::Platform(_)
        | WatchdogScmLaunchError::PlatformRoot(_) => WatchdogStopCode::PlatformInspection,
    }
}

/// Best-effort classification of a `run_watchdog` failure string.
///
/// `run_watchdog` (`runtime_loop.rs`) collapses every failure to `String`, so
/// admission/ordering logic is untouched and classification matches on the
/// exact production substrings it emits. Order is significant: bootstrap
/// markers first, then the self-admission gate, then transient redb lock
/// contention, then admission/spool/lease markers; anything else is the
/// supervision catch-all. The mapping is covered by
/// `runtime_error_strings_classify_to_documented_classes`.
///
/// The transient arm is taxonomy defense-in-depth only: the primary nonfatal
/// handling is the fence-poll retry in `runtime_loop.rs`, which never returns
/// a transient lock as a `run_watchdog` failure. If such a string ever
/// escapes (console path, future call site), it must not collapse into
/// `RuntimeAdmission` (1066/9, the approval-failure runbook); it maps to the
/// documented supervision catch-all while the capsule keeps the inner cause.
#[must_use]
pub(super) fn classify_runtime_error(message: &str) -> WatchdogStopCode {
    if message.contains("SCM bootstrap is required")
        || message.contains("omitted the installer-approved Host state root")
    {
        WatchdogStopCode::RuntimeBootstrapMissing
    } else if message.contains("self-admission")
        || message.contains("current Watchdog process identity")
    {
        WatchdogStopCode::RuntimeSelfAdmission
    } else if FileWatchdogAdmission::is_transient_registry_lock(message) {
        WatchdogStopCode::RuntimeSupervision
    } else if message.contains("watchdog spool")
        || message.contains("watchdog lease")
        || message.contains("watchdog admission was denied")
        || message.contains("invalid watchdog configuration")
        || message.contains("invalid supervision lease")
        || message.contains("supervision lease")
        || message.contains("installer")
        || message.contains("registry")
        || message.contains("Host SCM registration")
        || message.contains("runtime configuration")
    {
        WatchdogStopCode::RuntimeAdmission
    } else {
        WatchdogStopCode::RuntimeSupervision
    }
}

pub(super) fn set_service_status_running() {
    use std::sync::atomic::Ordering;
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
            0,
        );
    }
}

pub(super) fn set_service_status_stopped() {
    use std::sync::atomic::Ordering;
    let raw = SERVICE_STATUS_HANDLE.load(Ordering::Acquire);
    if raw != 0 {
        publish_service_status(
            raw as _,
            windows_sys::Win32::System::Services::SERVICE_STOPPED,
            0,
            0,
            0,
            0,
            0,
        );
    }
}

/// Publishes one typed `SERVICE_STOPPED` for a start failure: Win32 1066 plus
/// the per-class specific code from [`WatchdogStopCode::specific`].
pub(super) fn publish_stopped_with_code(
    handle: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
    code: WatchdogStopCode,
) {
    publish_service_status(
        handle,
        windows_sys::Win32::System::Services::SERVICE_STOPPED,
        0,
        WIN32_SERVICE_SPECIFIC_ERROR,
        code.specific(),
        0,
        0,
    );
}

pub(super) fn publish_service_status(
    handle: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
    state: u32,
    controls: u32,
    win32_error: u32,
    specific_error: u32,
    checkpoint: u32,
    wait_hint: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: 0x0000_0010,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: win32_error,
        dwServiceSpecificExitCode: specific_error,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    // SAFETY: the handle is either SCM-provided or zero-checked by callers.
    unsafe { SetServiceStatus(handle, &raw const status) };
}

/// Builds the bounded secret-free start-failure capsule JSON.
///
/// The record carries the failure class, both exit codes, and the
/// non-secret bootstrap identities (installation id, plan generation) when
/// known. The registration nonce is never read and therefore can never be
/// persisted; the free-text detail is truncated to
/// [`START_FAILURE_DETAIL_MAX_CHARS`] characters and the whole record is
/// capped at [`START_FAILURE_CAPSULE_MAX_BYTES`] bytes.
#[must_use]
pub(super) fn build_start_failure_capsule(
    code: WatchdogStopCode,
    detail: &str,
    installation_id: Option<&str>,
    plan_generation: Option<u64>,
) -> String {
    let detail = truncate_chars(detail, START_FAILURE_DETAIL_MAX_CHARS);
    let installation =
        installation_id.map(|value| truncate_chars(value, START_FAILURE_IDENTITY_MAX_CHARS));
    let value = serde_json::json!({
        "record_type": "watchdog_start_failure",
        "service": SERVICE_NAME,
        "failure_class": code.failure_class(),
        "win32_exit_code": WIN32_SERVICE_SPECIFIC_ERROR,
        "service_specific_exit_code": code.specific(),
        "installation_id": installation.as_deref(),
        "tx_plan_generation": plan_generation,
        "detail": detail,
    });
    let mut text = serde_json::to_string(&value)
        .unwrap_or_else(|_| String::from("{\"record_type\":\"watchdog_start_failure\"}"));
    while text.len() > START_FAILURE_CAPSULE_MAX_BYTES {
        text.pop();
    }
    text
}

/// Persists one bounded secret-free start-failure capsule through the retained
/// state root.
///
/// The root is the installer-approved Host state root from the captured
/// process bootstrap when available, else the process temp directory as a
/// last-resort carrier. The write is best-effort and never fails the service
/// path: SCM status plus stderr remain the primary signals.
pub(super) fn persist_start_failure(
    code: WatchdogStopCode,
    detail: &str,
    bootstrap: Option<&ServiceBootstrapArguments>,
) {
    let (installation_id, plan_generation, root) = match bootstrap {
        Some(bootstrap) => (
            Some(bootstrap.installation_id()),
            Some(bootstrap.transaction_plan_generation()),
            bootstrap
                .host_state_root()
                .map_or_else(std::env::temp_dir, PathBuf::from),
        ),
        None => (None, None, std::env::temp_dir()),
    };
    let capsule = build_start_failure_capsule(code, detail, installation_id, plan_generation);
    let _ = std::fs::write(root.join(START_FAILURE_CAPSULE_FILE_NAME), capsule);
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() > max_chars {
        value.chars().take(max_chars).collect()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_platform_windows::WindowsAdapterError;
    use eliot_watchdog::WatchdogRuntimeReadback;

    fn all_codes() -> [WatchdogStopCode; 12] {
        use WatchdogStopCode::{
            ApprovalMismatch, ApprovalUnavailable, DispatcherFailed, InvalidProcessBootstrap,
            InvalidScmArgv, PlatformInspection, RegistrationMismatch, RuntimeAdmission,
            RuntimeBootstrapMissing, RuntimeSelfAdmission, RuntimeSupervision, ScmRegisterNull,
        };
        [
            ScmRegisterNull,
            InvalidScmArgv,
            InvalidProcessBootstrap,
            ApprovalUnavailable,
            ApprovalMismatch,
            RegistrationMismatch,
            PlatformInspection,
            RuntimeBootstrapMissing,
            RuntimeAdmission,
            RuntimeSelfAdmission,
            RuntimeSupervision,
            DispatcherFailed,
        ]
    }

    #[test]
    fn stop_codes_are_stable_unique_and_typed() {
        let codes = all_codes();
        let mut specifics = codes.map(WatchdogStopCode::specific);
        specifics.sort_unstable();
        assert_eq!(
            specifics,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            "discriminants are the stable documented specific codes"
        );
        for code in codes {
            assert!(!code.failure_class().is_empty());
        }
        assert_eq!(
            WIN32_SERVICE_SPECIFIC_ERROR, 1066,
            "Win32 marker must be ERROR_SERVICE_SPECIFIC_ERROR"
        );
        let mut classes: Vec<&'static str> =
            codes.iter().map(|code| code.failure_class()).collect();
        classes.sort_unstable();
        classes.dedup();
        assert_eq!(classes.len(), codes.len(), "failure classes must be unique");
    }

    #[test]
    fn bootstrap_launch_errors_map_to_documented_classes() {
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::InvalidArgv(
                "bootstrap missing".to_owned()
            )),
            WatchdogStopCode::InvalidProcessBootstrap
        );
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::ApprovalUnavailable(
                "Host state root open failed".to_owned()
            )),
            WatchdogStopCode::ApprovalUnavailable
        );
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::ApprovalMismatch),
            WatchdogStopCode::ApprovalMismatch
        );
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::Registration(
                WatchdogRuntimeReadback::Absent
            )),
            WatchdogStopCode::RegistrationMismatch
        );
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::Platform(
                WindowsAdapterError::InvalidInput
            )),
            WatchdogStopCode::PlatformInspection
        );
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::PlatformRoot(
                "no parent".to_owned()
            )),
            WatchdogStopCode::PlatformInspection
        );
        assert_eq!(
            classify_bootstrap_launch_error(&WatchdogScmLaunchError::Executable(
                std::io::Error::new(std::io::ErrorKind::NotFound, "current exe")
            )),
            WatchdogStopCode::PlatformInspection
        );
    }

    #[test]
    fn approval_unavailable_preserves_bootstrap_failure_cause_in_capsule() {
        use eliot_installation::InstallerServiceRegistrationApproval;
        use eliot_platform_windows::ServiceBootstrapArguments;
        use eliot_platform_windows::test_support::override_protected_root;
        use eliot_watchdog::{SpoolError, validate_watchdog_scm_bootstrap};
        use std::path::{Path, PathBuf};

        fn bootstrap_with_host_root(
            host_state_root: &Path,
            nonce: &str,
        ) -> ServiceBootstrapArguments {
            let descriptor = std::env::temp_dir().join(format!(
                "eliot-watchdog-approval-descriptor-{}",
                std::process::id()
            ));
            ServiceBootstrapArguments::new(
                descriptor,
                "a".repeat(64),
                "installation-7",
                7,
                std::iter::empty::<String>(),
            )
            .and_then(|value| value.with_host_state_root(host_state_root))
            .and_then(|value| value.with_registration_nonce(nonce))
            .unwrap_or_else(|error| panic!("approval-cause bootstrap fixture: {error}"))
        }

        fn unavailable_detail(error: &WatchdogScmLaunchError) -> &str {
            match error {
                WatchdogScmLaunchError::ApprovalUnavailable(detail) => detail,
                other => panic!("expected ApprovalUnavailable, got {other}"),
            }
        }

        // (a) Host-state-root open failed: the bootstrap names a root that does
        // not exist, so the protected open is a real failure, not canned text.
        let missing_root: PathBuf = std::env::temp_dir().join(format!(
            "eliot-watchdog-approval-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing_root);
        let nonce_a = "e".repeat(64);
        let error_a = match validate_watchdog_scm_bootstrap(&bootstrap_with_host_root(
            &missing_root,
            &nonce_a,
        )) {
            Ok(_) => panic!("missing Host root unexpectedly validated"),
            Err(error) => error,
        };

        // (b) Registry/redb open failed: a retained Host root whose registry
        // child is not a database, so the redb open is a real failure.
        let probe_root: PathBuf = std::env::temp_dir().join(format!(
            "eliot-watchdog-approval-probe-{}",
            std::process::id()
        ));
        let host_root = probe_root.join("host");
        std::fs::create_dir_all(&host_root)
            .unwrap_or_else(|error| panic!("approval-cause probe root: {error}"));
        let _protected_root = override_protected_root(&probe_root);
        std::fs::write(
            host_root.join(eliot_watchdog::INSTALLATION_REGISTRY_FILE_NAME),
            b"not-a-redb-database",
        )
        .unwrap_or_else(|error| panic!("approval-cause corrupt registry: {error}"));
        let nonce_b = "f".repeat(64);
        let error_b = match validate_watchdog_scm_bootstrap(&bootstrap_with_host_root(
            &host_root, &nonce_b,
        )) {
            Ok(_) => panic!("corrupt registry unexpectedly validated"),
            Err(error) => error,
        };

        // (c) Approval invalid: a real installer approval whose configuration
        // digest does not match the reconstructed request, so
        // `service_registration_request` returns a real `InstallationError`.
        // The wrapping mirrors the production prefix in
        // `service_registration_projection.rs`.
        let image =
            std::env::current_exe().unwrap_or_else(|error| panic!("approval-cause image: {error}"));
        let grant_digest = eliot_platform_windows::watchdog_service_security_descriptor_digest(
            "S-1-5-80-1-2-3-4-5",
        )
        .unwrap_or_else(|error| panic!("approval-cause grant digest: {error}"));
        let wire = serde_json::json!({
            "transaction_id": "transaction-fixture",
            "generation": "generation-7",
            "effect_id": "effect-EliotWatchdog",
            "role": "WATCHDOG",
            "service_name": "EliotWatchdog",
            "executable_path": image.to_string_lossy(),
            "account": "LOCAL_SERVICE",
            "automatic_start": true,
            "service_bootstrap": {
                "descriptor_path": std::env::temp_dir().join("watchdog.json").to_string_lossy(),
                "descriptor_digest": "a".repeat(64),
                "installation_id": "installation-7",
                "plan_generation": 7,
                "host_state_root": std::env::temp_dir().join("host").to_string_lossy(),
            },
            "registration_nonce": "b".repeat(64),
            "configuration_digest": "0".repeat(64),
            "service_control_grant": {
                "principal_service": "EliotHost",
                "principal_sid": "S-1-5-80-1-2-3-4-5",
                "access_mask": eliot_platform_windows::ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                "security_descriptor_digest": grant_digest,
            },
        });
        let approval: InstallerServiceRegistrationApproval = serde_json::from_value(wire)
            .unwrap_or_else(|error| panic!("approval-cause wire: {error}"));
        let request_error = match approval.service_registration_request() {
            Ok(_) => panic!("substituted approval unexpectedly reconstructed"),
            Err(error) => error,
        };
        let error_c = WatchdogScmLaunchError::from(SpoolError::InvalidLease(format!(
            "installer SCM registration approval is invalid: {request_error}"
        )));
        assert!(
            unavailable_detail(&error_c).contains(&request_error.to_string()),
            "the typed inner cause must survive, not just the outer marker"
        );

        let nonce_c = "b".repeat(64);
        let cases = [
            (&error_a, "Host state root open failed", nonce_a.as_str()),
            (
                &error_b,
                "installation registry open failed",
                nonce_b.as_str(),
            ),
            (
                &error_c,
                "installer SCM registration approval is invalid",
                nonce_c.as_str(),
            ),
        ];
        let mut details = Vec::new();
        for (error, marker, nonce) in cases {
            assert_eq!(
                classify_bootstrap_launch_error(error),
                WatchdogStopCode::ApprovalUnavailable
            );
            let code = classify_bootstrap_launch_error(error);
            assert_eq!(code.specific(), 4);
            assert_eq!(code.failure_class(), "approval_unavailable");
            let detail = unavailable_detail(error);
            assert!(!detail.is_empty(), "cause detail must not be empty");
            assert!(
                detail.contains(marker),
                "cause detail must name its failure site: {detail}"
            );
            assert!(
                detail.chars().count() <= START_FAILURE_DETAIL_MAX_CHARS,
                "cause detail must stay bounded"
            );
            // Production stderr/capsule formatting from `main.rs`.
            let stderr_detail = format!("invalid SCM launch registration: {error}");
            let capsule =
                build_start_failure_capsule(code, &stderr_detail, Some("installation-7"), Some(7));
            assert!(
                capsule.contains(marker),
                "capsule must preserve the cause: {capsule}"
            );
            assert!(
                !capsule.contains(nonce),
                "the registration nonce must never be persisted"
            );
            assert!(
                capsule.len() <= START_FAILURE_CAPSULE_MAX_BYTES,
                "capsule must stay bounded"
            );
            let parsed: serde_json::Value = serde_json::from_str(&capsule)
                .unwrap_or_else(|error| panic!("capsule JSON: {error}"));
            assert_eq!(parsed["failure_class"], "approval_unavailable");
            assert_eq!(parsed["win32_exit_code"], 1066);
            assert_eq!(parsed["service_specific_exit_code"], 4);
            details.push(detail.to_owned());
        }
        assert_ne!(details[0], details[1]);
        assert_ne!(details[0], details[2]);
        assert_ne!(details[1], details[2]);
        let _ = std::fs::remove_dir_all(&probe_root);
    }

    #[test]
    fn runtime_error_strings_classify_to_documented_classes() {
        // Exact production strings from `runtime_loop.rs` and the
        // self-admission/spool/lease Display impls.
        assert_eq!(
            classify_runtime_error("SCM bootstrap is required for Runtime contour selection"),
            WatchdogStopCode::RuntimeBootstrapMissing
        );
        assert_eq!(
            classify_runtime_error("SCM bootstrap omitted the installer-approved Host state root"),
            WatchdogStopCode::RuntimeBootstrapMissing
        );
        assert_eq!(
            classify_runtime_error(
                "Watchdog SCM self-admission timed out after the bounded deadline"
            ),
            WatchdogStopCode::RuntimeSelfAdmission
        );
        assert_eq!(
            classify_runtime_error("current Watchdog process identity is unavailable"),
            WatchdogStopCode::RuntimeSelfAdmission
        );
        assert_eq!(
            classify_runtime_error("watchdog spool redb database: locked"),
            WatchdogStopCode::RuntimeAdmission
        );
        assert_eq!(
            classify_runtime_error("watchdog lease is stale: expired"),
            WatchdogStopCode::RuntimeAdmission
        );
        assert_eq!(
            classify_runtime_error(
                "approved Host SCM registration is not an exact read-only runtime match: Absent"
            ),
            WatchdogStopCode::RuntimeAdmission
        );
        assert_eq!(
            classify_runtime_error("watchdog admission was denied during shutdown"),
            WatchdogStopCode::RuntimeAdmission
        );
        assert_eq!(
            classify_runtime_error("tokio runtime construction failed: io error"),
            WatchdogStopCode::RuntimeSupervision
        );
    }

    #[test]
    fn transient_registry_lock_preserves_cause_and_retries_fence_poll() {
        use crate::runtime_loop::{
            FencePollDisposition, fence_poll_disposition, transient_lock_backoff,
        };
        use eliot_watchdog::{FileWatchdogAdmission, SpoolError};

        static TRANSIENT_LOCK_SERIAL: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let serial = TRANSIENT_LOCK_SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let lock_path = std::env::temp_dir().join(format!(
            "eliot-watchdog-transient-lock-{}-{serial}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&lock_path);
        // Genuine contention: hold a real writer `Database` open so the
        // read-only open fails with the production `DatabaseAlreadyOpen`
        // instead of canned text.
        let _writer = redb::Database::create(&lock_path)
            .unwrap_or_else(|error| panic!("transient-lock writer fixture: {error}"));
        let lock_error = match redb::ReadOnlyDatabase::open(&lock_path) {
            Ok(_) => panic!("held writer must block the read-only registry open"),
            Err(error) => error,
        };
        let lock_text = lock_error.to_string();
        assert!(
            lock_text.contains("already open"),
            "fixture must carry the real lock signal: {lock_text}"
        );
        assert!(
            lock_text.contains("Cannot acquire lock"),
            "fixture must carry the real lock cause: {lock_text}"
        );
        drop(lock_error);
        drop(_writer);
        let _ = std::fs::remove_file(&lock_path);

        // (a) The production wrap chain preserves the inner cause through
        // classification into the capsule without collapsing to 1066/9.
        let runtime_text = SpoolError::InvalidLease(lock_text.clone()).to_string();
        assert!(
            runtime_text.contains("watchdog lease is unavailable or invalid"),
            "wrap chain must keep the production prefix: {runtime_text}"
        );
        assert!(FileWatchdogAdmission::is_transient_registry_lock(
            &runtime_text
        ));
        // A same-process table defect without the lock marker stays
        // fail-closed: it is not transient contention.
        assert!(!FileWatchdogAdmission::is_transient_registry_lock(
            "watchdog lease is unavailable or invalid: Table 'registry' already opened at: test"
        ));
        let code = classify_runtime_error(&runtime_text);
        assert_eq!(code, WatchdogStopCode::RuntimeSupervision);
        assert_ne!(code, WatchdogStopCode::RuntimeAdmission);
        assert_eq!(code.specific(), 11);
        let capsule =
            build_start_failure_capsule(code, &runtime_text, Some("installation-7"), Some(7));
        assert!(
            capsule.contains("Cannot acquire lock"),
            "capsule must preserve the inner cause: {capsule}"
        );
        assert!(
            capsule.len() <= START_FAILURE_CAPSULE_MAX_BYTES,
            "capsule must stay bounded"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&capsule).unwrap_or_else(|error| panic!("capsule JSON: {error}"));
        assert_eq!(parsed["failure_class"], "runtime_supervision");
        assert_eq!(parsed["win32_exit_code"], 1066);
        assert_eq!(parsed["service_specific_exit_code"], 11);

        // (b) The real fence-poll disposition retries lock contention instead
        // of exiting, and still fails closed on real approval failures.
        for _ in 0..3 {
            assert_eq!(
                fence_poll_disposition(&runtime_text, &runtime_text),
                FencePollDisposition::RetryTransient
            );
        }
        // Contention on either read alone still retries: the waiter cannot
        // prove a fail-closed state while a read is lock-blocked.
        let real = "watchdog lease is unavailable or invalid: installer SCM registration approval is missing";
        assert_eq!(
            fence_poll_disposition(real, &runtime_text),
            FencePollDisposition::RetryTransient
        );
        assert_eq!(
            fence_poll_disposition(real, real),
            FencePollDisposition::FailClosed
        );
        assert!(!FileWatchdogAdmission::is_transient_registry_lock(real));
        assert_eq!(
            classify_runtime_error(real),
            WatchdogStopCode::RuntimeAdmission
        );
        // Backoff is bounded: base on the first streak, capped under
        // sustained contention.
        assert_eq!(
            transient_lock_backoff(0),
            std::time::Duration::from_millis(250)
        );
        assert_eq!(
            transient_lock_backoff(u32::MAX),
            std::time::Duration::from_millis(2_000)
        );
    }

    #[test]
    fn capsule_is_bounded_and_secret_free() {
        let code = WatchdogStopCode::RegistrationMismatch;
        let capsule =
            build_start_failure_capsule(code, &"x".repeat(4000), Some("installation-7"), Some(7));
        assert!(
            capsule.len() <= START_FAILURE_CAPSULE_MAX_BYTES,
            "capsule must stay bounded"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&capsule).unwrap_or_else(|error| panic!("capsule JSON: {error}"));
        assert_eq!(parsed["record_type"], "watchdog_start_failure");
        assert_eq!(parsed["service"], SERVICE_NAME);
        assert_eq!(parsed["failure_class"], "registration_mismatch");
        assert_eq!(parsed["win32_exit_code"], 1066);
        assert_eq!(parsed["service_specific_exit_code"], 6);
        assert_eq!(parsed["installation_id"], "installation-7");
        assert_eq!(parsed["tx_plan_generation"], 7);
        assert!(
            parsed["detail"]
                .as_str()
                .is_some_and(|detail| detail.chars().count() <= START_FAILURE_DETAIL_MAX_CHARS),
            "detail must be truncated"
        );
    }

    #[test]
    fn capsule_persist_roundtrip_never_carries_the_nonce() {
        let root = std::env::temp_dir().join(format!(
            "eliot-watchdog-stop-code-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("fixture root: {error}"));
        let nonce = "b".repeat(64);
        let bootstrap = ServiceBootstrapArguments::new(
            root.join("watchdog.json"),
            "a".repeat(64),
            "installation-7",
            7,
            std::iter::empty::<String>(),
        )
        .and_then(|value| value.with_host_state_root(&root))
        .and_then(|value| value.with_registration_nonce(nonce.clone()))
        .unwrap_or_else(|error| panic!("bootstrap fixture: {error}"));
        persist_start_failure(
            WatchdogStopCode::ApprovalMismatch,
            "bootstrap does not match the installer-approved registration",
            Some(&bootstrap),
        );
        let stored = std::fs::read_to_string(root.join(START_FAILURE_CAPSULE_FILE_NAME))
            .unwrap_or_else(|error| panic!("capsule readback: {error}"));
        assert!(
            !stored.contains(&nonce),
            "the registration nonce must never be persisted"
        );
        assert!(stored.contains("approval_mismatch"));
        assert!(stored.contains("installation-7"));
        assert!(stored.len() <= START_FAILURE_CAPSULE_MAX_BYTES);
        let _ = std::fs::remove_file(root.join(START_FAILURE_CAPSULE_FILE_NAME));
        let _ = std::fs::remove_dir(&root);
    }
}
