//! SCM launch contract for the independent Watchdog.
//!
//! Architecture: A8, ARCH-WDG-01, ARCH-WDG-02, A13.2
//! Implementation: I1.2, I1.4, I1.5, I8, B.5
//!
//! Watchdog is an independent failure domain. SCM bootstrap validates approved
//! identity and never becomes a semantic oracle.

use std::ffi::OsString;
use std::path::PathBuf;

use eliot_installation::{InstallerServiceRegistrationApproval, InstallerServiceRole};
use eliot_platform_windows::{
    ServiceBootstrapArguments, ServiceRegistrationRequest, WindowsAdapterError, WindowsPlatform,
    windows_paths_equal,
};
use thiserror::Error;

use crate::{
    SERVICE_NAME, SpoolError, WatchdogRuntimeReadback, project_service_runtime_inspection,
    read_approved_service_registration,
};

/// Failure while validating the immutable argv contract supplied by SCM.
#[derive(Debug, Error)]
pub enum WatchdogScmLaunchError {
    #[error("invalid Watchdog SCM argv: {0}")]
    InvalidArgv(String),
    #[error("Watchdog SCM executable: {0}")]
    Executable(#[source] std::io::Error),
    #[error("Watchdog SCM platform inspection: {0}")]
    Platform(#[from] WindowsAdapterError),
    #[error("Watchdog SCM platform root: {0}")]
    PlatformRoot(String),
    #[error("Watchdog SCM registration is not an exact read-only runtime match: {0:?}")]
    Registration(WatchdogRuntimeReadback),
    #[error("Watchdog SCM installer approval is unavailable or invalid")]
    ApprovalUnavailable,
    #[error("Watchdog SCM bootstrap does not match the installer-approved registration")]
    ApprovalMismatch,
}

/// Exact, read-only launch evidence accepted from the Windows Service Control
/// Manager.  The registration request is retained only as an inspection query;
/// this type exposes no SCM mutation operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWatchdogScmLaunch {
    bootstrap: ServiceBootstrapArguments,
    registration: ServiceRegistrationRequest,
    inspection: WatchdogRuntimeReadback,
}

impl ValidatedWatchdogScmLaunch {
    #[must_use]
    pub fn bootstrap(&self) -> &ServiceBootstrapArguments {
        &self.bootstrap
    }

    #[must_use]
    pub fn registration(&self) -> &ServiceRegistrationRequest {
        &self.registration
    }

    #[must_use]
    pub fn inspection(&self) -> &WatchdogRuntimeReadback {
        &self.inspection
    }
}

/// Opaque Host registration proof retained by the Watchdog observer.
///
/// The contained request is reconstructed from the installer projection and
/// has no public field or nonce accessor. It can therefore cross the library
/// to the binary composition root only as an inspection capability, never as
/// a caller-supplied SCM authority.
#[derive(Clone, Debug)]
pub struct ApprovedHostRegistration {
    pub(crate) request: ServiceRegistrationRequest,
}

impl ApprovedHostRegistration {
    pub(crate) fn from_approval(
        approval: &InstallerServiceRegistrationApproval,
    ) -> Result<Self, SpoolError> {
        if approval.role() != InstallerServiceRole::Host {
            return Err(SpoolError::InvalidLease(
                "installer SCM approval is not a Host registration".to_owned(),
            ));
        }
        let request = approval.service_registration_request().map_err(|_| {
            SpoolError::InvalidLease("installer Host SCM approval is invalid".to_owned())
        })?;
        if request.service_name() != eliot_platform_windows::ELIOT_HOST_SERVICE_NAME {
            return Err(SpoolError::InvalidLease(
                "installer Host SCM approval has the wrong service name".to_owned(),
            ));
        }
        Ok(Self { request })
    }
}

/// Parses the complete argv vector delivered to the SCM service callback.
///
/// `argv[0]` must be the canonical service name and the remaining twelve
/// values must be exactly the ordered bootstrap pairs rendered by
/// [`ServiceBootstrapArguments`], including the installer-approved
/// per-installation Host root and registration nonce. No optional or unknown
/// arguments are accepted for the installed service.
///
/// # Errors
///
/// Returns a typed error when SCM supplies a malformed, reordered, substituted,
/// or incomplete launch vector.
pub fn parse_watchdog_scm_argv<I, S>(
    args: I,
) -> Result<ServiceBootstrapArguments, WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.len() != 13 {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "expected service name plus six canonical pairs".to_owned(),
        ));
    }
    if args[0].to_str() != Some(SERVICE_NAME) {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "service name is not EliotWatchdog".to_owned(),
        ));
    }
    let flag = |index: usize, expected: &str| {
        args.get(index)
            .and_then(|value| value.to_str())
            .is_some_and(|actual| actual == expected)
    };
    if !flag(1, "--config-descriptor")
        || !flag(3, "--config-descriptor-sha256")
        || !flag(5, "--installation-id")
        || !flag(7, "--tx-plan-generation")
        || !flag(9, "--host-state-root")
        || !flag(11, "--registration-nonce")
    {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "bootstrap flags are missing, reordered, or substituted".to_owned(),
        ));
    }

    let descriptor_path = PathBuf::from(&args[2]);
    if !descriptor_path.is_absolute()
        || descriptor_path.as_os_str().is_empty()
        || descriptor_path
            .to_str()
            .is_none_or(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "config descriptor path must be absolute and valid".to_owned(),
        ));
    }
    let host_state_root = PathBuf::from(&args[10]);
    if !host_state_root.is_absolute()
        || host_state_root.as_os_str().is_empty()
        || host_state_root
            .to_str()
            .is_none_or(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "Host state root must be absolute and valid".to_owned(),
        ));
    }
    let text = |index: usize, field: &str| {
        args[index]
            .to_str()
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .map(str::to_owned)
            .ok_or_else(|| {
                WatchdogScmLaunchError::InvalidArgv(format!("{field} is not valid text"))
            })
    };
    let descriptor_digest = text(4, "config descriptor digest")?;
    let installation_id = text(6, "installation id")?;
    let generation_text = text(8, "transaction plan generation")?;
    let registration_nonce = text(12, "registration nonce")?;
    let generation = generation_text.parse::<u64>().map_err(|_| {
        WatchdogScmLaunchError::InvalidArgv(
            "transaction plan generation must be non-zero".to_owned(),
        )
    })?;
    if generation == 0 {
        return Err(WatchdogScmLaunchError::InvalidArgv(
            "transaction plan generation must be non-zero".to_owned(),
        ));
    }
    let bootstrap = ServiceBootstrapArguments::new(
        descriptor_path,
        descriptor_digest,
        installation_id,
        generation,
        std::iter::empty::<String>(),
    )
    .map_err(|error| WatchdogScmLaunchError::InvalidArgv(error.to_string()))?
    .with_host_state_root(host_state_root)
    .map_err(|error| WatchdogScmLaunchError::InvalidArgv(error.to_string()))?
    .with_registration_nonce(registration_nonce)
    .map_err(|error| WatchdogScmLaunchError::InvalidArgv(error.to_string()))?;
    Ok(bootstrap)
}

/// Parses the process command line that contains the immutable SCM image-path
/// bootstrap. Windows passes `ServiceMain` a separate argv vector: its
/// `argv[0]` is the service name and its remaining values are only the
/// arguments supplied to `StartService`. See
/// <https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-servicemain>.
///
/// # Errors
///
/// Returns an error when the process arguments do not form the exact
/// canonical bootstrap.
pub fn parse_watchdog_process_argv<I, S>(
    args: I,
) -> Result<ServiceBootstrapArguments, WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut full = vec![OsString::from(SERVICE_NAME)];
    full.extend(args.into_iter().map(Into::into));
    parse_watchdog_scm_argv(full)
}

/// Validates the distinct `ServiceMain` callback argv. Auto-start must provide
/// only the canonical service name; bootstrap values are parsed from the
/// process command line by [`parse_watchdog_process_argv`].
///
/// # Errors
///
/// Returns an error when the callback vector contains anything other than the
/// canonical service name.
pub fn validate_watchdog_service_main_argv<I, S>(args: I) -> Result<(), WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.len() == 1 && args[0].to_str() == Some(SERVICE_NAME) {
        Ok(())
    } else {
        Err(WatchdogScmLaunchError::InvalidArgv(
            "ServiceMain argv must contain only EliotWatchdog".to_owned(),
        ))
    }
}

/// Parses SCM argv, rebuilds the canonical registration request, and performs
/// only the platform adapter's read-only registration inspection.
///
/// # Errors
///
/// Returns an error for malformed argv, an unavailable current executable, or
/// any non-matching/unknown SCM registration. This function never calls an SCM
/// mutation API.
pub fn validate_watchdog_scm_launch<I, S>(
    args: I,
) -> Result<ValidatedWatchdogScmLaunch, WatchdogScmLaunchError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let bootstrap = parse_watchdog_scm_argv(args)?;
    validate_watchdog_scm_bootstrap(&bootstrap)
}

/// Rebuilds and read-only-inspects the canonical Watchdog SCM registration
/// from the process bootstrap. This is intentionally separate from
/// `ServiceMain` argv validation because the two Windows vectors have
/// different origins and semantics.
///
/// # Errors
///
/// Returns an error when the current executable, canonical registration
/// request, or read-only SCM registration inspection is invalid or unknown.
pub fn validate_watchdog_scm_bootstrap(
    bootstrap: &ServiceBootstrapArguments,
) -> Result<ValidatedWatchdogScmLaunch, WatchdogScmLaunchError> {
    let (_, _, registration) =
        read_approved_service_registration(bootstrap, InstallerServiceRole::Watchdog)
            .map_err(|_| WatchdogScmLaunchError::ApprovalUnavailable)?;
    let executable = std::env::current_exe().map_err(WatchdogScmLaunchError::Executable)?;
    if registration.service_name() != SERVICE_NAME
        || registration.bootstrap() != Some(bootstrap)
        || !windows_paths_equal(registration.binary_path(), &executable)
    {
        return Err(WatchdogScmLaunchError::ApprovalMismatch);
    }
    let root = executable.parent().ok_or_else(|| {
        WatchdogScmLaunchError::InvalidArgv("current executable has no parent".to_owned())
    })?;
    let platform = WindowsPlatform::new(root.to_path_buf())
        .map_err(|error| WatchdogScmLaunchError::PlatformRoot(error.to_string()))?;
    let inspection = project_service_runtime_inspection(
        platform.inspect_service_registration_runtime(&registration),
    );
    if matches!(
        inspection,
        WatchdogRuntimeReadback::Absent | WatchdogRuntimeReadback::Mismatched
    ) {
        return Err(WatchdogScmLaunchError::Registration(inspection));
    }
    Ok(ValidatedWatchdogScmLaunch {
        bootstrap: bootstrap.clone(),
        registration,
        inspection,
    })
}
