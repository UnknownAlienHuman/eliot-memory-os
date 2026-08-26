//! Read-only validation of the canonical Host SCM launch registration.

use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceBootstrapArguments, ServiceRegistrationInspection, ServiceRegistrationRequest,
    ServiceStartMode, WindowsPlatform,
};

use super::{HostError, HostLaunchOptions};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostScmLaunch {
    bootstrap: ServiceBootstrapArguments,
    registration: ServiceRegistrationRequest,
    inspection: ServiceRegistrationInspection,
}

impl ValidatedHostScmLaunch {
    #[must_use]
    pub fn bootstrap(&self) -> &ServiceBootstrapArguments {
        &self.bootstrap
    }

    #[must_use]
    pub fn registration(&self) -> &ServiceRegistrationRequest {
        &self.registration
    }

    #[must_use]
    pub fn inspection(&self) -> &ServiceRegistrationInspection {
        &self.inspection
    }
}

/// Rebuilds and read-only-inspects the canonical Host SCM registration from
/// the validated launch options. Host never registers or starts its own SCM
/// service; the installer is the sole registration owner.
///
/// # Errors
///
/// Returns an error when the current executable, canonical registration
/// request, or read-only SCM registration inspection is invalid or unknown.
pub fn validate_host_scm_bootstrap(
    launch_options: &HostLaunchOptions,
) -> Result<ValidatedHostScmLaunch, HostError> {
    let registration_nonce = launch_options.registration_nonce().ok_or_else(|| {
        HostError::Platform("SystemService requires the registration nonce pair".to_owned())
    })?;
    let bootstrap = ServiceBootstrapArguments::new(
        launch_options.config_descriptor_path().to_path_buf(),
        launch_options
            .config_descriptor_digest()
            .as_str()
            .to_owned(),
        launch_options.installation().as_str().to_owned(),
        launch_options.transaction_plan_generation(),
        std::iter::empty::<String>(),
    )
    .map_err(|error| HostError::Platform(error.to_string()))?
    .with_host_state_root(launch_options.host_state_root().to_path_buf())
    .map_err(|error| HostError::Platform(error.to_string()))?
    .with_registration_nonce(registration_nonce.as_str().to_owned())
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let executable =
        std::env::current_exe().map_err(|error| HostError::Platform(error.to_string()))?;
    let registration = ServiceRegistrationRequest::with_bootstrap(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        executable.clone(),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap.clone(),
    )
    .map_err(|error| HostError::Platform(error.to_string()))?;
    let root = executable
        .parent()
        .ok_or_else(|| HostError::Platform("current executable has no parent".to_owned()))?;
    let platform = WindowsPlatform::new(root.to_path_buf())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let inspection = platform.inspect_service_registration(&registration);
    if !matches!(inspection, ServiceRegistrationInspection::Matching { .. }) {
        return Err(HostError::Platform(format!(
            "Host SCM registration is not an exact read-only match: {inspection:?}"
        )));
    }
    Ok(ValidatedHostScmLaunch {
        bootstrap,
        registration,
        inspection,
    })
}
