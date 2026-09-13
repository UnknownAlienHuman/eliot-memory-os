//! Read-only validation of the canonical Host SCM launch registration.

use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceBootstrapArguments, ServiceRegistrationInspection, ServiceRegistrationRequest,
    ServiceStartMode, WindowsPlatform,
};

use super::{HostError, HostLaunchOptions};

/// Per-cause ceiling for the free-text SCM classification detail carried into
/// stderr and the start-failure capsule. This mirrors the Watchdog
/// `APPROVAL_DETAIL_MAX_CHARS` budget (the same 512-char width as the Host
/// capsule detail field) so the typed failure class stays stable while the
/// precise cause survives truncation secret-free. Host-owned; no cross-crate
/// sharing.
pub const HOST_SCM_CAUSE_MAX_CHARS: usize = 512;

fn truncate_host_scm_cause(value: &str) -> String {
    if value.chars().count() > HOST_SCM_CAUSE_MAX_CHARS {
        value.chars().take(HOST_SCM_CAUSE_MAX_CHARS).collect()
    } else {
        value.to_owned()
    }
}

/// Typed host-side cause for a non-matching Host SCM registration inspection.
///
/// The platform [`ServiceRegistrationInspection`] reports `Mismatched` as a
/// unit variant without field-level detail, so a binary-command/account drift
/// and a service-object security-descriptor (default-DACL, no service-SID
/// ACE) drift are indistinguishable at this layer; the `Mismatched` detail
/// text says so instead of guessing. This enum surfaces exactly what IS
/// observable — the variant plus its Debug text, with the live absence-proof
/// bindings for `Absent` — without redefining platform types. Field-level
/// mismatch detail remains a platform-owner gap (WRITER-A). Every variant is
/// fail-closed: [`validate_host_scm_bootstrap`] rejects bootstrap on all of
/// them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostScmRegistrationCause {
    /// The canonical service name is not registered. Carries the live
    /// absence-proof bindings (queried name plus admitted configuration
    /// digest, both non-secret) so the absence stays bound to the exact
    /// query.
    Absent {
        service_name: String,
        configuration_digest: String,
    },
    /// A service exists at the canonical name with different configuration.
    /// Carries the platform Debug text; the platform reports no
    /// SD-versus-config field breakdown.
    Mismatched { inspection_debug: String },
    /// SCM could not provide authoritative configuration and state readback
    /// (possible access-denied readback under the service account, or
    /// provider uncertainty). Still fail-closed.
    Unknown { inspection_debug: String },
}

impl HostScmRegistrationCause {
    /// Stable machine-readable cause name for stderr/capsule grepability.
    #[must_use]
    pub const fn cause(&self) -> &'static str {
        match self {
            Self::Absent { .. } => "absent",
            Self::Mismatched { .. } => "mismatched",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Bounded secret-free detail for stderr and the start-failure capsule.
    ///
    /// Carries only the canonical service name, the non-secret configuration
    /// digest (absent cause), and the platform variant/Debug text. Bootstrap
    /// paths, nonces, and digests beyond the SCM configuration digest never
    /// enter this string; output is truncated to
    /// [`HOST_SCM_CAUSE_MAX_CHARS`] characters.
    #[must_use]
    pub fn detail(&self) -> String {
        let text = match self {
            Self::Absent {
                service_name,
                configuration_digest,
            } => format!(
                "host-scm-registration-absent: service '{service_name}' is not registered (configuration {configuration_digest})"
            ),
            Self::Mismatched { inspection_debug } => format!(
                "host-scm-registration-mismatched: service '{}' exists but its SCM configuration, service-SID type, or service-object security descriptor does not exactly match the canonical request (platform inspection reports Mismatched without field-level detail; inspection: {inspection_debug})",
                ELIOT_HOST_SERVICE_NAME,
            ),
            Self::Unknown { inspection_debug } => format!(
                "host-scm-registration-unknown: service '{}' SCM configuration and state are not authoritatively observable (fail-closed; possible access-denied readback or provider uncertainty; inspection: {inspection_debug})",
                ELIOT_HOST_SERVICE_NAME,
            ),
        };
        truncate_host_scm_cause(&text)
    }
}

/// Pure projection from a platform registration inspection to the typed
/// host-side cause. Returns `None` only for `Matching`; every other variant
/// maps to its fail-closed cause, so `Mismatched` (including a default-DACL
/// security-descriptor drift) can never collapse into `Unknown`.
#[must_use]
pub fn classify_host_scm_inspection(
    inspection: &ServiceRegistrationInspection,
) -> Option<HostScmRegistrationCause> {
    match inspection {
        ServiceRegistrationInspection::Matching { .. } => None,
        ServiceRegistrationInspection::Absent { proof } => {
            Some(HostScmRegistrationCause::Absent {
                service_name: proof.service_name().to_owned(),
                configuration_digest: proof.configuration_digest().to_owned(),
            })
        }
        ServiceRegistrationInspection::Mismatched => Some(HostScmRegistrationCause::Mismatched {
            inspection_debug: format!("{inspection:?}"),
        }),
        ServiceRegistrationInspection::Unknown => Some(HostScmRegistrationCause::Unknown {
            inspection_debug: format!("{inspection:?}"),
        }),
    }
}

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
/// A non-matching inspection yields the typed [`HostScmRegistrationCause`]
/// detail (`absent`, `mismatched`, or `unknown`); all three reject bootstrap
/// fail-closed under the existing `invalid_scm_registration` stop class.
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
    if let Some(cause) = classify_host_scm_inspection(&inspection) {
        return Err(HostError::Platform(cause.detail()));
    }
    Ok(ValidatedHostScmLaunch {
        bootstrap,
        registration,
        inspection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dacl_mismatched_sd_classifies_as_mismatched_not_unknown() {
        // A default-DACL service (Windows default service DACL, not
        // protected, no service-SID ACE) reaches the platform readback as a
        // unit `Mismatched`: configuration/SID-type/service-DACL comparison
        // differs. The host projection must preserve that cause instead of
        // collapsing Absent/Mismatched/Unknown into one string.
        let mismatched =
            classify_host_scm_inspection(&ServiceRegistrationInspection::Mismatched)
                .expect("mismatched inspection must classify");
        assert_eq!(
            mismatched,
            HostScmRegistrationCause::Mismatched {
                inspection_debug: "Mismatched".to_owned(),
            }
        );
        assert_eq!(mismatched.cause(), "mismatched");
        let unknown = classify_host_scm_inspection(&ServiceRegistrationInspection::Unknown)
            .expect("unknown inspection must classify");
        assert_eq!(
            unknown,
            HostScmRegistrationCause::Unknown {
                inspection_debug: "Unknown".to_owned(),
            }
        );
        assert_eq!(unknown.cause(), "unknown");
        assert_ne!(mismatched, unknown);
        let mismatched_detail = mismatched.detail();
        let unknown_detail = unknown.detail();
        assert_eq!(
            mismatched_detail,
            "host-scm-registration-mismatched: service 'EliotHost' exists but its SCM configuration, service-SID type, or service-object security descriptor does not exactly match the canonical request (platform inspection reports Mismatched without field-level detail; inspection: Mismatched)"
        );
        assert_ne!(mismatched_detail, unknown_detail);
        assert!(mismatched_detail.contains("host-scm-registration-mismatched"));
        assert!(unknown_detail.contains("host-scm-registration-unknown"));
        for detail in [&mismatched_detail, &unknown_detail] {
            assert!(
                !detail.contains("is not an exact read-only match"),
                "the old collapsed string must be gone: {detail}"
            );
            assert!(
                detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
                "cause detail must stay bounded"
            );
        }
        // The bound itself is defense-in-depth for a future platform Debug
        // payload, not just today's unit-variant text.
        assert_eq!(
            truncate_host_scm_cause(&"d".repeat(4000)).chars().count(),
            HOST_SCM_CAUSE_MAX_CHARS
        );
    }
}
