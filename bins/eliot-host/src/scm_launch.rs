//! Read-only validation of the canonical Host SCM launch registration.

use eliot_platform::ServiceState;
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceBootstrapArguments, ServiceRegistrationRequest, ServiceRegistrationRuntimeInspection,
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
/// The runtime [`ServiceRegistrationRuntimeInspection`] reports `Mismatched`
/// as a unit variant without field-level detail, so a binary-command/account
/// drift and a service-object security-descriptor (default-DACL, no
/// service-SID ACE) drift are indistinguishable at this layer; the
/// `Mismatched` detail text says so instead of guessing. This enum surfaces
/// exactly what IS observable — the variant plus its Debug text, with the
/// request-bound identity bindings for `Absent` — without redefining platform
/// types. Field-level mismatch detail remains a platform-owner gap (WRITER-A).
/// Every variant is fail-closed: [`validate_host_scm_bootstrap`] rejects
/// bootstrap on all of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostScmRegistrationCause {
    /// The canonical service name is not registered. Carries the request-bound
    /// identity (queried name plus admitted configuration digest, both
    /// non-secret) so the absence stays bound to the exact query. The runtime
    /// contour reports `Absent` as a unit variant without a live proof object,
    /// so the bindings are taken from the validated registration request.
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
                "host-scm-registration-mismatched: service '{ELIOT_HOST_SERVICE_NAME}' exists but its SCM configuration, service-SID type, or service-object security descriptor does not exactly match the canonical request (platform inspection reports Mismatched without field-level detail; inspection: {inspection_debug})",
            ),
            Self::Unknown { inspection_debug } => format!(
                "host-scm-registration-unknown: service '{ELIOT_HOST_SERVICE_NAME}' SCM configuration and state are not authoritatively observable via runtime contour inspect_service_registration_runtime (fail-closed; possible access-denied readback or provider uncertainty; SACL never requested, platform DACL-only readback; inspection: {inspection_debug})",
            ),
        };
        truncate_host_scm_cause(&text)
    }
}

/// Whether a runtime `Matching` observation state is admissible as a valid
/// Host bootstrap at `ServiceMain` time.
///
/// `Stopped`, `Starting`, and `Running` are accepted: `ServiceMain` runs while
/// SCM reports `START_PENDING` with a live PID, so requiring `Stopped` would
/// deterministically reject a healthy start. Every other state (`Stopping`,
/// `Unknown`, `Absent`, `Failed`) is inadmissible and maps to a fail-closed
/// `Unknown` cause in [`classify_host_scm_inspection`].
///
/// This predicate is the exact gate the `Matching { observation }` arm uses.
/// It takes the public [`ServiceState`] (not the platform-owned
/// `ServiceRuntimeObservation`, whose fields are `pub(super)` and cannot be
/// constructed outside `eliot-platform-windows`) so the Starting-acceptance
/// rule stays directly unit-testable without live SCM calls.
#[must_use]
pub const fn host_runtime_bootstrap_state_is_admissible(state: ServiceState) -> bool {
    matches!(
        state,
        ServiceState::Stopped | ServiceState::Starting | ServiceState::Running
    )
}

/// Pure projection from a platform runtime registration inspection to the
/// typed host-side cause. Returns `None` only for an admissible `Matching`
/// observation; every other outcome maps to its fail-closed cause, so
/// `Mismatched` (including a default-DACL security-descriptor drift) can
/// never collapse into `Unknown`.
///
/// s40: Host `ServiceMain` runs while SCM reports `START_PENDING` with a live
/// PID. The non-runtime contour (`WindowsPlatform::inspect_service_registration`,
/// `crates/kernel/eliot-platform-windows/src/lib.rs:5427`) maps any PID != 0
/// readback through `inspect_service` (`lib.rs:5555`), which returns `Partial`
/// for every PID != 0 (`lib.rs:5624-5640`), to unit `Unknown` via
/// `service_registration_inspection_from_status` (`lib.rs:5532-5545`). A
/// healthy Starting host therefore deterministically failed closed with
/// 1066/3 (`bins/eliot-host/src/main.rs:588-600`,
/// `HostStopCode::InvalidRegistration` specific 3), while the installer
/// readback (`STOPPED`, PID 0) returned `Known` -> `Matching`. The runtime
/// contour (`WindowsPlatform::inspect_service_registration_runtime`,
/// `lib.rs:4938`) handles `Starting` + PID as `Matching` via
/// `classify_service_runtime_observation` (`lib.rs:4881-4921`) with two-sample
/// stability, matching the Watchdog path
/// (`bins/eliot-watchdog/src/scm_launch.rs:323-331`). SACL `S:(AU;FA;;;WD)`
/// is never requested: platform `GetSecurityInfo` reads are DACL-only
/// (`lib.rs:4019,4152`).
///
/// WRITER-A carry-over (s40 integration): platform `Unknown` is the typed
/// payload `Unknown { detail: ServiceInspectionUnknownDetail }` (Writer-A).
/// This is the sole inspection-to-cause mapping site; the `Unknown` arm
/// matches `Unknown { detail }` and preserves `detail.win32_error`,
/// `detail.stage`, `detail.current_state`, and `detail.process_id` via the
/// explicit typed rendering plus the platform Debug text verbatim (truncated
/// to [`HOST_SCM_CAUSE_MAX_CHARS`]). Fail-closed is unchanged: `Unknown`
/// never maps to `None`, never to `Matching`, and never collapses
/// `Mismatched`.
#[must_use]
pub fn classify_host_scm_inspection(
    request: &ServiceRegistrationRequest,
    inspection: &ServiceRegistrationRuntimeInspection,
) -> Option<HostScmRegistrationCause> {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if host_runtime_bootstrap_state_is_admissible(observation.state()) =>
        {
            None
        }
        ServiceRegistrationRuntimeInspection::Matching { .. } => {
            Some(HostScmRegistrationCause::Unknown {
                inspection_debug: format!("{inspection:?}"),
            })
        }
        ServiceRegistrationRuntimeInspection::Absent => Some(HostScmRegistrationCause::Absent {
            service_name: request.service_name().to_owned(),
            configuration_digest: request.expected_configuration_digest(),
        }),
        ServiceRegistrationRuntimeInspection::Mismatched => {
            Some(HostScmRegistrationCause::Mismatched {
                inspection_debug: format!("{inspection:?}"),
            })
        }
        ServiceRegistrationRuntimeInspection::Unknown { detail } => {
            // Typed payload carry-over: preserve win32_error/stage/state/pid
            // explicitly via the typed rendering plus Debug verbatim. Both
            // stay bounded through truncate_host_scm_cause downstream.
            // SACL is never requested (platform DACL-only); Unknown stays
            // fail-closed 1066/3.
            Some(HostScmRegistrationCause::Unknown {
                inspection_debug: format!("{} | {inspection:?}", detail.detail()),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostScmLaunch {
    bootstrap: ServiceBootstrapArguments,
    registration: ServiceRegistrationRequest,
    inspection: ServiceRegistrationRuntimeInspection,
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
    pub fn inspection(&self) -> &ServiceRegistrationRuntimeInspection {
        &self.inspection
    }
}

/// Rebuilds and read-only-inspects the canonical Host SCM registration from
/// the validated launch options. Host never registers or starts its own SCM
/// service; the installer is the sole registration owner.
///
/// The readback uses the runtime contour
/// (`WindowsPlatform::inspect_service_registration_runtime`), which accepts
/// `Stopped`, `Starting`, and `Running` observations with valid
/// configuration plus grant at `ServiceMain` time. `Starting` is valid: the
/// host process is already running while SCM still reports `START_PENDING`.
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
    let inspection = platform.inspect_service_registration_runtime(&registration);
    if let Some(cause) = classify_host_scm_inspection(&registration, &inspection) {
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

    fn test_registration_request() -> ServiceRegistrationRequest {
        let image = std::env::current_exe().unwrap_or_else(|_| panic!("test image unavailable"));
        ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|_| panic!("test registration request must build"))
    }

    #[test]
    fn default_dacl_mismatched_sd_classifies_as_mismatched_not_unknown() {
        // A default-DACL service (Windows default service DACL, not
        // protected, no service-SID ACE) reaches the platform readback as a
        // unit `Mismatched`: configuration/SID-type/service-DACL comparison
        // differs. The host projection must preserve that cause instead of
        // collapsing Absent/Mismatched/Unknown into one string.
        let request = test_registration_request();
        let mismatched = classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Mismatched,
        )
        .unwrap_or_else(|| panic!("mismatched inspection must classify"));
        assert_eq!(
            mismatched,
            HostScmRegistrationCause::Mismatched {
                inspection_debug: "Mismatched".to_owned(),
            }
        );
        assert_eq!(mismatched.cause(), "mismatched");
        // Writer-A payload carry-over: Unknown is now typed Unknown{detail}.
        // The host projection preserves win32_error/stage/state/pid via the
        // explicit typed rendering plus Debug verbatim, still fail-closed.
        let unknown_inspection =
            ServiceRegistrationRuntimeInspection::unknown_with_status(5, "open-service", 3, 1234);
        let unknown_detail_typed = unknown_inspection
            .unknown_detail()
            .unwrap_or_else(|| panic!("unknown inspection must carry diagnostics"));
        assert_eq!(unknown_detail_typed.win32_error(), 5);
        assert_eq!(unknown_detail_typed.stage(), "open-service");
        assert_eq!(unknown_detail_typed.current_state(), Some(3));
        assert_eq!(unknown_detail_typed.process_id(), Some(1234));
        let unknown = classify_host_scm_inspection(&request, &unknown_inspection)
            .unwrap_or_else(|| panic!("unknown inspection must classify"));
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
        // Typed preservation: the bounded cause carries win32_error/stage/
        // state/pid plus Debug verbatim.
        assert!(
            unknown_detail.contains("open-service"),
            "unknown cause must preserve stage: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains('5'),
            "unknown cause must preserve win32_error: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("Unknown"),
            "unknown cause must carry Debug verbatim: {unknown_detail}"
        );
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

    #[test]
    fn runtime_starting_is_admissible_while_mismatch_and_unknown_stay_typed() {
        // s40: `ServiceMain` runs while SCM reports `START_PENDING` with a
        // live PID. The `Matching` arm of `classify_host_scm_inspection`
        // accepts `Starting` via `host_runtime_bootstrap_state_is_admissible`.
        // `ServiceRuntimeObservation` fields are `pub(super)` to the platform
        // crate, so no `Matching { observation }` value can be constructed
        // here; the admissibility predicate IS the exact gate the `Matching`
        // arm uses, and the fail-closed arms are proven below with directly
        // constructible inspection variants (Mismatched unit, typed Unknown
        // payload). No SCM calls, no mocks.
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Starting
        ));
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Stopped
        ));
        assert!(host_runtime_bootstrap_state_is_admissible(
            ServiceState::Running
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Stopping
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Unknown
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Absent
        ));
        assert!(!host_runtime_bootstrap_state_is_admissible(
            ServiceState::Failed
        ));

        let request = test_registration_request();
        let mismatched = classify_host_scm_inspection(
            &request,
            &ServiceRegistrationRuntimeInspection::Mismatched,
        )
        .unwrap_or_else(|| panic!("mismatched inspection must classify"));
        // Writer-A payload: Unknown carries typed win32_error/stage/state/pid.
        let unknown_inspection = ServiceRegistrationRuntimeInspection::unknown_with_status(
            1066,
            "query-status",
            3,
            4242,
        );
        let unknown_typed = unknown_inspection
            .unknown_detail()
            .unwrap_or_else(|| panic!("unknown inspection must carry diagnostics"));
        assert_eq!(unknown_typed.win32_error(), 1066);
        assert_eq!(unknown_typed.stage(), "query-status");
        assert_eq!(unknown_typed.current_state(), Some(3));
        assert_eq!(unknown_typed.process_id(), Some(4242));
        let unknown = classify_host_scm_inspection(&request, &unknown_inspection)
            .unwrap_or_else(|| panic!("unknown inspection must classify"));
        assert_eq!(mismatched.cause(), "mismatched");
        assert_eq!(unknown.cause(), "unknown");
        assert_ne!(mismatched, unknown);
        let mismatched_detail = mismatched.detail();
        let unknown_detail = unknown.detail();
        assert_ne!(mismatched_detail, unknown_detail);
        assert!(mismatched_detail.contains("host-scm-registration-mismatched"));
        assert!(mismatched_detail.contains("inspection:"));
        assert!(mismatched_detail.contains("Mismatched"));
        assert!(unknown_detail.contains("host-scm-registration-unknown"));
        assert!(unknown_detail.contains("inspection:"));
        assert!(unknown_detail.contains("Unknown"));
        // Typed s40-1 diagnostics: the Unknown detail names the runtime
        // contour used and records that SACL was never requested, while
        // carrying the platform Debug text verbatim plus the explicit typed
        // win32_error/stage/state/pid rendering.
        assert!(
            unknown_detail.contains("inspect_service_registration_runtime"),
            "unknown detail must name the runtime contour: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("SACL"),
            "unknown detail must record that SACL was never requested: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("query-status"),
            "unknown detail must preserve stage: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("1066"),
            "unknown detail must preserve win32_error: {unknown_detail}"
        );
        assert!(
            unknown_detail.contains("4242"),
            "unknown detail must preserve pid: {unknown_detail}"
        );
        for detail in [&mismatched_detail, &unknown_detail] {
            assert!(
                detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
                "cause detail must stay bounded"
            );
        }

        // The runtime `Absent` unit variant binds the request identity
        // (service name plus configuration digest) into the cause.
        let absent =
            classify_host_scm_inspection(&request, &ServiceRegistrationRuntimeInspection::Absent)
                .unwrap_or_else(|| panic!("absent inspection must classify"));
        assert_eq!(absent.cause(), "absent");
        let absent_detail = absent.detail();
        assert!(absent_detail.contains("host-scm-registration-absent"));
        assert!(absent_detail.contains(request.service_name()));
        assert!(absent_detail.contains(&request.expected_configuration_digest()));
        assert!(
            absent_detail.chars().count() <= HOST_SCM_CAUSE_MAX_CHARS,
            "absent detail must stay bounded"
        );
        assert_ne!(absent_detail, mismatched_detail);
        assert_ne!(absent_detail, unknown_detail);
    }
}
