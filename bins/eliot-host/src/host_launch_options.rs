//! Exact Host launch argv parsing and typed accessors.
//!
//! This cell owns only parsing the already-approved Host launch argv into typed
//! values. It has no start/stop/restart/kill, lifecycle, reconciliation,
//! transaction, SCM mutation, semantic/canonical, credential, or publication
//! authority.
//!
//! Architecture anchors: `A5.5` scopes verifier inputs and failure
//! applicability; `A13.2` separates physical Host lifecycle from Kernel
//! authority; `A13.8` requires explicit integrity and provenance review.
//! Implementation anchors: `I1.2` assigns Host process lifecycle without
//! project semantics; `I1.8` defines exact ownership and `HostState` separation;
//! `I2.19` keeps a module cell's parser boundary narrow; `I18.1` assigns
//! parsers normalization only.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::ELIOT_HOST_SERVICE_NAME;

use super::super::HostError;
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) launch-options observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. A call site passes a static phase token plus a bounded
// `LaunchPhaseCorrelation` built only from values the owner already holds, each
// rendered through `crate::host_diagnostics::bound_field`: a static label
// classifies the phase, while the bounded identities name which installation,
// generation and config-descriptor digest produced it. No field is
// re-derived, probed or recomputed for a record: the bound identities are pure
// borrows of the admitted value (`host_launch_options_admitted_correlation`).
// `config_descriptor_path`, `host_state_root`, argv text and
// `registration_nonce` are never bound — paths, argv and nonce material stay
// out of diagnostics (I15.4, case 978/12) — and no arbitrary error
// `Debug`/`Display` text is rendered, so bounding limits size, not sensitivity
// (I15.4).
//
// Missing evidence stays explicitly missing: an identity the owner does not
// hold at a call site renders as `missing` instead of being invented. That
// is every typed rejection (no admitted options exist there) and the
// `ServiceMain` validation contour (which holds no options at all); this cell
// owns no operation id, process-start identity, fence or typed reason, and it
// observes no process and no readiness, so those slots stay missing (cases
// 978/2, 978/4).
//
// Sink outcome never alters result/order/status/cleanup. There is no mutable
// global dedup cache and no terminal emission here: the designated terminal for
// one failed launch is `lib.rs`'s `HostTerminalGuard(BOUNDARY_START_TERMINAL)`
// ("host-start-failed"), and the `HostJobBranches::start_approved` leaf guard is
// phase-only (issue #978 audit defect 2), so this cell can never emit a second
// terminal. Typed rejections stay `HostError::Platform` (case 978/2); admitted
// launches are distinct positive observations carrying the exact admitted
// identities (cases 978/1, 978/12).
fn host_launch_options_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

fn host_launch_options_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    host_launch_options_note_event_log_unavailable();
    let detail = correlation.render(phase);
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::LaunchConfig,
        &detail,
    );
}

/// Bounded correlation for one already-admitted [`HostLaunchOptions`].
///
/// Binds only identities the owner holds on the admitted path: the installation
/// id, the transaction-plan generation and the config-descriptor digest handle.
/// A rejected parse has no admitted value, so it binds nothing
/// (`LaunchPhaseCorrelation::NONE`); paths, the state root, argv text and the
/// registration nonce are never bound here (case 978/12).
fn host_launch_options_admitted_correlation(
    options: &HostLaunchOptions,
) -> LaunchPhaseCorrelation<'_> {
    LaunchPhaseCorrelation::NONE
        .with_installation(options.installation().as_str())
        .with_generation(options.transaction_plan_generation())
        .with_artifact(options.config_descriptor_digest.as_str())
}

/// Exact launch authority supplied by the Runtime Live SCM registration.
///
/// `SystemService` Host startup is argv-bound. The service must not recover any
/// of these values from ambient environment or current-directory state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostLaunchOptions {
    pub(crate) config_descriptor_path: PathBuf,
    pub(crate) config_descriptor_digest: PlatformHandle,
    pub(crate) installation: PlatformHandle,
    pub(crate) transaction_plan_generation: u64,
    pub(crate) host_state_root: PathBuf,
    pub(crate) registration_nonce: Option<PlatformHandle>,
}

impl HostLaunchOptions {
    /// Parses the canonical SCM argv after argv[0] (the service name).
    ///
    /// The five authority pairs must appear exactly once and in the order
    /// rendered by [`eliot_platform_windows::ServiceBootstrapArguments`]. The established optional
    /// registration nonce is accepted only as the final pair. That nonce is
    /// effect-scoped SCM readback evidence, not a Host admission binding; the
    /// approved manifest's five authority values remain independently required.
    /// All other flags and all substitutions are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the argv shape or a typed value is
    /// invalid.
    pub fn parse<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // WORK_UNIT_CASE: 978/1 — parse requested; no admitted value exists yet.
        host_launch_options_observe(
            "host.launch-options parse requested",
            &LaunchPhaseCorrelation::NONE,
        );
        let result = Self::parse_inner(args);
        match &result {
            Ok(options) => {
                // WORK_UNIT_CASE: 978/1 — parse admitted, distinct from rejection.
                host_launch_options_observe(
                    "host.launch-options parse admitted",
                    &host_launch_options_admitted_correlation(options),
                );
            }
            Err(_) => {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted; no
                // admitted identities exist here, so every slot stays missing.
                host_launch_options_observe(
                    "host.launch-options parse typed rejection",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
        }
        result
    }

    fn parse_inner<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() != 10 && args.len() != 12 {
            return Err(Self::invalid_argv("expected exactly five authority pairs"));
        }
        let flag = |index: usize, expected: &str| {
            args.get(index)
                .and_then(|value| value.to_str())
                .is_some_and(|actual| actual == expected)
        };
        if !flag(0, "--config-descriptor")
            || !flag(2, "--config-descriptor-sha256")
            || !flag(4, "--installation-id")
            || !flag(6, "--tx-plan-generation")
            || !flag(8, "--host-state-root")
        {
            return Err(Self::invalid_argv(
                "authority flags are missing, reordered, or substituted",
            ));
        }
        if args.len() == 12 && !flag(10, "--registration-nonce") {
            return Err(Self::invalid_argv("unknown or substituted trailing flag"));
        }

        let config_descriptor_path = PathBuf::from(&args[1]);
        if !config_descriptor_path.is_absolute()
            || config_descriptor_path.as_os_str().is_empty()
            || !valid_launch_os_path(config_descriptor_path.as_os_str())
        {
            return Err(Self::invalid_argv(
                "config descriptor path must be absolute and valid",
            ));
        }
        let config_descriptor_digest = parse_launch_text(&args[3], "config descriptor digest")?;
        if !valid_sha256_text(&config_descriptor_digest) {
            return Err(Self::invalid_argv(
                "config descriptor digest must be lowercase SHA-256",
            ));
        }
        let installation_value = parse_launch_text(&args[5], "installation id")?;
        if !valid_launch_identity(&installation_value) {
            return Err(Self::invalid_argv("installation id is invalid"));
        }
        let transaction_plan_generation =
            parse_launch_text(&args[7], "transaction plan generation")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| {
                    Self::invalid_argv("transaction plan generation must be non-zero")
                })?;
        let host_state_root = PathBuf::from(&args[9]);
        if !host_state_root.is_absolute()
            || host_state_root.as_os_str().is_empty()
            || !valid_launch_os_path(host_state_root.as_os_str())
        {
            return Err(Self::invalid_argv(
                "Host state root must be an absolute valid OS path",
            ));
        }
        let registration_nonce = if args.len() == 12 {
            let nonce = parse_launch_text(&args[11], "registration nonce")?;
            if !valid_sha256_text(&nonce) {
                return Err(Self::invalid_argv(
                    "registration nonce must be lowercase SHA-256",
                ));
            }
            Some(
                PlatformHandle::new(nonce)
                    .map_err(|error| Self::invalid_argv(&error.to_string()))?,
            )
        } else {
            None
        };
        let installation = PlatformHandle::new(installation_value)
            .map_err(|error| Self::invalid_argv(&error.to_string()))?;
        let config_descriptor_digest = PlatformHandle::new(config_descriptor_digest)
            .map_err(|error| Self::invalid_argv(&error.to_string()))?;
        Ok(Self {
            config_descriptor_path,
            config_descriptor_digest,
            installation,
            transaction_plan_generation,
            host_state_root,
            registration_nonce,
        })
    }

    /// Parses the mandatory argv contract for an installed `SystemService`.
    ///
    /// Installer service effects persist a registration nonce before SCM
    /// mutation, so a live SCM callback must include that final pair. The
    /// nonce remains effect-scoped readback evidence; the four manifest
    /// bindings below are still the Host admission authority.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the canonical argv is malformed or
    /// omits the required registration nonce.
    pub fn parse_system_service<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // WORK_UNIT_CASE: 978/1 — system-service admission requested; no admitted
        // value exists yet.
        host_launch_options_observe(
            "host.launch-options system-service requested",
            &LaunchPhaseCorrelation::NONE,
        );
        let result = Self::parse_system_service_inner(args);
        match &result {
            Ok(options) => {
                // WORK_UNIT_CASE: 978/1 — system-service admitted.
                host_launch_options_observe(
                    "host.launch-options system-service admitted",
                    &host_launch_options_admitted_correlation(options),
                );
            }
            Err(_) => {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted; no
                // admitted identities exist here, so every slot stays missing.
                host_launch_options_observe(
                    "host.launch-options system-service typed rejection",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
        }
        result
    }

    fn parse_system_service_inner<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let options = Self::parse(args)?;
        if options.registration_nonce.is_none() {
            return Err(Self::invalid_argv(
                "SystemService requires the registration nonce pair",
            ));
        }
        Ok(options)
    }

    /// Validates the distinct `ServiceMain` callback argv.
    ///
    /// `StartServiceW` is invoked with zero service arguments by the Windows
    /// platform adapter, so SCM supplies the callback with only the canonical
    /// service name. The immutable Host bootstrap is parsed from the process
    /// command line before `StartServiceCtrlDispatcherW` is entered.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the callback vector contains
    /// anything other than the canonical service name.
    pub fn validate_service_main_argv<I, S>(args: I) -> Result<(), HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // WORK_UNIT_CASE: 978/1 — service-main validation requested; this contour
        // holds no options, so no identity can be bound.
        host_launch_options_observe(
            "host.launch-options service-main requested",
            &LaunchPhaseCorrelation::NONE,
        );
        let result = Self::validate_service_main_argv_inner(args);
        match &result {
            Ok(()) => {
                // WORK_UNIT_CASE: 978/1 — service-main admitted; the callback
                // argv carries no admitted options identity.
                host_launch_options_observe(
                    "host.launch-options service-main admitted",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
            Err(_) => {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted; no
                // admitted identities exist here, so every slot stays missing.
                host_launch_options_observe(
                    "host.launch-options service-main typed rejection",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
        }
        result
    }

    fn validate_service_main_argv_inner<I, S>(args: I) -> Result<(), HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() == 1 && args[0].to_str() == Some(ELIOT_HOST_SERVICE_NAME) {
            Ok(())
        } else {
            Err(Self::invalid_argv(
                "ServiceMain argv must contain only EliotHost",
            ))
        }
    }

    // F-LOG-HOST-3 (#978) accessors stay pure borrows: no observation here,
    // so exact return/order/count is preserved and no duplicate evaluation
    // runs on the semantic path. Admission is already observed by
    // `parse`/`parse_system_service` (cases 978/1/978/2); these getters only
    // project already-admitted values.
    //
    // `installation`, `transaction_plan_generation` and
    // `config_descriptor_digest` are the identities the admitted
    // `host_launch_options_admitted_correlation` binds, read exactly once per
    // admitted observation. `config_descriptor_path`, `host_state_root` and
    // `registration_nonce` are read by launch owners but never bound into a
    // diagnostic field (case 978/12).
    #[must_use]
    pub fn config_descriptor_path(&self) -> &Path {
        &self.config_descriptor_path
    }

    #[must_use]
    pub fn config_descriptor_digest(&self) -> &PlatformHandle {
        &self.config_descriptor_digest
    }

    #[must_use]
    pub const fn installation(&self) -> &PlatformHandle {
        &self.installation
    }

    #[must_use]
    pub const fn transaction_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    /// Returns the exact per-installation Host runtime root selected by the
    /// trusted service bootstrap.
    #[must_use]
    pub fn host_state_root(&self) -> &Path {
        &self.host_state_root
    }

    #[must_use]
    pub fn registration_nonce(&self) -> Option<&PlatformHandle> {
        self.registration_nonce.as_ref()
    }

    fn invalid_argv(reason: &str) -> HostError {
        HostError::Platform(format!("invalid Host launch argv: {reason}"))
    }
}

fn parse_launch_text(value: &OsString, field: &str) -> Result<String, HostError> {
    value
        .to_str()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| HostLaunchOptions::invalid_argv(&format!("{field} is not valid text")))
}

fn valid_launch_os_path(value: &OsStr) -> bool {
    value
        .to_str()
        .is_some_and(|value| !value.is_empty() && !value.chars().any(char::is_control))
}

pub(crate) fn valid_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || matches!(value, b'a'..=b'f'))
}

fn valid_launch_identity(value: &str) -> bool {
    !value.is_empty() && !value.contains('"') && !value.chars().any(char::is_control)
}

// F-LOG-HOST-3 (#978) inline proof for this cell's private observation
// contract. These cases execute the real instrumented parser through its
// existing seams and read the exact correlation the production call site
// builds (`host_launch_options_admitted_correlation`); they never re-implement
// parsing, never widen visibility, and never construct an expected log record
// by hand. The launch-corpus mapping and cross-file cases of the issue matrix
// stay with the integration fixture owner.
#[cfg(test)]
mod tests {
    use super::{
        ELIOT_HOST_SERVICE_NAME, HostError, HostLaunchOptions, LaunchPhaseCorrelation,
        host_launch_options_admitted_correlation,
    };

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const INSTALLATION: &str = "978-installation-canary";
    const DESCRIPTOR_PATH: &str = "C:\\Eliot\\978-canary-descriptor.json";
    const STATE_ROOT: &str = "C:\\EliotData\\978-canary-state-root";
    const GENERATION: &str = "7";
    const NONCE_PAIR_REJECTION: &str =
        "invalid Host launch argv: SystemService requires the registration nonce pair";
    const ZERO_GENERATION_REJECTION: &str =
        "invalid Host launch argv: transaction plan generation must be non-zero";
    const SERVICE_MAIN_REJECTION: &str =
        "invalid Host launch argv: ServiceMain argv must contain only EliotHost";

    /// The canonical admitted argv, with canary material in every slot the
    /// diagnostics must never carry.
    fn canonical_argv() -> Vec<String> {
        vec![
            "--config-descriptor".to_owned(),
            DESCRIPTOR_PATH.to_owned(),
            "--config-descriptor-sha256".to_owned(),
            DIGEST.to_owned(),
            "--installation-id".to_owned(),
            INSTALLATION.to_owned(),
            "--tx-plan-generation".to_owned(),
            GENERATION.to_owned(),
            "--host-state-root".to_owned(),
            STATE_ROOT.to_owned(),
            "--registration-nonce".to_owned(),
            NONCE.to_owned(),
        ]
    }

    fn render_admitted(options: &HostLaunchOptions, phase: &str) -> String {
        host_launch_options_admitted_correlation(options).render(phase)
    }

    // WORK_UNIT_CASE: 978/1 — admission binds the held identities
    #[test]
    fn admitted_parse_binds_the_exact_held_identities() {
        let Ok(options) = HostLaunchOptions::parse(canonical_argv()) else {
            panic!("the canonical argv must be admitted");
        };
        let detail = render_admitted(&options, "host.launch-options parse admitted");
        let head = "phase=host.launch-options parse admitted installation=";
        assert!(
            detail.trim_start().starts_with(head),
            "phase must lead: {detail}"
        );
        let identities = format!("installation={INSTALLATION} generation={GENERATION}");
        assert!(
            detail.contains(&identities),
            "held identities must be bound: {detail}"
        );
        let artifact = format!("artifact={DIGEST}");
        assert!(
            detail.contains(&artifact),
            "held digest must be bound: {detail}"
        );

        let Ok(service_options) = HostLaunchOptions::parse_system_service(canonical_argv()) else {
            panic!("the canonical SystemService argv must be admitted");
        };
        let service_detail = render_admitted(
            &service_options,
            "host.launch-options system-service admitted",
        );
        assert!(
            service_detail.contains(&identities) && service_detail.contains(&artifact),
            "system-service admission must bind the same held identities: {service_detail}"
        );
    }

    // WORK_UNIT_CASE: 978/2 — typed rejection stays typed and binds nothing
    #[test]
    fn rejected_options_retain_typed_rejection_and_admit_nothing() {
        let mut argv = canonical_argv();
        argv.pop();
        argv.pop();
        // The nonce pair is dropped: the shape is still valid, so the rejection
        // comes from the SystemService nonce requirement itself.
        let requested = HostLaunchOptions::parse_system_service(argv);
        let Err(HostError::Platform(reason)) = requested else {
            panic!("a SystemService argv without the nonce pair must stay a typed rejection");
        };
        assert_eq!(reason, NONCE_PAIR_REJECTION);

        let mut rejected = canonical_argv();
        rejected[7] = "0".to_owned();
        let Err(HostError::Platform(reason)) = HostLaunchOptions::parse(rejected) else {
            panic!("a zero transaction-plan generation must stay a typed rejection");
        };
        assert_eq!(reason, ZERO_GENERATION_REJECTION);

        let unbound = LaunchPhaseCorrelation::NONE;
        let detail = unbound.render("host.launch-options parse typed rejection");
        for key in [
            "installation",
            "generation",
            "operation",
            "artifact",
            "process_start",
            "fence",
            "reason",
        ] {
            let expected = format!("{key}=missing");
            assert!(
                detail.contains(&expected),
                "no {key} identity is held: {detail}"
            );
        }

        let canonical_main = [ELIOT_HOST_SERVICE_NAME];
        assert!(
            HostLaunchOptions::validate_service_main_argv(canonical_main).is_ok(),
            "the canonical ServiceMain argv must stay admitted"
        );
        let substituted = ["NotEliotHost"];
        let Err(HostError::Platform(reason)) =
            HostLaunchOptions::validate_service_main_argv(substituted)
        else {
            panic!("a substituted ServiceMain argv must stay a typed rejection");
        };
        assert_eq!(reason, SERVICE_MAIN_REJECTION);
    }

    // WORK_UNIT_CASE: 978/4 — parse admission is no process or readiness
    #[test]
    fn parse_admission_is_not_a_process_or_readiness_observation() {
        let Ok(options) = HostLaunchOptions::parse(canonical_argv()) else {
            panic!("the canonical argv must be admitted");
        };
        let detail = render_admitted(&options, "host.launch-options parse admitted");
        let no_process = detail.contains("process_start=missing");
        let no_operation = detail.contains("operation=missing");
        assert!(
            no_process && no_operation,
            "no process identity is held: {detail}"
        );
        assert!(
            !detail.contains("ready"),
            "parse never claims readiness: {detail}"
        );
    }

    // WORK_UNIT_CASE: 978/12 — no path, argv or nonce value reaches a record
    #[test]
    fn admitted_correlation_excludes_paths_argv_and_nonce_values() {
        let Ok(options) = HostLaunchOptions::parse(canonical_argv()) else {
            panic!("the canonical argv must be admitted");
        };
        let detail = render_admitted(&options, "host.launch-options parse admitted");
        for canary in [
            DESCRIPTOR_PATH,
            STATE_ROOT,
            NONCE,
            "--config-descriptor",
            "--host-state-root",
            "--registration-nonce",
        ] {
            assert!(
                !detail.contains(canary),
                "no excluded value is bound: {detail}"
            );
        }
    }
}
