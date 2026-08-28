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
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() == 1 && args[0].to_str() == Some(ELIOT_HOST_SERVICE_NAME) {
            Ok(())
        } else {
            Err(Self::invalid_argv(
                "ServiceMain argv must contain only EliotHost",
            ))
        }
    }

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
