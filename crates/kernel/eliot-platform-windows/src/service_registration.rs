//! SCM service registration contract and runtime-inspection types.
//!
//! Architecture handles (verified at `docs/architecture/ELIOT_ARCHITECTURE.md`):
//! - A13.2 Kernel and failure domains (lines 2062-2075): minimal alive Kernel
//!   preserves authority/fencing/health, Host Supervisor is outside the shared
//!   failure domain of Kernel/Watchdog/Doctor and only bounded-restarts approved
//!   services without reading project semantics.
//! - A13.3 Module supervision and Doctor (lines 2081-2088): start, health/readiness
//!   check, quiesce/drain, checkpoint, restart/rebuild, replace/rollback, quarantine,
//!   retire.
//!
//! Implementation tier (separately labeled):
//! - `docs/PROJECT_MAP.md` lines 101-108: Windows protected paths, ACLs, SCM and
//!   process/Job observations are owned by `crates/kernel/eliot-platform-windows`
//!   (and `crates/eliot-windows-ipc`), distinct from installation, host-state,
//!   kernel-service, store, daemon, watchdog boundaries.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md` lines 1218-1237: `eliotd` owns
//!   WorkScopes/tasks/plan revisions and is hot-replaceable without changing
//!   canonical owner; lines 1941-2005: crate-rich, process-sparse, owner-sparse
//!   with one owner per mutable state and one canonical semantic path.
//!
//! Ownership: this module is the sole owner of the SCM service registration
//! contract and runtime-inspection types — `ServiceAccount`, `ServiceStartMode`,
//! `ServiceSidType`, service constants, `ServiceControlGrantReadback`,
//! `ServiceBootstrapArguments`, `ServiceRegistrationCurrent`,
//! `ServiceRegistrationRequest`, `ServiceRegistrationOutcome`,
//! `ServiceRegistrationInspection`, `ServiceRuntimeObservation`,
//! `ServiceRegistrationRuntimeInspection`, `ServiceStartOutcome`,
//! `ServiceStopOutcome` — and their proven closure-owned private helpers.
//! Physical SCM register, update, delete, start, stop and inspect operations
//! remain root-owned in `lib.rs` and must not be duplicated here. It does not
//! own and must not duplicate or broaden: Kernel generation/fencing,
//! front-door/session authentication, daemon readiness, Store/canonical writes,
//! or Watchdog task authority. Semantic, canonical, readiness, Kernel, Store,
//! and Watchdog authority remain outside this cell.

use std::path::{Path, PathBuf};

use eliot_platform::{ServiceObservation, ServiceState};

use crate::{ProcessIdentity, WindowsAdapterError};

/// Account under which SCM starts an ELIOT-owned Windows service.
///
/// Password-bearing custom accounts are intentionally absent. P-10 must use a
/// separately governed credential path before such an account can be added.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAccount {
    LocalSystem,
    LocalService,
    NetworkService,
}

/// SCM start mode admitted by the P-02 registration adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStartMode {
    Automatic,
    Demand,
    Disabled,
}

/// Exact SCM service-SID mode admitted by the installation adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSidType {
    /// The service has no service SID in its process token.
    None,
    /// SCM adds the deterministic `NT SERVICE\<name>` SID to the token.
    Unrestricted,
}

impl ServiceSidType {
    pub(super) const fn raw(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Unrestricted => 1,
        }
    }
}

/// Canonical SCM names owned by the Runtime Live installer.
pub const ELIOT_HOST_SERVICE_NAME: &str = "EliotHost";
pub const ELIOT_WATCHDOG_SERVICE_NAME: &str = "EliotWatchdog";
pub const ELIOT_HOST_SERVICE_DISPLAY_NAME: &str = "Eliot Host";
pub const ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME: &str = "Eliot Watchdog";

/// Exact service-object rights granted to the `EliotHost` service SID on the
/// canonical `EliotWatchdog` registration.
///
/// The mask is deliberately concrete rather than generic: query-config and
/// query-status are required for the retained readback contour, start/stop are
/// the only mutations admitted to Host, and `READ_CONTROL` is required to
/// reverify the protected DACL. It excludes change-config, delete, write-DACL,
/// write-owner, pause/continue and user-defined control rights.
pub const ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK: u32 =
    0x0000_0001 | 0x0000_0004 | 0x0000_0010 | 0x0000_0020 | 0x0002_0000;

/// Authoritative readback of the one narrow service-object grant installed by
/// the privileged installer for the non-elevated Host service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceControlGrantReadback {
    principal_service: String,
    principal_sid: String,
    access_mask: u32,
    security_descriptor_digest: String,
}

impl ServiceControlGrantReadback {
    pub(super) fn new(
        principal_service: impl Into<String>,
        principal_sid: impl Into<String>,
        access_mask: u32,
        security_descriptor_digest: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let value = Self {
            principal_service: principal_service.into(),
            principal_sid: principal_sid.into(),
            access_mask,
            security_descriptor_digest: security_descriptor_digest.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the canonical service whose deterministic SID receives the
    /// grant.
    #[must_use]
    pub fn principal_service(&self) -> &str {
        &self.principal_service
    }

    /// Returns the OS-resolved `S-1-5-80-...` service SID.
    #[must_use]
    pub fn principal_sid(&self) -> &str {
        &self.principal_sid
    }

    /// Returns the exact concrete service-object access mask.
    #[must_use]
    pub const fn access_mask(&self) -> u32 {
        self.access_mask
    }

    /// Returns the digest of the protected, byte-exact service DACL contour.
    #[must_use]
    pub fn security_descriptor_digest(&self) -> &str {
        &self.security_descriptor_digest
    }

    /// Validates the typed readback without touching SCM.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsAdapterError::IdentityMismatch`] when the principal,
    /// concrete access mask, or descriptor digest differs from the canonical
    /// Host-to-Watchdog control grant.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        if self.principal_service != ELIOT_HOST_SERVICE_NAME
            || !crate::valid_service_sid_text(&self.principal_sid)
            || self.access_mask != ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK
            || !crate::valid_sha256_hex(&self.security_descriptor_digest)
            || !crate::watchdog_service_security_descriptor_digest(&self.principal_sid)
                .is_ok_and(|expected| expected == self.security_descriptor_digest)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Provider-neutral, typed authority passed to an SCM service through argv.
///
/// The four named values are deliberately not read from ambient environment
/// state. `extra_args` is retained in caller order and is validated as argv
/// data; it is never accepted as an already-rendered command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBootstrapArguments {
    config_descriptor_path: PathBuf,
    config_descriptor_digest: String,
    installation_id: String,
    transaction_plan_generation: u64,
    host_state_root: Option<PathBuf>,
    registration_nonce: Option<String>,
    extra_args: Vec<String>,
}

impl ServiceBootstrapArguments {
    /// Creates the canonical bootstrap binding used by durable services.
    ///
    /// # Errors
    /// Returns `InvalidInput` when a path, digest, identity, generation, or
    /// extra argv value is not canonical.
    pub fn new<I, S>(
        config_descriptor_path: impl Into<PathBuf>,
        config_descriptor_digest: impl Into<String>,
        installation_id: impl Into<String>,
        transaction_plan_generation: u64,
        extra_args: I,
    ) -> Result<Self, WindowsAdapterError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let config_descriptor_path = config_descriptor_path.into();
        let config_descriptor_digest = config_descriptor_digest.into();
        let installation_id = installation_id.into();
        let extra_args = extra_args.into_iter().map(Into::into).collect::<Vec<_>>();
        if !config_descriptor_path.is_absolute()
            || !valid_os_path(config_descriptor_path.as_path())
            || !crate::valid_sha256_hex(&config_descriptor_digest)
            || !valid_bootstrap_identity(&installation_id)
            || transaction_plan_generation == 0
            || extra_args.iter().any(|arg| !valid_bootstrap_text(arg))
            || extra_args.iter().any(|arg| is_reserved_bootstrap_arg(arg))
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            config_descriptor_path,
            config_descriptor_digest,
            installation_id,
            transaction_plan_generation,
            host_state_root: None,
            registration_nonce: None,
            extra_args,
        })
    }

    /// Binds a Host service bootstrap to one explicit installer-provisioned
    /// runtime root. Other service roles may leave this selector absent.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the root is not an absolute valid OS path.
    pub fn with_host_state_root(
        mut self,
        host_state_root: impl Into<PathBuf>,
    ) -> Result<Self, WindowsAdapterError> {
        let host_state_root = host_state_root.into();
        if !host_state_root.is_absolute()
            || host_state_root.as_os_str().is_empty()
            || !valid_os_path(&host_state_root)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.host_state_root = Some(host_state_root);
        Ok(self)
    }

    /// Binds this bootstrap to one durable installer registration intent.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the nonce is not canonical SHA-256 text.
    pub fn with_registration_nonce(
        mut self,
        registration_nonce: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let registration_nonce = registration_nonce.into();
        if !crate::valid_sha256_hex(&registration_nonce) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.registration_nonce = Some(registration_nonce);
        Ok(self)
    }

    #[must_use]
    pub fn config_descriptor_path(&self) -> &Path {
        &self.config_descriptor_path
    }

    #[must_use]
    pub fn config_descriptor_digest(&self) -> &str {
        &self.config_descriptor_digest
    }

    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    #[must_use]
    pub const fn transaction_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    /// Returns the exact per-installation Host runtime-root selector, when
    /// this bootstrap is for the Host service.
    #[must_use]
    pub fn host_state_root(&self) -> Option<&Path> {
        self.host_state_root.as_deref()
    }

    #[must_use]
    pub const fn tx_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    #[must_use]
    pub fn registration_nonce(&self) -> Option<&str> {
        self.registration_nonce.as_deref()
    }

    #[must_use]
    pub fn extra_args(&self) -> &[String] {
        &self.extra_args
    }

    /// Returns typed fields rendered as ordered argv values.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let config_descriptor_path = exact_path_text(&self.config_descriptor_path);
        let mut argv = vec![
            "--config-descriptor".to_owned(),
            config_descriptor_path,
            "--config-descriptor-sha256".to_owned(),
            self.config_descriptor_digest.clone(),
            "--installation-id".to_owned(),
            self.installation_id.clone(),
            "--tx-plan-generation".to_owned(),
            self.transaction_plan_generation.to_string(),
        ];
        if let Some(root) = &self.host_state_root {
            argv.extend([
                "--host-state-root".to_owned(),
                exact_path_text(root.as_path()),
            ]);
        }
        if let Some(nonce) = &self.registration_nonce {
            argv.extend(["--registration-nonce".to_owned(), nonce.clone()]);
        }
        argv.extend(self.extra_args.iter().cloned());
        argv
    }

    #[cfg(windows)]
    pub(super) fn argv_os(&self) -> Vec<std::ffi::OsString> {
        let mut argv = vec![
            std::ffi::OsString::from("--config-descriptor"),
            self.config_descriptor_path.as_os_str().to_os_string(),
            std::ffi::OsString::from("--config-descriptor-sha256"),
            std::ffi::OsString::from(&self.config_descriptor_digest),
            std::ffi::OsString::from("--installation-id"),
            std::ffi::OsString::from(&self.installation_id),
            std::ffi::OsString::from("--tx-plan-generation"),
            std::ffi::OsString::from(self.transaction_plan_generation.to_string()),
        ];
        if let Some(root) = &self.host_state_root {
            argv.extend([
                std::ffi::OsString::from("--host-state-root"),
                root.as_os_str().to_os_string(),
            ]);
        }
        if let Some(nonce) = &self.registration_nonce {
            argv.extend([
                std::ffi::OsString::from("--registration-nonce"),
                std::ffi::OsString::from(nonce),
            ]);
        }
        argv.extend(
            self.extra_args
                .iter()
                .cloned()
                .map(std::ffi::OsString::from),
        );
        argv
    }
}

/// Exact current configuration identity required before installer mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistrationCurrent {
    service_name: String,
    configuration_digest: String,
}

impl ServiceRegistrationCurrent {
    /// Creates an expected current SCM identity and configuration digest.
    ///
    /// # Errors
    /// Returns `InvalidInput` for a non-canonical service name or digest.
    pub fn new(
        service_name: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let service_name = service_name.into();
        let configuration_digest = configuration_digest.into();
        if !crate::canonical_runtime_service_name(&service_name)
            || !crate::valid_sha256_hex(&configuration_digest)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            service_name,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

fn valid_bootstrap_text(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0')
}

fn valid_bootstrap_identity(value: &str) -> bool {
    valid_bootstrap_text(value) && !value.contains('"')
}

fn is_reserved_bootstrap_arg(value: &str) -> bool {
    matches!(
        value,
        "--config-descriptor"
            | "--config-descriptor-sha256"
            | "--installation-id"
            | "--tx-plan-generation"
            | "--host-state-root"
            | "--registration-nonce"
    )
}

pub(super) fn utf16_text(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn exact_utf16_text(value: &[u16]) -> String {
    String::from_utf16(value).unwrap_or_default()
}

pub(super) fn exact_path_text(path: &Path) -> String {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        exact_utf16_text(&path.as_os_str().encode_wide().collect::<Vec<_>>())
    }
    #[cfg(not(windows))]
    {
        path.to_str().unwrap_or_default().to_owned()
    }
}

fn valid_os_path(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        String::from_utf16(&units).is_ok()
            && units
                .iter()
                .all(|unit| *unit != 0 && !matches!(unit, 9..=13))
    }
    #[cfg(not(windows))]
    {
        path.to_str().is_some_and(|value| {
            !value
                .chars()
                .any(|character| character == '\0' || character.is_control())
        })
    }
}

/// Validated, password-free request for registering one own-process service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistrationRequest {
    service_name: String,
    display_name: String,
    binary_path: PathBuf,
    start_mode: ServiceStartMode,
    account: ServiceAccount,
    service_sid_type: ServiceSidType,
    bootstrap: Option<ServiceBootstrapArguments>,
    expected_current: Option<ServiceRegistrationCurrent>,
    expected_runtime_identity_digest: Option<String>,
}

impl ServiceRegistrationRequest {
    /// Creates an inert SCM registration request.
    ///
    /// # Errors
    /// Returns `InvalidInput` for invalid names or a non-absolute/non-file image.
    pub fn new(
        service_name: impl Into<String>,
        display_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        start_mode: ServiceStartMode,
        account: ServiceAccount,
    ) -> Result<Self, WindowsAdapterError> {
        let service_name = service_name.into();
        let display_name = display_name.into();
        let binary_path = binary_path.into();
        if !crate::valid_service_name(&service_name)
            || !crate::valid_display_name(&display_name)
            || !binary_path.is_absolute()
            || !binary_path.is_file()
            || !valid_os_path(binary_path.as_path())
            || !crate::canonical_runtime_service_name(&service_name)
            || crate::canonical_runtime_service_display_name(&service_name)
                .is_some_and(|expected| display_name != expected)
            || start_mode != ServiceStartMode::Automatic
            || account != ServiceAccount::LocalService
            || exact_path_text(binary_path.as_path()).contains('"')
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let service_sid_type = if service_name == ELIOT_HOST_SERVICE_NAME {
            ServiceSidType::Unrestricted
        } else {
            ServiceSidType::None
        };
        Ok(Self {
            service_name,
            display_name,
            binary_path,
            start_mode,
            account,
            service_sid_type,
            bootstrap: None,
            expected_current: None,
            expected_runtime_identity_digest: None,
        })
    }

    /// Creates a request with the immutable, argv-only bootstrap authority.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the service shape or bootstrap binding is
    /// not canonical.
    pub fn with_bootstrap(
        service_name: impl Into<String>,
        display_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        start_mode: ServiceStartMode,
        account: ServiceAccount,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, WindowsAdapterError> {
        let mut request = Self::new(service_name, display_name, binary_path, start_mode, account)?;
        request.bootstrap = Some(bootstrap);
        Ok(request)
    }

    /// Binds the exact current service configuration allowed for installer
    /// update or delete.
    /// # Errors
    /// Returns `InvalidInput` when the expected service identity does not
    /// match this request's canonical service name.
    pub fn with_expected_current(
        mut self,
        expected_current: ServiceRegistrationCurrent,
    ) -> Result<Self, WindowsAdapterError> {
        if expected_current.service_name() != self.service_name {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.expected_current = Some(expected_current);
        Ok(self)
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    #[must_use]
    pub const fn start_mode(&self) -> ServiceStartMode {
        self.start_mode
    }

    #[must_use]
    pub const fn account(&self) -> ServiceAccount {
        self.account
    }

    /// Returns the exact SCM service-SID mode required by this registration.
    #[must_use]
    pub const fn service_sid_type(&self) -> ServiceSidType {
        self.service_sid_type
    }

    /// Returns whether this registration requires the installer-owned
    /// `EliotHost` service-control grant and exact DACL readback.
    #[must_use]
    pub fn requires_host_service_control_grant(&self) -> bool {
        self.service_name == ELIOT_WATCHDOG_SERVICE_NAME
    }

    #[must_use]
    pub fn bootstrap(&self) -> Option<&ServiceBootstrapArguments> {
        self.bootstrap.as_ref()
    }

    #[must_use]
    pub fn expected_current(&self) -> Option<&ServiceRegistrationCurrent> {
        self.expected_current.as_ref()
    }

    /// Binds a rollback request to the exact process identity observed by the
    /// caller. The digest is evidence, not a caller-supplied PID; the typed
    /// stop primitive validates it again against a fresh SCM/process readback
    /// immediately before issuing its one stop call.
    ///
    /// # Errors
    /// Returns `InvalidInput` for a digest that is not canonical lowercase
    /// SHA-256 text.
    pub fn with_expected_runtime_identity_digest(
        mut self,
        digest: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let digest = digest.into();
        if !crate::valid_sha256_hex(&digest) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.expected_runtime_identity_digest = Some(digest);
        Ok(self)
    }

    /// Returns the process identity digest bound to a rollback request, when
    /// one was supplied by the caller.
    #[must_use]
    pub fn expected_runtime_identity_digest(&self) -> Option<&str> {
        self.expected_runtime_identity_digest.as_deref()
    }

    #[must_use]
    pub fn expected_configuration_digest(&self) -> String {
        crate::service_configuration_digest(
            &self.binary_command_wide(),
            &utf16_text(self.display_name()),
            &utf16_text("NT AUTHORITY\\LocalService"),
            0x0000_0010,
            0x0000_0002,
            0x0000_0001,
            0,
            &[],
            &[],
            self.service_sid_type.raw(),
        )
    }

    #[cfg(windows)]
    pub(super) fn binary_command_wide(&self) -> Vec<u16> {
        let mut command = crate::quote_service_os_argument(self.binary_path.as_os_str(), true);
        if let Some(bootstrap) = &self.bootstrap {
            for argument in bootstrap.argv_os() {
                command.push(' ' as u16);
                command.extend(crate::quote_service_os_argument(&argument, false));
            }
        }
        command
    }

    #[cfg(not(windows))]
    pub(super) fn binary_command_wide(&self) -> Vec<u16> {
        let mut command = crate::quote_service_argument(&exact_path_text(&self.binary_path), true);
        if let Some(bootstrap) = &self.bootstrap {
            for argument in bootstrap.argv() {
                command.push(' ');
                command.push_str(&crate::quote_service_argument(&argument, false));
            }
        }
        command.encode_utf16().collect()
    }

    #[must_use]
    pub fn binary_command(&self) -> String {
        exact_utf16_text(&self.binary_command_wide())
    }
}

/// Registration result preserving whether an external SCM effect requires
/// reconciliation before it can be called successful.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationOutcome {
    /// The SCM object was absent and this call created it successfully.
    CreatedNow {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    /// The exact object was already present before this call.
    PreexistingMatching {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Registered {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Updated {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Unchanged {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Deleted,
    AlreadyAbsent,
    ExistingRequiresReconciliation,
    EffectUnknown,
}

/// Read-only classification of one canonical Runtime Live SCM registration.
///
/// `Matching` means the SCM name, binary command, own-process service type,
/// automatic start mode, and `LocalService` account all match the validated
/// request.  Every other variant is fail-closed for Host startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationInspection {
    /// Exact configuration and current service state were observed.
    Matching {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    /// The canonical service name is not registered.
    Absent,
    /// A service exists at the canonical name with different configuration.
    Mismatched,
    /// SCM could not provide authoritative configuration and state readback.
    Unknown,
}

/// Exact read-only SCM runtime observation for one validated registration.
///
/// This is deliberately separate from [`eliot_platform::ServiceObservation`]:
/// Windows can authoritatively observe a service PID, process creation time,
/// and image path, but it cannot invent ELIOT's semantic authority epoch.
/// The configuration digest binds the observation to the complete canonical
/// service command, account, type, and start-mode request used for readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRuntimeObservation {
    pub(super) service_name: String,
    pub(super) configuration_digest: String,
    pub(super) state: ServiceState,
    pub(super) checkpoint: u32,
    pub(super) wait_hint_ms: u32,
    pub(super) process: Option<ProcessIdentity>,
}

impl ServiceRuntimeObservation {
    /// Returns the exact canonical SCM service name.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the digest of the complete configuration admitted during this
    /// same readback.
    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    /// Returns the current SCM lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ServiceState {
        self.state
    }

    /// Returns whether SCM reports the service as fully stopped.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        matches!(self.state, ServiceState::Stopped)
    }

    /// Returns whether SCM reports an in-progress start transition.
    #[must_use]
    pub const fn is_starting(&self) -> bool {
        matches!(self.state, ServiceState::Starting)
    }

    /// Returns whether SCM reports the service as running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, ServiceState::Running)
    }

    /// Returns whether SCM reports an in-progress stop transition.
    #[must_use]
    pub const fn is_stopping(&self) -> bool {
        matches!(self.state, ServiceState::Stopping)
    }

    /// Returns the SCM progress checkpoint for a pending transition.
    #[must_use]
    pub const fn checkpoint(&self) -> u32 {
        self.checkpoint
    }

    /// Returns the SCM provider's bounded-wait hint in milliseconds.
    #[must_use]
    pub const fn wait_hint_ms(&self) -> u32 {
        self.wait_hint_ms
    }

    /// Returns the handle-observed PID, creation time, and image identity when
    /// the current state has a live service process.
    #[must_use]
    pub const fn process(&self) -> Option<&ProcessIdentity> {
        self.process.as_ref()
    }

    /// Computes the stable digest that a rollback request must bind before it
    /// can issue a stop call. The digest covers the exact admitted service
    /// configuration and the handle-observed PID, creation time, and image.
    #[must_use]
    pub fn runtime_identity_digest(&self) -> Option<String> {
        self.process.as_ref().map(|process| {
            crate::runtime_identity_digest_from_configuration(&self.configuration_digest, process)
        })
    }
}

/// Read-only classification of exact SCM configuration plus runtime state.
///
/// `Matching` is returned only when the canonical registration matches and
/// every process identity required by the observed state is available from a
/// live process handle. Unknown provider state or an inaccessible live
/// process remains fail-closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationRuntimeInspection {
    /// Exact configuration and runtime state were observed together.
    Matching {
        observation: ServiceRuntimeObservation,
    },
    /// The canonical service name is not registered.
    Absent,
    /// The registration or live image differs from the validated request.
    Mismatched,
    /// SCM or the live process could not be observed authoritatively.
    Unknown,
}

/// Result of one exact-registration-bound SCM start attempt.
///
/// The operation is deliberately separate from the provider-neutral
/// `ServicePort::Start` request. It performs one fresh registration/runtime
/// admission and issues at most one `StartServiceW` call. `Started` means that
/// the call was issued and the post-call readback remained authoritative; it
/// does not claim that SCM has already reached `Running`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceStartOutcome {
    /// One `StartServiceW` call was issued and the post-call readback matches.
    Started {
        observation: ServiceRuntimeObservation,
    },
    /// The exact service was already running; no start call was issued.
    AlreadyRunning {
        observation: ServiceRuntimeObservation,
    },
    /// SCM reported an in-progress start; no start call was issued.
    AlreadyStarting {
        observation: ServiceRuntimeObservation,
    },
    /// A provider/readback race or failure prevented an authoritative result.
    EffectUnknown,
}

/// Result of one exact-registration-bound SCM stop attempt used for rollback
/// of a start effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceStopOutcome {
    /// One stop call was issued and the post-call readback matches.
    Stopped {
        observation: ServiceRuntimeObservation,
    },
    /// The exact service was already stopped; no stop call was issued.
    AlreadyStopped {
        observation: ServiceRuntimeObservation,
    },
    /// SCM reported an in-progress stop; no stop call was issued.
    AlreadyStopping {
        observation: ServiceRuntimeObservation,
    },
    /// A provider/readback race or failure prevented an authoritative result.
    EffectUnknown,
}
