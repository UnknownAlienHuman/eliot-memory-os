//! Windows provider security adapters isolated from the shared facade.
//! Architecture: A2.3/A8.5/A12.1/A12.3/A13.8; ARCH-AUTH-01/ARCH-SEC-02/ARCH-RES-03
//! Implementation: I1.6/I2.2/I2.23/I15.2/I15.3/I15.8/I15.16/I15.19
//! Explicitly no peer semantic/SCM/process/secret/canonical/default/retry/mint authority.

use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use sha2::{Digest, Sha256};

use crate::FileIdentity;
use crate::ProtectedPathLease;
use crate::WindowsAdapterError;

/// Stable role of one admitted local named-pipe peer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NamedPipePeerKind {
    /// The Host control client.
    Host,
    /// The exact Kernel-launched `eliotd` process.
    Eliotd,
    /// The separately installed agent bridge module.
    AgentBridge,
}

impl NamedPipePeerKind {
    /// Returns the fixed module identity used by this peer role.
    #[must_use]
    pub const fn module_id(self) -> &'static str {
        match self {
            Self::Host => "eliot-host",
            Self::Eliotd => "eliotd",
            Self::AgentBridge => "eliot-agent-bridge",
        }
    }
}

/// One immutable role/profile and its inert platform expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerProfile {
    kind: NamedPipePeerKind,
    module_id: String,
    profile_id: Option<String>,
    pub(super) expectation: crate::NamedPipePeerExpectation,
}

impl NamedPipePeerProfile {
    /// Creates one role entry.  The role and module identity are fixed and the
    /// expectation remains inert until a live pipe handle is observed.
    pub fn new(
        kind: NamedPipePeerKind,
        expectation: crate::NamedPipePeerExpectation,
        profile_id: Option<String>,
    ) -> Result<Self, WindowsAdapterError> {
        if profile_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
            || (kind == NamedPipePeerKind::AgentBridge && profile_id.is_none())
            || (kind != NamedPipePeerKind::AgentBridge && profile_id.is_some())
            || (kind == NamedPipePeerKind::AgentBridge && !expectation.is_dynamic_process())
            || (kind != NamedPipePeerKind::AgentBridge && expectation.is_dynamic_process())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            kind,
            module_id: kind.module_id().to_owned(),
            profile_id,
            expectation,
        })
    }

    /// Returns the role.
    #[must_use]
    pub const fn kind(&self) -> NamedPipePeerKind {
        self.kind
    }

    /// Returns the fixed module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the static profile identity for the bridge role.
    #[must_use]
    pub fn profile_id(&self) -> Option<&str> {
        self.profile_id.as_deref()
    }

    /// Returns the inert SID/process/Job expectation.
    #[must_use]
    pub const fn expectation(&self) -> &crate::NamedPipePeerExpectation {
        &self.expectation
    }
}

/// Bounded immutable peer set used for deterministic post-observation role
/// selection.  Entries are sorted by role and cannot be changed after build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerSet {
    entries: Vec<NamedPipePeerProfile>,
}

impl NamedPipePeerSet {
    /// Maximum number of local peer roles in one set.
    pub const MAX_ENTRIES: usize = 3;

    /// Seals a bounded set with at most one Host, Eliotd, and `AgentBridge`.
    pub fn new(mut entries: Vec<NamedPipePeerProfile>) -> Result<Self, WindowsAdapterError> {
        if entries.is_empty() || entries.len() > Self::MAX_ENTRIES {
            return Err(WindowsAdapterError::InvalidInput);
        }
        if entries.iter().any(|entry| {
            let static_process = entry.expectation.approved_process_binding();
            let dynamic_process = entry.expectation.is_dynamic_process();
            let valid = if entry.kind == NamedPipePeerKind::AgentBridge {
                dynamic_process
            } else {
                !dynamic_process && static_process.is_some()
            };
            !valid
        }) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        entries.sort_by_key(NamedPipePeerProfile::kind);
        if entries
            .windows(2)
            .any(|pair| pair[0].kind() == pair[1].kind())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { entries })
    }

    /// Alias emphasizing that construction seals the immutable set.
    pub fn seal(entries: Vec<NamedPipePeerProfile>) -> Result<Self, WindowsAdapterError> {
        Self::new(entries)
    }

    /// Returns entries in deterministic role order.
    #[must_use]
    pub fn entries(&self) -> &[NamedPipePeerProfile] {
        &self.entries
    }

    /// Returns whether any entry requires OS-proved built-in Administrators
    /// membership during live authentication.
    #[must_use]
    pub fn requires_builtin_administrators(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.expectation.requires_builtin_administrators())
    }

    /// Returns whether a dynamic bridge entry requires an OS-observed active
    /// interactive session during live authentication.
    #[must_use]
    pub fn requires_active_interactive_session(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.expectation.is_dynamic_process())
    }

    /// Returns the approved SID principals used to build and verify a set DACL.
    #[must_use]
    pub fn expected_sids(&self) -> Vec<&str> {
        let mut sids = Vec::with_capacity(self.entries.len());
        for sid in self
            .entries
            .iter()
            .map(|entry| entry.expectation.expected_sid())
        {
            if !sids.contains(&sid) {
                sids.push(sid);
            }
        }
        sids
    }

    /// Selects exactly one role from trusted, handle-bound peer evidence.
    /// Zero matches and multiple matches are both fail-closed.
    pub fn select(
        &self,
        evidence: &crate::NamedPipePeerEvidence,
    ) -> Result<NamedPipePeerSelection, WindowsAdapterError> {
        let matches = self
            .entries
            .iter()
            .filter(|entry| entry.expectation.matches_evidence(evidence))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [entry] => Ok(NamedPipePeerSelection {
                kind: entry.kind,
                module_id: entry.module_id.clone(),
                profile_id: entry.profile_id.clone(),
            }),
            _ => Err(WindowsAdapterError::IdentityMismatch),
        }
    }
}

/// Result of exact peer-set selection; it contains no semantic Session or task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerSelection {
    kind: NamedPipePeerKind,
    module_id: String,
    profile_id: Option<String>,
}

impl NamedPipePeerSelection {
    /// Returns the selected role.
    #[must_use]
    pub const fn kind(&self) -> NamedPipePeerKind {
        self.kind
    }

    /// Returns the selected module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the selected static profile identity, if this is the bridge role.
    #[must_use]
    pub fn profile_id(&self) -> Option<&str> {
        self.profile_id.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NamedPipeAuthDiscriminator {
    Ordinary,
    BuiltinAdministrators,
}

/// Installer-pinned inputs for the separately registered Watchdog fallback
/// task.  This value is configuration, not an authority token: registration
/// still proves the live caller's SID/session and verifies both immutable
/// artifact/config digests before touching Task Scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTaskRegistration {
    task_name: String,
    notify_executable: PathBuf,
    verifier_path: PathBuf,
    envelope_path: PathBuf,
    expected_sid: String,
    expected_session_id: u32,
    notify_artifact_sha256: String,
    verifier_sha256: String,
}

impl WatchdogTaskRegistration {
    /// Creates a registration request from installer-pinned paths and
    /// digests.  The live SID/session and protected file identities are proved
    /// by [`register_interactive_watchdog_task`].
    ///
    /// # Errors
    ///
    /// Returns an error when any fixed identity, absolute path, session, SID,
    /// or artifact digest is invalid.
    #[allow(
        clippy::too_many_arguments,
        reason = "installer-pinned paths, identity, session, and digests remain explicit"
    )]
    pub fn new(
        task_name: impl Into<String>,
        notify_executable: impl Into<PathBuf>,
        verifier_path: impl Into<PathBuf>,
        envelope_path: impl Into<PathBuf>,
        expected_sid: impl Into<String>,
        expected_session_id: u32,
        notify_artifact_sha256: impl Into<String>,
        verifier_sha256: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let task_name = task_name.into();
        let notify_executable = notify_executable.into();
        let verifier_path = verifier_path.into();
        let envelope_path = envelope_path.into();
        let expected_sid = expected_sid.into();
        let notify_artifact_sha256 = notify_artifact_sha256.into();
        let verifier_sha256 = verifier_sha256.into();
        if task_name != WATCHDOG_FALLBACK_TASK_NAME
            || !notify_executable.is_absolute()
            || !verifier_path.is_absolute()
            || !envelope_path.is_absolute()
            || !crate::valid_sid_text(&expected_sid)
            || expected_session_id == 0
            || !crate::valid_sha256_hex(&notify_artifact_sha256)
            || !crate::valid_sha256_hex(&verifier_sha256)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            task_name,
            notify_executable,
            verifier_path,
            envelope_path,
            expected_sid,
            expected_session_id,
            notify_artifact_sha256,
            verifier_sha256,
        })
    }

    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn notify_executable(&self) -> &Path {
        &self.notify_executable
    }

    #[must_use]
    pub fn verifier_path(&self) -> &Path {
        &self.verifier_path
    }

    #[must_use]
    pub fn envelope_path(&self) -> &Path {
        &self.envelope_path
    }

    #[must_use]
    pub fn expected_sid(&self) -> &str {
        &self.expected_sid
    }

    #[must_use]
    pub const fn expected_session_id(&self) -> u32 {
        self.expected_session_id
    }

    #[must_use]
    pub fn notify_artifact_sha256(&self) -> &str {
        &self.notify_artifact_sha256
    }

    #[must_use]
    pub fn verifier_sha256(&self) -> &str {
        &self.verifier_sha256
    }
}

/// Observation returned only after Task Scheduler accepted the exact
/// interactive-user registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTaskRegistrationReceipt {
    task_name: String,
    sid: String,
    session_id: u32,
    notify_artifact_sha256: String,
    verifier_sha256: String,
    task_xml_sha256: String,
}

impl WatchdogTaskRegistrationReceipt {
    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    #[must_use]
    pub fn notify_artifact_sha256(&self) -> &str {
        &self.notify_artifact_sha256
    }

    #[must_use]
    pub fn verifier_sha256(&self) -> &str {
        &self.verifier_sha256
    }

    #[must_use]
    pub fn task_xml_sha256(&self) -> &str {
        &self.task_xml_sha256
    }
}

/// Fixed scheduler identity for the X-01 fallback.  A caller cannot choose a
/// second task name or turn this route into a general command scheduler.
pub const WATCHDOG_FALLBACK_TASK_NAME: &str = r"\Eliot\WatchdogFallback";
const WATCHDOG_FALLBACK_TASK_FOLDER: &str = r"\Eliot";
const WATCHDOG_FALLBACK_TASK_LEAF: &str = "WatchdogFallback";

/// Registers the signed Watchdog fallback for the current interactive user.
///
/// The COM call uses `TASK_LOGON_INTERACTIVE_TOKEN` with empty credentials;
/// this boundary never manufactures, accepts or persists a logon token.  The
/// task runs only in the installer-bound interactive SID/session and invokes
/// the fixed no-stdin `--watchdog-fallback` mode.
///
/// # Errors
///
/// Returns an error when pinned registration evidence is invalid, the caller
/// identity mismatches, or Task Scheduler registration/readback fails.
pub fn register_interactive_watchdog_task(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRegistrationReceipt, WindowsAdapterError> {
    validate_watchdog_registration(registration)?;
    #[cfg(windows)]
    {
        register_watchdog_task_windows(registration)
    }
    #[cfg(not(windows))]
    {
        let _ = registration;
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(windows)]
fn validate_watchdog_registration(
    registration: &WatchdogTaskRegistration,
) -> Result<(), WindowsAdapterError> {
    let current = crate::named_pipe_process_admission::current_process_named_pipe_expectation()?;
    if current.expected_sid() != registration.expected_sid
        || current.expected_session_id() != registration.expected_session_id
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let executable = validate_pinned_artifact(
        &registration.notify_executable,
        &registration.notify_artifact_sha256,
    )?;
    if executable != registration.notify_executable {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let root = crate::protected_path::protected_program_data_root()
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    crate::ensure_protected_containment(&root, &registration.verifier_path)
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    crate::ensure_protected_containment(&root, &registration.envelope_path)
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    let verifier = ProtectedPathLease::open_existing_absolute(&registration.verifier_path)
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    verifier
        .verify_stable_identity()
        .and_then(|()| verifier.verify_path_identity())
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    let bytes = verifier
        .read_bounded(64 * 1024)
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    if crate::sha256_hex(&bytes) != registration.verifier_sha256 {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_watchdog_registration(
    _registration: &WatchdogTaskRegistration,
) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Validates an installer-pinned executable with no-follow/reparse checks and
/// returns the exact canonical path used for the digest proof.
///
/// # Errors
///
/// Returns an error when the path or digest is invalid, the artifact is absent
/// or a reparse point, its identity changes, or its digest mismatches.
pub fn validate_pinned_artifact(
    path: &Path,
    expected_sha256: &str,
) -> Result<PathBuf, WindowsAdapterError> {
    if !path.is_absolute() || !crate::valid_sha256_hex(expected_sha256) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    #[cfg(windows)]
    {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;

        crate::reject_reparse_chain(path, true)
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let canonical = std::fs::canonicalize(path).map_err(|_| WindowsAdapterError::NotFound)?;
        crate::reject_reparse_chain(&canonical, true)
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        );
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file = options
            .open(&canonical)
            .map_err(|_| WindowsAdapterError::NotFound)?;
        let metadata = file
            .metadata()
            .map_err(|_| WindowsAdapterError::Unavailable)?;
        if !metadata.is_file() || crate::is_reparse_point(&metadata) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        if metadata.len() > 256 * 1024 * 1024 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(|_| WindowsAdapterError::Unavailable)?;
        if crate::sha256_hex(&bytes) != expected_sha256 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(canonical)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, expected_sha256);
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(windows)]
fn register_watchdog_task_windows(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRegistrationReceipt, WindowsAdapterError> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        CLSID_CTaskScheduler, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::BSTR;

    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if initialized.0 < 0 {
        return Err(WindowsAdapterError::Unavailable);
    }
    let result = (|| {
        let service: ITaskService =
            unsafe { CoCreateInstance(&CLSID_CTaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        let empty = VARIANT::default();
        unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        }
        let root = unsafe {
            service
                .GetFolder(&BSTR::from("\\"))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let folder = get_or_create_watchdog_folder(&root, &empty)?;
        let xml = watchdog_task_xml(registration);
        let registered = match unsafe {
            folder.RegisterTask(
                &BSTR::from(WATCHDOG_FALLBACK_TASK_LEAF),
                &BSTR::from(xml),
                TASK_CREATE_OR_UPDATE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )
        } {
            Ok(registered) => registered,
            Err(_) => unsafe {
                folder
                    .GetTask(&BSTR::from(WATCHDOG_FALLBACK_TASK_LEAF))
                    .map_err(|_| WindowsAdapterError::Unavailable)?
            },
        };
        let actual_xml = readback_watchdog_task(&registered, registration)?;
        Ok(WatchdogTaskRegistrationReceipt {
            task_name: registration.task_name.clone(),
            sid: registration.expected_sid.clone(),
            session_id: registration.expected_session_id,
            notify_artifact_sha256: registration.notify_artifact_sha256.clone(),
            verifier_sha256: registration.verifier_sha256.clone(),
            task_xml_sha256: crate::sha256_hex(actual_xml.as_bytes()),
        })
    })();
    unsafe {
        CoUninitialize();
    }
    result
}

/// Requests one immediate run of an already registered fallback task after
/// the protected Watchdog envelope is present.  A scheduler/API failure is
/// returned as `Unavailable` so callers retain an unknown/reconcile cursor;
/// it is never projected as a successful notification.
///
/// # Errors
///
/// Returns an error when pinned registration or envelope evidence is invalid,
/// or when Task Scheduler cannot start and verify the fixed task.
pub fn run_registered_watchdog_task(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRunReceipt, WindowsAdapterError> {
    validate_watchdog_registration(registration)?;
    let envelope = ProtectedPathLease::open_existing_absolute(&registration.envelope_path)
        .map_err(|_| WindowsAdapterError::NotFound)?;
    envelope
        .verify_stable_identity()
        .and_then(|()| envelope.verify_path_identity())
        .and_then(|()| envelope.read_bounded(64 * 1024).map(|_| ()))
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    #[cfg(windows)]
    {
        run_registered_watchdog_task_windows(registration)
    }
    #[cfg(not(windows))]
    {
        let _ = registration;
        Err(WindowsAdapterError::Unavailable)
    }
}

/// Observation returned only after Task Scheduler accepted a bounded run
/// request for the registered interactive SID/session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTaskRunReceipt {
    task_name: String,
    sid: String,
    session_id: u32,
    task_xml_sha256: String,
}

impl WatchdogTaskRunReceipt {
    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    #[must_use]
    pub fn task_xml_sha256(&self) -> &str {
        &self.task_xml_sha256
    }
}

#[cfg(windows)]
fn run_registered_watchdog_task_windows(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRunReceipt, WindowsAdapterError> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        CLSID_CTaskScheduler, ITaskService, TASK_RUN_USE_SESSION_ID,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::BSTR;

    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if initialized.0 < 0 {
        return Err(WindowsAdapterError::Unavailable);
    }
    let result = (|| {
        let service: ITaskService =
            unsafe { CoCreateInstance(&CLSID_CTaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        let empty = VARIANT::default();
        unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        }
        let root = unsafe {
            service
                .GetFolder(&BSTR::from("\\"))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let folder = unsafe {
            root.GetFolder(&BSTR::from(WATCHDOG_FALLBACK_TASK_FOLDER))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let task = unsafe {
            folder
                .GetTask(&BSTR::from(WATCHDOG_FALLBACK_TASK_LEAF))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let actual_xml = readback_watchdog_task(&task, registration)?;
        let session_id = i32::try_from(registration.expected_session_id())
            .map_err(|_| WindowsAdapterError::InvalidInput)?;
        if unsafe {
            task.RunEx(
                &empty,
                TASK_RUN_USE_SESSION_ID.0,
                session_id,
                &BSTR::from(registration.expected_sid()),
            )
        }
        .is_err()
        {
            let _ = readback_watchdog_task(&task, registration)?;
            return Err(WindowsAdapterError::Unavailable);
        }
        Ok(WatchdogTaskRunReceipt {
            task_name: registration.task_name.clone(),
            sid: registration.expected_sid.clone(),
            session_id: registration.expected_session_id,
            task_xml_sha256: crate::sha256_hex(actual_xml.as_bytes()),
        })
    })();
    unsafe {
        CoUninitialize();
    }
    result
}

#[cfg(windows)]
fn readback_watchdog_task(
    task: &windows::Win32::System::TaskScheduler::IRegisteredTask,
    registration: &WatchdogTaskRegistration,
) -> Result<String, WindowsAdapterError> {
    let actual_path = unsafe { task.Path().map_err(|_| WindowsAdapterError::Unavailable)? };
    let actual_xml = unsafe { task.Xml().map_err(|_| WindowsAdapterError::Unavailable)? };
    let actual_xml =
        String::try_from(&actual_xml).map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    if actual_path != registration.task_name()
        || !watchdog_task_readback_matches(registration, &actual_xml)
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(actual_xml)
}

#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed Task Scheduler XML shape remains one contiguous predicate"
)]
pub(super) fn watchdog_task_readback_matches(
    registration: &WatchdogTaskRegistration,
    actual_xml: &str,
) -> bool {
    let Some(task) = xml_section(actual_xml, "Task") else {
        return false;
    };
    let Some(registration_info) = xml_section(task, "RegistrationInfo") else {
        return false;
    };
    let Some(triggers) = xml_section(task, "Triggers") else {
        return false;
    };
    let Some(principals) = xml_section(task, "Principals") else {
        return false;
    };
    let Some(settings) = xml_section(task, "Settings") else {
        return false;
    };
    let Some(actions) = xml_section(task, "Actions") else {
        return false;
    };
    if opening_tag(actual_xml, "Task")
        != Some(
            r#"<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"#,
        )
        || !has_exact_tag_shape(
            registration_info,
            &[
                ("RegistrationInfo", 1),
                ("Author", 1),
                ("Description", 1),
                ("URI", 1),
            ],
        )
        || opening_tag(principals, "Principal") != Some(r#"<Principal id="Author">"#)
        || opening_tag(actions, "Actions") != Some(r#"<Actions Context="Author">"#)
        || !has_exact_tag_shape(
            triggers,
            &[
                ("Triggers", 1),
                ("LogonTrigger", 1),
                ("Enabled", 1),
                ("UserId", 1),
            ],
        )
        || !has_exact_tag_shape(
            principals,
            &[
                ("Principals", 1),
                ("Principal", 1),
                ("UserId", 1),
                ("LogonType", 1),
                ("RunLevel", 1),
            ],
        )
        || !has_exact_tag_shape(
            settings,
            &[
                ("Settings", 1),
                ("MultipleInstancesPolicy", 1),
                ("DisallowStartIfOnBatteries", 1),
                ("StopIfGoingOnBatteries", 1),
                ("AllowHardTerminate", 1),
                ("StartWhenAvailable", 1),
                ("ExecutionTimeLimit", 1),
                ("Priority", 1),
            ],
        )
        || !has_exact_tag_shape(
            actions,
            &[
                ("Actions", 1),
                ("Exec", 1),
                ("Command", 1),
                ("Arguments", 1),
                ("WorkingDirectory", 1),
            ],
        )
    {
        return false;
    }
    let escaped_sid = xml_escape(registration.expected_sid());
    let escaped_executable = xml_escape(&registration.notify_executable.display().to_string());
    let escaped_working_directory = xml_escape(
        &registration
            .notify_executable
            .parent()
            .unwrap_or_else(|| Path::new("\\"))
            .display()
            .to_string(),
    );
    let escaped_verifier = xml_escape(&registration.verifier_path.display().to_string());
    let escaped_envelope = xml_escape(&registration.envelope_path.display().to_string());
    let description = format!(
        "X-01 signed one-shot Watchdog fallback; verifier={escaped_verifier}; envelope={escaped_envelope}; artifact={}; verifier_sha256={}",
        registration.notify_artifact_sha256(),
        registration.verifier_sha256()
    );
    element_text(actual_xml, "URI") == Some(registration.task_name())
        && element_text(triggers, "Enabled") == Some("true")
        && element_text(triggers, "UserId") == Some(escaped_sid.as_str())
        && element_text(principals, "UserId") == Some(escaped_sid.as_str())
        && element_text(principals, "LogonType") == Some("InteractiveToken")
        && element_text(principals, "RunLevel") == Some("LeastPrivilege")
        && element_text(settings, "MultipleInstancesPolicy") == Some("IgnoreNew")
        && element_text(settings, "DisallowStartIfOnBatteries") == Some("false")
        && element_text(settings, "StopIfGoingOnBatteries") == Some("false")
        && element_text(settings, "AllowHardTerminate") == Some("true")
        && element_text(settings, "StartWhenAvailable") == Some("true")
        && element_text(settings, "ExecutionTimeLimit") == Some("PT5M")
        && element_text(settings, "Priority") == Some("7")
        && element_text(actions, "Command") == Some(escaped_executable.as_str())
        && element_text(actions, "Arguments") == Some("--watchdog-fallback")
        && element_text(actions, "WorkingDirectory") == Some(escaped_working_directory.as_str())
        && element_text(registration_info, "Author") == Some("Eliot installer")
        && element_text(registration_info, "Description") == Some(description.as_str())
        && element_text(actual_xml, "Description") == Some(description.as_str())
}

pub(super) fn watchdog_task_xml(registration: &WatchdogTaskRegistration) -> String {
    let task_name = xml_escape(registration.task_name());
    let sid = xml_escape(registration.expected_sid());
    let executable = xml_escape(&registration.notify_executable.display().to_string());
    let working_directory = xml_escape(
        &registration
            .notify_executable
            .parent()
            .unwrap_or_else(|| Path::new("\\"))
            .display()
            .to_string(),
    );
    let verifier = xml_escape(&registration.verifier_path.display().to_string());
    let envelope = xml_escape(&registration.envelope_path.display().to_string());
    let artifact_digest = xml_escape(registration.notify_artifact_sha256());
    let verifier_digest = xml_escape(registration.verifier_sha256());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Eliot installer</Author>
    <Description>X-01 signed one-shot Watchdog fallback; verifier={verifier}; envelope={envelope}; artifact={artifact_digest}; verifier_sha256={verifier_digest}</Description>
    <URI>{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{sid}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{executable}</Command>
      <Arguments>--watchdog-fallback</Arguments>
      <WorkingDirectory>{working_directory}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn get_or_create_watchdog_folder(
    root: &windows::Win32::System::TaskScheduler::ITaskFolder,
    empty: &windows::Win32::System::Variant::VARIANT,
) -> Result<windows::Win32::System::TaskScheduler::ITaskFolder, WindowsAdapterError> {
    use windows::core::BSTR;
    match unsafe { root.GetFolder(&BSTR::from(WATCHDOG_FALLBACK_TASK_FOLDER)) } {
        Ok(folder) => Ok(folder),
        Err(_) => unsafe {
            root.CreateFolder(&BSTR::from("Eliot"), empty)
                .or_else(|_| root.GetFolder(&BSTR::from(WATCHDOG_FALLBACK_TASK_FOLDER)))
        }
        .map_err(|_| WindowsAdapterError::Unavailable),
    }
}

fn xml_section<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let open_end = xml[start..].find('>')? + start + 1;
    let close = format!("</{tag}>");
    let close_start = xml[open_end..].find(&close)? + open_end;
    if count_xml_open_tag(xml, tag) != 1 {
        return None;
    }
    Some(&xml[start..close_start + close.len()])
}

fn element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if xml.match_indices(&open).count() != 1 || xml.match_indices(&close).count() != 1 {
        return None;
    }
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

fn opening_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let prefix = format!("<{tag}");
    let start = xml.match_indices(&prefix).find_map(|(index, _)| {
        matches!(
            xml.get(index + prefix.len()..)
                .and_then(|rest| rest.chars().next()),
            Some(' ' | '>' | '/')
        )
        .then_some(index)
    })?;
    let end = xml[start..].find('>')? + start + 1;
    Some(&xml[start..end])
}

fn count_xml_open_tag(xml: &str, tag: &str) -> usize {
    let prefix = format!("<{tag}");
    xml.match_indices(&prefix)
        .filter(|(index, _)| {
            matches!(
                xml.get(index + prefix.len()..)
                    .and_then(|rest| rest.chars().next()),
                Some(' ' | '>' | '/')
            )
        })
        .count()
}

fn has_exact_tag_shape(xml: &str, expected: &[(&str, usize)]) -> bool {
    let names = xml_open_tag_names(xml);
    let expected_total = expected.iter().map(|(_, count)| *count).sum::<usize>();
    names.len() == expected_total
        && expected
            .iter()
            .all(|(tag, count)| names.iter().filter(|name| name.as_str() == *tag).count() == *count)
}

fn xml_open_tag_names(xml: &str) -> Vec<String> {
    let bytes = xml.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let Some(relative) = xml[index..].find('<') else {
            break;
        };
        let start = index + relative;
        let Some(next) = bytes.get(start + 1).copied() else {
            break;
        };
        if matches!(next, b'/' | b'!' | b'?') {
            index = start + 1;
            continue;
        }
        let name_start = start + 1;
        let name_end = (name_start..bytes.len())
            .find(|candidate| {
                matches!(
                    bytes[*candidate],
                    b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/'
                )
            })
            .unwrap_or(bytes.len());
        if name_end > name_start {
            names.push(xml[name_start..name_end].to_owned());
        }
        index = name_end.saturating_add(1);
    }
    names
}

/// Dedicated Windows OS-CSPRNG target factory for the `LocalService` Store
/// credential namespace.
///
/// This semantic factory is intentionally separate from installer ownership
/// references and Kernel activation nonces. It returns only the non-secret
/// Credential Manager target; credential bytes are generated and written by
/// the authenticated Store credential effect.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsStoreCredentialTargetGenerator;

impl WindowsStoreCredentialTargetGenerator {
    const RANDOM_BYTES: usize = 16;

    /// Constructs a target factory without touching Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Issues one unpredictable `eliot/store/v1/<32 lowercase hex>` target.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when the Windows OS CSPRNG is
    /// unavailable or the bounded target cannot be represented.
    pub fn fresh_target(&self) -> Result<PlatformHandle, WindowsAdapterError> {
        let mut random = [0_u8; Self::RANDOM_BYTES];
        crate::fill_system_random(&mut random)?;
        let target = format!(
            "{}{}",
            crate::secret_store::STORE_CREDENTIAL_TARGET_PREFIX,
            crate::hex_lower(&random)
        );
        random.fill(0);
        PlatformHandle::new(target).map_err(|_| WindowsAdapterError::InvalidInput)
    }
}

/// Verifies the exact owner, protected DACL and descriptor bytes on a live
/// handle.  This narrow helper is shared by protected installer primitives so
/// they cannot accidentally downgrade to a path-only ACL check.
#[cfg(windows)]
pub(crate) fn verify_exact_file_security(
    file: &std::fs::File,
    expected: &crate::OwnedSecurityDescriptor,
    expected_owner: &str,
) -> Result<(), WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };

    let expected_dacl = expected.dacl()?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(
            if status == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED {
                WindowsAdapterError::PermissionDenied
            } else {
                WindowsAdapterError::AclMismatch
            },
        );
    }

    let mut present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let dacl_matches = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut actual_dacl,
            &raw mut defaulted,
        ) != 0
            && present != 0
            && !actual_dacl.is_null()
            && (*actual_dacl).AclSize == (*expected_dacl).AclSize
            && std::slice::from_raw_parts(
                actual_dacl.cast::<u8>(),
                usize::from((*actual_dacl).AclSize),
            ) == std::slice::from_raw_parts(
                expected_dacl.cast::<u8>(),
                usize::from((*expected_dacl).AclSize),
            )
    };
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let protected = unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
    };
    let owner_matches =
        crate::sid_to_string(owner).is_ok_and(|observed| observed == expected_owner);
    unsafe { LocalFree(descriptor.cast()) };
    if dacl_matches && protected && owner_matches {
        Ok(())
    } else {
        Err(WindowsAdapterError::AclMismatch)
    }
}

/// Exact masks used by the installed Agent Bridge security contour.
pub const AGENT_BRIDGE_FILE_TRAVERSE_ACCESS_MASK: u32 = 0x0000_0020;
pub const AGENT_BRIDGE_DECLARATION_READ_ACCESS_MASK: u32 = 0x0012_0089;

/// Provider readback for the four Agent Bridge objects after ACL convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBridgeSecurityConvergenceReceipt {
    /// Retained Host state-root identity.
    pub host_state_root_identity: FileIdentity,
    /// Retained `agent-bridge` directory identity.
    pub bridge_directory_identity: FileIdentity,
    /// Retained admission-profile identity.
    pub profile_identity: FileIdentity,
    /// Retained client-declaration identity.
    pub declaration_identity: FileIdentity,
    /// Raw security-descriptor digests read from the four retained handles.
    pub host_state_root_descriptor_sha256: String,
    pub bridge_directory_descriptor_sha256: String,
    pub profile_descriptor_sha256: String,
    pub declaration_descriptor_sha256: String,
}

#[cfg(windows)]
fn open_agent_bridge_acl_target(
    path: &Path,
    directory: bool,
) -> Result<std::fs::File, WindowsAdapterError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC,
    };
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        );
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WindowsAdapterError::NotFound
        } else if error.kind() == std::io::ErrorKind::PermissionDenied {
            WindowsAdapterError::PermissionDenied
        } else {
            WindowsAdapterError::Failed
        }
    })?;
    let metadata = file.metadata().map_err(|_| WindowsAdapterError::Failed)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if metadata.is_dir() != directory {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(file)
}

#[cfg(windows)]
fn descriptor_digest_raw(
    raw: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<String, WindowsAdapterError> {
    use windows_sys::Win32::Security::GetSecurityDescriptorLength;
    if raw.is_null() {
        return Err(WindowsAdapterError::AclMismatch);
    }
    let length = unsafe { GetSecurityDescriptorLength(raw) };
    if length == 0 {
        return Err(WindowsAdapterError::AclMismatch);
    }
    let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), length as usize) };
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(windows)]
fn descriptor_digest_for_handle(file: &std::fs::File) -> Result<String, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(WindowsAdapterError::AclMismatch);
    }
    let digest = descriptor_digest_raw(descriptor);
    unsafe { LocalFree(descriptor.cast()) };
    digest
}

#[cfg(windows)]
fn apply_agent_bridge_descriptor(
    file: &std::fs::File,
    expected: &crate::OwnedSecurityDescriptor,
) -> Result<(), WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let dacl = expected.dacl()?;
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(
            if status == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED {
                WindowsAdapterError::PermissionDenied
            } else {
                WindowsAdapterError::AclMismatch
            },
        );
    }
    verify_exact_file_security(file, expected, "S-1-5-18")
}

#[cfg(windows)]
fn converge_agent_bridge_acl_target(
    file: &std::fs::File,
    old: &crate::OwnedSecurityDescriptor,
    final_descriptor: &crate::OwnedSecurityDescriptor,
) -> Result<String, WindowsAdapterError> {
    if verify_exact_file_security(file, final_descriptor, "S-1-5-18").is_err() {
        if verify_exact_file_security(file, old, "S-1-5-18").is_err() {
            return Err(WindowsAdapterError::AclMismatch);
        }
        apply_agent_bridge_descriptor(file, final_descriptor)?;
    }
    verify_exact_file_security(file, final_descriptor, "S-1-5-18")?;
    descriptor_digest_for_handle(file)
}

/// Converges the installed Agent Bridge pair and traversal contour.
///
/// The Host only publishes under its pre-existing service-only ACL. This
/// elevated provider operation classifies every retained no-follow handle as
/// either the exact old service contour or the exact final contour, then
/// applies the final descriptors in files → child → root order. A foreign or
/// partial descriptor is never rewritten.
#[cfg(windows)]
pub fn converge_agent_bridge_security(
    host_state_root: &Path,
    approved_user_sid: &str,
    profile_path: &Path,
    declaration_path: &Path,
) -> Result<AgentBridgeSecurityConvergenceReceipt, WindowsAdapterError> {
    if !crate::valid_sid_text(approved_user_sid) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let bridge_directory = host_state_root.join("agent-bridge");
    if profile_path != bridge_directory.join("admission-profile-v1.json")
        || declaration_path != bridge_directory.join("client-declaration-v2.json")
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let root = open_agent_bridge_acl_target(host_state_root, true)?;
    let child = open_agent_bridge_acl_target(&bridge_directory, true)?;
    let profile = open_agent_bridge_acl_target(profile_path, false)?;
    let declaration = open_agent_bridge_acl_target(declaration_path, false)?;
    let old_directory = crate::OwnedSecurityDescriptor::for_installer_system_object(true)?;
    let old_file = crate::OwnedSecurityDescriptor::for_installer_system_object(false)?;
    let service_only =
        crate::OwnedSecurityDescriptor::from_sddl("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)")?;
    let child_final = crate::OwnedSecurityDescriptor::from_sddl(&format!(
        "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)(A;;0x{AGENT_BRIDGE_FILE_TRAVERSE_ACCESS_MASK:08X};;;{approved_user_sid})"
    ))?;
    let declaration_final = crate::OwnedSecurityDescriptor::from_sddl(&format!(
        "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)(A;;0x{AGENT_BRIDGE_DECLARATION_READ_ACCESS_MASK:08X};;;{approved_user_sid})"
    ))?;
    let profile_digest = converge_agent_bridge_acl_target(&profile, &old_file, &service_only)?;
    let declaration_digest =
        converge_agent_bridge_acl_target(&declaration, &old_file, &declaration_final)?;
    let child_digest = converge_agent_bridge_acl_target(&child, &old_directory, &child_final)?;
    let root_digest = converge_agent_bridge_acl_target(&root, &old_directory, &child_final)?;
    Ok(AgentBridgeSecurityConvergenceReceipt {
        host_state_root_identity: crate::file_identity_from_handle(&root)
            .map_err(|_| WindowsAdapterError::Failed)?,
        bridge_directory_identity: crate::file_identity_from_handle(&child)
            .map_err(|_| WindowsAdapterError::Failed)?,
        profile_identity: crate::file_identity_from_handle(&profile)
            .map_err(|_| WindowsAdapterError::Failed)?,
        declaration_identity: crate::file_identity_from_handle(&declaration)
            .map_err(|_| WindowsAdapterError::Failed)?,
        host_state_root_descriptor_sha256: root_digest,
        bridge_directory_descriptor_sha256: child_digest,
        profile_descriptor_sha256: profile_digest,
        declaration_descriptor_sha256: declaration_digest,
    })
}

/// Verifies the final Agent Bridge ACL contour without mutating any object.
/// This is the dedicated Host recovery/admission reader; it does not use the
/// legacy protected-path lease, and rejects the pre-convergence service ACL.
#[cfg(windows)]
pub struct AgentBridgeFinalReadLease {
    #[allow(dead_code)]
    root: std::fs::File,
    #[allow(dead_code)]
    child: std::fs::File,
    profile: std::fs::File,
    declaration: std::fs::File,
    receipt: AgentBridgeSecurityConvergenceReceipt,
}

/// Narrow bridge-client reader. It deliberately never opens the
/// service-only admission profile; only the declaration and its traversable
/// root contour are retained.
#[cfg(windows)]
pub struct AgentBridgeDeclarationReadLease {
    #[allow(dead_code)]
    root: std::fs::File,
    #[allow(dead_code)]
    child: std::fs::File,
    declaration: std::fs::File,
    pub root_identity: FileIdentity,
    pub child_identity: FileIdentity,
    pub declaration_identity: FileIdentity,
    pub root_descriptor_sha256: Option<String>,
    pub child_descriptor_sha256: Option<String>,
    pub declaration_descriptor_sha256: String,
}

#[cfg(windows)]
fn open_agent_bridge_traverse_directory(
    path: &Path,
) -> Result<(FileIdentity, std::fs::File), WindowsAdapterError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(FILE_TRAVERSE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| WindowsAdapterError::PermissionDenied)?;
    let metadata = file.metadata().map_err(|_| WindowsAdapterError::Failed)?;
    if metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
        || !metadata.is_dir()
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let identity =
        crate::file_identity_from_handle(&file).map_err(|_| WindowsAdapterError::Failed)?;
    Ok((identity, file))
}

#[cfg(windows)]
impl AgentBridgeDeclarationReadLease {
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, WindowsAdapterError> {
        read_agent_bridge_lease_bytes(&mut self.declaration)
    }
}

#[cfg(windows)]
pub fn open_agent_bridge_declaration_read_lease(
    declaration_path: &Path,
) -> Result<AgentBridgeDeclarationReadLease, WindowsAdapterError> {
    let bridge_directory = declaration_path
        .parent()
        .ok_or(WindowsAdapterError::InvalidInput)?;
    let host_state_root = bridge_directory
        .parent()
        .ok_or(WindowsAdapterError::InvalidInput)?;
    if declaration_path.file_name().and_then(|name| name.to_str())
        != Some("client-declaration-v2.json")
        || bridge_directory.file_name().and_then(|name| name.to_str()) != Some("agent-bridge")
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let approved_user_sid =
        crate::current_process_sid().map_err(|_| WindowsAdapterError::Unavailable)?;
    if !crate::valid_sid_text(&approved_user_sid) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let bridge_directory = host_state_root.join("agent-bridge");
    let (root_identity, root) = open_agent_bridge_traverse_directory(host_state_root)?;
    let (child_identity, child) = open_agent_bridge_traverse_directory(&bridge_directory)?;
    let (declaration_identity, declaration) = crate::open_no_follow_file(declaration_path)
        .map_err(|_| WindowsAdapterError::PermissionDenied)?;
    let final_declaration = crate::OwnedSecurityDescriptor::from_sddl(&format!(
        "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)(A;;0x{AGENT_BRIDGE_DECLARATION_READ_ACCESS_MASK:08X};;;{approved_user_sid})"
    ))?;
    verify_exact_file_security(&declaration, &final_declaration, "S-1-5-18")?;
    Ok(AgentBridgeDeclarationReadLease {
        root_descriptor_sha256: None,
        child_descriptor_sha256: None,
        declaration_descriptor_sha256: descriptor_digest_for_handle(&declaration)?,
        root,
        child,
        declaration,
        root_identity,
        child_identity,
        declaration_identity,
    })
}

#[cfg(windows)]
impl AgentBridgeFinalReadLease {
    pub fn receipt(&self) -> &AgentBridgeSecurityConvergenceReceipt {
        &self.receipt
    }

    pub fn read_profile_bytes(&mut self) -> Result<Vec<u8>, WindowsAdapterError> {
        read_agent_bridge_lease_bytes(&mut self.profile)
    }

    pub fn read_declaration_bytes(&mut self) -> Result<Vec<u8>, WindowsAdapterError> {
        read_agent_bridge_lease_bytes(&mut self.declaration)
    }
}

#[cfg(windows)]
fn read_agent_bridge_lease_bytes(file: &mut std::fs::File) -> Result<Vec<u8>, WindowsAdapterError> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsAdapterError::Failed)?;
    let length = file
        .metadata()
        .map_err(|_| WindowsAdapterError::Failed)?
        .len();
    if length == 0 || length > 16 * 1024 * 1024 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_| WindowsAdapterError::InvalidInput)?);
    file.take(length)
        .read_to_end(&mut bytes)
        .map_err(|_| WindowsAdapterError::Failed)?;
    if bytes.len() as u64 != length {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(bytes)
}

#[cfg(windows)]
pub fn open_agent_bridge_final_read_lease(
    host_state_root: &Path,
    approved_user_sid: &str,
    profile_path: &Path,
    declaration_path: &Path,
) -> Result<AgentBridgeFinalReadLease, WindowsAdapterError> {
    if !crate::valid_sid_text(approved_user_sid) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let bridge_directory = host_state_root.join("agent-bridge");
    if profile_path != bridge_directory.join("admission-profile-v1.json")
        || declaration_path != bridge_directory.join("client-declaration-v2.json")
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let (root_identity, root) = crate::open_no_follow_directory(host_state_root)
        .map_err(|_| WindowsAdapterError::PermissionDenied)?;
    let (child_identity, child) = crate::open_no_follow_directory(&bridge_directory)
        .map_err(|_| WindowsAdapterError::PermissionDenied)?;
    let (profile_identity, profile) = crate::open_no_follow_file(profile_path)
        .map_err(|_| WindowsAdapterError::PermissionDenied)?;
    let (declaration_identity, declaration) = crate::open_no_follow_file(declaration_path)
        .map_err(|_| WindowsAdapterError::PermissionDenied)?;
    let service_only =
        crate::OwnedSecurityDescriptor::from_sddl("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)")?;
    let final_directory = crate::OwnedSecurityDescriptor::from_sddl(&format!(
        "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)(A;;0x{AGENT_BRIDGE_FILE_TRAVERSE_ACCESS_MASK:08X};;;{approved_user_sid})"
    ))?;
    let final_declaration = crate::OwnedSecurityDescriptor::from_sddl(&format!(
        "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)(A;;0x{AGENT_BRIDGE_DECLARATION_READ_ACCESS_MASK:08X};;;{approved_user_sid})"
    ))?;
    verify_exact_file_security(&profile, &service_only, "S-1-5-18")?;
    verify_exact_file_security(&declaration, &final_declaration, "S-1-5-18")?;
    verify_exact_file_security(&child, &final_directory, "S-1-5-18")?;
    verify_exact_file_security(&root, &final_directory, "S-1-5-18")?;
    let receipt = AgentBridgeSecurityConvergenceReceipt {
        host_state_root_identity: root_identity,
        bridge_directory_identity: child_identity,
        profile_identity,
        declaration_identity,
        host_state_root_descriptor_sha256: descriptor_digest_for_handle(&root)?,
        bridge_directory_descriptor_sha256: descriptor_digest_for_handle(&child)?,
        profile_descriptor_sha256: descriptor_digest_for_handle(&profile)?,
        declaration_descriptor_sha256: descriptor_digest_for_handle(&declaration)?,
    };
    Ok(AgentBridgeFinalReadLease {
        root,
        child,
        profile,
        declaration,
        receipt,
    })
}

#[cfg(not(windows))]
pub fn open_agent_bridge_declaration_read_lease(
    declaration_path: &Path,
) -> Result<(), WindowsAdapterError> {
    let _ = declaration_path;
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
pub fn verify_agent_bridge_security(
    host_state_root: &Path,
    approved_user_sid: &str,
    profile_path: &Path,
    declaration_path: &Path,
) -> Result<AgentBridgeSecurityConvergenceReceipt, WindowsAdapterError> {
    Ok(open_agent_bridge_final_read_lease(
        host_state_root,
        approved_user_sid,
        profile_path,
        declaration_path,
    )?
    .receipt)
}

#[cfg(not(windows))]
pub fn converge_agent_bridge_security(
    host_state_root: &Path,
    approved_user_sid: &str,
    profile_path: &Path,
    declaration_path: &Path,
) -> Result<AgentBridgeSecurityConvergenceReceipt, WindowsAdapterError> {
    let _ = (
        host_state_root,
        approved_user_sid,
        profile_path,
        declaration_path,
    );
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(not(windows))]
pub fn verify_agent_bridge_security(
    host_state_root: &Path,
    approved_user_sid: &str,
    profile_path: &Path,
    declaration_path: &Path,
) -> Result<AgentBridgeSecurityConvergenceReceipt, WindowsAdapterError> {
    let _ = (
        host_state_root,
        approved_user_sid,
        profile_path,
        declaration_path,
    );
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(not(windows))]
pub fn open_agent_bridge_final_read_lease(
    host_state_root: &Path,
    approved_user_sid: &str,
    profile_path: &Path,
    declaration_path: &Path,
) -> Result<(), WindowsAdapterError> {
    let _ = (
        host_state_root,
        approved_user_sid,
        profile_path,
        declaration_path,
    );
    Err(WindowsAdapterError::Unavailable)
}
