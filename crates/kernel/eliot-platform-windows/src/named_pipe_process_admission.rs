//! OS-observed named-pipe peer process admission.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A2.3`, `A12.2`, and `A12.3`.
//! - `docs/architecture/A16-01-decision-anchors.md`: `ARCH-AUTH-01`,
//!   `ARCH-SEC-01`, and `ARCH-SEC-02`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I2.23`, `I7.5`, `I7.14`,
//!   and `I15.2`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This module owns only sealed process/SID/session/Job evidence and
//! deterministic admission checks that bind a live peer to inert,
//! caller-selected expectations.
//!
//! Named-pipe listener/server creation, DACL/ACE construction, wire
//! handshake/session state, peer-role selection, generic process identity,
//! service registration, and tests remain with their existing owners. The
//! Host service query below is read-only process observation; this module
//! issues no authority, canonical transition, or semantic result.

use std::path::Path;

use crate::{
    ELIOT_HOST_SERVICE_NAME, FileIdentity, NamedPipeAuthDiscriminator, ProcessIdentity,
    WindowsAdapterError, file_identity, inspect_process_identity, job_process_ids,
    last_windows_adapter_error, process_token_identity, same_process_identity,
    same_process_image_path, service_runtime_sample_is_stable, valid_process_image_path,
    valid_sid_text, windows_adapter_from_io,
};

/// OS-observed process identity that may be used to pin named-pipe admission.
///
/// The identity is private and this type has no deserializer or public
/// constructor. Callers can obtain it only through
/// [`observe_named_pipe_peer_process`], which opens and observes the live
/// process handle. The contained identity is evidence, not request data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerProcessBinding {
    identity: ProcessIdentity,
    executable_file: Option<FileIdentity>,
}

impl NamedPipePeerProcessBinding {
    fn from_observed(identity: ProcessIdentity) -> Result<Self, WindowsAdapterError> {
        if !identity.is_usable() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let executable_file = file_identity(Path::new(&identity.image_path)).ok();
        Ok(Self {
            identity,
            executable_file,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        identity: ProcessIdentity,
        executable_file: Option<FileIdentity>,
    ) -> Result<Self, WindowsAdapterError> {
        if !identity.is_usable() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            identity,
            executable_file,
        })
    }

    /// Returns the read-only process evidence captured by the platform.
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Returns the observed process identifier.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.identity.process_id
    }

    /// Returns the observed process creation time in Windows 100-nanosecond
    /// units.
    #[must_use]
    pub const fn start_time_100ns(&self) -> u64 {
        self.identity.start_time_100ns
    }

    /// Returns the observed process image path.
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.identity.image_path
    }

    /// Returns the file-object identity observed for the executable image when
    /// the platform could open it without following a reparse point.
    #[must_use]
    pub const fn executable_file_identity(&self) -> Option<FileIdentity> {
        self.executable_file
    }
}

/// OS-observed process identity retained together with one exact owner Job.
///
/// The Job name is only a lookup key.  Admission reopens and re-observes the
/// named Job, process identity, and current membership before accepting a
/// pipe peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerJobBinding {
    pub(crate) process: NamedPipePeerProcessBinding,
    job_name: String,
}

impl NamedPipePeerJobBinding {
    pub(crate) fn from_observed(
        process: NamedPipePeerProcessBinding,
        job_name: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let job_name = job_name.into();
        if !valid_named_job_identity(&job_name) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { process, job_name })
    }

    /// Returns the retained handle-bound process evidence.
    #[must_use]
    pub const fn process_binding(&self) -> &NamedPipePeerProcessBinding {
        &self.process
    }

    /// Returns the exact owner-scoped Job identity.
    #[must_use]
    pub fn job_name(&self) -> &str {
        &self.job_name
    }
}

/// Expected authorization context for a named-pipe server.
///
/// The expectation is inert policy input.  It becomes evidence only after the
/// platform adapter observes the pipe handle, server process and token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerExpectation {
    expected_sid: String,
    expected_session_id: u32,
    approved_process: Option<NamedPipePeerProcessBinding>,
    approved_job_process: Option<NamedPipePeerJobBinding>,
    dynamic_image_path: Option<String>,
    dynamic_executable_file: Option<FileIdentity>,
    builtin_administrators: bool,
}

impl NamedPipePeerExpectation {
    /// Creates inert expected SID/session policy.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the SID is not canonical SID text.
    pub fn new(
        expected_sid: impl Into<String>,
        expected_session_id: u32,
    ) -> Result<Self, WindowsAdapterError> {
        let expected_sid = expected_sid.into();
        if !valid_sid_text(&expected_sid) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            expected_sid,
            expected_session_id,
            approved_process: None,
            approved_job_process: None,
            dynamic_image_path: None,
            dynamic_executable_file: None,
            builtin_administrators: false,
        })
    }

    /// Creates inert policy for an elevated installer client. The live pipe
    /// client is impersonated and its token must have the built-in
    /// Administrators group enabled; its exact user SID/session are still
    /// returned as evidence and bound to the connected process.
    ///
    /// # Errors
    ///
    /// This constructor currently cannot fail; the `Result` preserves the
    /// constructor shape shared with validated peer expectations.
    pub fn new_for_builtin_administrators() -> Result<Self, WindowsAdapterError> {
        Ok(Self {
            expected_sid: "S-1-5-32-544".to_owned(),
            expected_session_id: 0,
            approved_process: None,
            approved_job_process: None,
            dynamic_image_path: None,
            dynamic_executable_file: None,
            builtin_administrators: true,
        })
    }

    /// Creates a bridge expectation for a fresh process generation. The SID,
    /// normalized executable path and no-follow file identity are stable
    /// policy; PID, start time and interactive session are observed afresh on
    /// each connected handle.
    pub fn new_for_dynamic_process(
        expected_sid: impl Into<String>,
        image_path: impl Into<String>,
        executable_file: FileIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        let expected_sid = expected_sid.into();
        let image_path = image_path.into();
        if !valid_sid_text(&expected_sid)
            || !valid_process_image_path(&image_path)
            || executable_file.volume_serial_number == 0
            || executable_file.file_index == 0
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            expected_sid,
            expected_session_id: 0,
            approved_process: None,
            approved_job_process: None,
            dynamic_image_path: Some(image_path),
            dynamic_executable_file: Some(executable_file),
            builtin_administrators: false,
        })
    }

    /// Creates an expectation that additionally admits one exact OS-observed
    /// process binding. A PID supplied by a request cannot replace this
    /// binding.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the SID or binding is invalid.
    pub fn new_with_process_binding(
        expected_sid: impl Into<String>,
        expected_session_id: u32,
        approved_process: NamedPipePeerProcessBinding,
    ) -> Result<Self, WindowsAdapterError> {
        let mut expectation = Self::new(expected_sid, expected_session_id)?;
        expectation.approved_process = Some(approved_process);
        Ok(expectation)
    }

    /// Creates an expectation that requires one exact OS-observed process and
    /// its current membership in one exact owner Job.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the SID, session, or Job identity is invalid.
    pub fn new_with_process_and_job_binding(
        expected_sid: impl Into<String>,
        expected_session_id: u32,
        approved_process: NamedPipePeerJobBinding,
    ) -> Result<Self, WindowsAdapterError> {
        let mut expectation = Self::new(expected_sid, expected_session_id)?;
        expectation.approved_process = Some(approved_process.process.clone());
        expectation.approved_job_process = Some(approved_process);
        Ok(expectation)
    }

    /// Adds one exact OS-observed process binding to this expectation.
    ///
    /// This is a typed builder rather than a request-field setter: admission
    /// still obtains the observed identity from the operating system.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the binding is invalid.
    pub fn with_process_binding(
        mut self,
        approved_process: NamedPipePeerProcessBinding,
    ) -> Result<Self, WindowsAdapterError> {
        if self.is_dynamic_process() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.approved_process = Some(approved_process);
        Ok(self)
    }

    /// Adds one exact OS-observed process and Job binding to this expectation.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the retained Job identity is invalid.
    pub fn with_process_and_job_binding(
        mut self,
        approved_process: NamedPipePeerJobBinding,
    ) -> Result<Self, WindowsAdapterError> {
        if self.is_dynamic_process() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.approved_process = Some(approved_process.process.clone());
        self.approved_job_process = Some(approved_process);
        Ok(self)
    }

    #[must_use]
    pub fn expected_sid(&self) -> &str {
        &self.expected_sid
    }

    #[must_use]
    pub const fn expected_session_id(&self) -> u32 {
        self.expected_session_id
    }

    /// Whether admission requires enabled built-in Administrators membership
    /// instead of equality with one account SID/session.
    #[must_use]
    pub const fn requires_builtin_administrators(&self) -> bool {
        self.builtin_administrators
    }

    pub(crate) fn auth_discriminator(&self) -> NamedPipeAuthDiscriminator {
        if self.builtin_administrators {
            NamedPipeAuthDiscriminator::BuiltinAdministrators
        } else {
            NamedPipeAuthDiscriminator::Ordinary
        }
    }

    /// Returns the optional exact OS-observed process binding admitted by this
    /// policy.
    #[must_use]
    pub fn approved_process_binding(&self) -> Option<&NamedPipePeerProcessBinding> {
        self.approved_process.as_ref()
    }

    /// Returns the optional exact process/Job binding admitted by this policy.
    #[must_use]
    pub fn approved_process_job_binding(&self) -> Option<&NamedPipePeerJobBinding> {
        self.approved_job_process.as_ref()
    }

    /// Returns whether PID/start/session are intentionally per-connection.
    #[must_use]
    pub const fn is_dynamic_process(&self) -> bool {
        self.dynamic_image_path.is_some()
    }

    /// Returns the stable executable path for a dynamic process profile.
    #[must_use]
    pub fn dynamic_image_path(&self) -> Option<&str> {
        self.dynamic_image_path.as_deref()
    }

    /// Returns the stable no-follow executable file identity for a dynamic
    /// process profile.
    #[must_use]
    pub const fn dynamic_executable_file_identity(&self) -> Option<FileIdentity> {
        self.dynamic_executable_file
    }

    pub(crate) fn matches_dynamic_observation(&self, evidence: &NamedPipePeerEvidence) -> bool {
        if !self.is_dynamic_process() || evidence.sid != self.expected_sid {
            return false;
        }
        let Some(image_path) = self.dynamic_image_path.as_deref() else {
            return false;
        };
        same_process_image_path(&evidence.process.image_path, image_path)
            && evidence.executable_file == self.dynamic_executable_file
    }

    pub(crate) fn matches_evidence(&self, evidence: &NamedPipePeerEvidence) -> bool {
        if self.builtin_administrators {
            // The peer-set selector only consumes the already authenticated
            // token evidence. Administrator-group membership is proved by the
            // existing live impersonation boundary, not by SID text alone.
            if !evidence.builtin_administrators {
                return false;
            }
        } else if self.is_dynamic_process() {
            if evidence.session_id == 0
                || !evidence.interactive_session
                || !self.matches_dynamic_observation(evidence)
            {
                return false;
            }
        } else if evidence.sid != self.expected_sid
            || evidence.session_id != self.expected_session_id
        {
            return false;
        }
        if let Some(approved) = self.approved_process_binding()
            && (!same_process_identity(&evidence.process, approved.identity())
                || approved.executable_file_identity() != evidence.executable_file)
        {
            return false;
        }
        if let Some(approved) = self.approved_process_job_binding()
            && evidence.job_name.as_deref() != Some(approved.job_name())
        {
            return false;
        }
        true
    }
}

/// Sealed observation of the server at the other end of a live pipe handle.
///
/// Fields are private and this type is not deserializable, so callers cannot
/// turn a PID or SID string into authenticated transport authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerEvidence {
    pub(crate) process: ProcessIdentity,
    pub(crate) sid: String,
    pub(crate) session_id: u32,
    pub(crate) executable_file: Option<FileIdentity>,
    pub(crate) job_name: Option<String>,
    pub(crate) builtin_administrators: bool,
    pub(crate) interactive_session: bool,
}

impl NamedPipePeerEvidence {
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(
        process: ProcessIdentity,
        sid: impl Into<String>,
        session_id: u32,
        executable_file: Option<FileIdentity>,
        job_name: Option<String>,
        builtin_administrators: bool,
        interactive_session: bool,
    ) -> Result<Self, WindowsAdapterError> {
        let sid = sid.into();
        if !process.is_usable() || !valid_sid_text(&sid) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            process,
            sid,
            session_id,
            executable_file,
            job_name,
            builtin_administrators,
            interactive_session,
        })
    }

    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Returns the OS-observed executable file identity, when available.
    #[must_use]
    pub const fn executable_file_identity(&self) -> Option<FileIdentity> {
        self.executable_file
    }

    /// Returns the owner Job name revalidated for this peer, when applicable.
    #[must_use]
    pub fn job_name(&self) -> Option<&str> {
        self.job_name.as_deref()
    }

    /// Returns the OS-proved built-in Administrators membership result.
    #[must_use]
    pub const fn is_builtin_administrator(&self) -> bool {
        self.builtin_administrators
    }

    /// Returns the OS-observed WTS active-interactive state.
    #[must_use]
    pub const fn has_active_interactive_session(&self) -> bool {
        self.interactive_session
    }
}

pub(crate) fn admit_named_pipe_peer_process(
    observed: &ProcessIdentity,
    expectation: &NamedPipePeerExpectation,
) -> Result<(), WindowsAdapterError> {
    if let Some(approved) = expectation.approved_process_binding()
        && !same_process_identity(observed, approved.identity())
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if let Some(approved) = expectation.approved_process_job_binding() {
        if !same_process_identity(observed, approved.process_binding().identity()) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let current =
            observe_named_pipe_peer_process_in_job(approved.job_name(), observed.process_id)?;
        if !same_process_identity(
            current.process_binding().identity(),
            approved.process_binding().identity(),
        ) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
    }
    Ok(())
}

/// Observes the current process token for use as an inert named-pipe server
/// expectation. This does not authenticate any pipe or issue a peer result.
///
/// # Errors
/// Returns a typed adapter error when the current token cannot be observed.
#[cfg(windows)]
pub fn current_process_named_pipe_expectation()
-> Result<NamedPipePeerExpectation, WindowsAdapterError> {
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    let (sid, session_id) = process_token_identity(process)?;
    NamedPipePeerExpectation::new(sid, session_id)
}

#[cfg(not(windows))]
pub fn current_process_named_pipe_expectation()
-> Result<NamedPipePeerExpectation, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Observes one live process for use as a named-pipe admission binding.
///
/// The process identifier is only a lookup key. Windows opens the live
/// process and captures PID, creation time, and image path from that handle;
/// callers cannot construct the returned binding from request data.
///
/// # Errors
/// Returns a typed adapter error when the PID is invalid, the process cannot
/// be opened, or its identity cannot be observed and validated.
#[cfg(windows)]
pub fn observe_named_pipe_peer_process(
    process_id: u32,
) -> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    if process_id == 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    inspect_process_identity(process_id)
        .map_err(|error| windows_adapter_from_io(&error))
        .and_then(NamedPipePeerProcessBinding::from_observed)
}

#[cfg(not(windows))]
pub fn observe_named_pipe_peer_process(
    _process_id: u32,
) -> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

fn valid_named_job_identity(value: &str) -> bool {
    let length = value.encode_utf16().count();
    length != 0 && length <= 240 && !value.chars().any(char::is_control)
}

/// Observes one process and proves that the same PID is currently a member of
/// the named owner Job.  The returned value is sealed evidence, not a caller
/// constructed process or Job authority token.
///
/// # Errors
/// Returns a typed adapter error when the process, Job, or current membership
/// cannot be observed and validated.
#[cfg(windows)]
pub fn observe_named_pipe_peer_process_in_job(
    job_name: &str,
    process_id: u32,
) -> Result<NamedPipePeerJobBinding, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::OpenJobObjectW;
    const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;

    if process_id == 0 || !valid_named_job_identity(job_name) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut wide = std::ffi::OsStr::new(job_name)
        .encode_wide()
        .collect::<Vec<_>>();
    wide.push(0);
    // SAFETY: `wide` is NUL terminated and the returned handle is owned below.
    let handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY_ACCESS, 0, wide.as_ptr()) };
    if handle.is_null() {
        return Err(windows_adapter_from_io(&std::io::Error::last_os_error()));
    }
    let member = job_process_ids(handle)
        .map_err(|error| windows_adapter_from_io(&error))?
        .into_iter()
        .any(|member| member == process_id);
    // SAFETY: `handle` is the live Job handle returned by OpenJobObjectW.
    unsafe { CloseHandle(handle) };
    if !member {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let process = observe_named_pipe_peer_process(process_id)?;
    NamedPipePeerJobBinding::from_observed(process, job_name)
}

#[cfg(not(windows))]
pub fn observe_named_pipe_peer_process_in_job(
    _job_name: &str,
    _process_id: u32,
) -> Result<NamedPipePeerJobBinding, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Queries the canonical `EliotHost` service and retains its live PID, process
/// creation time and image identity for subsequent named-pipe admission.
/// Request data cannot supply any of those identity fields.
///
/// # Errors
///
/// Returns a typed adapter error when the service cannot be queried, is not
/// running, or its live process identity cannot be observed.
#[cfg(windows)]
pub fn observe_running_eliot_host_process()
-> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };
    let name = std::ffi::OsStr::new(ELIOT_HOST_SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_windows_adapter_error());
    }
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Err(last_windows_adapter_error());
    }
    let result = (|| {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        let status_bytes = u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>())
            .map_err(|_| WindowsAdapterError::Failed)?;
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                status_bytes,
                &raw mut needed,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let binding = observe_named_pipe_peer_process(status.dwProcessId)?;
        let mut confirmed_status = SERVICE_STATUS_PROCESS::default();
        let mut confirmed_needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut confirmed_status).cast(),
                status_bytes,
                &raw mut confirmed_needed,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if confirmed_status.dwCurrentState != SERVICE_RUNNING
            || !service_runtime_sample_is_stable(
                status.dwCurrentState,
                status.dwProcessId,
                confirmed_status.dwCurrentState,
                confirmed_status.dwProcessId,
            )
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let confirmed_binding = observe_named_pipe_peer_process(confirmed_status.dwProcessId)?;
        if confirmed_binding != binding {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(binding)
    })();
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    result
}
#[cfg(not(windows))]
pub fn observe_running_eliot_host_process()
-> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}
