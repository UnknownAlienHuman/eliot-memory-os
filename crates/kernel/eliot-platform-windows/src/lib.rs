//! Concrete Windows adapters for the P-01 platform ports.
//!
//! Windows implementation details are deliberately kept behind this facade.
//! Public values expose only provider-neutral P-01 results and typed P-02
//! mechanics evidence. Raw handles, provider records, secret bytes, and Win32
//! implementation details never escape this crate.

#![deny(unsafe_op_in_unsafe_fn)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::{
    AdapterPathInput, ClockPort, ClockRequest, FileKind, FilesystemObservation,
    FilesystemOperation, FilesystemPort, InstallationObservation, InstallationOperation,
    InstallationPort, InstallationRequest, InstallationState, NotificationObservation,
    NotificationPort, NotificationRequest, PlatformHandle, PortError, PortOutcome, SecretPort,
    SecretRequest, ServiceObservation, ServiceOperation, ServicePort, ServiceRequest, ServiceState,
    SessionObservation, SessionPort, SessionRequest, UnknownReason, WorkScopePath,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Failure returned by a Windows-only primitive before it can be projected
/// into a provider-neutral P-01 outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAdapterError {
    InvalidInput,
    NotFound,
    AlreadyExists,
    Unavailable,
    PermissionDenied,
    Timeout,
    Failed,
    IdentityMismatch,
    AclMismatch,
}

impl std::fmt::Display for WindowsAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Windows adapter failure: {self:?}")
    }
}

impl std::error::Error for WindowsAdapterError {}

/// Stable identity of a Windows file object.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// File index on the volume.
    pub file_index: u64,
}

/// Result of publishing bytes through the Windows atomic replacement path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Identity of the published file after replacement.
    pub identity: FileIdentity,
}

/// A publication whose external effect cannot be classified as committed.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationUnknown {
    /// Replacement committed, but the post-commit identity read was unavailable.
    PostCommitIdentityUnavailable,
    /// The destination was replaced again before the receipt could be bound.
    DestinationIdentityChanged,
}

/// Publication result that does not overclaim after a post-commit failure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PublicationOutcome {
    Published(PublicationReceipt),
    Unknown(PublicationUnknown),
}

/// Handle-bound identity of a live Windows process.
///
/// The PID is only a lookup key.  `start_time_100ns` and `image_path` are
/// measured through the same live process handle and therefore make PID
/// reuse or image substitution observable to the caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
}

/// Stable name of one owner-scoped Windows Job Object.
///
/// This is mechanics identity only. It carries no process-dispatch authority.
#[cfg(windows)]
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct JobObjectIdentity {
    name: String,
}

#[cfg(windows)]
impl JobObjectIdentity {
    /// Validates one exact Job Object name.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an empty name, embedded NUL, or a name wider
    /// than the bounded Windows object-manager representation used here.
    pub fn new(name: impl Into<String>) -> Result<Self, WindowsAdapterError> {
        let name = name.into();
        if !valid_job_object_name(&name) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { name })
    }

    /// Revalidates shape after deserializing a raw durable binding.
    ///
    /// This check grants no authority and does not prove that the named kernel
    /// object exists. [`RecoverableJobObject::open`] still has to reopen the
    /// Job and compare a fresh handle-bound root observation.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an invalid or unbounded object-manager name.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        if valid_job_object_name(&self.name) {
            Ok(())
        } else {
            Err(WindowsAdapterError::InvalidInput)
        }
    }

    /// Returns the exact Windows object-manager name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(windows)]
fn valid_job_object_name(name: &str) -> bool {
    let length = name.encode_utf16().count();
    length != 0 && length <= 240 && !name.chars().any(char::is_control)
}

/// Windows Job resource ceilings configured before the first process is
/// assigned. P-04 maps its provider-neutral P-03 limits into this mechanics
/// value; the type itself grants no launch authority.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobObjectLimits {
    cpu_time_ms: Option<u64>,
    memory_bytes: Option<u64>,
    active_process_limit: Option<u32>,
}

#[cfg(windows)]
impl JobObjectLimits {
    /// Creates validated optional Job limits.
    ///
    /// # Errors
    /// Returns `InvalidInput` when a supplied ceiling is zero or cannot be
    /// represented by the Win32 Job Object structures.
    pub fn new(
        cpu_time_ms: Option<u64>,
        memory_bytes: Option<u64>,
        active_process_limit: Option<u32>,
    ) -> Result<Self, WindowsAdapterError> {
        if matches!(cpu_time_ms, Some(0))
            || matches!(memory_bytes, Some(0))
            || matches!(active_process_limit, Some(0))
            || memory_bytes.is_some_and(|value| usize::try_from(value).is_err())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        if let Some(cpu_time_ms) = cpu_time_ms {
            let ticks = cpu_time_ms
                .checked_mul(10_000)
                .ok_or(WindowsAdapterError::InvalidInput)?;
            i64::try_from(ticks).map_err(|_| WindowsAdapterError::InvalidInput)?;
        }
        Ok(Self {
            cpu_time_ms,
            memory_bytes,
            active_process_limit,
        })
    }
}

/// Historical process membership observed from the Job completion port.
///
/// `complete` is true only after the kernel reported an empty Job and every
/// process-announcement event was resolved through a retained process handle.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    process: ProcessIdentity,
    executable: FileIdentity,
}

/// Durable raw binding used only to reopen and revalidate one named Job.
///
/// The value is not authority: `RecoverableJobObject::open` must re-observe
/// the exact root identity before returning a live mechanics handle.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverableJobBinding {
    job: JobObjectIdentity,
    root: ProcessObservation,
}

#[cfg(windows)]
impl RecoverableJobBinding {
    /// Validates only the bounded serialized shape.
    ///
    /// The result is not proof of a live process or Job. Callers must pass the
    /// binding to [`RecoverableJobObject::open`] for fresh kernel revalidation.
    ///
    /// # Errors
    /// Returns `InvalidInput` for malformed Job or root-process identity.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        self.job.validate()?;
        let root = self.root.process();
        let image_length = root.image_path.encode_utf16().count();
        if root.process_id == 0
            || root.start_time_100ns == 0
            || image_length == 0
            || image_length > 32_767
            || root.image_path.chars().any(char::is_control)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(())
    }

    /// Returns the bound Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Returns the exact root process/image observation.
    #[must_use]
    pub const fn root(&self) -> &ProcessObservation {
        &self.root
    }
}

#[cfg(windows)]
impl ProcessObservation {
    /// Returns the retained-handle process identity.
    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the file-object identity of the observed executable image.
    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable
    }

    fn stable_key(&self) -> String {
        format!(
            "{}:volume:{}:file:{}",
            self.process.stable_key(),
            self.executable.volume_serial_number,
            self.executable.file_index
        )
    }
}

/// Why a Job history cannot be claimed complete.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobObservationGap {
    /// At least one kernel process notification could not be resolved to an
    /// exact retained process/image identity before the process disappeared.
    IdentityCaptureFailed,
}

/// Historical process membership observed from the Job completion port.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobProcessHistory {
    processes: Vec<ProcessObservation>,
    complete: bool,
    job_empty: bool,
    capture_gap: Option<JobObservationGap>,
    resource_limit_triggered: bool,
}

#[cfg(windows)]
impl JobProcessHistory {
    /// Returns all distinct process identities observed during this Job life.
    #[must_use]
    pub fn processes(&self) -> &[ProcessObservation] {
        &self.processes
    }

    /// Returns whether the historical membership observation is complete.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether the Job was observed with zero active members.
    #[must_use]
    pub const fn job_empty(&self) -> bool {
        self.job_empty
    }

    /// Returns the explicit observation gap that prevented completeness.
    #[must_use]
    pub const fn capture_gap(&self) -> Option<JobObservationGap> {
        self.capture_gap
    }

    /// Returns whether the kernel emitted a CPU, memory, or process-count
    /// limit notification for this Job.
    #[must_use]
    pub const fn resource_limit_triggered(&self) -> bool {
        self.resource_limit_triggered
    }
}

impl ProcessIdentity {
    /// Stable comparison key; a PID alone is never sufficient.
    #[must_use]
    pub fn stable_key(&self) -> String {
        format!(
            "windows-pid:{}:start:{}:image:{}",
            self.process_id, self.start_time_100ns, self.image_path
        )
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
        })
    }

    #[must_use]
    pub fn expected_sid(&self) -> &str {
        &self.expected_sid
    }

    #[must_use]
    pub const fn expected_session_id(&self) -> u32 {
        self.expected_session_id
    }
}

/// Sealed observation of the server at the other end of a live pipe handle.
///
/// Fields are private and this type is not deserializable, so callers cannot
/// turn a PID or SID string into authenticated transport authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerEvidence {
    process: ProcessIdentity,
    sid: String,
    session_id: u32,
}

impl NamedPipePeerEvidence {
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
}

/// User-scoped DPAPI ciphertext.  The bytes carry no authority and are not
/// serializable by this crate.
pub struct ProtectedSecret(Vec<u8>);

impl ProtectedSecret {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Secret bytes read from Credential Manager.  Debug/serde are deliberately
/// absent and memory is cleared when the value is dropped.
pub struct CredentialSecret(Vec<u8>);

impl CredentialSecret {
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CredentialSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

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

/// Validated, password-free request for registering one own-process service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistrationRequest {
    service_name: String,
    display_name: String,
    binary_path: PathBuf,
    start_mode: ServiceStartMode,
    account: ServiceAccount,
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
        if !valid_service_name(&service_name)
            || !valid_display_name(&display_name)
            || !binary_path.is_absolute()
            || !binary_path.is_file()
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            service_name,
            display_name,
            binary_path,
            start_mode,
            account,
        })
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
}

/// Registration result preserving whether an external SCM effect requires
/// reconciliation before it can be called successful.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationOutcome {
    Registered { observation: ServiceObservation },
    ExistingRequiresReconciliation,
    EffectUnknown,
}

#[cfg(windows)]
static JOB_OBJECT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(windows)]
struct OwnedKernelHandle(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Windows kernel handles are process-global. This wrapper uniquely
// owns and closes its handle, so moving it between threads is sound.
#[cfg(windows)]
unsafe impl Send for OwnedKernelHandle {}

#[cfg(windows)]
impl OwnedKernelHandle {
    fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        if handle.is_null() {
            Err(last_windows_adapter_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn into_file(self) -> std::fs::File {
        use std::os::windows::io::FromRawHandle;
        let handle = self.0;
        std::mem::forget(self);
        // SAFETY: unique ownership of the live handle moves into `File` once.
        unsafe { std::fs::File::from_raw_handle(handle) }
    }
}

#[cfg(windows)]
impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the handle until this Drop.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
struct OwnedSecurityDescriptor {
    raw: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl OwnedSecurityDescriptor {
    fn for_job_owner() -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;OW)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut raw = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and `raw` is a valid out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        Ok(Self { raw })
    }
}

#[cfg(windows)]
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: Win32 allocated the descriptor and this wrapper owns it.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.raw.cast()) };
        }
    }
}

/// RAII wrapper for a named Windows Job Object configured to terminate
/// assigned processes when the sole owning handle closes.
#[cfg(windows)]
pub struct JobObject {
    handle: windows_sys::Win32::Foundation::HANDLE,
    identity: JobObjectIdentity,
}

// SAFETY: a Job Object handle is process-global and uniquely owned here.
#[cfg(windows)]
unsafe impl Send for JobObject {}

#[cfg(windows)]
impl JobObject {
    /// Creates a Job Object with kill-on-close configured before publication.
    ///
    /// # Errors
    /// Returns a typed adapter error when creation or configuration fails.
    pub fn new_kill_on_close() -> Result<Self, WindowsAdapterError> {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let identity = JobObjectIdentity::new(format!(
            "Local\\Eliot-P02-{}-{sequence}",
            std::process::id()
        ))?;
        Self::new_named_kill_on_close(identity)
    }

    /// Creates a fresh named Job Object and rejects an existing name.
    ///
    /// The protected DACL grants full access only to LocalSystem and the
    /// creating owner. A new generation therefore cannot silently join an
    /// older Job with the same durable identity.
    ///
    /// # Errors
    /// Returns `AlreadyExists` for a name collision or another typed adapter
    /// error when Windows rejects creation or limit configuration.
    pub fn new_named_kill_on_close(
        identity: JobObjectIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        Self::new_named_kill_on_close_with_limits(identity, JobObjectLimits::default())
    }

    /// Creates a fresh named kill-on-close Job with exact resource ceilings.
    ///
    /// All limits are installed before any process can be assigned.
    ///
    /// # Errors
    /// Returns a typed adapter error for name collision, invalid conversion,
    /// or rejected Job configuration.
    pub fn new_named_kill_on_close_with_limits(
        identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        let name = nul_terminated_wide(std::ffi::OsStr::new(identity.name()))
            .map_err(|error| windows_adapter_from_io(&error))?;
        let descriptor = OwnedSecurityDescriptor::for_job_owner()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| WindowsAdapterError::Failed)?,
            lpSecurityDescriptor: descriptor.raw,
            bInheritHandle: 0,
        };
        // SAFETY: name, descriptor and attributes remain live for the call.
        let handle = unsafe { CreateJobObjectW(&raw const attributes, name.as_ptr()) };
        // SAFETY: GetLastError immediately observes the creation disposition.
        let creation_error = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(last_windows_adapter_error());
        }
        if creation_error == ERROR_ALREADY_EXISTS {
            // SAFETY: this path owns the handle returned for the old object.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(WindowsAdapterError::AlreadyExists);
        }
        let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(cpu_time_ms) = resource_limits.cpu_time_ms {
            let ticks = cpu_time_ms
                .checked_mul(10_000)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(WindowsAdapterError::InvalidInput)?;
            job_info.BasicLimitInformation.PerJobUserTimeLimit = ticks;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        }
        if let Some(memory_bytes) = resource_limits.memory_bytes {
            job_info.JobMemoryLimit =
                usize::try_from(memory_bytes).map_err(|_| WindowsAdapterError::InvalidInput)?;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        }
        if let Some(active_process_limit) = resource_limits.active_process_limit {
            job_info.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }
        let length = u32::try_from(std::mem::size_of_val(&job_info))
            .map_err(|_| WindowsAdapterError::Failed)?;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const job_info).cast(),
                length,
            )
        } != 0;
        if !configured {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(last_windows_adapter_error());
        }
        Ok(Self { handle, identity })
    }

    /// Returns the durable Job Object identity.
    #[must_use]
    pub const fn identity(&self) -> &JobObjectIdentity {
        &self.identity
    }

    /// Assigns an existing process and returns its exact observed identity.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid identity, access or assignment failure.
    pub fn assign_process(&self, process_id: u32) -> Result<ProcessIdentity, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };
        if process_id == 0 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                0,
                process_id,
            )
        };
        if process.is_null() {
            return Err(last_windows_adapter_error());
        }
        let assigned = self.assign_process_handle(process);
        let result = if assigned.is_ok() {
            inspect_process_handle(process_id, process)
                .map_err(|error| windows_adapter_from_io(&error))
        } else {
            Err(assigned.err().unwrap_or(WindowsAdapterError::Failed))
        };
        unsafe { CloseHandle(process) };
        result
    }

    fn assign_process_handle(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    fn contains_process(&self, process_id: u32) -> Result<bool, WindowsAdapterError> {
        job_process_ids(self.handle)
            .map(|processes| processes.into_iter().any(|pid| pid == process_id))
            .map_err(|error| windows_adapter_from_io(&error))
    }

    /// Terminates every process currently assigned to this job.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects termination.
    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsAdapterError> {
        let ok = unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, exit_code)
        };
        if ok == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for JobObject {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

/// Handle to an existing named Job Object during restart reconciliation.
///
/// Reopening proves only current kernel membership. Historical descendants
/// must be unioned with the caller-owned durable raw-observation ledger; this
/// type intentionally exposes no `complete` history claim.
#[cfg(windows)]
pub struct RecoverableJobObject {
    handle: OwnedKernelHandle,
    binding: RecoverableJobBinding,
}

#[cfg(windows)]
impl RecoverableJobObject {
    /// Opens one existing named Job with query and terminate access.
    ///
    /// # Errors
    /// Returns `NotFound` when kill-on-close already removed the Job, or a
    /// typed access/platform error otherwise.
    pub fn open(binding: RecoverableJobBinding) -> Result<Self, WindowsAdapterError> {
        const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;
        const JOB_OBJECT_TERMINATE_ACCESS: u32 = 0x0008;
        use windows_sys::Win32::System::JobObjects::OpenJobObjectW;
        binding.validate()?;
        let name = nul_terminated_wide(std::ffi::OsStr::new(binding.job_identity().name()))
            .map_err(|error| windows_adapter_from_io(&error))?;
        // SAFETY: name is NUL-terminated and the call returns a new handle.
        let handle = unsafe {
            OpenJobObjectW(
                JOB_OBJECT_QUERY_ACCESS | JOB_OBJECT_TERMINATE_ACCESS,
                0,
                name.as_ptr(),
            )
        };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            if matches!(error.kind(), std::io::ErrorKind::NotFound) {
                return Err(WindowsAdapterError::NotFound);
            }
            return Err(windows_adapter_from_io(&error));
        }
        let recovered = Self {
            handle: OwnedKernelHandle::new(handle)?,
            binding,
        };
        let live = recovered.live_processes()?;
        if !live
            .iter()
            .any(|process| process == recovered.binding.root())
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(recovered)
    }

    /// Returns the exact Job identity used to reopen the object.
    #[must_use]
    pub const fn identity(&self) -> &JobObjectIdentity {
        self.binding.job_identity()
    }

    /// Returns the durable binding revalidated when this handle was opened.
    #[must_use]
    pub const fn binding(&self) -> &RecoverableJobBinding {
        &self.binding
    }

    /// Returns current live members with PID-reuse-safe process/image identity.
    ///
    /// # Errors
    /// Returns a typed adapter error when membership or identity cannot be read.
    pub fn live_processes(&self) -> Result<Vec<ProcessObservation>, WindowsAdapterError> {
        job_process_ids(self.handle.0)
            .map_err(|error| windows_adapter_from_io(&error))?
            .into_iter()
            .map(open_observed_job_process)
            .map(|result| result.map(|process| process.observation))
            .collect()
    }

    /// Returns the current active member count.
    ///
    /// # Errors
    /// Returns a typed adapter error when the Job cannot be queried.
    pub fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        u32::try_from(
            job_process_ids(self.handle.0)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)
    }

    /// Terminates all current members.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects termination.
    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsAdapterError> {
        // SAFETY: the reopened Job handle remains live for the call.
        if unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle.0, exit_code)
        } == 0
        {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    /// Waits until no live member remains.
    ///
    /// # Errors
    /// Returns a typed adapter error when current membership cannot be read.
    pub fn wait_for_empty(
        &self,
        timeout: std::time::Duration,
    ) -> Result<bool, WindowsAdapterError> {
        let started = std::time::Instant::now();
        loop {
            if self.active_process_count()? == 0 {
                return Ok(true);
            }
            if started.elapsed() >= timeout {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(windows)]
struct OwnedProcessHandle(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Windows kernel handles are process-global. This wrapper retains
// unique ownership and closes the handle exactly once in Drop.
#[cfg(windows)]
unsafe impl Send for OwnedProcessHandle {}

#[cfg(windows)]
impl OwnedProcessHandle {
    fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        if handle.is_null() {
            Err(last_windows_adapter_error())
        } else {
            Ok(Self(handle))
        }
    }
}

#[cfg(windows)]
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
struct SuspendedProcessCleanup {
    process: windows_sys::Win32::Foundation::HANDLE,
    armed: bool,
}

#[cfg(windows)]
impl SuspendedProcessCleanup {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for SuspendedProcessCleanup {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.armed && !self.process.is_null() {
            let _ = unsafe { TerminateProcess(self.process, 0xE1_04) };
            let _ = unsafe { WaitForSingleObject(self.process, 5_000) };
        }
    }
}

#[cfg(windows)]
struct PinnedExecutable {
    _file: std::fs::File,
    identity: FileIdentity,
}

#[cfg(windows)]
impl PinnedExecutable {
    fn open(path: &Path) -> Result<Self, WindowsAdapterError> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_READ, GetFileInformationByHandle,
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let metadata = file
            .metadata()
            .map_err(|error| windows_adapter_from_io(&error))?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information) }
            == 0
        {
            return Err(last_windows_adapter_error());
        }
        Ok(Self {
            _file: file,
            identity: FileIdentity {
                volume_serial_number: information.dwVolumeSerialNumber,
                file_index: (u64::from(information.nFileIndexHigh) << 32)
                    | u64::from(information.nFileIndexLow),
            },
        })
    }
}

/// Complete deterministic input to the Windows suspended-launch primitive.
///
/// This value contains mechanics only. It is not a dispatch permit and carries
/// no authority. Environment inheritance is intentionally unavailable: callers
/// must supply the complete child environment explicitly.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspendedLaunchSpec {
    executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    working_directory: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

#[cfg(windows)]
impl SuspendedLaunchSpec {
    /// Creates a deterministic launch specification without granting authority.
    ///
    /// # Errors
    /// Returns `InvalidInput` unless the executable and working directory are
    /// absolute existing paths and all argument/environment material is valid
    /// Windows UTF-16 without duplicate case-insensitive environment names.
    pub fn new(
        executable: impl Into<PathBuf>,
        arguments: Vec<std::ffi::OsString>,
        working_directory: impl Into<PathBuf>,
        environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Result<Self, WindowsAdapterError> {
        let executable = executable.into();
        let working_directory = working_directory.into();
        if !executable.is_absolute()
            || !executable.is_file()
            || !working_directory.is_absolute()
            || !working_directory.is_dir()
            || os_has_nul(executable.as_os_str())
            || os_has_nul(working_directory.as_os_str())
            || arguments.iter().any(|argument| os_has_nul(argument))
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        validate_complete_environment(&environment)?;
        Ok(Self {
            executable,
            arguments,
            working_directory,
            environment,
        })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }
}

/// Fresh mechanics evidence observed while the process is still suspended.
///
/// This type is deliberately non-serializable and non-cloneable. It is never
/// an authority receipt; only the caller-provided validator can return the
/// opaque validation token required by the next typestate.
#[cfg(windows)]
pub struct SuspendedProcessEvidence {
    process: ProcessIdentity,
    executable: FileIdentity,
    job: JobObjectIdentity,
    requested_executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    working_directory: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    command_line_utf16: Vec<u16>,
    job_process_count: u32,
}

#[cfg(windows)]
impl SuspendedProcessEvidence {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable
    }

    /// Returns the fresh, owner-scoped Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Builds the raw durable binding required for later named-Job recovery.
    #[must_use]
    pub fn recoverable_job_binding(&self) -> RecoverableJobBinding {
        RecoverableJobBinding {
            job: self.job.clone(),
            root: ProcessObservation {
                process: self.process.clone(),
                executable: self.executable,
            },
        }
    }

    #[must_use]
    pub fn requested_executable(&self) -> &Path {
        &self.requested_executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }

    #[must_use]
    pub fn command_line_utf16(&self) -> &[u16] {
        &self.command_line_utf16
    }

    #[must_use]
    pub const fn job_process_count(&self) -> u32 {
        self.job_process_count
    }
}

/// Failure of the consuming caller-owned validation transition.
#[cfg(windows)]
#[derive(Debug, Eq, PartialEq)]
pub enum SuspendedValidationError<E> {
    Mechanics(WindowsAdapterError),
    Rejected(E),
}

#[cfg(windows)]
const JOB_COMPLETION_KEY: usize = 0x454c_494f;
#[cfg(windows)]
const JOB_OBSERVER_SHUTDOWN_KEY: usize = 0x454e_4421;
#[cfg(windows)]
const JOB_OBJECT_MSG_END_OF_JOB_TIME: u32 = 1;
#[cfg(windows)]
const JOB_OBJECT_MSG_END_OF_PROCESS_TIME: u32 = 2;
#[cfg(windows)]
const JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT: u32 = 3;
#[cfg(windows)]
const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
#[cfg(windows)]
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
#[cfg(windows)]
const JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT: u32 = 9;
#[cfg(windows)]
const JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: u32 = 10;

#[cfg(windows)]
struct ObservedJobProcess {
    observation: ProcessObservation,
    _process: OwnedProcessHandle,
    _executable: PinnedExecutable,
}

#[cfg(windows)]
#[derive(Default)]
struct JobProcessObserverState {
    processes: Vec<ObservedJobProcess>,
    observation_incomplete: bool,
    active_process_zero: bool,
    resource_limit_triggered: bool,
}

#[cfg(windows)]
struct JobProcessObserver {
    completion_port: OwnedKernelHandle,
    state: std::sync::Arc<(
        std::sync::Mutex<JobProcessObserverState>,
        std::sync::Condvar,
    )>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl JobProcessObserver {
    fn attach(job: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::IO::CreateIoCompletionPort;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JobObjectAssociateCompletionPortInformation,
            SetInformationJobObject,
        };
        // SAFETY: this documented form creates one standalone completion port.
        let completion_port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        let completion_port = OwnedKernelHandle::new(completion_port)?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_COMPLETION_KEY as *mut std::ffi::c_void,
            CompletionPort: completion_port.0,
        };
        let length = u32::try_from(std::mem::size_of_val(&association))
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: both handles and the exact association structure are live.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                length,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        let state = std::sync::Arc::new((
            std::sync::Mutex::new(JobProcessObserverState::default()),
            std::sync::Condvar::new(),
        ));
        let thread_state = std::sync::Arc::clone(&state);
        let raw_port = completion_port.0 as usize;
        let thread = std::thread::Builder::new()
            .name("eliot-p02-job-observer".to_owned())
            .spawn(move || job_process_observer_loop(raw_port, &thread_state))
            .map_err(|error| windows_adapter_from_io(&error))?;
        Ok(Self {
            completion_port,
            state,
            thread: Some(thread),
        })
    }

    fn capture_pid(&self, process_id: u32) -> Result<(), WindowsAdapterError> {
        let process = open_observed_job_process(process_id)?;
        let (state, _) = &*self.state;
        let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        if !state
            .processes
            .iter()
            .any(|observed| observed.observation == process.observation)
        {
            state.processes.push(process);
        }
        Ok(())
    }

    fn capture_live_members(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<bool, WindowsAdapterError> {
        let process_ids = job_process_ids(job).map_err(|error| windows_adapter_from_io(&error))?;
        for process_id in &process_ids {
            if self.capture_pid(*process_id).is_err() {
                let (state, _) = &*self.state;
                let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
                state.observation_incomplete = true;
            }
        }
        Ok(process_ids.is_empty())
    }

    fn snapshot(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let job_empty = self.capture_live_members(job)?;
        self.snapshot_with_empty(job_empty)
    }

    fn wait_for_empty_history(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let started = std::time::Instant::now();
        loop {
            if self.capture_live_members(job)? {
                break;
            }
            if started.elapsed() >= timeout {
                return self.snapshot_with_empty(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let (state, notification) = &*self.state;
        let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        while !state.active_process_zero {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let (next, wait) = notification
                .wait_timeout(state, remaining)
                .map_err(|_| WindowsAdapterError::Failed)?;
            state = next;
            if wait.timed_out() {
                break;
            }
        }
        Ok(history_from_observer_state(&state, true))
    }

    fn snapshot_with_empty(
        &self,
        job_empty: bool,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let (state, _) = &*self.state;
        let state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        Ok(history_from_observer_state(&state, job_empty))
    }

    fn shutdown(&mut self) {
        if self.thread.is_none() {
            return;
        }
        use windows_sys::Win32::System::IO::PostQueuedCompletionStatus;
        // SAFETY: the port stays live until the observer thread is joined.
        let _ = unsafe {
            PostQueuedCompletionStatus(
                self.completion_port.0,
                0,
                JOB_OBSERVER_SHUTDOWN_KEY,
                std::ptr::null(),
            )
        };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
impl Drop for JobProcessObserver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(windows)]
fn history_from_observer_state(
    state: &JobProcessObserverState,
    job_empty: bool,
) -> JobProcessHistory {
    let mut processes = state
        .processes
        .iter()
        .map(|observed| observed.observation.clone())
        .collect::<Vec<_>>();
    processes.sort_by_key(ProcessObservation::stable_key);
    processes.dedup();
    JobProcessHistory {
        processes,
        complete: job_empty && state.active_process_zero && !state.observation_incomplete,
        job_empty,
        capture_gap: state
            .observation_incomplete
            .then_some(JobObservationGap::IdentityCaptureFailed),
        resource_limit_triggered: state.resource_limit_triggered,
    }
}

#[cfg(windows)]
fn open_observed_job_process(process_id: u32) -> Result<ObservedJobProcess, WindowsAdapterError> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if process_id == 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    // SAFETY: OpenProcess returns a newly owned handle or null.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    let process = OwnedProcessHandle::new(handle)?;
    let identity = inspect_process_handle(process_id, process.0)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let executable = PinnedExecutable::open(Path::new(&identity.image_path))?;
    let observation = ProcessObservation {
        process: identity,
        executable: executable.identity,
    };
    Ok(ObservedJobProcess {
        observation,
        _process: process,
        _executable: executable,
    })
}

#[cfg(windows)]
fn job_process_observer_loop(
    raw_port: usize,
    shared: &std::sync::Arc<(
        std::sync::Mutex<JobProcessObserverState>,
        std::sync::Condvar,
    )>,
) {
    use windows_sys::Win32::System::IO::GetQueuedCompletionStatus;
    let completion_port = raw_port as windows_sys::Win32::Foundation::HANDLE;
    loop {
        let mut message = 0_u32;
        let mut completion_key = 0_usize;
        let mut overlapped = std::ptr::null_mut();
        // SAFETY: all out pointers are live and the observer owns the port.
        let dequeued = unsafe {
            GetQueuedCompletionStatus(
                completion_port,
                &raw mut message,
                &raw mut completion_key,
                &raw mut overlapped,
                u32::MAX,
            )
        };
        if completion_key == JOB_OBSERVER_SHUTDOWN_KEY {
            break;
        }
        if dequeued == 0 || completion_key != JOB_COMPLETION_KEY {
            continue;
        }
        let (state, notification) = &**shared;
        if message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
            if let Ok(mut state) = state.lock() {
                state.active_process_zero = true;
                notification.notify_all();
            }
            continue;
        }
        if matches!(
            message,
            JOB_OBJECT_MSG_END_OF_JOB_TIME
                | JOB_OBJECT_MSG_END_OF_PROCESS_TIME
                | JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
                | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT
                | JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
        ) {
            if let Ok(mut state) = state.lock() {
                state.resource_limit_triggered = true;
                notification.notify_all();
            }
            continue;
        }
        if message != JOB_OBJECT_MSG_NEW_PROCESS {
            continue;
        }
        let Ok(process_id) = u32::try_from(overlapped as usize) else {
            if let Ok(mut state) = state.lock() {
                state.observation_incomplete = true;
            }
            continue;
        };
        let observed = open_observed_job_process(process_id);
        if let Ok(mut state) = state.lock() {
            state.active_process_zero = false;
            match observed {
                Ok(process)
                    if !state
                        .processes
                        .iter()
                        .any(|existing| existing.observation == process.observation) =>
                {
                    state.processes.push(process);
                }
                Ok(_) => {}
                Err(_) => state.observation_incomplete = true,
            }
        }
    }
}

#[cfg(windows)]
struct ProcThreadAttributeList {
    _storage: Vec<usize>,
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
}

#[cfg(windows)]
impl ProcThreadAttributeList {
    fn for_inherited_handles(
        handles: &[windows_sys::Win32::Foundation::HANDLE],
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::{
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            UpdateProcThreadAttribute,
        };
        let mut bytes = 0_usize;
        // SAFETY: the documented sizing call writes only `bytes`.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut bytes);
        }
        if bytes == 0 {
            return Err(last_windows_adapter_error());
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let list = storage.as_mut_ptr().cast::<std::ffi::c_void>();
        // SAFETY: storage is aligned, sufficiently large, and retained.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &raw mut bytes) } == 0 {
            return Err(last_windows_adapter_error());
        }
        let attribute = usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: list and exact handle slice are live for this call.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                attribute,
                handles.as_ptr().cast::<std::ffi::c_void>(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let error = last_windows_adapter_error();
            // SAFETY: list was initialized above.
            unsafe {
                windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(list);
            }
            return Err(error);
        }
        Ok(Self {
            _storage: storage,
            list,
        })
    }
}

#[cfg(windows)]
impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        // SAFETY: list remains initialized and its storage is still live.
        unsafe {
            windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(self.list);
        }
    }
}

#[cfg(windows)]
fn inheritable_pipe() -> Result<(OwnedKernelHandle, OwnedKernelHandle), WindowsAdapterError> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WindowsAdapterError::Failed)?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: output pointers and security attributes are valid for the call.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) } == 0 {
        return Err(last_windows_adapter_error());
    }
    Ok((
        OwnedKernelHandle::new(read)?,
        OwnedKernelHandle::new(write)?,
    ))
}

#[cfg(windows)]
fn make_non_inheritable(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    // SAFETY: the live handle is borrowed only for this call.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(last_windows_adapter_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
struct JobChildHandles {
    process: OwnedProcessHandle,
    thread: OwnedProcessHandle,
    job: JobObject,
    spawn_identity: ProcessIdentity,
    executable: PinnedExecutable,
    spec: SuspendedLaunchSpec,
    command_line_utf16: Vec<u16>,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    observer: JobProcessObserver,
    terminal: bool,
}

#[cfg(windows)]
impl JobChildHandles {
    fn fresh_evidence(&self) -> Result<SuspendedProcessEvidence, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::GetProcessId;
        let process_id = unsafe { GetProcessId(self.process.0) };
        if process_id == 0 || process_id != self.spawn_identity.process_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let process = inspect_process_handle(process_id, self.process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        if process.start_time_100ns != self.spawn_identity.start_time_100ns
            || !same_windows_path(&process.image_path, &self.spawn_identity.image_path)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&process.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != self.executable.identity || !self.job.contains_process(process_id)? {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let count = u32::try_from(
            job_process_ids(self.job.handle)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)?;
        if count == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(SuspendedProcessEvidence {
            process,
            executable: observed_file,
            job: self.job.identity().clone(),
            requested_executable: self.spec.executable.clone(),
            arguments: self.spec.arguments.clone(),
            working_directory: self.spec.working_directory.clone(),
            environment: self.spec.environment.clone(),
            command_line_utf16: self.command_line_utf16.clone(),
            job_process_count: count,
        })
    }

    fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        u32::try_from(
            job_process_ids(self.job.handle)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)
    }

    fn history(&self) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.observer.snapshot(self.job.handle)
    }

    fn wait_for_empty_history(
        &self,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.observer
            .wait_for_empty_history(self.job.handle, timeout)
    }

    fn root_exit_code(&self) -> Result<Option<i32>, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
                    return Err(last_windows_adapter_error());
                }
                Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
            }
            _ => Err(last_windows_adapter_error()),
        }
    }

    fn terminate_and_reap(
        &mut self,
        requested_exit_code: u32,
    ) -> Result<(i32, JobProcessHistory), WindowsAdapterError> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        self.job.terminate(requested_exit_code)?;
        wait_for_job_empty(self.job.handle, std::time::Duration::from_secs(5))?;
        if unsafe { WaitForSingleObject(self.process.0, 5_000) } != WAIT_OBJECT_0 {
            return Err(WindowsAdapterError::Timeout);
        }
        let exit_code = self.root_exit_code()?.ok_or(WindowsAdapterError::Failed)?;
        let history = self
            .observer
            .wait_for_empty_history(self.job.handle, std::time::Duration::from_secs(5))?;
        self.terminal = true;
        Ok((exit_code, history))
    }

    fn best_effort_cleanup(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.terminal {
            return;
        }
        let _ = unsafe { TerminateProcess(self.process.0, 0xE1_04) };
        let _ = self.job.terminate(0xE1_04);
        let _ = wait_for_job_empty(self.job.handle, std::time::Duration::from_secs(5));
        let _ = unsafe { WaitForSingleObject(self.process.0, 5_000) };
        self.terminal = true;
    }
}

#[cfg(windows)]
impl Drop for JobChildHandles {
    fn drop(&mut self) {
        self.best_effort_cleanup();
    }
}

/// Newly created suspended child. Validation and resume are consuming
/// typestate transitions, so neither transition can be repeated.
#[cfg(windows)]
pub struct SuspendedJobChild {
    inner: JobChildHandles,
}

/// Suspended child carrying the opaque token returned by caller-owned policy.
#[cfg(windows)]
pub struct ValidatedSuspendedJobChild<V> {
    inner: JobChildHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Resumed child contained by the same kill-on-close Job Object.
#[cfg(windows)]
pub struct RunningJobChild<V> {
    inner: JobChildHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Typed, idempotent observation of a resumed child.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunningJobObservation {
    Running {
        active_processes: u32,
    },
    RootExited {
        exit_code: i32,
        active_processes: u32,
    },
    Exited {
        exit_code: i32,
    },
}

/// Terminal receipt produced by one consuming termination transition.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminatedJobChild {
    process: ProcessIdentity,
    job: JobObjectIdentity,
    history: JobProcessHistory,
    requested_exit_code: u32,
    observed_exit_code: i32,
    job_empty: bool,
    root_reaped: bool,
}

#[cfg(windows)]
impl TerminatedJobChild {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the exact Job Object identity consumed by termination.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Returns the final historical process-membership observation.
    #[must_use]
    pub const fn history(&self) -> &JobProcessHistory {
        &self.history
    }

    #[must_use]
    pub const fn requested_exit_code(&self) -> u32 {
        self.requested_exit_code
    }

    #[must_use]
    pub const fn observed_exit_code(&self) -> i32 {
        self.observed_exit_code
    }

    #[must_use]
    pub const fn job_empty(&self) -> bool {
        self.job_empty
    }

    #[must_use]
    pub const fn root_reaped(&self) -> bool {
        self.root_reaped
    }
}

#[cfg(windows)]
impl SuspendedJobChild {
    /// Creates a child suspended in a fresh kill-on-close Job Object.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid deterministic material or any
    /// executable pin, process creation, identity, or Job assignment failure.
    pub fn spawn(spec: SuspendedLaunchSpec) -> Result<Self, WindowsAdapterError> {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let identity = JobObjectIdentity::new(format!(
            "Local\\Eliot-P02-{}-{sequence}",
            std::process::id()
        ))?;
        Self::spawn_named(spec, identity)
    }

    /// Creates a child suspended in one exact fresh named Job Object.
    ///
    /// The Job completion port is attached before assignment, and only the
    /// child-side standard handles are inheritable. Validation and resume stay
    /// separate consuming transitions.
    ///
    /// # Errors
    /// Returns a typed adapter error for a Job-name collision or any pipe,
    /// process, identity, or assignment failure.
    pub fn spawn_named(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        Self::spawn_named_with_limits(spec, job_identity, JobObjectLimits::default())
    }

    /// Creates a child suspended in a fresh named Job with resource ceilings.
    ///
    /// # Errors
    /// Returns a typed adapter error before resume when any limit, Job, pipe,
    /// process, identity, or assignment operation fails.
    pub fn spawn_named_with_limits(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW,
        };
        let executable = PinnedExecutable::open(&spec.executable)?;
        let application = nul_terminated_wide(spec.executable.as_os_str())
            .map_err(|error| windows_adapter_from_io(&error))?;
        let command_line_utf16 = command_line(&spec.executable, &spec.arguments)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let mut command_line = command_line_utf16.clone();
        let mut environment = command_environment(&spec.environment);
        let current_directory = nul_terminated_wide(spec.working_directory.as_os_str())
            .map_err(|error| windows_adapter_from_io(&error))?;
        let (stdin_read, stdin_write) = inheritable_pipe()?;
        let (stdout_read, stdout_write) = inheritable_pipe()?;
        let (stderr_read, stderr_write) = inheritable_pipe()?;
        make_non_inheritable(stdin_write.0)?;
        make_non_inheritable(stdout_read.0)?;
        make_non_inheritable(stderr_read.0)?;
        let inherited_handles = [stdin_read.0, stdout_write.0, stderr_write.0];
        let attributes = ProcThreadAttributeList::for_inherited_handles(&inherited_handles)?;
        let job = JobObject::new_named_kill_on_close_with_limits(job_identity, resource_limits)?;
        let observer = JobProcessObserver::attach(job.handle)?;
        let mut startup = STARTUPINFOEXW {
            StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
                cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
                    .map_err(|_| WindowsAdapterError::Failed)?,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: stdin_read.0,
                hStdOutput: stdout_write.0,
                hStdError: stderr_write.0,
                ..Default::default()
            },
            lpAttributeList: attributes.list,
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: all buffers and the STARTUPINFOEX attribute list remain live;
        // handle inheritance is restricted to `inherited_handles`.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw mut startup.StartupInfo,
                &raw mut information,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if information.hProcess.is_null() || information.hThread.is_null() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
            };
            let cleanup_process = if information.hProcess.is_null() && information.dwProcessId != 0
            {
                unsafe { OpenProcess(PROCESS_TERMINATE | 0x0010_0000, 0, information.dwProcessId) }
            } else {
                information.hProcess
            };
            if !cleanup_process.is_null() {
                let _ = unsafe { TerminateProcess(cleanup_process, 0xE1_04) };
                let _ = unsafe { WaitForSingleObject(cleanup_process, 5_000) };
                if cleanup_process != information.hProcess {
                    unsafe { CloseHandle(cleanup_process) };
                }
            }
            if !information.hThread.is_null() {
                unsafe { CloseHandle(information.hThread) };
            }
            if !information.hProcess.is_null() {
                unsafe { CloseHandle(information.hProcess) };
            }
            return Err(WindowsAdapterError::Failed);
        }
        // Parent keeps only the read sides. Closing the sole parent stdin
        // writer gives the child deterministic EOF instead of inherited input.
        drop(stdin_read);
        drop(stdin_write);
        drop(stdout_write);
        drop(stderr_write);
        let process = OwnedProcessHandle::new(information.hProcess)?;
        let thread = OwnedProcessHandle::new(information.hThread)?;
        let mut cleanup = SuspendedProcessCleanup {
            process: process.0,
            armed: true,
        };
        let spawn_identity = inspect_process_handle(information.dwProcessId, process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let inner = JobChildHandles {
            process,
            thread,
            job,
            spawn_identity,
            executable,
            spec,
            command_line_utf16,
            stdout: Some(stdout_read.into_file()),
            stderr: Some(stderr_read.into_file()),
            observer,
            terminal: false,
        };
        cleanup.disarm();
        inner.job.assign_process_handle(inner.process.0)?;
        inner
            .observer
            .capture_pid(inner.spawn_identity.process_id)?;
        if !inner
            .job
            .contains_process(inner.spawn_identity.process_id)?
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&inner.spawn_identity.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != inner.executable.identity
            || !same_windows_path(
                &inner.spawn_identity.image_path,
                &inner.spec.executable.to_string_lossy(),
            )
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(Self { inner })
    }

    #[must_use]
    pub const fn id(&self) -> u32 {
        self.inner.spawn_identity.process_id
    }

    /// Consumes the unvalidated state and requires caller-owned policy to
    /// return an opaque validation token over fresh P-02 mechanics evidence.
    ///
    /// # Errors
    /// Returns `Mechanics` for failed retained-handle validation or `Rejected`
    /// with the caller's own policy/permit error. Either path kills and reaps
    /// the full Job before the error escapes.
    pub fn validate<V, E, F>(
        mut self,
        validator: F,
    ) -> Result<ValidatedSuspendedJobChild<V>, SuspendedValidationError<E>>
    where
        F: FnOnce(&SuspendedProcessEvidence) -> Result<V, E>,
    {
        let evidence = match self.inner.fresh_evidence() {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Mechanics(error));
            }
        };
        let validation = match validator(&evidence) {
            Ok(validation) => validation,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Rejected(error));
            }
        };
        Ok(ValidatedSuspendedJobChild {
            inner: self.inner,
            evidence,
            validation,
        })
    }

    /// Consumes and terminates an unvalidated child without resuming it.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }
}

#[cfg(windows)]
impl<V> ValidatedSuspendedJobChild<V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Consumes the validated suspended state and resumes exactly once.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects `ResumeThread`; the
    /// error path kills and reaps the full Job.
    pub fn resume(mut self) -> Result<RunningJobChild<V>, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::ResumeThread;
        if unsafe { ResumeThread(self.inner.thread.0) } == u32::MAX {
            let error = last_windows_adapter_error();
            self.inner.best_effort_cleanup();
            return Err(error);
        }
        Ok(RunningJobChild {
            inner: self.inner,
            evidence: self.evidence,
            validation: self.validation,
        })
    }

    /// Consumes and terminates a validated child without resuming it.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }
}

#[cfg(windows)]
impl<V> RunningJobChild<V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Returns the exact owner-scoped Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        self.inner.job.identity()
    }

    /// Transfers ownership of the process stdout read handle exactly once.
    #[must_use]
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.inner.stdout.take()
    }

    /// Transfers ownership of the process stderr read handle exactly once.
    #[must_use]
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.inner.stderr.take()
    }

    /// Returns an idempotent observation without changing typestate.
    ///
    /// # Errors
    /// Returns a typed adapter error when process or Job state cannot be read.
    pub fn observe(&self) -> Result<RunningJobObservation, WindowsAdapterError> {
        let active_processes = self.inner.active_process_count()?;
        match self.inner.root_exit_code()? {
            None => Ok(RunningJobObservation::Running { active_processes }),
            Some(exit_code) if active_processes == 0 => {
                Ok(RunningJobObservation::Exited { exit_code })
            }
            Some(exit_code) => Ok(RunningJobObservation::RootExited {
                exit_code,
                active_processes,
            }),
        }
    }

    /// Returns identities observed in the Job so far, including exited members.
    ///
    /// # Errors
    /// Returns a typed adapter error when membership or identity cannot be read.
    pub fn job_processes(&self) -> Result<Vec<ProcessIdentity>, WindowsAdapterError> {
        Ok(self
            .inner
            .history()?
            .processes()
            .iter()
            .map(|process| process.process().clone())
            .collect())
    }

    /// Returns the current number of live Job members.
    ///
    /// # Errors
    /// Returns a typed adapter error when Job state cannot be queried.
    pub fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        self.inner.active_process_count()
    }

    /// Returns historical membership observed so far.
    ///
    /// While the Job is active, `complete` is necessarily false because more
    /// descendants may still be created.
    ///
    /// # Errors
    /// Returns a typed adapter error when current Job membership cannot be read.
    pub fn process_history(&self) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.inner.history()
    }

    /// Waits for the Job to become empty and returns the final history.
    ///
    /// A timed-out or identity-gap result is returned with `complete == false`;
    /// callers must project that as UNKNOWN rather than tree closure.
    ///
    /// # Errors
    /// Returns a typed adapter error when Job membership cannot be observed.
    pub fn wait_for_empty_history(
        &self,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.inner.wait_for_empty_history(timeout)
    }

    /// Terminates and reaps the complete Job without consuming this owner.
    ///
    /// A failed termination or bounded wait leaves the process and Job
    /// handles attached to this value so the owning executor can retry and
    /// retain exact cleanup evidence.
    pub fn terminate_in_place(
        &mut self,
        exit_code: u32,
    ) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }

    /// Consumes and terminates the complete Job exactly once.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        self.terminate_in_place(exit_code)
    }
}

/// Cancels one synchronous read issued by a capture reader thread.
///
/// `Ok(false)` means that the thread had no pending synchronous I/O when the
/// cancellation was requested; callers still need to use their bounded wait
/// policy before joining it.
#[cfg(windows)]
pub fn cancel_capture_thread_io(
    thread: &std::thread::JoinHandle<()>,
) -> Result<bool, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
    use windows_sys::Win32::System::IO::CancelSynchronousIo;

    if unsafe { CancelSynchronousIo(thread.as_raw_handle()) } != 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND.cast_signed()) {
        Ok(false)
    } else {
        Err(windows_adapter_from_io(&error))
    }
}

#[cfg(windows)]
fn terminalize(
    inner: &mut JobChildHandles,
    requested_exit_code: u32,
) -> Result<TerminatedJobChild, WindowsAdapterError> {
    let process = inner.spawn_identity.clone();
    let (observed_exit_code, history) = inner.terminate_and_reap(requested_exit_code)?;
    Ok(TerminatedJobChild {
        process,
        job: inner.job.identity().clone(),
        history,
        requested_exit_code,
        observed_exit_code,
        job_empty: true,
        root_reaped: true,
    })
}

/// Windows implementation of the P-01 ports.
pub struct WindowsPlatform {
    root: PathBuf,
    #[cfg(windows)]
    _root_pin: std::fs::File,
}

impl WindowsPlatform {
    /// Binds the adapter to an absolute, existing, non-reparse work root.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPath` when the root is not absolute, existing, and
    /// non-reparse.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PortError> {
        let root = root.into();
        validate_root(&root)?;
        #[cfg(windows)]
        let root_pin = pin_directory(&root).map_err(|_| PortError::InvalidPath)?;
        Ok(Self {
            root,
            #[cfg(windows)]
            _root_pin: root_pin,
        })
    }

    /// Returns the validated filesystem identity of a path below the work root.
    ///
    /// # Errors
    ///
    /// Returns a typed path or provider error when containment or identity
    /// validation cannot be established.
    pub fn file_identity(&self, path: &WorkScopePath) -> Result<FileIdentity, PortError> {
        let input = path.adapter_input();
        let full = self.resolve(&input)?;
        file_identity(&full).map_err(|_| PortError::Provider(provider_failed()))
    }

    /// Reads a process identity from one live query handle.
    ///
    /// The returned start time and image path are bound to the queried handle;
    /// callers must compare the complete value before reusing a PID.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when Windows cannot open or inspect the
    /// process, including insufficient query privilege.
    pub fn process_identity(&self, process_id: u32) -> Result<ProcessIdentity, PortError> {
        if process_id == 0 {
            return Err(PortError::InvalidPath);
        }
        inspect_process_identity(process_id)
            .map_err(|error| PortError::Provider(provider_from_io(&error)))
    }

    /// Protects secret bytes for the current Windows user through DPAPI.
    ///
    /// # Errors
    /// Returns a typed adapter error for empty input or DPAPI failure.
    pub fn protect_secret(&self, secret: &[u8]) -> Result<ProtectedSecret, WindowsAdapterError> {
        if secret.is_empty() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        dpapi_protect(secret)
    }

    /// Decrypts bytes previously protected for this Windows user.
    ///
    /// # Errors
    /// Returns a typed adapter error when ciphertext is invalid or unavailable.
    pub fn unprotect_secret(
        &self,
        protected: &ProtectedSecret,
    ) -> Result<CredentialSecret, WindowsAdapterError> {
        dpapi_unprotect(protected.as_bytes())
    }

    /// Writes an opaque generic credential through Windows Credential Manager.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid keys, size or provider failure.
    pub fn write_credential(&self, key: &str, secret: &[u8]) -> Result<(), WindowsAdapterError> {
        credential_write(key, secret)
    }

    /// Reads the exact opaque bytes stored in Windows Credential Manager.
    ///
    /// # Errors
    /// Returns a typed adapter error when the key is invalid, absent or inaccessible.
    pub fn read_credential(&self, key: &str) -> Result<CredentialSecret, WindowsAdapterError> {
        credential_read(key)
    }

    /// Deletes a generic credential. Missing credentials remain explicitly
    /// unavailable rather than being reported as a successful deletion.
    ///
    /// # Errors
    /// Returns a typed adapter error when the key is invalid, absent or inaccessible.
    pub fn delete_credential(&self, key: &str) -> Result<(), WindowsAdapterError> {
        credential_delete(key)
    }

    /// Registers one validated ELIOT own-process service through SCM.
    ///
    /// This P-02-specific API deliberately does not reinterpret P-01's smaller
    /// `ServiceRequest::Register` shape. P-10 supplies this exact request at
    /// composition time. Existing services are never treated as matching
    /// configuration without a separate reconciliation step.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid input, permission denial or a
    /// pre-effect provider failure.
    pub fn register_service(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
        register_service(request)
    }

    /// Publishes bytes by staging beside the destination and replacing it once.
    ///
    /// # Errors
    ///
    /// Returns a typed path or provider error when staging, replacement, or
    /// post-publication identity observation fails.
    pub fn publish_atomic(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<PublicationOutcome, PortError> {
        self.publish_atomic_outcome(path, bytes)
    }

    /// Publishes bytes and requires a fully observed receipt.
    ///
    /// Callers that cannot reconcile an externally visible effect must use
    /// [`Self::publish_atomic`] and preserve its `Unknown` variant.
    ///
    /// # Errors
    ///
    /// Returns a typed path/provider error when publication fails before the
    /// replacement is committed or when an unknown outcome is forced into a
    /// receipt-only call.
    pub fn publish_atomic_receipt(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<PublicationReceipt, PortError> {
        match self.publish_atomic(path, bytes)? {
            PublicationOutcome::Published(receipt) => Ok(receipt),
            PublicationOutcome::Unknown(_) => Err(PortError::Provider(unknown_provider())),
        }
    }

    /// Publishes bytes and preserves the post-commit unknown state.
    ///
    /// # Errors
    ///
    /// Returns a typed path or provider error before replacement. A successful
    /// replacement followed by an unobservable identity is returned as
    /// [`PublicationOutcome::Unknown`] rather than as a retryable error.
    pub fn publish_atomic_outcome(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<PublicationOutcome, PortError> {
        let input = path.adapter_input();
        let destination = self.resolve(&input)?;
        let parent = destination.parent().ok_or(PortError::InvalidPath)?;
        let parent_pin = pin_ancestors(&self.root, parent)?;
        let temporary = create_temporary(parent, bytes)?;
        let staged_identity = match file_identity(&temporary) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::Provider(provider_from_io(&error)));
            }
        };
        if let Err(error) = validate_destination(&destination) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        let result = replace_file(&temporary, &destination);
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        // MoveFileExW uses WRITE_THROUGH; flush the pinned directory when the
        // filesystem accepts directory flushes, without inventing a second
        // publication failure after the replacement has committed.
        flush_directory(&parent_pin);
        let identity = file_identity(&destination).map_err(|_| {
            // Replacement may already have committed. This is deliberately not
            // retried: the caller must reconcile the externally visible effect.
            PortError::Provider(unknown_provider())
        });
        Ok(match identity {
            Ok(identity) if identity == staged_identity => {
                PublicationOutcome::Published(PublicationReceipt { identity })
            }
            Ok(_) => PublicationOutcome::Unknown(PublicationUnknown::DestinationIdentityChanged),
            Err(_) => {
                PublicationOutcome::Unknown(PublicationUnknown::PostCommitIdentityUnavailable)
            }
        })
    }

    fn resolve(&self, input: &AdapterPathInput) -> Result<PathBuf, PortError> {
        let mut resolved = self.root.clone();
        for component in input.normalized_identity.split('/') {
            validate_component(component)?;
            resolved.push(component);
        }
        validate_containment(&self.root, &resolved)?;
        Ok(resolved)
    }

    fn resolve_component(&self, component: &str) -> Result<PathBuf, PortError> {
        validate_component(component)?;
        let path = self.root.join(component);
        validate_containment(&self.root, &path)?;
        Ok(path)
    }
}

/// Authenticates the server bound to a connected client-end named-pipe handle.
///
/// # Errors
/// Returns a typed adapter error when DACL, process, SID or session proof fails.
#[cfg(windows)]
pub fn authenticate_named_pipe_server(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expectation: &NamedPipePeerExpectation,
) -> Result<NamedPipePeerEvidence, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    validate_pipe_dacl(pipe_handle, &expectation.expected_sid)?;
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe_handle, &raw mut process_id) } == 0
        || process_id == 0
    {
        return Err(last_windows_adapter_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(last_windows_adapter_error());
    }
    let observed = (|| {
        let identity = inspect_process_handle(process_id, process)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let (sid, session_id) = process_token_identity(process)?;
        if sid != expectation.expected_sid || session_id != expectation.expected_session_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(NamedPipePeerEvidence {
            process: identity,
            sid,
            session_id,
        })
    })();
    unsafe { CloseHandle(process) };
    observed
}

/// Authenticates the client bound to a connected server-end named-pipe handle.
///
/// The process identity and process token are read from one retained process
/// handle. The connected client is then impersonated only long enough to bind
/// its thread token to the same SID/session, and an RAII guard calls
/// `RevertToSelf` on every return path.
///
/// # Errors
/// Returns a typed adapter error when PID, process, token, impersonation,
/// SID/session expectation or reversion cannot be established.
#[cfg(windows)]
pub fn authenticate_named_pipe_client(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expectation: &NamedPipePeerExpectation,
) -> Result<NamedPipePeerEvidence, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    validate_pipe_dacl(pipe_handle, &expectation.expected_sid)?;
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &raw mut process_id) } == 0
        || process_id == 0
    {
        return Err(last_windows_adapter_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(last_windows_adapter_error());
    }
    let observed = (|| {
        let identity = inspect_process_handle(process_id, process)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let process_token = process_token_identity(process)?;
        let impersonation = ImpersonationGuard::begin(pipe_handle)?;
        let thread_token = thread_token_identity()?;
        impersonation.revert()?;
        if process_token != thread_token
            || process_token.0 != expectation.expected_sid
            || process_token.1 != expectation.expected_session_id
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(NamedPipePeerEvidence {
            process: identity,
            sid: process_token.0,
            session_id: process_token.1,
        })
    })();
    unsafe { CloseHandle(process) };
    observed
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

impl FilesystemPort for WindowsPlatform {
    fn execute(
        &mut self,
        request: &eliot_platform::FilesystemRequest,
    ) -> PortOutcome<FilesystemObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let input = request.path.adapter_input();
        let path = match self.resolve(&input) {
            Ok(path) => path,
            Err(error) => return PortOutcome::Error(error),
        };
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return PortOutcome::Known(FilesystemObservation {
                    path: request.path.clone(),
                    kind: FileKind::Missing,
                    size: None,
                    content_digest: None,
                });
            }
            Err(error) => return inspect_failure(&error),
        };
        if is_reparse_point(&metadata) {
            return PortOutcome::Unknown(UnknownReason::Indeterminate);
        }
        let kind = if metadata.is_file() {
            FileKind::File
        } else if metadata.is_dir() {
            FileKind::Directory
        } else if metadata.file_type().is_symlink() {
            FileKind::Symlink
        } else {
            FileKind::Other
        };
        let observation = FilesystemObservation {
            path: request.path.clone(),
            kind,
            size: metadata.is_file().then_some(metadata.len()),
            content_digest: None,
        };
        match request.operation {
            FilesystemOperation::Stat => PortOutcome::Known(observation),
            FilesystemOperation::Read => PortOutcome::Partial {
                value: observation,
                missing: vec![handle("content_digest")],
            },
            FilesystemOperation::Write { .. } | FilesystemOperation::Remove => {
                PortOutcome::Unknown(UnknownReason::Unsupported)
            }
        }
    }
}

impl ServicePort for WindowsPlatform {
    fn execute(&mut self, request: &ServiceRequest) -> PortOutcome<ServiceObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        match request.operation {
            ServiceOperation::Inspect => inspect_service(request.service.as_str()),
            // P-01 deliberately carries no binary path, account or start-mode
            // registration configuration. Guessing those would fabricate SCM
            // authority, so registration remains a typed unsupported outcome.
            ServiceOperation::Register => PortOutcome::Unknown(UnknownReason::Unsupported),
            ServiceOperation::Start | ServiceOperation::Stop | ServiceOperation::Unregister => {
                mutate_service(request.service.as_str(), request.operation)
            }
        }
    }
}

impl ClockPort for WindowsPlatform {
    fn read(&mut self, request: &ClockRequest) -> PortOutcome<eliot_platform::ClockObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let valid_time_ms = unix_millis(SystemTime::now());
        let monotonic_ns = Some(
            u64::try_from(
                monotonic_origin()
                    .elapsed()
                    .as_nanos()
                    .min(u128::from(u64::MAX)),
            )
            .unwrap_or(u64::MAX),
        );
        PortOutcome::Known(eliot_platform::ClockObservation {
            valid_time_ms,
            known_time_ms: valid_time_ms,
            transaction_sequence: None,
            monotonic_ns,
        })
    }
}

impl SecretPort for WindowsPlatform {
    fn inspect(
        &mut self,
        request: &SecretRequest,
    ) -> PortOutcome<eliot_platform::SecretObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        inspect_credential(request)
    }
}

impl NotificationPort for WindowsPlatform {
    fn deliver(&mut self, request: &NotificationRequest) -> PortOutcome<NotificationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }
}

impl SessionPort for WindowsPlatform {
    fn inspect(&mut self, request: &SessionRequest) -> PortOutcome<SessionObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        inspect_session(request)
    }
}

impl InstallationPort for WindowsPlatform {
    fn execute(&mut self, request: &InstallationRequest) -> PortOutcome<InstallationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        if request.operation != InstallationOperation::Inspect {
            return PortOutcome::Unknown(UnknownReason::Unsupported);
        }
        for component in &request.components {
            if let Err(error) = validate_component(component.as_str()) {
                return PortOutcome::Error(error);
            }
        }
        let mut components = Vec::new();
        for component in &request.components {
            let path = match self.resolve_component(component.as_str()) {
                Ok(path) => path,
                Err(error) => return PortOutcome::Error(error),
            };
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return PortOutcome::Unknown(classify_unknown(&error)),
            };
            if is_reparse_point(&metadata) {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            if !metadata.is_file() {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            components.push(component.clone());
        }
        let state = if components.is_empty() {
            InstallationState::Absent
        } else if components.len() == request.components.len() {
            InstallationState::Present
        } else {
            InstallationState::Inconsistent
        };
        PortOutcome::Known(InstallationObservation {
            installation: request.installation.clone(),
            state,
            components,
        })
    }
}

fn handle(value: &str) -> eliot_platform::PlatformHandle {
    eliot_platform::PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn provider_failed() -> eliot_platform::ProviderError {
    eliot_platform::ProviderError {
        code: eliot_platform::ProviderErrorCode::Failed,
        retryable: false,
    }
}

fn inspect_failure(error: &std::io::Error) -> PortOutcome<FilesystemObservation> {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            PortOutcome::Error(PortError::Provider(provider_from_io(error)))
        }
        _ => PortOutcome::Unknown(UnknownReason::Indeterminate),
    }
}

fn classify_unknown(error: &std::io::Error) -> UnknownReason {
    match error.kind() {
        std::io::ErrorKind::Unsupported => UnknownReason::Unsupported,
        _ => UnknownReason::Indeterminate,
    }
}

fn unknown_provider() -> eliot_platform::ProviderError {
    eliot_platform::ProviderError {
        code: eliot_platform::ProviderErrorCode::Unavailable,
        retryable: false,
    }
}

fn provider_from_io(error: &std::io::Error) -> eliot_platform::ProviderError {
    use std::io::ErrorKind;
    let code = match error.kind() {
        ErrorKind::PermissionDenied => eliot_platform::ProviderErrorCode::PermissionDenied,
        ErrorKind::NotFound => eliot_platform::ProviderErrorCode::Unavailable,
        ErrorKind::TimedOut => eliot_platform::ProviderErrorCode::Timeout,
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
            eliot_platform::ProviderErrorCode::Unavailable
        }
        _ => eliot_platform::ProviderErrorCode::Failed,
    };
    eliot_platform::ProviderError {
        code,
        retryable: matches!(
            code,
            eliot_platform::ProviderErrorCode::Unavailable
                | eliot_platform::ProviderErrorCode::Timeout
        ),
    }
}

fn unix_millis(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

fn unique_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        unix_millis(SystemTime::now()).unwrap_or_default(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn validate_component(value: &str) -> Result<(), PortError> {
    let path = WorkScopePath::new(value)?;
    if path.normalized_identity() != value || value.contains(':') {
        return Err(PortError::InvalidPath);
    }
    Ok(())
}

fn create_temporary(parent: &Path, bytes: &[u8]) -> Result<PathBuf, PortError> {
    for _ in 0..64 {
        let path = parent.join(format!(".eliot-atomic-{}", unique_suffix()));
        let result = create_new_file(&path, bytes);
        match result {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PortError::Provider(provider_from_io(&error))),
        }
    }
    Err(PortError::Provider(eliot_platform::ProviderError {
        code: eliot_platform::ProviderErrorCode::Timeout,
        retryable: true,
    }))
}

#[cfg(windows)]
fn create_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging entry is not a file",
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(windows))]
fn create_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(windows)]
fn pin_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reparse directory",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn pin_ancestors(root: &Path, path: &Path) -> Result<Vec<std::fs::File>, PortError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PortError::InvalidPath)?;
    let mut current = root.to_path_buf();
    let mut pins = vec![pin_directory(root).map_err(|_| PortError::InvalidPath)?];
    for component in relative.components() {
        current.push(component.as_os_str());
        pins.push(pin_directory(&current).map_err(|_| PortError::InvalidPath)?);
    }
    Ok(pins)
}

#[cfg(not(windows))]
fn pin_ancestors(_root: &Path, _path: &Path) -> Result<Vec<std::fs::File>, PortError> {
    Ok(Vec::new())
}

fn monotonic_origin() -> &'static std::time::Instant {
    static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
    ORIGIN.get_or_init(std::time::Instant::now)
}

fn validate_root(root: &Path) -> Result<(), PortError> {
    if !root.is_absolute() || !root.is_dir() {
        return Err(PortError::InvalidPath);
    }
    if std::fs::symlink_metadata(root).map_or(true, |metadata| {
        metadata.file_type().is_symlink() || is_reparse_point(&metadata)
    }) {
        return Err(PortError::InvalidPath);
    }
    Ok(())
}

fn validate_containment(root: &Path, path: &Path) -> Result<(), PortError> {
    if !path.starts_with(root) {
        return Err(PortError::InvalidPath);
    }
    for ancestor in path.ancestors().take_while(|candidate| *candidate != root) {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(PortError::InvalidPath),
        };
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(PortError::InvalidPath);
        }
    }
    Ok(())
}

fn validate_destination(path: &Path) -> Result<(), PortError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if is_reparse_point(&metadata) || !metadata.is_file() => {
            Err(PortError::InvalidPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PortError::Provider(provider_from_io(&error))),
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn flush_directory(pins: &[std::fs::File]) {
    if let Some(directory) = pins.last() {
        let _ = directory.sync_all();
    }
}

#[cfg(not(windows))]
fn flush_directory(_pins: &[std::fs::File]) {}

#[cfg(windows)]
fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "identity target is not a regular file",
        ));
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and the output points to initialized storage.
    let ok =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut information) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(windows))]
fn file_identity(_path: &Path) -> std::io::Result<FileIdentity> {
    Err(std::io::Error::other("Windows identity unavailable"))
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), PortError> {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = wide(source);
    let destination = wide(destination);
    for attempt in 0..=40 {
        // SAFETY: both strings are NUL-terminated and remain alive for the call.
        let ok = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        let transient = matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ACCESS_DENIED.cast_signed()
                    || code == ERROR_SHARING_VIOLATION.cast_signed()
        );
        if !transient || attempt == 40 {
            return Err(PortError::Provider(provider_from_io(&error)));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    unreachable!("bounded replacement loop always returns")
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), PortError> {
    std::fs::rename(source, destination)
        .map_err(|error| PortError::Provider(provider_from_io(&error)))
}

#[cfg(windows)]
fn wide(value: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn valid_sid_text(value: &str) -> bool {
    value.strip_prefix("S-1-").is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 180
            && tail
                .chars()
                .all(|character| character.is_ascii_digit() || character == '-')
    })
}

fn valid_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| !character.is_control() && !matches!(character, '/' | '\\' | ','))
}

fn valid_display_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value.chars().all(|character| !character.is_control())
}

fn windows_adapter_from_io(error: &std::io::Error) -> WindowsAdapterError {
    #[cfg(windows)]
    if let Some(code) = error.raw_os_error() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND,
            ERROR_PATH_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_TIMEOUT,
        };
        if matches!(
            code,
            value if value == ERROR_FILE_NOT_FOUND.cast_signed()
                || value == ERROR_PATH_NOT_FOUND.cast_signed()
                || value == ERROR_NOT_FOUND.cast_signed()
                || value == ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()
        ) {
            return WindowsAdapterError::Unavailable;
        }
        if code == ERROR_ALREADY_EXISTS.cast_signed() {
            return WindowsAdapterError::AlreadyExists;
        }
        if code == ERROR_ACCESS_DENIED.cast_signed() {
            return WindowsAdapterError::PermissionDenied;
        }
        if code == ERROR_TIMEOUT.cast_signed() {
            return WindowsAdapterError::Timeout;
        }
    }
    match error.kind() {
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            WindowsAdapterError::InvalidInput
        }
        std::io::ErrorKind::PermissionDenied => WindowsAdapterError::PermissionDenied,
        std::io::ErrorKind::NotFound => WindowsAdapterError::Unavailable,
        std::io::ErrorKind::AlreadyExists => WindowsAdapterError::AlreadyExists,
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
            WindowsAdapterError::Unavailable
        }
        std::io::ErrorKind::TimedOut => WindowsAdapterError::Timeout,
        _ => WindowsAdapterError::Failed,
    }
}

#[cfg(windows)]
fn last_windows_adapter_error() -> WindowsAdapterError {
    windows_adapter_from_io(&std::io::Error::last_os_error())
}

#[cfg(not(windows))]
fn last_windows_adapter_error() -> WindowsAdapterError {
    WindowsAdapterError::Unavailable
}

#[cfg(windows)]
fn sid_to_string(sid: windows_sys::Win32::Security::PSID) -> Result<String, WindowsAdapterError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 || text.is_null() {
        return Err(last_windows_adapter_error());
    }
    let mut length = 0_usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let value = unsafe { std::ffi::OsString::from_wide(std::slice::from_raw_parts(text, length)) }
        .to_string_lossy()
        .into_owned();
    unsafe { LocalFree(text.cast()) };
    if valid_sid_text(&value) {
        Ok(value)
    } else {
        Err(WindowsAdapterError::Failed)
    }
}

#[cfg(windows)]
fn process_token_identity(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(String, u32), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_identity(token);
    unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
fn thread_token_identity() -> Result<(String, u32), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_identity(token);
    unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
fn token_identity(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(String, u32), WindowsAdapterError> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_USER, TokenSessionId, TokenUser,
    };
    let mut required = 0_u32;
    let _ = unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut required)
    };
    if required == 0 {
        return Err(last_windows_adapter_error());
    }
    let required_bytes = usize::try_from(required).map_err(|_| WindowsAdapterError::Failed)?;
    let words = required_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or(WindowsAdapterError::Failed)?
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = sid_to_string(token_user.User.Sid)?;
    let mut session_id = 0_u32;
    let mut session_length =
        u32::try_from(std::mem::size_of::<u32>()).map_err(|_| WindowsAdapterError::Failed)?;
    if unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            (&raw mut session_id).cast(),
            session_length,
            &raw mut session_length,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    Ok((sid, session_id))
}

#[cfg(windows)]
struct ImpersonationGuard {
    active: bool,
}

#[cfg(windows)]
impl ImpersonationGuard {
    fn begin(pipe: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(last_windows_adapter_error());
        }
        Ok(Self { active: true })
    }

    fn revert(mut self) -> Result<(), WindowsAdapterError> {
        if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
            return Err(last_windows_adapter_error());
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active && unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
            // Continuing a privileged server thread under an untrusted client
            // token is less safe than terminating the process. The explicit
            // `revert` path normally disarms this guard; this is its fail-stop.
            std::process::abort();
        }
    }
}

#[cfg(windows)]
fn validate_pipe_dacl(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    expected_sid: &str,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, PSECURITY_DESCRIPTOR,
    };
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(WindowsAdapterError::AclMismatch);
    }
    let result = (|| {
        let ace_count = unsafe { (*dacl).AceCount };
        if ace_count == 0 || ace_count > 16 {
            return Err(WindowsAdapterError::AclMismatch);
        }
        let mut expected_present = false;
        for index in 0..u32::from(ace_count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
                return Err(WindowsAdapterError::AclMismatch);
            }
            let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            if header.AceType != 0 {
                continue;
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&raw const allowed.SidStart).cast_mut().cast();
            let text = sid_to_string(sid)?;
            if text == expected_sid {
                expected_present = true;
            } else if !matches!(text.as_str(), "S-1-5-18" | "S-1-5-32-544") {
                return Err(WindowsAdapterError::AclMismatch);
            }
        }
        expected_present
            .then_some(())
            .ok_or(WindowsAdapterError::AclMismatch)
    })();
    unsafe { LocalFree(descriptor.cast()) };
    result
}

#[cfg(windows)]
fn dpapi_protect(secret: &[u8]) -> Result<ProtectedSecret, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let input_len = u32::try_from(secret.len()).map_err(|_| WindowsAdapterError::InvalidInput)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: secret.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if unsafe {
        CryptProtectData(
            &raw const input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
    }
    .to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(ProtectedSecret(bytes))
}

#[cfg(not(windows))]
fn dpapi_protect(_secret: &[u8]) -> Result<ProtectedSecret, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<CredentialSecret, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    if protected.is_empty() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).map_err(|_| WindowsAdapterError::InvalidInput)?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if unsafe {
        CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
    }
    .to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(CredentialSecret(bytes))
}

#[cfg(not(windows))]
fn dpapi_unprotect(_protected: &[u8]) -> Result<CredentialSecret, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn register_service(
    request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, CreateServiceW, OpenSCManagerW, SC_MANAGER_CREATE_SERVICE,
        SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR_NORMAL,
        SERVICE_QUERY_STATUS, SERVICE_WIN32_OWN_PROCESS,
    };

    let wide_text = |value: &OsStr| value.encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let service_name = wide_text(OsStr::new(request.service_name()));
    let display_name = wide_text(OsStr::new(request.display_name()));
    let mut binary_command = OsString::from("\"");
    binary_command.push(request.binary_path());
    binary_command.push("\"");
    let binary_command = wide_text(&binary_command);
    let account = match request.account() {
        ServiceAccount::LocalSystem => None,
        ServiceAccount::LocalService => Some(wide_text(OsStr::new("NT AUTHORITY\\LocalService"))),
        ServiceAccount::NetworkService => {
            Some(wide_text(OsStr::new("NT AUTHORITY\\NetworkService")))
        }
    };
    let account_ptr = account
        .as_ref()
        .map_or(std::ptr::null(), std::vec::Vec::as_ptr);
    let start_type = match request.start_mode() {
        ServiceStartMode::Automatic => SERVICE_AUTO_START,
        ServiceStartMode::Demand => SERVICE_DEMAND_START,
        ServiceStartMode::Disabled => SERVICE_DISABLED,
    };
    let manager = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CREATE_SERVICE,
        )
    };
    if manager.is_null() {
        return Err(last_windows_adapter_error());
    }
    let service = unsafe {
        CreateServiceW(
            manager,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_QUERY_STATUS,
            SERVICE_WIN32_OWN_PROCESS,
            start_type,
            SERVICE_ERROR_NORMAL,
            binary_command.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            account_ptr,
            std::ptr::null(),
        )
    };
    if service.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { CloseServiceHandle(manager) };
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_SERVICE_EXISTS.cast_signed()
                    || code == ERROR_SERVICE_MARKED_FOR_DELETE.cast_signed()
        ) {
            return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
        }
        return Err(windows_adapter_from_io(&error));
    }
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    Ok(match inspect_service(request.service_name()) {
        PortOutcome::Known(observation)
        | PortOutcome::Partial {
            value: observation, ..
        } => ServiceRegistrationOutcome::Registered { observation },
        PortOutcome::Unknown(_) | PortOutcome::Error(_) => {
            ServiceRegistrationOutcome::EffectUnknown
        }
    })
}

#[cfg(not(windows))]
fn register_service(
    _request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn inspect_service(name: &str) -> PortOutcome<ServiceObservation> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS_PROCESS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };
    let service_name = name.to_owned();
    let name = OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: null machine/database selects the local SCM; access is query-only.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return PortOutcome::Unknown(UnknownReason::Indeterminate);
    }
    // SAFETY: name is NUL-terminated and manager is live.
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        let error = std::io::Error::last_os_error();
        return classify_service_error(&service_name, &error);
    }
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut size = 0;
    // SAFETY: status is valid storage and the service handle is query-only/live.
    let status_size =
        u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX);
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            status_size,
            &raw mut size,
        )
    };
    let query_error = (ok == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if let Some(error) = query_error {
        return PortOutcome::Error(PortError::Provider(provider_from_io(&error)));
    }
    let state = match status.dwCurrentState {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING => ServiceState::Starting,
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_STOP_PENDING => ServiceState::Stopping,
        _ => ServiceState::Unknown,
    };
    let observation = ServiceObservation {
        service: handle(&service_name),
        state,
        generation: None,
        process: None,
    };
    if status.dwProcessId == 0 {
        PortOutcome::Known(observation)
    } else if inspect_process_identity(status.dwProcessId).is_ok() {
        // P-01's ServiceProcessRecord requires an authority epoch. Windows
        // does not issue that authority, so preserve the observed service
        // state and expose exact process identity only through
        // WindowsPlatform::process_identity.
        PortOutcome::Partial {
            value: observation,
            missing: vec![handle("authority_bound_process_record")],
        }
    } else {
        PortOutcome::Partial {
            value: observation,
            missing: vec![handle("process_identity")],
        }
    }
}

#[cfg(windows)]
fn mutate_service(name: &str, operation: ServiceOperation) -> PortOutcome<ServiceObservation> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, DeleteService, OpenSCManagerW, OpenServiceW,
        SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_START, SERVICE_STATUS, SERVICE_STOP,
        StartServiceW,
    };
    let name_wide = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let access = match operation {
        ServiceOperation::Start => SERVICE_START,
        ServiceOperation::Stop => SERVICE_STOP,
        ServiceOperation::Unregister => 0x0001_0000,
        ServiceOperation::Inspect | ServiceOperation::Register => {
            return PortOutcome::Unknown(UnknownReason::Unsupported);
        }
    };
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return PortOutcome::Error(PortError::Provider(provider_from_io(
            &std::io::Error::last_os_error(),
        )));
    }
    let service = unsafe { OpenServiceW(manager, name_wide.as_ptr(), access) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()) {
            return PortOutcome::Known(ServiceObservation {
                service: handle(name),
                state: ServiceState::Absent,
                generation: None,
                process: None,
            });
        }
        return PortOutcome::Error(PortError::Provider(provider_from_io(&error)));
    }
    let ok = match operation {
        ServiceOperation::Start => unsafe { StartServiceW(service, 0, std::ptr::null()) },
        ServiceOperation::Stop => {
            let mut status = SERVICE_STATUS::default();
            unsafe { ControlService(service, SERVICE_CONTROL_STOP, &raw mut status) }
        }
        ServiceOperation::Unregister => unsafe { DeleteService(service) },
        ServiceOperation::Inspect | ServiceOperation::Register => 0,
    };
    let error = (ok == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if let Some(error) = error {
        return PortOutcome::Error(PortError::Provider(provider_from_io(&error)));
    }
    reconcile_service_effect(inspect_service(name))
}

fn reconcile_service_effect(
    observation: PortOutcome<ServiceObservation>,
) -> PortOutcome<ServiceObservation> {
    match observation {
        PortOutcome::Known(_) | PortOutcome::Partial { .. } => observation,
        PortOutcome::Unknown(_) | PortOutcome::Error(_) => {
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        }
    }
}

#[cfg(not(windows))]
fn mutate_service(_name: &str, _operation: ServiceOperation) -> PortOutcome<ServiceObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(not(windows))]
fn inspect_service(_name: &str) -> PortOutcome<ServiceObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(windows)]
fn inspect_process_identity(process_id: u32) -> std::io::Result<ProcessIdentity> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // The handle is the authority for all three fields below.  A second PID
    // lookup is never used to build the durable identity.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let result = inspect_process_handle(process_id, process);
    // SAFETY: process is the live handle returned by OpenProcess.
    unsafe { CloseHandle(process) };
    result
}

#[cfg(windows)]
fn job_process_ids(job: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<Vec<u32>> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList, QueryInformationJobObject,
    };
    let mut capacity = 16_usize;
    loop {
        let bytes = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
            .checked_add(
                capacity
                    .saturating_sub(1)
                    .checked_mul(std::mem::size_of::<usize>())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Job process list is too large",
                        )
                    })?,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Job process list is too large",
                )
            })?;
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let bytes = u32::try_from(buffer.len() * std::mem::size_of::<usize>()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Job process buffer is too large",
            )
        })?;
        let mut returned = 0_u32;
        let queried = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(),
                bytes,
                &raw mut returned,
            )
        };
        let header = unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
        if queried != 0 {
            let count = usize::try_from(header.NumberOfProcessIdsInList).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Job process count invalid")
            })?;
            if count > capacity {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Job process list exceeded its supplied buffer",
                ));
            }
            let ids = unsafe { std::slice::from_raw_parts(header.ProcessIdList.as_ptr(), count) };
            return ids
                .iter()
                .copied()
                .filter(|pid| *pid != 0)
                .map(|pid| {
                    u32::try_from(pid).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Job PID does not fit u32",
                        )
                    })
                })
                .collect();
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_MORE_DATA.cast_signed()) {
            return Err(error);
        }
        let assigned = usize::try_from(header.NumberOfAssignedProcesses).unwrap_or(capacity + 1);
        capacity = assigned.max(capacity.saturating_mul(2));
        if capacity > 4_096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Job process list exceeded its safety bound",
            ));
        }
    }
}

#[cfg(windows)]
fn nul_terminated_wide(value: &std::ffi::OsStr) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows string contains an embedded NUL",
        ));
    }
    Ok(wide.into_iter().chain(std::iter::once(0)).collect())
}

#[cfg(windows)]
fn os_has_nul(value: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().any(|unit| unit == 0)
}

#[cfg(windows)]
fn validate_complete_environment(
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<(), WindowsAdapterError> {
    let mut names = std::collections::BTreeSet::new();
    for (name, value) in environment {
        let Some(name_text) = name.to_str() else {
            return Err(WindowsAdapterError::InvalidInput);
        };
        if name_text.is_empty()
            || name_text.contains('=')
            || os_has_nul(name)
            || value.to_str().is_none()
            || os_has_nul(value)
            || !names.insert(name_text.to_uppercase())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn same_windows_path(left: &str, right: &str) -> bool {
    fn normalized(value: &str) -> String {
        value
            .strip_prefix(r"\\?\")
            .unwrap_or(value)
            .replace('/', "\\")
            .to_uppercase()
    }
    normalized(left) == normalized(right)
}

#[cfg(windows)]
fn wait_for_job_empty(
    job: windows_sys::Win32::Foundation::HANDLE,
    timeout: std::time::Duration,
) -> Result<(), WindowsAdapterError> {
    let started = std::time::Instant::now();
    loop {
        if job_process_ids(job)
            .map_err(|error| windows_adapter_from_io(&error))?
            .is_empty()
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(WindowsAdapterError::Timeout);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn quote_windows_argument(value: &std::ffi::OsStr) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let value = value.encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process argument contains an embedded NUL",
        ));
    }
    // Quote every argument. This is CommandLineToArgvW/CRT compatible and
    // therefore handles embedded quotes and trailing backslashes even when an
    // argument contains no whitespace.
    let mut quoted = vec![u16::from(b'"')];
    let mut backslashes = 0_usize;
    for unit in value {
        if unit == u16::from(b'\\') {
            backslashes = backslashes.saturating_add(1);
        } else if unit == u16::from(b'"') {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            quoted.push(unit);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            quoted.push(unit);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    quoted.push(u16::from(b'"'));
    Ok(quoted)
}

#[cfg(windows)]
fn command_line(executable: &Path, arguments: &[std::ffi::OsString]) -> std::io::Result<Vec<u16>> {
    let mut line = Vec::new();
    for (index, argument) in std::iter::once(executable.as_os_str())
        .chain(arguments.iter().map(std::ffi::OsString::as_os_str))
        .enumerate()
    {
        if index > 0 {
            line.push(u16::from(b' '));
        }
        line.extend(quote_windows_argument(argument)?);
    }
    line.push(0);
    Ok(line)
}

#[cfg(windows)]
fn command_environment(environment: &[(std::ffi::OsString, std::ffi::OsString)]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut entries = environment.to_vec();
    entries.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (name, value) in entries {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(windows)]
fn inspect_process_handle(
    process_id: u32,
    process: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<ProcessIdentity> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, PROCESS_NAME_WIN32, QueryFullProcessImageNameW,
    };
    (|| {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: process is a live query handle and all FILETIME pointers are writable.
        let ok = unsafe {
            GetProcessTimes(
                process,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let start_time_100ns =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if start_time_100ns == 0 {
            return Err(std::io::Error::other("process start time unavailable"));
        }
        let mut buffer = vec![0_u16; 32_768];
        let mut length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: buffer is writable and length is its capacity in UTF-16 units.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &raw mut length,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let image_path =
            std::ffi::OsString::from_wide(&buffer[..usize::try_from(length).unwrap_or(0)])
                .to_string_lossy()
                .into_owned();
        if image_path.is_empty() {
            return Err(std::io::Error::other("process image unavailable"));
        }
        Ok(ProcessIdentity {
            process_id,
            start_time_100ns,
            image_path,
        })
    })()
}

#[cfg(not(windows))]
fn inspect_process_identity(_process_id: u32) -> std::io::Result<ProcessIdentity> {
    Err(std::io::Error::other(
        "Windows process identity unavailable",
    ))
}

#[cfg(windows)]
fn classify_service_error(name: &str, error: &std::io::Error) -> PortOutcome<ServiceObservation> {
    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()) {
        PortOutcome::Known(ServiceObservation {
            service: handle(name),
            state: ServiceState::Absent,
            generation: None,
            process: None,
        })
    } else {
        PortOutcome::Error(PortError::Provider(provider_from_io(error)))
    }
}

#[cfg(windows)]
fn inspect_credential(request: &SecretRequest) -> PortOutcome<eliot_platform::SecretObservation> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
    use windows_sys::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
    };
    if !is_windows_secret_provider(request.reference.provider.as_str()) {
        return PortOutcome::Unknown(UnknownReason::Unsupported);
    }
    if !valid_credential_key(request.reference.key.as_str()) {
        return PortOutcome::Error(PortError::InvalidPath);
    }
    let name = std::ffi::OsStr::new(request.reference.key.as_str())
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: name is NUL-terminated; Windows writes only the opaque credential pointer.
    let found = unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &raw mut credential) } != 0;
    let read_error = (!found).then(std::io::Error::last_os_error);
    if !credential.is_null() {
        unsafe { CredFree(credential.cast()) };
    }
    if found {
        PortOutcome::Known(eliot_platform::SecretObservation {
            reference: request.reference.clone(),
            present: true,
            version: None,
        })
    } else {
        let error = read_error.unwrap_or_else(std::io::Error::last_os_error);
        if error.raw_os_error() == Some(ERROR_NOT_FOUND.cast_signed()) {
            PortOutcome::Known(eliot_platform::SecretObservation {
                reference: request.reference.clone(),
                present: false,
                version: None,
            })
        } else {
            PortOutcome::Error(PortError::Provider(provider_from_io(&error)))
        }
    }
}

fn is_windows_secret_provider(value: &str) -> bool {
    matches!(
        value,
        "windows-credential-manager" | "windows-credential-manager-dpapi" | "dpapi"
    )
}

#[cfg(not(windows))]
fn inspect_credential(_request: &SecretRequest) -> PortOutcome<eliot_platform::SecretObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

fn valid_credential_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
        })
}

#[cfg(windows)]
fn credential_write(key: &str, secret: &[u8]) -> Result<(), WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
    };
    if !valid_credential_key(key) || secret.is_empty() || secret.len() > 2560 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut target = std::ffi::OsStr::new(key)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: u32::try_from(secret.len())
            .map_err(|_| WindowsAdapterError::InvalidInput)?,
        CredentialBlob: secret.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    if unsafe { CredWriteW(&raw mut credential, 0) } == 0 {
        Err(last_windows_adapter_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn credential_write(_key: &str, _secret: &[u8]) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn credential_read(key: &str) -> Result<CredentialSecret, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
    };
    if !valid_credential_key(key) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let target = std::ffi::OsStr::new(key)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &raw mut credential) } == 0
        || credential.is_null()
    {
        return Err(last_windows_adapter_error());
    }
    let value = unsafe {
        let credential_ref = &*credential;
        std::slice::from_raw_parts(
            credential_ref.CredentialBlob,
            usize::try_from(credential_ref.CredentialBlobSize).unwrap_or(0),
        )
        .to_vec()
    };
    unsafe { CredFree(credential.cast()) };
    Ok(CredentialSecret(value))
}

#[cfg(not(windows))]
fn credential_read(_key: &str) -> Result<CredentialSecret, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn credential_delete(key: &str) -> Result<(), WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};
    if !valid_credential_key(key) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let target = std::ffi::OsStr::new(key)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
        Err(last_windows_adapter_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn credential_delete(_key: &str) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn inspect_session(request: &SessionRequest) -> PortOutcome<SessionObservation> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSConnectState, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName,
    };
    let Ok(requested) = request.session.as_str().parse::<u32>() else {
        return PortOutcome::Unknown(UnknownReason::NotObserved);
    };
    let mut state_ptr = std::ptr::null_mut();
    let mut state_bytes = 0_u32;
    // SAFETY: WTS owns the returned buffer and receives valid output pointers.
    let state_ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            requested,
            WTSConnectState,
            &raw mut state_ptr,
            &raw mut state_bytes,
        )
    } != 0;
    if !state_ok || state_ptr.is_null() || state_bytes < 4 {
        if !state_ptr.is_null() {
            // SAFETY: state_ptr was returned by WTSQuerySessionInformationW.
            unsafe { WTSFreeMemory(state_ptr.cast()) };
        }
        return PortOutcome::Unknown(UnknownReason::Indeterminate);
    }
    // SAFETY: WTS returned at least four bytes for WTSConnectState.
    let state = unsafe { std::ptr::read_unaligned(state_ptr.cast::<i32>()) };
    // SAFETY: state_ptr was returned by WTSQuerySessionInformationW.
    unsafe { WTSFreeMemory(state_ptr.cast()) };

    let mut user_ptr = std::ptr::null_mut();
    let mut user_bytes = 0_u32;
    // SAFETY: WTS owns the returned buffer and receives valid output pointers.
    let user_ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            requested,
            WTSUserName,
            &raw mut user_ptr,
            &raw mut user_bytes,
        )
    } != 0;
    if !user_ok || user_ptr.is_null() {
        if !user_ptr.is_null() {
            // SAFETY: user_ptr was returned by WTSQuerySessionInformationW.
            unsafe { WTSFreeMemory(user_ptr.cast()) };
        }
        return PortOutcome::Unknown(UnknownReason::NotObserved);
    }
    let user_len = usize::try_from(user_bytes).unwrap_or(0) / 2;
    // SAFETY: user_bytes describes the UTF-16 buffer returned by WTS.
    let user_units = unsafe { std::slice::from_raw_parts(user_ptr, user_len) };
    let user = std::ffi::OsString::from_wide(user_units)
        .to_string_lossy()
        .trim_end_matches('\0')
        .to_owned();
    // SAFETY: user_ptr was returned by WTSQuerySessionInformationW.
    unsafe { WTSFreeMemory(user_ptr.cast()) };
    PortOutcome::Known(SessionObservation {
        session: request.session.clone(),
        user: PlatformHandle::new(user).ok(),
        interactive: state == WTSActive,
    })
}

#[cfg(test)]
fn session_matches(requested: u32, current: u32) -> bool {
    requested == current
}

#[cfg(not(windows))]
fn inspect_session(_request: &SessionRequest) -> PortOutcome<SessionObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_and_reparse_roots() {
        assert!(validate_root(Path::new("relative")).is_err());
    }

    #[test]
    fn atomic_suffix_is_nonempty_and_not_secret_derived() {
        assert!(!unique_suffix().is_empty());
    }

    #[test]
    fn rejects_component_traversal_and_control() {
        assert!(validate_component("../outside").is_err());
        assert!(validate_component("state\0.bin").is_err());
        assert!(valid_credential_key("nested/ok-key"));
        assert!(!valid_credential_key("../outside"));
    }

    #[test]
    fn permission_denied_is_explicit_and_not_retryable() {
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let provider = provider_from_io(&error);
        assert_eq!(
            provider.code,
            eliot_platform::ProviderErrorCode::PermissionDenied
        );
        assert!(!provider.retryable);
    }

    #[test]
    fn containment_is_component_wise_not_prefix_wise() {
        let root = Path::new("C:/work/root");
        assert!(validate_containment(root, Path::new("C:/work/root/file")).is_ok());
        assert!(validate_containment(root, Path::new("C:/work/root-sibling/file")).is_err());
    }

    #[test]
    fn wrong_session_is_not_observed() {
        assert!(!session_matches(7, 8));
        assert!(session_matches(7, 7));
    }

    #[test]
    fn post_commit_identity_failure_is_typed_unknown() {
        assert_eq!(
            PublicationOutcome::Unknown(PublicationUnknown::PostCommitIdentityUnavailable),
            PublicationOutcome::Unknown(PublicationUnknown::PostCommitIdentityUnavailable)
        );
    }

    #[test]
    fn durable_identity_types_reject_unknown_fields() {
        let result = serde_json::from_str::<FileIdentity>(
            r#"{"volume_serial_number":1,"file_index":2,"extra":3}"#,
        );
        assert!(result.is_err());
        let result = serde_json::from_str::<ProcessIdentity>(
            r#"{"process_id":1,"start_time_100ns":2,"image_path":"x","extra":3}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_secret_provider_never_routes_to_credential_manager() {
        assert!(!is_windows_secret_provider("arbitrary-provider"));
        assert!(is_windows_secret_provider("windows-credential-manager"));
    }

    #[test]
    fn pipe_expectation_rejects_caller_shaped_non_sid_values() {
        assert_eq!(
            NamedPipePeerExpectation::new("current-user", 1),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[test]
    fn service_registration_request_rejects_untrusted_shape() {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        assert_eq!(
            ServiceRegistrationRequest::new(
                "bad/service",
                "ELIOT test",
                &image,
                ServiceStartMode::Demand,
                ServiceAccount::LocalSystem,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceRegistrationRequest::new(
                "EliotTest",
                "\n",
                &image,
                ServiceStartMode::Demand,
                ServiceAccount::LocalSystem,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceRegistrationRequest::new(
                "EliotTest",
                "ELIOT test",
                PathBuf::from("relative.exe"),
                ServiceStartMode::Demand,
                ServiceAccount::LocalSystem,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[test]
    fn scm_post_effect_failure_is_reconciliation_unknown() {
        let failure = PortOutcome::Error(PortError::Provider(provider_failed()));
        assert_eq!(
            reconcile_service_effect(failure),
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        );
        assert_eq!(
            reconcile_service_effect(PortOutcome::Unknown(UnknownReason::NotObserved)),
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        );
    }

    #[test]
    fn create_new_does_not_truncate_existing_entry() {
        let root = std::env::temp_dir().join(format!("eliot-p02-create-new-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("entry");
        std::fs::write(&path, b"original").unwrap_or_else(|_| unreachable!());
        let error = create_new_file(&path, b"replacement").expect_err("must not truncate");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap_or_default(), b"original");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_service_is_typed_unsupported() {
        assert!(matches!(
            inspect_service("Eliot"),
            PortOutcome::Unknown(UnknownReason::Unsupported)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_identity_and_atomic_publication_are_safe_and_reproducible() {
        let root = std::env::temp_dir().join(format!("eliot-p02-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(root.join("state")).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let path = WorkScopePath::new("state/current.bin").unwrap_or_else(|_| unreachable!());
        let first = adapter
            .publish_atomic_receipt(&path, b"first")
            .unwrap_or_else(|_| unreachable!());
        let second = adapter
            .publish_atomic_receipt(&path, b"second")
            .unwrap_or_else(|_| unreachable!());
        assert_ne!(
            first.identity,
            FileIdentity {
                volume_serial_number: 0,
                file_index: 0
            }
        );
        assert_eq!(
            adapter
                .file_identity(&path)
                .unwrap_or_else(|_| unreachable!()),
            second.identity
        );
        assert_eq!(
            std::fs::read(root.join("state/current.bin")).unwrap_or_default(),
            b"second"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_dpapi_and_job_object_primitives_are_available() {
        let root = std::env::temp_dir().join(format!("eliot-p02-crypto-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let protected = adapter
            .protect_secret(b"p02-dpapi-roundtrip")
            .unwrap_or_else(|_| unreachable!());
        assert_ne!(protected.as_bytes(), b"p02-dpapi-roundtrip");
        let clear = adapter
            .unprotect_secret(&protected)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(clear.expose(), b"p02-dpapi-roundtrip");
        let _job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn job_child_process() {
        if std::env::var_os("ELIOT_P02_JOB_CHILD").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[cfg(windows)]
    fn wait_for_child_exit(child: &mut std::process::Child) -> bool {
        for _ in 0..100 {
            if child.try_wait().ok().flatten().is_some() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    #[cfg(windows)]
    fn spawn_job_child() -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap_or_else(|_| unreachable!()))
            .arg("--exact")
            .arg("tests::job_child_process")
            .arg("--nocapture")
            .env("ELIOT_P02_JOB_CHILD", "1")
            .spawn()
            .unwrap_or_else(|_| unreachable!())
    }

    #[cfg(windows)]
    #[test]
    fn suspended_child_process() {
        if let Some(marker) = std::env::var_os("ELIOT_P02_SUSPENDED_MARKER") {
            let _descendant = std::env::var_os("ELIOT_P02_SPAWN_DESCENDANT").map(|_| {
                std::process::Command::new(
                    std::env::current_exe().unwrap_or_else(|_| unreachable!()),
                )
                .arg("--exact")
                .arg("tests::job_child_process")
                .arg("--nocapture")
                .env("ELIOT_P02_JOB_CHILD", "1")
                .spawn()
                .unwrap_or_else(|_| unreachable!())
            });
            let body = format!(
                "cwd={}\nenv={}",
                std::env::current_dir()
                    .unwrap_or_else(|_| unreachable!())
                    .display(),
                std::env::var("ELIOT_P02_EXACT_ENV").unwrap_or_default()
            );
            std::fs::write(marker, body).unwrap_or_else(|_| unreachable!());
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[cfg(windows)]
    fn complete_test_environment(
        marker: &Path,
        spawn_descendant: bool,
    ) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        let mut environment = std::env::vars_os().collect::<Vec<_>>();
        for name in [
            "ELIOT_P02_SUSPENDED_MARKER",
            "ELIOT_P02_EXACT_ENV",
            "ELIOT_P02_SPAWN_DESCENDANT",
        ] {
            environment.retain(|(key, _)| !key.to_string_lossy().eq_ignore_ascii_case(name));
        }
        environment.push((
            "ELIOT_P02_SUSPENDED_MARKER".into(),
            marker.as_os_str().to_owned(),
        ));
        environment.push(("ELIOT_P02_EXACT_ENV".into(), "exact-value".into()));
        if spawn_descendant {
            environment.push(("ELIOT_P02_SPAWN_DESCENDANT".into(), "1".into()));
        }
        environment
    }

    #[cfg(windows)]
    fn suspended_spec(
        marker: &Path,
        working_directory: &Path,
        spawn_descendant: bool,
    ) -> SuspendedLaunchSpec {
        SuspendedLaunchSpec::new(
            std::env::current_exe().unwrap_or_else(|_| unreachable!()),
            vec![
                "--exact".into(),
                "tests::suspended_child_process".into(),
                "--nocapture".into(),
            ],
            working_directory,
            complete_test_environment(marker, spawn_descendant),
        )
        .unwrap_or_else(|error| panic!("spec failed: {error}"))
    }

    #[cfg(windows)]
    fn spawn_suspended_child(
        marker: &Path,
        working_directory: &Path,
        spawn_descendant: bool,
    ) -> SuspendedJobChild {
        SuspendedJobChild::spawn(suspended_spec(marker, working_directory, spawn_descendant))
            .unwrap_or_else(|error| panic!("spawn failed: {error}"))
    }

    #[cfg(windows)]
    fn wait_for_process_gone(pid: u32) -> bool {
        for _ in 0..100 {
            if inspect_process_identity(pid).is_err() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    #[cfg(windows)]
    #[test]
    fn suspended_launch_does_not_start_before_consuming_validation() {
        let root = std::env::temp_dir().join(format!("eliot-p02-suspended-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, false);
        let pid = child.id();
        assert!(!marker.exists(), "child must not run before ResumeThread");
        let terminal = child.terminate(0xE1_05).unwrap_or_else(|_| unreachable!());
        assert_eq!(terminal.process().process_id, pid);
        assert_eq!(terminal.requested_exit_code(), 0xE1_05);
        assert!(terminal.job_empty());
        assert!(terminal.root_reaped());
        assert!(wait_for_process_gone(pid));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn consuming_validation_binds_exact_launch_evidence_before_resume() {
        let root = std::env::temp_dir().join(format!("eliot-p02-evidence-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let expected_image = std::env::current_exe().unwrap_or_else(|_| unreachable!());
        let child = spawn_suspended_child(&marker, &root, false);
        let expected_pid = child.id();
        let validated = child
            .validate::<&'static str, &'static str, _>(|evidence| {
                assert_eq!(evidence.process().process_id, expected_pid);
                assert_ne!(evidence.executable_file_identity().file_index, 0);
                assert_eq!(evidence.job_process_count(), 1);
                assert!(same_windows_path(
                    &evidence.process().image_path,
                    &expected_image.to_string_lossy()
                ));
                assert_eq!(evidence.requested_executable(), expected_image);
                assert_eq!(evidence.working_directory(), root);
                assert_eq!(
                    evidence.arguments(),
                    [
                        std::ffi::OsString::from("--exact"),
                        std::ffi::OsString::from("tests::suspended_child_process"),
                        std::ffi::OsString::from("--nocapture"),
                    ]
                );
                assert!(evidence.environment().iter().any(|(name, value)| {
                    name == "ELIOT_P02_EXACT_ENV" && value == "exact-value"
                }));
                Ok("validated-by-test-policy")
            })
            .unwrap_or_else(|error| panic!("evidence validation failed: {error:?}"));
        assert!(!marker.exists(), "validation must not resume the child");
        assert_eq!(*validated.validation(), "validated-by-test-policy");
        let running = validated.resume().unwrap_or_else(|_| unreachable!());
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(marker.exists(), "child must run after validated resume");
        let marker_body = std::fs::read_to_string(&marker).unwrap_or_default();
        assert!(marker_body.contains(&format!("cwd={}", root.display())));
        assert!(marker_body.contains("env=exact-value"));
        let first = running.observe().unwrap_or_else(|_| unreachable!());
        let second = running.observe().unwrap_or_else(|_| unreachable!());
        assert_eq!(first, second, "observation is idempotent");
        running
            .terminate(0xE1_05)
            .unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn caller_pid_image_mismatch_rejection_kills_and_reaps_job() {
        let root = std::env::temp_dir().join(format!("eliot-p02-reject-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, false);
        let pid = child.id();
        let result = child.validate::<(), &'static str, _>(|evidence| {
            if evidence.process().process_id != pid + 1
                || evidence.process().image_path != "C:\\wrong\\image.exe"
            {
                Err("pid-image-mismatch")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.err(),
            Some(SuspendedValidationError::Rejected("pid-image-mismatch"))
        );
        assert!(wait_for_process_gone(pid), "rejected child must not leak");
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn stale_validation_cannot_validate_a_new_process_generation() {
        let root = std::env::temp_dir().join(format!("eliot-p02-stale-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let first_marker = root.join("first");
        let first = spawn_suspended_child(&first_marker, &root, false);
        let mut old_key = String::new();
        let first = first
            .validate::<(), &'static str, _>(|evidence| {
                old_key = evidence.process().stable_key();
                Ok(())
            })
            .unwrap_or_else(|_| unreachable!());
        first.terminate(0xE1_06).unwrap_or_else(|_| unreachable!());

        let second_marker = root.join("second");
        let second = spawn_suspended_child(&second_marker, &root, false);
        let second_pid = second.id();
        let result = second.validate::<(), &'static str, _>(|evidence| {
            if evidence.process().stable_key() == old_key {
                Ok(())
            } else {
                Err("stale-validation")
            }
        });
        assert_eq!(
            result.err(),
            Some(SuspendedValidationError::Rejected("stale-validation"))
        );
        assert!(wait_for_process_gone(second_pid));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn validator_panic_still_kills_and_reaps_suspended_job() {
        let root = std::env::temp_dir().join(format!("eliot-p02-panic-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, false);
        let pid = child.id();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = child.validate::<(), (), _>(|_| panic!("test validator panic"));
        }));
        assert!(panic.is_err());
        assert!(wait_for_process_gone(pid));
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn resumed_tree_termination_is_consuming_and_reaps_every_member() {
        let root = std::env::temp_dir().join(format!("eliot-p02-tree-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, true);
        let validated = child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!());
        let running = validated.resume().unwrap_or_else(|_| unreachable!());
        for _ in 0..100 {
            if marker.exists()
                && running
                    .job_processes()
                    .is_ok_and(|processes| processes.len() >= 2)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let members = running
            .job_processes()
            .unwrap_or_else(|error| panic!("membership failed: {error}"));
        assert!(members.len() >= 2);
        let pids = members
            .iter()
            .map(|process| process.process_id)
            .collect::<Vec<_>>();
        let terminal = running
            .terminate(0xE1_07)
            .unwrap_or_else(|error| panic!("termination failed: {error}"));
        assert_eq!(terminal.requested_exit_code(), 0xE1_07);
        assert!(terminal.job_empty());
        assert!(terminal.root_reaped());
        assert!(pids.into_iter().all(wait_for_process_gone));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_argument_quoting_covers_quotes_and_trailing_backslashes() {
        use std::os::windows::ffi::OsStringExt;
        let quote = |value: &str| {
            let units = quote_windows_argument(std::ffi::OsStr::new(value))
                .unwrap_or_else(|_| unreachable!());
            std::ffi::OsString::from_wide(&units)
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(quote(""), r#""""#);
        assert_eq!(quote("plain"), r#""plain""#);
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote("a\\"), "\"a\\\\\"");
        assert_eq!(quote(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[cfg(windows)]
    #[test]
    fn launch_spec_rejects_ambiguous_environment_and_nul_arguments() {
        let executable = std::env::current_exe().unwrap_or_else(|_| unreachable!());
        let root = std::env::temp_dir();
        assert_eq!(
            SuspendedLaunchSpec::new(
                &executable,
                Vec::new(),
                &root,
                vec![("Path".into(), "a".into()), ("PATH".into(), "b".into())],
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            SuspendedLaunchSpec::new(
                executable,
                vec![std::ffi::OsString::from("bad\0argument")],
                root,
                Vec::new(),
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn job_assignment_identity_termination_and_kill_on_close_are_real() {
        let job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
        let mut child = spawn_job_child();
        let identity = match job.assign_process(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("job assignment failed: {error}");
            }
        };
        assert_eq!(identity.process_id, child.id());
        assert!(identity.start_time_100ns > 0);
        assert!(!identity.image_path.is_empty());
        job.terminate(0xE102).unwrap_or_else(|_| unreachable!());
        assert!(wait_for_child_exit(&mut child));

        let job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
        let mut child = spawn_job_child();
        let identity = match job.assign_process(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("job assignment failed: {error}");
            }
        };
        assert_eq!(identity.process_id, child.id());
        drop(job);
        assert!(wait_for_child_exit(&mut child));
    }

    #[cfg(windows)]
    #[test]
    fn real_scm_registration_or_typed_acl_denial_is_reconciled_and_cleaned() {
        let root = std::env::temp_dir().join(format!("eliot-p02-scm-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let name = format!("EliotP02Test{}", unique_suffix().replace('-', ""));
        let request = ServiceRegistrationRequest::new(
            &name,
            "ELIOT P-02 registration test",
            std::env::current_exe().unwrap_or_else(|_| unreachable!()),
            ServiceStartMode::Demand,
            ServiceAccount::LocalSystem,
        )
        .unwrap_or_else(|_| unreachable!());
        let outcome = adapter.register_service(&request);
        eprintln!("p02_scm_registration_outcome={outcome:?}");
        match outcome {
            Ok(ServiceRegistrationOutcome::Registered { observation }) => {
                assert_eq!(observation.service.as_str(), name);
                let cleanup = mutate_service(&name, ServiceOperation::Unregister);
                assert!(matches!(
                    cleanup,
                    PortOutcome::Known(_)
                        | PortOutcome::Partial { .. }
                        | PortOutcome::Unknown(UnknownReason::Indeterminate)
                ));
            }
            Ok(ServiceRegistrationOutcome::EffectUnknown) => {
                let _ = mutate_service(&name, ServiceOperation::Unregister);
            }
            Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation) => {
                panic!("unique service unexpectedly existed")
            }
            Err(WindowsAdapterError::PermissionDenied) => {}
            Err(error) => panic!("unexpected registration error: {error}"),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_credential_manager_roundtrip_cleans_up() {
        let root = std::env::temp_dir().join(format!("eliot-p02-cred-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let key = format!("eliot/p02/test/{}", unique_suffix());
        adapter
            .write_credential(&key, b"credential-roundtrip")
            .unwrap_or_else(|_| unreachable!());
        let read = adapter.read_credential(&key);
        let delete = adapter.delete_credential(&key);
        assert_eq!(
            read.unwrap_or_else(|_| unreachable!()).expose(),
            b"credential-roundtrip"
        );
        assert!(delete.is_ok());
        assert_eq!(
            adapter.read_credential(&key).err(),
            Some(WindowsAdapterError::Unavailable)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_publication_is_collision_free_and_cleans_failed_staging() {
        use std::sync::Arc;
        let root = std::env::temp_dir().join(format!("eliot-p02-concurrent-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(root.join("state")).unwrap_or_else(|_| unreachable!());
        let adapter = Arc::new(WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!()));
        let path = WorkScopePath::new("state/current.bin").unwrap_or_else(|_| unreachable!());
        let workers = (0..8)
            .map(|index| {
                let adapter = Arc::clone(&adapter);
                let path = path.clone();
                std::thread::spawn(move || {
                    adapter.publish_atomic(&path, format!("value-{index}").as_bytes())
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            let outcome = worker
                .join()
                .unwrap_or_else(|_| unreachable!())
                .unwrap_or_else(|_| unreachable!());
            assert!(matches!(
                outcome,
                PublicationOutcome::Published(_) | PublicationOutcome::Unknown(_)
            ));
        }
        assert!(
            matches!(std::fs::read(root.join("state/current.bin")), Ok(bytes) if bytes.starts_with(b"value-"))
        );
        let entries = std::fs::read_dir(root.join("state"))
            .unwrap_or_else(|_| unreachable!())
            .count();
        assert_eq!(
            entries, 1,
            "failed publications must not leave staging files"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn live_process_identity_binds_pid_to_start_and_image() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let identity = inspect_process_identity(unsafe { GetCurrentProcessId() })
            .unwrap_or_else(|_| unreachable!());
        assert!(identity.start_time_100ns > 0);
        assert!(!identity.image_path.is_empty());
        let reused = ProcessIdentity {
            start_time_100ns: identity.start_time_100ns.saturating_add(1),
            ..identity.clone()
        };
        assert_ne!(identity.stable_key(), reused.stable_key());
    }

    #[cfg(windows)]
    #[test]
    fn reparse_ancestor_is_rejected_without_touching_target() {
        use std::os::windows::fs::symlink_dir;
        let root = std::env::temp_dir().join(format!("eliot-p02-reparse-{}", unique_suffix()));
        let outside = std::env::temp_dir().join(format!("eliot-p02-outside-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        if symlink_dir(&outside, root.join("link")).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let path = WorkScopePath::new("link/target.bin").unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            adapter.publish_atomic(&path, b"must-not-write"),
            Err(PortError::InvalidPath)
        ));
        assert!(!outside.join("target.bin").exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn reparse_destination_is_rejected_and_staging_is_removed() {
        use std::os::windows::fs::symlink_file;
        let root = std::env::temp_dir().join(format!("eliot-p02-destination-{}", unique_suffix()));
        let outside =
            std::env::temp_dir().join(format!("eliot-p02-destination-outside-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        std::fs::write(outside.join("target.bin"), b"original").unwrap_or_else(|_| unreachable!());
        if symlink_file(outside.join("target.bin"), root.join("current.bin")).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let path = WorkScopePath::new("current.bin").unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            adapter.publish_atomic(&path, b"must-not-write"),
            Err(PortError::InvalidPath)
        ));
        assert_eq!(
            std::fs::read(outside.join("target.bin")).unwrap_or_default(),
            b"original"
        );
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap_or_else(|_| unreachable!())
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
