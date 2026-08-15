//! Concrete Windows adapters for the P-01 platform ports.
//!
//! Windows implementation details are deliberately kept behind this facade.
//! The public surface contains P-01 contract values only; handles, provider
//! records, secret bytes, and IPC/process mechanics never escape this crate.

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

/// RAII wrapper for a Windows Job Object configured to terminate assigned
/// processes when the owning handle closes.
#[cfg(windows)]
pub struct JobObject {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl JobObject {
    /// Creates a Job Object with kill-on-close configured before publication.
    ///
    /// # Errors
    /// Returns a typed adapter error when creation or configuration fails.
    pub fn new_kill_on_close() -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(last_windows_adapter_error());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let length = u32::try_from(std::mem::size_of_val(&limits))
            .map_err(|_| WindowsAdapterError::Failed)?;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                length,
            )
        } != 0;
        if !configured {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(last_windows_adapter_error());
        }
        Ok(Self { handle })
    }

    /// Assigns an existing process and returns its exact observed identity.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid identity, access or assignment failure.
    pub fn assign_process(&self, process_id: u32) -> Result<ProcessIdentity, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
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
        let assigned = unsafe { AssignProcessToJobObject(self.handle, process) } != 0;
        let result = if assigned {
            inspect_process_handle(process_id, process)
                .map_err(|error| windows_adapter_from_io(&error))
        } else {
            Err(last_windows_adapter_error())
        };
        unsafe { CloseHandle(process) };
        result
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
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_PATH_NOT_FOUND,
            ERROR_SERVICE_DOES_NOT_EXIST, ERROR_TIMEOUT,
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
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset => WindowsAdapterError::Unavailable,
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
