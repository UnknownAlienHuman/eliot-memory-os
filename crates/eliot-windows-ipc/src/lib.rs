//! Audited Win32 security-descriptor boundary for Eliot named pipes.
//!
//! The rest of the workspace forbids unsafe code. This crate contains the single
//! FFI boundary required to pass an explicit current-user DACL to Tokio.

#![cfg(windows)]

use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_NOT_FOUND, ERROR_SHARING_VIOLATION, FILETIME, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, LocalFree, STILL_ACTIVE, SetHandleInformation, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW,
    CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FindCloseChangeNotification,
    FindFirstChangeNotificationW, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, CreateIoCompletionPort, DeviceIoControl, GetQueuedCompletionStatus, OVERLAPPED,
    PostQueuedCompletionStatus,
};
use windows_sys::Win32::System::Ioctl::{
    FSCTL_REQUEST_OPLOCK, OPLOCK_LEVEL_CACHE_HANDLE, OPLOCK_LEVEL_CACHE_READ,
    REQUEST_OPLOCK_CURRENT_VERSION, REQUEST_OPLOCK_INPUT_BUFFER, REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
    REQUEST_OPLOCK_OUTPUT_BUFFER,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, GetNamedPipeClientProcessId};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessW,
    GetExitCodeProcess, OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_QUOTA, PROCESS_TERMINATE, QueryFullProcessImageNameW, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

const MAX_PROCESS_IMAGE_CHARS: usize = 32_768;
const MAX_JOB_PROCESS_IDS: usize = 4_096;
const JOB_COMPLETION_KEY: usize = 0x454c_494f;
const JOB_OBSERVER_SHUTDOWN_KEY: usize = 0x454e_4421;
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;

/// Kernel-derived identity of a process observed through a named pipe or Job Object.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessImageIdentity {
    /// Windows process identifier.
    pub pid: u32,
    /// Full Win32 executable image path returned by the process API.
    pub image: PathBuf,
    /// Stable NTFS/file-system identity of the executable opened from `image`.
    pub file_identity: FileIdentity,
}

/// Stable file identity returned by `GetFileInformationByHandle`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileIdentity {
    /// Volume serial number containing the file.
    pub volume_serial_number: u32,
    /// 64-bit file index within the volume.
    pub file_index: u64,
}

/// A read-only file authority held open without write or delete sharing.
///
/// The handle prevents replacement or mutation of the named file while trusted
/// bytes are parsed, hashed, and consumed by a child process.
pub struct PinnedFile {
    file: File,
    identity: FileIdentity,
}

impl PinnedFile {
    /// Opens an existing non-reparse file and denies concurrent writes/deletes.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be opened, is not a regular file,
    /// or its final component is a reparse point.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pinned path is not a non-reparse file: {}", path.display()),
            ));
        }
        let identity = file_identity(&file)?;
        Ok(Self { file, identity })
    }

    /// Reads the complete file from the same held handle.
    ///
    /// # Errors
    ///
    /// Returns an error when seeking or reading the pinned handle fails.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Returns the stable volume/file-index identity of the held file object.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }
}

fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle is live and `information` is a valid out pointer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

/// A directory handle held without delete sharing to prevent path replacement.
pub struct PinnedDirectory {
    _directory: File,
}

impl PinnedDirectory {
    /// Opens an existing non-reparse directory while allowing child writes but
    /// denying replacement/deletion of the directory itself.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be opened, is not a directory, or
    /// its final component is a reparse point.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_share(path, FILE_SHARE_READ | FILE_SHARE_WRITE)
    }

    fn open_with_share(path: &Path, share_mode: u32) -> io::Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(share_mode)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "pinned path is not a non-reparse directory: {}",
                    path.display()
                ),
            ));
        }
        Ok(Self {
            _directory: directory,
        })
    }
}

/// A directory oplock that reports namespace mutation attempts.
///
/// Windows directory oplocks are advisory for child enumeration changes, so
/// callers must fail closed when the event is signaled. Existing bundle files
/// require separate deny-write/delete pinned handles.
pub struct DirectoryOplockGuard {
    directory: Option<File>,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    _input: Box<REQUEST_OPLOCK_INPUT_BUFFER>,
    _output: Box<REQUEST_OPLOCK_OUTPUT_BUFFER>,
}

// SAFETY: all pointers submitted to Windows refer to boxed allocations whose
// addresses do not change. Moving the guard transfers unique ownership while
// the kernel operation remains bound to the same handle/event/buffers.
unsafe impl Send for DirectoryOplockGuard {}

impl DirectoryOplockGuard {
    /// Acquires a read/handle caching oplock on a non-reparse directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is invalid or Windows cannot grant
    /// a pending oplock request.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
            )
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "oplock path is not a non-reparse directory: {}",
                    path.display()
                ),
            ));
        }
        // SAFETY: null security/name pointers request an unnamed event owned here.
        let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut overlapped = Box::new(OVERLAPPED::default());
        overlapped.hEvent = event.0;
        let structure_version = u16::try_from(REQUEST_OPLOCK_CURRENT_VERSION).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "oplock version does not fit u16",
            )
        })?;
        let structure_length = u16::try_from(std::mem::size_of::<REQUEST_OPLOCK_INPUT_BUFFER>())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oplock input size does not fit u16",
                )
            })?;
        let input = Box::new(REQUEST_OPLOCK_INPUT_BUFFER {
            StructureVersion: structure_version,
            StructureLength: structure_length,
            RequestedOplockLevel: OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE,
            Flags: REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
        });
        let mut output = Box::new(REQUEST_OPLOCK_OUTPUT_BUFFER::default());
        let input_size = u32::try_from(std::mem::size_of_val(input.as_ref()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "oplock input is too large"))?;
        let output_size = u32::try_from(std::mem::size_of_val(output.as_ref())).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "oplock output is too large")
        })?;
        // SAFETY: the file/event are live, all buffers are boxed and remain at
        // stable addresses in the returned guard, and the OVERLAPPED request is
        // canceled and drained before those buffers are dropped.
        let requested = unsafe {
            DeviceIoControl(
                directory.as_raw_handle().cast(),
                FSCTL_REQUEST_OPLOCK,
                ptr::from_ref::<REQUEST_OPLOCK_INPUT_BUFFER>(input.as_ref()).cast::<c_void>(),
                input_size,
                ptr::from_mut::<REQUEST_OPLOCK_OUTPUT_BUFFER>(output.as_mut()).cast::<c_void>(),
                output_size,
                ptr::null_mut(),
                overlapped.as_mut(),
            )
        };
        if requested != 0 {
            return Err(io::Error::other(
                "directory oplock completed without a durable pending lease",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != i32::try_from(ERROR_IO_PENDING).ok() {
            return Err(error);
        }
        Ok(Self {
            directory: Some(directory),
            event,
            overlapped,
            _input: input,
            _output: output,
        })
    }

    /// Returns true if Windows has requested an oplock break because a
    /// conflicting bundle mutation was attempted.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot query the oplock event.
    pub fn mutation_attempted(&self) -> io::Result<bool> {
        // SAFETY: event remains live for the complete guard lifetime.
        match unsafe { WaitForSingleObject(self.event.0, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for DirectoryOplockGuard {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            // SAFETY: the pending request belongs to this exact file handle and
            // OVERLAPPED allocation. Closing the handle completes cancellation.
            unsafe {
                CancelIoEx(directory.as_raw_handle().cast(), self.overlapped.as_ref());
            }
            drop(directory);
            // SAFETY: wait only drains the cancellation before boxed buffers drop.
            unsafe {
                WaitForSingleObject(self.event.0, 5_000);
            }
        }
    }
}

/// Creates and durably writes a new regular file without following a reparse
/// point and holds the handle without write/delete sharing until completion.
///
/// # Errors
///
/// Returns an error if the destination already exists, is raced by another
/// creator, resolves to a reparse point, or cannot be completely flushed.
pub fn write_new_pinned_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "new pinned output is not a non-reparse file: {}",
                path.display()
            ),
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Resolves the PID and executable image of the client connected to a server pipe.
///
/// # Errors
///
/// Returns an error when Windows cannot bind the server pipe to its client PID or
/// query that process image.
pub fn named_pipe_client_process(pipe: &NamedPipeServer) -> io::Result<ProcessImageIdentity> {
    let mut pid = 0_u32;
    // SAFETY: Tokio owns a live server-end pipe handle and `pid` is a valid out pointer.
    let resolved =
        unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle().cast(), &raw mut pid) };
    if resolved == 0 || pid == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(open_process_identity(pid)?.identity)
}

/// Returns the full executable image path for `pid` using limited query access.
///
/// # Errors
///
/// Returns an error for a zero PID or when Windows cannot open or query the process.
pub fn process_image_path(pid: u32) -> io::Result<PathBuf> {
    Ok(open_process_identity(pid)?.identity.image)
}

fn query_process_image(process: &OwnedHandle) -> io::Result<PathBuf> {
    let mut image = vec![0_u16; MAX_PROCESS_IMAGE_CHARS];
    let mut chars = u32::try_from(image.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process image buffer is too large",
        )
    })?;
    // SAFETY: the process handle is live and the UTF-16 output buffer has `chars` elements.
    let queried =
        unsafe { QueryFullProcessImageNameW(process.0, 0, image.as_mut_ptr(), &raw mut chars) };
    if queried == 0 || chars == 0 {
        return Err(io::Error::last_os_error());
    }
    let chars = usize::try_from(chars).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process image length is invalid",
        )
    })?;
    image.truncate(chars);
    Ok(PathBuf::from(OsString::from_wide(&image)))
}

fn open_process_identity(pid: u32) -> io::Result<ObservedProcess> {
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PID must be non-zero",
        ));
    }
    // SAFETY: `pid` is only used by Windows to resolve a process handle.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let process = OwnedHandle::new(process)?;
    let image = query_process_image(&process)?;
    let image_file = PinnedFile::open(&image)?;
    Ok(ObservedProcess {
        identity: ProcessImageIdentity {
            pid,
            image,
            file_identity: image_file.identity(),
        },
        _process: process,
        _image_file: image_file,
    })
}

/// Owns a Windows Job Object configured to kill the complete provider process
/// tree when the guard is explicitly terminated or dropped.
pub struct ProcessTreeGuard {
    job: windows_sys::Win32::Foundation::HANDLE,
}

impl ProcessTreeGuard {
    /// Attaches the process identified by `pid` to a kill-on-close Job Object.
    ///
    /// # Errors
    ///
    /// Returns an error when `pid` is zero or Windows cannot create, configure,
    /// open, or assign the process to the Job Object.
    pub fn attach(pid: u32) -> io::Result<Self> {
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PID must be non-zero",
            ));
        }
        // SAFETY: null name and security pointers request an unnamed job owned by this process.
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let info_size = u32::try_from(std::mem::size_of_val(&info)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Job Object limit structure is too large",
            )
        })?;
        // SAFETY: `job` is live and `info` has the exact structure required by the selected class.
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                info_size,
            )
        };
        if configured == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: `job` was created above and is closed exactly once on this error path.
            unsafe { CloseHandle(job) };
            return Err(error);
        }
        // SAFETY: numeric PID is provided by the freshly spawned child.
        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if process.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: `job` was created above and is closed exactly once on this error path.
            unsafe { CloseHandle(job) };
            return Err(error);
        }
        // SAFETY: both handles are live for the duration of the call.
        let assigned = unsafe { AssignProcessToJobObject(job, process) };
        let assign_error = (assigned == 0).then(io::Error::last_os_error);
        // SAFETY: `process` is no longer needed after assignment and is owned here.
        unsafe { CloseHandle(process) };
        if let Some(error) = assign_error {
            // SAFETY: `job` was created above and is closed exactly once on this error path.
            unsafe { CloseHandle(job) };
            return Err(error);
        }
        Ok(Self { job })
    }

    /// Terminates every process assigned to the job.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot terminate the Job Object.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: `self.job` remains live until Drop.
        let terminated = unsafe { TerminateJobObject(self.job, exit_code) };
        if terminated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        // SAFETY: `self.job` is uniquely owned and closed exactly once here.
        unsafe { CloseHandle(self.job) };
    }
}

struct OwnedHandle(HANDLE);

// SAFETY: Windows kernel handles are valid across threads. Ownership remains
// unique in this wrapper and CloseHandle is called exactly once in Drop.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn into_file(self) -> File {
        let handle = self.0;
        std::mem::forget(self);
        // SAFETY: ownership of the live handle moves into File exactly once.
        unsafe { File::from_raw_handle(handle) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the wrapper uniquely owns the handle until this Drop.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn create_kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: null name and security pointers request an unnamed job owned here.
    let job = OwnedHandle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let info_size = u32::try_from(std::mem::size_of_val(&info)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Job Object limits are too large",
        )
    })?;
    // SAFETY: job is live and info has the exact selected Job Object layout.
    let configured = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            info_size,
        )
    };
    if configured == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

fn inheritable_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SECURITY_ATTRIBUTES is too large",
            )
        })?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: output pointers and the security-attribute pointer are valid for the call.
    let created = unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((OwnedHandle::new(read)?, OwnedHandle::new(write)?))
}

fn make_non_inheritable(handle: HANDLE) -> io::Result<()> {
    // SAFETY: handle is live and SetHandleInformation does not retain it.
    let changed = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    if changed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn quote_windows_argument(value: &OsStr) -> io::Result<Vec<u16>> {
    let value = value.encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process argument contains an embedded NUL",
        ));
    }
    let needs_quotes = value.is_empty()
        || value.iter().any(|unit| {
            char::from_u32(u32::from(*unit)).is_some_and(char::is_whitespace)
                || *unit == u16::from(b'"')
        });
    if !needs_quotes {
        return Ok(value);
    }
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

fn command_line(command: &std::process::Command) -> io::Result<Vec<u16>> {
    let mut line = Vec::new();
    for (index, argument) in std::iter::once(command.get_program())
        .chain(command.get_args())
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

fn command_environment(command: &std::process::Command) -> io::Result<Vec<u16>> {
    let mut entries = Vec::new();
    for (name, value) in command.get_envs() {
        let Some(value) = value else {
            continue;
        };
        let name = name.to_string_lossy();
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process environment name is invalid",
            ));
        }
        let value = value.to_string_lossy();
        if value.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "process environment value contains NUL",
            ));
        }
        entries.push(format!("{name}={value}"));
    }
    entries.sort_by_key(|entry| entry.to_ascii_uppercase());
    let mut block = Vec::new();
    for entry in entries {
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

struct ObservedProcess {
    identity: ProcessImageIdentity,
    _process: OwnedHandle,
    _image_file: PinnedFile,
}

struct JobProcessObserver {
    completion_port: OwnedHandle,
    observed: Arc<Mutex<Vec<ObservedProcess>>>,
    thread: Option<JoinHandle<()>>,
}

impl JobProcessObserver {
    fn attach(job: HANDLE) -> io::Result<Self> {
        // SAFETY: INVALID_HANDLE_VALUE plus a null existing port creates a standalone IOCP.
        let completion_port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) };
        let completion_port = OwnedHandle::new(completion_port)?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_COMPLETION_KEY as *mut c_void,
            CompletionPort: completion_port.0,
        };
        let association_size =
            u32::try_from(std::mem::size_of_val(&association)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Job completion-port association is too large",
                )
            })?;
        // SAFETY: the job and completion port are live and the association has the exact class shape.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                association_size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let observed = Arc::new(Mutex::new(Vec::new()));
        let thread_observed = Arc::clone(&observed);
        let raw_port = completion_port.0 as usize;
        let thread = std::thread::Builder::new()
            .name("eliot-job-process-observer".to_owned())
            .spawn(move || job_process_observer_loop(raw_port, &thread_observed))?;
        Ok(Self {
            completion_port,
            observed,
            thread: Some(thread),
        })
    }

    fn snapshot(&self) -> Vec<ProcessImageIdentity> {
        self.observed.lock().map_or_else(
            |_| Vec::new(),
            |observed| {
                observed
                    .iter()
                    .map(|record| record.identity.clone())
                    .collect()
            },
        )
    }

    fn capture_pid(&self, pid: u32) -> io::Result<()> {
        let process = open_process_identity(pid)?;
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| io::Error::other("Job process observer lock is poisoned"))?;
        if !observed
            .iter()
            .any(|record| record.identity == process.identity)
        {
            observed.push(process);
        }
        Ok(())
    }

    fn contains_pid(&self, pid: u32) -> bool {
        self.observed
            .lock()
            .is_ok_and(|observed| observed.iter().any(|record| record.identity.pid == pid))
    }

    fn shutdown(&mut self) {
        if self.thread.is_none() {
            return;
        }
        // SAFETY: the completion port stays live until the observer thread is joined.
        unsafe {
            PostQueuedCompletionStatus(
                self.completion_port.0,
                0,
                JOB_OBSERVER_SHUTDOWN_KEY,
                ptr::null(),
            );
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for JobProcessObserver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn job_process_observer_loop(raw_port: usize, observed: &Arc<Mutex<Vec<ObservedProcess>>>) {
    let completion_port = raw_port as HANDLE;
    loop {
        let mut message = 0_u32;
        let mut completion_key = 0_usize;
        let mut overlapped = ptr::null_mut();
        // SAFETY: the IOCP is owned by the observer and all out pointers are live for the call.
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
        if dequeued == 0
            || completion_key != JOB_COMPLETION_KEY
            || message != JOB_OBJECT_MSG_NEW_PROCESS
        {
            continue;
        }
        let Ok(pid) = u32::try_from(overlapped as usize) else {
            continue;
        };
        if let Ok(process) = open_process_identity(pid)
            && let Ok(mut records) = observed.lock()
            && !records
                .iter()
                .any(|record| record.identity == process.identity)
        {
            records.push(process);
        }
    }
}

/// A child process created suspended, assigned to its kill-on-close Job Object,
/// and only then resumed. Its stdout/stderr read handles belong to the caller.
pub struct SuspendedJobChild {
    process: OwnedHandle,
    root_identity: ProcessImageIdentity,
    _root_image_file: PinnedFile,
    job: OwnedHandle,
    stdout: Option<File>,
    stderr: Option<File>,
    pid: u32,
    observer: JobProcessObserver,
}

impl SuspendedJobChild {
    /// Creates a hidden process from the exact program, args, cwd, and explicit
    /// environment configured on `command`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid command material or any pipe, process, Job
    /// Object assignment, or resume failure. Assignment always precedes resume.
    pub fn spawn(command: &std::process::Command) -> io::Result<Self> {
        let application = nul_terminated_wide(command.get_program())?;
        let mut command_line = command_line(command)?;
        let mut environment = command_environment(command)?;
        let current_directory = command
            .get_current_dir()
            .map(|path| nul_terminated_wide(path.as_os_str()))
            .transpose()?;
        let (stdin_read, stdin_write) = inheritable_pipe()?;
        let (stdout_read, stdout_write) = inheritable_pipe()?;
        let (stderr_read, stderr_write) = inheritable_pipe()?;
        make_non_inheritable(stdout_read.0)?;
        make_non_inheritable(stderr_read.0)?;
        drop(stdin_write);
        let job = create_kill_on_close_job()?;
        let observer = JobProcessObserver::attach(job.0)?;
        let startup = STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "STARTUPINFOW is too large")
            })?,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdin_read.0,
            hStdOutput: stdout_write.0,
            hStdError: stderr_write.0,
            ..STARTUPINFOW::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: all UTF-16 buffers are NUL-terminated and live for the call;
        // STARTUPINFO and PROCESS_INFORMATION pointers are valid out/in structs.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_mut_ptr().cast(),
                current_directory.as_ref().map_or(ptr::null(), Vec::as_ptr),
                &raw const startup,
                &raw mut information,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OwnedHandle::new(information.hProcess)?;
        let thread = OwnedHandle::new(information.hThread)?;
        let root_image = query_process_image(&process)?;
        let root_image_file = PinnedFile::open(&root_image)?;
        let root_identity = ProcessImageIdentity {
            pid: information.dwProcessId,
            image: root_image,
            file_identity: root_image_file.identity(),
        };
        // Child-only pipe endpoints must close in the parent before any reads.
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);
        // SAFETY: the process is still suspended and both handles are live.
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: process is live and remains suspended, so it cannot escape.
            unsafe {
                TerminateProcess(process.0, 1);
                WaitForSingleObject(process.0, 5_000);
            }
            return Err(error);
        }
        // SAFETY: the primary thread is live and suspended exactly once here.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = io::Error::last_os_error();
            // SAFETY: job contains the process before this error path.
            unsafe {
                TerminateJobObject(job.0, 1);
                WaitForSingleObject(process.0, 5_000);
            }
            return Err(error);
        }
        drop(thread);
        Ok(Self {
            process,
            root_identity,
            _root_image_file: root_image_file,
            job,
            stdout: Some(stdout_read.into_file()),
            stderr: Some(stderr_read.into_file()),
            pid: information.dwProcessId,
            observer,
        })
    }

    #[must_use]
    pub const fn id(&self) -> u32 {
        self.pid
    }

    /// Returns the root process identity through the same held process handle
    /// created by `CreateProcessW`.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot query the held root process handle.
    pub fn root_process_identity(&self) -> io::Result<ProcessImageIdentity> {
        Ok(self.root_identity.clone())
    }

    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    /// Enumerates the executable images currently contained by this child's Job Object.
    ///
    /// Processes which exit between the Job Object query and image lookup are omitted.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot query the Job Object or a live process image.
    pub fn job_processes(&self) -> io::Result<Vec<ProcessImageIdentity>> {
        for pid in job_process_ids(self.job.0)? {
            match self.observer.capture_pid(pid) {
                Ok(()) => {}
                Err(error)
                    if error.raw_os_error()
                        == Some(i32::try_from(ERROR_INVALID_PARAMETER).unwrap_or(87)) => {}
                Err(error)
                    if error.raw_os_error()
                        == Some(i32::try_from(ERROR_ACCESS_DENIED).unwrap_or(5))
                        && self.observer.contains_pid(pid) => {}
                Err(error) => return Err(error),
            }
        }
        let mut processes = self.observed_processes();
        processes.sort();
        processes.dedup();
        Ok(processes)
    }

    /// Returns identities already bound to retained process handles without a
    /// fresh Job Object or PID lookup.
    #[must_use]
    pub fn observed_processes(&self) -> Vec<ProcessImageIdentity> {
        let mut processes = self.observer.snapshot();
        if !processes.contains(&self.root_identity) {
            processes.push(self.root_identity.clone());
        }
        processes
    }

    /// Returns the process exit code without waiting.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot query the process wait or exit code.
    pub fn try_wait(&self) -> io::Result<Option<i32>> {
        // SAFETY: process handle remains live for the call.
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                // SAFETY: process is signaled and code is a valid out pointer.
                if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Waits up to `timeout` for the root process only.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot wait or query the exit code.
    pub fn wait_timeout(&self, timeout: Duration) -> io::Result<Option<i32>> {
        let millis = timeout.as_millis().min(u128::from(u32::MAX - 1));
        let millis = u32::try_from(millis).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "wait duration does not fit u32",
            )
        })?;
        // SAFETY: process handle remains live for the call.
        match unsafe { WaitForSingleObject(self.process.0, millis) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => self.try_wait(),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Terminates every process assigned to the Job Object.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot terminate the Job Object.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: job remains live for the call.
        if unsafe { TerminateJobObject(self.job.0, exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn job_process_ids(job: HANDLE) -> io::Result<Vec<u32>> {
    let mut capacity = 16_usize;
    loop {
        let bytes = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
            .checked_add(
                capacity
                    .saturating_sub(1)
                    .checked_mul(std::mem::size_of::<usize>())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Job process list is too large")
                    })?,
            )
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Job process list is too large")
            })?;
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let bytes = u32::try_from(buffer.len() * std::mem::size_of::<usize>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Job process buffer is too large",
            )
        })?;
        let mut returned = 0_u32;
        // SAFETY: `job` remains live and `buffer` is aligned for the selected Win32 structure.
        let queried = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(),
                bytes,
                &raw mut returned,
            )
        };
        // SAFETY: the buffer is aligned and large enough for the fixed header on every path.
        let header = unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
        if queried != 0 {
            let count = usize::try_from(header.NumberOfProcessIdsInList).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Job process count is invalid")
            })?;
            if count > capacity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Job process list exceeded its supplied buffer",
                ));
            }
            // SAFETY: Windows reported `count` initialized entries within the supplied buffer.
            let ids = unsafe { std::slice::from_raw_parts(header.ProcessIdList.as_ptr(), count) };
            return ids
                .iter()
                .copied()
                .filter(|pid| *pid != 0)
                .map(|pid| {
                    u32::try_from(pid).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Job PID does not fit u32")
                    })
                })
                .collect();
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(i32::try_from(ERROR_MORE_DATA).unwrap_or(234)) {
            return Err(error);
        }
        let assigned = usize::try_from(header.NumberOfAssignedProcesses).unwrap_or(capacity + 1);
        capacity = assigned.max(capacity.saturating_mul(2));
        if capacity > MAX_JOB_PROCESS_IDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Job process list exceeds the attestation limit",
            ));
        }
    }
}

impl Drop for SuspendedJobChild {
    fn drop(&mut self) {
        // SAFETY: kill-on-close is also configured. Drop requests termination
        // but never introduces a second hidden wait beyond the caller's deadline.
        unsafe {
            TerminateJobObject(self.job.0, 1);
        }
        self.observer.shutdown();
    }
}

/// Watches a directory subtree and reports any filesystem mutation after the
/// guard is created. It is intentionally fail-closed at the caller boundary.
pub struct DirectoryMutationGuard {
    handle: HANDLE,
}

impl DirectoryMutationGuard {
    /// Starts a recursive Windows change notification for an existing directory.
    ///
    /// # Errors
    ///
    /// Returns an error when `path` is not a directory or Windows cannot create
    /// the recursive change-notification handle.
    pub fn watch(path: &Path) -> io::Result<Self> {
        if !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("mutation-watch directory is missing: {}", path.display()),
            ));
        }
        let path = nul_terminated_wide(path.as_os_str())?;
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_ATTRIBUTES
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_CREATION
            | FILE_NOTIFY_CHANGE_SECURITY;
        // SAFETY: path is NUL-terminated and remains live for the call.
        let handle = unsafe { FindFirstChangeNotificationW(path.as_ptr(), 1, filter) };
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    /// Returns true after any watched subtree mutation.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot query the notification handle.
    pub fn mutation_detected(&self) -> io::Result<bool> {
        // SAFETY: notification handle remains live for the call.
        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for DirectoryMutationGuard {
    fn drop(&mut self) {
        // SAFETY: the guard uniquely owns the change-notification handle.
        unsafe { FindCloseChangeNotification(self.handle) };
    }
}

/// Reports whether a Windows process identifier still names a live process.
///
/// # Errors
///
/// Returns an error when Windows refuses the process query for a reason other
/// than the PID no longer existing.
pub fn process_is_alive(pid: u32) -> io::Result<bool> {
    if pid == 0 {
        return Ok(false);
    }
    // SAFETY: OpenProcess receives a numeric PID and returns an owned handle.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok() {
            return Ok(false);
        }
        return Err(error);
    }
    let mut exit_code = 0;
    // SAFETY: `handle` is live and owned here; `exit_code` is a valid out pointer.
    let queried = unsafe { GetExitCodeProcess(handle, &raw mut exit_code) };
    let query_error = (queried == 0).then(io::Error::last_os_error);
    // SAFETY: `handle` was returned by OpenProcess and is closed exactly once.
    let closed = unsafe { CloseHandle(handle) };
    let close_error = (closed == 0).then(io::Error::last_os_error);
    if let Some(error) = query_error {
        return Err(error);
    }
    if let Some(error) = close_error {
        return Err(error);
    }
    let still_active = u32::try_from(STILL_ACTIVE).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows STILL_ACTIVE value does not fit u32",
        )
    })?;
    Ok(exit_code == still_active)
}

/// Atomically replaces a file with another file from the same volume and asks
/// Windows to flush the move before returning.
///
/// # Errors
///
/// Returns an error when either path is invalid or Windows cannot complete the
/// replacement.
pub fn atomic_replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = nul_terminated_wide(source.as_os_str())?;
    let destination = nul_terminated_wide(destination.as_os_str())?;
    for attempt in 0..=40 {
        // SAFETY: both buffers are NUL-terminated and remain alive for the complete
        // call. MoveFileExW does not retain either pointer.
        let moved = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        let transient = matches!(
            error.raw_os_error(),
            Some(code)
                if code == i32::try_from(ERROR_ACCESS_DENIED).unwrap_or(5)
                    || code == i32::try_from(ERROR_SHARING_VIOLATION).unwrap_or(32)
        );
        if !transient || attempt == 40 {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    unreachable!("bounded atomic replacement loop always returns")
}

fn nul_terminated_wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an embedded NUL",
        ));
    }
    Ok(wide.into_iter().chain(std::iter::once(0)).collect())
}

fn credential_target(credential_id: &str) -> io::Result<Vec<u16>> {
    let valid = !credential_id.is_empty()
        && credential_id.len() <= 240
        && !credential_id.starts_with('/')
        && !credential_id.ends_with('/')
        && credential_id
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && credential_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
        });
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential id must be a bounded logical identifier",
        ));
    }
    nul_terminated_wide(OsStr::new(&format!("EliotGovernor/{credential_id}")))
}

struct CredentialBuffer(*mut CREDENTIALW);

impl Drop for CredentialBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `CredReadW` and remains owned by
            // this guard until it is released exactly once here.
            unsafe {
                CredFree(self.0.cast());
            }
        }
    }
}

/// Metadata-only view of a current-user Windows credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentUserCredentialStatus {
    pub present: bool,
    pub version: Option<u64>,
    pub size_bytes: Option<u32>,
}

/// Returns metadata for an Eliot credential without exposing its value.
///
/// # Errors
///
/// Returns an error for an invalid identifier or a Windows Credential Manager
/// failure other than a missing credential.
pub fn credential_status_current_user(
    credential_id: &str,
) -> io::Result<CurrentUserCredentialStatus> {
    let target = credential_target(credential_id)?;
    let mut raw = ptr::null_mut();
    // SAFETY: `target` is NUL-terminated and `raw` is a valid out pointer.
    let read = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &raw mut raw) };
    if read == 0 {
        // SAFETY: this call immediately follows the failed Win32 operation.
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
            return Ok(CurrentUserCredentialStatus {
                present: false,
                version: None,
                size_bytes: None,
            });
        }
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    let buffer = CredentialBuffer(raw);
    // SAFETY: successful `CredReadW` returned the allocation owned by `buffer`.
    let credential = unsafe { &*buffer.0 };
    let version = (u64::from(credential.LastWritten.dwHighDateTime) << 32)
        | u64::from(credential.LastWritten.dwLowDateTime);
    Ok(CurrentUserCredentialStatus {
        present: true,
        version: Some(version),
        size_bytes: Some(credential.CredentialBlobSize),
    })
}

/// Reads an Eliot generic credential from Windows Credential Manager for the
/// current user. The logical identifier is mapped into the Eliot namespace.
///
/// # Errors
///
/// Returns an error for an invalid identifier, an invalid credential blob, or
/// a Windows Credential Manager failure other than a missing credential.
pub fn credential_read_current_user(credential_id: &str) -> io::Result<Option<Vec<u8>>> {
    let target = credential_target(credential_id)?;
    let mut raw = ptr::null_mut();
    // SAFETY: `target` is NUL-terminated and `raw` is a valid out pointer.
    let read = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &raw mut raw) };
    if read == 0 {
        // SAFETY: this call immediately follows the failed Win32 operation.
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    let buffer = CredentialBuffer(raw);
    // SAFETY: a successful `CredReadW` returns a valid `CREDENTIALW` allocation
    // owned by `buffer` for the duration of this function.
    let credential = unsafe { &*buffer.0 };
    let blob_size = usize::try_from(credential.CredentialBlobSize).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "credential blob size is invalid",
        )
    })?;
    if credential.CredentialBlobSize > CRED_MAX_CREDENTIAL_BLOB_SIZE
        || (blob_size > 0 && credential.CredentialBlob.is_null())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential blob is invalid",
        ));
    }
    // SAFETY: the blob belongs to the credential allocation, and the API
    // guarantees `CredentialBlobSize` readable bytes on success.
    let bytes = unsafe { std::slice::from_raw_parts(credential.CredentialBlob, blob_size) };
    Ok(Some(bytes.to_vec()))
}

/// Writes an Eliot generic credential to Windows Credential Manager for the
/// current user. Existing content at the same logical identifier is replaced.
///
/// # Errors
///
/// Returns an error for an invalid identifier, an empty or oversized value, or
/// a Windows Credential Manager failure.
pub fn credential_write_current_user(credential_id: &str, value: &[u8]) -> io::Result<()> {
    let mut target = credential_target(credential_id)?;
    if value.is_empty() || value.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential value must be non-empty and within the Win32 blob limit",
        ));
    }
    let mut username = nul_terminated_wide(OsStr::new("EliotGovernor"))?;
    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        Comment: ptr::null_mut(),
        LastWritten: FILETIME::default(),
        CredentialBlobSize: u32::try_from(value.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "credential value is too large")
        })?,
        CredentialBlob: value.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: ptr::null_mut(),
        TargetAlias: ptr::null_mut(),
        UserName: username.as_mut_ptr(),
    };
    // SAFETY: all pointers in `credential` remain valid for the complete call,
    // and the blob length is checked against the Win32 maximum.
    let written = unsafe { CredWriteW(&raw const credential, 0) };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Deletes an Eliot generic credential for the current user.
///
/// Returns `false` when the credential did not exist.
///
/// # Errors
///
/// Returns an error for an invalid identifier or another Windows Credential
/// Manager failure.
pub fn credential_delete_current_user(credential_id: &str) -> io::Result<bool> {
    let target = credential_target(credential_id)?;
    // SAFETY: `target` is NUL-terminated and valid for the complete call.
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if deleted != 0 {
        return Ok(true);
    }
    // SAFETY: this call immediately follows the failed Win32 operation.
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_FOUND {
        Ok(false)
    } else {
        Err(io::Error::from_raw_os_error(code.cast_signed()))
    }
}

/// Creates a Tokio named-pipe server whose DACL grants access only to the
/// supplied Windows SID and `LocalSystem`.
///
/// # Errors
///
/// Returns an error when the SID is malformed, the security descriptor cannot
/// be constructed, or Windows cannot create the named-pipe server.
pub fn create_current_user_server(
    pipe_name: &str,
    allowed_sid: &str,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    validate_sid(allowed_sid)?;
    let descriptor = SecurityDescriptor::for_current_user(allowed_sid)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SECURITY_ATTRIBUTES size does not fit u32",
            )
        })?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first_instance);
    // SAFETY: `attributes` and the descriptor it points to remain alive for the
    // complete call. Tokio copies the descriptor into the created kernel object
    // and does not retain this pointer.
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            ptr::from_mut(&mut attributes).cast::<c_void>(),
        )
    }
}

fn validate_sid(sid: &str) -> io::Result<()> {
    if sid.len() < 5
        || !sid.starts_with("S-")
        || sid
            .chars()
            .any(|character| !character.is_ascii_digit() && character != 'S' && character != '-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows SID",
        ));
    }
    Ok(())
}

struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn for_current_user(sid: &str) -> io::Result<Self> {
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})");
        let wide = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut raw = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and valid for the duration of the
        // call; `raw` is an out pointer initialized by the Win32 API.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { raw })
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: the descriptor was allocated by the conversion API and
            // ownership remains with this wrapper until this Drop.
            unsafe {
                LocalFree(self.raw.cast());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DirectoryMutationGuard, DirectoryOplockGuard, PinnedDirectory, PinnedFile,
        ProcessTreeGuard, SuspendedJobChild, atomic_replace_file, credential_delete_current_user,
        credential_read_current_user, credential_status_current_user,
        credential_write_current_user, process_image_path, process_is_alive, validate_sid,
        write_new_pinned_file,
    };
    use std::fs;
    use std::io::Read as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    fn managed_powershell(script: &str, cwd: &std::path::Path) -> std::process::Command {
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let mut command = std::process::Command::new(
            std::path::PathBuf::from(system_root)
                .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        );
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .current_dir(cwd)
            .env_clear();
        for name in ["SystemRoot", "WINDIR", "ComSpec"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }

    #[test]
    fn credential_manager_round_trip_is_current_user_scoped() -> std::io::Result<()> {
        struct CredentialCleanup(String);
        impl Drop for CredentialCleanup {
            fn drop(&mut self) {
                let _ = credential_delete_current_user(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let credential_id = format!("tests/round-trip/{}-{nonce}", std::process::id());
        let _cleanup = CredentialCleanup(credential_id.clone());
        let value = format!("synthetic-test-value-{}-{nonce}", std::process::id());
        assert_eq!(credential_read_current_user(&credential_id)?, None);
        credential_write_current_user(&credential_id, value.as_bytes())?;
        let status = credential_status_current_user(&credential_id)?;
        assert!(status.present);
        assert!(status.version.is_some());
        let expected_size = u32::try_from(value.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "test value is too large")
        })?;
        assert_eq!(status.size_bytes, Some(expected_size));
        assert_eq!(
            credential_read_current_user(&credential_id)?.as_deref(),
            Some(value.as_bytes())
        );
        assert!(credential_delete_current_user(&credential_id)?);
        assert_eq!(credential_read_current_user(&credential_id)?, None);
        Ok(())
    }

    struct OwnedTestRoot {
        path: std::path::PathBuf,
    }

    impl OwnedTestRoot {
        fn new(label: &str) -> std::io::Result<Self> {
            static NEXT_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            loop {
                let sequence = NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "{label}-{}-{created_at}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }

    impl std::ops::Deref for OwnedTestRoot {
        type Target = std::path::Path;

        fn deref(&self) -> &Self::Target {
            &self.path
        }
    }

    impl Drop for OwnedTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn sid_validation_rejects_sddl_injection() {
        assert!(validate_sid("S-1-5-21-1234").is_ok());
        assert!(validate_sid("S-1-5-21)(A;;GA;;;WD").is_err());
    }

    #[test]
    fn owned_test_roots_are_unique_and_cleanup_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let first = OwnedTestRoot::new("eliot-owned-test-root")?;
        let first_path = first.path.clone();
        let second = OwnedTestRoot::new("eliot-owned-test-root")?;
        assert_ne!(first_path, second.path);
        drop(first);
        assert!(!first_path.exists());
        Ok(())
    }

    #[test]
    fn atomic_replace_overwrites_existing_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = OwnedTestRoot::new("eliot-atomic-replace")?;
        let source = root.join("source.tmp");
        let destination = root.join("destination.json");
        fs::write(&source, b"new")?;
        fs::write(&destination, b"old")?;
        atomic_replace_file(&source, &destination)?;
        assert_eq!(fs::read(&destination)?, b"new");
        assert!(!source.exists());
        Ok(())
    }

    #[test]
    fn atomic_replace_retries_a_transient_windows_reader_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = OwnedTestRoot::new("eliot-atomic-replace-reader")?;
        let source = root.join("source.tmp");
        let destination = root.join("destination.json");
        fs::write(&source, b"new")?;
        fs::write(&destination, b"old")?;
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&destination)?;
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(reader);
        });
        atomic_replace_file(&source, &destination)?;
        release
            .join()
            .map_err(|_| "reader release thread panicked")?;
        assert_eq!(fs::read(&destination)?, b"new");
        Ok(())
    }

    #[test]
    fn pinned_file_denies_mutation_and_replacement_until_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-pinned-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&root)?;
        let path = root.join("authority.bin");
        let replacement = root.join("replacement.bin");
        fs::write(&path, b"sealed")?;
        fs::write(&replacement, b"attacker")?;
        let mut pinned = PinnedFile::open(&path)?;
        assert_eq!(pinned.read_all()?, b"sealed");
        assert!(fs::write(&path, b"mutated").is_err());
        assert!(fs::rename(&replacement, &path).is_err());
        assert_eq!(pinned.read_all()?, b"sealed");
        drop(pinned);
        fs::write(&path, b"mutated")?;
        assert_eq!(fs::read(&path)?, b"mutated");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn pinned_directory_denies_replacement_but_allows_output_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = std::env::temp_dir().join(format!(
            "eliot-pinned-directory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let root = parent.join("output");
        let renamed = parent.join("replaced");
        fs::create_dir_all(&root)?;
        let pinned = PinnedDirectory::open(&root)?;
        fs::write(root.join("terminal.json"), b"{}")?;
        assert!(fs::rename(&root, &renamed).is_err());
        drop(pinned);
        fs::rename(&root, &renamed)?;
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn directory_oplock_detects_new_bundle_file_injection() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = std::env::temp_dir().join(format!(
            "eliot-pinned-bundle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&root)?;
        fs::write(root.join("sealed.md"), b"sealed")?;
        let guard = DirectoryOplockGuard::acquire(&root)?;
        let injected = root.join("injected.md");
        let (sender, receiver) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let result = fs::write(injected, b"attacker");
            let _ = sender.send(result);
        });
        receiver.recv_timeout(Duration::from_secs(2))??;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !guard.mutation_attempted()? && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(guard.mutation_attempted()?);
        drop(guard);
        writer.join().map_err(|_| "join bundle injection writer")?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn new_output_writer_rejects_precreated_junction_without_touching_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = std::env::temp_dir().join(format!(
            "eliot-output-reparse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let output = parent.join("output");
        let target = parent.join("target");
        let destination = output.join("raw.stdout");
        fs::create_dir_all(&output)?;
        fs::create_dir_all(&target)?;
        fs::write(target.join("sentinel.txt"), b"unchanged")?;
        let status = std::process::Command::new("cmd")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&destination)
            .arg(&target)
            .status()?;
        assert!(status.success(), "create output junction fixture");
        assert!(write_new_pinned_file(&destination, b"attacker-controlled").is_err());
        assert_eq!(fs::read(target.join("sentinel.txt"))?, b"unchanged");
        fs::remove_dir(&destination)?;
        fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn directory_mutation_guard_detects_recursive_write() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = OwnedTestRoot::new("eliot-mutation-watch")?;
        fs::create_dir_all(root.join("nested"))?;
        let guard = DirectoryMutationGuard::watch(&root)?;
        assert!(!guard.mutation_detected()?);
        fs::write(root.join("nested/mutated.txt"), "changed")?;
        assert!(guard.mutation_detected()?);
        drop(guard);
        Ok(())
    }

    #[test]
    fn process_liveness_distinguishes_current_and_exited_processes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(process_is_alive(std::process::id())?);
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()?;
        let child_pid = child.id();
        child.wait()?;
        assert!(!process_is_alive(child_pid)?);
        Ok(())
    }

    #[test]
    fn process_image_is_kernel_resolved_for_current_process()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            process_image_path(std::process::id())?.canonicalize()?,
            std::env::current_exe()?.canonicalize()?
        );
        Ok(())
    }

    #[test]
    fn suspended_job_reports_its_root_process_image() -> Result<(), Box<dyn std::error::Error>> {
        let root = OwnedTestRoot::new("eliot-job-process-attestation")?;
        let command = managed_powershell("Start-Sleep -Seconds 10", &root);
        let expected_image = std::path::PathBuf::from(command.get_program()).canonicalize()?;
        let mut child = SuspendedJobChild::spawn(&command)?;
        let processes = child.observed_processes();
        assert!(processes.iter().any(|process| {
            process.pid == child.id()
                && process
                    .image
                    .canonicalize()
                    .is_ok_and(|image| image == expected_image)
        }));
        child.terminate(37)?;
        let _ = child.wait_timeout(Duration::from_secs(1))?;
        drop(child.take_stdout());
        drop(child.take_stderr());
        Ok(())
    }

    #[test]
    fn suspended_job_retains_short_lived_descendant_handle_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = OwnedTestRoot::new("eliot-job-fast-descendant")?;
        let script = "$info = New-Object System.Diagnostics.ProcessStartInfo; $info.FileName = $env:ComSpec; $info.Arguments = '/D /C ping -n 2 127.0.0.1 >NUL'; $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $process = [System.Diagnostics.Process]::Start($info); $process.WaitForExit(); Start-Sleep -Milliseconds 1500";
        let mut child = SuspendedJobChild::spawn(&managed_powershell(script, &root))?;
        std::thread::sleep(Duration::from_millis(200));
        let live_processes = child.job_processes()?;
        let descendant = live_processes
            .iter()
            .find(|process| process.pid != child.id())
            .cloned()
            .ok_or_else(|| format!("no descendant in live Job identities: {live_processes:?}"))?;
        child.terminate(37)?;
        let _ = child.wait_timeout(Duration::from_secs(1))?;
        std::thread::sleep(Duration::from_millis(100));
        let processes = child.observed_processes();
        assert!(processes.contains(&descendant));
        drop(child.take_stdout());
        drop(child.take_stderr());
        Ok(())
    }

    #[test]
    fn process_tree_guard_terminates_attached_child() -> Result<(), Box<dyn std::error::Error>> {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping", "-n", "30", "127.0.0.1", ">NUL"])
            .spawn()?;
        let child_pid = child.id();
        let guard = ProcessTreeGuard::attach(child_pid)?;
        guard.terminate(37)?;
        let status = child.wait()?;
        assert!(!status.success());
        assert!(!process_is_alive(child_pid)?);
        Ok(())
    }

    #[test]
    fn suspended_job_contains_descendant_before_any_code_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = OwnedTestRoot::new("eliot-suspended-job")?;
        let sentinel = root.join("escaped.txt");
        fs::write(
            root.join("child.cmd"),
            "@echo off\r\n\"%SystemRoot%\\System32\\ping.exe\" -n 3 127.0.0.1 >NUL\r\necho escaped>escaped.txt\r\n",
        )?;
        let script = "$info = New-Object System.Diagnostics.ProcessStartInfo; $info.FileName = $env:ComSpec; $info.Arguments = '/D /C child.cmd'; $info.UseShellExecute = $false; $info.CreateNoWindow = $true; [System.Diagnostics.Process]::Start($info) | Out-Null; Write-Output root";
        let mut child = SuspendedJobChild::spawn(&managed_powershell(script, &root))?;
        std::thread::sleep(Duration::from_millis(250));
        child.terminate(37)?;
        let _ = child.wait_timeout(Duration::from_secs(1))?;
        std::thread::sleep(Duration::from_secs(3));
        assert!(
            !sentinel.exists(),
            "descendant escaped the pre-assigned Job Object"
        );
        drop(child.take_stdout());
        drop(child.take_stderr());
        Ok(())
    }

    #[test]
    fn terminating_job_closes_descendant_inherited_pipes() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = OwnedTestRoot::new("eliot-job-pipes")?;
        fs::write(
            root.join("child.cmd"),
            "@echo off\r\n\"%SystemRoot%\\System32\\ping.exe\" -n 30 127.0.0.1 >NUL\r\n",
        )?;
        let script = "$info = New-Object System.Diagnostics.ProcessStartInfo; $info.FileName = $env:ComSpec; $info.Arguments = '/D /C child.cmd'; $info.UseShellExecute = $false; $info.CreateNoWindow = $true; [System.Diagnostics.Process]::Start($info) | Out-Null; Write-Output root";
        let mut child = SuspendedJobChild::spawn(&managed_powershell(script, &root))?;
        let mut stdout = child.take_stdout().ok_or("stdout")?;
        let mut stderr = child.take_stderr().ok_or("stderr")?;
        assert_eq!(child.wait_timeout(Duration::from_secs(5))?, Some(0));
        let started = Instant::now();
        child.terminate(37)?;
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        stdout.read_to_end(&mut stdout_bytes)?;
        stderr.read_to_end(&mut stderr_bytes)?;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(String::from_utf8(stdout_bytes)?.contains("root"));
        Ok(())
    }
}
