//! Named-pipe peer authentication and validation mechanics.
//!
//! Architecture anchors: `A2.3`, `A12.2`,
//! A12.3, ARCH-AUTH-01, ARCH-SEC-01, and ARCH-SEC-02. This private cell owns
//! only physical peer identity/authentication evidence; it does not own
//! semantic readiness, session lifecycle, canonical transitions, or authority.
//!
//! Implementation anchors: `I2.1`, `I2.23`,
//! I7.5, I7.14, and I15.2. Pipe ACLs, live process/token observations,
//! impersonation boundaries, and bounded peer-set validation remain here;
//! peer models/process observation and role selection remain in their existing
//! sibling modules.
//!
//! Normative sources: `docs/ARCHITECTURE_CONTRACT.md`,
//! `docs/architecture/ELIOT_ARCHITECTURE.md`,
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` (compatibility entry points;
//! the governing shards are named per anchor above).

use crate::named_pipe_process_admission::{NamedPipePeerExpectation, NamedPipePeerJobBinding};
use crate::{ProcessIdentity, WindowsAdapterError, same_process_identity};

#[cfg(windows)]
use crate::named_pipe_process_admission::{NamedPipePeerEvidence, observe_named_pipe_peer_process};
#[cfg(windows)]
use crate::platform_security::{NamedPipePeerSelection, NamedPipePeerSet};
#[cfg(windows)]
use crate::{
    NamedPipeAuthDiscriminator, file_identity, inspect_process_handle, last_windows_adapter_error,
    process_token_identity, process_token_is_builtin_administrator, sid_to_string,
    thread_token_is_builtin_administrator, windows_adapter_from_io,
};
#[cfg(windows)]
use std::path::Path;

/// Rechecks process and Job bindings before generic peer authentication uses
/// them. The Job query is implemented in this cell so its opened handle has a
/// single owner on every return path.
pub(crate) fn admit_named_pipe_peer_process(
    observed: &ProcessIdentity,
    expectation: &NamedPipePeerExpectation,
) -> Result<(), WindowsAdapterError> {
    let Some(approved_job) = expectation.approved_process_job_binding() else {
        return crate::named_pipe_process_admission::admit_named_pipe_peer_process(
            observed,
            expectation,
        );
    };
    if let Some(approved) = expectation.approved_process_binding()
        && !same_process_identity(observed, approved.identity())
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if !same_process_identity(observed, approved_job.process_binding().identity()) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let current =
        observe_named_pipe_peer_process_in_job(approved_job.job_name(), observed.process_id)?;
    if !same_process_identity(
        current.process_binding().identity(),
        approved_job.process_binding().identity(),
    ) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn valid_named_job_identity(value: &str) -> bool {
    let length = value.encode_utf16().count();
    length != 0 && length <= 240 && !value.chars().any(char::is_control)
}

/// Observes one process and proves that the same PID is currently a member of
/// the named owner Job. The returned value is sealed evidence, not a caller
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
    let raw_handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY_ACCESS, 0, wide.as_ptr()) };
    if raw_handle.is_null() {
        return Err(windows_adapter_from_io(&std::io::Error::last_os_error()));
    }
    let handle = crate::OwnedKernelHandle::new(raw_handle)?;
    // `handle` owns the successful OpenJobObjectW result. A `?` from
    // `job_process_ids` drops it on the early error path; the explicit drop
    // below releases it before membership/process validation continues.
    let member = crate::job_process_ids(handle.0)
        .map_err(|error| windows_adapter_from_io(&error))?
        .into_iter()
        .any(|member| member == process_id);
    drop(handle);
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

/// Authenticates the server bound to a connected client-end named-pipe handle.
///
/// # Errors
/// Returns a typed adapter error when DACL, process identity, SID or session
/// proof fails.
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
    validate_pipe_dacl(pipe_handle, expectation.expected_sid())?;
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
        admit_named_pipe_peer_process(&identity, expectation)?;
        let (sid, session_id) = process_token_identity(process)?;
        if sid != expectation.expected_sid() || session_id != expectation.expected_session_id() {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let executable_file = file_identity(Path::new(&identity.image_path)).ok();
        Ok(NamedPipePeerEvidence {
            process: identity,
            sid,
            session_id,
            executable_file,
            job_name: expectation
                .approved_process_job_binding()
                .map(|binding| binding.job_name().to_owned()),
            builtin_administrators: false,
            interactive_session: false,
        })
    })();
    // SAFETY: `process` is the live handle returned by OpenProcess and is
    // closed exactly once after every result from the observation closure.
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
/// exact process identity, SID/session expectation or reversion cannot be
/// established.
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
    validate_pipe_dacl(pipe_handle, expectation.expected_sid())?;
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
        admit_named_pipe_peer_process(&identity, expectation)?;
        let process_token = process_token_identity(process)?;
        let principal_matches = match expectation.auth_discriminator() {
            NamedPipeAuthDiscriminator::Ordinary => {
                // Ordinary peers are admitted by the identity observed from
                // the retained process handle. Do not compare that primary
                // token with an impersonation token: they are distinct token
                // objects even when they represent the same client.
                process_token.0 == expectation.expected_sid()
                    && process_token.1 == expectation.expected_session_id()
            }
            NamedPipeAuthDiscriminator::BuiltinAdministrators => {
                let process_is_admin = process_token_is_builtin_administrator(process)?;
                let impersonation = ImpersonationGuard::begin(pipe_handle)?;
                let thread_is_admin = thread_token_is_builtin_administrator()?;
                impersonation.revert()?;
                // The process token and the impersonated token are checked
                // independently through TokenGroups. Never pass a primary
                // process token to CheckTokenMembership.
                process_is_admin && thread_is_admin && process_token.0 != "S-1-5-18"
            }
        };
        if !principal_matches {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let executable_file = file_identity(Path::new(&identity.image_path)).ok();
        Ok(NamedPipePeerEvidence {
            process: identity,
            sid: process_token.0,
            session_id: process_token.1,
            executable_file,
            job_name: expectation
                .approved_process_job_binding()
                .map(|binding| binding.job_name().to_owned()),
            builtin_administrators: matches!(
                expectation.auth_discriminator(),
                NamedPipeAuthDiscriminator::BuiltinAdministrators
            ),
            interactive_session: false,
        })
    })();
    // SAFETY: `process` is the live handle returned by OpenProcess and is
    // closed exactly once after every result from the observation closure.
    unsafe { CloseHandle(process) };
    observed
}

/// Authenticates a connected server-end pipe against a sealed peer set.
///
/// The DACL is checked as a bounded allow-list, then the server PID is read
/// from the live pipe handle and all identity fields are captured before the
/// immutable set performs exact selection. No SID or username supplied by a
/// caller is used as a selector.
#[cfg(windows)]
pub fn authenticate_named_pipe_server_with_peer_set(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    peers: &NamedPipePeerSet,
) -> Result<(NamedPipePeerEvidence, NamedPipePeerSelection), WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    validate_pipe_dacl_for_peer_set(pipe_handle, peers)?;
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
        let builtin_administrators = if peers.requires_builtin_administrators() {
            process_token_is_builtin_administrator(process)? && sid != "S-1-5-18"
        } else {
            false
        };
        let executable_file = file_identity(Path::new(&identity.image_path)).ok();
        let job_name = observed_peer_job_name(process_id, peers)?;
        let mut evidence = NamedPipePeerEvidence {
            process: identity,
            sid,
            session_id,
            executable_file,
            job_name,
            builtin_administrators,
            interactive_session: false,
        };
        if session_id != 0
            && peers
                .entries()
                .iter()
                .any(|entry| entry.expectation().matches_dynamic_observation(&evidence))
        {
            evidence.interactive_session = active_interactive_session(session_id)?;
        }
        let selection = peers.select(&evidence)?;
        Ok((evidence, selection))
    })();
    // SAFETY: `process` is the live handle returned by OpenProcess and is
    // closed exactly once after every result from the observation closure.
    unsafe { CloseHandle(process) };
    observed
}

/// Authenticates a connected client-end pipe against a sealed peer set.
///
/// Built-in Administrators membership is accepted only when both the retained
/// process token and a short-lived impersonated pipe token prove the group.
/// The latter is reverted before this function returns.
#[cfg(windows)]
pub fn authenticate_named_pipe_client_with_peer_set(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    peers: &NamedPipePeerSet,
) -> Result<(NamedPipePeerEvidence, NamedPipePeerSelection), WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    validate_pipe_dacl_for_peer_set(pipe_handle, peers)?;
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
        let (sid, session_id) = process_token_identity(process)?;
        let builtin_administrators = if peers.requires_builtin_administrators() {
            let process_is_admin = process_token_is_builtin_administrator(process)?;
            let impersonation = ImpersonationGuard::begin(pipe_handle)?;
            let thread_is_admin = thread_token_is_builtin_administrator()?;
            impersonation.revert()?;
            process_is_admin && thread_is_admin && sid != "S-1-5-18"
        } else {
            false
        };
        let executable_file = file_identity(Path::new(&identity.image_path)).ok();
        let job_name = observed_peer_job_name(process_id, peers)?;
        let mut evidence = NamedPipePeerEvidence {
            process: identity,
            sid,
            session_id,
            executable_file,
            job_name,
            builtin_administrators,
            interactive_session: false,
        };
        if session_id != 0
            && peers
                .entries()
                .iter()
                .any(|entry| entry.expectation().matches_dynamic_observation(&evidence))
        {
            evidence.interactive_session = active_interactive_session(session_id)?;
        }
        let selection = peers.select(&evidence)?;
        Ok((evidence, selection))
    })();
    // SAFETY: `process` is the live handle returned by OpenProcess and is
    // closed exactly once after every result from the observation closure.
    unsafe { CloseHandle(process) };
    observed
}

#[cfg(windows)]
fn observed_peer_job_name(
    process_id: u32,
    peers: &NamedPipePeerSet,
) -> Result<Option<String>, WindowsAdapterError> {
    let mut observed = None::<String>;
    for entry in peers.entries() {
        let Some(binding) = entry.expectation().approved_process_job_binding() else {
            continue;
        };
        if observe_named_pipe_peer_process_in_job(binding.job_name(), process_id).is_ok() {
            if observed
                .as_deref()
                .is_some_and(|existing| existing != binding.job_name())
            {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            observed = Some(binding.job_name().to_owned());
        }
    }
    Ok(observed)
}

#[cfg(windows)]
fn active_interactive_session(session_id: u32) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSConnectState, WTSFreeMemory,
        WTSQuerySessionInformationW,
    };
    if session_id == 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut state_ptr = std::ptr::null_mut();
    let mut state_bytes = 0_u32;
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSConnectState,
            &raw mut state_ptr,
            &raw mut state_bytes,
        )
    } != 0;
    if !ok || state_ptr.is_null() || state_bytes < 4 {
        if !state_ptr.is_null() {
            unsafe { WTSFreeMemory(state_ptr.cast()) };
        }
        return Err(last_windows_adapter_error());
    }
    let state = unsafe { std::ptr::read_unaligned(state_ptr.cast::<i32>()) };
    unsafe { WTSFreeMemory(state_ptr.cast()) };
    Ok(state == WTSActive)
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
            } else if !pipe_dacl_principal_allowed(expected_sid, &text) {
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
fn validate_pipe_dacl_for_peer_set(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    peers: &NamedPipePeerSet,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, PSECURITY_DESCRIPTOR,
    };

    let mut expected = vec!["S-1-5-18"];
    for sid in peers.expected_sids() {
        if !expected.contains(&sid) {
            expected.push(sid);
        }
    }
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
        if ace_count == 0 || ace_count > 32 {
            return Err(WindowsAdapterError::AclMismatch);
        }
        let mut observed_sids = Vec::with_capacity(expected.len());
        if usize::from(ace_count) != expected.len() {
            return Err(WindowsAdapterError::AclMismatch);
        }
        for index in 0..u32::from(ace_count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
                return Err(WindowsAdapterError::AclMismatch);
            }
            let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            if header.AceType != 0 {
                return Err(WindowsAdapterError::AclMismatch);
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            validate_peer_set_ace_fields(header.AceType, header.AceFlags, allowed.Mask)?;
            let sid = (&raw const allowed.SidStart).cast_mut().cast();
            observed_sids.push(sid_to_string(sid)?);
        }
        validate_peer_set_sids(&expected, &observed_sids)
    })();
    unsafe { LocalFree(descriptor.cast()) };
    result
}

pub(crate) const PEER_SET_GENERIC_ALL_MAPPED: u32 = 0x001F_01FF;

pub(crate) fn validate_peer_set_ace_fields(
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
) -> Result<(), WindowsAdapterError> {
    if ace_type == 0 && ace_flags == 0 && mask == PEER_SET_GENERIC_ALL_MAPPED {
        Ok(())
    } else {
        Err(WindowsAdapterError::AclMismatch)
    }
}

fn validate_peer_set_sid(expected: &[&str], observed: &str) -> Result<usize, WindowsAdapterError> {
    if let Some(index) = expected.iter().position(|value| *value == observed) {
        Ok(index)
    } else {
        Err(WindowsAdapterError::AclMismatch)
    }
}

pub(crate) fn validate_peer_set_sids(
    expected: &[&str],
    observed: &[String],
) -> Result<(), WindowsAdapterError> {
    if observed.len() != expected.len() {
        return Err(WindowsAdapterError::AclMismatch);
    }
    let mut present = vec![false; expected.len()];
    for sid in observed {
        let index = validate_peer_set_sid(expected, sid)?;
        if present[index] {
            return Err(WindowsAdapterError::AclMismatch);
        }
        present[index] = true;
    }
    if present.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(WindowsAdapterError::AclMismatch)
    }
}

pub(crate) fn pipe_dacl_principal_allowed(expected_sid: &str, observed_sid: &str) -> bool {
    observed_sid == "S-1-5-18"
        || observed_sid == "S-1-5-32-544"
        || (matches!(expected_sid, "S-1-5-19" | "S-1-5-32-544") && observed_sid == "S-1-5-19")
}
