//! Shared file, process, and token identity observation primitives.
//!
//! Architecture (verified):
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A2.3`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A12.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A12.3`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A13.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-AUTH-01`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-SEC-01`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-SEC-02`
//!
//! Implementation (verified):
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I1.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.23`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I7.3`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I7.14`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I15.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I15.3`
//!
//! This module owns shared file, process, and token identity observation
//! primitives only. It forbids `NamedPipe` admission, job or process lifecycle,
//! protected-path, secret, service-control, and canonical semantic authority,
//! minting, retry, or default.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::WindowsAdapterError;
use crate::last_windows_adapter_error;
use crate::sid_to_string;

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
}

impl ProcessIdentity {
    pub(crate) fn is_usable(&self) -> bool {
        self.process_id != 0
            && self.start_time_100ns != 0
            && valid_process_image_path(&self.image_path)
    }

    #[must_use]
    pub fn stable_key(&self) -> String {
        format!(
            "windows-pid:{}:start:{}:image:{}",
            self.process_id, self.start_time_100ns, self.image_path
        )
    }
}

#[cfg(windows)]
pub(crate) fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "identity target is not a regular file",
        ));
    }
    file_identity_from_handle(&file)
}

#[cfg(not(windows))]
pub(crate) fn file_identity(_path: &Path) -> std::io::Result<FileIdentity> {
    Err(std::io::Error::other("Windows identity unavailable"))
}

#[cfg(windows)]
pub(crate) fn file_identity_from_handle(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
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

pub fn is_process_builtin_administrator() -> Result<bool, WindowsAdapterError> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        process_token_is_builtin_administrator(unsafe { GetCurrentProcess() })
    }
    #[cfg(not(windows))]
    {
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(windows)]
pub(crate) fn process_token_identity(
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
pub(crate) fn process_token_is_builtin_administrator(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_is_builtin_administrator(token);
    unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
pub(crate) fn thread_token_is_builtin_administrator() -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_is_builtin_administrator(token);
    unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
pub(crate) fn token_is_builtin_administrator(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetTokenInformation, SECURITY_MAX_SID_SIZE,
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TokenGroups, WinBuiltinAdministratorsSid,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
    let mut sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_bytes = u32::try_from(sid.len()).map_err(|_| WindowsAdapterError::Failed)?;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let mut required = 0_u32;
    let _ = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
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
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let group_count =
        usize::try_from(groups.GroupCount).map_err(|_| WindowsAdapterError::Failed)?;
    let groups_offset = std::mem::size_of::<TOKEN_GROUPS>()
        .checked_sub(std::mem::size_of::<SID_AND_ATTRIBUTES>())
        .ok_or(WindowsAdapterError::Failed)?;
    let max_group_count = required_bytes
        .checked_sub(groups_offset)
        .ok_or(WindowsAdapterError::Failed)?
        / std::mem::size_of::<SID_AND_ATTRIBUTES>();
    if group_count > max_group_count {
        return Err(WindowsAdapterError::Failed);
    }
    let groups = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), group_count) };
    Ok(groups.iter().any(|group| {
        group.Attributes & (SE_GROUP_ENABLED as u32) != 0
            && unsafe { EqualSid(group.Sid, sid.as_ptr().cast_mut().cast()) != 0 }
    }))
}

#[cfg(windows)]
pub(crate) fn token_identity(
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

pub(crate) fn same_process_identity(
    observed: &ProcessIdentity,
    approved: &ProcessIdentity,
) -> bool {
    if observed.process_id != approved.process_id
        || observed.start_time_100ns != approved.start_time_100ns
        || !valid_process_image_path(&observed.image_path)
        || !valid_process_image_path(&approved.image_path)
    {
        return false;
    }
    #[cfg(windows)]
    {
        same_windows_path(&observed.image_path, &approved.image_path)
    }
    #[cfg(not(windows))]
    {
        observed.image_path == approved.image_path
    }
}

pub(crate) fn same_process_image_path(observed: &str, approved: &str) -> bool {
    if !valid_process_image_path(observed) || !valid_process_image_path(approved) {
        return false;
    }
    #[cfg(windows)]
    {
        same_windows_path(observed, approved)
    }
    #[cfg(not(windows))]
    {
        observed == approved
    }
}

#[cfg(windows)]
pub(crate) fn same_windows_path(left: &str, right: &str) -> bool {
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
pub(crate) fn valid_process_image_path(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_control) {
        return false;
    }
    let normalized = value.replace('/', "\\");
    let uppercase = normalized.to_uppercase();
    if uppercase.starts_with(r"\\.\")
        || uppercase.starts_with(r"\DEVICE\")
        || uppercase.starts_with(r"\\?\GLOBALROOT\")
    {
        return false;
    }
    let bytes = normalized.as_bytes();
    let drive_absolute =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc_absolute = normalized.starts_with(r"\\");
    drive_absolute || unc_absolute
}

#[cfg(not(windows))]
pub(crate) fn valid_process_image_path(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

#[cfg(windows)]
pub(crate) fn inspect_process_identity(process_id: u32) -> std::io::Result<ProcessIdentity> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let result = inspect_process_handle(process_id, process);
    unsafe { CloseHandle(process) };
    result
}

#[cfg(not(windows))]
pub(crate) fn inspect_process_identity(_process_id: u32) -> std::io::Result<ProcessIdentity> {
    Err(std::io::Error::other(
        "Windows process identity unavailable",
    ))
}

#[cfg(windows)]
pub(crate) fn inspect_process_handle(
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
