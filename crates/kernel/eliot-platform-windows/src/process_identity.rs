//! Shared file, process, and token identity observation primitives.
//!
//! Architecture (verified):
//! - `A2.3` (`docs/architecture/A02-03-modular-architecture.md`)
//! - `A12.2` (`docs/architecture/A12-02-principal-session-and-visibility.md`)
//! - `A12.3` (`docs/architecture/A12-03-one-governed-write-path.md`)
//! - `A13.2` (`docs/architecture/A13-02-kernel-and-failure-domains.md`)
//! - `ARCH-AUTH-01`, `ARCH-SEC-01`, `ARCH-SEC-02`
//!   (`docs/architecture/A16-01-decision-anchors.md`)
//!
//! Implementation (verified):
//! - `I1.2` (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`)
//! - `I2.1` (`docs/architecture/I02-01-primary-decision-crate-rich-process-sparse-owner-sparse.md`)
//! - `I2.23` (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`)
//! - `I7.3` (`docs/architecture/I07-03-handshake.md`)
//! - `I7.14` (`docs/architecture/I07-14-session-lifecycle.md`)
//! - `I15.2` (`docs/architecture/I15-02-principal-and-session-binding.md`)
//! - `I15.3` (`docs/architecture/I15-03-least-privilege-processes.md`)
//!
//! Normative sources: `docs/ARCHITECTURE_CONTRACT.md` and the canonical
//! sharded fragments named per anchor above.
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
use crate::process_job::ExecutionIdentityMode;
use crate::sid_to_string;

/// Declared name of the `I1.6` `system_service` execution identity.
///
/// `I1.6` requires that "`system_service` uses a dedicated low-privilege
/// service identity". The name is the existing installation-profile vocabulary
/// (`InstallationProfile::SystemService`), and this constant is the one place
/// in this crate that spells it, so a launch declaration and this selector
/// cannot drift into two different literals.
pub const SYSTEM_SERVICE_EXECUTION_IDENTITY_NAME: &str = "system_service";

/// Declared name of the `I1.6` `user_mode` execution identity.
///
/// `I1.6` requires that "`user_mode` runs under the current user without
/// pretending to be an SCM service". The name is the existing
/// installation-profile vocabulary (`InstallationProfile::UserMode`).
pub const USER_MODE_EXECUTION_IDENTITY_NAME: &str = "user_mode";

/// Selects the [`ExecutionIdentityMode`] one declared identity name names.
///
/// This is the admitted, deterministic selection `W4` asks for. It is a total
/// function over the two names `I1.6` defines and nothing else: a launch
/// declares one of them, this maps it to exactly one mode, and the mode is the
/// value the platform launch path then resolves to a concrete token and
/// re-checks against the still-suspended child. It is deliberately not a
/// "best effort" mapping — an unrecognized name is refused rather than
/// defaulted, because defaulting here would let a launch quietly run under an
/// identity it never declared, which is the SCM pretence `I1.6` forbids.
///
/// `portable_dev` is refused for the same reason and is named here only to be
/// refused: it is an installation profile, not one of the two execution
/// identities `I1.6` defines, so there is no `ExecutionIdentityMode` it can
/// honestly select.
///
/// # Errors
/// Returns `InvalidInput` for any name that is not exactly one of the two
/// declared execution identities. It never falls back to a default mode.
pub fn select_execution_identity_mode(
    name: &str,
) -> Result<ExecutionIdentityMode, WindowsAdapterError> {
    match name {
        SYSTEM_SERVICE_EXECUTION_IDENTITY_NAME => Ok(ExecutionIdentityMode::SystemService),
        USER_MODE_EXECUTION_IDENTITY_NAME => Ok(ExecutionIdentityMode::UserMode),
        _ => Err(WindowsAdapterError::InvalidInput),
    }
}

/// Returns the exact declared name of the identity this mode selects.
///
/// This is the observable, comparable half of the selection: the mode chosen
/// by [`select_execution_identity_mode`] renders back to the one name `I1.6`
/// spells, so the identity a launch used is readable and comparable rather
/// than a branch that happened to be taken. It is the exact inverse of the
/// selection over the two declared names.
#[must_use]
pub fn execution_identity_mode_name(mode: ExecutionIdentityMode) -> &'static str {
    match mode {
        ExecutionIdentityMode::SystemService => SYSTEM_SERVICE_EXECUTION_IDENTITY_NAME,
        ExecutionIdentityMode::UserMode => USER_MODE_EXECUTION_IDENTITY_NAME,
    }
}

/// The identity one declared `I1.6` name actually resolves to on this machine.
///
/// `I1.6` binds two different principals to the two names, and a selection that
/// did not prove it had picked a *different* one for each would be two branches
/// that happen to both reach the caller's own token. This binds the name to the
/// account SID that identity is required to run under, so the two names are
/// comparable and are observably distinct: `system_service` is the dedicated
/// low-privilege service account, and `user_mode` is whatever the current
/// interactive user is — which is exactly the distinction `I1.6` draws when it
/// says a `user_mode` launch must run "under the current user without pretending
/// to be an SCM service".
///
/// This is a pure read of the two principals; it opens no token and creates
/// nothing, so it is available on every target and safe to call from admission.
/// The launch itself opens the token (`open_dedicated_low_privilege_service_token`
/// for `system_service`) and re-checks the launched child against it before
/// resume; this value is what that check is compared against.
///
/// # Errors
/// Returns `IdentityMismatch` when `user_mode` is declared from one of the
/// built-in service accounts. There is no current *user* there, and returning
/// the service SID as if it were one is precisely the SCM pretence `I1.6`
/// forbids, so the launch is refused rather than silently run as the service.
/// Returns a typed adapter error when a well-known SID cannot be read.
#[cfg(windows)]
pub fn selected_execution_identity_sid(name: &str) -> Result<String, WindowsAdapterError> {
    match select_execution_identity_mode(name)? {
        // The dedicated low-privilege service identity, named by its own
        // well-known SID rather than by account text.
        ExecutionIdentityMode::SystemService => dedicated_low_privilege_service_sid(),
        // The current user, read from this process's own token. The SID is
        // whatever the launcher actually is, not an assumed one.
        ExecutionIdentityMode::UserMode => {
            // `current_process_sid` is the crate's existing safe read of this
            // process's own token SID, so this selector introduces no new
            // handle and no new unsafe site.
            let sid =
                crate::current_process_sid().map_err(|_| WindowsAdapterError::IdentityMismatch)?;
            if is_well_known_service_account_sid(&sid) {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            Ok(sid)
        }
    }
}

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

/// Returns the stable identity of one existing directory without following
/// a reparse point.
///
/// The directory opens with backup semantics for identity reads only; the
/// returned identity belongs to the opened handle, never to a pathname
/// metadata query. Handles are never retained: callers that need a pinned
/// protected-path contour use the protected-path owner, not this observer.
///
/// # Errors
///
/// Returns an error when the path is relative, missing, not a plain
/// directory, a reparse point, or its stable identity cannot be read — and
/// on non-Windows targets, where directory identity is unavailable.
#[cfg(windows)]
pub fn directory_identity_for_path(path: &Path) -> std::io::Result<FileIdentity> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    if !path.is_absolute() {
        return Err(std::io::Error::other(
            "directory identity requires an absolute path",
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "identity target is not a plain directory",
        ));
    }
    file_identity_from_handle(&file)
}

#[cfg(not(windows))]
pub fn directory_identity_for_path(_path: &Path) -> std::io::Result<FileIdentity> {
    Err(std::io::Error::other(
        "Windows directory identity unavailable",
    ))
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

/// Token of the dedicated low-privilege service identity `I1.6` requires for
/// `system_service`.
///
/// `I1.6` says `system_service` "uses a dedicated low-privilege service
/// identity". Both adjectives are load-bearing and both rule out
/// `LocalSystem` (`S-1-5-18`), which is the identity most "service identity"
/// code reaches for and which is the opposite of low-privilege: it is a
/// machine-administrator principal whose token carries the machine's full
/// authority, so a child launched under it inherits that authority regardless
/// of the Job Object containment applied around it. The well-known Local Service
/// account is the dedicated, named, restricted service principal Windows
/// reserves for exactly this role: it exists only to run a service, it is not an
/// interactive user, and its token carries none of the user's credentials.
///
/// The token is obtained by a service-type logon of that account and is then
/// re-read through [`token_identity`] and compared against the `S-1-5-19`
/// well-known SID built by the same `CreateWellKnownSid` mechanism this module
/// already uses in [`token_is_builtin_administrator`]. A token that is not the
/// declared account's is discarded rather than returned, so this function can
/// only ever hand back the identity it documents.
///
/// `NetworkService` is deliberately not the choice: `I1.6` binds a
/// `system_service` contour that does not need outbound network identity, and the
/// lower-privilege principal is the defensible reading of the same adjective
/// pair.
///
/// # Errors
/// Returns `Unavailable` when the machine cannot produce this dedicated
/// service token — the caller must treat that launch as unavailable and must
/// never fall back to the current process token, because running under the
/// caller is exactly the pretending `I1.6` forbids. Returns `IdentityMismatch`
/// when Windows hands back a token that is not the declared account's.
#[cfg(windows)]
pub(crate) fn open_dedicated_low_privilege_service_token()
-> Result<crate::OwnedProcessHandle, WindowsAdapterError> {
    use crate::OwnedProcessHandle;
    use crate::nul_terminated_wide;
    use crate::windows_adapter_from_io;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
        SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TokenPrimary,
    };

    let account = nul_terminated_wide(std::ffi::OsStr::new(LOCAL_SERVICE_ACCOUNT_NAME))
        .map_err(|error| windows_adapter_from_io(&error))?;
    let domain = nul_terminated_wide(std::ffi::OsStr::new("."))
        .map_err(|error| windows_adapter_from_io(&error))?;
    let mut source: HANDLE = std::ptr::null_mut();
    // SAFETY: `account` and `domain` are live NUL-terminated wide strings and
    // `source` is a valid output pointer. `LOGON32_LOGON_SERVICE` names the
    // machine service-account logon, which never acquires an interactive user's
    // credentials, and a null password selects this account's machine-managed
    // credential.
    if unsafe {
        LogonUserW(
            account.as_ptr(),
            domain.as_ptr(),
            std::ptr::null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &raw mut source,
        )
    } == 0
    {
        return Err(WindowsAdapterError::Unavailable);
    }
    let mut primary: HANDLE = std::ptr::null_mut();
    // SAFETY: `source` is a live token handle just returned by `LogonUserW`,
    // and `primary` is a valid output pointer. `TokenPrimary` is required by
    // `CreateProcessAsUserW`, which cannot create from an impersonation token.
    let duplicated = unsafe {
        DuplicateTokenEx(
            source,
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary,
        )
    };
    // SAFETY: `source` is a live owned handle that this scope no longer needs.
    unsafe { CloseHandle(source) };
    if duplicated == 0 {
        return Err(WindowsAdapterError::Unavailable);
    }
    let Ok(token) = OwnedProcessHandle::new(primary) else {
        // SAFETY: `primary` is a live owned handle that `OwnedProcessHandle`
        // just refused to wrap, so it has no other owner.
        unsafe { CloseHandle(primary) };
        return Err(WindowsAdapterError::Unavailable);
    };

    if token_identity(token.0)?.0 != dedicated_low_privilege_service_sid()? {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(token)
}

/// Textual SID of the dedicated low-privilege service account this module
/// selects.
///
/// `open_dedicated_low_privilege_service_token` uses this to reject a token that
/// is not the declared account's before it hands the token to any launcher.
///
/// # Errors
/// Returns a typed adapter error when the well-known SID cannot be built or
/// stringified.
#[cfg(windows)]
fn dedicated_low_privilege_service_sid() -> Result<String, WindowsAdapterError> {
    well_known_sid_text(windows_sys::Win32::Security::WinLocalServiceSid)
}

/// Reports whether `sid` is one of Windows' built-in service accounts.
///
/// `I1.6` requires `user_mode` to run "under the current user without pretending
/// to be an SCM service". A launcher that is itself one of these accounts has no
/// current *user* to run under: a child it creates inherits a machine service
/// token, so declaring `user_mode` there would be precisely the pretending the
/// clause forbids. The caller refuses instead.
#[cfg(windows)]
pub(crate) fn is_well_known_service_account_sid(sid: &str) -> bool {
    [
        windows_sys::Win32::Security::WinLocalSystemSid,
        windows_sys::Win32::Security::WinLocalServiceSid,
        windows_sys::Win32::Security::WinNetworkServiceSid,
    ]
    .into_iter()
    .any(|kind| well_known_sid_text(kind).is_ok_and(|text| text == sid))
}

/// Builds one well-known SID and renders it as text.
#[cfg(windows)]
fn well_known_sid_text(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> Result<String, WindowsAdapterError> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};
    let mut sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_bytes = u32::try_from(sid.len()).map_err(|_| WindowsAdapterError::Failed)?;
    // SAFETY: `sid` is a live `SECURITY_MAX_SID_SIZE` buffer and `sid_bytes`
    // carries its exact length.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    // SAFETY: `sid` holds exactly the valid SID bytes `CreateWellKnownSid`
    // just wrote.
    sid_to_string(sid.as_ptr().cast_mut().cast())
}

/// Account name of the dedicated low-privilege service identity.
#[cfg(windows)]
const LOCAL_SERVICE_ACCOUNT_NAME: &str = "LocalService";

/// Reads back the user SID and session ID of the token one live process runs
/// under, so a launch can prove which identity it actually created rather than
/// asserting one.
///
/// # Errors
/// Returns a typed adapter error when the process token cannot be opened or
/// queried. `OpenProcessToken` needs `PROCESS_QUERY_LIMITED_INFORMATION` on
/// the process, which is why every caller passes a handle it already owns.
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
