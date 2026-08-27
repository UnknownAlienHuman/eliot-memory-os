//! Kernel front-door server proof and authentication.
//!
//! Architecture anchors (eliot-architecture-docs-fa941135): A12.2 and A12.3,
//! with ARCH-AUTH-01, ARCH-SEC-01, and ARCH-SEC-02. This module owns only the
//! OS-observed front-door proof and fail-closed authentication mechanics; it
//! does not create semantic, Store, Governor, or transition authority.
//!
//! Implementation anchors (eliot-architecture-docs-fa941135): I2.2, I2.23,
//! I7.5, and I7.14. The proof binds the live process, executable object,
//! artifact digest, and narrow front-door DACL observation to the connected
//! pipe while preserving the existing cfg and unknown/failure behavior.
//!
//! Named-pipe listener/server creation, generic DACL/ACE builders, expectation
//! policy, process admission, generic process identity, handshake/session
//! orchestration, and tests remain owned by existing root or sibling modules.
//! This module observes and proves transport identity; it does not issue a
//! semantic result or Store/Governor authority.

use crate::{
    KernelFrontDoorAclMode, KernelFrontDoorServerExpectation, PEER_SET_GENERIC_ALL_MAPPED,
    WindowsAdapterError, valid_sid_text,
};

#[cfg(windows)]
use crate::{
    FileIdentity, NamedPipePeerEvidence, NamedPipePeerProcessBinding, ProcessIdentity,
    final_windows_path_from_handle, inspect_process_handle, last_windows_adapter_error,
    observe_named_pipe_peer_process_in_job, process_token_identity, same_process_identity,
    same_process_image_path, sid_to_string, windows_adapter_from_io,
};
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
pub(crate) struct OwnedProcessHandle(pub(crate) windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Windows kernel handles are process-global. This wrapper retains
// unique ownership and closes the handle exactly once in Drop.
#[cfg(windows)]
unsafe impl Send for OwnedProcessHandle {}

#[cfg(windows)]
impl OwnedProcessHandle {
    pub(crate) fn new(
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<Self, WindowsAdapterError> {
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
pub(crate) struct PinnedExecutable {
    pub(crate) file: std::fs::File,
    pub(crate) identity: FileIdentity,
}

#[cfg(windows)]
impl PinnedExecutable {
    pub(crate) fn open(path: &Path) -> Result<Self, WindowsAdapterError> {
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
            file,
            identity: FileIdentity {
                volume_serial_number: information.dwVolumeSerialNumber,
                file_index: (u64::from(information.nFileIndexHigh) << 32)
                    | u64::from(information.nFileIndexLow),
            },
        })
    }
}

/// Opaque live proof of the Kernel server on a connected named pipe.
///
/// The process and executable handles are retained until this value is
/// dropped. The proof observes the executable path object while the process
/// handle is live; it does not claim a mapped-image/section proof.
#[cfg(windows)]
pub struct KernelFrontDoorServerProof {
    process: OwnedProcessHandle,
    executable: PinnedExecutable,
    evidence: NamedPipePeerEvidence,
    artifact_sha256: String,
    observed_extra_sid: Option<String>,
}

#[cfg(windows)]
impl KernelFrontDoorServerProof {
    #[must_use]
    pub fn evidence(&self) -> &NamedPipePeerEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn observed_extra_sid(&self) -> Option<&str> {
        self.observed_extra_sid.as_deref()
    }

    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    /// Returns whether the retained process handle is still non-null. The
    /// handle itself remains opaque and is never exposed to callers.
    #[must_use]
    pub fn retains_live_process(&self) -> bool {
        !self.process.0.is_null()
    }

    /// Returns the retained executable file identity.
    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable.identity
    }
}

#[cfg(not(windows))]
pub struct KernelFrontDoorServerProof;

#[cfg(not(windows))]
impl KernelFrontDoorServerProof {
    pub fn evidence(&self) -> ! {
        unreachable!("Windows proof is unavailable on this target")
    }
}

/// Proves the exact Kernel server bound to a connected client-end pipe.
///
/// Unlike the generic peer APIs this function retains both the queried
/// process handle and the no-follow executable handle in the returned proof.
/// The DACL is independently checked against the narrow front-door contour.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the specialized Kernel proof keeps process, executable, artifact, and ACL checks contiguous"
)]
pub fn authenticate_kernel_front_door_server(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expectation: &KernelFrontDoorServerExpectation,
) -> Result<KernelFrontDoorServerProof, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let observed_extra_sid = validate_kernel_front_door_dacl(pipe_handle, expectation)?;
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
    let result = (|| {
        let identity = inspect_process_handle(process_id, process)
            .map_err(|error| windows_adapter_from_io(&error))?;
        validate_kernel_front_door_process_identity(&identity, expectation)?;
        if let Some(approved) = expectation.approved_process_job_binding() {
            if !same_process_identity(&identity, approved.process_binding().identity()) {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            let current = observe_named_pipe_peer_process_in_job(approved.job_name(), process_id)?;
            if !same_process_identity(
                current.process_binding().identity(),
                approved.process_binding().identity(),
            ) {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
        }
        let (sid, session_id) = process_token_identity(process)?;
        if sid != expectation.expected_server_sid()
            || session_id != expectation.expected_server_session_id()
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }

        let mut executable = PinnedExecutable::open(Path::new(&identity.image_path))?;
        let final_path = final_windows_path_from_handle(&executable.file)
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let final_path = final_path
            .to_str()
            .ok_or(WindowsAdapterError::IdentityMismatch)?;
        validate_kernel_front_door_executable_identity(
            &identity.image_path,
            final_path,
            executable.identity,
            expectation,
        )?;
        executable
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| WindowsAdapterError::Failed)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = executable
                .file
                .read(&mut buffer)
                .map_err(|_| WindowsAdapterError::Failed)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let artifact_sha256 = format!("{:x}", hasher.finalize());
        validate_kernel_front_door_artifact(&artifact_sha256, expectation)?;
        let evidence = NamedPipePeerEvidence {
            process: identity,
            sid,
            session_id,
            executable_file: Some(executable.identity),
            job_name: expectation
                .approved_process_job_binding()
                .map(|binding| binding.job_name().to_owned()),
            builtin_administrators: false,
            interactive_session: false,
        };
        let process = OwnedProcessHandle::new(process)?;
        Ok(KernelFrontDoorServerProof {
            process,
            executable,
            evidence,
            artifact_sha256,
            observed_extra_sid,
        })
    })();
    if result.is_err() {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(process) };
    }
    result
}

#[cfg(windows)]
pub(crate) fn validate_kernel_front_door_process_identity(
    observed: &ProcessIdentity,
    expectation: &KernelFrontDoorServerExpectation,
) -> Result<(), WindowsAdapterError> {
    if let Some(approved) = expectation.approved_process_binding()
        && !same_process_identity(observed, approved.identity())
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn validate_kernel_front_door_executable_identity(
    observed_image_path: &str,
    retained_final_path: &str,
    retained_file_identity: FileIdentity,
    expectation: &KernelFrontDoorServerExpectation,
) -> Result<(), WindowsAdapterError> {
    if !same_process_image_path(retained_final_path, observed_image_path) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if let Some(expected_file) = expectation
        .approved_process_binding()
        .and_then(NamedPipePeerProcessBinding::executable_file_identity)
        && expected_file != retained_file_identity
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

pub(crate) fn validate_kernel_front_door_artifact(
    observed_sha256: &str,
    expectation: &KernelFrontDoorServerExpectation,
) -> Result<(), WindowsAdapterError> {
    if observed_sha256 == expectation.expected_kernel_artifact_sha256() {
        Ok(())
    } else {
        Err(WindowsAdapterError::IdentityMismatch)
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the specialized Kernel DACL readback keeps all ACE classification in one fail-closed boundary"
)]
pub(crate) fn validate_kernel_front_door_dacl(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    expectation: &KernelFrontDoorServerExpectation,
) -> Result<Option<String>, WindowsAdapterError> {
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
        let mut entries = Vec::with_capacity(usize::from(unsafe { (*dacl).AceCount }));
        for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
                return Err(WindowsAdapterError::AclMismatch);
            }
            let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&raw const allowed.SidStart).cast_mut().cast();
            let text = sid_to_string(sid)?;
            let is_user_account = match expectation.acl_mode() {
                KernelFrontDoorAclMode::SystemAndLocalServiceWithClient { client_sid }
                    if client_sid == &text =>
                {
                    sid_text_is_user_account(&text)?
                }
                KernelFrontDoorAclMode::SystemAndLocalServiceWithOneClient
                | KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient
                    if !matches!(
                        text.as_str(),
                        "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544"
                    ) =>
                {
                    sid_text_is_user_account(&text)?
                }
                _ => false,
            };
            entries.push(KernelFrontDoorAce {
                sid: text,
                mask: allowed.Mask,
                ace_type: header.AceType,
                ace_flags: header.AceFlags,
                is_user_account,
            });
        }
        classify_kernel_front_door_acl(&entries, expectation.acl_mode())
    })();
    unsafe { LocalFree(descriptor.cast()) };
    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelFrontDoorAce {
    pub(crate) sid: String,
    pub(crate) mask: u32,
    pub(crate) ace_type: u8,
    pub(crate) ace_flags: u8,
    pub(crate) is_user_account: bool,
}

pub(crate) fn classify_kernel_front_door_acl(
    entries: &[KernelFrontDoorAce],
    mode: &KernelFrontDoorAclMode,
) -> Result<Option<String>, WindowsAdapterError> {
    let mut expected = vec!["S-1-5-18", "S-1-5-19"];
    let exactly_one_extra = matches!(
        mode,
        KernelFrontDoorAclMode::SystemAndLocalServiceWithOneClient
    );
    let optional_extra = matches!(
        mode,
        KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient
    );
    if let KernelFrontDoorAclMode::SystemAndLocalServiceWithClient { client_sid } = mode {
        expected.push(client_sid.as_str());
    }
    let valid_count = if exactly_one_extra {
        entries.len() == expected.len() + 1
    } else if optional_extra {
        (expected.len()..=expected.len() + 1).contains(&entries.len())
    } else {
        entries.len() == expected.len()
    };
    if !valid_count {
        return Err(WindowsAdapterError::AclMismatch);
    }
    let mut seen = vec![false; expected.len()];
    let mut observed_extra = None::<String>;
    for ace in entries {
        if ace.ace_type != 0 || ace.ace_flags != 0 || ace.mask != PEER_SET_GENERIC_ALL_MAPPED {
            return Err(WindowsAdapterError::AclMismatch);
        }
        if let Some(position) = expected.iter().position(|value| *value == ace.sid) {
            if position >= 2
                && matches!(
                    mode,
                    KernelFrontDoorAclMode::SystemAndLocalServiceWithClient { .. }
                )
                && !ace.is_user_account
            {
                return Err(WindowsAdapterError::AclMismatch);
            }
            if seen[position] {
                return Err(WindowsAdapterError::AclMismatch);
            }
            seen[position] = true;
        } else if (exactly_one_extra || optional_extra)
            && observed_extra.is_none()
            && valid_sid_text(&ace.sid)
            && !matches!(
                ace.sid.as_str(),
                "S-1-1-0"
                    | "S-1-5-11"
                    | "S-1-5-18"
                    | "S-1-5-19"
                    | "S-1-5-20"
                    | "S-1-5-32-544"
                    | "S-1-5-32-545"
            )
            && !ace.sid.starts_with("S-1-5-80-")
            && ace.is_user_account
        {
            observed_extra = Some(ace.sid.clone());
        } else {
            return Err(WindowsAdapterError::AclMismatch);
        }
    }
    if !seen.into_iter().all(std::convert::identity)
        || exactly_one_extra && observed_extra.is_none()
    {
        return Err(WindowsAdapterError::AclMismatch);
    }
    Ok(match mode {
        KernelFrontDoorAclMode::ServiceOnly => None,
        KernelFrontDoorAclMode::SystemAndLocalServiceWithClient { client_sid } => {
            Some(client_sid.clone())
        }
        KernelFrontDoorAclMode::SystemAndLocalServiceWithOneClient
        | KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient => observed_extra,
    })
}

#[cfg(windows)]
fn sid_text_is_user_account(value: &str) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::{LookupAccountSidW, SID_NAME_USE, SidTypeUser};

    let text = value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
        return Err(last_windows_adapter_error());
    }
    let result = (|| {
        let mut name_len = 0_u32;
        let mut domain_len = 0_u32;
        let mut sid_type: SID_NAME_USE = 0;
        let first = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                std::ptr::null_mut(),
                &raw mut name_len,
                std::ptr::null_mut(),
                &raw mut domain_len,
                &raw mut sid_type,
            )
        };
        if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(last_windows_adapter_error());
        }
        if name_len == 0 || name_len > 32 * 1024 || domain_len > 32 * 1024 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let mut name =
            vec![0_u16; usize::try_from(name_len).map_err(|_| WindowsAdapterError::Failed)?];
        let mut domain = vec![
            0_u16;
            usize::try_from(domain_len.max(1))
                .map_err(|_| WindowsAdapterError::Failed)?
        ];
        if unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &raw mut name_len,
                domain.as_mut_ptr(),
                &raw mut domain_len,
                &raw mut sid_type,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        Ok(sid_type == SidTypeUser)
    })();
    unsafe { LocalFree(sid.cast()) };
    result
}
