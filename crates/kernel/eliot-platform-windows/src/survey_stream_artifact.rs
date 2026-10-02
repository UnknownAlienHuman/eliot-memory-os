//! Native, create-only artifacts for installation survey process streams.
//!
//! The caller supplies the installer-verified root before the executor admits
//! its isolated child directory. This adapter retains protected native handles
//! for the root, artifact directory, and each file. It never adopts an existing
//! stream file and it exposes only bounded identity/hash readback to callers.

use std::path::PathBuf;
use std::sync::Arc;

#[cfg(windows)]
use std::{
    io::{Read as _, Seek as _, Write as _},
    path::Path,
};
#[cfg(windows)]
use sha2::{Digest as _, Sha256};

use crate::{
    FileIdentity, ProtectedPathError, UserOwnedRootLease, UserOwnedRootReadLease,
};

const ARTIFACT_DIRECTORY: &str = "installation-survey-streams";

/// Failure to create, append to, or read back one retained native artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurveyStreamArtifactError {
    /// The native operation is unavailable on this platform.
    UnsupportedPlatform,
    /// The caller supplied a limit or offset inconsistent with the artifact.
    InvalidInput,
    /// An artifact at the create-only session path already exists.
    ExistingArtifact,
    /// A retained handle or its file identity no longer matches admission.
    IdentityMismatch,
    /// The exact protected owner-only security descriptor could not be proved.
    SecurityMismatch,
    /// A native file operation failed; the caller must preserve the session as
    /// uncertain because the write or durability effect may have occurred.
    NativeIo,
}

/// Identity returned only after native readback of the actual artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurveyStreamArtifactReadback {
    /// Native immutable locator naming the canonical path of the retained file.
    pub locator: String,
    /// Native handle identity, readback length, and digest for this artifact.
    pub ready_receipt_ref: String,
    /// File identity measured from the retained native handle.
    pub file_identity: FileIdentity,
    /// Length read from and checked against the retained file handle.
    pub byte_length: u64,
    /// SHA-256 computed from the exact bytes read back through the retained handle.
    pub sha256: String,
}

/// Retained installer-root and owner-only artifact directory for one survey.
///
/// Existing exact owner-only artifact directories may be reused as a
/// containing area. Per-stream files are always create-only and are never
/// adopted after a collision.
#[derive(Clone)]
pub struct SurveyStreamArtifactRoot {
    inner: Arc<SurveyStreamArtifactRootInner>,
}

struct SurveyStreamArtifactRootInner {
    installer_root: UserOwnedRootLease,
    artifact_root: UserOwnedRootLease,
    installer_root_identity: FileIdentity,
    artifact_root_identity: FileIdentity,
    artifact_path: PathBuf,
    /// Holds ownership handles for any file created before a subsequent open
    /// or readback step failed. Such an effect remains attached to this exact
    /// root instance and cannot be adopted by another request.
    pending_created_files:
        std::sync::Mutex<std::collections::HashMap<String, PendingArtifactHandles>>,
}

#[derive(Default)]
struct PendingArtifactHandles {
    append_file: Option<std::fs::File>,
    flush_file: Option<std::fs::File>,
    read_file: Option<std::fs::File>,
}

impl SurveyStreamArtifactRoot {
    /// Opens the exact retained installer root and establishes its dedicated
    /// owner-only artifact subdirectory before temporary executor ACL changes.
    ///
    /// # Errors
    ///
    /// Refuses an unsupported platform, changed root identity, unsafe path,
    /// or a foreign/unprotected pre-existing artifact directory.
    pub fn open(
        original_root: &UserOwnedRootReadLease,
    ) -> Result<Self, SurveyStreamArtifactError> {
        #[cfg(windows)]
        {
            original_root
                .verify_stable_identity()
                .map_err(map_protected_path_error)?;
            let original_path = original_root
                .canonical_path()
                .map_err(map_protected_path_error)?;
            let installer_root = UserOwnedRootLease::open_existing(&original_path)
                .map_err(map_protected_path_error)?;
            if installer_root.identity() != original_root.identity()
                || installer_root
                    .canonical_path()
                    .map_err(map_protected_path_error)?
                    != original_path
            {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            let artifact_root = installer_root
                .open_or_create_child_directory(ARTIFACT_DIRECTORY)
                .map_err(map_protected_path_error)?;
            installer_root
                .verify_stable_identity()
                .map_err(map_protected_path_error)?;
            original_root
                .verify_stable_identity()
                .map_err(map_protected_path_error)?;
            artifact_root
                .verify_stable_identity()
                .map_err(map_protected_path_error)?;
            let artifact_path = artifact_root
                .canonical_path()
                .map_err(map_protected_path_error)?;
            Ok(Self {
                inner: Arc::new(SurveyStreamArtifactRootInner {
                    installer_root,
                    artifact_root_identity: artifact_root.identity(),
                    artifact_root,
                    installer_root_identity: original_root.identity(),
                    artifact_path,
                    pending_created_files: std::sync::Mutex::new(
                        std::collections::HashMap::new(),
                    ),
                }),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = original_root;
            Err(SurveyStreamArtifactError::UnsupportedPlatform)
        }
    }

    /// Creates one append-only raw stream file beneath the retained evidence
    /// area. A prior file at the same derived session path is never adopted.
    ///
    /// # Errors
    ///
    /// Refuses an existing file, unstable native contour, reparse point,
    /// unexpected owner/DACL, or unavailable native file operation.
    pub fn create_stream_file(
        &self,
        file_name: &str,
    ) -> Result<SurveyStreamArtifact, SurveyStreamArtifactError> {
        #[cfg(windows)]
        {
            self.inner.verify_retained_contour()?;
            validate_artifact_file_name(file_name)?;
            let mut pending = self
                .inner
                .pending_created_files
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pending.contains_key(file_name) {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            let path = self.inner.artifact_path.join(file_name);
            let proposed_locator = format!("native-artifact:{}", path.to_string_lossy());
            if proposed_locator.len() > 256 {
                return Err(SurveyStreamArtifactError::InvalidInput);
            }
            let append_file = create_new_append_artifact(
                &path,
                self.inner.artifact_root.current_user_sid(),
            )?;
            pending.insert(
                file_name.to_owned(),
                PendingArtifactHandles {
                    append_file: Some(append_file),
                    ..PendingArtifactHandles::default()
                },
            );
            // Finish through the retained CREATE_NEW handle. Any failure keeps
            // that original file and every acquired auxiliary handle pending
            // for a later reconciliation attempt.
            self.reconcile_pending_created_stream_file(file_name, &mut pending)
        }
        #[cfg(not(windows))]
        {
            let _ = file_name;
            Err(SurveyStreamArtifactError::UnsupportedPlatform)
        }
    }

    /// Reconciles only the original file retained after this root's successful
    /// `CREATE_NEW`; it never opens or adopts a file by its session pathname.
    ///
    /// # Errors
    ///
    /// Refuses an absent pending entry, changed identity/security, or a native
    /// reopen/readback failure. Every error leaves the pending handles owned by
    /// this root so the same create effect can be reconciled again.
    pub fn reconcile_created_stream_file(
        &self,
        file_name: &str,
    ) -> Result<SurveyStreamArtifact, SurveyStreamArtifactError> {
        #[cfg(windows)]
        {
            validate_artifact_file_name(file_name)?;
            let mut pending = self
                .inner
                .pending_created_files
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.reconcile_pending_created_stream_file(file_name, &mut pending)
        }
        #[cfg(not(windows))]
        {
            let _ = file_name;
            Err(SurveyStreamArtifactError::UnsupportedPlatform)
        }
    }

    #[cfg(windows)]
    fn reconcile_pending_created_stream_file(
        &self,
        file_name: &str,
        pending: &mut std::collections::HashMap<String, PendingArtifactHandles>,
    ) -> Result<SurveyStreamArtifact, SurveyStreamArtifactError> {
        self.inner.verify_retained_contour()?;
        let (identity, locator) = {
            let handles = pending
                .get_mut(file_name)
                .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
            let append_file = handles
                .append_file
                .as_ref()
                .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
            let identity = crate::file_identity_from_handle(append_file)
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
            verify_file_kind_and_link_count(append_file)?;
            verify_file_security(append_file, self.inner.artifact_root.current_user_sid())?;
            let canonical_file_path = crate::final_windows_path_from_handle(append_file)
                .map_err(map_protected_path_error)?;
            let locator = format!("native-artifact:{}", canonical_file_path.to_string_lossy());
            if locator.len() > 256 {
                return Err(SurveyStreamArtifactError::InvalidInput);
            }

            // ReOpenFile binds each auxiliary handle to the original created
            // object. Store a successful open before any fallible proof so a
            // later retry retains it alongside the original append handle.
            if handles.flush_file.is_none() {
                let flush_file = reopen_artifact_handle(
                    append_file,
                    windows_sys::Win32::Foundation::GENERIC_WRITE,
                )?;
                handles.flush_file = Some(flush_file);
            }
            let flush_file = handles
                .flush_file
                .as_ref()
                .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
            if crate::file_identity_from_handle(flush_file)
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?
                != identity
            {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            verify_file_kind_and_link_count(flush_file)?;
            verify_file_security(flush_file, self.inner.artifact_root.current_user_sid())?;

            if handles.read_file.is_none() {
                let read_file = reopen_artifact_handle(
                    append_file,
                    windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
                )?;
                handles.read_file = Some(read_file);
            }
            let read_file = handles
                .read_file
                .as_ref()
                .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
            if crate::file_identity_from_handle(read_file)
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?
                != identity
            {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            verify_file_kind_and_link_count(read_file)?;
            verify_file_security(read_file, self.inner.artifact_root.current_user_sid())?;
            (identity, locator)
        };

        let mut handles = pending
            .remove(file_name)
            .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
        let Some(read_file) = handles.read_file.take() else {
            pending.insert(file_name.to_owned(), handles);
            return Err(SurveyStreamArtifactError::IdentityMismatch);
        };
        Ok(SurveyStreamArtifact {
            append_file: handles.append_file,
            flush_file: handles.flush_file,
            read_file,
            identity,
            locator,
            root: Arc::clone(&self.inner),
            finalized: false,
        })
    }
}

impl SurveyStreamArtifactRootInner {
    fn verify_retained_contour(&self) -> Result<(), SurveyStreamArtifactError> {
        self.installer_root
            .verify_stable_identity()
            .map_err(map_protected_path_error)?;
        self.artifact_root
            .verify_stable_identity()
            .map_err(map_protected_path_error)?;
        if self.installer_root.identity() != self.installer_root_identity
            || self.artifact_root.identity() != self.artifact_root_identity
        {
            return Err(SurveyStreamArtifactError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Create-only stream artifact with distinct append, flush and readback handles.
pub struct SurveyStreamArtifact {
    append_file: Option<std::fs::File>,
    flush_file: Option<std::fs::File>,
    read_file: std::fs::File,
    identity: FileIdentity,
    locator: String,
    root: Arc<SurveyStreamArtifactRootInner>,
    finalized: bool,
}

impl SurveyStreamArtifact {
    /// Appends at the exact next physical offset, syncs the write, and verifies
    /// retained native identities. Any error is potentially an unknown write
    /// outcome; callers must keep this original session for reconciliation.
    ///
    /// # Errors
    ///
    /// Refuses a gap, overflow, limit overrun, closed writer, or native I/O
    /// failure. A native failure may follow a partial physical write.
    pub fn append(
        &mut self,
        expected_offset: u64,
        bytes: &[u8],
        max_total_bytes: u64,
    ) -> Result<u64, SurveyStreamArtifactError> {
        #[cfg(windows)]
        {
            self.verify_retained_handles()?;
            if self.finalized {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            let append_file = self
                .append_file
                .as_mut()
                .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
            let flush_file = self
                .flush_file
                .as_ref()
                .ok_or(SurveyStreamArtifactError::IdentityMismatch)?;
            let current = self
                .read_file
                .metadata()
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?
                .len();
            let new_length = expected_offset
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    SurveyStreamArtifactError::InvalidInput
                })?)
                .ok_or(SurveyStreamArtifactError::InvalidInput)?;
            if current != expected_offset || new_length > max_total_bytes {
                return Err(SurveyStreamArtifactError::InvalidInput);
            }
            append_file
                .write_all(bytes)
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
            flush_file
                .sync_data()
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
            if self.read_file
                .metadata()
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?
                .len()
                != new_length
            {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            self.verify_retained_handles()?;
            Ok(new_length)
        }
        #[cfg(not(windows))]
        {
            let _ = (expected_offset, bytes, max_total_bytes);
            Err(SurveyStreamArtifactError::UnsupportedPlatform)
        }
    }

    /// Flushes an open writer and reads the artifact through its retained
    /// native read handle. After finalization, the closed writer needs no flush.
    ///
    /// This returns metadata only; raw bytes are never projected into ORS.
    /// The same function is used for readback while a session remains open.
    /// Setting `finalize_artifact` prevents later appends through this retained
    /// artifact capability.
    ///
    /// # Errors
    ///
    /// Refuses an unstable identity, a file beyond its admitted bound, a
    /// reparse/multi-link file, or a mismatching owner/DACL/readback.
    pub fn readback(
        &mut self,
        max_total_bytes: u64,
        finalize_artifact: bool,
    ) -> Result<SurveyStreamArtifactReadback, SurveyStreamArtifactError> {
        #[cfg(windows)]
        {
            self.verify_retained_handles()?;
            if let Some(flush_file) = self.flush_file.as_ref() {
                flush_file
                    .sync_all()
                    .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
            } else if !self.finalized {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            self.read_file
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
            let mut hasher = Sha256::new();
            let mut byte_length = 0_u64;
            let mut buffer = [0_u8; 8192];
            loop {
                let read = self
                    .read_file
                    .read(&mut buffer)
                    .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
                if read == 0 {
                    break;
                }
                let read = u64::try_from(read).map_err(|_| SurveyStreamArtifactError::InvalidInput)?;
                byte_length = byte_length
                    .checked_add(read)
                    .ok_or(SurveyStreamArtifactError::InvalidInput)?;
                if byte_length > max_total_bytes {
                    return Err(SurveyStreamArtifactError::InvalidInput);
                }
                hasher.update(&buffer[..usize::try_from(read).map_err(|_| {
                    SurveyStreamArtifactError::InvalidInput
                })?]);
            }
            if self
                .read_file
                .metadata()
                .map_err(|_| SurveyStreamArtifactError::NativeIo)?
                .len()
                != byte_length
            {
                return Err(SurveyStreamArtifactError::IdentityMismatch);
            }
            let sha256 = format!("{:x}", hasher.finalize());
            verify_file_kind_and_link_count(&self.read_file)?;
            verify_file_security(&self.read_file, self.root.artifact_root.current_user_sid())?;
            self.verify_retained_handles()?;
            let ready_receipt_ref = format!(
                "native-readback:{:016x}-{:016x}:{byte_length}:{sha256}",
                self.identity.volume_serial_number,
                self.identity.file_index,
            );
            if finalize_artifact {
                // Drop both mutable capabilities only after the independent
                // GENERIC_WRITE handle successfully flushed the same FileID
                // and the read-only handle verified the final bytes.
                drop(self.append_file.take());
                drop(self.flush_file.take());
                self.finalized = true;
            }
            Ok(SurveyStreamArtifactReadback {
                locator: self.locator.clone(),
                ready_receipt_ref,
                file_identity: self.identity,
                byte_length,
                sha256,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (max_total_bytes, finalize_artifact);
            Err(SurveyStreamArtifactError::UnsupportedPlatform)
        }
    }

    #[cfg(windows)]
    fn verify_retained_handles(&self) -> Result<(), SurveyStreamArtifactError> {
        self.root.installer_root
            .verify_stable_identity()
            .map_err(map_protected_path_error)?;
        self.root.artifact_root
            .verify_stable_identity()
            .map_err(map_protected_path_error)?;
        let file_identity = crate::file_identity_from_handle(&self.read_file)
            .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
        if self.root.installer_root.identity() != self.root.installer_root_identity
            || self.root.artifact_root.identity() != self.root.artifact_root_identity
            || file_identity != self.identity
            || self
                .append_file
                .as_ref()
                .is_some_and(|file| crate::file_identity_from_handle(file).ok() != Some(self.identity))
            || self
                .flush_file
                .as_ref()
                .is_some_and(|file| crate::file_identity_from_handle(file).ok() != Some(self.identity))
            || (self.finalized
                && (self.append_file.is_some() || self.flush_file.is_some()))
            || (!self.finalized
                && (self.append_file.is_none() || self.flush_file.is_none()))
        {
            return Err(SurveyStreamArtifactError::IdentityMismatch);
        }
        Ok(())
    }
}

#[cfg(windows)]
fn validate_artifact_file_name(file_name: &str) -> Result<(), SurveyStreamArtifactError> {
    let Some((digest, suffix)) = file_name.split_once('-') else {
        return Err(SurveyStreamArtifactError::InvalidInput);
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !matches!(suffix, "stdout.raw" | "stderr.raw")
        || file_name
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\' | b':'))
    {
        return Err(SurveyStreamArtifactError::InvalidInput);
    }
    Ok(())
}

#[cfg(windows)]
fn map_protected_path_error(error: ProtectedPathError) -> SurveyStreamArtifactError {
    match error {
        ProtectedPathError::UnsupportedPlatform => SurveyStreamArtifactError::UnsupportedPlatform,
        ProtectedPathError::IdentityMismatch => SurveyStreamArtifactError::IdentityMismatch,
        ProtectedPathError::InvalidRoot
        | ProtectedPathError::InvalidPath
        | ProtectedPathError::ReparsePoint
        | ProtectedPathError::AclMismatch => SurveyStreamArtifactError::SecurityMismatch,
        ProtectedPathError::Io
        | ProtectedPathError::Win32 { .. }
        | ProtectedPathError::SizeExceeded => SurveyStreamArtifactError::NativeIo,
    }
}

#[cfg(not(windows))]
fn map_protected_path_error(_: ProtectedPathError) -> SurveyStreamArtifactError {
    SurveyStreamArtifactError::UnsupportedPlatform
}

#[cfg(windows)]
fn create_new_append_artifact(
    path: &Path,
    sid: &str,
) -> Result<std::fs::File, SurveyStreamArtifactError> {
    use std::os::windows::{io::FromRawHandle, os_str::OsStrExt};
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{READ_CONTROL, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let descriptor = crate::OwnedSecurityDescriptor::for_user_owned_storage(sid, false)
        .map_err(|_| SurveyStreamArtifactError::SecurityMismatch)?;
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| SurveyStreamArtifactError::InvalidInput)?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: path_wide and SECURITY_ATTRIBUTES live through CreateFileW; the
    // exact protected descriptor remains owned through this synchronous call.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw mut security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(match unsafe { GetLastError() } {
            windows_sys::Win32::Foundation::ERROR_FILE_EXISTS
            | windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS => {
                SurveyStreamArtifactError::ExistingArtifact
            }
            _ => SurveyStreamArtifactError::NativeIo,
        });
    }
    // SAFETY: CreateFileW returned a unique valid handle; ownership moves to
    // File before any subsequent fallible validation so pending retention can
    // preserve every post-create effect.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn reopen_artifact_handle(
    original: &std::fs::File,
    access: u32,
) -> Result<std::fs::File, SurveyStreamArtifactError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::READ_CONTROL;
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    // ReOpenFile creates a new handle to this exact file object. Share modes
    // permit the owned append/flush/read handles and deny delete/substitution.
    // SAFETY: the original handle remains live for the synchronous reopen.
    let handle = unsafe {
        ReOpenFile(
            original.as_raw_handle().cast(),
            access | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(SurveyStreamArtifactError::NativeIo);
    }
    // SAFETY: ReOpenFile returned a unique valid handle and ownership moves
    // directly into File before any fallible identity/security validation.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn verify_file_kind_and_link_count(file: &std::fs::File) -> Result<(), SurveyStreamArtifactError> {
    use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };

    let metadata = file
        .metadata()
        .map_err(|_| SurveyStreamArtifactError::NativeIo)?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(SurveyStreamArtifactError::IdentityMismatch);
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the retained file handle is live and the output points to valid
    // storage for the documented Windows information structure.
    let observed = unsafe {
        GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information)
    };
    if observed == 0 || information.nNumberOfLinks != 1 {
        return Err(SurveyStreamArtifactError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_file_security(
    file: &std::fs::File,
    sid: &str,
) -> Result<(), SurveyStreamArtifactError> {
    let expected = crate::OwnedSecurityDescriptor::for_user_owned_storage(sid, false)
        .map_err(|_| SurveyStreamArtifactError::SecurityMismatch)?;
    crate::verify_exact_file_security(file, &expected, sid)
        .map_err(|_| SurveyStreamArtifactError::SecurityMismatch)
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    fn owned_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "eliot-survey-artifact-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).expect("test root creation succeeds");
        let _ = UserOwnedRootLease::open_existing(&root).expect("test root is owner protected");
        root
    }

    #[test]
    fn create_only_artifact_appends_and_reads_back_empty_and_bounded_stdout() {
        let path = owned_root();
        let root = UserOwnedRootReadLease::open_existing(&path)
            .expect("test owner root readback succeeds");
        let artifact_root = SurveyStreamArtifactRoot::open(&root)
            .expect("dedicated artifact area opens");

        let session_name = format!("{}-stdout.raw", eliot_contracts::sha256_hex(b"test-session-stdout"));
        let mut stdout = artifact_root
            .create_stream_file(&session_name)
            .expect("stdout artifact is newly created");
        stdout
            .append(0, b"survey output", 64)
            .expect("bounded stdout append succeeds");
        let readback = stdout
            .readback(64, true)
            .expect("stdout bytes are read back from the same file");
        assert_eq!(readback.byte_length, 13);
        assert_eq!(readback.sha256, eliot_contracts::sha256_hex(b"survey output"));
        let repeated_readback = stdout
            .readback(64, true)
            .expect("finalized stdout remains readable through its retained read handle");
        assert_eq!(repeated_readback, readback);

        let empty_session = format!("{}-stderr.raw", eliot_contracts::sha256_hex(b"test-session-empty"));
        let mut empty = artifact_root
            .create_stream_file(&empty_session)
            .expect("empty stderr artifact is newly created");
        let empty_readback = empty
            .readback(64, true)
            .expect("zero-byte file is read back from the same file");
        assert_eq!(empty_readback.byte_length, 0);
        assert_eq!(empty_readback.sha256, eliot_contracts::sha256_hex(&[]));

        drop(empty);
        drop(stdout);
        drop(artifact_root);
        drop(root);
        std::fs::remove_dir_all(path).expect("test root cleanup succeeds");
    }

    #[test]
    fn reconcile_created_stream_recovers_from_the_original_pending_handle() {
        let path = owned_root();
        let root = UserOwnedRootReadLease::open_existing(&path)
            .expect("test owner root readback succeeds");
        let artifact_root = SurveyStreamArtifactRoot::open(&root)
            .expect("dedicated artifact area opens");
        let file_name = format!("{}-stdout.raw", eliot_contracts::sha256_hex(b"pending-recovery"));
        let file_path = artifact_root.inner.artifact_path.join(&file_name);
        let append_file = create_new_append_artifact(
            &file_path,
            artifact_root.inner.artifact_root.current_user_sid(),
        )
        .expect("original append-only artifact is created");
        let original_identity = crate::file_identity_from_handle(&append_file)
            .expect("created artifact identity is readable");
        let mut pending = artifact_root
            .inner
            .pending_created_files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.insert(
            file_name.clone(),
            PendingArtifactHandles {
                append_file: Some(append_file),
                ..PendingArtifactHandles::default()
            },
        );
        drop(pending);

        let mut recovered = artifact_root
            .reconcile_created_stream_file(&file_name)
            .expect("pending artifact reopens auxiliary handles on the original file");
        assert_eq!(recovered.identity, original_identity);
        recovered
            .append(0, b"reconciled bytes", 64)
            .expect("reconciled append handle writes to the created file");
        let readback = recovered
            .readback(64, true)
            .expect("reconciled file is flushed and read back");
        assert_eq!(readback.byte_length, 16);
        assert_eq!(readback.sha256, eliot_contracts::sha256_hex(b"reconciled bytes"));

        drop(recovered);
        drop(artifact_root);
        drop(root);
        std::fs::remove_dir_all(path).expect("test root cleanup succeeds");
    }

    #[test]
    fn existing_session_artifact_is_refused_without_adoption() {
        let path = owned_root();
        let root = UserOwnedRootReadLease::open_existing(&path)
            .expect("test owner root readback succeeds");
        let artifact_root = SurveyStreamArtifactRoot::open(&root)
            .expect("dedicated artifact area opens");
        let file_name = format!("{}-stdout.raw", eliot_contracts::sha256_hex(b"foreign-existing-session"));
        let foreign_path = artifact_root.inner.artifact_path.join(&file_name);
        std::fs::write(&foreign_path, b"foreign bytes")
            .expect("foreign file fixture is created");
        assert!(matches!(
            artifact_root.create_stream_file(&file_name),
            Err(SurveyStreamArtifactError::ExistingArtifact),
        ));
        assert!(matches!(
            artifact_root.reconcile_created_stream_file(&file_name),
            Err(SurveyStreamArtifactError::IdentityMismatch),
        ));
        assert_eq!(
            std::fs::read(&foreign_path).expect("foreign file remains readable"),
            b"foreign bytes",
        );

        drop(artifact_root);
        drop(root);
        std::fs::remove_dir_all(path).expect("test root cleanup succeeds");
    }
}
