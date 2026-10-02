//! Bounded, handle-bound Windows file-version observation.
//!
//! The adapter reads one non-reparse executable through a no-follow handle,
//! retains its volume/file identity and SHA-256, and asks the Windows version
//! resource APIs for the root `VS_FIXEDFILEINFO`. It never executes the image
//! and makes no trust or admission decision. A missing version resource is a
//! distinct observation from an unreadable or malformed resource.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FileIdentity;

/// The existing survey executable and version-resource byte ceiling.
///
/// Keeping the image read and the native resource allocation on the same
/// bound prevents a small executable observation from expanding into an
/// unbounded version-resource allocation.
pub const MAX_SURVEY_EXECUTABLE_BYTES: u64 = 134_217_728;

/// Exact result of inspecting the root version resource on one observed file.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileVersionOutcome {
    /// A valid root `VS_FIXEDFILEINFO` was present.
    Present {
        /// `VS_FIXEDFILEINFO.dwFileVersionMS` from the retained image.
        file_version_ms: u32,
        /// `VS_FIXEDFILEINFO.dwFileVersionLS` from the retained image.
        file_version_ls: u32,
    },
    /// The executable was read, but it contains no version resource.
    Absent,
    /// The path no longer names a file that can be opened.
    NotFound,
    /// The observing identity was denied access to the file or resource.
    Denied,
    /// The file or version resource could not be read completely.
    Unreadable,
    /// The image or version resource exceeded bounds or was malformed.
    Invalid,
}

/// A version-resource outcome retained with the exact no-follow file proof.
///
/// Identity and digest are independently retained when measured from the
/// opened file; a successful `Present` or `Absent` result requires both. This
/// is observation data, not an admission receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileVersionObservation {
    /// Stable identity of the opened non-reparse file, when measured.
    pub file_identity: Option<FileIdentity>,
    /// SHA-256 of the same opened file, when measured.
    pub sha256: Option<String>,
    /// Exact version-resource observation or its typed coverage result.
    pub outcome: FileVersionOutcome,
}

/// Reads a file's version resource without following a reparse point.
///
/// The file is opened with sharing that excludes later write and delete
/// handles. Its no-follow identity and SHA-256 are measured before the version
/// API call and checked again afterward, while that handle remains open. The
/// version API is given the final path obtained from the retained handle, so a
/// pathname replacement cannot redirect the query to another file.
#[must_use]
pub fn observe_file_version(path: &Path) -> FileVersionObservation {
    #[cfg(windows)]
    {
        observe_windows_file_version(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        observation(None, None, FileVersionOutcome::Unreadable)
    }
}

fn observation(
    file_identity: Option<FileIdentity>,
    sha256: Option<String>,
    outcome: FileVersionOutcome,
) -> FileVersionObservation {
    FileVersionObservation {
        file_identity,
        sha256,
        outcome,
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the retained-handle version lookup and post-read identity check are one reviewed operation"
)]
fn observe_windows_file_version(path: &Path) -> FileVersionObservation {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    use sha2::{Digest as _, Sha256};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    if !path.is_absolute() {
        return observation(None, None, FileVersionOutcome::Invalid);
    }

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        // The retained handle permits readers only; future write and delete
        // opens fail while the version provider reopens this exact final path.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) => return observation(None, None, classify_io_error(&error)),
    };

    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return observation(None, None, classify_io_error(&error)),
    };
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > MAX_SURVEY_EXECUTABLE_BYTES
    {
        return observation(None, None, FileVersionOutcome::Invalid);
    }

    let identity = match crate::file_identity_for_open_handle(&file) {
        Ok(identity) => identity,
        Err(_) => return observation(None, None, FileVersionOutcome::Unreadable),
    };
    let digest_before = match hash_retained_file(&mut file) {
        Ok(digest) => digest,
        Err(outcome) => return observation(Some(identity), None, outcome),
    };
    let path_from_handle = match crate::final_windows_path_from_handle(&file) {
        Ok(path) => path,
        Err(_) => return observation(None, None, FileVersionOutcome::Unreadable),
    };

    let outcome = query_fixed_file_version(&path_from_handle);

    // The provider APIs accept a pathname rather than this file handle. Keep
    // the original handle open and prove it stayed the same object and bytes
    // across the provider call before retaining any resource result.
    let identity_after = crate::file_identity_for_open_handle(&file);
    let digest_after = hash_retained_file(&mut file);
    let final_length = file.metadata().map(|metadata| metadata.len());
    let identity_after = match identity_after {
        Ok(identity_after) => identity_after,
        Err(_) => return observation(None, None, FileVersionOutcome::Unreadable),
    };
    let digest_after = match digest_after {
        Ok(digest_after) => digest_after,
        Err(outcome) => return observation(None, None, outcome),
    };
    let final_length = match final_length {
        Ok(length) => length,
        Err(error) => return observation(None, None, classify_io_error(&error)),
    };
    if identity_after != identity || digest_after != digest_before || final_length != metadata.len() {
        return observation(None, None, FileVersionOutcome::Invalid);
    }

    observation(Some(identity), Some(digest_before), outcome)
}

#[cfg(windows)]
fn hash_retained_file(file: &mut std::fs::File) -> Result<String, FileVersionOutcome> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    use sha2::{Digest as _, Sha256};

    file.seek(SeekFrom::Start(0))
        .map_err(|error| classify_io_error(&error))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| classify_io_error(&error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| FileVersionOutcome::Invalid)?)
            .ok_or(FileVersionOutcome::Invalid)?;
        if total > MAX_SURVEY_EXECUTABLE_BYTES {
            return Err(FileVersionOutcome::Invalid);
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(windows)]
fn classify_io_error(error: &std::io::Error) -> FileVersionOutcome {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        ERROR_SHARING_VIOLATION,
    };

    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PATH_NOT_FOUND) => FileVersionOutcome::NotFound,
        Some(ERROR_ACCESS_DENIED) | Some(ERROR_SHARING_VIOLATION) => FileVersionOutcome::Denied,
        _ if error.kind() == std::io::ErrorKind::NotFound => FileVersionOutcome::NotFound,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => FileVersionOutcome::Denied,
        _ => FileVersionOutcome::Unreadable,
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the native resource size, pointer, structure, and field checks form one bounded parse"
)]
fn query_fixed_file_version(path: &Path) -> FileVersionOutcome {
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BAD_EXE_FORMAT, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA,
        ERROR_PATH_NOT_FOUND, ERROR_RESOURCE_DATA_NOT_FOUND, ERROR_RESOURCE_LANG_NOT_FOUND,
        ERROR_RESOURCE_NAME_NOT_FOUND, ERROR_RESOURCE_TYPE_NOT_FOUND, ERROR_SHARING_VIOLATION,
        GetLastError,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_VER_GET_NEUTRAL, GetFileVersionInfoExW, GetFileVersionInfoSizeExW,
        VS_FFI_SIGNATURE, VS_FFI_STRUCVERSION, VS_FIXEDFILEINFO, VerQueryValueW,
    };

    let mut wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide_path.contains(&0) {
        return FileVersionOutcome::Invalid;
    }
    wide_path.push(0);
    let mut ignored_translation = 0_u32;

    // SAFETY: `wide_path` is a valid NUL-terminated UTF-16 path, and the
    // translation output points to a live writable u32.
    let size = unsafe {
        GetFileVersionInfoSizeExW(
            FILE_VER_GET_NEUTRAL,
            wide_path.as_ptr(),
            &mut ignored_translation,
        )
    };
    if size == 0 {
        // SAFETY: immediately captures the error from GetFileVersionInfoSizeExW.
        let error = unsafe { GetLastError() };
        return match error {
            ERROR_RESOURCE_DATA_NOT_FOUND
            | ERROR_RESOURCE_LANG_NOT_FOUND
            | ERROR_RESOURCE_NAME_NOT_FOUND
            | ERROR_RESOURCE_TYPE_NOT_FOUND => FileVersionOutcome::Absent,
            ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION => FileVersionOutcome::Denied,
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => FileVersionOutcome::NotFound,
            ERROR_INVALID_DATA | ERROR_BAD_EXE_FORMAT => FileVersionOutcome::Invalid,
            _ => FileVersionOutcome::Unreadable,
        };
    }
    if u64::from(size) > MAX_SURVEY_EXECUTABLE_BYTES {
        return FileVersionOutcome::Invalid;
    }
    let size = match usize::try_from(size) {
        Ok(size) if u64::try_from(size).is_ok_and(|size| size <= MAX_SURVEY_EXECUTABLE_BYTES) => {
            size
        }
        _ => return FileVersionOutcome::Invalid,
    };
    let mut resource = Vec::new();
    if resource.try_reserve_exact(size).is_err() {
        return FileVersionOutcome::Unreadable;
    }
    resource.resize(size, 0);
    let size_u32 = match u32::try_from(size) {
        Ok(size) => size,
        Err(_) => return FileVersionOutcome::Invalid,
    };

    // SAFETY: the buffer is writable for its checked size and the path remains
    // bound to the caller-retained no-follow handle until this call returns.
    let populated = unsafe {
        GetFileVersionInfoExW(
            FILE_VER_GET_NEUTRAL,
            wide_path.as_ptr(),
            0,
            size_u32,
            resource.as_mut_ptr().cast(),
        )
    };
    if populated == 0 {
        // SAFETY: immediately captures the error from GetFileVersionInfoExW.
        let error = unsafe { GetLastError() };
        return match error {
            ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION => FileVersionOutcome::Denied,
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => FileVersionOutcome::NotFound,
            ERROR_INVALID_DATA | ERROR_BAD_EXE_FORMAT | ERROR_RESOURCE_DATA_NOT_FOUND
            | ERROR_RESOURCE_LANG_NOT_FOUND | ERROR_RESOURCE_NAME_NOT_FOUND
            | ERROR_RESOURCE_TYPE_NOT_FOUND => FileVersionOutcome::Invalid,
            _ => FileVersionOutcome::Unreadable,
        };
    }

    let root = ['\\' as u16, 0];
    let mut value = std::ptr::null_mut();
    let mut value_length = 0_u32;
    // SAFETY: `resource` is the live buffer produced by GetFileVersionInfoExW,
    // and both outputs point to initialized writable values.
    let found = unsafe {
        VerQueryValueW(
            resource.as_ptr().cast(),
            root.as_ptr(),
            &mut value,
            &mut value_length,
        )
    };
    if found == 0 || value.is_null() {
        return FileVersionOutcome::Invalid;
    }
    let resource_start = resource.as_ptr() as usize;
    let Some(resource_end) = resource_start.checked_add(resource.len()) else {
        return FileVersionOutcome::Invalid;
    };
    let value_start = value as usize;
    let Some(value_end) = value_start.checked_add(value_length as usize) else {
        return FileVersionOutcome::Invalid;
    };
    if value_start < resource_start || value_end > resource_end {
        return FileVersionOutcome::Invalid;
    }
    let required = match u32::try_from(std::mem::size_of::<VS_FIXEDFILEINFO>()) {
        Ok(required) => required,
        Err(_) => return FileVersionOutcome::Invalid,
    };
    if value_length < required {
        return FileVersionOutcome::Invalid;
    }
    // SAFETY: VerQueryValueW returned a non-null pointer with at least the
    // complete fixed-info structure length, validated directly above.
    let fixed = unsafe { value.cast::<VS_FIXEDFILEINFO>().read_unaligned() };
    match fixed_version_parts(
        fixed.dwSignature,
        fixed.dwStrucVersion,
        fixed.dwFileVersionMS,
        fixed.dwFileVersionLS,
        value_length,
        required,
        VS_FFI_SIGNATURE as u32,
        VS_FFI_STRUCVERSION as u32,
    ) {
        Some((file_version_ms, file_version_ls)) => FileVersionOutcome::Present {
            file_version_ms,
            file_version_ls,
        },
        None => FileVersionOutcome::Invalid,
    }
}

fn fixed_version_parts(
    signature: u32,
    structure_version: u32,
    file_version_ms: u32,
    file_version_ls: u32,
    observed_length: u32,
    required_length: u32,
    expected_signature: u32,
    expected_structure_version: u32,
) -> Option<(u32, u32)> {
    (signature == expected_signature
        && structure_version == expected_structure_version
        && observed_length >= required_length)
        .then_some((file_version_ms, file_version_ls))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_FILE_INFO_BYTES: u32 = 52;
    const VERSION_SIGNATURE: u32 = 0xFEEF_04BD;
    const STRUCTURE_VERSION: u32 = 0x0001_0000;

    #[test]
    fn retains_exact_fixed_file_version_words() {
        assert_eq!(
            fixed_version_parts(
                VERSION_SIGNATURE,
                STRUCTURE_VERSION,
                0x0001_0002,
                0x0003_0004,
                FIXED_FILE_INFO_BYTES,
                FIXED_FILE_INFO_BYTES,
                VERSION_SIGNATURE,
                STRUCTURE_VERSION,
            ),
            Some((0x0001_0002, 0x0003_0004)),
        );
    }

    #[test]
    fn malformed_fixed_file_info_is_not_reported_as_version_absence() {
        assert_eq!(
            fixed_version_parts(
                0,
                STRUCTURE_VERSION,
                1,
                2,
                FIXED_FILE_INFO_BYTES,
                FIXED_FILE_INFO_BYTES,
                VERSION_SIGNATURE,
                STRUCTURE_VERSION,
            ),
            None,
        );
        assert_eq!(
            fixed_version_parts(
                VERSION_SIGNATURE,
                STRUCTURE_VERSION,
                1,
                2,
                FIXED_FILE_INFO_BYTES - 1,
                FIXED_FILE_INFO_BYTES,
                VERSION_SIGNATURE,
                STRUCTURE_VERSION,
            ),
            None,
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_version_query_retains_the_open_executable_identity() {
        let executable = std::env::current_exe().expect("the test executable has an absolute path");
        let observed = observe_file_version(&executable);

        assert!(observed.file_identity.is_some());
        assert!(observed.sha256.is_some());
        assert!(matches!(
            observed.outcome,
            FileVersionOutcome::Present { .. } | FileVersionOutcome::Absent
        ));
    }
}
