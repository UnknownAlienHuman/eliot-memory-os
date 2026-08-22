//! Exact-identity retirement for immutable owned directory publications.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FileIdentity;

/// One exact retained child returned by an immutable directory observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryObservedEntry {
    pub file_name: String,
    pub identity: FileIdentity,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// Complete exact-name, identity and byte observation of an immutable owned
/// publication directory.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryObservation {
    pub directory_identity: FileIdentity,
    pub entries: Vec<OwnedDirectoryObservedEntry>,
}

impl OwnedDirectoryObservation {
    /// Returns a compare-and-delete precondition for this exact observation.
    #[must_use]
    pub fn retirement_precondition(&self) -> OwnedDirectoryRetirementPrecondition {
        OwnedDirectoryRetirementPrecondition {
            directory_identity: self.directory_identity,
            entries: self
                .entries
                .iter()
                .map(|entry| OwnedDirectoryRetirementEntry {
                    file_name: entry.file_name.clone(),
                    identity: entry.identity,
                    sha256: entry.sha256.clone(),
                })
                .collect(),
        }
    }

    /// Returns exact bytes for one observed canonical child.
    #[must_use]
    pub fn bytes(&self, file_name: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|entry| entry.file_name.eq_ignore_ascii_case(file_name))
            .map(|entry| entry.bytes.as_slice())
    }
}

/// Exact file identity and content fence required before retirement.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryRetirementEntry {
    /// Single canonical child name; nested paths are not accepted.
    pub file_name: String,
    /// Exact retained NTFS identity observed by the owner.
    pub identity: FileIdentity,
    /// SHA-256 of the complete file bytes observed through that identity.
    pub sha256: String,
}

/// Complete identity/content compare-and-delete fence for one owned directory.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryRetirementPrecondition {
    /// Exact retained NTFS identity of the directory itself.
    pub directory_identity: FileIdentity,
    /// Exact, complete set of regular-file children expected in the directory.
    pub entries: Vec<OwnedDirectoryRetirementEntry>,
}

impl OwnedDirectoryRetirementPrecondition {
    fn validate(&self) -> Result<(), OwnedDirectoryRetirementError> {
        if invalid_identity(self.directory_identity)
            || self.entries.is_empty()
            || self.entries.len() > 16
        {
            return Err(OwnedDirectoryRetirementError::InvalidPrecondition);
        }
        let mut names = std::collections::BTreeSet::new();
        for entry in &self.entries {
            if !valid_leaf(&entry.file_name)
                || invalid_identity(entry.identity)
                || !valid_sha256(&entry.sha256)
                || !names.insert(entry.file_name.to_ascii_lowercase())
            {
                return Err(OwnedDirectoryRetirementError::InvalidPrecondition);
            }
        }
        Ok(())
    }
}

/// A directory retirement crossed its first delete disposition but final
/// absence could not be classified. The directory is never current authority;
/// callers must rescan and surface a bounded recovery gap before continuing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryRetirementUnknown {
    /// Exact directory identity whose retirement began.
    pub directory_identity: FileIdentity,
}

/// Exact retirement outcome. A post-delete ambiguity is never returned as a
/// retryable error.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum OwnedDirectoryRetirementOutcome {
    /// The exact directory is absent after identity-bound retirement (or was
    /// already absent when reconciliation began).
    Retired,
    /// At least one delete disposition committed, but final absence is unknown.
    CommittedUnknown(OwnedDirectoryRetirementUnknown),
}

/// Failure before the first exact child delete disposition committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedDirectoryRetirementError {
    InvalidPath,
    InvalidPrecondition,
    ReparsePoint,
    IdentityMismatch,
    ContentMismatch,
    UnexpectedEntry,
    Io,
    UnsupportedPlatform,
}

impl std::fmt::Display for OwnedDirectoryRetirementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "owned directory retirement failed: {self:?}")
    }
}

impl std::error::Error for OwnedDirectoryRetirementError {}

/// Retires one immutable directory tree only after retaining and comparing its
/// exact directory identity and complete child identity/content set.
///
/// # Errors
///
/// Returns only before the first delete disposition. Once a delete commits,
/// any provider ambiguity is represented by `CommittedUnknown`.
pub fn retire_owned_directory_exact(
    path: &Path,
    expected: &OwnedDirectoryRetirementPrecondition,
) -> Result<OwnedDirectoryRetirementOutcome, OwnedDirectoryRetirementError> {
    expected.validate()?;
    #[cfg(windows)]
    {
        retire_owned_directory_exact_inner(path, expected, || {})
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(OwnedDirectoryRetirementError::UnsupportedPlatform)
    }
}

/// Reads one immutable owned directory through retained no-follow handles and
/// requires an exact complete child-name set. New writers, deletion and rename
/// are denied for every retained child through the final enumeration.
///
/// # Errors
///
/// Returns a typed error for invalid paths/names, reparse points, unexpected
/// entries, identity changes, oversized content, or provider I/O failure.
pub fn observe_owned_directory_exact(
    path: &Path,
    expected_file_names: &[&str],
    max_file_bytes: u64,
) -> Result<OwnedDirectoryObservation, OwnedDirectoryRetirementError> {
    if expected_file_names.is_empty()
        || expected_file_names.len() > 16
        || max_file_bytes == 0
        || max_file_bytes > 16 * 1024 * 1024
        || expected_file_names.iter().any(|name| !valid_leaf(name))
    {
        return Err(OwnedDirectoryRetirementError::InvalidPrecondition);
    }
    let mut expected_names = expected_file_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    expected_names.sort_unstable();
    if expected_names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(OwnedDirectoryRetirementError::InvalidPrecondition);
    }
    #[cfg(windows)]
    {
        observe_owned_directory_exact_inner(
            path,
            expected_file_names,
            &expected_names,
            max_file_bytes,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(OwnedDirectoryRetirementError::UnsupportedPlatform)
    }
}

fn invalid_identity(identity: FileIdentity) -> bool {
    identity.volume_serial_number == 0 || identity.file_index == 0
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_leaf(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', ':'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(windows)]
struct RetainedChild {
    file: std::fs::File,
    identity: FileIdentity,
}

#[cfg(windows)]
fn observe_owned_directory_exact_inner(
    path: &Path,
    expected_file_names: &[&str],
    expected_names: &[String],
    max_file_bytes: u64,
) -> Result<OwnedDirectoryObservation, OwnedDirectoryRetirementError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    crate::validate_directory_publication_absolute(path).map_err(map_directory_error)?;
    let parent = path
        .parent()
        .ok_or(OwnedDirectoryRetirementError::InvalidPath)?;
    let contour =
        crate::retain_directory_publication_contour(parent).map_err(map_directory_error)?;
    crate::verify_directory_publication_contour(&contour).map_err(map_directory_error)?;
    let expected_path = contour.canonical_parent.join(
        path.file_name()
            .ok_or(OwnedDirectoryRetirementError::InvalidPath)?,
    );
    let directory = open_directory_for_observation(&expected_path)?;
    let observed_path = crate::final_windows_path_from_handle(&directory)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    let directory_identity = crate::file_identity_from_handle(&directory)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    if !crate::windows_paths_equal(&observed_path, &expected_path)
        || invalid_identity(directory_identity)
    {
        return Err(OwnedDirectoryRetirementError::IdentityMismatch);
    }
    if read_exact_child_names(&expected_path)? != expected_names {
        return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
    }

    let mut retained = Vec::with_capacity(expected_file_names.len());
    let mut entries = Vec::with_capacity(expected_file_names.len());
    for file_name in expected_file_names {
        let child_path = expected_path.join(file_name);
        let mut file = open_file_for_observation(&child_path)?;
        let child_observed_path = crate::final_windows_path_from_handle(&file)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        let identity = crate::file_identity_from_handle(&file)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        let metadata = file
            .metadata()
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if !crate::windows_paths_equal(&child_observed_path, &child_path)
            || invalid_identity(identity)
        {
            return Err(OwnedDirectoryRetirementError::IdentityMismatch);
        }
        if metadata.len() > max_file_bytes {
            return Err(OwnedDirectoryRetirementError::ContentMismatch);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(OwnedDirectoryRetirementError::ContentMismatch);
        }
        entries.push(OwnedDirectoryObservedEntry {
            file_name: (*file_name).to_owned(),
            identity,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            bytes,
        });
        retained.push(RetainedChild { file, identity });
    }
    crate::verify_directory_publication_contour(&contour).map_err(map_directory_error)?;
    if read_exact_child_names(&expected_path)? != expected_names {
        return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
    }
    for child in &retained {
        if crate::file_identity_from_handle(&child.file)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?
            != child.identity
        {
            return Err(OwnedDirectoryRetirementError::IdentityMismatch);
        }
    }
    drop(retained);
    drop(directory);
    drop(contour);
    Ok(OwnedDirectoryObservation {
        directory_identity,
        entries,
    })
}

#[cfg(windows)]
fn retire_owned_directory_exact_inner<BeforeDelete>(
    path: &Path,
    expected: &OwnedDirectoryRetirementPrecondition,
    before_delete: BeforeDelete,
) -> Result<OwnedDirectoryRetirementOutcome, OwnedDirectoryRetirementError>
where
    BeforeDelete: FnOnce(),
{
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    crate::validate_directory_publication_absolute(path).map_err(map_directory_error)?;
    let parent = path
        .parent()
        .ok_or(OwnedDirectoryRetirementError::InvalidPath)?;
    let contour =
        crate::retain_directory_publication_contour(parent).map_err(map_directory_error)?;
    crate::verify_directory_publication_contour(&contour).map_err(map_directory_error)?;
    let expected_path = contour.canonical_parent.join(
        path.file_name()
            .ok_or(OwnedDirectoryRetirementError::InvalidPath)?,
    );
    let directory = match open_directory_for_delete(&expected_path) {
        Ok(directory) => directory,
        Err(OwnedDirectoryRetirementError::InvalidPath)
            if std::fs::symlink_metadata(&expected_path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(OwnedDirectoryRetirementOutcome::Retired);
        }
        Err(error) => return Err(error),
    };
    let directory_path = crate::final_windows_path_from_handle(&directory)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    let directory_identity = crate::file_identity_from_handle(&directory)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    if !crate::windows_paths_equal(&directory_path, &expected_path)
        || directory_identity != expected.directory_identity
    {
        return Err(OwnedDirectoryRetirementError::IdentityMismatch);
    }

    let mut expected_entries = expected.entries.clone();
    expected_entries.sort_by(|left, right| {
        left.file_name
            .to_ascii_lowercase()
            .cmp(&right.file_name.to_ascii_lowercase())
    });
    let actual_names = read_exact_child_names(&expected_path)?;
    let expected_names = expected_entries
        .iter()
        .map(|entry| entry.file_name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if actual_names != expected_names {
        return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
    }

    let mut retained = Vec::with_capacity(expected_entries.len());
    for entry in &expected_entries {
        let child_path = expected_path.join(&entry.file_name);
        let mut file = open_file_for_delete(&child_path)?;
        let observed_path = crate::final_windows_path_from_handle(&file)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        let identity = crate::file_identity_from_handle(&file)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if !crate::windows_paths_equal(&observed_path, &child_path) || identity != entry.identity {
            return Err(OwnedDirectoryRetirementError::IdentityMismatch);
        }
        let metadata = file
            .metadata()
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if metadata.len() > 1024 * 1024 {
            return Err(OwnedDirectoryRetirementError::ContentMismatch);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if format!("{:x}", Sha256::digest(&bytes)) != entry.sha256 {
            return Err(OwnedDirectoryRetirementError::ContentMismatch);
        }
        retained.push(RetainedChild { file, identity });
    }
    crate::verify_directory_publication_contour(&contour).map_err(map_directory_error)?;
    before_delete();
    if read_exact_child_names(&expected_path)? != expected_names {
        return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
    }
    for child in &retained {
        let actual = crate::file_identity_from_handle(&child.file)
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if actual != child.identity {
            return Err(OwnedDirectoryRetirementError::IdentityMismatch);
        }
    }

    let unknown = || {
        Ok(OwnedDirectoryRetirementOutcome::CommittedUnknown(
            OwnedDirectoryRetirementUnknown { directory_identity },
        ))
    };
    let mut committed = false;
    for child in retained {
        if mark_delete(&child.file).is_err() {
            return if committed {
                unknown()
            } else {
                Err(OwnedDirectoryRetirementError::Io)
            };
        }
        committed = true;
        drop(child);
    }
    if mark_delete(&directory).is_err() {
        return unknown();
    }
    drop(directory);
    drop(contour);
    match std::fs::symlink_metadata(&expected_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(OwnedDirectoryRetirementOutcome::Retired)
        }
        Ok(_) | Err(_) => unknown(),
    }
}

#[cfg(windows)]
fn read_exact_child_names(directory: &Path) -> Result<Vec<String>, OwnedDirectoryRetirementError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|_| OwnedDirectoryRetirementError::Io)? {
        let entry = entry.map_err(|_| OwnedDirectoryRetirementError::Io)?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or(OwnedDirectoryRetirementError::UnexpectedEntry)?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|_| OwnedDirectoryRetirementError::Io)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !valid_leaf(&name)
        {
            return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
        }
        names.push(name.to_ascii_lowercase());
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(windows)]
fn open_directory_for_observation(
    path: &Path,
) -> Result<std::fs::File, OwnedDirectoryRetirementError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OwnedDirectoryRetirementError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(OwnedDirectoryRetirementError::InvalidPath);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_file_for_observation(path: &Path) -> Result<std::fs::File, OwnedDirectoryRetirementError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OwnedDirectoryRetirementError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_directory_for_delete(path: &Path) -> Result<std::fs::File, OwnedDirectoryRetirementError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            OwnedDirectoryRetirementError::InvalidPath
        } else {
            OwnedDirectoryRetirementError::Io
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OwnedDirectoryRetirementError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(OwnedDirectoryRetirementError::InvalidPath);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_file_for_delete(path: &Path) -> Result<std::fs::File, OwnedDirectoryRetirementError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| OwnedDirectoryRetirementError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OwnedDirectoryRetirementError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(OwnedDirectoryRetirementError::UnexpectedEntry);
    }
    Ok(file)
}

#[cfg(windows)]
fn mark_delete(file: &std::fs::File) -> Result<(), OwnedDirectoryRetirementError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        // SAFETY: the retained handle was opened with DELETE and no delete
        // sharing, and the disposition buffer has the documented layout.
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| OwnedDirectoryRetirementError::Io)?,
        )
    };
    if ok == 0 {
        Err(OwnedDirectoryRetirementError::Io)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn map_directory_error(error: crate::DirectoryPublicationError) -> OwnedDirectoryRetirementError {
    match error {
        crate::DirectoryPublicationError::InvalidPath
        | crate::DirectoryPublicationError::AlreadyExists => {
            OwnedDirectoryRetirementError::InvalidPath
        }
        crate::DirectoryPublicationError::ReparsePoint => {
            OwnedDirectoryRetirementError::ReparsePoint
        }
        crate::DirectoryPublicationError::IdentityMismatch => {
            OwnedDirectoryRetirementError::IdentityMismatch
        }
        crate::DirectoryPublicationError::Io => OwnedDirectoryRetirementError::Io,
        crate::DirectoryPublicationError::UnsupportedPlatform => {
            OwnedDirectoryRetirementError::UnsupportedPlatform
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn identity(path: &Path) -> FileIdentity {
        let file = open_file_for_delete(path).expect("retained file");
        crate::file_identity_from_handle(&file).expect("file identity")
    }

    fn fixture() -> (std::path::PathBuf, OwnedDirectoryRetirementPrecondition) {
        let root = std::env::temp_dir().join(format!(
            "eliot-owned-directory-retirement-{}-{}",
            std::process::id(),
            crate::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("fixture root");
        let destination = root.join("bundle");
        let publication =
            crate::OwnedDirectoryPublication::create(&destination).expect("prepare publication");
        for (name, bytes) in [("a.json", b"a".as_slice()), ("b.json", b"b".as_slice())] {
            std::fs::write(publication.temporary_path().join(name), bytes).expect("child write");
        }
        let temporary_identity = publication.temporary_identity();
        publication
            .publish(temporary_identity)
            .expect("publish bundle");
        let directory = open_directory_for_delete(&destination).expect("retained directory");
        let directory_identity =
            crate::file_identity_from_handle(&directory).expect("directory identity");
        drop(directory);
        let entries = [("a.json", b"a".as_slice()), ("b.json", b"b".as_slice())]
            .into_iter()
            .map(|(name, bytes)| OwnedDirectoryRetirementEntry {
                file_name: name.to_owned(),
                identity: identity(&destination.join(name)),
                sha256: format!("{:x}", Sha256::digest(bytes)),
            })
            .collect();
        (
            destination,
            OwnedDirectoryRetirementPrecondition {
                directory_identity,
                entries,
            },
        )
    }

    #[test]
    fn exact_tree_is_retired_by_handle_identity() {
        let (path, expected) = fixture();
        let observed = observe_owned_directory_exact(&path, &["a.json", "b.json"], 64)
            .expect("exact observation");
        assert_eq!(observed.bytes("a.json"), Some(b"a".as_slice()));
        assert_eq!(observed.bytes("b.json"), Some(b"b".as_slice()));
        assert_eq!(observed.retirement_precondition(), expected);
        assert_eq!(
            retire_owned_directory_exact(&path, &expected).expect("retirement"),
            OwnedDirectoryRetirementOutcome::Retired
        );
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().expect("fixture parent"));
    }

    #[test]
    fn concurrent_child_substitution_is_blocked_and_extra_create_fails_precommit() {
        let (path, expected) = fixture();
        let child = path.join("a.json");
        let moved = path.join("a-moved.json");
        let intruder = path.join("intruder.json");
        let outcome = retire_owned_directory_exact_inner(&path, &expected, || {
            assert!(
                std::fs::rename(&child, &moved).is_err(),
                "retained no-delete-sharing child must block substitution"
            );
            std::fs::write(&intruder, b"intruder").expect("concurrent create");
        });
        assert_eq!(outcome, Err(OwnedDirectoryRetirementError::UnexpectedEntry));
        assert_eq!(std::fs::read(child).expect("original child"), b"a");
        assert!(intruder.exists());
        let _ = std::fs::remove_dir_all(path.parent().expect("fixture parent"));
    }
}
