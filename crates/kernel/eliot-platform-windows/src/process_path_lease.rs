//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01
//! Implementation: I10.8.2, I15.3, I15.5, I15.8, I15.19, I2.2, I2.23
//! Retained open handle plus ancestor pins plus actual image identity before resume; least privilege, source assurance, direct-write protection.
//! Forbidden: process/Job lifecycle, SCM, `NamedPipe`, secret, semantic, Governor, Store, default, retry, adoption, receipt/fence, mint authority.

use std::path::{Path, PathBuf};

use eliot_platform::PortError;

use crate::WindowsPlatform;
use crate::process_identity::{
    FileIdentity, ProcessIdentity, file_identity, file_identity_from_handle,
    inspect_process_identity, same_windows_path,
};
use crate::{
    is_reparse_point, pin_ancestors, pin_directory, provider_failed, provider_from_io, sha256_hex,
    valid_sha256_hex, validate_containment,
};

/// Retained no-follow launch proof for an executable and its working scope.
///
/// The open handles and ancestor pins remain owned by this value through the
/// suspended `CreateProcess` validation and resume boundary. Reopening a path
/// is only a comparison against these retained identities; it is never the
/// sole proof of containment.
pub struct RetainedProcessPathLease {
    root: PathBuf,
    executable_path: PathBuf,
    working_directory: PathBuf,
    executable_identity: FileIdentity,
    working_directory_identity: FileIdentity,
    #[cfg(windows)]
    executable: std::fs::File,
    #[cfg(windows)]
    working_directory_handle: std::fs::File,
    #[cfg(windows)]
    ancestor_pins: Vec<std::fs::File>,
    #[cfg(windows)]
    ancestor_identities: Vec<(PathBuf, FileIdentity)>,
}

impl std::fmt::Debug for RetainedProcessPathLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProcessPathLease")
            .field("root", &self.root)
            .field("executable_path", &self.executable_path)
            .field("working_directory", &self.working_directory)
            .field("executable_identity", &self.executable_identity)
            .field(
                "working_directory_identity",
                &self.working_directory_identity,
            )
            .finish_non_exhaustive()
    }
}

impl WindowsPlatform {
    /// Retains exact no-follow handles and ancestor identities for a launch.
    ///
    /// # Errors
    ///
    /// Returns a typed path/provider error when containment, identity, or
    /// digest validation cannot be established.
    pub fn retain_process_path_lease(
        &self,
        executable: &Path,
        working_directory: &Path,
        expected_sha256: &str,
    ) -> Result<RetainedProcessPathLease, PortError> {
        if !executable.is_absolute()
            || !working_directory.is_absolute()
            || !valid_sha256_hex(expected_sha256)
        {
            return Err(PortError::InvalidPath);
        }
        validate_containment(&self.root, executable)?;
        validate_containment(&self.root, working_directory)?;
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            let mut executable_options = std::fs::OpenOptions::new();
            executable_options
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut executable_handle = executable_options
                .open(executable)
                .map_err(|_| PortError::InvalidPath)?;
            let executable_metadata = executable_handle
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !executable_metadata.is_file() || is_reparse_point(&executable_metadata) {
                return Err(PortError::InvalidPath);
            }
            let executable_identity = file_identity_from_handle(&executable_handle)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            let mut bytes = Vec::with_capacity(executable_metadata.len().try_into().unwrap_or(0));
            executable_handle
                .read_to_end(&mut bytes)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
                return Err(PortError::InvalidPath);
            }
            let mut directory_options = std::fs::OpenOptions::new();
            directory_options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                        | FILE_FLAG_OPEN_REPARSE_POINT,
                );
            let working_handle = directory_options
                .open(working_directory)
                .map_err(|_| PortError::InvalidPath)?;
            let working_metadata = working_handle
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !working_metadata.is_dir() || is_reparse_point(&working_metadata) {
                return Err(PortError::InvalidPath);
            }
            let working_directory_identity = file_identity_from_handle(&working_handle)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            let parent = executable.parent().ok_or(PortError::InvalidPath)?;
            let mut ancestor_pins = pin_ancestors(&self.root, parent)?;
            ancestor_pins.extend(pin_ancestors(&self.root, working_directory)?);
            let mut ancestor_identities = Vec::new();
            for path in executable
                .ancestors()
                .take_while(|path| *path != self.root)
                .chain(
                    working_directory
                        .ancestors()
                        .take_while(|path| *path != self.root),
                )
            {
                if path.is_dir() {
                    let handle = pin_directory(path).map_err(|_| PortError::InvalidPath)?;
                    let identity = file_identity_from_handle(&handle)
                        .map_err(|_| PortError::Provider(provider_failed()))?;
                    ancestor_identities.push((path.to_path_buf(), identity));
                }
            }
            Ok(RetainedProcessPathLease {
                root: self.root.clone(),
                executable_path: executable.to_path_buf(),
                working_directory: working_directory.to_path_buf(),
                executable_identity,
                working_directory_identity,
                executable: executable_handle,
                working_directory_handle: working_handle,
                ancestor_pins,
                ancestor_identities,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, working_directory, expected_sha256);
            Err(PortError::Provider(provider_failed()))
        }
    }
}

impl RetainedProcessPathLease {
    /// Returns the identity retained for the executable handle.
    pub const fn executable_identity(&self) -> FileIdentity {
        self.executable_identity
    }

    /// Validates current path projections against retained handles and pins.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPath` or a provider error when an identity, digest,
    /// ancestor, or no-follow check cannot be proven.
    pub fn validate(
        &self,
        executable: &Path,
        working_directory: &Path,
        expected_sha256: &str,
    ) -> Result<(), PortError> {
        if executable != self.executable_path || working_directory != self.working_directory {
            return Err(PortError::InvalidPath);
        }
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
                FILE_SHARE_WRITE,
            };
            let mut executable_options = std::fs::OpenOptions::new();
            executable_options
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut current_executable = executable_options
                .open(executable)
                .map_err(|_| PortError::InvalidPath)?;
            let metadata = current_executable
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !metadata.is_file() || is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
            if file_identity_from_handle(&current_executable)
                .map_err(|_| PortError::Provider(provider_failed()))?
                != self.executable_identity
            {
                return Err(PortError::InvalidPath);
            }
            let mut bytes = Vec::new();
            current_executable
                .read_to_end(&mut bytes)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
                return Err(PortError::InvalidPath);
            }
            let mut directory_options = std::fs::OpenOptions::new();
            directory_options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            let current_working = directory_options
                .open(working_directory)
                .map_err(|_| PortError::InvalidPath)?;
            let metadata = current_working
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !metadata.is_dir() || is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
            if file_identity_from_handle(&current_working)
                .map_err(|_| PortError::Provider(provider_failed()))?
                != self.working_directory_identity
            {
                return Err(PortError::InvalidPath);
            }
            for (path, identity) in &self.ancestor_identities {
                let handle = pin_directory(path).map_err(|_| PortError::InvalidPath)?;
                if file_identity_from_handle(&handle)
                    .map_err(|_| PortError::Provider(provider_failed()))?
                    != *identity
                {
                    return Err(PortError::InvalidPath);
                }
            }
            let _ = (
                &self.executable,
                &self.working_directory_handle,
                &self.ancestor_pins,
            );
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, working_directory, expected_sha256);
            Err(PortError::Provider(provider_failed()))
        }
    }

    /// Revalidates the retained executable/work-root/digest proof and observes
    /// the exact live process identity for one child PID.
    ///
    /// The observed image path and file identity must still project to the
    /// retained executable. Callers must compare the complete returned value
    /// across security-sensitive observations so PID reuse and image changes
    /// fail closed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPath` or a typed provider failure when the retained
    /// path proof, process query, image path, or image file identity cannot be
    /// proven.
    pub fn validate_process_identity(
        &self,
        process_id: u32,
        executable: &Path,
        working_directory: &Path,
        expected_sha256: &str,
    ) -> Result<ProcessIdentity, PortError> {
        self.validate(executable, working_directory, expected_sha256)?;
        if process_id == 0 {
            return Err(PortError::InvalidPath);
        }
        #[cfg(windows)]
        {
            let identity = inspect_process_identity(process_id)
                .map_err(|error| PortError::Provider(provider_from_io(&error)))?;
            if !same_windows_path(&identity.image_path, &executable.to_string_lossy())
                || file_identity(Path::new(&identity.image_path))
                    .map_err(|error| PortError::Provider(provider_from_io(&error)))?
                    != self.executable_identity
            {
                return Err(PortError::InvalidPath);
            }
            Ok(identity)
        }
        #[cfg(not(windows))]
        {
            let _ = process_id;
            Err(PortError::Provider(provider_failed()))
        }
    }
}
