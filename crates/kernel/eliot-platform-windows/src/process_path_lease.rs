//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01
//! Implementation: I10.8.2, I15.3, I15.5, I15.8, I15.19, I2.2, I2.23
//! Retained open handle plus ancestor pins plus actual image identity before resume; least privilege, source assurance, direct-write protection.
//! Forbidden: process/Job lifecycle, SCM, `NamedPipe`, secret, semantic, Governor, Store, default, retry, adoption, receipt/fence, mint authority.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_platform::PortError;

use crate::WindowsPlatform;
use crate::process_identity::{
    FileIdentity, ProcessIdentity, file_identity, file_identity_from_handle,
    inspect_process_identity, same_windows_path,
};
use crate::{
    is_reparse_point, provider_failed, provider_from_io, sha256_hex, valid_sha256_hex,
    validate_containment,
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
    executable_sha256: String,
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
            .field("executable_sha256", &self.executable_sha256)
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
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
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
                // Reparse metadata can be changed on a directory while its
                // identity stays the same. Do not allow a second writable
                // handle to appear while this lease is retained: otherwise
                // a junction could redirect the later CreateProcess path
                // lookup after validation has already succeeded.
                .share_mode(FILE_SHARE_READ)
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
            let mut ancestor_pins = pin_process_path_ancestors(&self.root, parent)?;
            ancestor_pins.extend(pin_process_path_ancestors(&self.root, working_directory)?);
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
                    let handle =
                        pin_process_path_directory(path).map_err(|_| PortError::InvalidPath)?;
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
                executable_sha256: expected_sha256.to_ascii_lowercase(),
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

    /// Retains a surveyed executable without requiring it to live under the
    /// Kernel work root or changing its ACL. The caller separately supplies
    /// the authenticated working-area lease for the operation cwd; this value
    /// pins only the exact executable and its existing ancestor contour.
    ///
    /// # Errors
    ///
    /// Returns a typed path/provider error when the exact non-reparse file,
    /// its bounded bytes, digest, or physical identity cannot be retained.
    pub fn retain_survey_probe_executable_lease(
        &self,
        executable: &Path,
        expected_sha256: &str,
    ) -> Result<RetainedProcessPathLease, PortError> {
        if !executable.is_absolute() || !valid_sha256_hex(expected_sha256) {
            return Err(PortError::InvalidPath);
        }
        let working_directory = executable.parent().ok_or(PortError::InvalidPath)?;
        let root = executable
            .ancestors()
            .last()
            .filter(|path| path.has_root())
            .ok_or(PortError::InvalidPath)?;
        validate_containment(root, executable)?;

        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
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
            if !executable_metadata.is_file()
                || is_reparse_point(&executable_metadata)
                || executable_metadata.len() > crate::MAX_SURVEY_EXECUTABLE_BYTES
            {
                return Err(PortError::InvalidPath);
            }
            let executable_identity = file_identity_from_handle(&executable_handle)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if executable_identity.file_index == 0 {
                return Err(PortError::InvalidPath);
            }
            let mut bytes = Vec::new();
            executable_handle
                .read_to_end(&mut bytes)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
                return Err(PortError::InvalidPath);
            }

            let mut directory_options = std::fs::OpenOptions::new();
            directory_options
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                        | FILE_FLAG_OPEN_REPARSE_POINT,
                );
            let working_directory_handle = directory_options
                .open(working_directory)
                .map_err(|_| PortError::InvalidPath)?;
            let working_metadata = working_directory_handle
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !working_metadata.is_dir() || is_reparse_point(&working_metadata) {
                return Err(PortError::InvalidPath);
            }
            let working_directory_identity = file_identity_from_handle(&working_directory_handle)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            let ancestor_pins = pin_process_path_ancestors(root, working_directory)?;
            let mut ancestor_identities = Vec::new();
            for path in executable.ancestors().take_while(|path| *path != root) {
                let handle =
                    pin_process_path_directory(path).map_err(|_| PortError::InvalidPath)?;
                let identity = file_identity_from_handle(&handle)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                ancestor_identities.push((path.to_path_buf(), identity));
            }

            Ok(RetainedProcessPathLease {
                root: root.to_path_buf(),
                executable_path: executable.to_path_buf(),
                working_directory: working_directory.to_path_buf(),
                executable_identity,
                executable_sha256: expected_sha256.to_ascii_lowercase(),
                working_directory_identity,
                executable: executable_handle,
                working_directory_handle,
                ancestor_pins,
                ancestor_identities,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, expected_sha256, working_directory, root);
            Err(PortError::Provider(provider_failed()))
        }
    }
}

impl RetainedProcessPathLease {
    /// Returns the exact path admitted for the retained executable handle.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    /// Returns the identity retained for the executable handle.
    #[must_use]
    pub const fn executable_identity(&self) -> FileIdentity {
        self.executable_identity
    }

    /// Returns the digest measured when the executable handle was retained.
    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    /// Validates the retained executable independently from its original
    /// working directory. Survey probes bind a new, operation-owned working
    /// directory after the original `ProcessRequest` is sealed; the executable
    /// proof remains the original one and is never widened to that directory.
    ///
    /// # Errors
    /// Returns `InvalidPath` or a provider error when the exact retained image
    /// path, identity, or digest cannot be established.
    pub fn validate_executable(
        &self,
        executable: &Path,
        expected_sha256: &str,
    ) -> Result<(), PortError> {
        if executable != self.executable_path
            || !valid_sha256_hex(expected_sha256)
            || !expected_sha256.eq_ignore_ascii_case(&self.executable_sha256)
        {
            return Err(PortError::InvalidPath);
        }
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut current = options
                .open(executable)
                .map_err(|_| PortError::InvalidPath)?;
            let metadata = current.metadata().map_err(|_| PortError::InvalidPath)?;
            if !metadata.is_file() || is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
            if file_identity_from_handle(&current)
                .map_err(|_| PortError::Provider(provider_failed()))?
                != self.executable_identity
            {
                return Err(PortError::InvalidPath);
            }
            let mut bytes = Vec::new();
            current
                .read_to_end(&mut bytes)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
                return Err(PortError::InvalidPath);
            }
            let _ = &self.executable;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, expected_sha256);
            Err(PortError::Provider(provider_failed()))
        }
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
                .share_mode(FILE_SHARE_READ)
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
                let handle =
                    pin_process_path_directory(path).map_err(|_| PortError::InvalidPath)?;
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

/// Opens one directory without following a final reparse point and denies
/// later writable handles while a process-path lease is retained.
///
/// The deny-write sharing mode closes the gap between path validation and
/// `CreateProcess`: a retained directory identity alone does not prevent an
/// in-place reparse-point update, which could redirect the executable or
/// working-directory lookup without renaming the directory.
#[cfg(windows)]
fn pin_process_path_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = handle.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process path directory is not a plain directory",
        ));
    }
    Ok(handle)
}

/// Retains each directory in a path contour with reparse-changing writes
/// denied until the process-path lease is dropped.
#[cfg(windows)]
fn pin_process_path_ancestors(root: &Path, path: &Path) -> Result<Vec<std::fs::File>, PortError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PortError::InvalidPath)?;
    let mut current = root.to_path_buf();
    let mut handles = vec![pin_process_path_directory(root).map_err(|_| PortError::InvalidPath)?];
    for component in relative.components() {
        current.push(component.as_os_str());
        handles.push(pin_process_path_directory(&current).map_err(|_| PortError::InvalidPath)?);
    }
    Ok(handles)
}

/// Physical `AppContainer` identity derived only from one original operation
/// identity. It creates no profile and carries no capability or authority.
/// The lowercase digest is also the closed child-directory locator beneath an
/// independently authenticated working-area root.
#[derive(Clone)]
pub struct SurveyProbeAppContainerIdentity {
    operation_id: String,
    moniker: String,
}

impl std::fmt::Debug for SurveyProbeAppContainerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SurveyProbeAppContainerIdentity")
            .field("moniker", &self.moniker)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SurveyProbeAppContainerIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id && self.moniker == other.moniker
    }
}

impl Eq for SurveyProbeAppContainerIdentity {}

impl SurveyProbeAppContainerIdentity {
    /// Derives the physical `AppContainer` moniker from an original operation
    /// identity. This is a deterministic locator only; it does not create an
    /// `AppContainer` profile or issue process authority.
    ///
    /// # Errors
    /// Returns `InvalidText` when the original operation identity is blank,
    /// unbounded, or contains control characters.
    pub fn for_operation_id(operation_id: &str) -> Result<Self, PortError> {
        if operation_id.trim().is_empty()
            || operation_id.len() > 256
            || operation_id.chars().any(char::is_control)
        {
            return Err(PortError::InvalidText {
                field: "operation_id".to_owned(),
            });
        }
        Ok(Self {
            operation_id: operation_id.to_owned(),
            moniker: sha256_hex(operation_id.as_bytes()),
        })
    }

    /// Returns the operation-owned child cwd beneath `working_area`.
    #[must_use]
    pub fn working_directory(&self, working_area: &Path) -> PathBuf {
        working_area.join(&self.moniker)
    }

    pub(crate) fn moniker(&self) -> &str {
        &self.moniker
    }
}

/// Non-serializable `AppContainer` profile created only for one original probe
/// operation. Existing profiles are refused; this lease retains the exact
/// newly-created SID until terminal tree readback and explicit deletion.
pub struct SurveyProbeAppContainerProfile {
    identity: SurveyProbeAppContainerIdentity,
    sid_text: String,
    #[cfg(windows)]
    sid: windows_sys::Win32::Security::PSID,
    active: bool,
}

// SAFETY: the profile exclusively owns the SID allocation returned by
// CreateAppContainerProfile. Moving this non-cloneable owner between executor
// threads does not change SID lifetime; all reads/deletion stay serialized by
// the single ProcessExecutor operation mutex.
#[cfg(windows)]
unsafe impl Send for SurveyProbeAppContainerProfile {}

impl std::fmt::Debug for SurveyProbeAppContainerProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SurveyProbeAppContainerProfile")
            .field("moniker", &self.identity.moniker())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl SurveyProbeAppContainerProfile {
    /// Creates a profile for the exact original operation identity with zero
    /// capability SIDs. `AlreadyExists` is refused and never adopted.
    ///
    /// # Errors
    /// Returns `InvalidPath` for an already-existing profile and a provider
    /// failure when Windows cannot create or read back the exact profile SID.
    pub fn create(identity: &SurveyProbeAppContainerIdentity) -> Result<Self, PortError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Security::Isolation::{
                CreateAppContainerProfile, DeleteAppContainerProfile,
            };

            let moniker = crate::nul_terminated_wide(std::ffi::OsStr::new(identity.moniker()))
                .map_err(|_| PortError::Provider(provider_failed()))?;
            let mut sid = std::ptr::null_mut();
            // SAFETY: each moniker pointer remains live through the call;
            // null capabilities and count zero request no capability SIDs.
            let status = unsafe {
                CreateAppContainerProfile(
                    moniker.as_ptr(),
                    moniker.as_ptr(),
                    moniker.as_ptr(),
                    std::ptr::null(),
                    0,
                    &raw mut sid,
                )
            };
            if status != 0 || sid.is_null() {
                if !sid.is_null() {
                    // SAFETY: the API allocated this returned SID.
                    unsafe { windows_sys::Win32::Security::FreeSid(sid) };
                }
                return Err(if status == 0 {
                    PortError::Provider(provider_failed())
                } else {
                    // Any failed create, including HRESULT_FROM_WIN32
                    // ERROR_ALREADY_EXISTS, is a refusal; no SID is adopted.
                    PortError::InvalidPath
                });
            }
            let Ok(sid_text) = crate::sid_to_string(sid) else {
                // Creation succeeded for this operation. Attempt only the
                // exact profile cleanup; the unique moniker is never
                // queried or adopted after this failed readback.
                let _ = unsafe { DeleteAppContainerProfile(moniker.as_ptr()) };
                // SAFETY: the API allocated this returned SID.
                unsafe { windows_sys::Win32::Security::FreeSid(sid) };
                return Err(PortError::Provider(provider_failed()));
            };
            let profile = Self {
                identity: identity.clone(),
                sid_text,
                sid,
                active: true,
            };
            let derived = DerivedSurveyAppContainerSid::derive(identity)?;
            // SAFETY: both SIDs remain live and were allocated by their
            // respective AppContainer APIs.
            if unsafe { windows_sys::Win32::Security::EqualSid(profile.sid, derived.0) } == 0 {
                let mut profile = profile;
                let _ = profile.remove();
                return Err(PortError::Provider(provider_failed()));
            }
            Ok(profile)
        }
        #[cfg(not(windows))]
        {
            let _ = identity;
            Err(PortError::Provider(provider_failed()))
        }
    }

    /// Returns the exact original-operation identity for this newly-created
    /// profile.
    #[must_use]
    pub const fn identity(&self) -> &SurveyProbeAppContainerIdentity {
        &self.identity
    }

    /// Returns the freshly-created SID's bounded canonical text projection.
    #[must_use]
    pub fn sid_text(&self) -> &str {
        &self.sid_text
    }

    /// Reports whether the profile still requires explicit cleanup.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deletes only the exact profile this value observed being created.
    ///
    /// # Errors
    /// Returns a provider failure and retains the SID/moniker when Windows
    /// does not confirm deletion, allowing original-operation reconciliation
    /// to retry without adopting another profile.
    pub fn remove(&mut self) -> Result<(), PortError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;

            if !self.active {
                return Ok(());
            }
            let moniker = crate::nul_terminated_wide(std::ffi::OsStr::new(self.identity.moniker()))
                .map_err(|_| PortError::Provider(provider_failed()))?;
            // SAFETY: moniker is the exact operation-derived name retained by
            // the profile lease; no caller-provided name reaches deletion.
            if unsafe { DeleteAppContainerProfile(moniker.as_ptr()) } != 0 {
                return Err(PortError::Provider(provider_failed()));
            }
            if !self.sid.is_null() {
                // SAFETY: CreateAppContainerProfile allocated this exact SID.
                unsafe { windows_sys::Win32::Security::FreeSid(self.sid) };
                self.sid = std::ptr::null_mut();
            }
            self.active = false;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(PortError::Provider(provider_failed()))
        }
    }

    #[cfg(windows)]
    pub(crate) const fn sid(&self) -> windows_sys::Win32::Security::PSID {
        self.sid
    }
}

impl Drop for SurveyProbeAppContainerProfile {
    fn drop(&mut self) {
        if self.active {
            let _ = self.remove();
        }
    }
}

/// Non-serializable temporary ACL and path lease for one original survey-probe
/// request. It retains the authenticated parent identity, exact executable
/// proof, operation/request binding, empty child cwd handle, and both original
/// DACLs through terminal reconciliation.
pub struct RetainedSurveyProbePathLease {
    operation_id: String,
    invocation_digest: String,
    app_container: SurveyProbeAppContainerIdentity,
    admitted_executable: Arc<RetainedProcessPathLease>,
    root_identity: FileIdentity,
    working_directory: PathBuf,
    child_identity: Option<FileIdentity>,
    #[cfg(windows)]
    root_handle: std::fs::File,
    #[cfg(windows)]
    child_handle: Option<std::fs::File>,
    #[cfg(windows)]
    original_root_dacl: DaclSnapshot,
    #[cfg(windows)]
    original_child_dacl: Option<DaclSnapshot>,
    #[cfg(windows)]
    scoped_root_dacl: Option<OwnedAclBytes>,
    #[cfg(windows)]
    scoped_child_dacl: Option<OwnedAclBytes>,
    #[cfg(windows)]
    root_dacl_may_be_changed: bool,
    #[cfg(windows)]
    child_dacl_may_be_changed: bool,
    #[cfg(windows)]
    active: bool,
}

/// Failed strict path admission, preserving the primary failure and the
/// exact native lease owner whenever directory creation or ACL mutation has
/// already happened. `lease` is absent only before native owner allocation.
pub struct SurveyProbePathAdmissionError {
    primary: PortError,
    cleanup: Option<PortError>,
    lease: Option<RetainedSurveyProbePathLease>,
}

impl std::fmt::Debug for SurveyProbePathAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SurveyProbePathAdmissionError")
            .field("primary", &self.primary)
            .field("cleanup", &self.cleanup)
            .field("lease", &self.lease)
            .finish()
    }
}

impl SurveyProbePathAdmissionError {
    fn before_owner(primary: PortError) -> Self {
        Self {
            primary,
            cleanup: None,
            lease: None,
        }
    }

    fn with_owner(
        primary: PortError,
        cleanup: Option<PortError>,
        lease: RetainedSurveyProbePathLease,
    ) -> Self {
        Self {
            primary,
            cleanup,
            lease: Some(lease),
        }
    }

    /// Returns the failure that caused strict admission to stop.
    #[must_use]
    pub fn primary_error(&self) -> &PortError {
        &self.primary
    }

    /// Returns any cleanup error without replacing the primary failure.
    #[must_use]
    pub fn cleanup_error(&self) -> Option<&PortError> {
        self.cleanup.as_ref()
    }

    /// Transfers the original errors and, when allocated, the same native
    /// path lease into the original operation owner for reconciliation.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PortError,
        Option<PortError>,
        Option<RetainedSurveyProbePathLease>,
    ) {
        (self.primary, self.cleanup, self.lease)
    }
}

impl From<PortError> for SurveyProbePathAdmissionError {
    fn from(primary: PortError) -> Self {
        Self::before_owner(primary)
    }
}

impl std::fmt::Debug for RetainedSurveyProbePathLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedSurveyProbePathLease")
            .field("operation_id", &self.operation_id)
            .field("invocation_digest", &self.invocation_digest)
            .field("root_identity", &self.root_identity)
            .field("child_identity", &self.child_identity)
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

impl RetainedSurveyProbePathLease {
    /// Returns the exact original operation identity bound to this scope.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the digest of the exact sealed `ProcessRequest` bound to this
    /// scope.
    #[must_use]
    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    /// Returns the exact admitted executable path retained for this operation.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        self.admitted_executable.executable_path()
    }

    /// Returns the exact operation-owned cwd named by the original request.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Returns the physical `AppContainer` identity consumed by suspended
    /// process creation.
    #[must_use]
    pub const fn app_container_identity(&self) -> &SurveyProbeAppContainerIdentity {
        &self.app_container
    }

    /// Returns the executable identity retained by the original admission.
    #[must_use]
    pub fn executable_identity(&self) -> FileIdentity {
        self.admitted_executable.executable_identity()
    }

    /// Returns the digest retained for the original executable admission.
    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        self.admitted_executable.executable_sha256()
    }

    /// Reports whether scoped ACL state still needs terminal restoration.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        #[cfg(windows)]
        {
            self.active
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Revalidates the original request binding and physical identities before
    /// the suspended child crosses the consuming permit/resume boundary.
    ///
    /// # Errors
    /// Returns `InvalidPath` or a provider failure when any request field,
    /// retained identity, no-follow check, or exact cwd projection differs.
    pub fn validate_request_binding(
        &self,
        executable: &Path,
        executable_sha256: &str,
        working_directory: &Path,
        operation_id: &str,
        invocation_digest: &str,
    ) -> Result<(), PortError> {
        if executable != self.admitted_executable.executable_path()
            || executable_sha256 != self.admitted_executable.executable_sha256()
            || working_directory != self.working_directory
            || operation_id != self.operation_id
            || invocation_digest != self.invocation_digest
            || SurveyProbeAppContainerIdentity::for_operation_id(operation_id)?
                != self.app_container
        {
            return Err(PortError::InvalidPath);
        }
        self.admitted_executable
            .validate_executable(executable, executable_sha256)?;
        #[cfg(windows)]
        {
            validate_survey_probe_scope(self)?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(PortError::Provider(provider_failed()))
        }
    }

    /// Restores the original parent/child DACLs and removes the exact empty
    /// operation-owned child cwd. The caller invokes this only after original
    /// executor terminal reconciliation has closed descendants and streams.
    ///
    /// # Errors
    /// Returns a provider failure when either DACL changed unexpectedly,
    /// restoration readback differs, the child is not empty, or native cleanup
    /// cannot be proven.
    pub fn restore(&mut self) -> Result<(), PortError> {
        #[cfg(windows)]
        {
            restore_survey_probe_scope(self)
        }
        #[cfg(not(windows))]
        {
            Err(PortError::Provider(provider_failed()))
        }
    }
}

impl Drop for RetainedSurveyProbePathLease {
    fn drop(&mut self) {
        if self.is_active() {
            let _ = self.restore();
        }
    }
}

/// Atomically creates the exact empty child cwd named by the original request
/// and temporarily grants LPAC only root traversal plus cwd read/execute.
///
/// The caller must already have issued the original sealed `ProcessRequest`;
/// `operation_id`, `invocation_digest`, and `working_directory` are copied
/// directly from that request. Existing paths are never adopted, executable
/// ACLs are never changed, and no parent outside `owned_area` is modified.
///
/// # Errors
/// Returns a typed path/provider error when the root, executable proof, exact
/// operation locator, atomic creation, ACL readback, or cleanup cannot be
/// established.
#[allow(clippy::result_large_err)]
pub fn retain_survey_probe_path_lease(
    owned_area: &crate::UserOwnedRootReadLease,
    admitted_executable: Arc<RetainedProcessPathLease>,
    operation_id: &str,
    invocation_digest: &str,
    working_directory: &Path,
) -> Result<RetainedSurveyProbePathLease, SurveyProbePathAdmissionError> {
    if !valid_sha256_hex(invocation_digest) {
        return Err(SurveyProbePathAdmissionError::before_owner(
            PortError::InvalidText {
                field: "invocation_digest".to_owned(),
            },
        ));
    }
    let app_container = SurveyProbeAppContainerIdentity::for_operation_id(operation_id)
        .map_err(SurveyProbePathAdmissionError::before_owner)?;
    owned_area
        .verify_path_identity()
        .map_err(|_| SurveyProbePathAdmissionError::before_owner(PortError::InvalidPath))?;
    owned_area
        .verify_stable_identity()
        .map_err(|_| SurveyProbePathAdmissionError::before_owner(PortError::InvalidPath))?;
    let root_path = owned_area
        .canonical_path()
        .map_err(|_| SurveyProbePathAdmissionError::before_owner(PortError::InvalidPath))?;
    if owned_area.identity().file_index == 0
        || admitted_executable.executable_identity().file_index == 0
        || working_directory != app_container.working_directory(&root_path)
    {
        return Err(SurveyProbePathAdmissionError::before_owner(
            PortError::InvalidPath,
        ));
    }
    admitted_executable
        .validate_executable(
            admitted_executable.executable_path(),
            admitted_executable.executable_sha256(),
        )
        .map_err(SurveyProbePathAdmissionError::before_owner)?;

    #[cfg(windows)]
    {
        create_survey_probe_scope(
            owned_area,
            admitted_executable,
            app_container,
            operation_id,
            invocation_digest,
            &root_path,
            working_directory,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (
            owned_area,
            admitted_executable,
            app_container,
            operation_id,
            invocation_digest,
            root_path,
            working_directory,
        );
        Err(SurveyProbePathAdmissionError::before_owner(
            PortError::Provider(provider_failed()),
        ))
    }
}

#[cfg(windows)]
struct OwnedAclBytes {
    words: Vec<usize>,
    length: usize,
}

#[cfg(windows)]
impl OwnedAclBytes {
    fn copy_from(acl: *const windows_sys::Win32::Security::ACL) -> Result<Self, PortError> {
        if acl.is_null() {
            return Err(PortError::Provider(provider_failed()));
        }
        // SAFETY: the caller passes a live ACL pointer returned by Windows;
        // `AclSize` is part of that validated header and bounds the copy.
        let length = usize::from(unsafe { (*acl).AclSize });
        if length < std::mem::size_of::<windows_sys::Win32::Security::ACL>() {
            return Err(PortError::Provider(provider_failed()));
        }
        let mut words = vec![0_usize; length.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: the destination is aligned and allocated for at least
        // `length` bytes; the live source ACL reports that exact bound.
        unsafe {
            std::ptr::copy_nonoverlapping(
                acl.cast::<u8>(),
                words.as_mut_ptr().cast::<u8>(),
                length,
            );
        }
        Ok(Self { words, length })
    }

    fn as_acl(&self) -> *const windows_sys::Win32::Security::ACL {
        self.words.as_ptr().cast()
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `words` owns at least `length` initialized bytes.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }

    fn matches_raw(
        &self,
        acl: *const windows_sys::Win32::Security::ACL,
    ) -> Result<bool, PortError> {
        Ok(self.bytes() == Self::copy_from(acl)?.bytes())
    }
}

#[cfg(windows)]
struct DaclSnapshot {
    owner_sid: String,
    dacl: OwnedAclBytes,
    protected: bool,
}

#[cfg(windows)]
impl DaclSnapshot {
    fn read(file: &std::fs::File) -> Result<Self, PortError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        };

        let security = OWNER_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: the retained handle is live and each output points to a
        // valid initialized slot for the Win32 result.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                security,
                &raw mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() {
            if !descriptor.is_null() {
                // SAFETY: GetSecurityInfo allocated this descriptor.
                unsafe { LocalFree(descriptor.cast()) };
            }
            return Err(PortError::Provider(provider_failed()));
        }
        let mut present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: descriptor came from GetSecurityInfo and remains live until
        // LocalFree below; outputs are valid local slots.
        let dacl_read = unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        };
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: descriptor is live and output slots are valid.
        let control_read = unsafe {
            GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
        };
        let snapshot = if dacl_read == 0 || present == 0 || dacl.is_null() || control_read == 0 {
            Err(PortError::Provider(provider_failed()))
        } else {
            crate::sid_to_string(owner)
                .map_err(|_| PortError::Provider(provider_failed()))
                .and_then(|owner_sid| {
                    OwnedAclBytes::copy_from(dacl.cast_const()).map(|dacl| Self {
                        owner_sid,
                        dacl,
                        protected: control & SE_DACL_PROTECTED != 0,
                    })
                })
        };
        // SAFETY: descriptor came from GetSecurityInfo and is freed exactly once.
        unsafe { LocalFree(descriptor.cast()) };
        snapshot
    }

    fn matches(&self, file: &std::fs::File) -> Result<bool, PortError> {
        let observed = Self::read(file)?;
        Ok(self.owner_sid == observed.owner_sid
            && self.protected == observed.protected
            && self.dacl.bytes() == observed.dacl.bytes())
    }
}

#[cfg(windows)]
struct OwnedAclBuffer(*mut windows_sys::Win32::Security::ACL);

#[cfg(windows)]
impl Drop for OwnedAclBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SetEntriesInAclW allocated this ACL with LocalAlloc.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

#[cfg(windows)]
fn acl_with_sid(
    old: &DaclSnapshot,
    sid: windows_sys::Win32::Security::PSID,
    access: u32,
) -> Result<OwnedAclBuffer, PortError> {
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SetEntriesInAclW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_W,
    };

    if sid.is_null() {
        return Err(PortError::Provider(provider_failed()));
    }
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: windows_sys::Win32::Security::NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    };
    let mut acl = std::ptr::null_mut();
    // SAFETY: `entry` and the copied old DACL remain live through the call;
    // Windows allocates the returned ACL for this wrapper to own.
    let status = unsafe { SetEntriesInAclW(1, &raw const entry, old.dacl.as_acl(), &raw mut acl) };
    if status != 0 || acl.is_null() {
        if !acl.is_null() {
            // SAFETY: SetEntriesInAclW allocated this partial result.
            unsafe { windows_sys::Win32::Foundation::LocalFree(acl.cast()) };
        }
        return Err(PortError::Provider(provider_failed()));
    }
    Ok(OwnedAclBuffer(acl))
}

#[cfg(windows)]
struct DerivedSurveyAppContainerSid(windows_sys::Win32::Security::PSID);

#[cfg(windows)]
impl DerivedSurveyAppContainerSid {
    fn derive(identity: &SurveyProbeAppContainerIdentity) -> Result<Self, PortError> {
        use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;

        let name = crate::nul_terminated_wide(std::ffi::OsStr::new(identity.moniker()))
            .map_err(|_| PortError::Provider(provider_failed()))?;
        let mut sid = std::ptr::null_mut();
        // SAFETY: the moniker buffer is NUL terminated and the result slot is
        // valid for the Win32 allocation.
        if unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &raw mut sid) } < 0
            || sid.is_null()
        {
            return Err(PortError::Provider(provider_failed()));
        }
        Ok(Self(sid))
    }
}

#[cfg(windows)]
impl Drop for DerivedSurveyAppContainerSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: DeriveAppContainerSidFromAppContainerName allocated SID.
            unsafe { windows_sys::Win32::Security::FreeSid(self.0) };
        }
    }
}

#[cfg(windows)]
#[allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    reason = "native ownership acquisition and its incomplete-cleanup handoff stay contiguous"
)]
fn create_survey_probe_scope(
    owned_area: &crate::UserOwnedRootReadLease,
    admitted_executable: Arc<RetainedProcessPathLease>,
    app_container: SurveyProbeAppContainerIdentity,
    operation_id: &str,
    invocation_digest: &str,
    root_path: &Path,
    working_directory: &Path,
) -> Result<RetainedSurveyProbePathLease, SurveyProbePathAdmissionError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    let mut root_options = std::fs::OpenOptions::new();
    root_options
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let root_handle = root_options
        .open(root_path)
        .map_err(|_| PortError::InvalidPath)?;
    let root_metadata = root_handle.metadata().map_err(|_| PortError::InvalidPath)?;
    let root_identity = file_identity_from_handle(&root_handle)
        .map_err(|_| PortError::Provider(provider_failed()))?;
    if !root_metadata.is_dir()
        || root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || root_identity != owned_area.identity()
        || file_identity_from_handle(&root_handle)
            .map_err(|_| PortError::Provider(provider_failed()))?
            != root_identity
    {
        return Err(SurveyProbePathAdmissionError::before_owner(
            PortError::InvalidPath,
        ));
    }
    let original_root_dacl = DaclSnapshot::read(&root_handle)?;
    if !original_root_dacl.protected
        || original_root_dacl.owner_sid != owned_area.current_user_sid()
    {
        return Err(SurveyProbePathAdmissionError::before_owner(
            PortError::InvalidPath,
        ));
    }
    let app_sid = DerivedSurveyAppContainerSid::derive(&app_container)?;

    // CreateDirectory is the ownership edge. An existing operation-derived
    // locator is never adopted as evidence of ownership.
    std::fs::create_dir(working_directory).map_err(|_| PortError::InvalidPath)?;
    let mut child_options = std::fs::OpenOptions::new();
    child_options
        .read(true)
        .access_mode(
            FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | WRITE_DAC
                | windows_sys::Win32::Storage::FileSystem::DELETE,
        )
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let mut lease = RetainedSurveyProbePathLease {
        operation_id: operation_id.to_owned(),
        invocation_digest: invocation_digest.to_owned(),
        app_container,
        admitted_executable,
        root_identity,
        working_directory: working_directory.to_path_buf(),
        child_identity: None,
        root_handle,
        child_handle: None,
        original_root_dacl,
        original_child_dacl: None,
        scoped_root_dacl: None,
        scoped_child_dacl: None,
        root_dacl_may_be_changed: false,
        child_dacl_may_be_changed: false,
        active: true,
    };

    let Ok(child_handle) = child_options.open(working_directory) else {
        let primary = PortError::InvalidPath;
        let cleanup = lease.restore().err();
        return Err(SurveyProbePathAdmissionError::with_owner(
            primary, cleanup, lease,
        ));
    };
    lease.child_handle = Some(child_handle);
    let child_metadata_result = lease
        .child_handle
        .as_ref()
        .map(std::fs::File::metadata)
        .transpose();
    let Ok(Some(child_metadata)) = child_metadata_result else {
        let primary = PortError::InvalidPath;
        let cleanup = lease.restore().err();
        return Err(SurveyProbePathAdmissionError::with_owner(
            primary, cleanup, lease,
        ));
    };
    let child_identity_result = lease
        .child_handle
        .as_ref()
        .map(file_identity_from_handle)
        .transpose();
    let Ok(Some(child_identity)) = child_identity_result else {
        let primary = PortError::Provider(provider_failed());
        let cleanup = lease.restore().err();
        return Err(SurveyProbePathAdmissionError::with_owner(
            primary, cleanup, lease,
        ));
    };
    lease.child_identity = Some(child_identity);
    if !child_metadata.is_dir()
        || child_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || child_identity.file_index == 0
        || !directory_is_empty_and_same_identity(working_directory, child_identity)
    {
        let primary = PortError::InvalidPath;
        let cleanup = lease.restore().err();
        return Err(SurveyProbePathAdmissionError::with_owner(
            primary, cleanup, lease,
        ));
    }
    let original_child_dacl_result = lease
        .child_handle
        .as_ref()
        .map(DaclSnapshot::read)
        .transpose();
    let original_child_dacl = match original_child_dacl_result {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            let primary = PortError::InvalidPath;
            let cleanup = lease.restore().err();
            return Err(SurveyProbePathAdmissionError::with_owner(
                primary, cleanup, lease,
            ));
        }
        Err(error) => {
            let cleanup = lease.restore().err();
            return Err(SurveyProbePathAdmissionError::with_owner(
                error, cleanup, lease,
            ));
        }
    };
    lease.original_child_dacl = Some(original_child_dacl);

    let prepared = (|| {
        let original_child_dacl = lease
            .original_child_dacl
            .as_ref()
            .ok_or(PortError::InvalidPath)?;
        let child_handle = lease.child_handle.as_ref().ok_or(PortError::InvalidPath)?;
        if !original_child_dacl.matches(child_handle)? {
            return Err(PortError::InvalidPath);
        }
        let child_acl = acl_with_sid(
            original_child_dacl,
            app_sid.0,
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE,
        )?;
        lease.scoped_child_dacl = Some(OwnedAclBytes::copy_from(child_acl.0.cast_const())?);
        lease.child_dacl_may_be_changed = true;
        set_dacl(child_handle, child_acl.0.cast_const(), true)?;
        let scoped_child_dacl = DaclSnapshot::read(child_handle)?;
        if scoped_child_dacl.owner_sid != original_child_dacl.owner_sid
            || !scoped_child_dacl.protected
            || !scoped_child_dacl
                .dacl
                .matches_raw(child_acl.0.cast_const())?
        {
            return Err(PortError::InvalidPath);
        }
        lease.scoped_child_dacl = Some(scoped_child_dacl.dacl);

        let root_acl = acl_with_sid(
            &lease.original_root_dacl,
            app_sid.0,
            windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE,
        )?;
        if !lease.original_root_dacl.matches(&lease.root_handle)? {
            return Err(PortError::InvalidPath);
        }
        lease.scoped_root_dacl = Some(OwnedAclBytes::copy_from(root_acl.0.cast_const())?);
        lease.root_dacl_may_be_changed = true;
        set_dacl(&lease.root_handle, root_acl.0.cast_const(), true)?;
        let scoped_root_dacl = DaclSnapshot::read(&lease.root_handle)?;
        if scoped_root_dacl.owner_sid != lease.original_root_dacl.owner_sid
            || !scoped_root_dacl.protected
            || !scoped_root_dacl.dacl.matches_raw(root_acl.0.cast_const())?
        {
            return Err(PortError::InvalidPath);
        }
        lease.scoped_root_dacl = Some(scoped_root_dacl.dacl);
        if !directory_is_empty_and_same_identity(&lease.working_directory, child_identity) {
            return Err(PortError::InvalidPath);
        }
        Ok(())
    })();
    match prepared {
        Ok(()) => Ok(lease),
        Err(primary) => {
            let cleanup = lease.restore().err();
            Err(SurveyProbePathAdmissionError::with_owner(
                primary, cleanup, lease,
            ))
        }
    }
}

#[cfg(windows)]
fn set_dacl(
    file: &std::fs::File,
    dacl: *const windows_sys::Win32::Security::ACL,
    protected: bool,
) -> Result<(), PortError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    if dacl.is_null() {
        return Err(PortError::Provider(provider_failed()));
    }
    let protection = if protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    // SAFETY: `file` and `dacl` are retained/live for the call; owner/group
    // and SACL remain untouched because their security information is absent.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    (status == 0)
        .then_some(())
        .ok_or_else(|| PortError::Provider(provider_failed()))
}

#[cfg(windows)]
fn directory_is_empty_and_same_identity(path: &Path, expected: FileIdentity) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let same = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .open(path)
        .ok()
        .and_then(|handle| {
            let identity = file_identity_from_handle(&handle).ok()?;
            let metadata = handle.metadata().ok()?;
            (identity == expected && metadata.is_dir() && !is_reparse_point(&metadata))
                .then_some(())
        })
        .is_some();
    same && std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}

#[cfg(windows)]
fn validate_survey_probe_scope(lease: &RetainedSurveyProbePathLease) -> Result<(), PortError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let child_handle = lease.child_handle.as_ref().ok_or(PortError::InvalidPath)?;
    let child_identity = lease.child_identity.ok_or(PortError::InvalidPath)?;
    let original_child_dacl = lease
        .original_child_dacl
        .as_ref()
        .ok_or(PortError::InvalidPath)?;
    if !lease.active
        || file_identity_from_handle(&lease.root_handle)
            .map_err(|_| PortError::Provider(provider_failed()))?
            != lease.root_identity
        || file_identity_from_handle(child_handle)
            .map_err(|_| PortError::Provider(provider_failed()))?
            != child_identity
    {
        return Err(PortError::InvalidPath);
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let current = options
        .open(&lease.working_directory)
        .map_err(|_| PortError::InvalidPath)?;
    let metadata = current.metadata().map_err(|_| PortError::InvalidPath)?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || file_identity_from_handle(&current)
            .map_err(|_| PortError::Provider(provider_failed()))?
            != child_identity
        || !directory_is_empty_and_same_identity(&lease.working_directory, child_identity)
    {
        return Err(PortError::InvalidPath);
    }
    let scoped_child = lease
        .scoped_child_dacl
        .as_ref()
        .ok_or(PortError::InvalidPath)?;
    let scoped_root = lease
        .scoped_root_dacl
        .as_ref()
        .ok_or(PortError::InvalidPath)?;
    let child = DaclSnapshot::read(child_handle)?;
    let root = DaclSnapshot::read(&lease.root_handle)?;
    if !child.protected
        || !root.protected
        || child.owner_sid != original_child_dacl.owner_sid
        || root.owner_sid != lease.original_root_dacl.owner_sid
        || child.dacl.bytes() != scoped_child.bytes()
        || root.dacl.bytes() != scoped_root.bytes()
    {
        return Err(PortError::InvalidPath);
    }
    lease.admitted_executable.validate_executable(
        lease.admitted_executable.executable_path(),
        lease.admitted_executable.executable_sha256(),
    )
}

#[cfg(windows)]
fn restore_survey_probe_scope(lease: &mut RetainedSurveyProbePathLease) -> Result<(), PortError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FILE_INFO_BY_HANDLE_CLASS, FileDispositionInfo,
        SetFileInformationByHandle,
    };

    if !lease.active {
        return Ok(());
    }
    let Some(child_identity) = lease.child_identity else {
        // The operation directory was created, but native identity could not
        // be retained. Keep this same owner active and refuse deletion.
        return Err(PortError::InvalidPath);
    };
    let Some(child_handle) = lease.child_handle.as_ref() else {
        // CreateDirectory succeeded but opening its result failed. The path is
        // retained as an unresolved owner locator and is never adopted later.
        return Err(PortError::InvalidPath);
    };
    if file_identity_from_handle(&lease.root_handle)
        .map_err(|_| PortError::Provider(provider_failed()))?
        != lease.root_identity
        || file_identity_from_handle(child_handle)
            .map_err(|_| PortError::Provider(provider_failed()))?
            != child_identity
    {
        return Err(PortError::InvalidPath);
    }

    let current_root = DaclSnapshot::read(&lease.root_handle)?;
    if let Some(scoped) = &lease.scoped_root_dacl {
        let is_original = current_root.owner_sid == lease.original_root_dacl.owner_sid
            && current_root.protected == lease.original_root_dacl.protected
            && current_root.dacl.bytes() == lease.original_root_dacl.dacl.bytes();
        let is_scoped = current_root.owner_sid == lease.original_root_dacl.owner_sid
            && current_root.protected
            && current_root.dacl.bytes() == scoped.bytes();
        if is_scoped {
            set_dacl(
                &lease.root_handle,
                lease.original_root_dacl.dacl.as_acl(),
                lease.original_root_dacl.protected,
            )?;
        } else if !is_original {
            return Err(PortError::InvalidPath);
        }
    } else if lease.root_dacl_may_be_changed {
        // A write may have partially landed, but without the exact scoped
        // bytes we cannot distinguish it from an intervening ACL change.
        // Retain the lease and refuse to rewrite an unrecognized descriptor.
        return Err(PortError::InvalidPath);
    }
    if !lease.original_root_dacl.matches(&lease.root_handle)? {
        return Err(PortError::InvalidPath);
    }
    lease.root_dacl_may_be_changed = false;

    if let Some(original_child_dacl) = lease.original_child_dacl.as_ref() {
        let current_child = DaclSnapshot::read(child_handle)?;
        if let Some(scoped) = &lease.scoped_child_dacl {
            let is_original = current_child.owner_sid == original_child_dacl.owner_sid
                && current_child.protected == original_child_dacl.protected
                && current_child.dacl.bytes() == original_child_dacl.dacl.bytes();
            let is_scoped = current_child.owner_sid == original_child_dacl.owner_sid
                && current_child.protected
                && current_child.dacl.bytes() == scoped.bytes();
            if is_scoped {
                set_dacl(
                    child_handle,
                    original_child_dacl.dacl.as_acl(),
                    original_child_dacl.protected,
                )?;
            } else if !is_original {
                return Err(PortError::InvalidPath);
            }
        } else if lease.child_dacl_may_be_changed {
            return Err(PortError::InvalidPath);
        }
        if !original_child_dacl.matches(child_handle)? {
            return Err(PortError::InvalidPath);
        }
    } else if lease.child_dacl_may_be_changed {
        return Err(PortError::InvalidPath);
    }
    lease.child_dacl_may_be_changed = false;

    if !directory_is_empty_and_same_identity(&lease.working_directory, child_identity) {
        return Err(PortError::InvalidPath);
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: this retained no-follow child handle includes DELETE access;
    // empty contents and exact identity were just read back, and the buffer
    // is the documented fixed FILE_DISPOSITION_INFO structure.
    let removed = unsafe {
        SetFileInformationByHandle(
            child_handle.as_raw_handle().cast(),
            FileDispositionInfo as FILE_INFO_BY_HANDLE_CLASS,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| PortError::Provider(provider_failed()))?,
        )
    };
    if removed == 0 {
        return Err(PortError::Provider(provider_failed()));
    }
    match std::fs::symlink_metadata(&lease.working_directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(PortError::Provider(provider_failed())),
    }
    lease.active = false;
    Ok(())
}

#[cfg(test)]
mod survey_probe_path_admission_error_tests {
    use super::SurveyProbePathAdmissionError;
    use eliot_platform::PortError;

    #[test]
    fn pre_owner_refusal_carries_no_fabricated_native_lease() {
        let error = SurveyProbePathAdmissionError::before_owner(PortError::InvalidPath);
        let (primary, cleanup, lease) = error.into_parts();

        assert!(matches!(primary, PortError::InvalidPath));
        assert!(cleanup.is_none());
        assert!(lease.is_none());
    }
}
