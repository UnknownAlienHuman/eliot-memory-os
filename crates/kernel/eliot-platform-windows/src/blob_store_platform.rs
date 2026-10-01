//! Retained-root filesystem primitives for the S-04 Blob CAS adapter.
//!
//! This module deliberately exposes byte and path mechanics only; it does not
//! depend on Blob contracts or create Blob authority. All paths are validated
//! as WorkScope-relative, checked for reparse points, and operated beneath the
//! already pinned `WindowsPlatform` root. The Store's `BlobRootOwner` lease is
//! the cross-process single-writer boundary; this type supplies durable file
//! operations within that boundary.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::{PortError, WorkScopePath};
use sha2::Digest;

use crate::{PublicationOutcome, WindowsPlatform, pin_ancestors, validate_containment};

/// Filesystem state observed through a checked `WorkScope` path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsBlobPathState {
    /// No entry exists at the target path.
    Missing,
    /// A regular file exists.
    File { length: u64, modified_unix_ms: u64 },
    /// A directory exists.
    Directory,
    /// A reparse point exists and must not be followed.
    ReparsePoint,
    /// Another filesystem entry kind exists.
    Other,
}

/// Outcome of reconciling a publication while the caller holds the original
/// operation journal and root-owner fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsBlobPublicationReconciliation {
    /// Exact bytes were observed and the file plus containing directory were
    /// flushed successfully during this reconciliation.
    ConfirmedDurable,
    /// Neither the exact source nor destination (or create destination) was
    /// present after the operation-bound observation.
    KnownAbsent,
}

/// Root-pinned durable filesystem primitive set used by the Blob adapter.
pub struct WindowsBlobStorePlatform {
    platform: WindowsPlatform,
    #[cfg(windows)]
    protected_root: crate::ProtectedRootLease,
}

impl std::fmt::Debug for WindowsBlobStorePlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsBlobStorePlatform")
            .field("root", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl WindowsBlobStorePlatform {
    /// Binds to one existing absolute non-reparse root.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PortError> {
        let root = root.into();
        let platform = WindowsPlatform::new(root.clone())?;
        #[cfg(windows)]
        let protected_root =
            crate::ProtectedRootLease::open_existing(&root).map_err(|_| PortError::InvalidPath)?;
        Ok(Self {
            platform,
            #[cfg(windows)]
            protected_root,
        })
    }

    fn verify_root_pin(&self) -> Result<(), PortError> {
        #[cfg(windows)]
        self.protected_root
            .verify_stable_identity()
            .map_err(|_| PortError::InvalidPath)?;
        Ok(())
    }

    /// Canonical identity of the pinned root, used to compare a Blob lease.
    pub fn root_identity(&self) -> Result<String, PortError> {
        self.verify_root_pin()?;
        let canonical =
            fs::canonicalize(&self.platform.root).map_err(|_| PortError::InvalidPath)?;
        validate_containment(&canonical, &canonical)?;
        let mut identity = canonical.to_string_lossy().replace('\\', "/");
        if cfg!(windows) {
            identity.make_ascii_lowercase();
        }
        Ok(identity)
    }

    /// Generation of the physical root object pinned by this adapter.
    pub fn root_generation(&self) -> Result<u64, PortError> {
        self.verify_root_pin()?;
        #[cfg(windows)]
        {
            let identity = crate::file_identity_from_handle(&self.platform.root_pin)
                .map_err(|_| PortError::InvalidPath)?;
            let material = format!("{}:{}", identity.volume_serial_number, identity.file_index);
            let digest = sha2::Sha256::digest(material.as_bytes());
            let mut prefix = [0_u8; 8];
            prefix.copy_from_slice(&digest[..8]);
            Ok(u64::from_be_bytes(prefix).max(1))
        }
        #[cfg(not(windows))]
        {
            let identity = self.root_identity()?;
            let digest = sha2::Sha256::digest(identity.as_bytes());
            let mut prefix = [0_u8; 8];
            prefix.copy_from_slice(&digest[..8]);
            Ok(u64::from_be_bytes(prefix).max(1))
        }
    }

    /// Proves the current process can create, flush, and remove an entry under
    /// the pinned root. The marker is unique, bounded, and deleted before the
    /// observation succeeds; this proves usable filesystem access, while the
    /// retained OS root lease supplies single-writer exclusivity.
    pub fn prove_root_writable(&self) -> Result<(), PortError> {
        self.verify_root_pin()?;
        let path = WorkScopePath::new(format!(".eliot-blob-access-{}", super::unique_suffix()))
            .map_err(|_| PortError::InvalidPath)?;
        let target = self.platform.resolve(&path.adapter_input())?;
        let pins = pin_ancestors(&self.platform.root, &self.platform.root)?;
        create_new_blob_file(&target, b"eliot-blob-root-access-v1")?;
        flush_pins(&pins)?;
        fs::remove_file(&target)
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        flush_pins(&pins)?;
        verify_pinned_directories(&pins)?;
        self.verify_root_pin()
    }

    /// Obtains cryptographic entropy from the Windows system provider.
    pub fn random_secret_bytes(&self, length: usize) -> Result<Vec<u8>, PortError> {
        if !(32..=4096).contains(&length) {
            return Err(PortError::InvalidPath);
        }
        let mut bytes = vec![0; length];
        crate::fill_system_random(&mut bytes).map_err(|_| {
            PortError::Provider(eliot_platform::ProviderError {
                code: eliot_platform::ProviderErrorCode::Unavailable,
                retryable: false,
            })
        })?;
        Ok(bytes)
    }

    /// Protects a receipt-issuer secret with user-scoped DPAPI.
    pub fn protect_secret_bytes(&self, secret: &[u8]) -> Result<Vec<u8>, PortError> {
        self.platform
            .protect_secret(secret)
            .map(|protected| protected.as_bytes().to_vec())
            .map_err(|_| {
                PortError::Provider(eliot_platform::ProviderError {
                    code: eliot_platform::ProviderErrorCode::Failed,
                    retryable: false,
                })
            })
    }

    /// Unprotects a DPAPI-owned receipt-issuer secret for the current user.
    pub fn unprotect_secret_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PortError> {
        let protected = crate::ProtectedSecret::from_ciphertext(ciphertext.to_vec())
            .map_err(|_| PortError::InvalidPath)?;
        self.platform
            .unprotect_secret(&protected)
            .map(|secret| secret.expose().to_vec())
            .map_err(|_| {
                PortError::Provider(eliot_platform::ProviderError {
                    code: eliot_platform::ProviderErrorCode::Failed,
                    retryable: false,
                })
            })
    }

    /// Revalidates the entire extant path and pins its parent directories.
    pub fn prove_contained(&self, path: &WorkScopePath) -> Result<(), PortError> {
        self.verify_root_pin()?;
        let (target, _pins) = self.resolve_and_pin_parent(path)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if super::is_reparse_point(&metadata) => Err(PortError::InvalidPath),
            Ok(_) => {
                self.verify_root_pin()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(PortError::Provider(super::provider_from_io(&error))),
        }
    }

    /// Reads one stable regular file through an open no-follow handle, bounded
    /// before allocation and rechecked against its original path afterward.
    pub fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, PortError> {
        self.verify_root_pin()?;
        let (target, parent_pins) = self.resolve_and_pin_parent(path)?;
        let file = open_blob_file_read(&target)?;
        let before = file
            .metadata()
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        if !before.is_file() || before.len() > max_bytes {
            return Err(PortError::InvalidPath);
        }
        let identity =
            super::file_identity_from_handle(&file).map_err(|_| PortError::InvalidPath)?;
        let modified = before
            .modified()
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        let mut bytes = Vec::new();
        let capacity = usize::try_from(before.len()).map_err(|_| PortError::InvalidPath)?;
        bytes.try_reserve_exact(capacity).map_err(|_| {
            PortError::Provider(eliot_platform::ProviderError {
                code: eliot_platform::ProviderErrorCode::Failed,
                retryable: false,
            })
        })?;
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        if bytes.len() as u64 > max_bytes
            || bytes.len() as u64 != before.len()
            || super::file_identity_from_handle(&open_blob_file_read(&target)?)
                .map_err(|_| PortError::InvalidPath)?
                != identity
            || fs::symlink_metadata(&target)
                .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?
                .modified()
                .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?
                != modified
        {
            return Err(PortError::InvalidPath);
        }
        verify_pinned_directories(&parent_pins)?;
        self.verify_root_pin()?;
        Ok(bytes)
    }

    /// Creates a new file durably without replacing an existing entry.
    pub fn write_new_durable(&self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), PortError> {
        self.ensure_parent_directories(path)?;
        let (target, parent_pins) = self.resolve_and_pin_parent(path)?;
        create_new_blob_file(&target, bytes)?;
        flush_pins(&parent_pins)?;
        verify_pinned_directories(&parent_pins)
    }

    /// Atomically replaces a file through the existing write-through Windows
    /// rename primitive and confirms the parent directory flush.
    pub fn replace_durable(&self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), PortError> {
        self.ensure_parent_directories(path)?;
        self.prove_contained(path)?;
        match self.platform.publish_atomic_outcome(path, bytes)? {
            PublicationOutcome::Published(_) => Ok(()),
            PublicationOutcome::Unknown(_) => {
                Err(PortError::Provider(eliot_platform::ProviderError {
                    code: eliot_platform::ProviderErrorCode::Failed,
                    retryable: false,
                }))
            }
        }
    }

    /// Publishes a durable no-replace name with a same-volume hard link, then
    /// removes the source name. A failure after linking remains observable as
    /// an uncertain effect to the caller, which must reconcile the original
    /// operation rather than retry blindly.
    pub fn rename_no_replace_durable(
        &self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), PortError> {
        let (source_path, source_pins) = self.resolve_and_pin_parent(source)?;
        self.ensure_parent_directories(destination)?;
        let (destination_path, destination_pins) = self.resolve_and_pin_parent(destination)?;
        self.prove_contained(source)?;
        self.prove_contained(destination)?;
        fs::hard_link(&source_path, &destination_path)
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        flush_pins(&destination_pins)?;
        fs::remove_file(&source_path)
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        flush_pins(&source_pins)?;
        verify_pinned_directories(&destination_pins)?;
        verify_pinned_directories(&source_pins)
    }

    /// Resolves a prior uncertain no-replace publication under the same
    /// durable Blob operation. It never treats matching bytes as durability:
    /// an installed destination is reopened, checked, and flushed; an exact
    /// source with a known-missing destination may be published once more
    /// under the caller's unchanged journal identity.
    pub fn reconcile_rename_publication(
        &self,
        operation_id: &str,
        idempotency_key: &str,
        source: &WorkScopePath,
        destination: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
    ) -> Result<WindowsBlobPublicationReconciliation, PortError> {
        validate_reconciliation_binding(operation_id, idempotency_key, expected_sha256, hard_ceiling)?;
        self.prove_contained(source)?;
        self.prove_contained(destination)?;
        let source_state = self.stat(source)?;
        let destination_state = self.stat(destination)?;
        if destination_state == WindowsBlobPathState::Missing
            && source_state == WindowsBlobPathState::Missing
        {
            return Ok(WindowsBlobPublicationReconciliation::KnownAbsent);
        }
        if let WindowsBlobPathState::File { .. } = destination_state {
            if !self.exact_bytes_at(destination, expected_sha256, hard_ceiling)? {
                return Err(PortError::InvalidPath);
            }
            if matches!(source_state, WindowsBlobPathState::File { .. })
                && !self.exact_bytes_at(source, expected_sha256, hard_ceiling)?
            {
                return Err(PortError::InvalidPath);
            }
            self.flush_exact_file_and_parents(destination, expected_sha256, hard_ceiling)?;
            return Ok(WindowsBlobPublicationReconciliation::ConfirmedDurable);
        }
        if destination_state != WindowsBlobPathState::Missing {
            return Err(PortError::InvalidPath);
        }
        if !matches!(source_state, WindowsBlobPathState::File { .. })
            || !self.exact_bytes_at(source, expected_sha256, hard_ceiling)?
        {
            return Err(PortError::InvalidPath);
        }

        match self.rename_no_replace_durable(source, destination) {
            Ok(()) => {}
            Err(error) => {
                let destination_state = self.stat(destination)?;
                if !matches!(destination_state, WindowsBlobPathState::File { .. })
                    || !self.exact_bytes_at(destination, expected_sha256, hard_ceiling)?
                {
                    return Err(error);
                }
            }
        }
        self.flush_exact_file_and_parents(destination, expected_sha256, hard_ceiling)?;
        Ok(WindowsBlobPublicationReconciliation::ConfirmedDurable)
    }

    /// Resolves a prior uncertain create-new publication under the same
    /// operation journal. When the exact object is absent it attempts only
    /// those original bytes; a foreign occupant is never replaced.
    pub fn reconcile_create_publication(
        &self,
        operation_id: &str,
        idempotency_key: &str,
        destination: &WorkScopePath,
        expected_sha256: &str,
        bytes: &[u8],
        hard_ceiling: u64,
    ) -> Result<WindowsBlobPublicationReconciliation, PortError> {
        validate_reconciliation_binding(operation_id, idempotency_key, expected_sha256, hard_ceiling)?;
        if bytes.len() as u64 > hard_ceiling || sha256_digest(bytes) != expected_sha256 {
            return Err(PortError::InvalidPath);
        }
        self.prove_contained(destination)?;
        match self.stat(destination)? {
            WindowsBlobPathState::File { .. } => {
                if !self.exact_bytes_at(destination, expected_sha256, hard_ceiling)? {
                    return Err(PortError::InvalidPath);
                }
                self.flush_exact_file_and_parents(destination, expected_sha256, hard_ceiling)?;
                Ok(WindowsBlobPublicationReconciliation::ConfirmedDurable)
            }
            WindowsBlobPathState::Missing => match self.write_new_durable(destination, bytes) {
                Ok(()) => {
                    self.flush_exact_file_and_parents(destination, expected_sha256, hard_ceiling)?;
                    Ok(WindowsBlobPublicationReconciliation::ConfirmedDurable)
                }
                Err(error) => match self.stat(destination)? {
                    WindowsBlobPathState::File { .. }
                        if self.exact_bytes_at(destination, expected_sha256, hard_ceiling)? =>
                    {
                        self.flush_exact_file_and_parents(destination, expected_sha256, hard_ceiling)?;
                        Ok(WindowsBlobPublicationReconciliation::ConfirmedDurable)
                    }
                    WindowsBlobPathState::Missing => {
                        let _ = error;
                        Ok(WindowsBlobPublicationReconciliation::KnownAbsent)
                    }
                    _ => Err(PortError::InvalidPath),
                },
            },
            _ => Err(PortError::InvalidPath),
        }
    }

    fn exact_bytes_at(
        &self,
        path: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
    ) -> Result<bool, PortError> {
        match self.stat(path)? {
            WindowsBlobPathState::File { length, .. } if length <= hard_ceiling => {
                Ok(sha256_digest(&self.read_bounded(path, hard_ceiling)?) == expected_sha256)
            }
            WindowsBlobPathState::Missing => Ok(false),
            _ => Err(PortError::InvalidPath),
        }
    }

    fn flush_exact_file_and_parents(
        &self,
        path: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
    ) -> Result<(), PortError> {
        self.verify_root_pin().map_err(|_| PortError::InvalidPath)?;
        let (target, parent_pins) = self.resolve_and_pin_parent(path)?;
        let mut file = open_blob_file_for_reconciliation(&target)?;
        let before = file
            .metadata()
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        if !before.is_file() || before.len() > hard_ceiling {
            return Err(PortError::InvalidPath);
        }
        let identity = super::file_identity_from_handle(&file).map_err(|_| PortError::InvalidPath)?;
        let mut bytes = Vec::new();
        let capacity = usize::try_from(before.len()).map_err(|_| PortError::InvalidPath)?;
        bytes.try_reserve_exact(capacity).map_err(|_| PortError::InvalidPath)?;
        (&mut file)
            .take(hard_ceiling.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        if bytes.len() as u64 != before.len()
            || bytes.len() as u64 > hard_ceiling
            || sha256_digest(&bytes) != expected_sha256
        {
            return Err(PortError::InvalidPath);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        file.sync_all()
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        let reopened = open_blob_file_read(&target)?;
        if super::file_identity_from_handle(&reopened).map_err(|_| PortError::InvalidPath)?
            != identity
        {
            return Err(PortError::InvalidPath);
        }
        flush_pins(&parent_pins)?;
        verify_pinned_directories(&parent_pins)?;
        self.verify_root_pin().map_err(|_| PortError::InvalidPath)
    }

    /// Removes a regular file and flushes its parent directory.
    pub fn remove_durable(&self, path: &WorkScopePath) -> Result<(), PortError> {
        let (target, parent_pins) = self.resolve_and_pin_parent(path)?;
        self.prove_contained(path)?;
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(PortError::Provider(super::provider_from_io(&error))),
        }
        flush_pins(&parent_pins)?;
        verify_pinned_directories(&parent_pins)
    }

    /// Observes one no-follow filesystem entry.
    pub fn stat(&self, path: &WorkScopePath) -> Result<WindowsBlobPathState, PortError> {
        let (target, _pins) = self.resolve_and_pin_parent(path)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if super::is_reparse_point(&metadata) => {
                Ok(WindowsBlobPathState::ReparsePoint)
            }
            Ok(metadata) if metadata.is_file() => {
                let modified = metadata
                    .modified()
                    .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
                let modified_unix_ms = modified
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX);
                Ok(WindowsBlobPathState::File {
                    length: metadata.len(),
                    modified_unix_ms,
                })
            }
            Ok(metadata) if metadata.is_dir() => Ok(WindowsBlobPathState::Directory),
            Ok(_) => Ok(WindowsBlobPathState::Other),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(WindowsBlobPathState::Missing)
            }
            Err(error) => Err(PortError::Provider(super::provider_from_io(&error))),
        }
    }

    /// Lists all descendants under one checked directory prefix.
    pub fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, PortError> {
        self.verify_root_pin()?;
        let (target, _pins) = self.resolve_and_pin_parent(prefix)?;
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(PortError::Provider(super::provider_from_io(&error))),
        };
        if !metadata.is_dir() || super::is_reparse_point(&metadata) {
            return Err(PortError::InvalidPath);
        }
        let mut entries = Vec::new();
        self.walk(prefix.normalized_identity(), &target, &mut entries)?;
        self.verify_root_pin()?;
        Ok(entries)
    }

    /// Current Unix time in milliseconds for durable metadata.
    pub fn now_unix_ms(&self) -> Result<u64, PortError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
            .map_err(|_| PortError::InvalidPath)
    }

    fn resolve_and_pin_parent(
        &self,
        path: &WorkScopePath,
    ) -> Result<(PathBuf, Vec<fs::File>), PortError> {
        let target = self.platform.resolve(&path.adapter_input())?;
        validate_containment(&self.platform.root, &target)?;
        let mut parent = target.parent().ok_or(PortError::InvalidPath)?;
        loop {
            match fs::symlink_metadata(parent) {
                Ok(metadata) => {
                    if !metadata.is_dir() || super::is_reparse_point(&metadata) {
                        return Err(PortError::InvalidPath);
                    }
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    parent = parent.parent().ok_or(PortError::InvalidPath)?;
                    if !parent.starts_with(&self.platform.root) {
                        return Err(PortError::InvalidPath);
                    }
                }
                Err(error) => return Err(PortError::Provider(super::provider_from_io(&error))),
            }
        }
        let pins = pin_ancestors(&self.platform.root, parent)?;
        Ok((target, pins))
    }

    fn ensure_parent_directories(&self, path: &WorkScopePath) -> Result<(), PortError> {
        let target = self.platform.resolve(&path.adapter_input())?;
        let parent = target.parent().ok_or(PortError::InvalidPath)?;
        let relative = parent
            .strip_prefix(&self.platform.root)
            .map_err(|_| PortError::InvalidPath)?;
        let mut current = self.platform.root.clone();
        for component in relative.components() {
            current.push(component.as_os_str());
            match fs::create_dir(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(PortError::Provider(super::provider_from_io(&error))),
            }
            let metadata = fs::symlink_metadata(&current)
                .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
            if !metadata.is_dir() || super::is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
        }
        let _pins = pin_ancestors(&self.platform.root, parent)?;
        Ok(())
    }

    fn walk(
        &self,
        prefix: &str,
        directory: &Path,
        entries: &mut Vec<WorkScopePath>,
    ) -> Result<(), PortError> {
        let _pins = pin_ancestors(&self.platform.root, directory)?;
        for entry in fs::read_dir(directory)
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?
        {
            let entry =
                entry.map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
            if super::is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let identity = format!("{prefix}/{name}");
            let path = WorkScopePath::new(identity.clone()).map_err(|_| PortError::InvalidPath)?;
            if metadata.is_dir() {
                self.walk(&identity, &entry.path(), entries)?;
            } else if metadata.is_file() {
                entries.push(path);
            } else {
                return Err(PortError::InvalidPath);
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
fn open_blob_file_read(path: &Path) -> Result<fs::File, PortError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
    if file
        .metadata()
        .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?
        .file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(PortError::InvalidPath);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_blob_file_for_reconciliation(path: &Path) -> Result<fs::File, PortError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
    let metadata = file
        .metadata()
        .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PortError::InvalidPath);
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_blob_file_for_reconciliation(path: &Path) -> Result<fs::File, PortError> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| PortError::Provider(super::provider_from_io(&error)))
}

#[cfg(not(windows))]
fn open_blob_file_read(path: &Path) -> Result<fs::File, PortError> {
    fs::File::open(path).map_err(|error| PortError::Provider(super::provider_from_io(&error)))
}

fn create_new_blob_file(path: &Path, bytes: &[u8]) -> Result<(), PortError> {
    super::create_new_file(path, bytes)
        .map_err(|error| PortError::Provider(super::provider_from_io(&error)))
}

fn verify_pinned_directories(pins: &[fs::File]) -> Result<(), PortError> {
    for pin in pins {
        let metadata = pin
            .metadata()
            .map_err(|error| PortError::Provider(super::provider_from_io(&error)))?;
        if !metadata.is_dir() || super::is_reparse_point(&metadata) {
            return Err(PortError::InvalidPath);
        }
    }
    Ok(())
}

fn flush_pins(pins: &[fs::File]) -> Result<(), PortError> {
    super::flush_directory(pins).map_err(|_| {
        PortError::Provider(eliot_platform::ProviderError {
            code: eliot_platform::ProviderErrorCode::Failed,
            retryable: false,
        })
    })
}

fn validate_reconciliation_binding(
    operation_id: &str,
    idempotency_key: &str,
    expected_sha256: &str,
    hard_ceiling: u64,
) -> Result<(), PortError> {
    if operation_id.trim().is_empty()
        || operation_id.len() > 1024
        || operation_id.chars().any(char::is_control)
        || idempotency_key.trim().is_empty()
        || idempotency_key.len() > 1024
        || idempotency_key.chars().any(char::is_control)
        || expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || hard_ceiling == 0
    {
        return Err(PortError::InvalidPath);
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}
