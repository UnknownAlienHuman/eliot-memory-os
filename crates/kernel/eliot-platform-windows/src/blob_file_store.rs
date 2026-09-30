//! Reparse-safe physical file operations for the single-owner Blob service.
//!
//! This module is the platform half of S-04. It owns only bounded physical
//! access, durable file publication and handle-relative no-replace rename.
//! Blob identity, encryption, receipts, root leases and reachability remain
//! owned by `eliot-blob` and its canonical owner.

use eliot_platform::WorkScopePath;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use crate::{FileIdentity, PortError, ProtectedPathError, WindowsPlatform};

/// Refusal from the reparse-safe Blob physical file adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobFileStoreError {
    InvalidPath,
    ReparsePoint,
    NotFound,
    AlreadyExists,
    PreconditionFailed,
    UnsupportedPlatform,
    Platform(BlobFileStorePlatformFailure),
    Io(String),
    UnknownPublication,
}

impl std::fmt::Display for BlobFileStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => formatter.write_str("Blob path is invalid or outside its root"),
            Self::ReparsePoint => formatter.write_str("Blob path crosses a reparse point"),
            Self::NotFound => formatter.write_str("Blob file was not found"),
            Self::AlreadyExists => formatter.write_str("Blob destination already exists"),
            Self::PreconditionFailed => {
                formatter.write_str("Blob compare-and-replace precondition failed")
            }
            Self::UnsupportedPlatform => formatter.write_str("Blob file store requires Windows"),
            Self::Platform(source) => write!(formatter, "Blob platform operation failed: {source}"),
            Self::Io(reason) => write!(formatter, "Blob file operation failed: {reason}"),
            Self::UnknownPublication => {
                formatter.write_str("Blob replacement committed with an unknown outcome")
            }
        }
    }
}

impl std::error::Error for BlobFileStoreError {}

/// Preserves native failure categories and status across the physical Blob
/// boundary rather than reducing Windows errors to formatted text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobFileStorePlatformFailure {
    Port(PortError),
    Protected(ProtectedPathError),
    Directory(crate::DirectoryPublicationError),
    WindowsAdapter(crate::WindowsAdapterError),
    Native {
        operation: &'static str,
        status: u32,
    },
    SystemIo {
        kind: std::io::ErrorKind,
        raw_os_error: Option<i32>,
    },
}

impl std::fmt::Display for BlobFileStorePlatformFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Port(error) => write!(formatter, "path contract: {error}"),
            Self::Protected(error) => write!(formatter, "protected path: {error}"),
            Self::Directory(error) => write!(formatter, "directory operation: {error}"),
            Self::WindowsAdapter(error) => write!(formatter, "Windows adapter: {error}"),
            Self::Native { operation, status } => {
                write!(formatter, "{operation} failed with status 0x{status:08X}")
            }
            Self::SystemIo { kind, raw_os_error } => {
                write!(
                    formatter,
                    "system I/O {kind:?} (OS status {raw_os_error:?})"
                )
            }
        }
    }
}

impl std::error::Error for BlobFileStorePlatformFailure {}

/// Pinned Windows root used for physical Blob files.
///
/// Construction retains the existing `WindowsPlatform` root pin. Every
/// mutating method retains and syncs the containing directory; reads open a
/// no-follow file handle with write/delete sharing disabled. The Blob service
/// must keep its original `BlobRootOwner` claim for the full lifetime of this
/// adapter, which supplies cross-process single-owner serialization.
pub struct BlobFileStore {
    platform: WindowsPlatform,
    root_identity: FileIdentity,
}

impl std::fmt::Debug for BlobFileStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlobFileStore")
            .field("root_identity", &self.root_identity)
            .finish_non_exhaustive()
    }
}

impl BlobFileStore {
    /// Pins one existing absolute, non-reparse Blob root.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, BlobFileStoreError> {
        let platform = WindowsPlatform::new(root).map_err(map_port)?;
        let root_handle = platform.root_pin.try_clone().map_err(|error| map_io(&error))?;
        if !root_handle.metadata().map_err(|error| map_io(&error))?.is_dir() {
            return Err(BlobFileStoreError::InvalidPath);
        }
        let root_identity =
            crate::file_identity_for_open_handle(&root_handle).map_err(map_protected)?;
        Ok(Self {
            platform,
            root_identity,
        })
    }

    /// Stable identity captured from the pinned root directory handle.
    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root_identity
    }

    /// Reopens the root without following a reparse point and compares its
    /// exact file identity with the object pinned at construction.
    pub fn validate_root(&self) -> Result<(), BlobFileStoreError> {
        let (identity, _handle) =
            crate::open_no_follow_directory(self.platform.root.as_path()).map_err(map_protected)?;
        if identity != self.root_identity {
            return Err(BlobFileStoreError::InvalidPath);
        }
        Ok(())
    }

    /// Proves current effective create, read, durable-flush and handle-bound
    /// delete rights inside the pinned root. Success is based on the complete
    /// observed create/read/delete round trip, never on a configured boolean.
    pub fn prove_root_permissions(&self) -> Result<(), BlobFileStoreError> {
        #[cfg(windows)]
        {
            let parent = self.pinned_root_directory()?;
            let (_name, mut probe) = create_unique_sibling(&parent)?;
            let identity = crate::file_identity_for_open_handle(&probe).map_err(map_protected)?;
            let sample = b"eliot-blob-root-permission-proof-v1";
            let proof = (|| {
                ensure_regular_single_link(&probe)?;
                probe.write_all(sample).map_err(|error| map_io(&error))?;
                probe.sync_all().map_err(|error| map_io(&error))?;
                crate::directory_publication::sync_directory_handle(&parent)
                    .map_err(map_directory)?;
                probe.seek(SeekFrom::Start(0)).map_err(|error| map_io(&error))?;
                let mut observed = Vec::with_capacity(sample.len());
                (&mut probe)
                    .take(sample.len() as u64 + 1)
                    .read_to_end(&mut observed)
                    .map_err(|error| map_io(&error))?;
                if observed != sample
                    || crate::file_identity_for_open_handle(&probe).map_err(map_protected)?
                        != identity
                {
                    return Err(BlobFileStoreError::Io(
                        "Blob root permission probe readback differed".to_owned(),
                    ));
                }
                Ok(())
            })();
            let removed = crate::delete_owned_file_handle(probe, identity).map_err(map_protected);
            match (proof, removed) {
                (Ok(()), Ok(())) => crate::directory_publication::sync_directory_handle(&parent)
                    .map_err(map_directory),
                (Err(error), Ok(())) => {
                    let _ = crate::directory_publication::sync_directory_handle(&parent);
                    Err(error)
                }
                (_, Err(_)) => Err(BlobFileStoreError::Io(
                    "Blob root permission probe could not safely remove its owned file".to_owned(),
                )),
            }
        }
        #[cfg(not(windows))]
        {
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Loads or durably creates the purpose-specific S-04 receipt issuer key.
    ///
    /// The secret is DPAPI-protected for the current user and bound inside the
    /// protected plaintext to this pinned root's file identity and the
    /// composition owner's identity. The caller must retain the original
    /// `BlobRootOwner` claim while invoking this method. Existing, malformed,
    /// foreign-root, or undecryptable state fails closed; it is never replaced
    /// with a fresh key. The first creation uses the Windows system CSPRNG and
    /// a durable create-if-absent write, so a crash cannot silently rotate the
    /// receipt key on the next startup.
    pub fn load_or_create_receipt_issuer_key(
        &self,
        owner_identity: &str,
    ) -> Result<crate::CredentialSecret, BlobFileStoreError> {
        if owner_identity.trim().is_empty()
            || owner_identity.len() > u16::MAX as usize
            || owner_identity.chars().any(char::is_control)
        {
            return Err(BlobFileStoreError::InvalidPath);
        }
        self.validate_root()?;
        let path = WorkScopePath::new("security/receipt-issuer-key-v1.dpapi")
            .map_err(|_| BlobFileStoreError::InvalidPath)?;
        self.ensure_parent(&path)?;
        match self.read_bounded(&path, 16 * 1024) {
            Ok(ciphertext) => self.open_receipt_issuer_key(&ciphertext, owner_identity),
            Err(BlobFileStoreError::NotFound) => {
                let mut key = [0_u8; 32];
                crate::fill_system_random(&mut key).map_err(|error| {
                    BlobFileStoreError::Platform(BlobFileStorePlatformFailure::WindowsAdapter(
                        error,
                    ))
                })?;
                let mut cleartext = match self.receipt_issuer_key_frame(owner_identity, &key) {
                    Ok(cleartext) => cleartext,
                    Err(error) => {
                        key.fill(0);
                        return Err(error);
                    }
                };
                let protected = self.platform.protect_secret(&cleartext).map_err(|error| {
                    BlobFileStoreError::Platform(BlobFileStorePlatformFailure::WindowsAdapter(
                        error,
                    ))
                });
                cleartext.fill(0);
                let protected = match protected {
                    Ok(protected) => protected,
                    Err(error) => {
                        key.fill(0);
                        return Err(error);
                    }
                };
                let candidate = crate::CredentialSecret::from_bytes(key.to_vec()).map_err(|_| {
                    BlobFileStoreError::Io("Blob issuer key could not be retained".to_owned())
                });
                key.fill(0);
                let candidate = candidate?;
                match self.create_new_durable(&path, protected.as_bytes()) {
                    Ok(()) => Ok(candidate),
                    Err(BlobFileStoreError::AlreadyExists) => {
                        drop(candidate);
                        let ciphertext = self.read_bounded(&path, 16 * 1024)?;
                        self.open_receipt_issuer_key(&ciphertext, owner_identity)
                    }
                    Err(error) => {
                        drop(candidate);
                        Err(error)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    fn open_receipt_issuer_key(
        &self,
        ciphertext: &[u8],
        owner_identity: &str,
    ) -> Result<crate::CredentialSecret, BlobFileStoreError> {
        let protected = crate::ProtectedSecret::from_ciphertext(ciphertext.to_vec())
            .map_err(|_| BlobFileStoreError::InvalidPath)?;
        let cleartext = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| {
                BlobFileStoreError::Platform(BlobFileStorePlatformFailure::WindowsAdapter(error))
            })?;
        let header = self.receipt_issuer_key_header(owner_identity)?;
        let expected_len = header
            .len()
            .checked_add(32)
            .ok_or(BlobFileStoreError::InvalidPath)?;
        if cleartext.expose().len() != expected_len || !cleartext.expose().starts_with(&header) {
            return Err(BlobFileStoreError::InvalidPath);
        }
        crate::CredentialSecret::from_bytes(cleartext.expose()[header.len()..].to_vec())
            .map_err(|_| BlobFileStoreError::InvalidPath)
    }

    fn receipt_issuer_key_frame(
        &self,
        owner_identity: &str,
        key: &[u8; 32],
    ) -> Result<Vec<u8>, BlobFileStoreError> {
        let mut frame = self.receipt_issuer_key_header(owner_identity)?;
        frame.extend_from_slice(key);
        Ok(frame)
    }

    fn receipt_issuer_key_header(
        &self,
        owner_identity: &str,
    ) -> Result<Vec<u8>, BlobFileStoreError> {
        let owner_length =
            u16::try_from(owner_identity.len()).map_err(|_| BlobFileStoreError::InvalidPath)?;
        let mut header = b"eliot.s04.receipt-issuer-key.v1\0".to_vec();
        header.extend_from_slice(&self.root_identity.volume_serial_number.to_le_bytes());
        header.extend_from_slice(&self.root_identity.file_index.to_le_bytes());
        header.extend_from_slice(&owner_length.to_le_bytes());
        header.extend_from_slice(owner_identity.as_bytes());
        Ok(header)
    }

    /// Proves one typed relative path remains below the retained root and
    /// every existing parent is a regular non-reparse directory.
    pub fn prove_contained(&self, path: &WorkScopePath) -> Result<(), BlobFileStoreError> {
        self.resolve(path).map(|_| ())
    }

    /// Reads at most `max_bytes` from a retained no-follow handle and refuses
    /// a file that grows beyond that limit while the read is in progress.
    pub fn read_bounded(
        &self,
        path: &WorkScopePath,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BlobFileStoreError> {
        self.read_bounded_with_identity(path, max_bytes)
            .map(|(bytes, _)| bytes)
    }

    /// Reads bounded bytes and returns the identity of the exact no-follow
    /// object held throughout the read. Callers that later mutate the path
    /// must retain this identity as their compare-and-replace precondition.
    pub fn read_bounded_with_identity(
        &self,
        path: &WorkScopePath,
        max_bytes: u64,
    ) -> Result<(Vec<u8>, FileIdentity), BlobFileStoreError> {
        if max_bytes == 0 {
            return Err(BlobFileStoreError::InvalidPath);
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_SHARE_READ};

            let parent = self.pin_existing_parent(path)?;
            let mut file = open_file_relative(
                &parent,
                path_leaf(path)?,
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
            )?;
            let before = file.metadata().map_err(|error| map_io(&error))?;
            if !before.is_file() || before.len() > max_bytes {
                return Err(BlobFileStoreError::InvalidPath);
            }
            ensure_single_link(&file)?;
            ensure_not_reparse(&file)?;
            let identity = crate::file_identity_for_open_handle(&file).map_err(map_protected)?;
            let read_limit = max_bytes
                .checked_add(1)
                .ok_or(BlobFileStoreError::InvalidPath)?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(read_limit)
                .read_to_end(&mut bytes)
                .map_err(|error| map_io(&error))?;
            if bytes.len() as u64 > max_bytes
                || crate::file_identity_for_open_handle(&file).map_err(map_protected)? != identity
            {
                return Err(BlobFileStoreError::Io(
                    "bounded Blob read exceeded its exact object".to_owned(),
                ));
            }
            Ok((bytes, identity))
        }
        #[cfg(not(windows))]
        {
            let _ = (path, max_bytes);
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Creates one absent file, writes and flushes its bytes, then flushes the
    /// retained parent directory before success is returned.
    pub fn create_new_durable(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<(), BlobFileStoreError> {
        #[cfg(windows)]
        {
            let parent = self.ensure_parent(path)?;
            let mut file = create_file_relative(&parent, path_leaf(path)?)?;
            ensure_regular_single_link(&file)?;
            let identity = crate::file_identity_for_open_handle(&file).map_err(map_protected)?;
            file.write_all(bytes).map_err(|error| map_io(&error))?;
            file.sync_all().map_err(|error| map_io(&error))?;
            if crate::file_identity_for_open_handle(&file).map_err(map_protected)? != identity {
                return Err(BlobFileStoreError::InvalidPath);
            }
            crate::directory_publication::sync_directory_handle(&parent).map_err(map_directory)?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (path, bytes);
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Atomically replaces one regular file through its retained root-relative
    /// parent handle and requires a post-publication identity receipt.
    pub fn replace_durable(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<(), BlobFileStoreError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_GENERIC_READ, FILE_SHARE_READ,
            };

            let parent = self.ensure_parent(path)?;
            let leaf = path_leaf(path)?;
            // Keep the current destination pinned with the same no-write,
            // no-delete sharing used by compare-and-replace while staging.
            let _original = match open_file_relative(
                &parent,
                leaf,
                FILE_GENERIC_READ | DELETE,
                FILE_SHARE_READ,
            ) {
                Ok(file) => {
                    ensure_not_reparse(&file)?;
                    ensure_regular_single_link(&file)?;
                    Some(file)
                }
                Err(BlobFileStoreError::NotFound) => None,
                Err(error) => return Err(error),
            };

            let (_temporary_name, mut temporary) = create_unique_sibling(&parent)?;
            let temporary_identity =
                crate::file_identity_for_open_handle(&temporary).map_err(map_protected)?;
            let stage_result = (|| {
                ensure_regular_single_link(&temporary)?;
                temporary.write_all(bytes).map_err(|error| map_io(&error))?;
                temporary.sync_all().map_err(|error| map_io(&error))?;
                if crate::file_identity_for_open_handle(&temporary).map_err(map_protected)?
                    != temporary_identity
                {
                    return Err(BlobFileStoreError::InvalidPath);
                }
                Ok(())
            })();

            if let Err(error) = stage_result {
                return match crate::delete_owned_file_handle(temporary, temporary_identity)
                    .map_err(map_protected)
                {
                    Ok(()) => Err(error),
                    Err(_) => Err(BlobFileStoreError::UnknownPublication),
                };
            }

            if native_replace_from_handle(&temporary, &parent, leaf).is_err() {
                return Err(BlobFileStoreError::UnknownPublication);
            }
            if crate::directory_publication::sync_directory_handle(&parent).is_err() {
                return Err(BlobFileStoreError::UnknownPublication);
            }
            let Ok(published) =
                open_file_relative(&parent, leaf, FILE_GENERIC_READ, FILE_SHARE_READ)
            else {
                return Err(BlobFileStoreError::UnknownPublication);
            };
            if ensure_regular_single_link(&published).is_err()
                || !crate::file_identity_for_open_handle(&published)
                    .is_ok_and(|identity| identity == temporary_identity)
            {
                return Err(BlobFileStoreError::UnknownPublication);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (path, bytes);
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Replaces a regular file only when its identity and digest still match
    /// the values observed by the caller. The original no-follow handle is
    /// retained without write or delete sharing, so its pathname cannot be
    /// replaced between the final comparison and the handle-relative atomic
    /// rename. POSIX rename semantics let that original handle remain live
    /// until publication is durable.
    pub fn replace_durable_if_matches(
        &self,
        path: &WorkScopePath,
        expected_identity: FileIdentity,
        expected_sha256: &str,
        bytes: &[u8],
    ) -> Result<(), BlobFileStoreError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_GENERIC_READ, FILE_SHARE_READ,
            };

            if !valid_sha256(expected_sha256) {
                return Err(BlobFileStoreError::InvalidPath);
            }
            let parent = self.pin_existing_parent(path)?;
            let mut original = match open_file_relative(
                &parent,
                path_leaf(path)?,
                FILE_GENERIC_READ | DELETE,
                FILE_SHARE_READ,
            ) {
                Ok(file) => file,
                Err(BlobFileStoreError::NotFound) => {
                    return Err(BlobFileStoreError::PreconditionFailed);
                }
                Err(error) => return Err(error),
            };
            ensure_regular_single_link(&original)?;
            if crate::file_identity_for_open_handle(&original).map_err(map_protected)?
                != expected_identity
                || digest_open_file(&mut original)? != expected_sha256.to_ascii_lowercase()
            {
                return Err(BlobFileStoreError::PreconditionFailed);
            }

            let (_temporary_name, mut temporary) = create_unique_sibling(&parent)?;
            let temporary_identity =
                crate::file_identity_for_open_handle(&temporary).map_err(map_protected)?;
            let stage_result = (|| {
                ensure_regular_single_link(&temporary)?;
                temporary.write_all(bytes).map_err(|error| map_io(&error))?;
                temporary.sync_all().map_err(|error| map_io(&error))?;
                if crate::file_identity_for_open_handle(&temporary).map_err(map_protected)?
                    != temporary_identity
                {
                    return Err(BlobFileStoreError::InvalidPath);
                }
                // Recheck the retained original immediately before the atomic
                // name operation. Its share mode also prevents ordinary
                // write, delete, and rename opens while staging completes.
                if crate::file_identity_for_open_handle(&original).map_err(map_protected)?
                    != expected_identity
                    || digest_open_file(&mut original)? != expected_sha256.to_ascii_lowercase()
                {
                    return Err(BlobFileStoreError::PreconditionFailed);
                }
                Ok(())
            })();

            if let Err(error) = stage_result {
                // Before the rename succeeds the temporary name is still ours;
                // delete only the exact object created above. Once rename
                // succeeds, subsequent failures are an unknown publication.
                let cleanup = crate::delete_owned_file_handle(temporary, temporary_identity);
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(_) => Err(BlobFileStoreError::UnknownPublication),
                };
            }

            // Treat every native rename failure as an unknown outcome. The
            // held temporary handle might already name the published target,
            // so cleanup by handle could otherwise delete committed data.
            if native_replace_from_handle(&temporary, &parent, path_leaf(path)?).is_err() {
                return Err(BlobFileStoreError::UnknownPublication);
            }

            if crate::directory_publication::sync_directory_handle(&parent).is_err() {
                return Err(BlobFileStoreError::UnknownPublication);
            }
            let Ok(published) = open_file_relative(
                &parent,
                path_leaf(path)?,
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
            ) else {
                return Err(BlobFileStoreError::UnknownPublication);
            };
            if ensure_regular_single_link(&published).is_err()
                || !crate::file_identity_for_open_handle(&published)
                    .is_ok_and(|identity| identity == temporary_identity)
            {
                return Err(BlobFileStoreError::UnknownPublication);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (path, expected_identity, expected_sha256, bytes);
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Renames one regular file to an absent destination relative to a
    /// retained destination-parent handle. Windows' native no-replace rename
    /// is the commit primitive; a path-level copy/remove fallback is forbidden.
    pub fn rename_no_replace_durable(
        &self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), BlobFileStoreError> {
        #[cfg(windows)]
        {
            let source_parent = self.pin_existing_parent(source)?;
            let destination_parent = self.ensure_parent(destination)?;
            let leaf = path_leaf(destination)?;
            let source_file = open_file_relative_for_delete(&source_parent, path_leaf(source)?)?;
            ensure_regular_single_link(&source_file)?;
            let source_identity =
                crate::file_identity_for_open_handle(&source_file).map_err(map_protected)?;
            native_rename_no_replace(&source_file, &destination_parent, leaf)?;
            if crate::file_identity_for_open_handle(&source_file).map_err(map_protected)?
                != source_identity
            {
                return Err(BlobFileStoreError::InvalidPath);
            }
            crate::directory_publication::sync_directory_handle(&source_parent)
                .map_err(map_directory)?;
            crate::directory_publication::sync_directory_handle(&destination_parent)
                .map_err(map_directory)?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (source, destination);
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Removes exactly the file object opened without following a reparse
    /// point, then flushes the retained parent directory.
    pub fn remove_durable(&self, path: &WorkScopePath) -> Result<(), BlobFileStoreError> {
        #[cfg(windows)]
        {
            let parent = self.pin_existing_parent(path)?;
            let file = open_file_relative_for_delete(&parent, path_leaf(path)?)?;
            ensure_regular_single_link(&file)?;
            let identity = crate::file_identity_for_open_handle(&file).map_err(map_protected)?;
            crate::delete_owned_file_handle(file, identity).map_err(map_protected)?;
            crate::directory_publication::sync_directory_handle(&parent).map_err(map_directory)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Reports a file/directory/missing state without following a reparse
    /// point. File metadata is read from the same no-follow handle that
    /// provides the stable identity.
    pub fn stat(&self, path: &WorkScopePath) -> Result<BlobFilePathState, BlobFileStoreError> {
        self.resolve(path)?;
        let parent = match self.pin_existing_parent(path) {
            Ok(parent) => parent,
            Err(BlobFileStoreError::NotFound) => return Ok(BlobFilePathState::Missing),
            Err(error) => return Err(error),
        };
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
            };
            let file = match open_file_relative(
                &parent,
                path_leaf(path)?,
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
            ) {
                Ok(file) => file,
                Err(BlobFileStoreError::NotFound) => return Ok(BlobFilePathState::Missing),
                Err(error) => return Err(error),
            };
            let attributes = file.metadata().map_err(|error| map_io(&error))?;
            if attributes.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Ok(BlobFilePathState::ReparsePoint);
            }
            if attributes.is_dir() {
                return Ok(BlobFilePathState::Directory);
            }
            if !attributes.is_file() {
                return Ok(BlobFilePathState::Other);
            }
            ensure_single_link(&file)?;
            let identity = crate::file_identity_for_open_handle(&file).map_err(map_protected)?;
            let observed = file.metadata().map_err(|error| map_io(&error))?;
            if !observed.is_file()
                || crate::file_identity_for_open_handle(&file).map_err(map_protected)? != identity
            {
                return Err(BlobFileStoreError::InvalidPath);
            }
            let modified = observed
                .modified()
                .map_err(|error| map_io(&error))?
                .duration_since(UNIX_EPOCH)
                .map_err(|error| BlobFileStoreError::Io(error.to_string()))?
                .as_millis();
            let modified_unix_ms =
                u64::try_from(modified).map_err(|_| BlobFileStoreError::InvalidPath)?;
            Ok(BlobFilePathState::File {
                length: observed.len(),
                modified_unix_ms,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(BlobFileStoreError::UnsupportedPlatform)
        }
    }

    /// Lists regular descendants under a typed prefix. Reparse entries and
    /// non-UTF-8 names refuse the whole enumeration instead of disappearing
    /// from a completeness-sensitive Blob journal scan.
    pub fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobFileStoreError> {
        self.resolve(prefix)?;
        let mut values = Vec::new();
        #[cfg(windows)]
        {
            let parent = match self.pin_existing_parent(prefix) {
                Ok(parent) => parent,
                Err(BlobFileStoreError::NotFound) => return Ok(values),
                Err(error) => return Err(error),
            };
            let directory = match open_file_relative(
                &parent,
                path_leaf(prefix)?,
                windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
            ) {
                Ok(directory) => directory,
                Err(BlobFileStoreError::NotFound) => return Ok(values),
                Err(error) => return Err(error),
            };
            ensure_not_reparse(&directory)?;
            if !directory.metadata().map_err(|error| map_io(&error))?.is_dir() {
                return Err(BlobFileStoreError::InvalidPath);
            }
            walk_regular_files_handle(prefix, &directory, &mut values)?;
        }
        #[cfg(not(windows))]
        return Err(BlobFileStoreError::UnsupportedPlatform);
        values.sort();
        Ok(values)
    }

    fn resolve(&self, path: &WorkScopePath) -> Result<PathBuf, BlobFileStoreError> {
        self.validate_root()?;
        self.platform
            .resolve(&path.adapter_input())
            .map_err(map_port)
    }

    #[cfg(windows)]
    fn ensure_parent(&self, path: &WorkScopePath) -> Result<File, BlobFileStoreError> {
        self.resolve(path)?;
        let mut current_handle = self.pinned_root_directory()?;
        let components = path_components(path)?;
        for name in components.iter().take(components.len().saturating_sub(1)) {
            let child = match crate::directory_publication::create_owned_directory_relative(
                &current_handle,
                name,
                std::ptr::null_mut(),
            ) {
                Ok(child) => {
                    crate::directory_publication::sync_directory_handle(&current_handle)
                        .map_err(map_directory)?;
                    child
                }
                Err(crate::DirectoryPublicationError::AlreadyExists) => {
                    crate::directory_publication::open_owned_directory_relative(
                        &current_handle,
                        name,
                    )
                    .map_err(map_directory)?
                }
                Err(error) => return Err(map_directory(error)),
            };
            if !child.metadata().map_err(|error| map_io(&error))?.is_dir() {
                return Err(BlobFileStoreError::InvalidPath);
            }
            current_handle = child;
        }
        Ok(current_handle)
    }

    #[cfg(windows)]
    fn pin_existing_parent(&self, path: &WorkScopePath) -> Result<File, BlobFileStoreError> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        self.resolve(path)?;
        let mut current_handle = self.pinned_root_directory()?;
        let components = path_components(path)?;
        for name in components.iter().take(components.len().saturating_sub(1)) {
            let child = open_file_relative(
                &current_handle,
                name,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            ensure_not_reparse(&child)?;
            if !child.metadata().map_err(|error| map_io(&error))?.is_dir() {
                return Err(BlobFileStoreError::InvalidPath);
            }
            current_handle = child;
        }
        Ok(current_handle)
    }

    #[cfg(windows)]
    fn pinned_root_directory(&self) -> Result<File, BlobFileStoreError> {
        let handle = self.platform.root_pin.try_clone().map_err(|error| map_io(&error))?;
        if !handle.metadata().map_err(|error| map_io(&error))?.is_dir()
            || crate::file_identity_for_open_handle(&handle).map_err(map_protected)?
                != self.root_identity
        {
            return Err(BlobFileStoreError::InvalidPath);
        }
        Ok(handle)
    }

    #[cfg(not(windows))]
    fn ensure_parent(&self, _path: &WorkScopePath) -> Result<File, BlobFileStoreError> {
        Err(BlobFileStoreError::UnsupportedPlatform)
    }

    #[cfg(not(windows))]
    fn pin_existing_parent(&self, _path: &WorkScopePath) -> Result<File, BlobFileStoreError> {
        Err(BlobFileStoreError::UnsupportedPlatform)
    }
}

/// Physical path state corresponding to the Blob service's platform-neutral
/// state vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobFilePathState {
    Missing,
    File { length: u64, modified_unix_ms: u64 },
    Directory,
    ReparsePoint,
    Other,
}

fn validate_leaf(value: &str) -> Result<(), BlobFileStoreError> {
    crate::validate_component(value).map_err(map_port)
}

fn path_components(path: &WorkScopePath) -> Result<Vec<&str>, BlobFileStoreError> {
    let components = path.normalized_identity().split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| validate_leaf(component).is_err())
    {
        return Err(BlobFileStoreError::InvalidPath);
    }
    Ok(components)
}

fn path_leaf(path: &WorkScopePath) -> Result<&str, BlobFileStoreError> {
    path_components(path)?
        .last()
        .copied()
        .ok_or(BlobFileStoreError::InvalidPath)
}

#[cfg(windows)]
#[repr(C)]
struct BlobNativeUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[cfg(windows)]
#[repr(C)]
struct BlobNativeObjectAttributes {
    length: u32,
    root_directory: windows_sys::Win32::Foundation::HANDLE,
    object_name: *mut BlobNativeUnicodeString,
    attributes: u32,
    security_descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    security_quality_of_service: *mut std::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
struct BlobNativeIoStatusBlock {
    status: i32,
    information: usize,
}

#[cfg(windows)]
const BLOB_NATIVE_OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
#[cfg(windows)]
const BLOB_NATIVE_FILE_OPEN: u32 = 1;
#[cfg(windows)]
const BLOB_NATIVE_FILE_CREATE: u32 = 2;
#[cfg(windows)]
const BLOB_NATIVE_FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
#[cfg(windows)]
const BLOB_NATIVE_FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
#[cfg(windows)]
const BLOB_NATIVE_FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const BLOB_NATIVE_FILE_WRITE_THROUGH: u32 = 0x0000_0002;
#[cfg(windows)]
const BLOB_STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32.cast_signed();
#[cfg(windows)]
const BLOB_STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32.cast_signed();
#[cfg(windows)]
const BLOB_STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32.cast_signed();

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut windows_sys::Win32::Foundation::HANDLE,
        desired_access: u32,
        object_attributes: *mut BlobNativeObjectAttributes,
        io_status_block: *mut BlobNativeIoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut std::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        file_handle: windows_sys::Win32::Foundation::HANDLE,
        io_status_block: *mut BlobNativeIoStatusBlock,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: i32,
    ) -> i32;
}

#[cfg(windows)]
fn create_file_relative(parent: &File, name: &str) -> Result<File, BlobFileStoreError> {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };
    nt_open_relative(
        parent,
        name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
        BLOB_NATIVE_FILE_CREATE,
        FILE_ATTRIBUTE_NORMAL,
        BLOB_NATIVE_FILE_NON_DIRECTORY_FILE
            | BLOB_NATIVE_FILE_OPEN_REPARSE_POINT
            | BLOB_NATIVE_FILE_SYNCHRONOUS_IO_NONALERT
            | BLOB_NATIVE_FILE_WRITE_THROUGH,
    )
}

#[cfg(windows)]
fn open_file_relative(
    parent: &File,
    name: &str,
    desired_access: u32,
    share_access: u32,
) -> Result<File, BlobFileStoreError> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
    nt_open_relative(
        parent,
        name,
        desired_access,
        share_access,
        BLOB_NATIVE_FILE_OPEN,
        FILE_ATTRIBUTE_NORMAL,
        BLOB_NATIVE_FILE_OPEN_REPARSE_POINT | BLOB_NATIVE_FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

#[cfg(windows)]
fn open_file_relative_for_delete(parent: &File, name: &str) -> Result<File, BlobFileStoreError> {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    nt_open_relative(
        parent,
        name,
        FILE_GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        BLOB_NATIVE_FILE_OPEN,
        FILE_ATTRIBUTE_NORMAL,
        BLOB_NATIVE_FILE_OPEN_REPARSE_POINT | BLOB_NATIVE_FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

#[cfg(windows)]
fn nt_open_relative(
    parent: &File,
    name: &str,
    desired_access: u32,
    share_access: u32,
    disposition: u32,
    file_attributes: u32,
    create_options: u32,
) -> Result<File, BlobFileStoreError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    validate_leaf(name)?;
    let wide = name.encode_utf16().collect::<Vec<_>>();
    let length = u16::try_from(
        wide.len()
            .checked_mul(2)
            .ok_or(BlobFileStoreError::InvalidPath)?,
    )
    .map_err(|_| BlobFileStoreError::InvalidPath)?;
    let mut unicode = BlobNativeUnicodeString {
        length,
        maximum_length: length,
        buffer: wide.as_ptr().cast_mut(),
    };
    let mut attributes = BlobNativeObjectAttributes {
        length: u32::try_from(std::mem::size_of::<BlobNativeObjectAttributes>())
            .map_err(|_| BlobFileStoreError::InvalidPath)?,
        root_directory: parent.as_raw_handle().cast(),
        object_name: &raw mut unicode,
        attributes: BLOB_NATIVE_OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut io_status = BlobNativeIoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut raw = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the UTF-16 name, object attributes, and status storage stay
        // live for the synchronous call; RootDirectory is the retained
        // no-follow parent handle and the disposition is explicit.
        NtCreateFile(
            &raw mut raw,
            desired_access,
            &raw mut attributes,
            &raw mut io_status,
            std::ptr::null_mut(),
            file_attributes,
            share_access,
            disposition,
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(match status {
            BLOB_STATUS_OBJECT_NAME_COLLISION => BlobFileStoreError::AlreadyExists,
            BLOB_STATUS_OBJECT_NAME_NOT_FOUND | BLOB_STATUS_OBJECT_PATH_NOT_FOUND => {
                BlobFileStoreError::NotFound
            }
            _ => BlobFileStoreError::Platform(BlobFileStorePlatformFailure::Native {
                operation: "NtCreateFile",
                status: status.cast_unsigned(),
            }),
        });
    }
    if raw.is_null() {
        return Err(BlobFileStoreError::Io(
            "handle-relative Blob file open returned no handle".to_owned(),
        ));
    }
    Ok(unsafe {
        // SAFETY: successful NtCreateFile returned this newly owned handle.
        File::from_raw_handle(raw.cast())
    })
}

#[cfg(windows)]
fn ensure_not_reparse(file: &File) -> Result<(), BlobFileStoreError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if file
        .metadata()
        .map_err(|error| map_io(&error))?
        .file_attributes()
        & FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        Err(BlobFileStoreError::ReparsePoint)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn ensure_regular_single_link(file: &File) -> Result<(), BlobFileStoreError> {
    if !file.metadata().map_err(|error| map_io(&error))?.is_file() {
        return Err(BlobFileStoreError::InvalidPath);
    }
    ensure_not_reparse(file)?;
    ensure_single_link(file)
}

#[cfg(windows)]
fn ensure_single_link(file: &File) -> Result<(), BlobFileStoreError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let observed = unsafe {
        // SAFETY: the retained file handle is live and the output points to
        // initialized storage for the documented structure.
        GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information)
    };
    if observed == 0 || information.nNumberOfLinks != 1 {
        return Err(BlobFileStoreError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct BlobNativeDirectoryInformation {
    next_entry_offset: u32,
    _file_index: u32,
    _creation_time: i64,
    _last_access_time: i64,
    _last_write_time: i64,
    _change_time: i64,
    _end_of_file: i64,
    _allocation_size: i64,
    file_attributes: u32,
    file_name_length: u32,
    file_name: [u16; 0],
}

#[cfg(windows)]
const BLOB_FILE_DIRECTORY_INFORMATION_CLASS: i32 = 1;
#[cfg(windows)]
const BLOB_STATUS_NO_MORE_FILES: i32 = 0x8000_0006_u32.cast_signed();
#[cfg(windows)]
const BLOB_FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
#[cfg(windows)]
const BLOB_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryDirectoryFile(
        file_handle: windows_sys::Win32::Foundation::HANDLE,
        event: windows_sys::Win32::Foundation::HANDLE,
        apc_routine: *mut std::ffi::c_void,
        apc_context: *mut std::ffi::c_void,
        io_status_block: *mut BlobNativeIoStatusBlock,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: i32,
        return_single_entry: u8,
        file_name: *mut BlobNativeUnicodeString,
        restart_scan: u8,
    ) -> i32;
}

#[cfg(windows)]
fn walk_regular_files_handle(
    prefix: &WorkScopePath,
    directory: &File,
    output: &mut Vec<WorkScopePath>,
) -> Result<(), BlobFileStoreError> {
    use std::os::windows::io::AsRawHandle;

    let mut restart_scan = true;
    loop {
        // The native directory query is handle-based. Its fixed buffer is a
        // transfer window only; the scan continues until STATUS_NO_MORE_FILES.
        let mut storage = vec![0_u64; 8192];
        let byte_length = u32::try_from(storage.len() * std::mem::size_of::<u64>())
            .map_err(|_| BlobFileStoreError::InvalidPath)?;
        let mut io_status = BlobNativeIoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            // SAFETY: the directory handle is live and queried synchronously;
            // the aligned output buffer and status block remain writable until
            // the native call returns. No asynchronous APC is requested.
            NtQueryDirectoryFile(
                directory.as_raw_handle().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut io_status,
                storage.as_mut_ptr().cast(),
                byte_length,
                BLOB_FILE_DIRECTORY_INFORMATION_CLASS,
                0,
                std::ptr::null_mut(),
                u8::from(restart_scan),
            )
        };
        restart_scan = false;
        if status == BLOB_STATUS_NO_MORE_FILES {
            return Ok(());
        }
        if status < 0 {
            return Err(BlobFileStoreError::Platform(
                BlobFileStorePlatformFailure::Native {
                    operation: "NtQueryDirectoryFile",
                    status: status.cast_unsigned(),
                },
            ));
        }
        let available = io_status.information;
        if available > storage.len() * std::mem::size_of::<u64>() {
            return Err(BlobFileStoreError::InvalidPath);
        }
        let bytes = unsafe {
            // SAFETY: the native call initialized `available` bytes in the
            // aligned backing allocation, and the bound above proves the slice.
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), available)
        };
        decode_regular_file_records(prefix, directory, bytes, output)?;
    }
}

#[cfg(windows)]
fn decode_regular_file_records(
    prefix: &WorkScopePath,
    directory: &File,
    bytes: &[u8],
    output: &mut Vec<WorkScopePath>,
) -> Result<(), BlobFileStoreError> {
    let available = bytes.len();
    let header = std::mem::size_of::<BlobNativeDirectoryInformation>();
    if std::mem::offset_of!(BlobNativeDirectoryInformation, file_name) != header {
        return Err(BlobFileStoreError::InvalidPath);
    }
    let mut offset = 0_usize;
    while offset < available {
        if available - offset < header {
            return Err(BlobFileStoreError::InvalidPath);
        }
        let information = unsafe {
            // SAFETY: `header` is the exact struct size and the bound above
            // proves that many initialized native bytes remain. Reads are
            // unaligned because records are byte-packed.
            std::ptr::read_unaligned(
                bytes
                    .as_ptr()
                    .add(offset)
                    .cast::<BlobNativeDirectoryInformation>(),
            )
        };
        let name_length = usize::try_from(information.file_name_length)
            .map_err(|_| BlobFileStoreError::InvalidPath)?;
        if name_length % 2 != 0 || name_length > available - offset - header {
            return Err(BlobFileStoreError::InvalidPath);
        }
        let record_end = if information.next_entry_offset == 0 {
            available
        } else {
            let next = usize::try_from(information.next_entry_offset)
                .map_err(|_| BlobFileStoreError::InvalidPath)?;
            if next < header + name_length || next > available - offset {
                return Err(BlobFileStoreError::InvalidPath);
            }
            offset + next
        };
        let name_start = offset + header;
        let name_units = bytes[name_start..name_start + name_length]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let name =
            String::from_utf16(&name_units).map_err(|_| BlobFileStoreError::InvalidPath)?;
        if name != "." && name != ".." {
            validate_leaf(&name)?;
            if information.file_attributes & BLOB_FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(BlobFileStoreError::ReparsePoint);
            }
            let relative =
                WorkScopePath::new(format!("{}/{name}", prefix.normalized_identity()))
                    .map_err(|_| BlobFileStoreError::InvalidPath)?;
            if information.file_attributes & BLOB_FILE_ATTRIBUTE_DIRECTORY != 0 {
                let child = crate::directory_publication::open_owned_directory_relative(
                    directory, &name,
                )
                .map_err(map_directory)?;
                walk_regular_files_handle(&relative, &child, output)?;
            } else {
                let child = open_file_relative(
                    directory,
                    &name,
                    windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
                    windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ,
                )?;
                ensure_regular_single_link(&child)?;
                output.push(relative);
            }
        }
        if information.next_entry_offset == 0 {
            break;
        }
        offset = record_end;
    }
    Ok(())
}

#[cfg(windows)]
fn native_rename_no_replace(
    source: &File,
    destination_parent: &File,
    leaf: &str,
) -> Result<(), BlobFileStoreError> {
    validate_leaf(leaf)?;
    crate::directory_publication::rename_directory_from_handle(source, destination_parent, leaf)
        .map_err(map_directory)
}

#[cfg(windows)]
fn native_replace_from_handle(
    source: &File,
    destination_parent: &File,
    leaf: &str,
) -> Result<(), BlobFileStoreError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::WindowsProgramming::{
        FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
    };

    validate_leaf(leaf)?;
    let name = leaf.encode_utf16().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(BlobFileStoreError::InvalidPath)?;
    let header_bytes = std::mem::size_of::<BlobNativeFileRenameInformationEx>()
        .checked_sub(std::mem::size_of::<u16>())
        .ok_or_else(|| BlobFileStoreError::Io("invalid native rename layout".to_owned()))?;
    let total_bytes = header_bytes
        .checked_add(name_bytes)
        .ok_or_else(|| BlobFileStoreError::Io("native rename buffer overflow".to_owned()))?;
    let word_count = total_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or_else(|| BlobFileStoreError::Io("native rename buffer overflow".to_owned()))?
        / std::mem::size_of::<usize>();
    let mut storage = vec![0_usize; word_count];
    let information = storage
        .as_mut_ptr()
        .cast::<BlobNativeFileRenameInformationEx>();
    unsafe {
        // SAFETY: the aligned storage has enough room for the native header
        // and UTF-16 leaf; both handles remain live for the synchronous call.
        // POSIX replace semantics permit replacing the destination while its
        // original handle remains open. That handle's share mode denies
        // competing ordinary pathname replacements before this operation.
        (*information).flags =
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*information).padding = 0;
        (*information).root_directory = destination_parent.as_raw_handle().cast();
        (*information).file_name_length =
            u32::try_from(name_bytes).map_err(|_| BlobFileStoreError::InvalidPath)?;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (*information).file_name.as_mut_ptr(),
            name.len(),
        );
    }
    let mut io_status = BlobNativeIoStatusBlock {
        status: 0,
        information: 0,
    };
    let status = unsafe {
        // SAFETY: `source` is our durable staged file, destination parent is
        // pinned below the root, and the rename buffer is valid through call.
        NtSetInformationFile(
            source.as_raw_handle().cast(),
            &raw mut io_status,
            information.cast(),
            u32::try_from(total_bytes).map_err(|_| BlobFileStoreError::InvalidPath)?,
            65, // FileRenameInformationEx
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(BlobFileStoreError::Platform(
            BlobFileStorePlatformFailure::Native {
                operation: "NtSetInformationFile(FileRenameInformationEx)",
                status: status.cast_unsigned(),
            },
        ))
    }
}

#[cfg(windows)]
#[repr(C)]
struct BlobNativeFileRenameInformationEx {
    flags: u32,
    padding: u32,
    root_directory: windows_sys::Win32::Foundation::HANDLE,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[cfg(windows)]
fn create_unique_sibling(parent: &File) -> Result<(String, File), BlobFileStoreError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for _ in 0..32 {
        let mut random = [0_u8; 16];
        crate::fill_system_random(&mut random).map_err(|error| {
            BlobFileStoreError::Platform(BlobFileStorePlatformFailure::WindowsAdapter(error))
        })?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            suffix.push(char::from(HEX[usize::from(byte >> 4)]));
            suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        let leaf = format!(".eliot-blob-cas-{suffix}.tmp");
        match create_file_relative(parent, &leaf) {
            Ok(file) => return Ok((leaf, file)),
            Err(BlobFileStoreError::AlreadyExists) => {}
            Err(error) => return Err(error),
        }
    }
    Err(BlobFileStoreError::AlreadyExists)
}

#[cfg(windows)]
fn digest_open_file(file: &mut File) -> Result<String, BlobFileStoreError> {
    use sha2::{Digest, Sha256};

    let identity_before = crate::file_identity_for_open_handle(file).map_err(map_protected)?;
    let length_before = file.metadata().map_err(|error| map_io(&error))?.len();
    file.seek(SeekFrom::Start(0)).map_err(|error| map_io(&error))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut read_total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|error| map_io(&error))?;
        if count == 0 {
            break;
        }
        read_total = read_total
            .checked_add(count as u64)
            .ok_or(BlobFileStoreError::InvalidPath)?;
        digest.update(&buffer[..count]);
    }
    if read_total != length_before
        || file.metadata().map_err(|error| map_io(&error))?.len() != length_before
        || crate::file_identity_for_open_handle(file).map_err(map_protected)? != identity_before
    {
        return Err(BlobFileStoreError::PreconditionFailed);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(windows)]
fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn map_io(error: &std::io::Error) -> BlobFileStoreError {
    match error.kind() {
        std::io::ErrorKind::NotFound => BlobFileStoreError::NotFound,
        std::io::ErrorKind::AlreadyExists => BlobFileStoreError::AlreadyExists,
        kind => BlobFileStoreError::Platform(BlobFileStorePlatformFailure::SystemIo {
            kind,
            raw_os_error: error.raw_os_error(),
        }),
    }
}

fn map_port(error: PortError) -> BlobFileStoreError {
    match error {
        PortError::InvalidPath => BlobFileStoreError::InvalidPath,
        _ => BlobFileStoreError::Platform(BlobFileStorePlatformFailure::Port(error)),
    }
}

fn map_protected(error: ProtectedPathError) -> BlobFileStoreError {
    match error {
        ProtectedPathError::InvalidPath => BlobFileStoreError::InvalidPath,
        ProtectedPathError::ReparsePoint => BlobFileStoreError::ReparsePoint,
        ProtectedPathError::UnsupportedPlatform => BlobFileStoreError::UnsupportedPlatform,
        error => BlobFileStoreError::Platform(BlobFileStorePlatformFailure::Protected(error)),
    }
}

#[cfg(windows)]
fn map_directory(error: crate::DirectoryPublicationError) -> BlobFileStoreError {
    match error {
        crate::DirectoryPublicationError::AlreadyExists => BlobFileStoreError::AlreadyExists,
        crate::DirectoryPublicationError::ReparsePoint => BlobFileStoreError::ReparsePoint,
        crate::DirectoryPublicationError::InvalidPath => BlobFileStoreError::InvalidPath,
        crate::DirectoryPublicationError::UnsupportedPlatform => {
            BlobFileStoreError::UnsupportedPlatform
        }
        error => BlobFileStoreError::Platform(BlobFileStorePlatformFailure::Directory(error)),
    }
}
