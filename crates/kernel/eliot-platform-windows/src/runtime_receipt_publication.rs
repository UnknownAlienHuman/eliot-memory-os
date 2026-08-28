//! Physical atomic publication and compare-and-swap (CAS) for the Kernel-owned
//! runtime receipt.
//!
//! Architecture: A2.3, ARCH-MOD-01, ARCH-MOD-02, ARCH-AUTH-01, ARCH-OBS-01.
//! Implementation: I1.2, I1.6, I2.2, I2.23.
//!
//! This module owns only physical atomic publication/CAS and typed
//! `UnknownOutcome` reconciliation. It has no semantic, canonical, lifecycle,
//! or SCM authority and does not overlap `directory_publication`,
//! service-control, or any frozen cell.

#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use eliot_platform::PortError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::FileIdentity;
use crate::provider_failed;

#[cfg(windows)]
use crate::process_identity::{file_identity, file_identity_from_handle};
#[cfg(windows)]
use crate::protected_path::canonical_windows_path;
#[cfg(windows)]
use crate::{
    create_temporary, ensure_protected_containment, expected_root, flush_directory,
    is_reparse_point, open_runtime_read_file, pin_ancestors, provider_from_io, replace_file,
    validate_destination, wide,
};

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_RECEIPT_PUBLICATION_UNKNOWN: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

/// Forces the next owned-receipt replacement to report a post-commit identity
/// unknown outcome after the durable rename.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn force_next_owned_runtime_receipt_unknown() {
    TEST_RECEIPT_PUBLICATION_UNKNOWN.with(|slot| slot.set(true));
}

/// Result of publishing bytes through the Windows atomic replacement path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Identity of the published file after replacement.
    pub identity: FileIdentity,
}

/// Caller-proven identity and content fence for replacing one existing owned
/// runtime receipt.  A digest without the retained file identity is never a
/// sufficient replacement precondition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPrecondition {
    /// Exact retained destination identity observed by the caller.
    pub identity: FileIdentity,
    /// SHA-256 of the exact canonical bytes observed through that identity.
    pub sha256: String,
}

impl PublicationPrecondition {
    /// Captures the compare-and-swap fence from the exact bytes read through
    /// the retained destination identity. The digest is deliberately over the
    /// complete serialized file, not an inner receipt/content digest.
    #[must_use]
    pub fn from_bytes(identity: FileIdentity, bytes: &[u8]) -> Self {
        Self {
            identity,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }
}

/// A publication whose external effect cannot be classified as committed.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationUnknown {
    /// Replacement committed, but the post-commit identity read was unavailable.
    PostCommitIdentityUnavailable,
    /// The destination was replaced again before the receipt could be bound.
    DestinationIdentityChanged,
}

/// Reconciliation evidence returned after a replacement whose final provider
/// observation was inconclusive. The staged file identity is always retained
/// so a caller may reopen and compare identity, path, and content; bytes alone
/// never classify this result as published.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationUnknownReceipt {
    /// Provider classification of the ambiguous post-commit observation.
    pub reason: PublicationUnknown,
    /// Exact identity of the same-parent staged file moved into place.
    pub expected_identity: FileIdentity,
}

/// Publication result that does not overclaim after a post-commit failure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PublicationOutcome {
    Published(PublicationReceipt),
    Unknown(PublicationUnknownReceipt),
}

#[cfg(windows)]
const OWNED_RUNTIME_RECEIPT_PUBLICATION_LOCK: &str = ".eliot-owned-runtime-receipt.publish.lock";

/// Publishes one Kernel-owned runtime receipt below the canonical protected
/// `ProgramData` contour. The optional identity/content pair is a
/// compare-and-swap fence for a receipt previously proven by the caller; an
/// unbound existing destination is never replaced. No-follow parent pins are
/// retained through replacement and the final bytes and identity are read
/// back exactly.
///
/// # Errors
///
/// Returns a typed path, identity, or provider error before publication, and
/// preserves a post-commit unknown outcome when the final identity/readback
/// cannot be classified.
#[allow(
    clippy::too_many_lines,
    reason = "publication, post-commit classification, and exact readback remain one fail-closed boundary"
)]
pub fn publish_atomic_owned_runtime_receipt(
    path: &Path,
    bytes: &[u8],
    expected_existing: Option<&PublicationPrecondition>,
) -> Result<PublicationOutcome, PortError> {
    #[cfg(not(windows))]
    {
        let _ = (path, bytes, expected_existing);
        return Err(PortError::Provider(provider_failed()));
    }
    #[cfg(windows)]
    {
        if !path.is_absolute() || bytes.is_empty() {
            return Err(PortError::InvalidPath);
        }
        if expected_existing.is_some_and(|expected| {
            expected.sha256.len() != 64
                || !expected
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(PortError::IdentityConflict);
        }
        let root = expected_root().map_err(|_| PortError::InvalidPath)?;
        ensure_protected_containment(&root, path).map_err(|_| PortError::InvalidPath)?;
        let canonical = match std::fs::symlink_metadata(path) {
            Ok(metadata) if is_reparse_point(&metadata) || metadata.file_type().is_symlink() => {
                return Err(PortError::InvalidPath);
            }
            Ok(_) => canonical_windows_path(path).map_err(|_| PortError::InvalidPath)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(PortError::InvalidPath)?;
                let parent = canonical_windows_path(parent).map_err(|_| PortError::InvalidPath)?;
                let leaf = path.file_name().ok_or(PortError::InvalidPath)?;
                parent.join(leaf)
            }
            Err(_) => return Err(PortError::InvalidPath),
        };
        ensure_protected_containment(&root, &canonical).map_err(|_| PortError::InvalidPath)?;
        let parent = canonical.parent().ok_or(PortError::InvalidPath)?;
        let pins = pin_ancestors(&root, parent)?;

        // Every writer using this production primitive owns the same retained,
        // protected sibling handle before it observes the destination.  The
        // predecessor remains pinned without FILE_SHARE_DELETE until the
        // commit boundary; only then is it released while this protocol lease
        // still excludes another authorized publisher.  A bypassing
        // create-new race is independently stopped by the no-replace move.
        let _publication_lock = acquire_owned_runtime_receipt_publication_lock(parent)?;

        let mut existing = match open_runtime_read_file(&canonical) {
            Ok(mut file) => {
                let identity = file_identity_from_handle(&file)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                let mut existing_bytes = Vec::new();
                file.read_to_end(&mut existing_bytes)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                let actual = format!("{:x}", Sha256::digest(&existing_bytes));
                match expected_existing {
                    Some(expected)
                        if expected.sha256 == actual && expected.identity == identity =>
                    {
                        Some(file)
                    }
                    Some(_) | None => return Err(PortError::IdentityConflict),
                }
            }
            Err(_) => match std::fs::symlink_metadata(&canonical) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if expected_existing.is_some() {
                        return Err(PortError::IdentityConflict);
                    }
                    None
                }
                _ => return Err(PortError::Provider(provider_failed())),
            },
        };
        let temporary = create_temporary(parent, bytes)?;
        let Ok(staged_identity) = file_identity(&temporary) else {
            let _ = std::fs::remove_file(&temporary);
            return Err(PortError::Provider(provider_failed()));
        };
        if let Err(error) = validate_destination(&canonical) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Some(file) = existing.as_mut() {
            let current_identity = file_identity_from_handle(file)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if file.seek(SeekFrom::Start(0)).is_err() {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::Provider(provider_failed()));
            }
            let mut current_bytes = Vec::new();
            if file.read_to_end(&mut current_bytes).is_err() {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::Provider(provider_failed()));
            }
            let actual = format!("{:x}", Sha256::digest(&current_bytes));
            if expected_existing.is_none_or(|expected| {
                expected.sha256 != actual || expected.identity != current_identity
            }) {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::IdentityConflict);
            }
        }
        drop(existing);
        let commit = if expected_existing.is_some() {
            replace_file(&temporary, &canonical)
        } else {
            move_file_create_new(&temporary, &canonical)
        };
        if let Err(error) = commit {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        flush_directory(&pins);
        #[cfg(any(test, feature = "test-support"))]
        if TEST_RECEIPT_PUBLICATION_UNKNOWN.with(|slot| slot.replace(false)) {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        }
        let Ok(identity) = file_identity(&canonical) else {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        };
        if identity != staged_identity {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::DestinationIdentityChanged,
                expected_identity: staged_identity,
            }));
        }
        let Ok(mut readback) = open_runtime_read_file(&canonical) else {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        };
        let mut readback_bytes = Vec::new();
        if readback.read_to_end(&mut readback_bytes).is_err() {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        }
        if readback_bytes != bytes {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::DestinationIdentityChanged,
                expected_identity: staged_identity,
            }));
        }
        Ok(PublicationOutcome::Published(PublicationReceipt {
            identity,
        }))
    }
}

#[cfg(windows)]
fn acquire_owned_runtime_receipt_publication_lock(
    parent: &Path,
) -> Result<std::fs::File, PortError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let lock_path = parent.join(OWNED_RUNTIME_RECEIPT_PUBLICATION_LOCK);
    for attempt in 0..=400 {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .access_mode(crate::protected_path::legacy_protected_file_access_mode())
            // A live handle is the inter-process ownership token. No read,
            // write, or delete sharing is permitted until publication has
            // been classified through exact post-commit readback.
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        match options.open(&lock_path) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                if !metadata.is_file()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(PortError::InvalidPath);
                }
                crate::protected_path::protect_opened_handle(&file, false)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                return Ok(file);
            }
            Err(error)
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.cast_signed())
                    && attempt < 400 =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(PortError::Provider(provider_from_io(&error))),
        }
    }
    unreachable!("bounded publication-lock loop always returns")
}

#[cfg(windows)]
fn move_file_create_new(source: &Path, destination: &Path) -> Result<(), PortError> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let source_wide = wide(source);
    let destination_wide = wide(destination);
    // SAFETY: both strings are NUL-terminated and remain live for the call.
    // Omitting REPLACE_EXISTING is the atomic no-replace commit contract.
    let ok = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_ALREADY_EXISTS.cast_signed()
                || code == ERROR_FILE_EXISTS.cast_signed()
    ) || std::fs::symlink_metadata(destination).is_ok()
    {
        return Err(PortError::IdentityConflict);
    }
    Err(PortError::Provider(provider_from_io(&error)))
}
