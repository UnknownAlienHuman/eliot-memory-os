use std::io::Read as _;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::{
    HostError, HostInstallationEpoch, HostKernelRestartReceipt, HostRuntimeControlOperation,
    HostRuntimeControlRequest, valid_sha256_text,
};

#[cfg(windows)]
mod pending_codec;
#[cfg(windows)]
use pending_codec::{
    read_runtime_restart_pending_identity, runtime_restart_pending_identity,
    runtime_restart_pending_payload,
};

#[cfg(windows)]
pub(super) fn runtime_restart_store_dir(host_state_root: &Path) -> PathBuf {
    host_state_root.join("runtime-restarts")
}

#[cfg(windows)]
pub(super) fn runtime_restart_receipt_path(host_state_root: &Path, digest: &str) -> PathBuf {
    runtime_restart_store_dir(host_state_root).join(format!("{digest}.receipt.json"))
}

#[cfg(windows)]
pub(super) fn runtime_restart_pending_path(host_state_root: &Path, digest: &str) -> PathBuf {
    runtime_restart_store_dir(host_state_root).join(format!("{digest}.pending.json"))
}

#[cfg(windows)]
pub(super) fn read_bounded_runtime_restart_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, HostError> {
    let file = std::fs::File::open(path)
        .map_err(|error| HostError::RecoveryRequired(format!("{label} cannot be read: {error}")))?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::RecoveryRequired(format!("{label} cannot be read: {error}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(HostError::RecoveryRequired(format!("{label} is too large")));
    }
    Ok(bytes)
}

#[cfg(windows)]
pub(super) fn load_durable_runtime_restarts(
    host_state_root: &Path,
) -> Result<std::collections::HashMap<String, HostKernelRestartReceipt>, HostError> {
    const MAX_RUNTIME_RESTART_RECORD_BYTES: u64 = 16 * 1024;
    const MAX_RUNTIME_RESTART_RECORDS: usize = 1024;
    let mut map = std::collections::HashMap::new();
    let dir = runtime_restart_store_dir(host_state_root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(map),
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart store cannot be enumerated: {error}"
            )));
        }
    };
    for (entry_index, entry) in entries.enumerate() {
        if entry_index >= MAX_RUNTIME_RESTART_RECORDS {
            return Err(HostError::RecoveryRequired(
                "runtime restart store contains too many records".to_owned(),
            ));
        }
        let entry = entry.map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart store entry cannot be inspected: {error}"
            ))
        })?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart store entry metadata cannot be read: {error}"
            ))
        })?;
        if !metadata.is_file() {
            return Err(HostError::RecoveryRequired(
                "runtime restart store contains a non-file entry".to_owned(),
            ));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "runtime restart store contains a non-text filename".to_owned(),
                )
            })?;
        let pending_digest = file_name
            .strip_suffix(".pending.json")
            .filter(|digest| valid_sha256_text(digest));
        if pending_digest.is_some() {
            // Pending records are validated by the bounded reader below. They
            // are not receipts and therefore never enter the adoption map.
            let _ = read_runtime_restart_pending_identity(&path)?;
            continue;
        }
        let receipt_digest = file_name
            .strip_suffix(".receipt.json")
            .filter(|digest| valid_sha256_text(digest))
            .ok_or_else(|| {
                HostError::RecoveryRequired(format!(
                    "runtime restart store contains an unknown or wrongly named record: {file_name}"
                ))
            })?;
        if metadata.len() > MAX_RUNTIME_RESTART_RECORD_BYTES {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart receipt {file_name} is too large"
            )));
        }
        let bytes = read_bounded_runtime_restart_file(
            &path,
            MAX_RUNTIME_RESTART_RECORD_BYTES,
            &format!("runtime restart receipt {file_name}"),
        )?;
        let receipt =
            serde_json::from_slice::<HostKernelRestartReceipt>(&bytes).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "runtime restart receipt {file_name} is malformed: {error}"
                ))
            })?;
        receipt.validate().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart receipt {file_name} is invalid: {error}"
            ))
        })?;
        if receipt.mutation_digest.as_str() != receipt_digest {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart receipt {file_name} is bound to the wrong mutation"
            )));
        }
        if map.insert(receipt_digest.to_owned(), receipt).is_some() {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart store contains duplicate receipt identity {receipt_digest}"
            )));
        }
    }
    Ok(map)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeRestartPendingPublication {
    Created,
    Replay,
}

/// Commits a directory entry to the volume.
///
/// A directory handle on Windows requires `FILE_FLAG_BACKUP_SEMANTICS`; without
/// it the open fails with `ERROR_ACCESS_DENIED` and the sync silently never
/// happens. This mirrors `sync_parent_directory` in
/// `crates/kernel/eliot-installation/src/redb_state.rs`, including its tolerance
/// for filesystems that cannot sync a directory at all.
#[cfg(windows)]
fn sync_runtime_restart_store_dir(dir: &Path) -> Result<(), HostError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .and_then(|file| file.sync_all())
        .or_else(|error| match error.kind() {
            std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::Unsupported => Ok(()),
            _ => Err(error),
        })
        .map_err(|error| HostError::Platform(error.to_string()))
}

/// Writes `bytes` to `path` and commits them to the volume.
///
/// `sync_all` maps to `FlushFileBuffers`, which needs write access; syncing
/// through a re-opened read-only handle is a no-op that reports success.
#[cfg(windows)]
fn write_durable_file(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::io::Write as _;

    let mut file = std::fs::File::create(path).map_err(|e| HostError::Platform(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| HostError::Platform(e.to_string()))?;
    file.sync_all()
        .map_err(|e| HostError::Platform(e.to_string()))
}

#[cfg(windows)]
pub(super) fn persist_runtime_restart_pending(
    host_state_root: &Path,
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
) -> Result<RuntimeRestartPendingPublication, HostError> {
    request.validate().map_err(HostError::RecoveryRequired)?;
    if request.operation != HostRuntimeControlOperation::RestartKernel {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending records are reserved for RestartKernel".to_owned(),
        ));
    }
    if host.epoch.current.sequence == 0 {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending records require a non-zero host epoch".to_owned(),
        ));
    }
    let dir = runtime_restart_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let identity = runtime_restart_pending_identity(request, host);
    let path = runtime_restart_pending_path(host_state_root, request.mutation_digest.as_str());
    if let Some(existing) = read_runtime_restart_pending_identity(&path)? {
        if existing == identity {
            return Ok(RuntimeRestartPendingPublication::Replay);
        }
        return Err(HostError::RecoveryRequired(
            "runtime restart pending record conflicts with the requested operation".to_owned(),
        ));
    }
    let payload = runtime_restart_pending_payload(&identity)?;
    let bytes = serde_json::to_vec(&payload).map_err(|e| HostError::Platform(e.to_string()))?;
    let tmp = dir.join(format!(
        ".{}.pending.{}.tmp",
        request.mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let publication = (|| {
        write_durable_file(&tmp, &bytes)?;
        // A hard-link publication is atomic and, unlike rename, never replaces
        // a final record that won a concurrent create race.
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_runtime_restart_store_dir(&dir)?;
                Ok(RuntimeRestartPendingPublication::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let Some(existing) = read_runtime_restart_pending_identity(&path)? else {
                    return Err(HostError::RecoveryRequired(
                        "runtime restart pending record disappeared during publication".to_owned(),
                    ));
                };
                if existing == identity {
                    Ok(RuntimeRestartPendingPublication::Replay)
                } else {
                    Err(HostError::RecoveryRequired(
                        "runtime restart pending record conflicts with the requested operation"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    let cleanup = std::fs::remove_file(&tmp);
    let cleanup_sync = sync_runtime_restart_store_dir(&dir);
    match publication {
        Err(error) => Err(error),
        Ok(value) => match cleanup {
            Ok(()) => cleanup_sync.map(|()| value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                cleanup_sync.map(|()| value)
            }
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "runtime restart pending temporary cleanup failed: {error}"
            ))),
        },
    }
}

#[cfg(windows)]
pub(super) fn persist_runtime_restart_receipt(
    host_state_root: &Path,
    receipt: &HostKernelRestartReceipt,
) -> Result<(), HostError> {
    let dir = runtime_restart_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let path = runtime_restart_receipt_path(host_state_root, receipt.mutation_digest.as_str());
    let tmp = dir.join(format!(".{}.receipt.tmp", receipt.mutation_digest.as_str()));
    let bytes = serde_json::to_vec(receipt).map_err(|e| HostError::Platform(e.to_string()))?;
    write_durable_file(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path).map_err(|e| HostError::Platform(e.to_string()))?;
    // The receipt must be on the volume before the pending record it retires is
    // removed; otherwise a crash here leaves neither on disk.
    sync_runtime_restart_store_dir(&dir)?;
    let pending = runtime_restart_pending_path(host_state_root, receipt.mutation_digest.as_str());
    match std::fs::remove_file(pending) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(HostError::Platform(error.to_string())),
    }
    sync_runtime_restart_store_dir(&dir)
}

#[cfg(windows)]
pub(super) fn has_runtime_restart_pending(
    host_state_root: &Path,
    digest: &str,
) -> Result<bool, HostError> {
    let path = runtime_restart_pending_path(host_state_root, digest);
    Ok(read_runtime_restart_pending_identity(&path)?
        .is_some_and(|identity| identity.mutation_digest() == digest))
}

#[cfg(windows)]
pub(super) fn rebind_runtime_restart_receipt(
    receipt: &HostKernelRestartReceipt,
    request: &HostRuntimeControlRequest,
) -> Result<HostKernelRestartReceipt, HostError> {
    if request.operation != HostRuntimeControlOperation::ReconcileKernelRestart
        || receipt.mutation_digest != request.mutation_digest
    {
        return Err(HostError::RecoveryRequired(
            "runtime restart receipt is not bound to the requested mutation".to_owned(),
        ));
    }
    let mut rebound = receipt.clone();
    rebound.request_digest = request.request_digest.clone();
    rebound.receipt_digest = rebound.computed_digest().map_err(HostError::Platform)?;
    rebound.validate().map_err(HostError::Platform)?;
    Ok(rebound)
}
