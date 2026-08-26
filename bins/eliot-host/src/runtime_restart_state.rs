use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    HostError, HostInstallationEpoch, HostKernelRestartReceipt, HostRuntimeControlOperation,
    HostRuntimeControlRequest, PlatformHandle, valid_sha256_text,
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
#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeRestartPendingIdentity {
    wire: String,
    operation: HostRuntimeControlOperation,
    request_id: String,
    mutation_digest: String,
    request_digest: String,
    host_epoch: u64,
    host_lineage: String,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRestartPendingRecord {
    wire: String,
    operation: HostRuntimeControlOperation,
    request_id: String,
    mutation_digest: String,
    request_digest: String,
    host_epoch: u64,
    host_lineage: String,
    created_at: String,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeRestartPendingPublication {
    Created,
    Replay,
}

#[cfg(windows)]
fn runtime_restart_pending_identity(
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
) -> RuntimeRestartPendingIdentity {
    RuntimeRestartPendingIdentity {
        wire: request.wire.as_str().to_owned(),
        operation: request.operation.clone(),
        request_id: request.request_id.as_str().to_owned(),
        mutation_digest: request.mutation_digest.as_str().to_owned(),
        request_digest: request.request_digest.as_str().to_owned(),
        host_epoch: host.epoch.current.sequence,
        host_lineage: host.epoch.current.lineage.as_str().to_owned(),
    }
}

#[cfg(windows)]
fn runtime_restart_pending_payload(
    identity: &RuntimeRestartPendingIdentity,
) -> Result<serde_json::Value, HostError> {
    Ok(serde_json::json!({
        "wire": identity.wire,
        "operation": serde_json::to_value(&identity.operation)
            .map_err(|e| HostError::Platform(e.to_string()))?,
        "request_id": identity.request_id,
        "mutation_digest": identity.mutation_digest,
        "request_digest": identity.request_digest,
        "host_epoch": identity.host_epoch,
        "host_lineage": identity.host_lineage,
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string(),
    }))
}

#[cfg(windows)]
fn runtime_restart_pending_identity_from_bytes(
    bytes: &[u8],
    expected_mutation_digest: &str,
) -> Result<RuntimeRestartPendingIdentity, HostError> {
    let record = serde_json::from_slice::<RuntimeRestartPendingRecord>(bytes).map_err(|e| {
        HostError::RecoveryRequired(format!("runtime restart pending record is malformed: {e}"))
    })?;
    let identity = RuntimeRestartPendingIdentity {
        wire: record.wire,
        operation: record.operation,
        request_id: record.request_id,
        mutation_digest: record.mutation_digest,
        request_digest: record.request_digest,
        host_epoch: record.host_epoch,
        host_lineage: record.host_lineage,
    };
    if identity.wire != "eliot.host.runtime-control.v2"
        || identity.operation != HostRuntimeControlOperation::RestartKernel
        || identity.request_id.trim().is_empty()
        || identity.request_id.chars().any(char::is_control)
        || !valid_sha256_text(&identity.mutation_digest)
        || !valid_sha256_text(&identity.request_digest)
        || identity.host_epoch == 0
        || identity.host_lineage.trim().is_empty()
        || identity.host_lineage.chars().any(char::is_control)
        || record.created_at.trim().is_empty()
        || record.created_at.chars().any(char::is_control)
        || identity.mutation_digest != expected_mutation_digest
    {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending record identity is malformed".to_owned(),
        ));
    }
    let request_id = PlatformHandle::new(identity.request_id.clone()).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "runtime restart pending request_id is malformed: {error}"
        ))
    })?;
    let mutation_digest =
        PlatformHandle::new(identity.mutation_digest.clone()).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart pending mutation_digest is malformed: {error}"
            ))
        })?;
    let expected_request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        request_id,
        mutation_digest,
    )
    .map_err(|error| {
        HostError::RecoveryRequired(format!(
            "runtime restart pending request identity is malformed: {error}"
        ))
    })?;
    if expected_request.request_digest.as_str() != identity.request_digest {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending request_digest does not match its operation and mutation"
                .to_owned(),
        ));
    }
    Ok(identity)
}

#[cfg(windows)]
fn read_runtime_restart_pending_identity(
    path: &Path,
) -> Result<Option<RuntimeRestartPendingIdentity>, HostError> {
    const MAX_PENDING_BYTES: u64 = 16 * 1024;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart pending record cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_PENDING_BYTES {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending record is malformed or too large".to_owned(),
        ));
    }
    let bytes = read_bounded_runtime_restart_file(
        path,
        MAX_PENDING_BYTES,
        "runtime restart pending record",
    )?;
    let expected_mutation_digest = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".pending.json"))
        .filter(|digest| valid_sha256_text(digest))
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "runtime restart pending path is not bound to a lowercase sha256 mutation"
                    .to_owned(),
            )
        })?;
    runtime_restart_pending_identity_from_bytes(&bytes, expected_mutation_digest).map(Some)
}

#[cfg(windows)]
fn sync_runtime_restart_store_dir(dir: &Path) {
    if let Ok(file) = std::fs::OpenOptions::new().read(true).open(dir) {
        let _ = file.sync_all();
    }
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
        std::fs::write(&tmp, bytes).map_err(|e| HostError::Platform(e.to_string()))?;
        if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&tmp) {
            let _ = file.sync_all();
        }
        // A hard-link publication is atomic and, unlike rename, never replaces
        // a final record that won a concurrent create race.
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_runtime_restart_store_dir(&dir);
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
    sync_runtime_restart_store_dir(&dir);
    match publication {
        Err(error) => Err(error),
        Ok(value) => match cleanup {
            Ok(()) => Ok(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(value),
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
    std::fs::write(
        &tmp,
        serde_json::to_vec(receipt).map_err(|e| HostError::Platform(e.to_string()))?,
    )
    .map_err(|e| HostError::Platform(e.to_string()))?;
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&tmp)
            .map_err(|e| HostError::Platform(e.to_string()))?;
        let _ = file.sync_all();
    }
    std::fs::rename(&tmp, &path).map_err(|e| HostError::Platform(e.to_string()))?;
    let pending = runtime_restart_pending_path(host_state_root, receipt.mutation_digest.as_str());
    let _ = std::fs::remove_file(pending);
    if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&dir) {
        let _ = file.sync_all();
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn has_runtime_restart_pending(
    host_state_root: &Path,
    digest: &str,
) -> Result<bool, HostError> {
    let path = runtime_restart_pending_path(host_state_root, digest);
    Ok(read_runtime_restart_pending_identity(&path)?
        .is_some_and(|identity| identity.mutation_digest == digest))
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
