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
use super::host_durable_persistence::{sync_dir, write_durable_file};

#[cfg(all(test, windows))]
use super::host_durable_persistence::ordering;

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

#[cfg(windows)]
fn sync_runtime_restart_store_dir(dir: &Path) -> Result<(), HostError> {
    sync_dir(dir)
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
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_runtime_restart_store_dir(&dir)?;
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
        #[cfg(all(test, windows))]
        ordering::record("pending_hardlink_attempt");
        // A hard-link publication is atomic and, unlike rename, never replaces
        // a final record that won a concurrent create race.
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_runtime_restart_store_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("pending_publication_dir_sync_success");
                Ok(RuntimeRestartPendingPublication::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let Some(existing) = read_runtime_restart_pending_identity(&path)? else {
                    return Err(HostError::RecoveryRequired(
                        "runtime restart pending record disappeared during publication".to_owned(),
                    ));
                };
                if existing == identity {
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_runtime_restart_store_dir(&dir)?;
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
    #[cfg(all(test, windows))]
    ordering::record("tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("tmp_cleanup_done");
    let sync_after_cleanup = sync_runtime_restart_store_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("tmp_cleanup_dir_sync_error");
        }
    }
    match publication {
        Err(publication_error) => Err(publication_error),
        Ok(value) => {
            match cleanup {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(HostError::RecoveryRequired(format!(
                        "runtime restart pending temporary cleanup failed: {error}"
                    )));
                }
            }
            sync_after_cleanup?;
            #[cfg(all(test, windows))]
            ordering::record("pending_publication_complete");
            Ok(value)
        }
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
pub(super) fn persist_runtime_restart_receipt(
    host_state_root: &Path,
    receipt: &HostKernelRestartReceipt,
) -> Result<(), HostError> {
    receipt.validate().map_err(HostError::Platform)?;
    let dir = runtime_restart_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let path = runtime_restart_receipt_path(host_state_root, receipt.mutation_digest.as_str());
    if let Some(existing_bytes) = (|| -> Result<Option<Vec<u8>>, HostError> {
        match std::fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "runtime restart receipt cannot be inspected: {error}"
                )));
            }
        }
        let bytes = read_bounded_runtime_restart_file(&path, 16 * 1024, "runtime restart receipt")?;
        Ok(Some(bytes))
    })()? {
        let existing = serde_json::from_slice::<HostKernelRestartReceipt>(&existing_bytes)
            .map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "existing runtime restart receipt is malformed: {error}"
                ))
            })?;
        existing.validate().map_err(HostError::RecoveryRequired)?;
        if existing == *receipt {
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_runtime_restart_store_dir(&dir)?;
            return Ok(());
        }
        return Err(HostError::RecoveryRequired(
            "existing runtime restart receipt conflicts with reconstructed authority".to_owned(),
        ));
    }
    let tmp = dir.join(format!(
        ".{}.receipt.{}.tmp",
        receipt.mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let bytes = serde_json::to_vec(receipt).map_err(|e| HostError::Platform(e.to_string()))?;
    let publication = (|| {
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("receipt_hardlink_attempt");
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_runtime_restart_store_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("receipt_publication_dir_sync_success");
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes =
                    read_bounded_runtime_restart_file(&path, 16 * 1024, "runtime restart receipt")?;
                let existing = serde_json::from_slice::<HostKernelRestartReceipt>(&bytes).map_err(
                    |error| {
                        HostError::RecoveryRequired(format!(
                            "existing runtime restart receipt is malformed: {error}"
                        ))
                    },
                )?;
                existing.validate().map_err(HostError::RecoveryRequired)?;
                if existing == *receipt {
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_runtime_restart_store_dir(&dir)?;
                    Ok(())
                } else {
                    Err(HostError::RecoveryRequired(
                        "existing runtime restart receipt conflicts with reconstructed authority"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("receipt_tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("receipt_tmp_cleanup_done");
    let sync_after_cleanup = sync_runtime_restart_store_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("receipt_tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("receipt_tmp_cleanup_dir_sync_error");
        }
    }
    // Publication failure is primary; cleanup cannot rename it as success.
    let () = match publication {
        Err(error) => return Err(error),
        Ok(()) => match cleanup {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "runtime restart receipt temporary cleanup failed: {error}"
                )));
            }
        },
    };
    sync_after_cleanup?;
    #[cfg(all(test, windows))]
    ordering::record("receipt_durable_before_pending_remove");
    // Receipt is durable before pending removal.
    let pending = runtime_restart_pending_path(host_state_root, receipt.mutation_digest.as_str());
    #[cfg(all(test, windows))]
    ordering::record("pending_remove_attempt");
    match std::fs::remove_file(&pending) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart pending cleanup failed: {error}"
            )));
        }
    }
    #[cfg(all(test, windows))]
    ordering::record("pending_remove_done");
    sync_runtime_restart_store_dir(&dir)?;
    #[cfg(all(test, windows))]
    ordering::record("pending_remove_dir_sync_success");
    Ok(())
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

#[cfg(test)]
#[cfg(windows)]
mod durability_repair_tests {
    use super::*;
    use crate::HostKernelRestartReceipt;
    use crate::TestResult;
    use crate::host_durable_persistence::{ordering, test_fault};
    use crate::{HostInstallationEpoch, PlatformHandle};

    fn test_host() -> Result<HostInstallationEpoch, Box<dyn std::error::Error>> {
        Ok(crate::fresh_host_epoch(
            PlatformHandle::new("test-installation")?,
            None,
        )?)
    }

    fn temp_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-host-durability-{label}-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn make_receipt(
        mutation_digest: &str,
    ) -> Result<HostKernelRestartReceipt, Box<dyn std::error::Error>> {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: PlatformHandle::new(mutation_digest.to_owned())?,
            request_digest: PlatformHandle::new("a".repeat(64))?,
            old_kernel_generation: PlatformHandle::new("a".repeat(64))?,
            new_kernel_generation: PlatformHandle::new("b".repeat(64))?,
            store_fence: PlatformHandle::new("c".repeat(64))?,
            activation_receipt_digest: PlatformHandle::new("d".repeat(64))?,
            ready_receipt_digest: PlatformHandle::new("e".repeat(64))?,
            receipt_digest: PlatformHandle::new("f".repeat(64))?,
        };
        receipt.receipt_digest = receipt.computed_digest()?;
        Ok(receipt)
    }

    fn make_receipt_for_request(
        request: &super::super::HostRuntimeControlRequest,
    ) -> Result<HostKernelRestartReceipt, Box<dyn std::error::Error>> {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: PlatformHandle::new("a".repeat(64))?,
            new_kernel_generation: PlatformHandle::new("b".repeat(64))?,
            store_fence: PlatformHandle::new("c".repeat(64))?,
            activation_receipt_digest: PlatformHandle::new("d".repeat(64))?,
            ready_receipt_digest: PlatformHandle::new("e".repeat(64))?,
            receipt_digest: PlatformHandle::new("0".repeat(64))?,
        };
        receipt.receipt_digest = receipt.computed_digest()?;
        Ok(receipt)
    }

    #[test]
    fn runtime_restart_pending_dir_sync_permission_denied_is_not_swallowed() -> TestResult {
        let root = temp_root("rr-pending-perm")?;
        let host = test_host()?;
        let digest = "c1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-pending-perm")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        ordering::clear();
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(result.is_err(), "PermissionDenied must propagate");
        assert!(
            matches!(&result, Err(crate::HostError::Platform(msg)) if msg.contains("PermissionDenied") || msg.contains("injected")),
            "error must be Platform"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"dir_sync_fault_injected".to_owned())
                || log.contains(&"dir_sync_attempt".to_owned())
        );
        // The hard link is published before the directory sync that failed, so
        // the record exists but its durability was never confirmed.
        let pending_path = runtime_restart_pending_path(&root, &digest);
        assert!(
            pending_path.exists(),
            "the link precedes the failed directory sync"
        );
        // A retry must confirm durability instead of replaying the unsynced record.
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        assert!(
            persist_runtime_restart_pending(&root, &request, &host).is_err(),
            "replay must not skip the failed directory sync"
        );
        test_fault::clear_sync_fault();
        assert_eq!(
            persist_runtime_restart_pending(&root, &request, &host)?,
            RuntimeRestartPendingPublication::Replay
        );
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_dir_sync_invalid_input_is_not_swallowed() -> TestResult {
        let root = temp_root("rr-pending-invalid")?;
        let host = test_host()?;
        let digest = "c2".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-pending-invalid")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        ordering::clear();
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::InvalidInput);
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        let log = ordering::take_log();
        assert!(
            log.iter()
                .any(|e| e.contains("fault") || e.contains("attempt"))
        );
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_dir_sync_unsupported_is_not_swallowed() -> TestResult {
        let root = temp_root("rr-pending-unsupported")?;
        let host = test_host()?;
        let digest = "c3".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-pending-unsupported")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        ordering::clear();
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::Unsupported);
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_dir_sync_failure_keeps_pending_evidence() -> TestResult {
        let root = temp_root("rr-receipt-keep-pending")?;
        let host = test_host()?;
        let digest = "d1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-receipt-keep")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        // First create pending successfully
        test_fault::clear_sync_fault();
        ordering::clear();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let pending_path = runtime_restart_pending_path(&root, &digest);
        assert!(pending_path.exists());
        // Now attempt receipt with injected dir sync failure on publication
        let receipt = make_receipt(&digest)?;
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        ordering::clear();
        let result = persist_runtime_restart_receipt(&root, &receipt);
        assert!(
            result.is_err(),
            "dir sync failure must propagate and not claim durable"
        );
        // Pending evidence must remain (not removed)
        assert!(
            pending_path.exists(),
            "pending evidence must remain after failed receipt dir sync"
        );
        // Receipt may be absent or not durable
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_ordering_file_sync_before_dir_sync_before_cleanup() -> TestResult {
        let root = temp_root("rr-ordering")?;
        let host = test_host()?;
        let digest = "e1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-ordering")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        test_fault::clear_sync_fault();
        ordering::clear();
        let result = persist_runtime_restart_pending(&root, &request, &host)?;
        assert_eq!(result, RuntimeRestartPendingPublication::Created);
        let log = ordering::take_log();
        let file_idx = log
            .iter()
            .position(|e| e == "file_sync_success")
            .ok_or("file_sync must be logged")?;
        let dir_idx = log
            .iter()
            .position(|e| e == "dir_sync_success" || e == "pending_publication_dir_sync_success")
            .ok_or("dir sync success must be logged")?;
        let cleanup_idx = log
            .iter()
            .position(|e| e == "tmp_cleanup_dir_sync_success")
            .ok_or("cleanup dir sync must be logged")?;
        assert!(
            file_idx < dir_idx,
            "file sync must precede dir sync: {log:?}"
        );
        assert!(
            dir_idx < cleanup_idx,
            "dir sync must precede cleanup dir sync: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_ordering_durable_before_pending_removal() -> TestResult {
        let root = temp_root("rr-receipt-ordering")?;
        let host = test_host()?;
        let digest = "f1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-receipt-order")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        test_fault::clear_sync_fault();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let receipt = make_receipt(&digest)?;
        ordering::clear();
        persist_runtime_restart_receipt(&root, &receipt)?;
        let log = ordering::take_log();
        let durable_idx = log
            .iter()
            .position(|e| e == "receipt_durable_before_pending_remove")
            .ok_or("durable marker missing")?;
        let pending_remove_idx = log
            .iter()
            .position(|e| e == "pending_remove_attempt")
            .ok_or("pending remove attempt missing")?;
        let pending_dir_idx = log
            .iter()
            .position(|e| e == "pending_remove_dir_sync_success")
            .ok_or("pending remove dir sync missing")?;
        assert!(durable_idx < pending_remove_idx);
        assert!(pending_remove_idx < pending_dir_idx);
        // After durable receipt, pending should be gone
        assert!(!runtime_restart_pending_path(&root, &digest).exists());
        assert!(runtime_restart_receipt_path(&root, &digest).exists());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    #[ignore = "child-process target of the abrupt-termination test; returns early unless spawned with its environment"]
    fn durability_child_runtime() -> TestResult {
        if std::env::var("ELIOT_HOST_DURABILITY_CHILD_RUNTIME").is_err() {
            return Ok(());
        }
        let root = PathBuf::from(std::env::var("ELIOT_HOST_CHILD_ROOT")?);
        let digest = std::env::var("ELIOT_HOST_CHILD_DIGEST")?;
        let mode = std::env::var("ELIOT_HOST_CHILD_MODE").unwrap_or_else(|_| "success".to_owned());
        let host = test_host()?;
        if mode == "success" {
            let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
                HostRuntimeControlOperation::RestartKernel,
                PlatformHandle::new("rr-child")?,
                PlatformHandle::new(digest.clone())?,
            )?;
            persist_runtime_restart_pending(&root, &request, &host)?;
            let receipt = make_receipt_for_request(&request)?;
            persist_runtime_restart_receipt(&root, &receipt)?;
            let _ = std::fs::File::open(&root).and_then(|f| f.sync_all());
        } else if mode == "fault" {
            let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
                HostRuntimeControlOperation::RestartKernel,
                PlatformHandle::new("rr-child-fault")?,
                PlatformHandle::new(digest.clone())?,
            )?;
            let pending_path = runtime_restart_pending_path(&root, &digest);
            if !pending_path.exists() {
                persist_runtime_restart_pending(&root, &request, &host)?;
            }
            let receipt = make_receipt_for_request(&request)?;
            test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
            let result = persist_runtime_restart_receipt(&root, &receipt);
            let marker = root.join("child_fault_marker");
            if result.is_err() {
                std::fs::write(&marker, b"fault_propagated")?;
                let _ = std::fs::File::open(&marker).and_then(|f| f.sync_all());
            } else {
                std::fs::write(&marker, b"unexpected_success")?;
            }
        }
        std::process::abort();
    }

    #[test]
    fn runtime_restart_abrupt_child_causal_success_and_fault_reopen() -> TestResult {
        let root = temp_root("rr-abrupt-causal")?;
        let digest = "a1".repeat(32);
        let exe = std::env::current_exe()?;
        let mut child = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime_restart_state::durability_repair_tests::durability_child_runtime")
            .env("ELIOT_HOST_DURABILITY_CHILD_RUNTIME", "1")
            .env("ELIOT_HOST_CHILD_ROOT", &root)
            .env("ELIOT_HOST_CHILD_DIGEST", &digest)
            .env("ELIOT_HOST_CHILD_MODE", "success")
            .spawn()?;
        let status = child.wait()?;
        assert!(!status.success(), "child must abort");
        let loaded = load_durable_runtime_restarts(&root)?;
        assert!(loaded.contains_key(&digest), "receipt must survive abort");
        let digest2 = "a2".repeat(32);
        let mut child2 = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime_restart_state::durability_repair_tests::durability_child_runtime")
            .env("ELIOT_HOST_DURABILITY_CHILD_RUNTIME", "1")
            .env("ELIOT_HOST_CHILD_ROOT", &root)
            .env("ELIOT_HOST_CHILD_DIGEST", &digest2)
            .env("ELIOT_HOST_CHILD_MODE", "fault")
            .spawn()?;
        let status2 = child2.wait()?;
        assert!(!status2.success());
        let marker = root.join("child_fault_marker");
        let bytes = std::fs::read(&marker)?;
        assert_eq!(bytes, b"fault_propagated");
        assert!(runtime_restart_pending_path(&root, &digest2).exists());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }
}
