use std::path::{Path, PathBuf};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    AuthorityEpoch, HostError, HostInstallationEpoch, HostProcessBinding,
    HostRuntimeControlOperation, HostRuntimeControlRequest, HostStoreBootstrapRequirement,
    HostStoreRecoveryReceipt, PlatformHandle, ResourceGeneration, StoreProcessBinding,
    StoreRebindHandoff, StoreRebindReceipt, StoreRebindRecord, StoreRecoveryInnerBinding,
    StoreRecoveryReopenFence, StoreRecoveryTerminationEvidence, TerminatedJobChild,
    read_bounded_runtime_restart_file, read_store_recovery_inner_binding,
    read_store_recovery_termination_evidence, sha256_json, valid_sha256_text,
};

#[cfg(windows)]
fn store_recovery_store_dir(host_state_root: &Path) -> PathBuf {
    host_state_root.join("store-recoveries")
}

#[cfg(windows)]
pub(super) fn store_recovery_receipt_path(host_state_root: &Path, digest: &str) -> PathBuf {
    store_recovery_store_dir(host_state_root).join(format!("{digest}.receipt.json"))
}

#[cfg(windows)]
pub(super) fn store_recovery_pending_path(host_state_root: &Path, digest: &str) -> PathBuf {
    store_recovery_store_dir(host_state_root).join(format!("{digest}.pending.json"))
}

#[cfg(windows)]
pub(super) fn store_recovery_termination_path(host_state_root: &Path, digest: &str) -> PathBuf {
    store_recovery_store_dir(host_state_root).join(format!("{digest}.termination.json"))
}

#[cfg(windows)]
pub(super) fn store_recovery_inner_binding_path(host_state_root: &Path, digest: &str) -> PathBuf {
    store_recovery_store_dir(host_state_root).join(format!("{digest}.inner.json"))
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the loader performs one exhaustive fail-closed filename, shape, and cross-binding audit before exposing startup fences"
)]
pub(super) fn load_durable_store_recoveries(
    host_state_root: &Path,
) -> Result<Vec<StoreRecoveryReopenFence>, HostError> {
    const MAX_STORE_RECOVERY_RECORD_BYTES: u64 = 16 * 1024;
    const MAX_STORE_RECOVERY_RECORDS: usize = 1024;
    let mut pending_records = std::collections::HashMap::new();
    let mut termination_records = std::collections::HashMap::new();
    let mut inner_bindings = std::collections::HashMap::new();
    let dir = store_recovery_store_dir(host_state_root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "store recovery store cannot be enumerated: {error}"
            )));
        }
    };
    for (entry_index, entry) in entries.enumerate() {
        if entry_index >= MAX_STORE_RECOVERY_RECORDS {
            return Err(HostError::RecoveryRequired(
                "store recovery store contains too many records".to_owned(),
            ));
        }
        let entry = entry.map_err(|error| {
            HostError::RecoveryRequired(format!(
                "store recovery store entry cannot be inspected: {error}"
            ))
        })?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "store recovery store entry metadata cannot be read: {error}"
            ))
        })?;
        if !metadata.is_file() {
            return Err(HostError::RecoveryRequired(
                "store recovery store contains a non-file entry".to_owned(),
            ));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "store recovery store contains a non-text filename".to_owned(),
                )
            })?;
        let pending_digest = file_name
            .strip_suffix(".pending.json")
            .filter(|digest| valid_sha256_text(digest));
        if let Some(pending_digest) = pending_digest {
            let pending = read_store_recovery_pending_identity(&path)?.ok_or_else(|| {
                HostError::RecoveryRequired(format!(
                    "store recovery pending record {file_name} disappeared during inspection"
                ))
            })?;
            pending_records.insert(pending_digest.to_owned(), pending);
            continue;
        }
        let termination_digest = file_name
            .strip_suffix(".termination.json")
            .filter(|digest| valid_sha256_text(digest));
        if let Some(termination_digest) = termination_digest {
            let termination = read_store_recovery_termination_evidence(
                host_state_root,
                termination_digest,
            )?
            .ok_or_else(|| {
                HostError::RecoveryRequired(format!(
                    "store recovery termination record {file_name} disappeared during inspection"
                ))
            })?;
            termination_records.insert(termination_digest.to_owned(), termination);
            continue;
        }
        let inner_digest = file_name
            .strip_suffix(".inner.json")
            .filter(|digest| valid_sha256_text(digest));
        if let Some(inner_digest) = inner_digest {
            let inner = read_store_recovery_inner_binding(host_state_root, inner_digest)?
                .ok_or_else(|| {
                    HostError::RecoveryRequired(format!(
                        "store recovery inner binding {file_name} disappeared during inspection"
                    ))
                })?;
            inner_bindings.insert(inner_digest.to_owned(), inner);
            continue;
        }
        let receipt_digest = file_name
            .strip_suffix(".receipt.json")
            .filter(|digest| valid_sha256_text(digest))
            .ok_or_else(|| {
                HostError::RecoveryRequired(format!(
                    "store recovery store contains an unknown or wrongly named record: {file_name}"
                ))
            })?;
        if metadata.len() > MAX_STORE_RECOVERY_RECORD_BYTES {
            return Err(HostError::RecoveryRequired(format!(
                "store recovery receipt {file_name} is too large"
            )));
        }
        let bytes = read_bounded_runtime_restart_file(
            &path,
            MAX_STORE_RECOVERY_RECORD_BYTES,
            &format!("store recovery receipt {file_name}"),
        )?;
        let receipt =
            serde_json::from_slice::<HostStoreRecoveryReceipt>(&bytes).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "store recovery receipt {file_name} is malformed: {error}"
                ))
            })?;
        receipt.validate().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "store recovery receipt {file_name} is invalid: {error}"
            ))
        })?;
        if receipt.external_control_mutation_digest.as_str() != receipt_digest {
            return Err(HostError::RecoveryRequired(format!(
                "store recovery receipt {file_name} is bound to the wrong mutation"
            )));
        }
        // Receipt shape is checked so malformed durable state still fences
        // startup, but the receipt is deliberately not adopted as authority.
        // A live StoreRecovered response is rebuilt only from the exact
        // pending/termination/inner journal contour below.
    }
    for (digest, termination) in &termination_records {
        let pending = pending_records.get(digest).ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "Store termination evidence {digest} has no exact durable recovery intent"
            ))
        })?;
        termination.validate_for_pending(pending)?;
    }
    for (digest, inner) in &inner_bindings {
        let pending = pending_records.get(digest).ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "Store inner binding {digest} has no exact durable recovery intent"
            ))
        })?;
        let termination = termination_records.get(digest).ok_or_else(|| {
            HostError::RecoveryRequired(format!(
                "Store inner binding {digest} has no exact termination evidence"
            ))
        })?;
        inner.validate_for_pending(pending, termination)?;
    }
    let mut fences = pending_records
        .into_iter()
        .map(|(digest, pending)| {
            StoreRecoveryReopenFence::from_durable(
                digest.clone(),
                pending,
                termination_records.remove(&digest),
                inner_bindings.remove(&digest),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    fences.sort_by(|left, right| left.mutation_digest.cmp(&right.mutation_digest));
    Ok(fences)
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreRecoveryPendingIdentity {
    pub(super) wire: String,
    pub(super) operation: HostRuntimeControlOperation,
    pub(super) request_id: String,
    pub(super) mutation_digest: String,
    pub(super) request_digest: String,
    pub(super) host_epoch: u64,
    pub(super) host_lineage: String,
}

#[cfg(windows)]
impl StoreRecoveryPendingIdentity {
    pub(super) fn recover_request(&self) -> Result<HostRuntimeControlRequest, HostError> {
        let request_id = PlatformHandle::new(self.request_id.clone()).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "Store recovery pending request_id is malformed: {error}"
            ))
        })?;
        let mutation_digest =
            PlatformHandle::new(self.mutation_digest.clone()).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "Store recovery pending mutation_digest is malformed: {error}"
                ))
            })?;
        let request = HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RecoverStore,
            request_id,
            mutation_digest,
        )
        .map_err(HostError::RecoveryRequired)?;
        if request.wire.as_str() != self.wire
            || request.request_digest.as_str() != self.request_digest
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery pending request is not canonical".to_owned(),
            ));
        }
        Ok(request)
    }

    pub(super) fn validate_current_request(
        &self,
        request: &HostRuntimeControlRequest,
    ) -> Result<(), HostError> {
        request.validate().map_err(HostError::RecoveryRequired)?;
        if request.mutation_digest.as_str() != self.mutation_digest {
            return Err(HostError::RecoveryRequired(
                "Store recovery request mutation does not match the durable intent".to_owned(),
            ));
        }
        match request.operation {
            HostRuntimeControlOperation::RecoverStore => {
                if request != &self.recover_request()? {
                    return Err(HostError::RecoveryRequired(
                        "RecoverStore replay does not match the exact durable request".to_owned(),
                    ));
                }
            }
            HostRuntimeControlOperation::ReconcileStoreRecovery => {}
            _ => {
                return Err(HostError::RecoveryRequired(
                    "Store recovery durable intent was queried by another operation".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreRecoveryPendingRecord {
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
pub(super) enum StoreRecoveryPendingPublication {
    Created,
    Replay,
}

#[cfg(windows)]
fn store_recovery_pending_identity(
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
) -> StoreRecoveryPendingIdentity {
    StoreRecoveryPendingIdentity {
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
fn store_recovery_pending_payload(
    identity: &StoreRecoveryPendingIdentity,
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
fn store_recovery_pending_identity_from_bytes(
    bytes: &[u8],
    expected_mutation_digest: &str,
) -> Result<StoreRecoveryPendingIdentity, HostError> {
    let record = serde_json::from_slice::<StoreRecoveryPendingRecord>(bytes).map_err(|e| {
        HostError::RecoveryRequired(format!("store recovery pending record is malformed: {e}"))
    })?;
    let identity = StoreRecoveryPendingIdentity {
        wire: record.wire,
        operation: record.operation,
        request_id: record.request_id,
        mutation_digest: record.mutation_digest,
        request_digest: record.request_digest,
        host_epoch: record.host_epoch,
        host_lineage: record.host_lineage,
    };
    if identity.wire != "eliot.host.runtime-control.v2"
        || identity.operation != HostRuntimeControlOperation::RecoverStore
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
            "store recovery pending record identity is malformed".to_owned(),
        ));
    }
    let request_id = PlatformHandle::new(identity.request_id.clone()).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "store recovery pending request_id is malformed: {error}"
        ))
    })?;
    let mutation_digest =
        PlatformHandle::new(identity.mutation_digest.clone()).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "store recovery pending mutation_digest is malformed: {error}"
            ))
        })?;
    let expected_request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RecoverStore,
        request_id,
        mutation_digest,
    )
    .map_err(|error| {
        HostError::RecoveryRequired(format!(
            "store recovery pending request identity is malformed: {error}"
        ))
    })?;
    if expected_request.request_digest.as_str() != identity.request_digest {
        return Err(HostError::RecoveryRequired(
            "store recovery pending request_digest does not match its operation and mutation"
                .to_owned(),
        ));
    }
    Ok(identity)
}

#[cfg(windows)]
pub(super) fn read_store_recovery_pending_identity(
    path: &Path,
) -> Result<Option<StoreRecoveryPendingIdentity>, HostError> {
    const MAX_PENDING_BYTES: u64 = 16 * 1024;
    let expected_mutation_digest = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".pending.json"))
        .filter(|digest| valid_sha256_text(digest))
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "store recovery pending path is not bound to a lowercase sha256 mutation"
                    .to_owned(),
            )
        })?;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "store recovery pending record cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_PENDING_BYTES {
        return Err(HostError::RecoveryRequired(
            "store recovery pending record is malformed or too large".to_owned(),
        ));
    }
    let bytes = read_bounded_runtime_restart_file(
        path,
        MAX_PENDING_BYTES,
        "store recovery pending record",
    )?;
    store_recovery_pending_identity_from_bytes(&bytes, expected_mutation_digest).map(Some)
}

#[cfg(windows)]
fn sync_store_recovery_dir(dir: &Path) {
    if let Ok(file) = std::fs::OpenOptions::new().read(true).open(dir) {
        let _ = file.sync_all();
    }
}

#[cfg(windows)]
pub(super) fn persist_store_recovery_pending(
    host_state_root: &Path,
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
) -> Result<StoreRecoveryPendingPublication, HostError> {
    request.validate().map_err(HostError::RecoveryRequired)?;
    if request.operation != HostRuntimeControlOperation::RecoverStore {
        return Err(HostError::RecoveryRequired(
            "store recovery pending records are reserved for RecoverStore".to_owned(),
        ));
    }
    if host.epoch.current.sequence == 0 {
        return Err(HostError::RecoveryRequired(
            "store recovery pending records require a non-zero host epoch".to_owned(),
        ));
    }
    let dir = store_recovery_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let identity = store_recovery_pending_identity(request, host);
    let path = store_recovery_pending_path(host_state_root, request.mutation_digest.as_str());
    if let Some(existing) = read_store_recovery_pending_identity(&path)? {
        if existing == identity {
            return Ok(StoreRecoveryPendingPublication::Replay);
        }
        return Err(HostError::RecoveryRequired(
            "store recovery pending record conflicts with the requested operation".to_owned(),
        ));
    }
    let payload = store_recovery_pending_payload(&identity)?;
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
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir);
                Ok(StoreRecoveryPendingPublication::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let Some(existing) = read_store_recovery_pending_identity(&path)? else {
                    return Err(HostError::RecoveryRequired(
                        "store recovery pending record disappeared during publication".to_owned(),
                    ));
                };
                if existing == identity {
                    Ok(StoreRecoveryPendingPublication::Replay)
                } else {
                    Err(HostError::RecoveryRequired(
                        "store recovery pending record conflicts with the requested operation"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    let cleanup = std::fs::remove_file(&tmp);
    sync_store_recovery_dir(&dir);
    match publication {
        Err(error) => Err(error),
        Ok(value) => match cleanup {
            Ok(()) => Ok(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(value),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "store recovery pending temporary cleanup failed: {error}"
            ))),
        },
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the termination receipt persists exact mutation and Job completion evidence atomically"
)]
pub(super) fn persist_store_recovery_termination_evidence(
    host_state_root: &Path,
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
    terminated: &TerminatedJobChild,
    expected_job_name: &str,
) -> Result<(), HostError> {
    request.validate().map_err(HostError::RecoveryRequired)?;
    if request.operation != HostRuntimeControlOperation::RecoverStore {
        return Err(HostError::RecoveryRequired(
            "Store termination evidence is reserved for RecoverStore".to_owned(),
        ));
    }
    let pending = read_store_recovery_pending_identity(&store_recovery_pending_path(
        host_state_root,
        request.mutation_digest.as_str(),
    ))?
    .ok_or_else(|| {
        HostError::RecoveryRequired(
            "Store termination evidence requires the exact durable recovery intent".to_owned(),
        )
    })?;
    let expected = store_recovery_pending_identity(request, host);
    if pending != expected {
        return Err(HostError::RecoveryRequired(
            "Store termination evidence does not match the durable recovery intent".to_owned(),
        ));
    }
    let process = terminated.process();
    let evidence = StoreRecoveryTerminationEvidence {
        wire: request.wire.as_str().to_owned(),
        operation: request.operation.clone(),
        request_id: request.request_id.as_str().to_owned(),
        mutation_digest: request.mutation_digest.as_str().to_owned(),
        request_digest: request.request_digest.as_str().to_owned(),
        host_epoch: host.epoch.current.sequence,
        host_lineage: host.epoch.current.lineage.as_str().to_owned(),
        process_id: process.process_id,
        process_start_time_100ns: process.start_time_100ns,
        process_image_path: process.image_path.clone(),
        job_name: expected_job_name.to_owned(),
        job_empty: terminated.job_empty(),
        root_reaped: terminated.root_reaped(),
        restart_attempt: 1,
    };
    evidence.validate_for_digest(request.mutation_digest.as_str())?;
    let dir = store_recovery_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|error| HostError::Platform(error.to_string()))?;
    let path = store_recovery_termination_path(host_state_root, request.mutation_digest.as_str());
    if let Some(existing) =
        read_store_recovery_termination_evidence(host_state_root, request.mutation_digest.as_str())?
    {
        if existing == evidence {
            return Ok(());
        }
        return Err(HostError::RecoveryRequired(
            "Store termination evidence conflicts with the requested operation".to_owned(),
        ));
    }
    let bytes =
        serde_json::to_vec(&evidence).map_err(|error| HostError::Platform(error.to_string()))?;
    let tmp = dir.join(format!(
        ".{}.termination.{}.tmp",
        request.mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let publication = (|| {
        std::fs::write(&tmp, bytes).map_err(|error| HostError::Platform(error.to_string()))?;
        if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&tmp) {
            let _ = file.sync_all();
        }
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let Some(existing) = read_store_recovery_termination_evidence(
                    host_state_root,
                    request.mutation_digest.as_str(),
                )?
                else {
                    return Err(HostError::RecoveryRequired(
                        "Store termination evidence disappeared during publication".to_owned(),
                    ));
                };
                if existing == evidence {
                    Ok(())
                } else {
                    Err(HostError::RecoveryRequired(
                        "Store termination evidence conflicts with the requested operation"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    let cleanup = std::fs::remove_file(&tmp);
    sync_store_recovery_dir(&dir);
    match publication {
        Err(error) => Err(error),
        Ok(()) => match cleanup {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Store termination temporary cleanup failed: {error}"
            ))),
        },
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the no-replace publication verifies every outer, termination, and canonical inner handoff binding before durable readback"
)]
pub(super) fn persist_store_recovery_inner_binding(
    host_state_root: &Path,
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
    handoff: &StoreRebindHandoff,
) -> Result<(), HostError> {
    request.validate().map_err(HostError::RecoveryRequired)?;
    if request.operation != HostRuntimeControlOperation::RecoverStore {
        return Err(HostError::RecoveryRequired(
            "Store inner bindings are reserved for RecoverStore".to_owned(),
        ));
    }
    handoff
        .validate_canonical_digest()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let pending = read_store_recovery_pending_identity(&store_recovery_pending_path(
        host_state_root,
        request.mutation_digest.as_str(),
    ))?
    .ok_or_else(|| {
        HostError::RecoveryRequired(
            "Store inner binding requires the exact durable recovery intent".to_owned(),
        )
    })?;
    if pending != store_recovery_pending_identity(request, host) {
        return Err(HostError::RecoveryRequired(
            "Store inner binding does not match the exact recovery request/Host epoch".to_owned(),
        ));
    }
    let termination = read_store_recovery_termination_evidence(
        host_state_root,
        request.mutation_digest.as_str(),
    )?
    .ok_or_else(|| {
        HostError::RecoveryRequired(
            "Store inner binding requires exact termination evidence".to_owned(),
        )
    })?;
    termination.validate_for_pending(&pending)?;
    if handoff.process_binding.process.process_id == termination.process_id
        && handoff.process_binding.process.start_time_100ns == termination.process_start_time_100ns
        && handoff.process_binding.process.image_path == termination.process_image_path
        && handoff.process_binding.job.as_str() == termination.job_name
    {
        return Err(HostError::RecoveryRequired(
            "Store inner binding points at the terminated predecessor".to_owned(),
        ));
    }
    let binding = StoreRecoveryInnerBinding {
        wire: request.wire.as_str().to_owned(),
        operation: request.operation.clone(),
        request_id: request.request_id.as_str().to_owned(),
        external_control_mutation_digest: request.mutation_digest.as_str().to_owned(),
        external_control_request_digest: request.request_digest.as_str().to_owned(),
        host_epoch: host.epoch.current.sequence,
        host_lineage: host.epoch.current.lineage.as_str().to_owned(),
        terminated_store_evidence_digest: sha256_json(&termination)?,
        store_rebind_operation_id: handoff.operation_id.as_str().to_owned(),
        store_rebind_request_digest: handoff.request_digest.clone(),
        handoff: handoff.clone(),
    };
    binding.validate_for_pending(&pending, &termination)?;
    let dir = store_recovery_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|error| HostError::Platform(error.to_string()))?;
    let path = store_recovery_inner_binding_path(host_state_root, request.mutation_digest.as_str());
    if let Some(existing) =
        read_store_recovery_inner_binding(host_state_root, request.mutation_digest.as_str())?
    {
        return if existing == binding {
            Ok(())
        } else {
            Err(HostError::RecoveryRequired(
                "Store recovery inner binding conflicts with retained identity".to_owned(),
            ))
        };
    }
    let bytes =
        serde_json::to_vec(&binding).map_err(|error| HostError::Platform(error.to_string()))?;
    let tmp = dir.join(format!(
        ".{}.inner.{}.tmp",
        request.mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let publication = (|| {
        std::fs::write(&tmp, bytes).map_err(|error| HostError::Platform(error.to_string()))?;
        if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&tmp) {
            let _ = file.sync_all();
        }
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_store_recovery_inner_binding(
                    host_state_root,
                    request.mutation_digest.as_str(),
                )?
                .ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Store recovery inner binding disappeared during publication".to_owned(),
                    )
                })?;
                if existing == binding {
                    Ok(())
                } else {
                    Err(HostError::RecoveryRequired(
                        "Store recovery inner binding conflicts with retained identity".to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    let cleanup = std::fs::remove_file(&tmp);
    sync_store_recovery_dir(&dir);
    match publication {
        Err(error) => Err(error),
        Ok(()) => match cleanup {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Store recovery inner-binding temporary cleanup failed: {error}"
            ))),
        },
    }
}

#[cfg(windows)]
pub(super) fn read_store_recovery_receipt(
    host_state_root: &Path,
    mutation_digest: &str,
) -> Result<Option<HostStoreRecoveryReceipt>, HostError> {
    if !valid_sha256_text(mutation_digest) {
        return Err(HostError::RecoveryRequired(
            "Store recovery receipt path is not a lowercase sha256 mutation".to_owned(),
        ));
    }
    let path = store_recovery_receipt_path(host_state_root, mutation_digest);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Store recovery receipt cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() || metadata.len() > 16 * 1024 {
        return Err(HostError::RecoveryRequired(
            "Store recovery receipt is malformed or too large".to_owned(),
        ));
    }
    let bytes = read_bounded_runtime_restart_file(&path, 16 * 1024, "Store recovery receipt")?;
    let receipt = serde_json::from_slice::<HostStoreRecoveryReceipt>(&bytes).map_err(|error| {
        HostError::RecoveryRequired(format!("Store recovery receipt is malformed: {error}"))
    })?;
    receipt.validate().map_err(HostError::RecoveryRequired)?;
    if receipt.external_control_mutation_digest.as_str() != mutation_digest {
        return Err(HostError::RecoveryRequired(
            "Store recovery receipt is bound to another mutation".to_owned(),
        ));
    }
    Ok(Some(receipt))
}

#[cfg(windows)]
pub(super) fn persist_store_recovery_receipt(
    host_state_root: &Path,
    receipt: &HostStoreRecoveryReceipt,
) -> Result<(), HostError> {
    let dir = store_recovery_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let path = store_recovery_receipt_path(
        host_state_root,
        receipt.external_control_mutation_digest.as_str(),
    );
    if let Some(existing) = read_store_recovery_receipt(
        host_state_root,
        receipt.external_control_mutation_digest.as_str(),
    )? {
        if existing == *receipt {
            return Ok(());
        }
        return Err(HostError::RecoveryRequired(
            "existing Store recovery receipt conflicts with reconstructed authority".to_owned(),
        ));
    }
    let tmp = dir.join(format!(
        ".{}.receipt.{}.tmp",
        receipt.external_control_mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
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
    // Publish with a hard link so a concurrent writer can never replace an
    // already durable outer receipt.  The winner is read back and must be the
    // exact same canonical authority; a conflicting winner remains Unknown.
    let publication = match std::fs::hard_link(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes =
                read_bounded_runtime_restart_file(&path, 16 * 1024, "Store recovery receipt")?;
            let existing =
                serde_json::from_slice::<HostStoreRecoveryReceipt>(&bytes).map_err(|error| {
                    HostError::RecoveryRequired(format!(
                        "existing Store recovery receipt is malformed: {error}"
                    ))
                })?;
            existing.validate().map_err(HostError::RecoveryRequired)?;
            if existing == *receipt {
                Ok(())
            } else {
                Err(HostError::RecoveryRequired(
                    "existing Store recovery receipt conflicts with reconstructed authority"
                        .to_owned(),
                ))
            }
        }
        Err(error) => Err(HostError::Platform(error.to_string())),
    };
    let cleanup = std::fs::remove_file(&tmp);
    sync_store_recovery_dir(&dir);
    match publication {
        Err(error) => Err(error),
        Ok(()) => match cleanup {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Store recovery receipt temporary cleanup failed: {error}"
            ))),
        },
    }
}

#[cfg(windows)]
pub(super) fn cleanup_store_recovery_supporting_evidence_for(
    host_state_root: &Path,
    mutation_digest: &str,
) -> Result<(), HostError> {
    if !valid_sha256_text(mutation_digest) {
        return Err(HostError::RecoveryRequired(
            "Store recovery resolution mutation is not a lowercase sha256".to_owned(),
        ));
    }
    let receipt_path = store_recovery_receipt_path(host_state_root, mutation_digest);
    let receipt_bytes = read_bounded_runtime_restart_file(
        &receipt_path,
        16 * 1024,
        "Store recovery resolution receipt",
    )?;
    let receipt = serde_json::from_slice::<HostStoreRecoveryReceipt>(&receipt_bytes)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    receipt.validate().map_err(HostError::RecoveryRequired)?;
    if receipt.external_control_mutation_digest.as_str() != mutation_digest {
        return Err(HostError::RecoveryRequired(
            "Store recovery resolution receipt is bound to another mutation".to_owned(),
        ));
    }
    let dir = store_recovery_store_dir(host_state_root);
    for path in [
        store_recovery_pending_path(host_state_root, mutation_digest),
        store_recovery_termination_path(host_state_root, mutation_digest),
        store_recovery_inner_binding_path(host_state_root, mutation_digest),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "Store recovery resolution cleanup failed for {}: {error}",
                    path.display()
                )));
            }
        }
    }
    sync_store_recovery_dir(&dir);
    Ok(())
}

#[cfg(windows)]
pub(super) fn cleanup_completed_store_recovery_supporting_evidence(
    host_state_root: &Path,
) -> Result<(), HostError> {
    let fences = load_durable_store_recoveries(host_state_root)?;
    let dir = store_recovery_store_dir(host_state_root);
    for fence in fences {
        if !store_recovery_receipt_path(host_state_root, &fence.mutation_digest).exists() {
            continue;
        }
        for path in [
            store_recovery_pending_path(host_state_root, &fence.mutation_digest),
            store_recovery_termination_path(host_state_root, &fence.mutation_digest),
            store_recovery_inner_binding_path(host_state_root, &fence.mutation_digest),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(HostError::RecoveryRequired(format!(
                        "completed Store recovery evidence cleanup failed for {}: {error}",
                        path.display()
                    )));
                }
            }
        }
    }
    sync_store_recovery_dir(&dir);
    Ok(())
}

#[cfg(windows)]
pub(super) fn has_store_recovery_pending(
    host_state_root: &Path,
    digest: &str,
) -> Result<bool, HostError> {
    let path = store_recovery_pending_path(host_state_root, digest);
    Ok(read_store_recovery_pending_identity(&path)?
        .is_some_and(|identity| identity.mutation_digest == digest))
}

#[cfg(windows)]
pub(super) fn rebind_store_recovery_receipt(
    receipt: &HostStoreRecoveryReceipt,
    request: &HostRuntimeControlRequest,
) -> Result<HostStoreRecoveryReceipt, HostError> {
    if request.operation != HostRuntimeControlOperation::ReconcileStoreRecovery
        || receipt.external_control_mutation_digest != request.mutation_digest
    {
        return Err(HostError::RecoveryRequired(
            "store recovery receipt is not bound to the requested mutation".to_owned(),
        ));
    }
    let mut rebound = receipt.clone();
    rebound.request_digest = request.request_digest.clone();
    rebound.receipt_digest = rebound.computed_digest().map_err(HostError::Platform)?;
    rebound.validate().map_err(HostError::Platform)?;
    Ok(rebound)
}

#[cfg(windows)]
pub(super) fn committed_store_rebind_receipt(
    record: &StoreRebindRecord,
    requirement: &HostStoreBootstrapRequirement,
    candidate_digest: &str,
) -> Result<StoreRebindReceipt, HostError> {
    requirement
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let expected_requirement_digest = sha256_json(requirement)?;
    if record.requirement.as_str() != expected_requirement_digest {
        return Err(HostError::RecoveryRequired(
            "committed Store rebind requirement digest is substituted".to_owned(),
        ));
    }
    let generation = ResourceGeneration::new(record.generation)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let authority_epoch = AuthorityEpoch::new(record.authority_epoch)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let process_binding = StoreProcessBinding {
        process: HostProcessBinding {
            process_id: record.process_id,
            start_time_100ns: record.process_start_time_100ns,
            image_path: record.process_image_path.as_str().to_owned(),
        },
        job: record.job_name.clone(),
    };
    process_binding
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let handoff = StoreRebindHandoff {
        operation_id: record.operation_id.clone(),
        request_digest: "0".repeat(64),
        requirement: requirement.clone(),
        process_binding: process_binding.clone(),
        candidate_binding_digest: candidate_digest.to_owned(),
        generation,
        authority_epoch,
        store_fence: record.store_fence.as_str().to_owned(),
    };
    let expected_inner_digest = handoff
        .canonical_request_digest()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    let inner_request_digest = record.receipt_request_digest.clone().ok_or_else(|| {
        HostError::RecoveryRequired(
            "committed Store rebind is missing its canonical request digest".to_owned(),
        )
    })?;
    let inner_store_fence = record.receipt_store_fence.clone().ok_or_else(|| {
        HostError::RecoveryRequired(
            "committed Store rebind is missing its receipt fence".to_owned(),
        )
    })?;
    if inner_request_digest != record.request_digest
        || inner_request_digest.as_str() != expected_inner_digest
        || inner_store_fence != record.store_fence
    {
        return Err(HostError::RecoveryRequired(
            "committed Store rebind receipt is not bound to its canonical request".to_owned(),
        ));
    }
    let inner = StoreRebindReceipt {
        operation_id: record.operation_id.clone(),
        request_digest: inner_request_digest.as_str().to_owned(),
        requirement_digest: record.requirement.as_str().to_owned(),
        process_binding,
        candidate_binding_digest: record.candidate_binding_digest.as_str().to_owned(),
        generation: handoff.generation,
        authority_epoch: handoff.authority_epoch,
        store_fence: inner_store_fence.as_str().to_owned(),
    };
    inner
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    Ok(inner)
}
