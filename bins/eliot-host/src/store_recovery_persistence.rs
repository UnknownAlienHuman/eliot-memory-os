use std::path::{Path, PathBuf};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    HostError, HostInstallationEpoch, HostProcessBinding, HostRuntimeControlOperation,
    HostRuntimeControlRequest, HostStoreBootstrapRequirement, HostStoreRecoveryReceipt,
    PlatformHandle, ResourceGeneration, StoreProcessBinding, StoreRebindHandoff,
    StoreRebindReceipt, StoreRebindRecord, StoreRecoveryInnerBinding, StoreRecoveryReopenFence,
    StoreRecoveryTerminationEvidence, TerminatedJobChild, read_bounded_runtime_restart_file,
    read_store_recovery_inner_binding, read_store_recovery_termination_evidence, sha256_json,
    valid_sha256_text,
};

#[cfg(windows)]
use super::host_durable_persistence::{sync_dir, write_durable_file};

#[cfg(all(test, windows))]
use super::host_durable_persistence::ordering;

// F-LOG-HOST-2 (#893) Store-recovery durable observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never Store
// payloads, digests treated as secrets, paths, or arbitrary error text — so
// bounding limits size, not sensitivity (I15.4). These primitives own no
// terminal: a single terminal per failed recovery operation is enforced by
// the outermost `HostComposition` recovery boundary in
// `host_composition_store_recovery.rs`, while these phases correlate by stage
// order only. Exact-record replay is observed as readback, never as a second
// commit; conflicts are observed as preserved, never adopted. Sink outcome
// never alters result/order/status/cleanup.
#[cfg(windows)]
fn store_recovery_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn store_recovery_persist_observe(detail: &str) {
    store_recovery_note_event_log_unavailable();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(test)]
#[cfg(windows)]
mod store_write_fault {
    use std::cell::Cell;

    thread_local! {
        static WRITE_FAULT: Cell<bool> = const { Cell::new(false) };
    }

    /// Inject a one-shot failure of the next store-recovery temp-file write.
    /// Thread-local and consumed once, so parallel tests stay isolated.
    pub(super) fn inject_write_fault() {
        WRITE_FAULT.with(|slot| slot.set(true));
    }

    pub(super) fn clear_write_fault() {
        WRITE_FAULT.with(|slot| slot.set(false));
    }

    pub(super) fn take_write_fault() -> bool {
        WRITE_FAULT.with(|slot| slot.replace(false))
    }
}

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
    // F-LOG-HOST-2 (#893): Store projection boundary. The projected fences
    // are startup evidence only; terminals stay with the outermost recovery
    // boundary.
    store_recovery_persist_observe("host.store-recovery projection requested");
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
    // F-LOG-HOST-2 (#893): projection admitted; receipts on disk were
    // shape-checked only and never adopted as authority here.
    store_recovery_persist_observe("host.store-recovery projection admitted");
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
            // F-LOG-HOST-2 (#893): stale/mismatched mutation preserved as
            // Unknown by the caller, never adopted.
            store_recovery_persist_observe("host.store-recovery intent mutation mismatch preserved");
            return Err(HostError::RecoveryRequired(
                "Store recovery request mutation does not match the durable intent".to_owned(),
            ));
        }
        match request.operation {
            HostRuntimeControlOperation::RecoverStore => {
                if request != &self.recover_request()? {
                    // F-LOG-HOST-2 (#893): changed same-operation content
                    // remains a conflict, never a replay.
                    store_recovery_persist_observe(
                        "host.store-recovery intent replay mismatch preserved",
                    );
                    return Err(HostError::RecoveryRequired(
                        "RecoverStore replay does not match the exact durable request".to_owned(),
                    ));
                }
            }
            HostRuntimeControlOperation::ReconcileStoreRecovery => {}
            _ => {
                // F-LOG-HOST-2 (#893): another operation cannot query this
                // durable intent; preserved, never adopted.
                store_recovery_persist_observe(
                    "host.store-recovery intent operation mismatch preserved",
                );
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
        host_epoch: host.epoch.current.sequence.get(),
        host_lineage: host.epoch.current.lineage_id.as_str().to_owned(),
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
    // F-LOG-HOST-2 (#893): pending-identity load boundary; loaded versus
    // absent stay distinct, failures stay with the outermost terminal.
    store_recovery_persist_observe("host.store-recovery pending load requested");
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            store_recovery_persist_observe("host.store-recovery pending absent");
            return Ok(None);
        }
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
    let identity =
        store_recovery_pending_identity_from_bytes(&bytes, expected_mutation_digest)?;
    store_recovery_persist_observe("host.store-recovery pending loaded");
    Ok(Some(identity))
}

#[cfg(windows)]
fn sync_store_recovery_dir(dir: &Path) -> Result<(), HostError> {
    sync_dir(dir)
}

#[cfg(windows)]
pub(super) fn persist_store_recovery_pending(
    host_state_root: &Path,
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
) -> Result<StoreRecoveryPendingPublication, HostError> {
    // F-LOG-HOST-2 (#893): pending persist boundary. Created versus exact
    // replay stay distinct; conflicts are preserved, never adopted.
    store_recovery_persist_observe("host.store-recovery pending persist requested");
    request.validate().map_err(HostError::RecoveryRequired)?;
    if request.operation != HostRuntimeControlOperation::RecoverStore {
        return Err(HostError::RecoveryRequired(
            "store recovery pending records are reserved for RecoverStore".to_owned(),
        ));
    }
    if host.epoch.current.sequence.get() == 0 {
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
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_store_recovery_dir(&dir)?;
            // F-LOG-HOST-2 (#893): exact-record replay is a readback, never
            // a duplicate commit.
            store_recovery_persist_observe("host.store-recovery pending replay readback");
            return Ok(StoreRecoveryPendingPublication::Replay);
        }
        // F-LOG-HOST-2 (#893): changed same-operation content remains a
        // conflict; the retained record is preserved.
        store_recovery_persist_observe("host.store-recovery pending conflict preserved");
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
        #[cfg(all(test, windows))]
        {
            if store_write_fault::take_write_fault() {
                ordering::record("store_pending_file_write_fault_injected");
                return Err(HostError::Platform(
                    "injected store recovery pending file flush failure".to_owned(),
                ));
            }
        }
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("store_pending_hardlink_attempt");
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("store_pending_publication_dir_sync_success");
                Ok(StoreRecoveryPendingPublication::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let Some(existing) = read_store_recovery_pending_identity(&path)? else {
                    return Err(HostError::RecoveryRequired(
                        "store recovery pending record disappeared during publication".to_owned(),
                    ));
                };
                if existing == identity {
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_store_recovery_dir(&dir)?;
                    // F-LOG-HOST-2 (#893): exact-record replay is a readback,
                    // never a duplicate commit.
                    store_recovery_persist_observe("host.store-recovery pending replay readback");
                    Ok(StoreRecoveryPendingPublication::Replay)
                } else {
                    // F-LOG-HOST-2 (#893): a conflicting winner is preserved;
                    // this attempt stays Unknown.
                    store_recovery_persist_observe(
                        "host.store-recovery pending conflict preserved",
                    );
                    Err(HostError::RecoveryRequired(
                        "store recovery pending record conflicts with the requested operation"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("store_pending_tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("store_pending_tmp_cleanup_done");
    let sync_after_cleanup = sync_store_recovery_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("store_pending_tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("store_pending_tmp_cleanup_dir_sync_error");
        }
    }
    match publication {
        Err(error) => Err(error),
        Ok(value) => {
            match cleanup {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(HostError::RecoveryRequired(format!(
                        "store recovery pending temporary cleanup failed: {error}"
                    )));
                }
            }
            sync_after_cleanup?;
            #[cfg(all(test, windows))]
            ordering::record("store_pending_publication_complete");
            // F-LOG-HOST-2 (#893): created versus replayed publication stay
            // distinct; replay is a readback, never a duplicate commit.
            match value {
                StoreRecoveryPendingPublication::Created => {
                    store_recovery_persist_observe("host.store-recovery pending persisted");
                }
                StoreRecoveryPendingPublication::Replay => {
                    store_recovery_persist_observe("host.store-recovery pending replay readback");
                }
            }
            Ok(value)
        }
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
    // F-LOG-HOST-2 (#893): termination persist boundary. Exact replay is a
    // readback; conflicts are preserved, never adopted.
    store_recovery_persist_observe("host.store-recovery termination persist requested");
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
        host_epoch: host.epoch.current.sequence.get(),
        host_lineage: host.epoch.current.lineage_id.as_str().to_owned(),
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
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_store_recovery_dir(&dir)?;
            // F-LOG-HOST-2 (#893): exact-record replay is a readback, never
            // a duplicate commit.
            store_recovery_persist_observe("host.store-recovery termination replay readback");
            return Ok(());
        }
        // F-LOG-HOST-2 (#893): conflicting termination evidence is preserved;
        // this attempt stays Unknown.
        store_recovery_persist_observe("host.store-recovery termination conflict preserved");
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
        #[cfg(all(test, windows))]
        {
            if store_write_fault::take_write_fault() {
                ordering::record("store_termination_file_write_fault_injected");
                return Err(HostError::Platform(
                    "injected store recovery termination file flush failure".to_owned(),
                ));
            }
        }
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("store_termination_hardlink_attempt");
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("store_termination_publication_dir_sync_success");
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
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_store_recovery_dir(&dir)?;
                    // F-LOG-HOST-2 (#893): exact-record replay is a readback,
                    // never a duplicate commit.
                    store_recovery_persist_observe(
                        "host.store-recovery termination replay readback",
                    );
                    Ok(())
                } else {
                    // F-LOG-HOST-2 (#893): a conflicting winner is preserved;
                    // this attempt stays Unknown.
                    store_recovery_persist_observe(
                        "host.store-recovery termination conflict preserved",
                    );
                    Err(HostError::RecoveryRequired(
                        "Store termination evidence conflicts with the requested operation"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("store_termination_tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("store_termination_tmp_cleanup_done");
    let sync_after_cleanup = sync_store_recovery_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("store_termination_tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("store_termination_tmp_cleanup_dir_sync_error");
        }
    }
    publication?;
    match cleanup {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Store termination temporary cleanup failed: {error}"
            )));
        }
    }
    sync_after_cleanup?;
    // F-LOG-HOST-2 (#893): termination evidence persisted; cleanup observed
    // by the checked cleanup seam only after the receipt is durable.
    store_recovery_persist_observe("host.store-recovery termination persisted");
    Ok(())
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
    // F-LOG-HOST-2 (#893): inner-binding persist boundary. Exact replay is a
    // readback; conflicts are preserved, never adopted.
    store_recovery_persist_observe("host.store-recovery inner persist requested");
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
        host_epoch: host.epoch.current.sequence.get(),
        host_lineage: host.epoch.current.lineage_id.as_str().to_owned(),
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
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_store_recovery_dir(&dir)?;
            // F-LOG-HOST-2 (#893): exact-record replay is a readback, never
            // a duplicate commit.
            store_recovery_persist_observe("host.store-recovery inner replay readback");
            Ok(())
        } else {
            // F-LOG-HOST-2 (#893): a conflicting retained binding is
            // preserved; this attempt stays Unknown.
            store_recovery_persist_observe("host.store-recovery inner conflict preserved");
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
        #[cfg(all(test, windows))]
        {
            if store_write_fault::take_write_fault() {
                ordering::record("store_inner_file_write_fault_injected");
                return Err(HostError::Platform(
                    "injected store recovery inner-binding file flush failure".to_owned(),
                ));
            }
        }
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("store_inner_hardlink_attempt");
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("store_inner_publication_dir_sync_success");
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
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_store_recovery_dir(&dir)?;
                    // F-LOG-HOST-2 (#893): exact-record replay is a readback,
                    // never a duplicate commit.
                    store_recovery_persist_observe("host.store-recovery inner replay readback");
                    Ok(())
                } else {
                    // F-LOG-HOST-2 (#893): a conflicting winner is preserved;
                    // this attempt stays Unknown.
                    store_recovery_persist_observe("host.store-recovery inner conflict preserved");
                    Err(HostError::RecoveryRequired(
                        "Store recovery inner binding conflicts with retained identity".to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("store_inner_tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("store_inner_tmp_cleanup_done");
    let sync_after_cleanup = sync_store_recovery_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("store_inner_tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("store_inner_tmp_cleanup_dir_sync_error");
        }
    }
    publication?;
    match cleanup {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Store recovery inner-binding temporary cleanup failed: {error}"
            )));
        }
    }
    sync_after_cleanup?;
    #[cfg(all(test, windows))]
    ordering::record("store_inner_publication_complete");
    // F-LOG-HOST-2 (#893): inner binding persisted against the exact durable
    // intent and termination evidence.
    store_recovery_persist_observe("host.store-recovery inner persisted");
    Ok(())
}

#[cfg(windows)]
pub(super) fn read_store_recovery_receipt(
    host_state_root: &Path,
    mutation_digest: &str,
) -> Result<Option<HostStoreRecoveryReceipt>, HostError> {
    // F-LOG-HOST-2 (#893): receipt load/compare boundary; loaded versus
    // absent stay distinct, failures stay with the outermost terminal.
    store_recovery_persist_observe("host.store-recovery receipt load requested");
    if !valid_sha256_text(mutation_digest) {
        return Err(HostError::RecoveryRequired(
            "Store recovery receipt path is not a lowercase sha256 mutation".to_owned(),
        ));
    }
    let path = store_recovery_receipt_path(host_state_root, mutation_digest);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            store_recovery_persist_observe("host.store-recovery receipt absent");
            return Ok(None);
        }
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
    store_recovery_persist_observe("host.store-recovery receipt loaded");
    Ok(Some(receipt))
}

#[cfg(windows)]
pub(super) fn persist_store_recovery_receipt(
    host_state_root: &Path,
    receipt: &HostStoreRecoveryReceipt,
) -> Result<(), HostError> {
    // F-LOG-HOST-2 (#893): receipt persist/restore boundary. Exact replay is
    // a readback; a conflicting winner is preserved, never replaced.
    store_recovery_persist_observe("host.store-recovery receipt persist requested");
    receipt.validate().map_err(HostError::RecoveryRequired)?;
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
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_store_recovery_dir(&dir)?;
            // F-LOG-HOST-2 (#893): exact-record replay is a readback, never
            // a duplicate commit.
            store_recovery_persist_observe("host.store-recovery receipt replay readback");
            return Ok(());
        }
        // F-LOG-HOST-2 (#893): a conflicting durable receipt is preserved;
        // the reconstructed authority stays Unknown.
        store_recovery_persist_observe("host.store-recovery receipt conflict preserved");
        return Err(HostError::RecoveryRequired(
            "existing Store recovery receipt conflicts with reconstructed authority".to_owned(),
        ));
    }
    let tmp = dir.join(format!(
        ".{}.receipt.{}.tmp",
        receipt.external_control_mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let bytes = serde_json::to_vec(receipt).map_err(|e| HostError::Platform(e.to_string()))?;
    let publication = (|| {
        #[cfg(all(test, windows))]
        {
            if store_write_fault::take_write_fault() {
                ordering::record("store_receipt_file_write_fault_injected");
                return Err(HostError::Platform(
                    "injected store recovery receipt file flush failure".to_owned(),
                ));
            }
        }
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("store_receipt_hardlink_attempt");
        // Publish with a hard link so a concurrent writer can never replace an
        // already durable outer receipt.  The winner is read back and must be the
        // exact same canonical authority; a conflicting winner remains Unknown.
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_store_recovery_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("store_receipt_publication_dir_sync_success");
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes =
                    read_bounded_runtime_restart_file(&path, 16 * 1024, "Store recovery receipt")?;
                let existing = serde_json::from_slice::<HostStoreRecoveryReceipt>(&bytes).map_err(
                    |error| {
                        HostError::RecoveryRequired(format!(
                            "existing Store recovery receipt is malformed: {error}"
                        ))
                    },
                )?;
                existing.validate().map_err(HostError::RecoveryRequired)?;
                if existing == *receipt {
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_store_recovery_dir(&dir)?;
                    // F-LOG-HOST-2 (#893): exact-record replay is a readback,
                    // never a duplicate commit.
                    store_recovery_persist_observe(
                        "host.store-recovery receipt replay readback",
                    );
                    Ok(())
                } else {
                    // F-LOG-HOST-2 (#893): a conflicting winner is preserved;
                    // this attempt stays Unknown.
                    store_recovery_persist_observe(
                        "host.store-recovery receipt conflict preserved",
                    );
                    Err(HostError::RecoveryRequired(
                        "existing Store recovery receipt conflicts with reconstructed authority"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("store_receipt_tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("store_receipt_tmp_cleanup_done");
    let sync_after_cleanup = sync_store_recovery_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("store_receipt_tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("store_receipt_tmp_cleanup_dir_sync_error");
        }
    }
    publication?;
    match cleanup {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Store recovery receipt temporary cleanup failed: {error}"
            )));
        }
    }
    sync_after_cleanup?;
    // The receipt entry is durable before any pending/termination/inner
    // evidence may be removed.  Cleanup observes this marker and calls the
    // checked `cleanup_store_recovery_supporting_evidence_for` seam only
    // after this return; removing evidence first would lose the only
    // crash-recovery proof of the completed recovery.
    #[cfg(all(test, windows))]
    ordering::record("store_receipt_durable_before_evidence_removal");
    #[cfg(all(test, windows))]
    ordering::record("store_receipt_publication_complete");
    // F-LOG-HOST-2 (#893): receipt restored as the durable authority; the
    // checked cleanup seam removes supporting evidence only after this return.
    store_recovery_persist_observe("host.store-recovery receipt persisted");
    Ok(())
}

#[cfg(windows)]
pub(super) fn cleanup_store_recovery_supporting_evidence_for(
    host_state_root: &Path,
    mutation_digest: &str,
) -> Result<(), HostError> {
    // F-LOG-HOST-2 (#893): supporting-evidence cleanup boundary. Removal
    // commits only after the durable receipt readback above; cleanup failure
    // is a distinct non-success owned by the caller's terminal.
    store_recovery_persist_observe("host.store-recovery cleanup requested");
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
    #[cfg(all(test, windows))]
    ordering::record("cleanup_for_evidence_remove_attempt");
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
    #[cfg(all(test, windows))]
    ordering::record("cleanup_for_evidence_remove_done");
    sync_store_recovery_dir(&dir)?;
    #[cfg(all(test, windows))]
    ordering::record("cleanup_for_dir_sync_success");
    // F-LOG-HOST-2 (#893): supporting evidence removed with the receipt left
    // durable; absence of this record means cleanup did not complete.
    store_recovery_persist_observe("host.store-recovery cleanup removed");
    Ok(())
}

#[cfg(windows)]
pub(super) fn cleanup_completed_store_recovery_supporting_evidence(
    host_state_root: &Path,
) -> Result<(), HostError> {
    // F-LOG-HOST-2 (#893): completed-evidence sweep boundary; only fenced
    // intents with a durable receipt lose their supporting evidence.
    store_recovery_persist_observe("host.store-recovery cleanup-completed requested");
    let fences = load_durable_store_recoveries(host_state_root)?;
    let dir = store_recovery_store_dir(host_state_root);
    for fence in fences {
        if !store_recovery_receipt_path(host_state_root, &fence.mutation_digest).exists() {
            continue;
        }
        #[cfg(all(test, windows))]
        ordering::record("cleanup_completed_for_fence");
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
    #[cfg(all(test, windows))]
    ordering::record("cleanup_completed_remove_done");
    sync_store_recovery_dir(&dir)?;
    #[cfg(all(test, windows))]
    ordering::record("cleanup_completed_dir_sync_success");
    // F-LOG-HOST-2 (#893): completed sweep committed; absence of this record
    // means the sweep did not complete.
    store_recovery_persist_observe("host.store-recovery cleanup-completed removed");
    Ok(())
}

#[cfg(windows)]
pub(super) fn has_store_recovery_pending(
    host_state_root: &Path,
    digest: &str,
) -> Result<bool, HostError> {
    // F-LOG-HOST-2 (#893): pending probe boundary. Present versus absent
    // stay distinct; a present intent keeps the caller Unknown, never a
    // second commit.
    let path = store_recovery_pending_path(host_state_root, digest);
    let present = read_store_recovery_pending_identity(&path)?
        .is_some_and(|identity| identity.mutation_digest == digest);
    if present {
        store_recovery_persist_observe("host.store-recovery pending present");
    } else {
        store_recovery_persist_observe("host.store-recovery pending absent");
    }
    Ok(present)
}

#[cfg(windows)]
pub(super) fn rebind_store_recovery_receipt(
    receipt: &HostStoreRecoveryReceipt,
    request: &HostRuntimeControlRequest,
) -> Result<HostStoreRecoveryReceipt, HostError> {
    // F-LOG-HOST-2 (#893): receipt rebind boundary. An exact rebind is a
    // response-loss readback for the new request identity, never a duplicate
    // commit; a mismatched mutation stays a preserved conflict.
    store_recovery_persist_observe("host.store-recovery rebind requested");
    if request.operation != HostRuntimeControlOperation::ReconcileStoreRecovery
        || receipt.external_control_mutation_digest != request.mutation_digest
    {
        store_recovery_persist_observe("host.store-recovery rebind conflict preserved");
        return Err(HostError::RecoveryRequired(
            "store recovery receipt is not bound to the requested mutation".to_owned(),
        ));
    }
    let mut rebound = receipt.clone();
    rebound.request_digest = request.request_digest.clone();
    rebound.receipt_digest = rebound.computed_digest().map_err(HostError::Platform)?;
    rebound.validate().map_err(HostError::Platform)?;
    store_recovery_persist_observe("host.store-recovery rebind readback");
    Ok(rebound)
}

#[cfg(windows)]
pub(super) fn committed_store_rebind_receipt(
    record: &StoreRebindRecord,
    requirement: &HostStoreBootstrapRequirement,
    candidate_digest: &str,
) -> Result<StoreRebindReceipt, HostError> {
    // F-LOG-HOST-2 (#893): committed-inner readback boundary. Rebuilding the
    // inner receipt from the durable committed record is a readback, never a
    // new inner commit; substitution stays a typed failure.
    store_recovery_persist_observe("host.store-recovery committed rebind requested");
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
    if record.authority_epoch != requirement.state_fence.authority_epoch.sequence.get() {
        return Err(HostError::RecoveryRequired(
            "committed Store rebind epoch does not match the canonical requirement fence"
                .to_owned(),
        ));
    }
    let authority_epoch = requirement.state_fence.authority_epoch.clone();
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
    store_recovery_persist_observe("host.store-recovery committed rebind readback");
    Ok(inner)
}

#[cfg(test)]
#[cfg(windows)]
mod durability_repair_tests {
    use super::*;
    use crate::TestResult;
    use crate::host_durable_persistence::{ordering, test_fault};
    use crate::{HostInstallationEpoch, PlatformHandle};
    use uuid::Uuid;

    fn test_host() -> Result<HostInstallationEpoch, Box<dyn std::error::Error>> {
        Ok(crate::fresh_host_epoch(
            PlatformHandle::new("test-installation")?,
            None,
        )?)
    }

    fn temp_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-host-store-durability-{label}-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn store_request(
        digest: &str,
        label: &str,
    ) -> Result<HostRuntimeControlRequest, Box<dyn std::error::Error>> {
        Ok(HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RecoverStore,
            PlatformHandle::new(label)?,
            PlatformHandle::new(digest.to_owned())?,
        )?)
    }

    fn make_store_receipt(
        digest: &str,
    ) -> Result<crate::HostStoreRecoveryReceipt, Box<dyn std::error::Error>> {
        let mut receipt = crate::HostStoreRecoveryReceipt {
            external_control_mutation_digest: PlatformHandle::new(digest.to_owned())?,
            request_digest: PlatformHandle::new("a".repeat(64))?,
            store_rebind_request_digest: PlatformHandle::new("b".repeat(64))?,
            store_fence: PlatformHandle::new("c".repeat(64))?,
            // Must satisfy HostStoreRecoveryReceipt::validate, which requires
            // the pid:<u32>:start:<u64> identity shape (not a sha256 digest).
            new_store_process_id: PlatformHandle::new("pid:4202:start:42020")?,
            kernel_generation: PlatformHandle::new("e".repeat(64))?,
            activation_nonce_digest: PlatformHandle::new("f".repeat(64))?,
            ready_receipt_digest: PlatformHandle::new("1".repeat(64))?,
            receipt_digest: PlatformHandle::new("2".repeat(64))?,
        };
        receipt.receipt_digest = receipt.computed_digest()?;
        Ok(receipt)
    }

    #[test]
    fn store_pending_file_flush_failure_is_not_success() -> TestResult {
        let root = temp_root("pending-flush")?;
        let host = test_host()?;
        let digest = "b4".repeat(32);
        let request = store_request(&digest, "store-pending-flush")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        ordering::clear();
        store_write_fault::inject_write_fault();
        let result = persist_store_recovery_pending(&root, &request, &host);
        assert!(result.is_err(), "injected file flush failure is not success");
        assert!(
            matches!(result, Err(crate::HostError::Platform(_))),
            "file flush failure must be a typed HostError"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"store_pending_file_write_fault_injected".to_owned()),
            "fault injection must be visible: {log:?}"
        );
        assert!(
            !store_recovery_pending_path(&root, &digest).exists(),
            "a failed temp-file write must not publish a pending record"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        assert_eq!(
            persist_store_recovery_pending(&root, &request, &host)?,
            StoreRecoveryPendingPublication::Created
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_pending_exact_record_replays_idempotent() -> TestResult {
        let root = temp_root("pending-replay")?;
        let host = test_host()?;
        let digest = "b7".repeat(32);
        let request = store_request(&digest, "store-pending-replay")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        assert_eq!(
            persist_store_recovery_pending(&root, &request, &host)?,
            StoreRecoveryPendingPublication::Created
        );
        ordering::clear();
        assert_eq!(
            persist_store_recovery_pending(&root, &request, &host)?,
            StoreRecoveryPendingPublication::Replay
        );
        let log = ordering::take_log();
        assert!(
            log.iter().any(|e| e == "dir_sync_success"),
            "replay must re-confirm the directory entry: {log:?}"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_pending_conflicting_record_is_fail_closed() -> TestResult {
        let root = temp_root("pending-conflict")?;
        let host = test_host()?;
        let digest = "b8".repeat(32);
        let request = store_request(&digest, "store-pending-conflict")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let conflicting = store_request(&digest, "store-pending-conflict-other")?;
        let result = persist_store_recovery_pending(&root, &conflicting, &host);
        assert!(
            matches!(result, Err(crate::HostError::RecoveryRequired(_))),
            "a conflicting pending record must fail closed: {result:?}"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    fn make_termination_evidence(
        request: &HostRuntimeControlRequest,
        host: &HostInstallationEpoch,
        process_id: u32,
        start_time_100ns: u64,
        image_path: &str,
        job_name: &str,
    ) -> Result<StoreRecoveryTerminationEvidence, Box<dyn std::error::Error>> {
        Ok(StoreRecoveryTerminationEvidence {
            wire: request.wire.as_str().to_owned(),
            operation: request.operation.clone(),
            request_id: request.request_id.as_str().to_owned(),
            mutation_digest: request.mutation_digest.as_str().to_owned(),
            request_digest: request.request_digest.as_str().to_owned(),
            host_epoch: host.epoch.current.sequence.get(),
            host_lineage: host.epoch.current.lineage_id.as_str().to_owned(),
            process_id,
            process_start_time_100ns: start_time_100ns,
            process_image_path: image_path.to_owned(),
            job_name: job_name.to_owned(),
            job_empty: true,
            root_reaped: true,
            restart_attempt: 1,
        })
    }

    fn make_inner_handoff(
        host: &HostInstallationEpoch,
    ) -> Result<StoreRebindHandoff, Box<dyn std::error::Error>> {
        use eliot_contracts::{EpochLineageId, ResourceGeneration, StateFence};
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
        let sequence = std::num::NonZeroU64::new(7).ok_or("sequence must be non-zero")?;
        let authority_epoch = eliot_contracts::EpochId::new(lineage, sequence)?;
        let generation = ResourceGeneration::genesis();
        let requirement = HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)?,
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store")?,
            store_generation: generation,
            state_fence: StateFence::new(authority_epoch.clone(), generation),
            launch_nonce: PlatformHandle::new("store-durability-launch-nonce")?,
            connection_id: PlatformHandle::new("store-durability-connection")?,
            expected_peer_sid: PlatformHandle::new("S-1-5-18")?,
            expected_peer_session_id: 0,
            approved_artifact_hash: PlatformHandle::new("a".repeat(64))?,
            approved_config_hash: PlatformHandle::new("b".repeat(64))?,
            timeout_ms: 5_000,
        };
        let process_binding = StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 4_202,
                start_time_100ns: 42_020,
                image_path: r"C:\Eliot\store-new.exe".to_owned(),
            },
            job: PlatformHandle::new(r"Local\Eliot-Store-new")?,
        };
        let mut handoff = StoreRebindHandoff {
            operation_id: PlatformHandle::new("store-durability-inner")?,
            request_digest: "0".repeat(64),
            requirement,
            process_binding,
            candidate_binding_digest: "d".repeat(64),
            generation,
            authority_epoch,
            store_fence: "e".repeat(64),
        };
        handoff.request_digest = handoff.canonical_request_digest()?;
        handoff.validate_canonical_digest()?;
        let _ = host;
        Ok(handoff)
    }

    #[test]
    fn store_termination_file_flush_failure_is_not_success() -> TestResult {
        let root = temp_root("termination-flush")?;
        let host = test_host()?;
        let digest = "c4".repeat(32);
        let request = store_request(&digest, "store-termination-flush")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let evidence = make_termination_evidence(
            &request,
            &host,
            4_101,
            41_010,
            r"C:\Eliot\store-old.exe",
            r"Local\Eliot-Store-old",
        )?;
        evidence.validate_for_digest(&digest)?;
        let terminated_bytes = serde_json::to_vec(&evidence)?;
        let termination_path = store_recovery_termination_path(&root, &digest);
        std::fs::write(&termination_path, &terminated_bytes)?;
        let conflicting = make_termination_evidence(
            &request,
            &host,
            4_102,
            41_020,
            r"C:\Eliot\store-old.exe",
            r"Local\Eliot-Store-old",
        )?;
        // Publish the first record through the durable publisher on a fresh
        // digest so the flush-fault path below exercises publication, not the
        // idempotent-readback branch above.
        let digest2 = "c5".repeat(32);
        let request2 = store_request(&digest2, "store-termination-flush")?;
        persist_store_recovery_pending(&root, &request2, &host)?;
        let pending_path2 = store_recovery_pending_path(&root, &digest2);
        assert!(pending_path2.exists());
        let _ = conflicting;
        ordering::clear();
        store_write_fault::inject_write_fault();
        // The termination publisher requires a live terminated child, which
        // cannot be fabricated without weakening the check; exercise the
        // shared temp-file flush-fault seam through the inner-binding
        // publisher instead, which fails closed on the same error before it
        // can report success or durable ordering.
        let handoff = make_inner_handoff(&host)?;
        let t2 = make_termination_evidence(
            &request2,
            &host,
            4_101,
            41_010,
            r"C:\Eliot\store-old.exe",
            r"Local\Eliot-Store-old",
        )?;
        let t2_bytes = serde_json::to_vec(&t2)?;
        std::fs::write(store_recovery_termination_path(&root, &digest2), &t2_bytes)?;
        let result = persist_store_recovery_inner_binding(&root, &request2, &host, &handoff);
        assert!(result.is_err(), "injected file flush failure is not success");
        assert!(
            matches!(result, Err(crate::HostError::Platform(_))),
            "file flush failure must be a typed HostError"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"store_inner_file_write_fault_injected".to_owned()),
            "fault injection must be visible: {log:?}"
        );
        assert!(
            !store_recovery_inner_binding_path(&root, &digest2).exists(),
            "a failed temp-file write must not publish an inner binding"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_termination_dir_sync_failure_is_not_success() -> TestResult {
        let root = temp_root("termination-dirsync")?;
        let host = test_host()?;
        let digest = "c6".repeat(32);
        let request = store_request(&digest, "store-termination-dirsync")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let evidence = make_termination_evidence(
            &request,
            &host,
            4_101,
            41_010,
            r"C:\Eliot\store-old.exe",
            r"Local\Eliot-Store-old",
        )?;
        let evidence_bytes = serde_json::to_vec(&evidence)?;
        std::fs::write(store_recovery_termination_path(&root, &digest), &evidence_bytes)?;
        // The durable termination publisher validates the exact live
        // predecessor contour, which stays covered by the inner-binding seam:
        // an injected directory-sync failure there must not report success
        // and must leave the termination evidence in place for retry.
        let digest2 = "c7".repeat(32);
        let request2 = store_request(&digest2, "store-termination-dirsync")?;
        persist_store_recovery_pending(&root, &request2, &host)?;
        let t2 = make_termination_evidence(
            &request2,
            &host,
            4_101,
            41_010,
            r"C:\Eliot\store-old.exe",
            r"Local\Eliot-Store-old",
        )?;
        std::fs::write(
            store_recovery_termination_path(&root, &digest2),
            serde_json::to_vec(&t2)?,
        )?;
        let handoff = make_inner_handoff(&host)?;
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        let result = persist_store_recovery_inner_binding(&root, &request2, &host, &handoff);
        assert!(result.is_err(), "injected dir sync failure is not success");
        assert!(
            matches!(result, Err(crate::HostError::Platform(_))),
            "dir sync failure must be a typed HostError"
        );
        assert!(
            store_recovery_pending_path(&root, &digest2).exists(),
            "pending intent must remain after a failed inner-binding dir sync"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_pending_dir_sync_permission_denied_propagates() -> TestResult {
        let root = temp_root("pending-perm")?;
        let host = test_host()?;
        let digest = "b1".repeat(32);
        let request = store_request(&digest, "store-pending-perm")?;
        test_fault::clear_sync_fault();
        ordering::clear();
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        let result = persist_store_recovery_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        // The link precedes the failed directory sync, so the record exists; a
        // retry must confirm durability instead of replaying it.
        assert!(store_recovery_pending_path(&root, &digest).exists());
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        assert!(persist_store_recovery_pending(&root, &request, &host).is_err());
        test_fault::clear_sync_fault();
        assert_eq!(
            persist_store_recovery_pending(&root, &request, &host)?,
            StoreRecoveryPendingPublication::Replay
        );
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_pending_dir_sync_invalid_input_propagates() -> TestResult {
        let root = temp_root("pending-invalid")?;
        let host = test_host()?;
        let digest = "b2".repeat(32);
        let request = store_request(&digest, "store-pending-invalid")?;
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::InvalidInput);
        let result = persist_store_recovery_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_pending_dir_sync_unsupported_propagates() -> TestResult {
        let root = temp_root("pending-unsupported")?;
        let host = test_host()?;
        let digest = "b3".repeat(32);
        let request = store_request(&digest, "store-pending-unsupported")?;
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::Unsupported);
        let result = persist_store_recovery_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_receipt_file_flush_failure_is_not_success() -> TestResult {
        let root = temp_root("receipt-flush")?;
        let host = test_host()?;
        let digest = "e1".repeat(32);
        let request = store_request(&digest, "store-receipt-flush")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let receipt = make_store_receipt(&digest)?;
        ordering::clear();
        store_write_fault::inject_write_fault();
        let result = persist_store_recovery_receipt(&root, &receipt);
        assert!(result.is_err(), "injected file flush failure is not success");
        assert!(
            matches!(result, Err(crate::HostError::Platform(_))),
            "file flush failure must be a typed HostError"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"store_receipt_file_write_fault_injected".to_owned()),
            "fault injection must be visible: {log:?}"
        );
        assert!(
            !store_recovery_receipt_path(&root, &digest).exists(),
            "a failed temp-file write must not publish a receipt"
        );
        assert!(
            store_recovery_pending_path(&root, &digest).exists(),
            "pending evidence must remain when the receipt write fails"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_receipt_exact_record_replays_idempotent() -> TestResult {
        let root = temp_root("receipt-replay")?;
        let host = test_host()?;
        let digest = "e2".repeat(32);
        let request = store_request(&digest, "store-receipt-replay")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let receipt = make_store_receipt(&digest)?;
        persist_store_recovery_receipt(&root, &receipt)?;
        ordering::clear();
        persist_store_recovery_receipt(&root, &receipt)?;
        let log = ordering::take_log();
        assert!(
            log.iter().any(|e| e == "dir_sync_success"),
            "receipt replay must re-confirm the directory entry: {log:?}"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_receipt_conflicting_record_is_fail_closed() -> TestResult {
        let root = temp_root("receipt-conflict")?;
        let host = test_host()?;
        let digest = "e3".repeat(32);
        let request = store_request(&digest, "store-receipt-conflict")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let receipt = make_store_receipt(&digest)?;
        persist_store_recovery_receipt(&root, &receipt)?;
        let mut conflicting = receipt.clone();
        conflicting.ready_receipt_digest = PlatformHandle::new("9".repeat(64))?;
        conflicting.receipt_digest = conflicting.computed_digest()?;
        let result = persist_store_recovery_receipt(&root, &conflicting);
        assert!(
            matches!(result, Err(crate::HostError::RecoveryRequired(_))),
            "a conflicting receipt must fail closed: {result:?}"
        );
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_receipt_durable_before_pending_termination_inner_removal() -> TestResult {
        let root = temp_root("receipt-ordering")?;
        let host = test_host()?;
        let digest = "e5".repeat(32);
        let request = store_request(&digest, "store-receipt-ordering")?;
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let termination = make_termination_evidence(
            &request,
            &host,
            4_101,
            41_010,
            r"C:\Eliot\store-old.exe",
            r"Local\Eliot-Store-old",
        )?;
        std::fs::write(
            store_recovery_termination_path(&root, &digest),
            serde_json::to_vec(&termination)?,
        )?;
        let handoff = make_inner_handoff(&host)?;
        let termination_digest = crate::sha256_json(&termination)?;
        let binding = StoreRecoveryInnerBinding {
            wire: request.wire.as_str().to_owned(),
            operation: request.operation.clone(),
            request_id: request.request_id.as_str().to_owned(),
            external_control_mutation_digest: request.mutation_digest.as_str().to_owned(),
            external_control_request_digest: request.request_digest.as_str().to_owned(),
            host_epoch: host.epoch.current.sequence.get(),
            host_lineage: host.epoch.current.lineage_id.as_str().to_owned(),
            terminated_store_evidence_digest: termination_digest,
            store_rebind_operation_id: handoff.operation_id.as_str().to_owned(),
            store_rebind_request_digest: handoff.request_digest.clone(),
            handoff: handoff.clone(),
        };
        binding.validate_for_pending(
            &read_store_recovery_pending_identity(&store_recovery_pending_path(
                &root,
                &digest,
            ))?
            .ok_or("pending must exist")?,
            &termination,
        )?;
        std::fs::write(
            store_recovery_inner_binding_path(&root, &digest),
            serde_json::to_vec(&binding)?,
        )?;
        // Publish the receipt through the durable publisher only; evidence
        // removal is the separate checked cleanup seam below.
        let receipt = make_store_receipt(&digest)?;
        ordering::clear();
        persist_store_recovery_receipt(&root, &receipt)?;
        let log = ordering::take_log();
        let durable_idx = log
            .iter()
            .position(|e| e == "store_receipt_durable_before_evidence_removal")
            .ok_or("receipt durable marker missing")?;
        let complete_idx = log
            .iter()
            .position(|e| e == "store_receipt_publication_complete")
            .ok_or("receipt publication complete marker missing")?;
        assert!(
            durable_idx < complete_idx,
            "receipt durability must be established before publication returns: {log:?}"
        );
        assert!(
            store_recovery_pending_path(&root, &digest).exists(),
            "receipt publication must not remove pending evidence itself"
        );
        assert!(
            store_recovery_termination_path(&root, &digest).exists(),
            "receipt publication must not remove termination evidence itself"
        );
        assert!(
            store_recovery_inner_binding_path(&root, &digest).exists(),
            "receipt publication must not remove inner-binding evidence itself"
        );
        // The checked cleanup seam removes all three only after the receipt
        // is durable, and commits the removal with a final directory sync.
        ordering::clear();
        cleanup_store_recovery_supporting_evidence_for(&root, &digest)?;
        let cleanup_log = ordering::take_log();
        assert!(
            cleanup_log
                .iter()
                .position(|e| e == "cleanup_for_evidence_remove_attempt")
                .is_some(),
            "cleanup must record evidence removal: {cleanup_log:?}"
        );
        assert!(
            cleanup_log.contains(&"cleanup_for_dir_sync_success".to_owned()),
            "cleanup must commit the final directory entry: {cleanup_log:?}"
        );
        assert!(!store_recovery_pending_path(&root, &digest).exists());
        assert!(!store_recovery_termination_path(&root, &digest).exists());
        assert!(!store_recovery_inner_binding_path(&root, &digest).exists());
        assert!(store_recovery_receipt_path(&root, &digest).exists());
        test_fault::clear_sync_fault();
        store_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_receipt_dir_sync_failure_does_not_remove_evidence() -> TestResult {
        let root = temp_root("receipt-fail-evidence")?;
        let host = test_host()?;
        let digest = "e4".repeat(32);
        let request = store_request(&digest, "store-receipt-fail")?;
        test_fault::clear_sync_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let receipt = make_store_receipt(&digest)?;
        test_fault::inject_sync_fault(std::io::ErrorKind::Unsupported);
        let result = persist_store_recovery_receipt(&root, &receipt);
        assert!(result.is_err(), "receipt dir sync failure must propagate");
        assert!(
            store_recovery_pending_path(&root, &digest).exists(),
            "pending must remain"
        );
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_ordering_file_sync_before_dir_sync() -> TestResult {
        let root = temp_root("store-ordering")?;
        let host = test_host()?;
        let digest = "f4".repeat(32);
        let request = store_request(&digest, "store-ordering")?;
        test_fault::clear_sync_fault();
        ordering::clear();
        persist_store_recovery_pending(&root, &request, &host)?;
        let log = ordering::take_log();
        let file_idx = log
            .iter()
            .position(|e| e == "file_sync_success")
            .ok_or("file sync logged")?;
        let dir_idx = log
            .iter()
            .position(|e| e.contains("store_pending_publication_dir_sync_success"))
            .ok_or("dir sync logged")?;
        assert!(
            file_idx < dir_idx,
            "file sync must precede dir sync: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn store_cleanup_failed_dir_sync_propagates() -> TestResult {
        let root = temp_root("store-cleanup-fail")?;
        let host = test_host()?;
        let digest = "a5".repeat(32);
        let request = store_request(&digest, "store-cleanup-fail")?;
        test_fault::clear_sync_fault();
        persist_store_recovery_pending(&root, &request, &host)?;
        let receipt = make_store_receipt(&digest)?;
        let receipt_path = store_recovery_receipt_path(&root, &digest);
        std::fs::write(&receipt_path, serde_json::to_vec(&receipt)?)?;
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        let result = cleanup_store_recovery_supporting_evidence_for(&root, &digest);
        assert!(result.is_err(), "cleanup dir sync failure must propagate");
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    #[ignore = "child-process target of the abrupt-termination test; returns early unless spawned with its environment"]
    fn durability_child_store() -> TestResult {
        if std::env::var("ELIOT_HOST_DURABILITY_CHILD_STORE").is_err() {
            return Ok(());
        }
        let root = PathBuf::from(std::env::var("ELIOT_HOST_CHILD_ROOT")?);
        let digest = std::env::var("ELIOT_HOST_CHILD_DIGEST")?;
        let mode = std::env::var("ELIOT_HOST_CHILD_MODE").unwrap_or_else(|_| "success".to_owned());
        let host = test_host()?;
        let request = store_request(&digest, "store-child")?;
        if mode == "success" {
            persist_store_recovery_pending(&root, &request, &host)?;
            let _ = std::fs::File::open(&root).and_then(|f| f.sync_all());
        } else if mode == "fault" {
            if !store_recovery_pending_path(&root, &digest).exists() {
                persist_store_recovery_pending(&root, &request, &host)?;
            }
            let receipt = make_store_receipt(&digest)?;
            test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
            let result = persist_store_recovery_receipt(&root, &receipt);
            let marker = root.join("child_store_fault_marker");
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
    fn store_abrupt_child_causal_success_and_fault_reopen() -> TestResult {
        let root = temp_root("store-abrupt-causal")?;
        let digest = "b5".repeat(32);
        let exe = std::env::current_exe()?;
        let mut child = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("store_recovery_persistence::durability_repair_tests::durability_child_store")
            .env("ELIOT_HOST_DURABILITY_CHILD_STORE", "1")
            .env("ELIOT_HOST_CHILD_ROOT", &root)
            .env("ELIOT_HOST_CHILD_DIGEST", &digest)
            .env("ELIOT_HOST_CHILD_MODE", "success")
            .spawn()?;
        let status = child.wait()?;
        assert!(!status.success(), "child must abort");
        let fences = load_durable_store_recoveries(&root)?;
        assert!(fences.iter().any(|f| f.mutation_digest == digest));
        let digest2 = "b6".repeat(32);
        let mut child2 = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("store_recovery_persistence::durability_repair_tests::durability_child_store")
            .env("ELIOT_HOST_DURABILITY_CHILD_STORE", "1")
            .env("ELIOT_HOST_CHILD_ROOT", &root)
            .env("ELIOT_HOST_CHILD_DIGEST", &digest2)
            .env("ELIOT_HOST_CHILD_MODE", "fault")
            .spawn()?;
        let status2 = child2.wait()?;
        assert!(!status2.success());
        let marker = root.join("child_store_fault_marker");
        let bytes = std::fs::read(&marker)?;
        assert_eq!(bytes, b"fault_propagated");
        assert!(store_recovery_pending_path(&root, &digest2).exists());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }
}
