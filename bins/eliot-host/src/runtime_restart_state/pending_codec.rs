//! Runtime-restart pending wire codec.
//!
//! Architecture: canonical `ELIOT_ARCHITECTURE.md` §A2.3 (Modular architecture),
//! §A13.6 (Operational Recovery State), and `ARCH-AUTH-01` (Authority explicit,
//! scoped and fenced). Implementation: canonical `ELIOT_IMPLEMENTATION.md`
//! §I1.2 (Host ownership), §I2.19 (Layered module cell), and §I2.23
//! (Capability-family topology and crate extraction decisions).
//!
//! This child owns pending identity construction, canonical wire encoding,
//! bounded decoding, and validation only. The parent retains path resolution,
//! persistence, synchronization, and effect authority.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use super::super::{
    HostError, HostInstallationEpoch, HostRuntimeControlOperation, HostRuntimeControlRequest,
    PlatformHandle, valid_sha256_text,
};
use super::read_bounded_runtime_restart_file;

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeRestartPendingIdentity {
    wire: String,
    operation: HostRuntimeControlOperation,
    request_id: String,
    mutation_digest: String,
    request_digest: String,
    host_epoch: u64,
    host_lineage: String,
}

#[cfg(windows)]
impl RuntimeRestartPendingIdentity {
    pub(super) fn mutation_digest(&self) -> &str {
        &self.mutation_digest
    }
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
pub(super) fn runtime_restart_pending_identity(
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
fn runtime_restart_created_at(now: SystemTime) -> Result<String, HostError> {
    let millis = now.duration_since(UNIX_EPOCH).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "runtime restart pending clock precedes Unix epoch: {error}"
        ))
    })?;
    Ok(millis.as_millis().to_string())
}

#[cfg(windows)]
pub(super) fn runtime_restart_pending_payload(
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
        "created_at": runtime_restart_created_at(SystemTime::now())?,
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
pub(super) fn read_runtime_restart_pending_identity(
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

#[cfg(all(test, windows))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn created_at_preserves_exact_unix_milliseconds() {
        let observed = UNIX_EPOCH + Duration::from_millis(42);
        assert!(matches!(
            runtime_restart_created_at(observed).as_deref(),
            Ok("42")
        ));
    }

    #[test]
    fn created_at_rejects_clock_before_unix_epoch() {
        let observed = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("one second before Unix epoch must be representable");
        assert!(matches!(
            runtime_restart_created_at(observed),
            Err(HostError::RecoveryRequired(_))
        ));
    }
}
