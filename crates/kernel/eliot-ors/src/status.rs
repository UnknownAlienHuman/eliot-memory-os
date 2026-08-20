use std::path::Path;

use eliot_runtime_contracts::{
    HealthDimension, SupervisionLeaseVerificationContext, SupervisionLeaseVerifier,
    SupervisionTrustAnchor,
};
use redb::{ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use serde::de::DeserializeOwned;

use crate::{MAX_RECOVERY_PAGE, SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt};

const SUPERVISION_LEASE_STAGED: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_staged_v1");
const SUPERVISION_LEASE_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_current_v1");
const SUPERVISION_LEASE_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_history_v1");
const SUPERVISION_LEASE_RESULTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_supervision_lease_results_v1");

const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_HISTORY: u16 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrsSupervisionStatusError {
    Missing(String),
    AccessDenied(String),
    MigrationRequired(String),
    Corrupt(String),
    Unknown(String),
}

impl std::fmt::Display for OrsSupervisionStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(r) => write!(f, "missing: {r}"),
            Self::AccessDenied(r) => write!(f, "access denied: {r}"),
            Self::MigrationRequired(r) => write!(f, "migration required: {r}"),
            Self::Corrupt(r) => write!(f, "corrupt: {r}"),
            Self::Unknown(r) => write!(f, "unknown: {r}"),
        }
    }
}

impl std::error::Error for OrsSupervisionStatusError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisionStatusReason {
    Healthy,
    MissingCurrent,
    StagedOnly,
    Expired,
    SignatureInvalid(String),
    BindingMismatch(String),
    CorruptRecord(String),
    VerificationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisionStatusProjection {
    pub lease_id: String,
    pub health: HealthDimension,
    pub heartbeat: HealthDimension,
    pub reason: SupervisionStatusReason,
    pub current: Option<SupervisionLeaseSnapshot>,
    pub staged: Option<SupervisionLeaseStageReceipt>,
    pub history: Vec<SupervisionLeaseSnapshot>,
}

#[allow(clippy::needless_pass_by_value)]
fn map_io_error(err: std::io::Error) -> OrsSupervisionStatusError {
    match err.kind() {
        std::io::ErrorKind::NotFound => OrsSupervisionStatusError::Missing(err.to_string()),
        std::io::ErrorKind::PermissionDenied => {
            OrsSupervisionStatusError::AccessDenied(err.to_string())
        }
        _ => OrsSupervisionStatusError::Unknown(err.to_string()),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_db_error(err: redb::DatabaseError) -> OrsSupervisionStatusError {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("os error 5")
    {
        OrsSupervisionStatusError::AccessDenied(msg)
    } else if lower.contains("not found") || lower.contains("no such file") {
        OrsSupervisionStatusError::Missing(msg)
    } else {
        OrsSupervisionStatusError::Corrupt(msg)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_tx_error(err: redb::TransactionError) -> OrsSupervisionStatusError {
    OrsSupervisionStatusError::Corrupt(err.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn map_table_error(err: redb::TableError) -> OrsSupervisionStatusError {
    let msg = err.to_string();
    if msg.contains("does not exist") {
        OrsSupervisionStatusError::MigrationRequired(msg)
    } else {
        OrsSupervisionStatusError::Corrupt(msg)
    }
}

fn decode_named<T: DeserializeOwned>(
    value: &str,
    record_type: &'static str,
) -> Result<T, OrsSupervisionStatusError> {
    serde_json::from_str::<T>(value)
        .map_err(|e| OrsSupervisionStatusError::Corrupt(format!("{record_type}: {e}")))
}

fn validate_path(path: &Path) -> Result<(), OrsSupervisionStatusError> {
    if !path.is_absolute() {
        return Err(OrsSupervisionStatusError::Unknown(
            "absolute path required".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| OrsSupervisionStatusError::Unknown("path must have parent".to_owned()))?;
    if parent.as_os_str().is_empty() {
        return Err(OrsSupervisionStatusError::Unknown(
            "path must have parent".to_owned(),
        ));
    }
    match std::fs::symlink_metadata(parent) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(OrsSupervisionStatusError::Unknown(
                "parent must be directory".to_owned(),
            ));
        }
        Err(e) => return Err(map_io_error(e)),
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(()),
        Ok(_) => Err(OrsSupervisionStatusError::Corrupt(
            "existing path is not a regular file".to_owned(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(OrsSupervisionStatusError::Missing(e.to_string()))
        }
        Err(e) => Err(map_io_error(e)),
    }
}

fn has_table(
    read: &redb::ReadTransaction,
    def: TableDefinition<&str, &str>,
) -> Result<bool, OrsSupervisionStatusError> {
    match read.open_table(def) {
        Ok(_) => Ok(true),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(e) => Err(map_table_error(e)),
    }
}

fn check_schema(read: &redb::ReadTransaction) -> Result<(), OrsSupervisionStatusError> {
    let expected = [
        (SUPERVISION_LEASE_STAGED, "ors_supervision_lease_staged_v1"),
        (
            SUPERVISION_LEASE_CURRENT,
            "ors_supervision_lease_current_v1",
        ),
        (
            SUPERVISION_LEASE_HISTORY,
            "ors_supervision_lease_history_v1",
        ),
        (
            SUPERVISION_LEASE_RESULTS,
            "ors_supervision_lease_results_v1",
        ),
    ];
    let mut present = Vec::new();
    let mut absent = Vec::new();
    for (def, name) in expected {
        if has_table(read, def)? {
            present.push(name.to_owned());
        } else {
            absent.push(name.to_owned());
        }
    }
    if absent.is_empty() {
        return Ok(());
    }
    let any_table = read
        .list_tables()
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
        .next()
        .is_some();
    if any_table {
        return Err(OrsSupervisionStatusError::MigrationRequired(format!(
            "missing supervision tables: {}",
            absent.join(",")
        )));
    }
    Err(OrsSupervisionStatusError::Missing(
        "empty database without supervision tables".to_owned(),
    ))
}

fn bounded_charge(
    used: &mut usize,
    key_len: usize,
    val_len: usize,
) -> Result<(), OrsSupervisionStatusError> {
    let item = key_len
        .checked_add(val_len)
        .ok_or_else(|| OrsSupervisionStatusError::Corrupt("byte count overflow".to_owned()))?;
    *used = used
        .checked_add(item)
        .ok_or_else(|| OrsSupervisionStatusError::Corrupt("byte count overflow".to_owned()))?;
    if *used > MAX_TOTAL_BYTES {
        return Err(OrsSupervisionStatusError::Corrupt(
            "total bytes exceed bounded limit".to_owned(),
        ));
    }
    Ok(())
}

fn load_current(
    read: &redb::ReadTransaction,
    lease_id: &str,
    used: &mut usize,
) -> Result<Option<SupervisionLeaseSnapshot>, OrsSupervisionStatusError> {
    let table = read
        .open_table(SUPERVISION_LEASE_CURRENT)
        .map_err(map_table_error)?;
    let Some(val) = table
        .get(lease_id)
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
    else {
        return Ok(None);
    };
    bounded_charge(used, lease_id.len(), val.value().len())?;
    let snapshot: SupervisionLeaseSnapshot =
        decode_named(val.value(), "supervision_lease_current")?;
    snapshot
        .validate()
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
    if snapshot.record.lease_id.as_str() != lease_id {
        return Err(OrsSupervisionStatusError::Corrupt(
            "current key does not match lease identity".to_owned(),
        ));
    }
    Ok(Some(snapshot))
}

fn load_staged(
    read: &redb::ReadTransaction,
    lease_id: &str,
    used: &mut usize,
) -> Result<Option<SupervisionLeaseStageReceipt>, OrsSupervisionStatusError> {
    let table = read
        .open_table(SUPERVISION_LEASE_STAGED)
        .map_err(map_table_error)?;
    let Some(val) = table
        .get(lease_id)
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
    else {
        return Ok(None);
    };
    bounded_charge(used, lease_id.len(), val.value().len())?;
    let stage: SupervisionLeaseStageReceipt =
        decode_named(val.value(), "supervision_lease_staged")?;
    stage
        .validate()
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
    if stage.ticket.lease_id.as_str() != lease_id {
        return Err(OrsSupervisionStatusError::Corrupt(
            "staged key does not match lease identity".to_owned(),
        ));
    }
    Ok(Some(stage))
}

fn load_history(
    read: &redb::ReadTransaction,
    lease_id: &str,
    used: &mut usize,
) -> Result<Vec<SupervisionLeaseSnapshot>, OrsSupervisionStatusError> {
    let table = read
        .open_table(SUPERVISION_LEASE_HISTORY)
        .map_err(map_table_error)?;
    let start = format!("{lease_id}::");
    let end = format!("{start}\u{10ffff}");
    let mut out = Vec::new();
    for item in table
        .range(start.as_str()..end.as_str())
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
    {
        let (k, v) = item.map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
        bounded_charge(used, k.value().len(), v.value().len())?;
        if out.len() >= usize::from(MAX_HISTORY) {
            break;
        }
        let snap: SupervisionLeaseSnapshot = decode_named(v.value(), "supervision_lease_history")?;
        snap.validate()
            .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
        if snap.record.lease_id.as_str() != lease_id {
            return Err(OrsSupervisionStatusError::Corrupt(
                "history key does not match lease identity".to_owned(),
            ));
        }
        out.push(snap);
    }
    if out.len() > usize::from(MAX_RECOVERY_PAGE) {
        return Err(OrsSupervisionStatusError::Corrupt(
            "history exceeds bounded limit".to_owned(),
        ));
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.record.revision));
    Ok(out)
}

fn verify_health(
    anchor: &SupervisionTrustAnchor,
    ctx: &SupervisionLeaseVerificationContext,
    current: &SupervisionLeaseSnapshot,
) -> Result<(), String> {
    anchor.validate().map_err(|e| e.to_string())?;
    ctx.validate().map_err(|e| e.to_string())?;
    let verified = anchor
        .verify(&current.record.artifact, ctx)
        .map_err(|e| e.to_string())?;
    if verified.payload().ors_mirror != ctx.ors_mirror {
        return Err("ors mirror mismatch".to_owned());
    }
    Ok(())
}

pub fn observe_supervision_status(
    path: impl AsRef<Path>,
    anchor: &SupervisionTrustAnchor,
    context: &SupervisionLeaseVerificationContext,
) -> Result<SupervisionStatusProjection, OrsSupervisionStatusError> {
    let path = path.as_ref();
    validate_path(path)?;
    let db = ReadOnlyDatabase::open(path).map_err(map_db_error)?;
    let read = db.begin_read().map_err(map_tx_error)?;
    let schema_res = check_schema(&read);
    if let Err(e) = schema_res {
        match e {
            OrsSupervisionStatusError::Missing(msg) if msg.contains("empty database") => {
                return Ok(SupervisionStatusProjection {
                    lease_id: context.lease_id.clone(),
                    health: HealthDimension::Failed,
                    heartbeat: HealthDimension::Unknown,
                    reason: SupervisionStatusReason::MissingCurrent,
                    current: None,
                    staged: None,
                    history: Vec::new(),
                });
            }
            other => return Err(other),
        }
    }
    let mut used = 0usize;
    let lease_id = context.lease_id.as_str();
    let staged = load_staged(&read, lease_id, &mut used)?;
    let current = load_current(&read, lease_id, &mut used)?;
    let history = load_history(&read, lease_id, &mut used)?;
    let (health, reason) = if staged.is_some() && current.is_none() {
        (HealthDimension::Failed, SupervisionStatusReason::StagedOnly)
    } else if let Some(cur) = &current {
        if cur.record.projection != crate::SupervisionLeaseProjection::Active {
            (
                HealthDimension::Failed,
                SupervisionStatusReason::BindingMismatch("terminal projection".to_owned()),
            )
        } else if context.now_ms >= cur.record.artifact.payload.expires_at_ms {
            (HealthDimension::Failed, SupervisionStatusReason::Expired)
        } else {
            match verify_health(anchor, context, cur) {
                Ok(()) => {
                    if staged.is_some() {
                        (HealthDimension::Failed, SupervisionStatusReason::StagedOnly)
                    } else {
                        (HealthDimension::Healthy, SupervisionStatusReason::Healthy)
                    }
                }
                Err(msg) => {
                    let reason = if msg.contains("SignatureInvalid")
                        || msg.contains("signature")
                        || msg.contains("TrustAnchorMismatch")
                        || msg.contains("public_key")
                    {
                        SupervisionStatusReason::SignatureInvalid(msg)
                    } else if msg.contains("Expired") {
                        SupervisionStatusReason::Expired
                    } else {
                        SupervisionStatusReason::BindingMismatch(msg)
                    };
                    (HealthDimension::Failed, reason)
                }
            }
        }
    } else {
        (
            HealthDimension::Failed,
            SupervisionStatusReason::MissingCurrent,
        )
    };
    Ok(SupervisionStatusProjection {
        lease_id: context.lease_id.clone(),
        health,
        heartbeat: HealthDimension::Unknown,
        reason,
        current,
        staged,
        history,
    })
}

pub fn open_existing_read_only(
    path: impl AsRef<Path>,
) -> Result<ReadOnlyDatabase, OrsSupervisionStatusError> {
    let path = path.as_ref();
    validate_path(path)?;
    ReadOnlyDatabase::open(path).map_err(map_db_error)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use eliot_runtime_contracts::{
        Ed25519SupervisionLeaseSigner, HealthDimension, LeaseState, RegisteredActivityWakePolicy,
        SupervisionGenerationBinding, SupervisionLeaseActiveStateBinding, SupervisionLeaseSigner,
        SupervisionLeaseVerificationContext, SupervisionObservationScope,
        SupervisionOrsMirrorBinding, SupervisionTrustAnchor,
    };
    use redb::ReadableTable;

    use super::*;
    use crate::{
        OpaqueLabel, OperationIdentity, RedbRecoveryStore, SupervisionLeaseBinding,
        SupervisionLeaseOperation, SupervisionLeasePrepareRequest,
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn path(label: &str) -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("eliot-ors-status-{label}-{n}.redb"))
    }

    fn cleanup(p: &PathBuf) {
        let _ = fs::remove_file(p);
    }

    fn label(v: &str) -> OpaqueLabel {
        OpaqueLabel::new(v).unwrap()
    }

    fn binding(state: LeaseState, issued: u64) -> SupervisionLeaseBinding {
        SupervisionLeaseBinding {
            scope_ref: label("scope-supervision"),
            observation_scope: SupervisionObservationScope {
                targets: vec!["target-1".to_owned()],
                sensor_profile: "kernel-heartbeat".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live".to_owned(),
            },
            installation_id: label("installation-1"),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            activation_id: label("activation-1"),
            activation_generation: ResourceGeneration::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::new(2).unwrap(),
            watchdog_epoch: AuthorityEpoch::new(1).unwrap(),
            generation_binding: SupervisionGenerationBinding {
                target_id: "target-1".to_owned(),
                target_generation: ResourceGeneration::new(1).unwrap(),
                module_id: "module-1".to_owned(),
                module_generation: ResourceGeneration::new(1).unwrap(),
                process_id: "kernel-process-1".to_owned(),
                process_generation: ResourceGeneration::new(1).unwrap(),
            },
            state_fence: StateFence::new(
                AuthorityEpoch::new(2).unwrap(),
                ResourceGeneration::new(1).unwrap(),
            ),
            issued_at_ms: issued,
            expires_at_ms: issued + 900,
            renew_before_ms: issued + 450,
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            state,
            terminal_disposition: None,
            revocation_reason: None,
            revocation_id: None,
            revocation_epoch: None,
        }
    }

    fn request(
        ticket: &str,
        op: &str,
        lease: &str,
        rev: Option<u64>,
        operation: SupervisionLeaseOperation,
        b: SupervisionLeaseBinding,
    ) -> SupervisionLeasePrepareRequest {
        SupervisionLeasePrepareRequest {
            ticket_id: label(ticket),
            operation_id: label(op),
            lease_id: label(lease),
            expected_revision: rev,
            operation,
            binding: b,
        }
    }

    fn anchor_and_context(
        snap: &SupervisionLeaseSnapshot,
        now_ms: u64,
    ) -> (SupervisionTrustAnchor, SupervisionLeaseVerificationContext) {
        let payload = &snap.record.artifact.payload;
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            payload.installation_id.clone(),
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let generation = &payload.generation_binding;
        let ctx = SupervisionLeaseVerificationContext {
            now_ms,
            lease_id: payload.lease_id.clone(),
            host_epoch: payload.host_epoch,
            activation_id: payload.activation_id.clone(),
            activation_generation: payload.activation_generation,
            kernel_epoch: payload.kernel_epoch,
            watchdog_epoch: payload.watchdog_epoch,
            state_fence: payload.state_fence.clone(),
            scope_ref: payload.scope_ref.clone(),
            observation_scope: payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: payload.revocation_id.clone(),
                revocation_epoch: payload.revocation_epoch,
            },
        };
        (anchor, ctx)
    }

    fn file_bytes_and_mtime(p: &PathBuf) -> (Vec<u8>, std::time::SystemTime) {
        let bytes = fs::read(p).unwrap();
        let mtime = fs::metadata(p).unwrap().modified().unwrap();
        (bytes, mtime)
    }

    #[test]
    fn missing_file_is_missing() {
        let p = path("missing");
        cleanup(&p);
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: "lease-1".to_owned(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            activation_id: "activation-1".to_owned(),
            activation_generation: ResourceGeneration::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::new(2).unwrap(),
            watchdog_epoch: AuthorityEpoch::new(1).unwrap(),
            state_fence: StateFence::new(
                AuthorityEpoch::new(2).unwrap(),
                ResourceGeneration::new(1).unwrap(),
            ),
            scope_ref: "scope-supervision".to_owned(),
            observation_scope: SupervisionObservationScope {
                targets: vec!["target-1".to_owned()],
                sensor_profile: "kernel-heartbeat".to_owned(),
                claimed_coverage: vec!["process".to_owned()],
                governance_axis: "runtime-live".to_owned(),
            },
            target_id: "target-1".to_owned(),
            module_id: "module-1".to_owned(),
            process_id: "kernel-process-1".to_owned(),
            target_generation: ResourceGeneration::new(1).unwrap(),
            module_generation: ResourceGeneration::new(1).unwrap(),
            process_generation: ResourceGeneration::new(1).unwrap(),
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: SupervisionOrsMirrorBinding {
                record_id: "lease-1::r00000000000000000001".to_owned(),
                subject_lease_id: "lease-1".to_owned(),
                lease_revision: 1,
                ticket_sha256: "aa".repeat(32),
                previous_receipt_sha256: None,
            },
            active_state: SupervisionLeaseActiveStateBinding {
                state: LeaseState::Active,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Missing(_))));
        assert!(!p.exists());
    }

    #[test]
    fn empty_database_is_not_healthy_and_read_only() {
        let p = path("empty");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        drop(store);
        let before = file_bytes_and_mtime(&p);
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: "lease-1".to_owned(),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            activation_id: "activation-1".to_owned(),
            activation_generation: ResourceGeneration::new(1).unwrap(),
            kernel_epoch: AuthorityEpoch::new(2).unwrap(),
            watchdog_epoch: AuthorityEpoch::new(1).unwrap(),
            state_fence: StateFence::new(
                AuthorityEpoch::new(2).unwrap(),
                ResourceGeneration::new(1).unwrap(),
            ),
            scope_ref: "scope-supervision".to_owned(),
            observation_scope: SupervisionObservationScope {
                targets: vec!["target-1".to_owned()],
                sensor_profile: "kernel-heartbeat".to_owned(),
                claimed_coverage: vec!["process".to_owned()],
                governance_axis: "runtime-live".to_owned(),
            },
            target_id: "target-1".to_owned(),
            module_id: "module-1".to_owned(),
            process_id: "kernel-process-1".to_owned(),
            target_generation: ResourceGeneration::new(1).unwrap(),
            module_generation: ResourceGeneration::new(1).unwrap(),
            process_generation: ResourceGeneration::new(1).unwrap(),
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: SupervisionOrsMirrorBinding {
                record_id: "lease-1::r00000000000000000001".to_owned(),
                subject_lease_id: "lease-1".to_owned(),
                lease_revision: 1,
                ticket_sha256: "aa".repeat(32),
                previous_receipt_sha256: None,
            },
            active_state: SupervisionLeaseActiveStateBinding {
                state: LeaseState::Active,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        let proj = observe_supervision_status(&p, &anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Failed);
        assert_eq!(proj.heartbeat, HealthDimension::Unknown);
        assert_eq!(proj.reason, SupervisionStatusReason::MissingCurrent);
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn valid_signed_current_is_healthy_and_preserves_bytes() {
        let p = path("valid");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                "lease-1",
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
            .unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let envelope = stage
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let (anchor, ctx) = {
            let anchor = SupervisionTrustAnchor::new(
                "installation-1",
                signer.signer_id(),
                signer.key_id(),
                signer.public_key().to_vec(),
            )
            .unwrap();
            let payload = &envelope.payload;
            let generation = &payload.generation_binding;
            let ctx = SupervisionLeaseVerificationContext {
                now_ms: 101,
                lease_id: payload.lease_id.clone(),
                host_epoch: payload.host_epoch,
                activation_id: payload.activation_id.clone(),
                activation_generation: payload.activation_generation,
                kernel_epoch: payload.kernel_epoch,
                watchdog_epoch: payload.watchdog_epoch,
                state_fence: payload.state_fence.clone(),
                scope_ref: payload.scope_ref.clone(),
                observation_scope: payload.observation_scope.clone(),
                target_id: generation.target_id.clone(),
                module_id: generation.module_id.clone(),
                process_id: generation.process_id.clone(),
                target_generation: generation.target_generation,
                module_generation: generation.module_generation,
                process_generation: generation.process_generation,
                public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
                ors_mirror: payload.ors_mirror.clone(),
                active_state: SupervisionLeaseActiveStateBinding {
                    state: payload.state,
                    revocation_id: None,
                    revocation_epoch: None,
                },
            };
            (anchor, ctx)
        };
        let verified = anchor.verify(&envelope, &ctx).unwrap();
        store
            .commit_supervision_lease(&stage.ticket, &verified)
            .unwrap();
        drop(store);
        let before = file_bytes_and_mtime(&p);
        let proj = observe_supervision_status(&p, &anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Healthy);
        assert_eq!(proj.heartbeat, HealthDimension::Unknown);
        assert_eq!(proj.reason, SupervisionStatusReason::Healthy);
        assert!(proj.current.is_some());
        assert!(proj.staged.is_none());
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn staged_only_is_not_healthy() {
        let p = path("staged");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                "lease-1",
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
            .unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let envelope = stage
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let payload = &envelope.payload;
        let generation = &payload.generation_binding;
        let ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: payload.lease_id.clone(),
            host_epoch: payload.host_epoch,
            activation_id: payload.activation_id.clone(),
            activation_generation: payload.activation_generation,
            kernel_epoch: payload.kernel_epoch,
            watchdog_epoch: payload.watchdog_epoch,
            state_fence: payload.state_fence.clone(),
            scope_ref: payload.scope_ref.clone(),
            observation_scope: payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        drop(store);
        let before = file_bytes_and_mtime(&p);
        let proj = observe_supervision_status(&p, &anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Failed);
        assert_eq!(proj.reason, SupervisionStatusReason::StagedOnly);
        assert!(proj.staged.is_some());
        assert!(proj.current.is_none());
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn expired_lease_is_not_healthy() {
        let p = path("expired");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                "lease-1",
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
            .unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let envelope = stage
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let payload = &envelope.payload;
        let generation = &payload.generation_binding;
        let mut ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: payload.lease_id.clone(),
            host_epoch: payload.host_epoch,
            activation_id: payload.activation_id.clone(),
            activation_generation: payload.activation_generation,
            kernel_epoch: payload.kernel_epoch,
            watchdog_epoch: payload.watchdog_epoch,
            state_fence: payload.state_fence.clone(),
            scope_ref: payload.scope_ref.clone(),
            observation_scope: payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        let verified = anchor.verify(&envelope, &ctx).unwrap();
        store
            .commit_supervision_lease(&stage.ticket, &verified)
            .unwrap();
        drop(store);
        ctx.now_ms = payload.expires_at_ms;
        let proj = observe_supervision_status(&p, &anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Failed);
        assert_eq!(proj.reason, SupervisionStatusReason::Expired);
        cleanup(&p);
    }

    #[test]
    fn signature_substitution_is_not_healthy() {
        let p = path("sig-sub");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                "lease-1",
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
            .unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let envelope = stage
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let payload = &envelope.payload;
        let generation = &payload.generation_binding;
        let ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: payload.lease_id.clone(),
            host_epoch: payload.host_epoch,
            activation_id: payload.activation_id.clone(),
            activation_generation: payload.activation_generation,
            kernel_epoch: payload.kernel_epoch,
            watchdog_epoch: payload.watchdog_epoch,
            state_fence: payload.state_fence.clone(),
            scope_ref: payload.scope_ref.clone(),
            observation_scope: payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        let mut wrong_signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [9; 32])
                .unwrap();
        let wrong_anchor = SupervisionTrustAnchor::new(
            "installation-1",
            wrong_signer.signer_id(),
            wrong_signer.key_id(),
            wrong_signer.public_key().to_vec(),
        )
        .unwrap();
        let verified = anchor.verify(&envelope, &ctx).unwrap();
        store
            .commit_supervision_lease(&stage.ticket, &verified)
            .unwrap();
        drop(store);
        let proj = observe_supervision_status(&p, &wrong_anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Failed);
        assert!(matches!(
            proj.reason,
            SupervisionStatusReason::SignatureInvalid(_)
        ));
        cleanup(&p);
    }

    #[test]
    fn binding_substitution_is_not_healthy() {
        let p = path("bind-sub");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                "lease-1",
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
            .unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let envelope = stage
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let payload = &envelope.payload;
        let generation = &payload.generation_binding;
        let mut ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: payload.lease_id.clone(),
            host_epoch: payload.host_epoch,
            activation_id: payload.activation_id.clone(),
            activation_generation: payload.activation_generation,
            kernel_epoch: payload.kernel_epoch,
            watchdog_epoch: payload.watchdog_epoch,
            state_fence: payload.state_fence.clone(),
            scope_ref: payload.scope_ref.clone(),
            observation_scope: payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        let verified = anchor.verify(&envelope, &ctx).unwrap();
        store
            .commit_supervision_lease(&stage.ticket, &verified)
            .unwrap();
        drop(store);
        ctx.watchdog_epoch = AuthorityEpoch::new(99).unwrap();
        let proj = observe_supervision_status(&p, &anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Failed);
        assert!(matches!(
            proj.reason,
            SupervisionStatusReason::BindingMismatch(_)
        ));
        cleanup(&p);
    }

    #[test]
    fn malformed_schema_is_corrupt() {
        let p = path("malformed");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                "lease-1",
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
            .unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let envelope = stage
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .unwrap();
        let payload = &envelope.payload;
        let generation = &payload.generation_binding;
        let ctx = SupervisionLeaseVerificationContext {
            now_ms: 101,
            lease_id: payload.lease_id.clone(),
            host_epoch: payload.host_epoch,
            activation_id: payload.activation_id.clone(),
            activation_generation: payload.activation_generation,
            kernel_epoch: payload.kernel_epoch,
            watchdog_epoch: payload.watchdog_epoch,
            state_fence: payload.state_fence.clone(),
            scope_ref: payload.scope_ref.clone(),
            observation_scope: payload.observation_scope.clone(),
            target_id: generation.target_id.clone(),
            module_id: generation.module_id.clone(),
            process_id: generation.process_id.clone(),
            target_generation: generation.target_generation,
            module_generation: generation.module_generation,
            process_generation: generation.process_generation,
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: payload.state,
                revocation_id: None,
                revocation_epoch: None,
            },
        };
        let verified = anchor.verify(&envelope, &ctx).unwrap();
        store
            .commit_supervision_lease(&stage.ticket, &verified)
            .unwrap();
        drop(store);
        let db = redb::Database::create(&p).unwrap();
        let write = db.begin_write().unwrap();
        {
            let mut table = write.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
            let encoded = {
                let val = table.get("lease-1").unwrap().unwrap();
                let mut v: serde_json::Value = serde_json::from_str(val.value()).unwrap();
                v["receipt"]["receipt_sha256"] = serde_json::Value::String("00".repeat(32));
                serde_json::to_string(&v).unwrap()
            };
            table.insert("lease-1", encoded.as_str()).unwrap();
        }
        write.commit().unwrap();
        drop(db);
        let before = fs::read(&p).unwrap();
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))));
        let after = fs::read(&p).unwrap();
        assert_eq!(before, after);
        cleanup(&p);
    }
}
