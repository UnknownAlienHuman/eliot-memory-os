use std::path::Path;

use eliot_runtime_contracts::{
    HealthDimension, SupervisionLeaseVerificationContext, SupervisionLeaseVerifier,
    SupervisionTrustAnchor,
};
use redb::{ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use serde::de::DeserializeOwned;

use crate::status_projection::{
    OrsSupervisionStatusError, SupervisionStatusProjection, SupervisionStatusReason,
};
use crate::{SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt};

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

#[allow(clippy::needless_pass_by_value)]
fn map_io_error(err: std::io::Error) -> OrsSupervisionStatusError {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("os error 5")
    {
        return OrsSupervisionStatusError::AccessDenied(msg);
    }
    match err.kind() {
        std::io::ErrorKind::NotFound => OrsSupervisionStatusError::Missing(msg),
        std::io::ErrorKind::PermissionDenied => OrsSupervisionStatusError::AccessDenied(msg),
        _ => OrsSupervisionStatusError::Unknown(msg),
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

fn encode_key_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            ':' => out.push_str("%3A"),
            _ => out.push(ch),
        }
    }
    out
}

fn canonical_history_key(lease_id: &str, revision: u64) -> String {
    format!("{}::{revision:020}", encode_key_component(lease_id))
}

fn raw_canonical_history_key(lease_id: &str, revision: u64) -> String {
    format!("{lease_id}::{revision:020}")
}

fn canonical_record_id(lease_id: &str, revision: u64) -> String {
    format!("{lease_id}::r{revision:020}")
}

fn load_history(
    read: &redb::ReadTransaction,
    lease_id: &str,
    used: &mut usize,
) -> Result<Vec<SupervisionLeaseSnapshot>, OrsSupervisionStatusError> {
    let table = read
        .open_table(SUPERVISION_LEASE_HISTORY)
        .map_err(map_table_error)?;
    let prefix = format!("{}::", encode_key_component(lease_id));
    let raw_prefix = format!("{lease_id}::");
    let has_legacy_chars = lease_id.contains(':') || lease_id.contains('%');
    let prefix_end = format!("{prefix}\u{10ffff}");
    let mut out = Vec::new();
    for item in table
        .range(prefix.as_str()..=prefix_end.as_str())
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
    {
        let (k, v) = item.map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
        if !k.value().starts_with(prefix.as_str()) {
            break;
        }
        bounded_charge(used, k.value().len(), v.value().len())?;
        let snap: SupervisionLeaseSnapshot = decode_named(v.value(), "supervision_lease_history")?;
        snap.validate()
            .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
        if snap.record.lease_id.as_str() != lease_id {
            return Err(OrsSupervisionStatusError::Corrupt(
                "history lease identity does not match key".to_owned(),
            ));
        }
        let expected_key = canonical_history_key(lease_id, snap.record.revision);
        if k.value() != expected_key {
            return Err(OrsSupervisionStatusError::Corrupt(
                "history key does not match canonical revision key".to_owned(),
            ));
        }
        let expected_record_id = canonical_record_id(lease_id, snap.record.revision);
        if snap.record.record_id.as_str() != expected_record_id {
            return Err(OrsSupervisionStatusError::Corrupt(
                "history record_id does not match canonical revision key".to_owned(),
            ));
        }
        if snap.record.artifact.payload.ors_mirror.record_id != expected_record_id {
            return Err(OrsSupervisionStatusError::Corrupt(
                "ors_mirror record_id does not match canonical key".to_owned(),
            ));
        }
        if snap.record.artifact.payload.ors_mirror.lease_revision != snap.record.revision {
            return Err(OrsSupervisionStatusError::Corrupt(
                "ors_mirror revision does not match key".to_owned(),
            ));
        }
        if snap.record.artifact.payload.ors_mirror.subject_lease_id != lease_id {
            return Err(OrsSupervisionStatusError::Corrupt(
                "ors_mirror subject does not match lease identity".to_owned(),
            ));
        }
        out.push(snap);
    }
    if has_legacy_chars {
        let raw_prefix_end = format!("{raw_prefix}\u{10ffff}");
        let mut legacy_found = false;
        for item in table
            .range(raw_prefix.as_str()..=raw_prefix_end.as_str())
            .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
        {
            let (k, v) = item.map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
            let key = k.value();
            if !key.starts_with(raw_prefix.as_str()) {
                break;
            }
            let suffix = &key[raw_prefix.len()..];
            if suffix.len() != 20 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            bounded_charge(used, key.len(), v.value().len())?;
            let snap: SupervisionLeaseSnapshot =
                decode_named(v.value(), "supervision_lease_history")?;
            snap.validate()
                .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
            if snap.record.lease_id.as_str() != lease_id {
                continue;
            }
            let expected_key = raw_canonical_history_key(lease_id, snap.record.revision);
            if key != expected_key {
                return Err(OrsSupervisionStatusError::Corrupt(
                    "legacy history key does not match lease identity or revision".to_owned(),
                ));
            }
            legacy_found = true;
        }
        if legacy_found {
            return Err(OrsSupervisionStatusError::MigrationRequired(
                "legacy lease_id encoding requires migration: history key uses unescaped colon"
                    .to_owned(),
            ));
        }
    }
    if out.len() > usize::from(MAX_HISTORY) {
        return Err(OrsSupervisionStatusError::Unknown(
            "history overflow: bounded proof incomplete".to_owned(),
        ));
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.record.revision));
    Ok(out)
}

fn validate_history_provenance(
    current: Option<&SupervisionLeaseSnapshot>,
    history: &[SupervisionLeaseSnapshot],
) -> Result<(), OrsSupervisionStatusError> {
    if history.is_empty() {
        if current.is_some() {
            return Err(OrsSupervisionStatusError::Corrupt(
                "history empty but current exists".to_owned(),
            ));
        }
        return Ok(());
    }
    let Some(cur) = current else {
        return Err(OrsSupervisionStatusError::Corrupt(
            "history exists without current".to_owned(),
        ));
    };
    if history[0] != *cur {
        return Err(OrsSupervisionStatusError::Corrupt(
            "current is not the newest history record".to_owned(),
        ));
    }
    for idx in 0..history.len() {
        let snap = &history[idx];
        if idx + 1 < history.len() {
            let pred = &history[idx + 1];
            if snap.record.revision != pred.record.revision + 1 {
                return Err(OrsSupervisionStatusError::Corrupt(
                    "history revision gap".to_owned(),
                ));
            }
            match &snap.receipt.previous_receipt_sha256 {
                Some(prev_digest) if *prev_digest == pred.receipt.receipt_sha256 => {}
                _ => {
                    return Err(OrsSupervisionStatusError::Corrupt(
                        "history previous receipt does not match predecessor".to_owned(),
                    ));
                }
            }
            if snap.record.previous_receipt_sha256 != snap.receipt.previous_receipt_sha256 {
                return Err(OrsSupervisionStatusError::Corrupt(
                    "history record previous does not match receipt".to_owned(),
                ));
            }
            if snap.record.previous_receipt_sha256.as_deref()
                != Some(pred.receipt.receipt_sha256.as_str())
            {
                return Err(OrsSupervisionStatusError::Corrupt(
                    "history record previous does not match predecessor receipt".to_owned(),
                ));
            }
        } else {
            if snap.record.revision != 1 {
                return Err(OrsSupervisionStatusError::Unknown(
                    "history incomplete: oldest revision is not genesis".to_owned(),
                ));
            }
            if snap.receipt.previous_receipt_sha256.is_some()
                || snap.record.previous_receipt_sha256.is_some()
            {
                return Err(OrsSupervisionStatusError::Corrupt(
                    "genesis must have no predecessor".to_owned(),
                ));
            }
        }
    }
    if history[0].record.revision != history.len() as u64 {
        return Err(OrsSupervisionStatusError::Corrupt(
            "history length does not match newest revision".to_owned(),
        ));
    }
    Ok(())
}

fn validate_replay_authority(
    read: &redb::ReadTransaction,
    current: &SupervisionLeaseSnapshot,
    used: &mut usize,
) -> Result<(), OrsSupervisionStatusError> {
    let table = read
        .open_table(SUPERVISION_LEASE_RESULTS)
        .map_err(map_table_error)?;
    let key = current.record.ticket_id.as_str();
    let Some(val) = table
        .get(key)
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?
    else {
        return Err(OrsSupervisionStatusError::Unknown(
            "replay authority missing: no results row for current ticket".to_owned(),
        ));
    };
    bounded_charge(used, key.len(), val.value().len())?;
    let result: DurableSupervisionLeaseResult =
        decode_named(val.value(), "supervision_lease_result")?;
    result
        .snapshot
        .validate()
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
    if result.snapshot != *current {
        return Err(OrsSupervisionStatusError::Corrupt(
            "replay result snapshot does not match current".to_owned(),
        ));
    }
    if result.artifact != current.record.artifact {
        return Err(OrsSupervisionStatusError::Corrupt(
            "replay artifact does not match current".to_owned(),
        ));
    }
    if result.ticket.ticket_id != current.record.ticket_id
        || result.ticket.record_id != current.record.record_id
        || result.ticket.lease_id != current.record.lease_id
        || result.ticket.revision != current.record.revision
    {
        return Err(OrsSupervisionStatusError::Corrupt(
            "replay ticket does not match current".to_owned(),
        ));
    }
    let expected_ticket_sha256 = result
        .ticket
        .ticket_sha256()
        .map_err(|e| OrsSupervisionStatusError::Corrupt(e.to_string()))?;
    if expected_ticket_sha256 != current.record.ticket_sha256
        || expected_ticket_sha256 != current.receipt.ticket_sha256
        || result.snapshot.record.ticket_sha256 != expected_ticket_sha256
    {
        return Err(OrsSupervisionStatusError::Corrupt(
            "replay ticket_sha256 does not match current".to_owned(),
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct DurableSupervisionLeaseResult {
    ticket: crate::SupervisionLeaseCommitTicket,
    artifact: eliot_runtime_contracts::SignedSupervisionLease,
    snapshot: SupervisionLeaseSnapshot,
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

#[allow(clippy::needless_pass_by_value)]
fn map_panic(err: Box<dyn std::any::Any + Send>) -> OrsSupervisionStatusError {
    let msg = if let Some(s) = err.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic during redb inspection".to_owned()
    };
    OrsSupervisionStatusError::Corrupt(msg)
}

pub fn observe_supervision_status(
    path: impl AsRef<Path>,
    anchor: &SupervisionTrustAnchor,
    context: &SupervisionLeaseVerificationContext,
) -> Result<SupervisionStatusProjection, OrsSupervisionStatusError> {
    let path = path.as_ref();
    validate_path(path)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
        validate_history_provenance(current.as_ref(), &history)?;
        if let Some(cur) = &current {
            validate_replay_authority(&read, cur, &mut used)?;
        }
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
    }));
    match outcome {
        Ok(res) => res,
        Err(err) => Err(map_panic(err)),
    }
}

pub fn open_existing_read_only(
    path: impl AsRef<Path>,
) -> Result<ReadOnlyDatabase, OrsSupervisionStatusError> {
    let path = path.as_ref();
    validate_path(path)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ReadOnlyDatabase::open(path).map_err(map_db_error)
    }));
    match outcome {
        Ok(res) => res,
        Err(err) => Err(map_panic(err)),
    }
}

/// Reads one validated current supervision-lease snapshot without invoking a
/// trust-anchor verifier.  Consumers that must compare a signed envelope with
/// the durable ORS artifact use this seam to establish the durable mirror
/// before constructing their final verification context.
pub fn read_current_supervision_lease_read_only(
    path: impl AsRef<Path>,
    lease_id: &crate::OperationIdentity,
) -> Result<Option<SupervisionLeaseSnapshot>, OrsSupervisionStatusError> {
    let path = path.as_ref();
    validate_path(path)?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let db = ReadOnlyDatabase::open(path).map_err(map_db_error)?;
        let read = db.begin_read().map_err(map_tx_error)?;
        check_schema(&read)?;
        let mut used = 0usize;
        let current = load_current(&read, lease_id.as_str(), &mut used)?;
        let history = load_history(&read, lease_id.as_str(), &mut used)?;
        validate_history_provenance(current.as_ref(), &history)?;
        if let Some(current) = &current {
            validate_replay_authority(&read, current, &mut used)?;
        }
        Ok(current)
    }));
    match outcome {
        Ok(result) => result,
        Err(error) => Err(map_panic(error)),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::unnested_or_patterns,
    reason = "test fixtures use unwrap/expect and long helpers; production lints remain -D warnings"
)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::OnceLock;
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
        OpaqueLabel, RedbRecoveryStore, SupervisionLeaseBinding, SupervisionLeaseOperation,
        SupervisionLeasePrepareRequest,
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

    fn test_time(offset_ms: u64) -> u64 {
        static TEST_EPOCH_MS: OnceLock<u64> = OnceLock::new();
        TEST_EPOCH_MS
            .get_or_init(|| {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis(),
                )
                .unwrap_or(u64::MAX.saturating_sub(3_600_000))
                .saturating_add(3_600_000)
            })
            .saturating_add(offset_ms)
    }

    fn binding(state: LeaseState, issued: u64) -> SupervisionLeaseBinding {
        let issued = test_time(issued);
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

    #[allow(dead_code)]
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

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
        out
    }

    fn canonicalize(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(canonicalize).collect())
            }
            serde_json::Value::Object(obj) => {
                let mut sorted = serde_json::Map::new();
                let mut entries: Vec<_> = obj.into_iter().collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                for (k, v) in entries {
                    sorted.insert(k, canonicalize(v));
                }
                serde_json::Value::Object(sorted)
            }
            v => v,
        }
    }

    fn recompute_snapshot_receipt(v: &mut serde_json::Value) {
        let receipt_hash = {
            let receipt = v.get("receipt").unwrap().as_object().unwrap();
            let core = serde_json::json!({
                "ticket_id": receipt.get("ticket_id").unwrap().clone(),
                "operation_id": receipt.get("operation_id").unwrap().clone(),
                "record_id": receipt.get("record_id").unwrap().clone(),
                "lease_id": receipt.get("lease_id").unwrap().clone(),
                "revision": receipt.get("revision").unwrap().clone(),
                "operation": receipt.get("operation").unwrap().clone(),
                "state": receipt.get("state").unwrap().clone(),
                "projection": receipt.get("projection").unwrap().clone(),
                "operation_order": receipt.get("operation_order").unwrap().clone(),
                "ticket_sha256": receipt.get("ticket_sha256").unwrap().clone(),
                "artifact_sha256": receipt.get("artifact_sha256").unwrap().clone(),
                "previous_receipt_sha256": receipt.get("previous_receipt_sha256").unwrap().clone()
            });
            let canonical = canonicalize(core);
            let bytes = serde_json::to_vec(&canonical).unwrap();
            sha256_hex(&bytes)
        };
        v.get_mut("receipt")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "receipt_sha256".to_owned(),
                serde_json::Value::String(receipt_hash.clone()),
            );
        v.get_mut("record")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "receipt_sha256".to_owned(),
                serde_json::Value::String(receipt_hash),
            );
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
            now_ms: test_time(101),
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
            now_ms: test_time(101),
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
                now_ms: test_time(101),
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
            now_ms: test_time(101),
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
            now_ms: test_time(101),
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
            now_ms: test_time(101),
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
        let wrong_signer =
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
            now_ms: test_time(101),
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
            now_ms: test_time(101),
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

    #[test]
    fn empty_file_without_tables_is_not_healthy_and_read_only() {
        let p = path("empty-no-tables");
        cleanup(&p);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            write.commit().unwrap();
        }
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
            now_ms: test_time(101),
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
        assert_eq!(proj.reason, SupervisionStatusReason::MissingCurrent);
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn legacy_schema_is_migration_required_and_read_only() {
        let p = path("legacy");
        cleanup(&p);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let _ = write.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
                let _ = write
                    .open_table(TableDefinition::<&str, &str>::new("ors_meta_v1"))
                    .unwrap();
            }
            write.commit().unwrap();
        }
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
            now_ms: test_time(101),
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
        assert!(matches!(
            res,
            Err(OrsSupervisionStatusError::MigrationRequired(_))
        ));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn unrelated_redb_is_migration_required_and_read_only() {
        let p = path("unrelated");
        cleanup(&p);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut t = write
                    .open_table(TableDefinition::<&str, &str>::new("ors_envelopes_v1"))
                    .unwrap();
                t.insert("k", "v").unwrap();
            }
            write.commit().unwrap();
        }
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
            now_ms: test_time(101),
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
        assert!(matches!(
            res,
            Err(OrsSupervisionStatusError::MigrationRequired(_))
        ));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn terminal_lease_is_not_healthy_and_read_only() {
        let p = path("terminal");
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
        let ctx_active = SupervisionLeaseVerificationContext {
            now_ms: test_time(101),
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
        let verified = anchor.verify(&envelope, &ctx_active).unwrap();
        let committed = store
            .commit_supervision_lease(&stage.ticket, &verified)
            .unwrap();
        let prior_active = verified;
        let predecessor = eliot_runtime_contracts::SupervisionLeasePredecessorProof {
            lease_id: committed.record.lease_id.as_str().to_owned(),
            record_id: committed.record.record_id.as_str().to_owned(),
            lease_revision: committed.record.revision,
            receipt_sha256: committed.receipt.receipt_sha256.clone(),
            envelope_sha256: prior_active.envelope_digest().to_owned(),
        };
        let stage2 = store
            .prepare_supervision_lease(request(
                "t2",
                "o2",
                "lease-1",
                Some(1),
                SupervisionLeaseOperation::Revoke,
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
                    issued_at_ms: test_time(100),
                    expires_at_ms: test_time(1000),
                    renew_before_ms: test_time(550),
                    wake_policy: RegisteredActivityWakePolicy::Disabled,
                    state: LeaseState::Revoked,
                    terminal_disposition: Some(
                        eliot_runtime_contracts::SupervisionLeaseTerminalDisposition::Revoked,
                    ),
                    revocation_reason: Some("revoked".to_owned()),
                    revocation_id: Some("rev-1".to_owned()),
                    revocation_epoch: Some(AuthorityEpoch::new(2).unwrap()),
                },
            ))
            .unwrap();
        let envelope2 = stage2
            .ticket
            .expected_payload()
            .unwrap()
            .sign(&signer)
            .unwrap();
        let terminal_verified = anchor
            .verify_terminal_transition(&prior_active, &envelope2, &predecessor)
            .unwrap();
        store
            .commit_terminal_supervision_lease(&stage2.ticket, &terminal_verified)
            .unwrap();
        drop(store);
        let before = file_bytes_and_mtime(&p);
        let ctx_terminal = SupervisionLeaseVerificationContext {
            now_ms: test_time(200),
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
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live".to_owned(),
            },
            target_id: "target-1".to_owned(),
            module_id: "module-1".to_owned(),
            process_id: "kernel-process-1".to_owned(),
            target_generation: ResourceGeneration::new(1).unwrap(),
            module_generation: ResourceGeneration::new(1).unwrap(),
            process_generation: ResourceGeneration::new(1).unwrap(),
            public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
            ors_mirror: envelope2.payload.ors_mirror.clone(),
            active_state: SupervisionLeaseActiveStateBinding {
                state: LeaseState::Revoked,
                revocation_id: Some("rev-1".to_owned()),
                revocation_epoch: Some(AuthorityEpoch::new(2).unwrap()),
            },
        };
        let proj = observe_supervision_status(&p, &anchor, &ctx_terminal).unwrap();
        assert_eq!(proj.health, HealthDimension::Failed);
        assert!(matches!(
            proj.reason,
            SupervisionStatusReason::BindingMismatch(_)
        ));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    fn build_chain(
        p: &PathBuf,
        n: usize,
    ) -> (SupervisionTrustAnchor, SupervisionLeaseVerificationContext) {
        let store = RedbRecoveryStore::open(p).unwrap();
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
        let mut last: Option<SupervisionLeaseSnapshot> = None;
        for i in 1..=n {
            let expected = if i == 1 { None } else { Some((i - 1) as u64) };
            let op = SupervisionLeaseOperation::Commit;
            let op = if i == 1 {
                op
            } else {
                SupervisionLeaseOperation::Renew
            };
            let stage = store
                .prepare_supervision_lease(request(
                    &format!("t{i}"),
                    &format!("o{i}"),
                    "lease-1",
                    expected,
                    op,
                    binding(LeaseState::Active, 100),
                ))
                .unwrap();
            let envelope = stage
                .ticket
                .expected_payload()
                .unwrap()
                .sign(&signer)
                .unwrap();
            let payload = &envelope.payload;
            let generation = &payload.generation_binding;
            let ctx = SupervisionLeaseVerificationContext {
                now_ms: test_time(101),
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
            let snap = store
                .commit_supervision_lease(&stage.ticket, &verified)
                .unwrap();
            last = Some(snap);
        }
        let snap = last.unwrap();
        let payload = &snap.record.artifact.payload;
        let generation = &payload.generation_binding;
        let ctx = SupervisionLeaseVerificationContext {
            now_ms: test_time(101),
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
        (anchor, ctx)
    }

    #[test]
    fn history_key_substitution_is_corrupt_and_read_only() {
        let p = path("history-key-sub");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 2);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                let truth = table
                    .get("lease-1::00000000000000000001")
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_owned();
                table.insert("lease-1::evil", truth.as_str()).unwrap();
                table
                    .remove("lease-1::00000000000000000001")
                    .unwrap()
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn history_revision_gap_is_corrupt_and_read_only() {
        let p = path("history-gap");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 3);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                table
                    .remove("lease-1::00000000000000000002")
                    .unwrap()
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn history_wrong_predecessor_digest_is_corrupt_and_read_only() {
        let p = path("history-wrong-pred");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 2);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                let key1 = "lease-1::00000000000000000001";
                let val1 = table.get(key1).unwrap().unwrap().value().to_owned();
                let mut v1: serde_json::Value = serde_json::from_str(&val1).unwrap();
                v1["receipt"]["operation_order"] = serde_json::Value::Number(999.into());
                v1["record"]["operation_order"] = serde_json::Value::Number(999.into());
                recompute_snapshot_receipt(&mut v1);
                let encoded1 = serde_json::to_string(&v1).unwrap();
                let snap1: SupervisionLeaseSnapshot = serde_json::from_str(&encoded1).unwrap();
                snap1.validate().unwrap();
                table.insert(key1, encoded1.as_str()).unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn history_overflow_is_unknown_and_read_only() {
        let p = path("history-overflow");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 9);
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Unknown(_))));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn history_corruption_after_bound_is_not_ignored_and_read_only() {
        let p = path("history-after-bound");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 8);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                table
                    .insert("lease-1::00000000000000000009", "not-json")
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(
            res,
            Err(OrsSupervisionStatusError::Corrupt(_) | OrsSupervisionStatusError::Unknown(_))
        ));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn replay_result_missing_is_unknown_and_read_only() {
        let p = path("replay-missing");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 2);
        let current_ticket = {
            let db = redb::Database::create(&p).unwrap();
            let read = db.begin_read().unwrap();
            let table = read.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
            let val = table.get("lease-1").unwrap().unwrap().value().to_owned();
            let snap: SupervisionLeaseSnapshot = serde_json::from_str(&val).unwrap();
            snap.record.ticket_id.as_str().to_owned()
        };
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_RESULTS).unwrap();
                table.remove(current_ticket.as_str()).unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Unknown(_))));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn replay_result_substitution_is_corrupt_and_read_only() {
        let p = path("replay-sub");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 2);
        let current_ticket = {
            let db = redb::Database::create(&p).unwrap();
            let read = db.begin_read().unwrap();
            let table = read.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
            let val = table.get("lease-1").unwrap().unwrap().value().to_owned();
            let snap: SupervisionLeaseSnapshot = serde_json::from_str(&val).unwrap();
            snap.record.ticket_id.as_str().to_owned()
        };
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_RESULTS).unwrap();
                let val = table
                    .get(current_ticket.as_str())
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_owned();
                let mut v: serde_json::Value = serde_json::from_str(&val).unwrap();
                v["ticket"]["ticket_id"] =
                    serde_json::Value::String("t-evil-substitution".to_owned());
                let encoded = serde_json::to_string(&v).unwrap();
                let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
                let snap: SupervisionLeaseSnapshot =
                    serde_json::from_value(decoded.get("snapshot").unwrap().clone()).unwrap();
                snap.validate().unwrap();
                table
                    .insert(current_ticket.as_str(), encoded.as_str())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))));
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn torn_database_is_corrupt_and_read_only() {
        let p = path("torn");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 1);
        let before = file_bytes_and_mtime(&p);
        {
            let bytes = std::fs::read(&p).unwrap();
            let mut truncated = bytes.clone();
            truncated.truncate(bytes.len() / 2);
            std::fs::write(&p, &truncated).unwrap();
        }
        let before_corrupt = file_bytes_and_mtime(&p);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observe_supervision_status(&p, &anchor, &ctx)
        }));
        assert!(res.is_ok(), "torn inspection must not panic");
        let inner = res.unwrap();
        assert!(
            matches!(
                inner,
                Err(OrsSupervisionStatusError::Corrupt(_)
                    | OrsSupervisionStatusError::Unknown(_)
                    | OrsSupervisionStatusError::Missing(_)
                    | OrsSupervisionStatusError::AccessDenied(_))
            ),
            "torn database must be reported as corrupt/unknown/missing/access-denied, got {inner:?}"
        );
        let after_corrupt = file_bytes_and_mtime(&p);
        assert_eq!(before_corrupt.0, after_corrupt.0);
        assert_eq!(before_corrupt.1, after_corrupt.1);
        std::fs::write(&p, &before.0).unwrap();
        let restored = file_bytes_and_mtime(&p);
        assert_eq!(restored.0, before.0);
        cleanup(&p);
    }

    #[test]
    fn valid_history_with_replay_is_healthy_and_read_only() {
        let p = path("valid-with-replay");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 3);
        let before = file_bytes_and_mtime(&p);
        let proj = observe_supervision_status(&p, &anchor, &ctx).unwrap();
        assert_eq!(proj.health, HealthDimension::Healthy);
        assert_eq!(proj.history.len(), 3);
        assert!(proj.current.is_some());
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn max_scalar_history_key_is_not_excluded_and_is_corrupt() {
        let p = path("max-scalar");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 1);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                let max_key = "lease-1::\u{10ffff}";
                table.insert(max_key, "not-json").unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observe_supervision_status(&p, &anchor, &ctx)
        }));
        assert!(res.is_ok(), "max-scalar scan must not panic");
        let inner = res.unwrap();
        assert!(
            matches!(
                inner,
                Err(OrsSupervisionStatusError::Corrupt(_) | OrsSupervisionStatusError::Unknown(_))
            ),
            "max-scalar corruption must be detected, got {inner:?}"
        );
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn colon_lease_is_isolated_from_sibling_prefix() {
        let p = path("colon-sibling");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        for lease in ["lease-a", "lease-a::b"] {
            let stage = store
                .prepare_supervision_lease(request(
                    &format!("t-{lease}"),
                    &format!("o-{lease}"),
                    lease,
                    None,
                    SupervisionLeaseOperation::Commit,
                    binding(LeaseState::Active, 100),
                ))
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
                now_ms: test_time(101),
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
        }
        drop(store);
        let signer2 =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer2.signer_id(),
            signer2.key_id(),
            signer2.public_key().to_vec(),
        )
        .unwrap();
        for lease in ["lease-a", "lease-a::b"] {
            let snap: SupervisionLeaseSnapshot = {
                let db = redb::Database::create(&p).unwrap();
                let read = db.begin_read().unwrap();
                let table = read.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
                let v = table.get(lease).unwrap().unwrap().value().to_owned();
                serde_json::from_str(&v).unwrap()
            };
            let payload = &snap.record.artifact.payload;
            let generation = &payload.generation_binding;
            let ctx2 = SupervisionLeaseVerificationContext {
                now_ms: test_time(101),
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
            let proj = observe_supervision_status(&p, &anchor, &ctx2).unwrap();
            assert_eq!(proj.health, HealthDimension::Healthy);
            assert_eq!(proj.history.len(), 1);
            assert_eq!(
                proj.current.as_ref().unwrap().record.lease_id.as_str(),
                lease
            );
        }
        cleanup(&p);
    }

    #[test]
    fn mixed_canonical_and_legacy_colon_keys_are_migration_required() {
        let p = path("legacy-colon-migration");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let lease = "lease:colon";
        let stage = store
            .prepare_supervision_lease(request(
                "t1",
                "o1",
                lease,
                None,
                SupervisionLeaseOperation::Commit,
                binding(LeaseState::Active, 100),
            ))
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
            now_ms: test_time(101),
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
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut hist = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                let encoded_key = format!("{}::{:020}", "lease%3Acolon", 1);
                let raw_key = format!("{lease}::{:020}", 1);
                let val = hist
                    .get(encoded_key.as_str())
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_owned();
                hist.insert(raw_key.as_str(), val.as_str()).unwrap();
            }
            write.commit().unwrap();
        }
        let proj = observe_supervision_status(&p, &anchor, &ctx);
        assert!(
            matches!(proj, Err(OrsSupervisionStatusError::MigrationRequired(_))),
            "legacy raw colon key must be migration-required, got {proj:?}"
        );
        cleanup(&p);
    }

    #[test]
    fn open_existing_read_only_missing_is_missing_and_no_create() {
        let p = path("open-missing");
        cleanup(&p);
        let res = open_existing_read_only(&p);
        assert!(matches!(res, Err(OrsSupervisionStatusError::Missing(_))));
        assert!(!p.exists(), "open_existing_read_only must not create file");
        cleanup(&p);
    }

    #[test]
    fn open_existing_read_only_preserves_bytes_and_mtime() {
        let p = path("open-preserve");
        cleanup(&p);
        {
            let _store = RedbRecoveryStore::open(&p).unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let db = open_existing_read_only(&p).unwrap();
        drop(db);
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        let db2 = open_existing_read_only(&p).unwrap();
        let read = db2.begin_read().unwrap();
        let _ = read.list_tables().unwrap().next();
        drop(read);
        drop(db2);
        let after2 = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after2.0);
        assert_eq!(before.1, after2.1);
        cleanup(&p);
    }

    #[test]
    fn open_existing_read_only_torn_is_non_panic_and_typed() {
        let p = path("open-torn");
        cleanup(&p);
        {
            let _store = RedbRecoveryStore::open(&p).unwrap();
        }
        let before = fs::read(&p).unwrap();
        {
            let mut truncated = before.clone();
            truncated.truncate(before.len() / 2);
            fs::write(&p, &truncated).unwrap();
        }
        let res =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open_existing_read_only(&p)));
        assert!(
            res.is_ok(),
            "open_existing_read_only must not panic on torn file"
        );
        let inner = res.unwrap();
        assert!(
            matches!(
                inner,
                Err(OrsSupervisionStatusError::Corrupt(_)
                    | OrsSupervisionStatusError::Unknown(_)
                    | OrsSupervisionStatusError::Missing(_)
                    | OrsSupervisionStatusError::AccessDenied(_))
            ),
            "torn open must be typed error"
        );
        fs::write(&p, &before).unwrap();
        cleanup(&p);
    }

    #[test]
    fn open_existing_read_only_directory_is_typed_error() {
        let dir = std::env::temp_dir().join(format!(
            "eliot-ors-status-dir-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::create_dir_all(&dir);
        let res = open_existing_read_only(&dir);
        assert!(
            matches!(
                res,
                Err(OrsSupervisionStatusError::Corrupt(_)
                    | OrsSupervisionStatusError::Unknown(_)
                    | OrsSupervisionStatusError::AccessDenied(_))
            ),
            "directory path must be typed error"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_empty_but_current_exists_is_corrupt_and_read_only() {
        let p = path("history-empty-current");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 1);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                table.remove("lease-1::00000000000000000001").unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(
            matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))),
            "history empty but current exists must be corrupt, got {res:?}"
        );
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn history_exists_without_current_is_corrupt_and_read_only() {
        let p = path("history-no-current");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 1);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
                table.remove("lease-1").unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(
            matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))),
            "history without current must be corrupt, got {res:?}"
        );
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn current_is_not_newest_is_corrupt_and_read_only() {
        let p = path("current-not-newest");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 2);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut cur = write.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
                let hist = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                let old_val = hist
                    .get("lease-1::00000000000000000001")
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_owned();
                let snap: SupervisionLeaseSnapshot = serde_json::from_str(&old_val).unwrap();
                snap.validate().unwrap();
                cur.insert("lease-1", old_val.as_str()).unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(
            matches!(res, Err(OrsSupervisionStatusError::Corrupt(_))),
            "current not newest must be corrupt, got {res:?}"
        );
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn genesis_revision_not_one_is_unknown_and_read_only() {
        let p = path("genesis-not-one");
        cleanup(&p);
        let (anchor, ctx) = build_chain(&p, 3);
        {
            let db = redb::Database::create(&p).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut hist = write.open_table(SUPERVISION_LEASE_HISTORY).unwrap();
                hist.remove("lease-1::00000000000000000001").unwrap();
            }
            write.commit().unwrap();
        }
        let before = file_bytes_and_mtime(&p);
        let res = observe_supervision_status(&p, &anchor, &ctx);
        assert!(
            matches!(res, Err(OrsSupervisionStatusError::Unknown(_))),
            "genesis not one must be unknown, got {res:?}"
        );
        let after = file_bytes_and_mtime(&p);
        assert_eq!(before.0, after.0);
        assert_eq!(before.1, after.1);
        cleanup(&p);
    }

    #[test]
    fn percent_lease_is_isolated_from_sibling_prefix() {
        let p = path("percent-sibling");
        cleanup(&p);
        let store = RedbRecoveryStore::open(&p).unwrap();
        let signer =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        for lease in ["lease%1", "lease%2"] {
            let stage = store
                .prepare_supervision_lease(request(
                    &format!("t-{lease}"),
                    &format!("o-{lease}"),
                    lease,
                    None,
                    SupervisionLeaseOperation::Commit,
                    binding(LeaseState::Active, 100),
                ))
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
                now_ms: test_time(101),
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
        }
        drop(store);
        let signer2 =
            Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])
                .unwrap();
        let anchor = SupervisionTrustAnchor::new(
            "installation-1",
            signer2.signer_id(),
            signer2.key_id(),
            signer2.public_key().to_vec(),
        )
        .unwrap();
        for lease in ["lease%1", "lease%2"] {
            let snap: SupervisionLeaseSnapshot = {
                let db = redb::Database::create(&p).unwrap();
                let read = db.begin_read().unwrap();
                let table = read.open_table(SUPERVISION_LEASE_CURRENT).unwrap();
                let v = table.get(lease).unwrap().unwrap().value().to_owned();
                serde_json::from_str(&v).unwrap()
            };
            let payload = &snap.record.artifact.payload;
            let generation = &payload.generation_binding;
            let ctx2 = SupervisionLeaseVerificationContext {
                now_ms: test_time(101),
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
            let proj = observe_supervision_status(&p, &anchor, &ctx2).unwrap();
            assert_eq!(proj.health, HealthDimension::Healthy);
            assert_eq!(proj.history.len(), 1);
            assert_eq!(
                proj.current.as_ref().unwrap().record.lease_id.as_str(),
                lease
            );
        }
        cleanup(&p);
    }
}
