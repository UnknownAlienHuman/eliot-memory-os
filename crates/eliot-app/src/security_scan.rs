use crate::{config::load_config, runtime_instance::RuntimeInstance};
use anyhow::{Context as _, Result};
use eliot_store::{CanonicalStore, SurrealServerSupervisor};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::Path;
use uuid::Uuid;

const OPERATOR_CURSOR_SIGNING_KEY_FILE: &str = "operator-cursor-signing.key";
const OPERATOR_CURSOR_SIGNING_KEY_BYTES: usize = 32;
const OPERATOR_CURSOR_SIGNING_KEY_BYTES_U32: u32 = 32;

#[derive(Debug, Serialize)]
struct OperatorCursorCredentialRotationReport {
    schema_version: &'static str,
    instance_name: String,
    credential_id: String,
    credential_before: CredentialMetadataReport,
    credential_after: CredentialMetadataReport,
    legacy_file: LegacyFileRotationReport,
    secret_values_redacted: bool,
}

#[derive(Debug, Serialize)]
struct CredentialMetadataReport {
    present: bool,
    credential_size_bytes: Option<u32>,
    credential_version: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LegacyFileRotationReport {
    present_before: bool,
    legacy_value_fingerprint_sha256: Option<String>,
    removed: bool,
}

pub async fn run_canonical(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let report = CanonicalStore::new(config.db.surreal)
        .privileged_secret_scan()
        .await?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    writeln!(stdout)?;
    Ok(())
}

pub async fn rotate_legacy_credential(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let report = SurrealServerSupervisor::new(config.db.surreal)
        .rotate_legacy_credential_to_windows()
        .await?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    writeln!(stdout)?;
    Ok(())
}

pub fn rotate_operator_cursor_credential(
    config_path: &Path,
    instance_name: Option<&str>,
    remove_legacy_file: bool,
) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance_name)?;
    let credential_id = format!("operator-cursor/{}", instance.name());
    let legacy_path = instance
        .runtime_dir()
        .join("secrets")
        .join(OPERATOR_CURSOR_SIGNING_KEY_FILE);
    let legacy_bytes = match fs::read(&legacy_path) {
        Ok(bytes) => {
            anyhow::ensure!(
                bytes.len() == OPERATOR_CURSOR_SIGNING_KEY_BYTES,
                "legacy operator cursor key has an invalid byte length"
            );
            Some(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("read exact legacy operator cursor key"),
    };
    let legacy_value_fingerprint_sha256 = legacy_bytes
        .as_deref()
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    let status_before = eliot_windows_ipc::credential_status_current_user(&credential_id)?;

    let mut generated = [0_u8; OPERATOR_CURSOR_SIGNING_KEY_BYTES];
    generated[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    generated[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    eliot_windows_ipc::credential_write_current_user(&credential_id, &generated)?;
    let mut persisted = eliot_windows_ipc::credential_read_current_user(&credential_id)?
        .context("rotated operator cursor credential was not persisted")?;
    let readback_matches = persisted.as_slice() == generated;
    persisted.fill(0);
    generated.fill(0);
    anyhow::ensure!(
        readback_matches,
        "rotated operator cursor credential readback did not match"
    );

    let status_after = eliot_windows_ipc::credential_status_current_user(&credential_id)?;
    anyhow::ensure!(
        status_after.present
            && status_after.size_bytes == Some(OPERATOR_CURSOR_SIGNING_KEY_BYTES_U32),
        "rotated operator cursor credential metadata is invalid"
    );

    let legacy_file_removed = if remove_legacy_file && legacy_bytes.is_some() {
        fs::remove_file(&legacy_path).context("remove exact legacy operator cursor key")?;
        anyhow::ensure!(
            !legacy_path.exists(),
            "exact legacy operator cursor key remains after removal"
        );
        true
    } else {
        false
    };

    let report = OperatorCursorCredentialRotationReport {
        schema_version: "eliot-operator-cursor-credential-rotation-v1",
        instance_name: instance.name().to_owned(),
        credential_id,
        credential_before: CredentialMetadataReport {
            present: status_before.present,
            credential_size_bytes: status_before.size_bytes,
            credential_version: status_before.version,
        },
        credential_after: CredentialMetadataReport {
            present: status_after.present,
            credential_size_bytes: status_after.size_bytes,
            credential_version: status_after.version,
        },
        legacy_file: LegacyFileRotationReport {
            present_before: legacy_bytes.is_some(),
            legacy_value_fingerprint_sha256,
            removed: legacy_file_removed,
        },
        secret_values_redacted: true,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    writeln!(stdout)?;
    Ok(())
}
