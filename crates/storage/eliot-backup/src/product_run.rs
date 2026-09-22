//! Product backup issuance and isolated restore execution (issue #1873).
//!
//! Typed orchestration behind the `eliot backup issue` / `backup restore-run`
//! arms: assemble-and-issue archives from exporter-supplied inputs (never a
//! silent class downgrade), and drive the governed journaled restore into an
//! isolated root with a freshly minted lineage. Reports are serializable DTOs
//! the composition binary prints; this module owns no CLI parsing, no process
//! management, and no cutover (cutover stays a separate `#961`
//! authorization and is never performed here).

use std::num::NonZeroU64;
use std::path::Path;

use serde::{Deserialize, Serialize};

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

use super::{
    BackupBundle, BackupClass, BackupError, BackupInput, IsolatedRoot, RestoreContext,
    RestoreEvidenceLevel, RestoreObligationState, WrappedKeyManifest, execute_isolated_restore,
    issue_full_recovery, issue_restoration_receipts, text, verify_key_coverage,
};

/// How the restore target epoch is determined: an explicit caller triple, or
/// a fresh activation lineage (genesis sequence on a new lineage id with the
/// next resource generation after the archived source fence).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreEpochSpec {
    Explicit {
        lineage: String,
        sequence: u64,
        generation: u64,
    },
    NewLineage {
        lineage: String,
    },
}

/// Serializable issuance report for one `backup issue` run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueReport {
    pub backup_id: String,
    pub requested_class: BackupClass,
    pub issued_class: BackupClass,
    /// True only when a requested `full_recovery` was explicitly re-issued
    /// below its class under `--allow-degraded`. Never silent.
    pub downgraded: bool,
    pub bundle_sha256: String,
    pub bundle_path: String,
    pub key_manifest_path: Option<String>,
    pub restoration_receipts: u64,
    pub key_coverage: Option<bool>,
    pub evidence_level: RestoreEvidenceLevel,
    pub canonical_only: bool,
}

/// Serializable execution report for one `backup restore-run`.
// Wire booleans mirror the fixed evidence booleans they report; each names one
// distinct gate checked in `run_restore`, so they are not fungible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RestoreRunReport {
    pub receipt_id: String,
    pub plan_id: String,
    pub bundle_sha256: String,
    pub target_id: String,
    pub evidence_level: RestoreEvidenceLevel,
    pub canonical_only: bool,
    pub operational_recovery_ready: bool,
    pub cutover_performed: bool,
    pub new_authority_lineage: String,
    pub new_authority_sequence: u64,
    pub new_resource_generation: u64,
    pub suspended_ors_operations: u64,
    pub first_phases: Vec<String>,
    pub obligations_satisfied: bool,
    pub ors_suspension: RestoreObligationState,
    pub reconciliation: RestoreObligationState,
    pub user_broker: RestoreObligationState,
    pub isolated_root: String,
    pub journal_path: String,
}

fn write_file(path: &Path, bytes: &[u8], what: &'static str) -> Result<(), BackupError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| BackupError::Target(format!("cannot create output dir: {error}")))?;
    }
    std::fs::write(path, bytes).map_err(|error| {
        BackupError::Target(format!("cannot write {what} {}: {error}", path.display()))
    })
}

fn decode_input(bytes: &[u8]) -> Result<BackupInput, BackupError> {
    serde_json::from_slice(bytes).map_err(|error| BackupError::Serialization(error.to_string()))
}

fn decode_manifest(bytes: &[u8]) -> Result<WrappedKeyManifest, BackupError> {
    let manifest: WrappedKeyManifest = serde_json::from_slice(bytes)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Issues one backup archive from exporter-supplied inputs.
///
/// `export_bytes` carry one [`BackupInput`] assembled by the canonical/ORS/
/// blob exporter owners; this entrypoint validates, gates the class, binds
/// portable key coverage, and persists the bundle, key manifest, restoration
/// receipts, and issue report under `out_dir`. A requested `full_recovery`
/// that cannot meet its denominator fails with the exact missing component;
/// only an explicit `allow_degraded` re-issues the same material as
/// `canonical_only_degraded` with its distinct non-recovery-ready receipt.
pub fn issue_backup(
    export_bytes: &[u8],
    key_bytes: Option<&[u8]>,
    out_dir: &Path,
    allow_degraded: bool,
) -> Result<IssueReport, BackupError> {
    let export = decode_input(export_bytes)?;
    let keys = key_bytes.map(decode_manifest).transpose()?;
    let requested = export.class;
    if requested == BackupClass::FullRecovery {
        match issue_full_recovery(export, keys.clone()) {
            Ok(package) => {
                return persist_issued(&package.bundle, keys.as_ref(), out_dir, requested, false);
            }
            Err(BackupError::MissingRecoveryComponent(_)) if allow_degraded => {}
            Err(error) => return Err(error),
        }
    }
    // Explicit degraded/scope issuance, or the allowed-degraded fallback: the
    // same material, never labeled full recovery. A degraded archive must not
    // carry installation recovery content, so ORS content with it is a scope
    // error, not something to strip silently.
    let mut degraded = decode_input(export_bytes)?;
    let was_full_request = degraded.class == BackupClass::FullRecovery;
    if was_full_request {
        degraded.class = BackupClass::CanonicalOnlyDegraded;
    }
    if degraded.ors_snapshot.is_some() {
        return Err(BackupError::UnexpectedRecoveryComponent("ors_snapshot"));
    }
    let bundle = BackupBundle::build(degraded)?;
    let downgraded = was_full_request && bundle.manifest.class != BackupClass::FullRecovery;
    persist_issued(&bundle, keys.as_ref(), out_dir, requested, downgraded)
}

fn persist_issued(
    bundle: &BackupBundle,
    keys: Option<&WrappedKeyManifest>,
    out_dir: &Path,
    requested: BackupClass,
    downgraded: bool,
) -> Result<IssueReport, BackupError> {
    let bundle_sha256 = bundle.bundle_sha256()?;
    let bundle_path = out_dir.join("bundle.json");
    write_file(&bundle_path, &bundle.encode()?, "bundle file")?;
    let mut key_manifest_path = None;
    let mut receipts = 0_u64;
    let mut key_coverage = None;
    if let Some(manifest) = keys {
        verify_key_coverage(&bundle.blobs, manifest)?;
        key_coverage = Some(true);
        let issued =
            issue_restoration_receipts(&bundle.manifest.backup_id, manifest, &bundle.blobs)?;
        receipts = issued.len() as u64;
        let manifest_path = out_dir.join("key-manifest.json");
        write_file(
            &manifest_path,
            &serde_json::to_vec(manifest)
                .map_err(|error| BackupError::Serialization(error.to_string()))?,
            "key manifest file",
        )?;
        key_manifest_path = Some(manifest_path.display().to_string());
        let receipts_path = out_dir.join("restoration-receipts.json");
        write_file(
            &receipts_path,
            &serde_json::to_vec(&issued)
                .map_err(|error| BackupError::Serialization(error.to_string()))?,
            "restoration receipts file",
        )?;
    }
    Ok(IssueReport {
        backup_id: bundle.manifest.backup_id.clone(),
        requested_class: requested,
        issued_class: bundle.manifest.class,
        downgraded,
        bundle_sha256,
        bundle_path: bundle_path.display().to_string(),
        key_manifest_path,
        restoration_receipts: receipts,
        key_coverage,
        evidence_level: bundle.manifest.class.evidence_level(),
        canonical_only: bundle.manifest.class.is_canonical_only(),
    })
}

fn resolve_epoch(
    bundle: &BackupBundle,
    spec: &RestoreEpochSpec,
) -> Result<(EpochId, ResourceGeneration), BackupError> {
    match spec {
        RestoreEpochSpec::Explicit {
            lineage,
            sequence,
            generation,
        } => {
            let lineage_id = EpochLineageId::new(lineage)
                .map_err(|error| BackupError::Foundation(error.to_string()))?;
            let sequence = NonZeroU64::new(*sequence).ok_or(BackupError::InvalidField {
                field: "restore.target_sequence",
                reason: "sequence must be nonzero",
            })?;
            let epoch = EpochId::new(lineage_id, sequence)
                .map_err(|error| BackupError::Foundation(error.to_string()))?;
            let generation = ResourceGeneration::new(*generation)
                .map_err(|error| BackupError::Foundation(error.to_string()))?;
            Ok((epoch, generation))
        }
        RestoreEpochSpec::NewLineage { lineage } => {
            // Fresh Host/Kernel activation lineage: genesis sequence on a new
            // lineage id, one generation past the archived source fence. This
            // records lineage only; no authority activates without cutover.
            let lineage_id = EpochLineageId::new(lineage)
                .map_err(|error| BackupError::Foundation(error.to_string()))?;
            let sequence = NonZeroU64::new(1).ok_or(BackupError::InvalidField {
                field: "restore.new_lineage",
                reason: "genesis sequence must be nonzero",
            })?;
            let epoch = EpochId::new(lineage_id, sequence)
                .map_err(|error| BackupError::Foundation(error.to_string()))?;
            let generation = bundle
                .export_fence
                .state_fence
                .resource_generation
                .next()
                .map_err(|error| BackupError::Foundation(error.to_string()))?;
            Ok((epoch, generation))
        }
    }
}

/// Executes one isolated restore and reports the observed outcome.
///
/// Resolves the target lineage (explicit triple or fresh genesis lineage),
/// creates a temp-enforced isolated root, and drives the governed journaled
/// executor. Returns the target-observed receipt and evidence; cutover is
/// never performed and `operational_recovery_ready` stays false.
pub fn run_restore(
    bundle_bytes: &[u8],
    key_bytes: Option<&[u8]>,
    target_id: &str,
    epoch_spec: &RestoreEpochSpec,
    label: &str,
) -> Result<RestoreRunReport, BackupError> {
    text(target_id, "restore.target_id")?;
    let bundle = BackupBundle::decode(bundle_bytes)?;
    let keys = key_bytes.map(decode_manifest).transpose()?;
    let (authority_epoch, resource_generation) = resolve_epoch(&bundle, epoch_spec)?;
    let target = RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: authority_epoch.clone(),
        target_resource_generation: resource_generation,
    };
    let root = IsolatedRoot::create(label)?;
    let outcome = execute_isolated_restore(
        &bundle,
        target,
        authority_epoch,
        resource_generation,
        &root,
        keys.as_ref(),
    )?;
    let evidence = outcome.evidence;
    let first_phases: Vec<String> = outcome.phase_log.iter().take(2).cloned().collect();
    if first_phases.len() < 2 {
        return Err(BackupError::RestoreEvidenceIncomplete);
    }
    Ok(RestoreRunReport {
        receipt_id: outcome.receipt.receipt_id.clone(),
        plan_id: outcome.receipt.plan_id.clone(),
        bundle_sha256: outcome.receipt.bundle_sha256.clone(),
        target_id: outcome.receipt.target_id.clone(),
        evidence_level: outcome.receipt.evidence_level,
        canonical_only: outcome.receipt.canonical_only,
        operational_recovery_ready: outcome.receipt.operational_recovery_ready,
        cutover_performed: outcome.receipt.cutover_performed,
        new_authority_lineage: evidence.authority_epoch.lineage_id.to_string(),
        new_authority_sequence: evidence.authority_epoch.sequence.get(),
        new_resource_generation: evidence.resource_generation.value(),
        suspended_ors_operations: outcome.suspended_entries.len() as u64,
        first_phases,
        obligations_satisfied: evidence.obligations.all_satisfied(),
        ors_suspension: evidence.obligations.ors_suspension.state,
        reconciliation: evidence
            .obligations
            .unresolved_effect_reconciliation
            .state,
        user_broker: evidence.obligations.user_broker_invalidation.state,
        isolated_root: outcome.root.display().to_string(),
        journal_path: outcome.journal_path.display().to_string(),
    })
}
