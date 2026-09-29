//! Portable blob recovery: wrapped-key manifest, key-coverage proof, and
//! per-blob restoration receipts (issue #1873; I5.13 key-material rule).
//!
//! A portable/full backup never copies installation-encrypted payloads while
//! assuming destination key ownership. It either re-encrypts payloads into the
//! backup envelope (performed by the `BlobStore`/secret-provider owner, outside
//! this crate) or records a separately protected wrapped-key manifest plus a
//! restoration receipt per blob. This module binds that manifest, proves exact
//! key coverage, proves the manifest names the archive it travels with, and
//! fails `full_recovery` issuance when key material for any
//! carried blob lineage is missing or unverifiable. The backup contains key
//! lineage and format metadata, never plaintext master/data keys, and no key
//! is ever opened here: digests bind opaque wrapped bytes only.
//!
//! # Coverage is measured against the archive's own declaration (#1141, W5)
//!
//! `verify_key_coverage` is the issuance-side set proof over a caller-supplied
//! blob list. The restore direction uses `verify_declared_key_coverage`
//! instead, which anchors the expected set on
//! `manifest.encryption.key_lineages` — the archive's own record, bound by
//! `manifest.integrity_sha256` — and then requires that record, the carried
//! blobs and the wrapped-key manifest all name the same lineages. Completeness
//! measured only against the blob list the restore phases iterate would be a
//! copy of the same caller list, and would pass an archive whose key
//! declaration and material were narrowed together. I5.13 requires the
//! opposite: missing key material "makes the affected blob set unrestorable and
//! fails `full_recovery` proof".

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    BackupBlob, BackupBundle, BackupClass, BackupError, BackupInput, bytes_sha256, digest, text,
    unique,
};

/// Maximum one wrapped data-key accepted in a key manifest.
pub const MAX_WRAPPED_KEY_BYTES: usize = 4096;

/// One wrapped (encrypted) data key for a single blob key lineage.
///
/// `wrapped_key_bytes` are opaque to this crate: only presence, size bound,
/// and digest binding are checked. Unwrapping belongs to the `BlobStore`/
/// secret-provider owner at the destination.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKeyEntry {
    pub key_lineage: String,
    pub wrapping_key_id: String,
    pub algorithm: String,
    pub wrapped_key_bytes: Vec<u8>,
    pub wrapped_key_sha256: String,
}

impl WrappedKeyEntry {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.key_lineage, "key_manifest.key_lineage")?;
        text(&self.wrapping_key_id, "key_manifest.wrapping_key_id")?;
        text(&self.algorithm, "key_manifest.algorithm")?;
        if self.wrapped_key_bytes.is_empty() {
            return Err(BackupError::InvalidField {
                field: "key_manifest.wrapped_key_bytes",
                reason: "wrapped key cannot be empty",
            });
        }
        if self.wrapped_key_bytes.len() > MAX_WRAPPED_KEY_BYTES {
            return Err(BackupError::LimitExceeded {
                field: "key_manifest.wrapped_key_bytes",
                limit: MAX_WRAPPED_KEY_BYTES,
            });
        }
        digest(&self.wrapped_key_sha256, "key_manifest.wrapped_key_sha256")?;
        if bytes_sha256(&self.wrapped_key_bytes) != self.wrapped_key_sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: format!("wrapped key {}", self.key_lineage),
            });
        }
        Ok(())
    }
}

/// Separately protected wrapped-key manifest traveling with a backup.
///
/// One entry per blob key lineage carried by the bundle: exact set equality
/// is enforced, so neither missing nor surplus key material passes silently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKeyManifest {
    pub manifest_id: String,
    pub backup_id: String,
    pub entries: Vec<WrappedKeyEntry>,
}

impl WrappedKeyManifest {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.manifest_id, "key_manifest.manifest_id")?;
        text(&self.backup_id, "key_manifest.backup_id")?;
        unique(
            self.entries.iter().map(|entry| entry.key_lineage.clone()),
            "key_manifest.key_lineage",
        )?;
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }

    fn lineage_set(&self) -> BTreeSet<&str> {
        self.entries
            .iter()
            .map(|entry| entry.key_lineage.as_str())
            .collect()
    }
}

/// Proves every carried blob lineage has exactly one wrapped key.
///
/// Missing coverage fails `full_recovery` proof: the affected blob set is
/// unrestorable at the destination. Surplus entries fail as well: the
/// manifest must describe exactly the carried lineages, nothing more.
pub fn verify_key_coverage(
    blobs: &[BackupBlob],
    manifest: &WrappedKeyManifest,
) -> Result<(), BackupError> {
    manifest.validate()?;
    let needed: BTreeSet<&str> = blobs.iter().map(|blob| blob.key_lineage.as_str()).collect();
    require_exact_lineage_coverage(&needed, &manifest.lineage_set())
}

/// Exact set equality between the lineages that need key material and the
/// lineages the manifest covers, in both directions.
///
/// The refusals are the two existing typed recovery-component errors: a
/// missing lineage makes the affected blob set unrestorable at the
/// destination, and a surplus lineage means the manifest describes key
/// material this archive never needed.
fn require_exact_lineage_coverage(
    needed: &BTreeSet<&str>,
    covered: &BTreeSet<&str>,
) -> Result<(), BackupError> {
    for lineage in needed {
        if !covered.contains(lineage) {
            return Err(BackupError::MissingRecoveryComponent("blob_key_material"));
        }
    }
    for lineage in covered {
        if !needed.contains(lineage) {
            return Err(BackupError::UnexpectedRecoveryComponent(
                "blob_key_material",
            ));
        }
    }
    Ok(())
}

/// Proves wrapped-key coverage against the archive's **own declared** lineage
/// set, and that the archive's two recorded positions agree (issue #1141, W5).
///
/// [`verify_key_coverage`] derives its expected set from the very blob list
/// the restore phases iterate, so on its own it is a copy of the same caller
/// list compared with itself: a bundle whose carried blobs were narrowed
/// alongside its key manifest would pass while the archive still declares key
/// lineages the destination never received material for. I5.13 requires the
/// opposite — missing key material "makes the affected blob set unrestorable
/// and fails `full_recovery` proof" — and I14.24 requires that a failing
/// verification forbid cutover rather than let an unproven candidate proceed.
///
/// This check therefore compares three independently recorded positions:
///
/// * `bundle.manifest.encryption.key_lineages` — the archive's declared
///   encryption summary, covered by `manifest.integrity_sha256` through
///   `manifest_integrity_digest`, so it is bound to the manifest rather than
///   to a caller's list;
/// * the key lineages the carried blobs actually reference;
/// * the lineages the wrapped-key manifest covers.
///
/// All three must be the same set. A manifest that is narrowed to match a
/// tampered blob list, an archive whose declaration drifts from its blobs, and
/// a manifest that both over- and under-covers all fail closed with the
/// existing typed errors rather than agreeing with a copy of themselves.
///
/// Not re-exported: it is the restore direction's coverage proof and is
/// reached through [`verify_portable_key_material`], which is the one entry
/// point the restore runner and the operator command already call.
fn verify_declared_key_coverage(
    bundle: &BackupBundle,
    manifest: &WrappedKeyManifest,
) -> Result<(), BackupError> {
    let declared: BTreeSet<&str> = bundle
        .manifest
        .encryption
        .key_lineages
        .iter()
        .map(String::as_str)
        .collect();
    let carried: BTreeSet<&str> = bundle
        .blobs
        .iter()
        .map(|blob| blob.key_lineage.as_str())
        .collect();
    // Two archive-recorded positions first: the manifest's own declaration and
    // the lineages its carried blobs reference. Neither is the caller's list.
    require_exact_lineage_coverage(&declared, &carried)?;
    manifest.validate()?;
    require_exact_lineage_coverage(&declared, &manifest.lineage_set())
}

/// Proves the wrapped-key manifest is *this* archive's key material.
///
/// [`verify_key_coverage`] compares only the carried blob key lineages. It is
/// a set-membership proof, and lineage strings are chosen by the source
/// installation, so a manifest minted for a different backup whose lineages
/// happen to match passes it. On the restore direction that is precisely the
/// failure I5.13 forbids: installation-encrypted payloads would be copied into
/// the destination isolated root on the strength of *another* archive's key
/// proof, which is assuming destination key ownership rather than proving it.
/// The manifest therefore has to name this exact backup — the same binding
/// [`FullRecoveryPackage::validate`] already required at issuance — before the
/// runner may write a single sealed byte.
///
/// The coverage proof itself is the crate's declared-coverage check, not
/// [`verify_key_coverage`]: it is anchored on the archive's own declared
/// `encryption.key_lineages` and cross-checked against both the carried blobs
/// and the manifest, so completeness is never measured against a copy of the
/// same caller list the restore phases iterate (issue #1141, W5).
///
/// This does not decrypt anything: `wrapped_key_bytes` stay opaque here. The
/// unwrap/re-seal under destination key ownership remains the `BlobStore` and
/// secret-provider owner's step, driven by the restoration receipts.
pub fn verify_portable_key_material(
    bundle: &BackupBundle,
    manifest: &WrappedKeyManifest,
) -> Result<(), BackupError> {
    if manifest.backup_id != bundle.manifest.backup_id {
        return Err(BackupError::FenceMismatch {
            subject: "key manifest backup binding".to_owned(),
        });
    }
    verify_declared_key_coverage(bundle, manifest)
}

/// Per-blob restoration receipt binding one carried blob to its wrapped key.
///
/// Issued at backup time from validated coverage; consumed by the destination
/// `BlobStore` owner to unwrap and re-seal under destination key ownership.
/// The receipt proves the binding only — it never carries key material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRestorationReceipt {
    pub receipt_id: String,
    pub backup_id: String,
    pub manifest_id: String,
    pub blob_hash: String,
    pub key_lineage: String,
    pub wrapping_key_id: String,
}

impl BlobRestorationReceipt {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.receipt_id, "restoration_receipt.receipt_id")?;
        text(&self.backup_id, "restoration_receipt.backup_id")?;
        text(&self.manifest_id, "restoration_receipt.manifest_id")?;
        text(&self.blob_hash, "restoration_receipt.blob_hash")?;
        text(&self.key_lineage, "restoration_receipt.key_lineage")?;
        text(&self.wrapping_key_id, "restoration_receipt.wrapping_key_id")?;
        Ok(())
    }
}

/// Issues one restoration receipt per carried blob in deterministic order.
pub fn issue_restoration_receipts(
    backup_id: &str,
    manifest: &WrappedKeyManifest,
    blobs: &[BackupBlob],
) -> Result<Vec<BlobRestorationReceipt>, BackupError> {
    text(backup_id, "restoration_receipt.backup_id")?;
    verify_key_coverage(blobs, manifest)?;
    let mut hashes: Vec<&str> = blobs
        .iter()
        .map(|blob| blob.locator.hash.as_str())
        .collect();
    hashes.sort_unstable();
    let mut receipts = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let blob = blobs
            .iter()
            .find(|blob| blob.locator.hash.as_str() == hash)
            .ok_or_else(|| BackupError::IntegrityMismatch {
                subject: format!("restoration blob {hash}"),
            })?;
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.key_lineage.as_str() == blob.key_lineage.as_str())
            .ok_or(BackupError::MissingRecoveryComponent("blob_key_material"))?;
        let receipt = BlobRestorationReceipt {
            receipt_id: format!("blob-restore-{backup_id}-{hash}"),
            backup_id: backup_id.to_owned(),
            manifest_id: manifest.manifest_id.clone(),
            blob_hash: hash.to_owned(),
            key_lineage: blob.key_lineage.as_str().to_owned(),
            wrapping_key_id: entry.wrapping_key_id.clone(),
        };
        receipt.validate()?;
        receipts.push(receipt);
    }
    unique(
        receipts.iter().map(|receipt| receipt.receipt_id.clone()),
        "restoration_receipt.receipt_id",
    )?;
    Ok(receipts)
}

/// A `full_recovery` issuance: validated bundle plus its wrapped-key manifest.
///
/// The manifest travels as a companion artifact (it is not a bundle section):
/// every carried blob lineage must be covered, and the manifest must name
/// this backup. Blob-free archives carry no manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullRecoveryPackage {
    pub bundle: BackupBundle,
    pub key_manifest: Option<WrappedKeyManifest>,
}

impl FullRecoveryPackage {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.bundle.validate()?;
        if self.bundle.manifest.class != BackupClass::FullRecovery {
            return Err(BackupError::InvalidField {
                field: "backup.class",
                reason: "full-recovery issuance requires FullRecovery",
            });
        }
        match &self.key_manifest {
            Some(manifest) => verify_portable_key_material(&self.bundle, manifest)?,
            None => {
                if !self.bundle.blobs.is_empty() {
                    return Err(BackupError::MissingRecoveryComponent("blob_key_material"));
                }
            }
        }
        Ok(())
    }
}

/// Issues one `full_recovery` archive with portable blob recovery.
///
/// Fails rather than labeling success when blob key material is missing or
/// unverifiable; the same canonical material remains issuable through
/// `BackupBundle::build` as `CanonicalOnlyDegraded` with its distinct
/// non-recovery-ready receipt.
pub fn issue_full_recovery(
    input: BackupInput,
    key_manifest: Option<WrappedKeyManifest>,
) -> Result<FullRecoveryPackage, BackupError> {
    if input.class != BackupClass::FullRecovery {
        return Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "full-recovery issuance requires FullRecovery",
        });
    }
    if !input.blobs.is_empty() && key_manifest.is_none() {
        return Err(BackupError::MissingRecoveryComponent("blob_key_material"));
    }
    let bundle = BackupBundle::build(input)?;
    let package = FullRecoveryPackage {
        bundle,
        key_manifest,
    };
    package.validate()?;
    Ok(package)
}
