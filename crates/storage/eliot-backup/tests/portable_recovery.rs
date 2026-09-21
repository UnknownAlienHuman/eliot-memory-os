//! Portable blob recovery proofs (issue #1873; I5.13 key-material rule).
//!
//! Minimal proof only: wrapped-key coverage for carried blob lineages,
//! missing/unverifiable key material failing `full_recovery` issuance,
//! per-blob restoration receipts, and blob-free archives needing no manifest.
//! No key is ever opened here: digests bind opaque wrapped bytes only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupError, BackupInput, EventRange,
    ExportFence, OrsSnapshotFence, WatchdogSpoolFence, WrappedKeyEntry, WrappedKeyManifest,
    issue_full_recovery, issue_restoration_receipts, verify_key_coverage,
};
use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VersionedContentDigest,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const KEY_LINEAGE: &str = "key-lineage-1873p";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_A).expect("valid lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("valid epoch")
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn locator_for(label: &str) -> BlobLocator {
    let digest_hex = sha256_hex(label.as_bytes());
    BlobLocator {
        hash: BlobHash::new(digest_hex.clone()).expect("valid blob hash"),
        residency: ObjectResidencyKey {
            scope_domain_id: BlobId::new("scope-1873p").expect("scope domain"),
            access_domain_id: BlobId::new("access-1873p").expect("access domain"),
            confidentiality_domain_id: BlobId::new("confidentiality-1873p")
                .expect("confidentiality domain"),
            encryption_key_domain_id: BlobId::new("keydomain-1873p").expect("key domain"),
            retention_domain_id: BlobId::new("retention-1873p").expect("retention domain"),
            erasure_domain_id: BlobId::new("erasure-1873p").expect("erasure domain"),
            content_digest: VersionedContentDigest {
                algorithm: BlobId::new("blake3").expect("valid algorithm"),
                version: 1,
                digest: BlobHash::new(digest_hex).expect("valid digest"),
            },
        },
        root_generation: 1,
        path_generation: 1,
    }
}

fn blob_for(label: &str) -> BackupBlob {
    let sealed_bytes = format!("sealed-envelope-{label}").into_bytes();
    BackupBlob {
        locator: locator_for(label),
        sealed_sha256: sha256_hex(&sealed_bytes),
        plaintext_sha256: sha256_hex(format!("plaintext-{label}").as_bytes()),
        sealed_bytes,
        key_lineage: BlobId::new(KEY_LINEAGE).expect("key lineage"),
        format: BlobId::new("backup-format").expect("format"),
        format_version: 1,
        compression: CompressionDescriptor {
            algorithm: BlobId::new("none").expect("compression"),
            version: 1,
        },
        crypto: CryptoDescriptor {
            algorithm: BlobId::new("aead-test").expect("crypto"),
            version: 1,
            key_lineage: BlobId::new(KEY_LINEAGE).expect("crypto lineage"),
            key_generation: 1,
        },
    }
}

fn artifact(kind: &str) -> BackupArtifact {
    let bytes = format!("{kind}-manifest-bytes").into_bytes();
    let sha256 = sha256_hex(&bytes);
    BackupArtifact {
        kind: kind.to_owned(),
        artifact_id: format!("{kind}-1"),
        bytes,
        sha256,
    }
}

fn full_input_with_blob() -> BackupInput {
    let source_fence = fence();
    let blob = blob_for("portable-1873p");
    let blob_hash = blob.locator.hash.to_string();
    BackupInput {
        backup_id: "backup-1873p-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-1873p".to_owned(),
            store_generation: "store-1873p".to_owned(),
            state_fence: source_fence.clone(),
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: None,
                last_sequence: None,
                count: 0,
            },
            blob_reachability_manifest: vec![BlobHash::new(blob_hash).expect("reachability")],
            consistent: true,
        },
        canonical_events: Vec::new(),
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: vec![blob],
        purge_ledger: Vec::new(),
        ors_snapshot: Some(OrsSnapshotFence {
            snapshot_id: "ors-1873p".to_owned(),
            authority_epoch: epoch(1),
            resource_generation: ResourceGeneration::genesis(),
            last_receipt_cursor: 0,
            last_event_cursor: 0,
            last_outbox_cursor: 0,
            pending_operation_ids: Vec::new(),
            job_checkpoint_ids: Vec::new(),
            generation_cutover_ids: Vec::new(),
            state_fence: source_fence.clone(),
            active_authority_restored: false,
        }),
        artifacts: ["config", "policy", "module", "host_dependency_build"]
            .iter()
            .map(|kind| artifact(kind))
            .collect(),
        watchdog_spool: Some(WatchdogSpoolFence {
            fence_id: "watchdog-1873p".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-1873p")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn wrapped_entry(lineage: &str) -> WrappedKeyEntry {
    let wrapped = format!("wrapped-key-{lineage}").into_bytes();
    WrappedKeyEntry {
        key_lineage: lineage.to_owned(),
        wrapping_key_id: "wrapping-key-1873p".to_owned(),
        algorithm: "aead-wrap-test".to_owned(),
        wrapped_key_sha256: sha256_hex(&wrapped),
        wrapped_key_bytes: wrapped,
    }
}

fn key_manifest() -> WrappedKeyManifest {
    WrappedKeyManifest {
        manifest_id: "key-manifest-1873p".to_owned(),
        backup_id: "backup-1873p-full".to_owned(),
        entries: vec![wrapped_entry(KEY_LINEAGE)],
    }
}

// WORK_UNIT_CASE: 1873p/portable-issuance
#[test]
fn full_recovery_with_covered_blob_lineage_issues_and_receipts() {
    let input = full_input_with_blob();
    let manifest = key_manifest();
    verify_key_coverage(&input.blobs, &manifest).expect("covered lineages verify");
    let package = issue_full_recovery(input, Some(manifest.clone())).expect("issuance succeeds");
    package.validate().expect("package validates");
    assert_eq!(package.bundle.manifest.class, BackupClass::FullRecovery);
    let receipts =
        issue_restoration_receipts("backup-1873p-full", &manifest, &package.bundle.blobs)
            .expect("receipts issue");
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    receipt.validate().expect("receipt validates");
    assert_eq!(receipt.backup_id, "backup-1873p-full");
    assert_eq!(receipt.manifest_id, "key-manifest-1873p");
    assert_eq!(receipt.key_lineage, KEY_LINEAGE);
    assert_eq!(receipt.wrapping_key_id, "wrapping-key-1873p");
    assert_eq!(
        receipt.blob_hash,
        package.bundle.blobs[0].locator.hash.to_string()
    );
}

// WORK_UNIT_CASE: 1873p/portable-missing
#[test]
fn full_recovery_without_blob_key_material_fails() {
    let input = full_input_with_blob();
    // No manifest at all: the blob set is unrestorable at the destination.
    assert_eq!(
        issue_full_recovery(input.clone(), None),
        Err(BackupError::MissingRecoveryComponent("blob_key_material"))
    );
    // Manifest present but missing the carried lineage: same typed failure.
    let mut partial = key_manifest();
    partial.entries = Vec::new();
    assert_eq!(
        issue_full_recovery(input.clone(), Some(partial)),
        Err(BackupError::MissingRecoveryComponent("blob_key_material"))
    );
    // Surplus key material for a lineage the bundle does not carry: refused.
    let mut surplus = key_manifest();
    surplus.entries.push(wrapped_entry("key-lineage-unrelated"));
    assert_eq!(
        issue_full_recovery(input, Some(surplus)),
        Err(BackupError::UnexpectedRecoveryComponent(
            "blob_key_material"
        ))
    );
}

// WORK_UNIT_CASE: 1873p/portable-unverifiable
#[test]
fn unverifiable_wrapped_key_material_fails() {
    let mut manifest = key_manifest();
    manifest.entries[0].wrapped_key_bytes = b"tampered-bytes".to_vec();
    let input = full_input_with_blob();
    let result = issue_full_recovery(input, Some(manifest));
    assert!(
        matches!(result, Err(BackupError::IntegrityMismatch { .. })),
        "tampered wrapped bytes must be an integrity mismatch, got {result:?}"
    );
}

// WORK_UNIT_CASE: 1873p/portable-scope
#[test]
fn issuance_gate_is_full_recovery_only_and_blob_free_needs_no_manifest() {
    // A degraded archive never enters the full-recovery issuance path.
    let mut degraded = full_input_with_blob();
    "backup-1873p-degraded".clone_into(&mut degraded.backup_id);
    degraded.class = BackupClass::CanonicalOnlyDegraded;
    degraded.ors_snapshot = None;
    assert!(
        matches!(
            issue_full_recovery(degraded, Some(key_manifest())),
            Err(BackupError::InvalidField { field, .. }) if field == "backup.class"
        ),
        "non-full input must be refused by class"
    );
    // Blob-free full archives carry no manifest: no key proof is owed.
    let mut blob_free = full_input_with_blob();
    blob_free.blobs = Vec::new();
    blob_free.export_fence.blob_reachability_manifest = Vec::new();
    let package = issue_full_recovery(blob_free, None).expect("blob-free issuance succeeds");
    package.validate().expect("blob-free package validates");
    assert!(package.key_manifest.is_none());
    // The underlying degraded build path is untouched by this gate.
    let bundle = BackupBundle::build(degraded_input_without_blob()).expect("degraded builds");
    assert_eq!(bundle.manifest.class, BackupClass::CanonicalOnlyDegraded);
}

fn degraded_input_without_blob() -> BackupInput {
    let mut input = full_input_with_blob();
    "backup-1873p-degraded".clone_into(&mut input.backup_id);
    input.class = BackupClass::CanonicalOnlyDegraded;
    input.ors_snapshot = None;
    input.blobs = Vec::new();
    input.export_fence.blob_reachability_manifest = Vec::new();
    input
}
