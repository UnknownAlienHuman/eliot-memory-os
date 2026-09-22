//! Destination owner-adapter proofs (issue #1873; closed `dpapi-user-v1` set).
//!
//! Real OS-backed roundtrips on Windows (seal/open/unwrap/rewrap through
//! DPAPI with digest verification at every step) plus a platform-independent
//! refusal matrix: unknown algorithms, tampered bytes, missing lineage, and
//! receipt/binding mismatches. No Credential Manager contact (machine-global
//! surface, refused as a fixture); no live storage, installation, or user
//! restore — temp isolated roots only.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use eliot_backup::{
    BackupBlob, BackupError, BlobRestorationReceipt, DestinationRestoreAdapter, DestinationScope,
    RESTORE_ENVELOPE_ALGORITHM, WrappedKeyEntry, WrappedKeyManifest,
};
use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VersionedContentDigest,
};
use eliot_contracts::sha256_hex;

const KEY_LINEAGE: &str = "key-lineage-1873o";
const DEST_LINEAGE: &str = "key-lineage-1873o-dest";
const BACKUP_ID: &str = "backup-1873o-full";
const MANIFEST_ID: &str = "key-manifest-1873o";
const WRAPPING_ID: &str = "dpapi-user";
const DEST_WRAPPING_ID: &str = "dpapi-user-dest";

fn locator_for(label: &str) -> BlobLocator {
    let digest_hex = sha256_hex(label.as_bytes());
    BlobLocator {
        hash: BlobHash::new(digest_hex.clone()).expect("valid blob hash"),
        residency: ObjectResidencyKey {
            scope_domain_id: BlobId::new("scope-1873o").expect("scope domain"),
            access_domain_id: BlobId::new("access-1873o").expect("access domain"),
            confidentiality_domain_id: BlobId::new("confidentiality-1873o")
                .expect("confidentiality domain"),
            encryption_key_domain_id: BlobId::new("keydomain-1873o").expect("key domain"),
            retention_domain_id: BlobId::new("retention-1873o").expect("retention domain"),
            erasure_domain_id: BlobId::new("erasure-1873o").expect("erasure domain"),
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

fn v1_crypto(lineage: &str) -> CryptoDescriptor {
    CryptoDescriptor {
        algorithm: BlobId::new(RESTORE_ENVELOPE_ALGORITHM).expect("envelope algorithm"),
        version: 1,
        key_lineage: BlobId::new(lineage).expect("crypto lineage"),
        key_generation: 1,
    }
}

fn blob_for(sealed_bytes: Vec<u8>, plaintext_sha256: String) -> BackupBlob {
    BackupBlob {
        locator: locator_for("blob-1873o"),
        sealed_sha256: sha256_hex(&sealed_bytes),
        plaintext_sha256,
        sealed_bytes,
        key_lineage: BlobId::new(KEY_LINEAGE).expect("key lineage"),
        format: BlobId::new("backup-format").expect("format"),
        format_version: 1,
        compression: CompressionDescriptor {
            algorithm: BlobId::new("none").expect("compression"),
            version: 1,
        },
        crypto: v1_crypto(KEY_LINEAGE),
    }
}

fn manifest_for(wrapped_key_bytes: Vec<u8>) -> WrappedKeyManifest {
    WrappedKeyManifest {
        manifest_id: MANIFEST_ID.to_owned(),
        backup_id: BACKUP_ID.to_owned(),
        entries: vec![WrappedKeyEntry {
            key_lineage: KEY_LINEAGE.to_owned(),
            wrapping_key_id: WRAPPING_ID.to_owned(),
            algorithm: RESTORE_ENVELOPE_ALGORITHM.to_owned(),
            wrapped_key_sha256: sha256_hex(&wrapped_key_bytes),
            wrapped_key_bytes,
        }],
    }
}

fn receipt_for(blob_hash: &str) -> BlobRestorationReceipt {
    BlobRestorationReceipt {
        receipt_id: format!("blob-restore-{BACKUP_ID}-{blob_hash}"),
        backup_id: BACKUP_ID.to_owned(),
        manifest_id: MANIFEST_ID.to_owned(),
        blob_hash: blob_hash.to_owned(),
        key_lineage: KEY_LINEAGE.to_owned(),
        wrapping_key_id: WRAPPING_ID.to_owned(),
    }
}

fn dest_scope() -> DestinationScope {
    DestinationScope {
        dest_key_lineage: BlobId::new(DEST_LINEAGE).expect("dest lineage"),
        dest_key_generation: 2,
    }
}

fn isolated_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("eliot-1873o-{label}"));
    std::fs::create_dir_all(&root).expect("isolated root");
    root
}

#[test]
fn unknown_blob_algorithm_refused_without_crypto() {
    let root = isolated_root("unknown-alg");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let mut blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    blob.crypto.algorithm = BlobId::new("aead-test").expect("other algorithm");
    let manifest = manifest_for(b"wrapped-opaque".to_vec());
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("unknown envelope algorithm must refuse");
    assert!(
        matches!(error, BackupError::RestoreCapabilityUnsupported { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn unknown_key_algorithm_refused_without_crypto() {
    let root = isolated_root("unknown-key-alg");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    let mut manifest = manifest_for(b"wrapped-opaque".to_vec());
    manifest.entries[0].algorithm = "future-kek-v9".to_owned();
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("unknown key algorithm must refuse");
    assert!(
        matches!(error, BackupError::RestoreCapabilityUnsupported { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn receipt_blob_mismatch_refused() {
    let root = isolated_root("receipt-mismatch");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    let manifest = manifest_for(b"wrapped-opaque".to_vec());
    let receipt = receipt_for("deadbeef");
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("receipt/blob mismatch must refuse");
    assert!(
        matches!(error, BackupError::PlanMismatch),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn receipt_manifest_binding_mismatch_refused() {
    let root = isolated_root("manifest-binding");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    let manifest = manifest_for(b"wrapped-opaque".to_vec());
    let mut receipt = receipt_for(blob.locator.hash.as_str());
    receipt.backup_id = "backup-other".to_owned();
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("manifest binding mismatch must refuse");
    assert!(
        matches!(error, BackupError::FenceMismatch { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn missing_lineage_coverage_refused() {
    let root = isolated_root("missing-lineage");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    let mut manifest = manifest_for(b"wrapped-opaque".to_vec());
    manifest.entries[0].key_lineage = "key-lineage-other".to_owned();
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("missing lineage must refuse");
    assert!(
        matches!(error, BackupError::MissingRecoveryComponent(_)),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn tampered_sealed_bytes_refused_before_crypto() {
    let root = isolated_root("tampered-sealed");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let mut blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    blob.sealed_bytes = b"tampered-envelope".to_vec();
    let manifest = manifest_for(b"wrapped-opaque".to_vec());
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("tampered sealed bytes must refuse");
    assert!(
        matches!(error, BackupError::IntegrityMismatch { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn tampered_wrapped_key_refused_before_crypto() {
    let root = isolated_root("tampered-key");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    let mut manifest = manifest_for(b"wrapped-opaque".to_vec());
    manifest.entries[0].wrapped_key_bytes = b"tampered-key".to_vec();
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect_err("tampered wrapped key must refuse");
    assert!(
        matches!(error, BackupError::IntegrityMismatch { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn seal_refuses_empty_plaintext() {
    let root = isolated_root("seal-empty");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let error = adapter
        .seal_plaintext(b"")
        .expect_err("empty plaintext must refuse");
    assert!(
        matches!(error, BackupError::InvalidField { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn zero_dest_generation_refused() {
    let root = isolated_root("zero-generation");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let blob = blob_for(b"sealed-opaque".to_vec(), sha256_hex(b"plaintext-opaque"));
    let manifest = manifest_for(b"wrapped-opaque".to_vec());
    let receipt = receipt_for(blob.locator.hash.as_str());
    let dest = DestinationScope {
        dest_key_lineage: BlobId::new(DEST_LINEAGE).expect("dest lineage"),
        dest_key_generation: 0,
    };
    let error = adapter
        .restore_blob_sealed(&blob, &receipt, &manifest, &dest)
        .expect_err("zero destination generation must refuse");
    assert!(
        matches!(error, BackupError::InvalidField { .. }),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[cfg(windows)]
#[test]
fn dpapi_v1_restore_roundtrip_under_destination_ownership() {
    use eliot_platform_windows::WindowsPlatform;

    let root = isolated_root("roundtrip");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let platform = WindowsPlatform::new(root.clone()).expect("platform bind");

    let plaintext = b"restore-plaintext-1873o";
    let envelope = adapter.seal_plaintext(plaintext).expect("seal");
    assert_eq!(envelope.plaintext_sha256, sha256_hex(plaintext));

    let data_key = b"lineage-data-key-1873o-32bytes!!";
    let wrapped = platform.protect_secret(data_key).expect("wrap data key");
    let blob = blob_for(envelope.sealed_bytes, envelope.plaintext_sha256);
    let manifest = manifest_for(wrapped.as_bytes().to_vec());
    let receipt = receipt_for(blob.locator.hash.as_str());

    adapter
        .verify_restorable(&blob, &receipt, &manifest)
        .expect("binding must verify");

    let restored = adapter
        .restore_blob_sealed(&blob, &receipt, &manifest, &dest_scope())
        .expect("restore must succeed");
    assert_eq!(restored.source_plaintext_sha256, sha256_hex(plaintext));
    assert_eq!(
        restored.resealed_sha256,
        sha256_hex(&restored.resealed_bytes)
    );
    assert_ne!(restored.resealed_bytes, blob.sealed_bytes);
    assert_eq!(
        restored.dest_crypto.algorithm.as_str(),
        RESTORE_ENVELOPE_ALGORITHM
    );
    assert_eq!(restored.dest_crypto.version, 1);
    assert_eq!(restored.dest_crypto.key_lineage.as_str(), DEST_LINEAGE);
    assert_eq!(restored.dest_crypto.key_generation, 2);
    assert_eq!(restored.receipt_id, receipt.receipt_id);
    assert_eq!(restored.key_lineage, KEY_LINEAGE);

    // The re-sealed envelope opens under the destination scope and verifies.
    let reopened = platform
        .unprotect_secret(
            &eliot_platform_windows::ProtectedSecret::from_ciphertext(restored.resealed_bytes)
                .expect("resealed ciphertext"),
        )
        .expect("reopen resealed envelope");
    assert_eq!(reopened.expose(), plaintext);
    std::fs::remove_dir_all(&root).ok();
}

#[cfg(windows)]
#[test]
fn dpapi_v1_rewrap_preserves_lineage_under_new_binding() {
    use eliot_platform_windows::WindowsPlatform;

    let root = isolated_root("rewrap");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");
    let platform = WindowsPlatform::new(root.clone()).expect("platform bind");

    let data_key = b"lineage-data-key-1873o-32bytes!!";
    let manifest = manifest_for(
        platform
            .protect_secret(data_key)
            .expect("wrap data key")
            .as_bytes()
            .to_vec(),
    );
    let rewrapped = adapter
        .rewrap_lineage_key(&manifest.entries[0], DEST_WRAPPING_ID)
        .expect("rewrap must succeed");
    assert_eq!(rewrapped.key_lineage, KEY_LINEAGE);
    assert_eq!(rewrapped.wrapping_key_id, DEST_WRAPPING_ID);
    assert_eq!(rewrapped.algorithm, RESTORE_ENVELOPE_ALGORITHM);
    assert_eq!(
        rewrapped.wrapped_key_sha256,
        sha256_hex(&rewrapped.wrapped_key_bytes)
    );
    rewrapped.validate().expect("rewrapped entry valid");

    let reopened = platform
        .unprotect_secret(
            &eliot_platform_windows::ProtectedSecret::from_ciphertext(rewrapped.wrapped_key_bytes)
                .expect("rewrapped ciphertext"),
        )
        .expect("reopen rewrapped key");
    assert_eq!(reopened.expose(), data_key);
    std::fs::remove_dir_all(&root).ok();
}

#[cfg(windows)]
#[test]
fn foreign_envelope_refused_without_invented_success() {
    let root = isolated_root("foreign-envelope");
    let adapter = DestinationRestoreAdapter::bind(&root).expect("adapter bind");

    // Well-formed digests, but bytes no destination identity can open.
    let sealed_bytes = b"foreign-dpapi-envelope-bytes";
    let blob = blob_for(sealed_bytes.to_vec(), sha256_hex(b"claimed-plaintext"));
    let manifest = manifest_for(b"foreign-wrapped-key".to_vec());
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = adapter
        .restore_blob_sealed(&blob, &receipt, &manifest, &dest_scope())
        .expect_err("foreign envelope must refuse");
    assert!(
        matches!(error, BackupError::Target(_)),
        "unexpected error: {error}"
    );
    std::fs::remove_dir_all(&root).ok();
}
