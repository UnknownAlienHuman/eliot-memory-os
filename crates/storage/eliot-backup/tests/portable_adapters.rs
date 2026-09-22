//! Portable AES-256-GCM restore proofs (issue #1873; cross-machine recovery).
//!
//! Real cipher roundtrips with fixed isolated-fixture keys (test-only
//! material, never production secrets): seal/open binding, re-seal under
//! destination keys, key rewrap, nonce freshness, and a refusal matrix
//! covering unknown algorithms, wrong KEKs, moved envelopes, tampered or
//! truncated ciphertext, missing lineage, and binding mismatches.
//! Platform-independent: no DPAPI, no Credential Manager, no live state.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_backup::{
    BackupBlob, BackupError, BlobRestorationReceipt, DestinationScope, PORTABLE_ENVELOPE_ALGORITHM,
    WrappedKeyEntry, WrappedKeyManifest, portable_blob_ad, portable_keywrap_ad,
    restore_portable_blob, rewrap_portable_data_key, seal_portable_envelope,
    verify_portable_restorable,
};
use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VersionedContentDigest,
};
use eliot_contracts::sha256_hex;

const KEY_LINEAGE: &str = "key-lineage-1873x";
const DEST_LINEAGE: &str = "key-lineage-1873x-dest";
const BACKUP_ID: &str = "backup-1873x-full";
const MANIFEST_ID: &str = "key-manifest-1873x";
const WRAPPING_ID: &str = "kek-operator-a";
const DEST_WRAPPING_ID: &str = "kek-operator-b";

const KEK_A: [u8; 32] = [0xA1; 32];
const KEK_B: [u8; 32] = [0xB2; 32];
const DATA_KEY: [u8; 32] = [0xD4; 32];
const DEST_KEY: [u8; 32] = [0xDE; 32];

fn locator_for(label: &str) -> BlobLocator {
    let digest_hex = sha256_hex(label.as_bytes());
    BlobLocator {
        hash: BlobHash::new(digest_hex.clone()).expect("valid blob hash"),
        residency: ObjectResidencyKey {
            scope_domain_id: BlobId::new("scope-1873x").expect("scope domain"),
            access_domain_id: BlobId::new("access-1873x").expect("access domain"),
            confidentiality_domain_id: BlobId::new("confidentiality-1873x")
                .expect("confidentiality domain"),
            encryption_key_domain_id: BlobId::new("keydomain-1873x").expect("key domain"),
            retention_domain_id: BlobId::new("retention-1873x").expect("retention domain"),
            erasure_domain_id: BlobId::new("erasure-1873x").expect("erasure domain"),
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

fn portable_crypto() -> CryptoDescriptor {
    CryptoDescriptor {
        algorithm: BlobId::new(PORTABLE_ENVELOPE_ALGORITHM).expect("envelope algorithm"),
        version: 1,
        key_lineage: BlobId::new(KEY_LINEAGE).expect("crypto lineage"),
        key_generation: 1,
    }
}

fn blob_for(sealed_bytes: Vec<u8>, plaintext_sha256: String) -> BackupBlob {
    BackupBlob {
        locator: locator_for("blob-1873x"),
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
        crypto: portable_crypto(),
    }
}

fn wrap_data_key(
    key: &[u8; 32],
    kek: &[u8; 32],
    wrapping_id: &str,
    lineage: &str,
) -> WrappedKeyEntry {
    let envelope = seal_portable_envelope(key, kek, &portable_keywrap_ad(BACKUP_ID, lineage))
        .expect("wrap data key");
    WrappedKeyEntry {
        key_lineage: lineage.to_owned(),
        wrapping_key_id: wrapping_id.to_owned(),
        algorithm: PORTABLE_ENVELOPE_ALGORITHM.to_owned(),
        wrapped_key_sha256: envelope.sealed_sha256,
        wrapped_key_bytes: envelope.sealed_bytes,
    }
}

fn manifest_for(entry: WrappedKeyEntry) -> WrappedKeyManifest {
    WrappedKeyManifest {
        manifest_id: MANIFEST_ID.to_owned(),
        backup_id: BACKUP_ID.to_owned(),
        entries: vec![entry],
    }
}

fn seal_blob_envelope(plaintext: &[u8]) -> (Vec<u8>, String) {
    let envelope = seal_portable_envelope(
        plaintext,
        &DATA_KEY,
        &portable_blob_ad(BACKUP_ID, &sha256_hex(b"blob-1873x"), KEY_LINEAGE),
    )
    .expect("seal blob");
    (envelope.sealed_bytes, envelope.plaintext_sha256)
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

fn full_triple(plaintext: &[u8]) -> (BackupBlob, WrappedKeyManifest, BlobRestorationReceipt) {
    let locator_hash = sha256_hex(b"blob-1873x");
    let (sealed_bytes, plaintext_sha256) = seal_blob_envelope(plaintext);
    let blob = blob_for(sealed_bytes, plaintext_sha256);
    assert_eq!(blob.locator.hash.as_str(), locator_hash.as_str());
    let manifest = manifest_for(wrap_data_key(&DATA_KEY, &KEK_A, WRAPPING_ID, KEY_LINEAGE));
    let receipt = receipt_for(blob.locator.hash.as_str());
    (blob, manifest, receipt)
}

#[test]
fn portable_restore_roundtrip_under_destination_keys() {
    let plaintext = b"portable-plaintext-1873x";
    let (blob, manifest, receipt) = full_triple(plaintext);
    let restored =
        restore_portable_blob(&blob, &receipt, &manifest, &dest_scope(), &KEK_A, &DEST_KEY)
            .expect("portable restore must succeed");
    assert_eq!(restored.source_plaintext_sha256, sha256_hex(plaintext));
    assert_eq!(
        restored.resealed_sha256,
        sha256_hex(&restored.resealed_bytes)
    );
    assert_ne!(restored.resealed_bytes, blob.sealed_bytes);
    assert_eq!(
        restored.dest_crypto.algorithm.as_str(),
        PORTABLE_ENVELOPE_ALGORITHM
    );
    assert_eq!(restored.dest_crypto.key_lineage.as_str(), DEST_LINEAGE);
    assert_eq!(restored.dest_crypto.key_generation, 2);
    assert_eq!(restored.receipt_id, receipt.receipt_id);

    // The re-sealed envelope opens under the destination key with the same
    // source binding triple: chain a second restore through a destination
    // manifest to prove destination ownership end to end.
    let dest_entry = wrap_data_key(&DEST_KEY, &KEK_B, DEST_WRAPPING_ID, DEST_LINEAGE);
    let dest_manifest = WrappedKeyManifest {
        manifest_id: MANIFEST_ID.to_owned(),
        backup_id: BACKUP_ID.to_owned(),
        entries: vec![dest_entry],
    };
    let dest_blob = BackupBlob {
        locator: locator_for("blob-1873x"),
        sealed_sha256: restored.resealed_sha256.clone(),
        plaintext_sha256: sha256_hex(plaintext),
        sealed_bytes: restored.resealed_bytes.clone(),
        key_lineage: BlobId::new(DEST_LINEAGE).expect("dest key lineage"),
        format: BlobId::new("backup-format").expect("format"),
        format_version: 1,
        compression: CompressionDescriptor {
            algorithm: BlobId::new("none").expect("compression"),
            version: 1,
        },
        crypto: CryptoDescriptor {
            algorithm: BlobId::new(PORTABLE_ENVELOPE_ALGORITHM).expect("algorithm"),
            version: 1,
            key_lineage: BlobId::new(DEST_LINEAGE).expect("crypto lineage"),
            key_generation: 2,
        },
    };
    let dest_receipt = BlobRestorationReceipt {
        receipt_id: format!("blob-restore-{BACKUP_ID}-second"),
        backup_id: BACKUP_ID.to_owned(),
        manifest_id: MANIFEST_ID.to_owned(),
        blob_hash: dest_blob.locator.hash.as_str().to_owned(),
        key_lineage: DEST_LINEAGE.to_owned(),
        wrapping_key_id: DEST_WRAPPING_ID.to_owned(),
    };
    let second = restore_portable_blob(
        &dest_blob,
        &dest_receipt,
        &dest_manifest,
        &dest_scope(),
        &KEK_B,
        &DEST_KEY,
    )
    .expect("second restore must succeed");
    assert_eq!(second.source_plaintext_sha256, sha256_hex(plaintext));
}

#[test]
fn portable_seal_uses_fresh_nonce_per_envelope() {
    let first = seal_portable_envelope(
        b"same-plaintext",
        &DATA_KEY,
        &portable_blob_ad(BACKUP_ID, "hash", KEY_LINEAGE),
    )
    .expect("first seal");
    let second = seal_portable_envelope(
        b"same-plaintext",
        &DATA_KEY,
        &portable_blob_ad(BACKUP_ID, "hash", KEY_LINEAGE),
    )
    .expect("second seal");
    assert_ne!(first.sealed_bytes, second.sealed_bytes);
    assert_eq!(first.plaintext_sha256, second.plaintext_sha256);
}

#[test]
fn unknown_blob_algorithm_refused_without_crypto() {
    let (mut blob, manifest, receipt) = full_triple(b"plaintext");
    blob.crypto.algorithm = BlobId::new("aead-test").expect("other algorithm");
    let error = verify_portable_restorable(&blob, &receipt, &manifest)
        .expect_err("unknown envelope algorithm must refuse");
    assert!(
        matches!(error, BackupError::RestoreCapabilityUnsupported { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn unknown_key_algorithm_refused_without_crypto() {
    let (blob, mut manifest, receipt) = full_triple(b"plaintext");
    manifest.entries[0].algorithm = "future-kek-v9".to_owned();
    let error = verify_portable_restorable(&blob, &receipt, &manifest)
        .expect_err("unknown key algorithm must refuse");
    assert!(
        matches!(error, BackupError::RestoreCapabilityUnsupported { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn wrong_kek_refused_as_integrity_failure() {
    let (blob, manifest, receipt) = full_triple(b"plaintext");
    let error = restore_portable_blob(&blob, &receipt, &manifest, &dest_scope(), &KEK_B, &DEST_KEY)
        .expect_err("wrong KEK must refuse");
    assert!(
        matches!(error, BackupError::IntegrityMismatch { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn moved_envelope_across_backup_refused() {
    let plaintext = b"plaintext";
    let (mut blob, manifest, _) = full_triple(plaintext);
    // Envelope sealed under a DIFFERENT backup binding cannot move here:
    // re-seal the same plaintext under another backup id, keep this triple.
    let foreign = seal_portable_envelope(
        plaintext,
        &DATA_KEY,
        &portable_blob_ad("backup-other", blob.locator.hash.as_str(), KEY_LINEAGE),
    )
    .expect("foreign seal");
    blob.sealed_bytes = foreign.sealed_bytes;
    blob.sealed_sha256 = foreign.sealed_sha256;
    let receipt = receipt_for(blob.locator.hash.as_str());
    let error = restore_portable_blob(&blob, &receipt, &manifest, &dest_scope(), &KEK_A, &DEST_KEY)
        .expect_err("moved envelope must refuse");
    assert!(
        matches!(error, BackupError::IntegrityMismatch { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn tampered_ciphertext_refused() {
    let (mut blob, manifest, receipt) = full_triple(b"plaintext");
    let last = blob.sealed_bytes.len() - 1;
    blob.sealed_bytes[last] ^= 0x01;
    blob.sealed_sha256 = sha256_hex(&blob.sealed_bytes);
    let error = restore_portable_blob(&blob, &receipt, &manifest, &dest_scope(), &KEK_A, &DEST_KEY)
        .expect_err("tampered ciphertext must refuse");
    assert!(
        matches!(error, BackupError::IntegrityMismatch { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn truncated_envelope_refused() {
    let (mut blob, manifest, receipt) = full_triple(b"plaintext");
    blob.sealed_bytes.truncate(10);
    blob.sealed_sha256 = sha256_hex(&blob.sealed_bytes);
    let error = restore_portable_blob(&blob, &receipt, &manifest, &dest_scope(), &KEK_A, &DEST_KEY)
        .expect_err("truncated envelope must refuse");
    assert!(
        matches!(error, BackupError::IntegrityMismatch { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn missing_lineage_coverage_refused() {
    let (blob, mut manifest, receipt) = full_triple(b"plaintext");
    manifest.entries[0].key_lineage = "key-lineage-other".to_owned();
    let error = verify_portable_restorable(&blob, &receipt, &manifest)
        .expect_err("missing lineage must refuse");
    assert!(
        matches!(error, BackupError::MissingRecoveryComponent(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn receipt_blob_mismatch_refused() {
    let (blob, manifest, _) = full_triple(b"plaintext");
    let receipt = receipt_for("deadbeef");
    let error = verify_portable_restorable(&blob, &receipt, &manifest)
        .expect_err("receipt/blob mismatch must refuse");
    assert!(
        matches!(error, BackupError::PlanMismatch),
        "unexpected error: {error}"
    );
}

#[test]
fn rewrap_changes_binding_not_lineage() {
    let (_, manifest, _) = full_triple(b"plaintext");
    let rewrapped = rewrap_portable_data_key(
        &manifest.entries[0],
        BACKUP_ID,
        &KEK_A,
        &KEK_B,
        DEST_WRAPPING_ID,
    )
    .expect("rewrap must succeed");
    assert_eq!(rewrapped.key_lineage, KEY_LINEAGE);
    assert_eq!(rewrapped.wrapping_key_id, DEST_WRAPPING_ID);
    assert_eq!(rewrapped.algorithm, PORTABLE_ENVELOPE_ALGORITHM);
    assert_eq!(
        rewrapped.wrapped_key_sha256,
        sha256_hex(&rewrapped.wrapped_key_bytes)
    );
    assert_ne!(
        rewrapped.wrapped_key_bytes,
        manifest.entries[0].wrapped_key_bytes
    );
    rewrapped.validate().expect("rewrapped entry valid");

    // The old KEK no longer opens the re-bound entry; the new one does
    // (proven through a restore against a rebound manifest).
    let rebound = WrappedKeyManifest {
        manifest_id: MANIFEST_ID.to_owned(),
        backup_id: BACKUP_ID.to_owned(),
        entries: vec![rewrapped],
    };
    let (blob, _, receipt) = full_triple(b"plaintext");
    let stale = restore_portable_blob(&blob, &receipt, &rebound, &dest_scope(), &KEK_A, &DEST_KEY);
    assert!(
        matches!(stale, Err(BackupError::IntegrityMismatch { .. })),
        "old KEK must refuse rebound entry"
    );
    restore_portable_blob(&blob, &receipt, &rebound, &dest_scope(), &KEK_B, &DEST_KEY)
        .expect("new KEK opens rebound entry");
}

#[test]
fn seal_refuses_empty_plaintext() {
    let error =
        seal_portable_envelope(b"", &DATA_KEY, b"ad").expect_err("empty plaintext must refuse");
    assert!(
        matches!(error, BackupError::InvalidField { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn zero_dest_generation_refused() {
    let (blob, manifest, receipt) = full_triple(b"plaintext");
    let dest = DestinationScope {
        dest_key_lineage: BlobId::new(DEST_LINEAGE).expect("dest lineage"),
        dest_key_generation: 0,
    };
    let error = restore_portable_blob(&blob, &receipt, &manifest, &dest, &KEK_A, &DEST_KEY)
        .expect_err("zero destination generation must refuse");
    assert!(
        matches!(error, BackupError::InvalidField { .. }),
        "unexpected error: {error}"
    );
}
