//! Portable AES-256-GCM envelope open and re-seal for cross-machine restore
//! (issue #1873).
//!
//! Closed algorithm [`PORTABLE_ENVELOPE_ALGORITHM`] (`aead-aes256-gcm-v1`,
//! vetted AES-GCM backend; random 96-bit nonce per seal via
//! `getrandom`). Envelope layout is `nonce(12) || ciphertext || tag(16)`;
//! associated data binds the backup/blob/lineage identity, so envelopes
//! cannot move across archives, blobs, or lineages. Keys are
//! caller-supplied 32-byte handles resolved by the coordinator from its
//! admitted secret surface: this module never fetches, persists, mints, or
//! exports key material. Unwrapped keys and plaintext live in memory only
//! and zeroize; the only success outputs are sealed bytes, descriptors,
//! digests, and receipts.
//!
//! The installation-bound `dpapi-user-v1` path (`owner_adapters`) is the
//! preserved intermediate freeze and stays untouched. Portable open of any
//! other algorithm refuses with
//! [`BackupError::RestoreCapabilityUnsupported`]; tag, digest, binding, or
//! coverage failures refuse with the existing integrity/binding errors —
//! unsupported portable input is never labeled successful.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use eliot_blob_api::{BlobId, CryptoDescriptor};

use super::{
    BackupBlob, BackupError, BlobRestorationReceipt, WrappedKeyEntry, WrappedKeyManifest,
    bytes_sha256, text,
};

/// The portable restore envelope algorithm (AES-256-GCM, random nonce).
pub const PORTABLE_ENVELOPE_ALGORITHM: &str = "aead-aes256-gcm-v1";
/// Envelope format version pinned into destination descriptors.
pub const PORTABLE_ENVELOPE_VERSION: u32 = 1;
/// GCM nonce length in bytes; fresh random per seal, never reused by construction.
pub const PORTABLE_NONCE_BYTES: usize = 12;
/// GCM authentication tag length in bytes, appended to the ciphertext.
pub const PORTABLE_TAG_BYTES: usize = 16;
/// Data/KEK key length in bytes (AES-256).
pub const PORTABLE_KEY_BYTES: usize = 32;

/// Memory-only unwrapped data key. Zeroized on drop; never returned.
struct UnwrappedPortableKey {
    lineage: String,
    bytes: [u8; PORTABLE_KEY_BYTES],
}

impl Drop for UnwrappedPortableKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl std::fmt::Debug for UnwrappedPortableKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key bytes deliberately omitted: Debug must never print secret material.
        formatter
            .debug_struct("UnwrappedPortableKey")
            .field("lineage", &self.lineage)
            .finish_non_exhaustive()
    }
}

/// Canonical associated data binding one sealed blob envelope.
///
/// The opener recomputes these bytes identically from manifest + blob
/// metadata, so an envelope cannot move across backups, blobs, or key
/// lineages without failing authentication.
#[must_use]
pub fn portable_blob_ad(backup_id: &str, blob_hash: &str, key_lineage: &str) -> Vec<u8> {
    format!("eliot-backup-portable-v1|blob|{backup_id}|{blob_hash}|{key_lineage}").into_bytes()
}

/// Canonical associated data binding one wrapped lineage key.
#[must_use]
pub fn portable_keywrap_ad(backup_id: &str, key_lineage: &str) -> Vec<u8> {
    format!("eliot-backup-portable-v1|keywrap|{backup_id}|{key_lineage}").into_bytes()
}

/// Sealed portable envelope plus the digests restore re-verifies.
#[derive(Clone, Debug)]
pub struct PortableSealedEnvelope {
    /// `nonce(12) || ciphertext || tag(16)`, openable only with the data key
    /// and the envelope associated data.
    pub sealed_bytes: Vec<u8>,
    /// Digest of `sealed_bytes`.
    pub sealed_sha256: String,
    /// Digest of the plaintext sealed inside.
    pub plaintext_sha256: String,
}

fn cipher_for(key: &[u8; PORTABLE_KEY_BYTES]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

fn fresh_nonce() -> Result<[u8; PORTABLE_NONCE_BYTES], BackupError> {
    let mut nonce = [0_u8; PORTABLE_NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|error| {
        BackupError::Target(format!("portable nonce generation failed: {error}"))
    })?;
    Ok(nonce)
}

/// Seals plaintext into a portable envelope (issuance-side and isolated
/// fixture constructor).
///
/// # Errors
///
/// Returns [`BackupError::InvalidField`] for empty plaintext and
/// [`BackupError::Target`] when randomness or sealing fails.
pub fn seal_portable_envelope(
    plaintext: &[u8],
    key: &[u8; PORTABLE_KEY_BYTES],
    associated_data: &[u8],
) -> Result<PortableSealedEnvelope, BackupError> {
    if plaintext.is_empty() {
        return Err(BackupError::InvalidField {
            field: "restore.plaintext",
            reason: "cannot seal empty plaintext",
        });
    }
    let nonce = fresh_nonce()?;
    let ciphertext = cipher_for(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| BackupError::Target("portable seal failed".to_owned()))?;
    let mut sealed_bytes = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed_bytes.extend_from_slice(&nonce);
    sealed_bytes.extend_from_slice(&ciphertext);
    Ok(PortableSealedEnvelope {
        sealed_sha256: bytes_sha256(&sealed_bytes),
        plaintext_sha256: bytes_sha256(plaintext),
        sealed_bytes,
    })
}

/// Opens one portable envelope with tag authentication only.
///
/// Private: callers add their own digest/length binding on top —
/// [`restore_portable_blob`] pins the blob plaintext digest, key unwrap
/// pins the sealed input digest (already checked by `entry.validate()`)
/// plus the exact 32-byte unwrapped length.
fn open_portable_raw(
    sealed: &[u8],
    key: &[u8; PORTABLE_KEY_BYTES],
    associated_data: &[u8],
    subject: &str,
) -> Result<Vec<u8>, BackupError> {
    if sealed.len() < PORTABLE_NONCE_BYTES + PORTABLE_TAG_BYTES {
        return Err(BackupError::IntegrityMismatch {
            subject: format!("portable envelope {subject}"),
        });
    }
    let (nonce, ciphertext) = sealed.split_at(PORTABLE_NONCE_BYTES);
    cipher_for(key)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| BackupError::IntegrityMismatch {
            subject: format!("portable envelope {subject}"),
        })
}

/// Opens one sealed blob envelope and verifies its plaintext digest.
///
/// Private: the production path is [`restore_portable_blob`], which re-seals
/// before return so plaintext never crosses a public boundary.
fn open_portable_envelope(
    sealed: &[u8],
    key: &[u8; PORTABLE_KEY_BYTES],
    associated_data: &[u8],
    expected_plaintext_sha256: &str,
    subject: &str,
) -> Result<Vec<u8>, BackupError> {
    let plaintext = open_portable_raw(sealed, key, associated_data, subject)?;
    if bytes_sha256(&plaintext) != expected_plaintext_sha256 {
        return Err(BackupError::IntegrityMismatch {
            subject: format!("restored portable plaintext {subject}"),
        });
    }
    Ok(plaintext)
}

/// Verifies the portable binding chain without touching crypto.
///
/// Checks blob, receipt, and manifest validity; receipt↔blob and
/// receipt↔manifest bindings; exact lineage coverage; and the portable
/// algorithm on both the envelope and the key entry.
///
/// # Errors
///
/// Returns binding, coverage, or capability errors; unknown algorithms
/// yield [`BackupError::RestoreCapabilityUnsupported`].
pub fn verify_portable_restorable<'a>(
    blob: &BackupBlob,
    receipt: &BlobRestorationReceipt,
    manifest: &'a WrappedKeyManifest,
) -> Result<&'a WrappedKeyEntry, BackupError> {
    blob.validate()?;
    receipt.validate()?;
    if receipt.blob_hash != blob.locator.hash.as_str() {
        return Err(BackupError::PlanMismatch);
    }
    if receipt.key_lineage != blob.key_lineage.as_str() {
        return Err(BackupError::PlanMismatch);
    }
    if receipt.manifest_id != manifest.manifest_id || receipt.backup_id != manifest.backup_id {
        return Err(BackupError::FenceMismatch {
            subject: "restoration receipt manifest binding".to_owned(),
        });
    }
    if blob.crypto.algorithm.as_str() != PORTABLE_ENVELOPE_ALGORITHM {
        return Err(BackupError::RestoreCapabilityUnsupported {
            capability: "aead-aes256-gcm-v1 blob open",
        });
    }
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.key_lineage == blob.key_lineage.as_str())
        .ok_or(BackupError::MissingRecoveryComponent("blob_key_material"))?;
    entry.validate()?;
    if entry.algorithm != PORTABLE_ENVELOPE_ALGORITHM {
        return Err(BackupError::RestoreCapabilityUnsupported {
            capability: "aead-aes256-gcm-v1 key unwrap",
        });
    }
    Ok(entry)
}

/// Unwraps one manifest lineage key under a caller-supplied KEK.
///
/// The KEK is resolved by the coordinator from its admitted secret surface
/// (operator-provisioned for cross-machine restore); this function only
/// consumes the 32-byte handle. The unwrapped data key is memory-only and
/// zeroizes on drop.
///
/// # Errors
///
/// Returns validation, capability, integrity, or target errors; an
/// unresolvable wrapping identity refuses here, never invented key material.
fn unwrap_portable_data_key(
    entry: &WrappedKeyEntry,
    manifest_backup_id: &str,
    kek: &[u8; PORTABLE_KEY_BYTES],
) -> Result<UnwrappedPortableKey, BackupError> {
    entry.validate()?;
    if entry.algorithm != PORTABLE_ENVELOPE_ALGORITHM {
        return Err(BackupError::RestoreCapabilityUnsupported {
            capability: "aead-aes256-gcm-v1 key unwrap",
        });
    }
    let associated_data = portable_keywrap_ad(manifest_backup_id, &entry.key_lineage);
    // Sealed-input digest already pinned by entry.validate(); the GCM tag
    // authenticates the unwrap; exact length pins the data-key shape.
    let key_bytes = open_portable_raw(
        &entry.wrapped_key_bytes,
        kek,
        &associated_data,
        &format!("wrapped key {}", entry.key_lineage),
    )?;
    if key_bytes.len() != PORTABLE_KEY_BYTES {
        return Err(BackupError::IntegrityMismatch {
            subject: format!("unwrapped key length {}", entry.key_lineage),
        });
    }
    let mut bytes = [0_u8; PORTABLE_KEY_BYTES];
    bytes.copy_from_slice(&key_bytes);
    Ok(UnwrappedPortableKey {
        lineage: entry.key_lineage.clone(),
        bytes,
    })
}

/// Re-wraps one lineage key under a destination wrapping identity.
///
/// Unwraps with the source KEK, then seals the same lineage bytes under
/// `dest_kek` with a fresh nonce and digest, bound to
/// `dest_wrapping_key_id`. Same lineage, new wrapping binding — the
/// destination re-encryption half of portable recovery. Both KEKs are
/// caller-supplied handles; unwrapped bytes zeroize before return.
///
/// # Errors
///
/// Returns validation, capability, integrity, or target errors; text,
/// digest, and tag failures all refuse.
pub fn rewrap_portable_data_key(
    entry: &WrappedKeyEntry,
    manifest_backup_id: &str,
    source_kek: &[u8; PORTABLE_KEY_BYTES],
    dest_kek: &[u8; PORTABLE_KEY_BYTES],
    dest_wrapping_key_id: &str,
) -> Result<WrappedKeyEntry, BackupError> {
    text(dest_wrapping_key_id, "key_manifest.wrapping_key_id")?;
    let unwrapped = unwrap_portable_data_key(entry, manifest_backup_id, source_kek)?;
    let associated_data = portable_keywrap_ad(manifest_backup_id, &unwrapped.lineage);
    let rewrapped = seal_portable_envelope(&unwrapped.bytes, dest_kek, &associated_data)?;
    drop(unwrapped);
    let rewrapped_entry = WrappedKeyEntry {
        key_lineage: entry.key_lineage.clone(),
        wrapping_key_id: dest_wrapping_key_id.to_owned(),
        algorithm: PORTABLE_ENVELOPE_ALGORITHM.to_owned(),
        wrapped_key_sha256: bytes_sha256(&rewrapped.sealed_bytes),
        wrapped_key_bytes: rewrapped.sealed_bytes,
    };
    rewrapped_entry.validate()?;
    Ok(rewrapped_entry)
}

/// Restores one sealed blob under destination ownership (portable path).
///
/// Verifies the binding chain, unwraps the lineage data key with the
/// caller-supplied source KEK, opens and digest-verifies the envelope,
/// then re-seals the plaintext under `dest_data_key` with the same source
/// binding triple as associated data (stable across re-seal and verifiable
/// by any holder of manifest + blob metadata). Returns re-sealed bytes
/// plus the destination descriptor and consumed receipt linkage for the
/// coordinator's phase receipt. No plaintext or key bytes are returned.
///
/// # Errors
///
/// Returns binding, capability, integrity, or target errors; any refusal
/// must fail the restore phase closed — never write-through.
#[allow(clippy::too_many_arguments)]
pub fn restore_portable_blob(
    blob: &BackupBlob,
    receipt: &BlobRestorationReceipt,
    manifest: &WrappedKeyManifest,
    dest: &super::owner_adapters::DestinationScope,
    source_kek: &[u8; PORTABLE_KEY_BYTES],
    dest_data_key: &[u8; PORTABLE_KEY_BYTES],
) -> Result<super::owner_adapters::RestoredSealedBlob, BackupError> {
    use super::owner_adapters::RestoredSealedBlob;

    let entry = verify_portable_restorable(blob, receipt, manifest)?;
    if dest.dest_key_generation == 0 {
        return Err(BackupError::InvalidField {
            field: "restore.dest_key_generation",
            reason: "must be greater than zero",
        });
    }
    let data_key = unwrap_portable_data_key(entry, &manifest.backup_id, source_kek)?;
    let associated_data = portable_blob_ad(
        &manifest.backup_id,
        blob.locator.hash.as_str(),
        &entry.key_lineage,
    );
    let mut plaintext = open_portable_envelope(
        &blob.sealed_bytes,
        &data_key.bytes,
        &associated_data,
        &blob.plaintext_sha256,
        blob.locator.hash.as_str(),
    )?;
    drop(data_key);
    // The re-sealed envelope binds the DESTINATION lineage triple: a future
    // opener recomputes associated data from its own manifest entry, which
    // covers the destination lineage — so the seal must already name it.
    // The source triple above stays the open binding for this archive.
    let dest_associated_data = portable_blob_ad(
        &manifest.backup_id,
        blob.locator.hash.as_str(),
        dest.dest_key_lineage.as_str(),
    );
    let resealed = seal_portable_envelope(&plaintext, dest_data_key, &dest_associated_data)?;
    plaintext.fill(0);
    let dest_crypto = CryptoDescriptor {
        algorithm: BlobId::new(PORTABLE_ENVELOPE_ALGORITHM)?,
        version: PORTABLE_ENVELOPE_VERSION,
        key_lineage: dest.dest_key_lineage.clone(),
        key_generation: dest.dest_key_generation,
    };
    dest_crypto.validate()?;
    Ok(RestoredSealedBlob {
        resealed_sha256: bytes_sha256(&resealed.sealed_bytes),
        resealed_bytes: resealed.sealed_bytes,
        dest_crypto,
        source_plaintext_sha256: blob.plaintext_sha256.clone(),
        receipt_id: receipt.receipt_id.clone(),
        key_lineage: blob.key_lineage.as_str().to_owned(),
    })
}
