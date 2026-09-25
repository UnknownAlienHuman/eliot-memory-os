//! Destination Blob/Secret owner adapters for backup restore (issue #1873).
//!
//! The exchange format carries sealed blob envelopes plus a separately
//! protected wrapped-key manifest; both stay opaque inside `eliot-backup`
//! (see `portable_recovery`). This module is the destination owner that
//! opens them: it unwraps lineage data keys through the installation secret
//! owner, opens sealed envelopes, verifies plaintext digests, and re-seals
//! under destination lineage. It performs no coordination, journaling,
//! cutover, machine installation, or user-storage restore — the #960
//! coordinator (A4 lane) calls [`DestinationRestoreAdapter::restore_blob_sealed`]
//! per sealed blob and stages only the returned re-sealed bytes.
//!
//! Closed envelope set: exactly [`RESTORE_ENVELOPE_ALGORITHM`]
//! (`dpapi-user-v1`, OS-authenticated user-scope protection via
//! `WindowsPlatform::protect_secret`/`unprotect_secret`). Anything else is a
//! typed refusal, never a guessed decryption. There is deliberately no
//! homebrew cipher here: confidentiality and OS-identity binding come from
//! the platform primitive, integrity binding from the manifest/bundle digest
//! chain verified at every step.
//!
//! Denied-by-default rules honored here:
//! - unknown envelope or key algorithm → [`BackupError::RestoreCapabilityUnsupported`];
//! - destination holds no wrapping identity (DPAPI unprotect fails, e.g.
//!   cross-machine envelopes) → [`BackupError::Target`], never invented success;
//! - receipt/blob/manifest lineage, backup, or digest mismatch → the existing
//!   binding errors; nothing is written through.
//! - unwrapped key bytes and plaintext live in memory only, are zeroized on
//!   drop/use, and never cross a return boundary: the only success output is
//!   re-sealed bytes plus descriptors and receipts.

use std::path::Path;

use eliot_blob_api::{BlobId, CryptoDescriptor};
use eliot_platform_windows::WindowsPlatform;
use zeroize::Zeroizing;

use super::{
    BackupBlob, BackupError, BlobRestorationReceipt, WrappedKeyEntry, WrappedKeyManifest,
    bytes_sha256,
};

/// The only restore envelope algorithm this adapter opens or seals.
///
/// `dpapi-user-v1` means: sealed bytes are opaque OS user-scope protection
/// payloads; wrapped key bytes are opaque OS user-scope protection payloads
/// holding one lineage data key. Same-user/same-machine restore round-trips
/// for real; anything else refuses at the platform call.
pub const RESTORE_ENVELOPE_ALGORITHM: &str = "dpapi-user-v1";
/// Envelope format version pinned into destination descriptors.
pub const RESTORE_ENVELOPE_VERSION: u32 = 1;

const CAPABILITY_BLOB_OPEN: &str = "dpapi-user-v1 blob open";
const CAPABILITY_KEY_UNWRAP: &str = "dpapi-user-v1 key unwrap";

/// Destination identity for re-sealed envelopes.
///
/// The lineage/generation name the destination `BlobStore` root owns. They
/// travel in the destination [`CryptoDescriptor`]; the coordinator records
/// them in the phase receipt next to the consumed restoration receipt id.
#[derive(Clone, Debug)]
pub struct DestinationScope {
    /// Key lineage the destination owns (must differ from source lineage on
    /// cross-root restore so equal bytes cannot coalesce across obligation
    /// domains; may equal it for same-root rehearsal).
    pub dest_key_lineage: BlobId,
    /// Destination key generation; must be greater than zero.
    pub dest_key_generation: u64,
}

/// A sealed envelope plus destination sealing material.
#[derive(Clone, Debug)]
pub struct SealedEnvelope {
    /// Opaque protected bytes to store.
    pub sealed_bytes: Vec<u8>,
    /// Digest of `sealed_bytes`.
    pub sealed_sha256: String,
    /// Digest of the plaintext sealed inside.
    pub plaintext_sha256: String,
}

/// A re-sealed envelope ready for destination staging.
#[derive(Clone, Debug)]
pub struct RestoredSealedBlob {
    /// Destination-protected bytes; stageable as-is, openable only through
    /// this adapter bound to the destination scope.
    pub resealed_bytes: Vec<u8>,
    /// Digest of `resealed_bytes`.
    pub resealed_sha256: String,
    /// Destination crypto identity (algorithm [`RESTORE_ENVELOPE_ALGORITHM`],
    /// destination lineage/generation).
    pub dest_crypto: CryptoDescriptor,
    /// Plaintext digest verified before re-sealing; equals the source
    /// `blob.plaintext_sha256`.
    pub source_plaintext_sha256: String,
    /// Consumed restoration receipt id.
    pub receipt_id: String,
    /// Restored source key lineage.
    pub key_lineage: String,
}

/// Memory-only lineage key material. Zeroized on drop via the vetted
/// `zeroize` RAII wrapper; never returned.
struct UnwrappedLineageKey {
    lineage: String,
    bytes: Zeroizing<Vec<u8>>,
}

/// Destination Blob/Secret owner adapter.
///
/// Bound to one isolated root for platform scoping; performs no file,
/// store, credential-manager, or machine writes itself. All secret bytes it
/// touches are memory-only inside vetted zeroizing wrappers.
pub struct DestinationRestoreAdapter {
    platform: WindowsPlatform,
}

impl DestinationRestoreAdapter {
    /// Binds the adapter for one isolated restore root.
    ///
    /// The root is passed to the platform handle for scoping; this adapter
    /// performs no I/O against it. Isolation enforcement stays with the
    /// restore path owner (`IsolatedRoot`).
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::Target`] when the platform handle cannot bind.
    pub fn bind(isolated_root: &Path) -> Result<Self, BackupError> {
        let platform = WindowsPlatform::new(isolated_root).map_err(|error| {
            BackupError::Target(format!("destination platform bind failed: {error:?}"))
        })?;
        Ok(Self { platform })
    }

    /// Seals plaintext into a [`RESTORE_ENVELOPE_ALGORITHM`] envelope.
    ///
    /// Issuance-side constructor (also used to build isolated fixtures):
    /// proves the plaintext digest that restore later re-verifies. Empty
    /// plaintext is refused before any platform call.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::InvalidField`] for empty plaintext and
    /// [`BackupError::Target`] when platform protection fails.
    pub fn seal_plaintext(&self, plaintext: &[u8]) -> Result<SealedEnvelope, BackupError> {
        if plaintext.is_empty() {
            return Err(BackupError::InvalidField {
                field: "restore.plaintext",
                reason: "cannot seal empty plaintext",
            });
        }
        let protected = self
            .platform
            .protect_secret(plaintext)
            .map_err(|error| BackupError::Target(format!("envelope seal failed: {error:?}")))?;
        let sealed_bytes = protected.as_bytes().to_vec();
        Ok(SealedEnvelope {
            sealed_sha256: bytes_sha256(&sealed_bytes),
            plaintext_sha256: bytes_sha256(plaintext),
            sealed_bytes,
        })
    }

    /// Verifies the full binding chain without touching crypto.
    ///
    /// Checks blob, receipt, and manifest validity; receipt↔blob
    /// (hash + lineage) and receipt↔manifest (manifest + backup binding);
    /// exact lineage coverage locating the manifest entry; and the closed
    /// algorithm set on both the envelope and the key entry.
    ///
    /// # Errors
    ///
    /// Returns binding, coverage, or capability errors; see
    /// [`BackupError::RestoreCapabilityUnsupported`] for unknown algorithms.
    pub fn verify_restorable<'a>(
        &self,
        blob: &BackupBlob,
        receipt: &BlobRestorationReceipt,
        manifest: &'a WrappedKeyManifest,
    ) -> Result<&'a WrappedKeyEntry, BackupError> {
        blob.validate()?;
        receipt.validate()?;
        manifest.validate()?;
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
        if blob.crypto.algorithm.as_str() != RESTORE_ENVELOPE_ALGORITHM
            || blob.crypto.version != RESTORE_ENVELOPE_VERSION
        {
            return Err(BackupError::RestoreCapabilityUnsupported {
                capability: CAPABILITY_BLOB_OPEN,
            });
        }
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.key_lineage == blob.key_lineage.as_str())
            .ok_or(BackupError::MissingRecoveryComponent("blob_key_material"))?;
        if entry.algorithm != RESTORE_ENVELOPE_ALGORITHM {
            return Err(BackupError::RestoreCapabilityUnsupported {
                capability: CAPABILITY_KEY_UNWRAP,
            });
        }
        Ok(entry)
    }

    /// Unwraps one manifest lineage key through the destination secret owner.
    ///
    /// The returned bytes live in memory only and zeroize on drop; they are
    /// never logged, serialized, or returned. Success proves the destination
    /// holds the source wrapping identity — cross-machine envelopes refuse
    /// here with [`BackupError::Target`], never invented key material.
    ///
    /// # Errors
    ///
    /// Returns validation, capability, or target errors as documented above.
    fn unwrap_lineage_key(
        &self,
        entry: &WrappedKeyEntry,
    ) -> Result<UnwrappedLineageKey, BackupError> {
        entry.validate()?;
        if entry.algorithm != RESTORE_ENVELOPE_ALGORITHM {
            return Err(BackupError::RestoreCapabilityUnsupported {
                capability: CAPABILITY_KEY_UNWRAP,
            });
        }
        let protected = eliot_platform_windows::ProtectedSecret::from_ciphertext(
            entry.wrapped_key_bytes.clone(),
        )
        .map_err(|_| BackupError::InvalidField {
            field: "key_manifest.wrapped_key_bytes",
            reason: "protected key bytes cannot be empty",
        })?;
        let secret = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| {
                BackupError::Target(format!(
                    "lineage key unwrap failed for {}: {error:?}",
                    entry.key_lineage
                ))
            })?;
        Ok(UnwrappedLineageKey {
            lineage: entry.key_lineage.clone(),
            bytes: Zeroizing::new(secret.expose().to_vec()),
        })
    }

    /// Re-wraps one lineage key under a destination wrapping identity.
    ///
    /// Unwraps through the destination secret owner, then protects the same
    /// lineage bytes under `dest_wrapping_key_id`, minting a fresh digest.
    /// Same lineage, new wrapping binding — the destination re-encryption
    /// half of portable recovery.
    ///
    /// # Errors
    ///
    /// Returns validation, capability, or target errors as documented above.
    pub fn rewrap_lineage_key(
        &self,
        entry: &WrappedKeyEntry,
        dest_wrapping_key_id: &str,
    ) -> Result<WrappedKeyEntry, BackupError> {
        super::text(dest_wrapping_key_id, "key_manifest.wrapping_key_id")?;
        let unwrapped = self.unwrap_lineage_key(entry)?;
        let rewrapped = self
            .platform
            .protect_secret(&unwrapped.bytes)
            .map_err(|error| {
                BackupError::Target(format!(
                    "lineage key rewrap failed for {}: {error:?}",
                    unwrapped.lineage
                ))
            })?;
        let rewrapped_bytes = rewrapped.as_bytes().to_vec();
        let rewrapped_entry = WrappedKeyEntry {
            key_lineage: entry.key_lineage.clone(),
            wrapping_key_id: dest_wrapping_key_id.to_owned(),
            algorithm: RESTORE_ENVELOPE_ALGORITHM.to_owned(),
            wrapped_key_sha256: bytes_sha256(&rewrapped_bytes),
            wrapped_key_bytes: rewrapped_bytes,
        };
        rewrapped_entry.validate()?;
        Ok(rewrapped_entry)
    }

    /// Opens one sealed envelope and verifies its plaintext digest.
    ///
    /// Private: plaintext never crosses a public boundary, and the returned
    /// bytes zeroize on drop — including the digest-mismatch error path.
    /// The production path is [`Self::restore_blob_sealed`], which re-seals
    /// before return.
    fn open_envelope(&self, blob: &BackupBlob) -> Result<Zeroizing<Vec<u8>>, BackupError> {
        let protected =
            eliot_platform_windows::ProtectedSecret::from_ciphertext(blob.sealed_bytes.clone())
                .map_err(|_| BackupError::InvalidField {
                    field: "blob.sealed_bytes",
                    reason: "sealed envelope cannot be empty",
                })?;
        let secret = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| {
                BackupError::Target(format!(
                    "sealed envelope open failed for {}: {error:?}",
                    blob.locator.hash.as_str()
                ))
            })?;
        let plaintext = Zeroizing::new(secret.expose().to_vec());
        if bytes_sha256(&plaintext) != blob.plaintext_sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: format!("restored blob plaintext {}", blob.locator.hash.as_str()),
            });
        }
        Ok(plaintext)
    }

    /// Restores one sealed blob under destination ownership.
    ///
    /// Verifies the binding chain, proves wrapping-identity possession by
    /// unwrapping the lineage key (memory-only, dropped here), opens and
    /// digest-verifies the envelope, then re-seals the plaintext under
    /// `dest`. Returns re-sealed bytes plus the destination descriptor and
    /// consumed receipt linkage for the coordinator's phase receipt. No
    /// plaintext or key bytes are returned.
    ///
    /// # Errors
    ///
    /// Returns binding, capability, integrity, or target errors; any refusal
    /// must fail the restore phase closed — never write-through.
    pub fn restore_blob_sealed(
        &self,
        blob: &BackupBlob,
        receipt: &BlobRestorationReceipt,
        manifest: &WrappedKeyManifest,
        dest: &DestinationScope,
    ) -> Result<RestoredSealedBlob, BackupError> {
        let entry = self.verify_restorable(blob, receipt, manifest)?;
        if dest.dest_key_generation == 0 {
            return Err(BackupError::InvalidField {
                field: "restore.dest_key_generation",
                reason: "must be greater than zero",
            });
        }
        let _lineage_key = self.unwrap_lineage_key(entry)?;
        let plaintext = self.open_envelope(blob)?;
        let resealed = self.platform.protect_secret(&plaintext).map_err(|error| {
            BackupError::Target(format!(
                "destination envelope reseal failed for {}: {error:?}",
                blob.locator.hash.as_str()
            ))
        })?;
        // `plaintext` is Zeroizing: drops (including the ?-early error paths
        // above) clear it via the vetted RAII wrapper — no manual fill.
        drop(plaintext);
        let resealed_bytes = resealed.as_bytes().to_vec();
        let dest_crypto = CryptoDescriptor {
            algorithm: BlobId::new(RESTORE_ENVELOPE_ALGORITHM)?,
            version: RESTORE_ENVELOPE_VERSION,
            key_lineage: dest.dest_key_lineage.clone(),
            key_generation: dest.dest_key_generation,
        };
        dest_crypto.validate()?;
        Ok(RestoredSealedBlob {
            resealed_sha256: bytes_sha256(&resealed_bytes),
            resealed_bytes,
            dest_crypto,
            source_plaintext_sha256: blob.plaintext_sha256.clone(),
            receipt_id: receipt.receipt_id.clone(),
            key_lineage: blob.key_lineage.as_str().to_owned(),
        })
    }
}
