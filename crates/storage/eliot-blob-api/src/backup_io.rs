//! Provider-neutral sealed-blob backup values: destination scope and capture
//! evidence (issue #956, slice 1).
//!
//! The F restore lane (`bins/eliot-kernel/src/backup_restore.rs`) refuses a
//! sealed-blob archive without an admitted destination blob scope
//! (`BLOB_SCOPE_BINDING = "blob-destination-scope"`) and consumes
//! per-residency sealed capture evidence. These values are that lane's
//! Blob-owner vocabulary: [`BlobBackupScope`] binds one isolated destination
//! (root generation plus destination key lineage/generation plus the exact
//! residency-key digest under import), and [`SealedBlobCaptureRecord`] binds
//! one captured sealed member (locator plus sealed/plaintext digests plus the
//! envelope crypto descriptor plus the residency-key digest).
//!
//! # Authority boundary
//!
//! Both types have private fields and validate through the real owner
//! contracts on every construction path: [`BlobRootLease::validate`],
//! [`CryptoDescriptor::validate`], [`ObjectResidencyKey::validate`],
//! [`BlobLocator::validate`], and [`ObjectResidencyKey::key_digest`]. There
//! is no caller-asserted scope: issuance recomputes the residency digest from
//! the validated residency identity, and verification re-checks every binding.
//! Neither type mints authority — key possession is proven separately by the
//! Blob owner resolving the descriptor through its real key port
//! (`eliot-blob/src/backup_io.rs`), and decryptability stays attested by the
//! envelope owner, never by ciphertext equality here.

use serde::{Deserialize, Deserializer, Serialize, de};

use super::{BlobError, BlobHash, BlobLocator, CryptoDescriptor, ObjectResidencyKey};

fn validate_hex_field(value: &str, field: &'static str) -> Result<(), BlobError> {
    BlobHash::new(value).map_err(|_| BlobError::InvalidField {
        field,
        reason: "must be lowercase hex",
    })?;
    Ok(())
}

/// Owner-issued destination scope for sealed-blob backup import.
///
/// Binds the admitted destination root generation, the destination key
/// lineage/generation that re-sealed envelopes must carry, and the exact
/// residency-key digest of the residency identity under import. Equal content
/// in different residency domains yields different digests, so the scope can
/// never authorize cross-domain coalescing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobBackupScope {
    dest_root_generation: u64,
    dest_key_lineage: super::BlobId,
    dest_key_generation: u64,
    residency_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobBackupScopeWire {
    dest_root_generation: u64,
    dest_key_lineage: super::BlobId,
    dest_key_generation: u64,
    residency_digest: String,
}

impl BlobBackupScope {
    /// Issues a destination scope from owner-validated inputs.
    ///
    /// Validates the destination root lease, the destination crypto
    /// descriptor, and the residency identity through their real owner
    /// contracts, then derives the residency digest from the validated
    /// residency — the caller supplies no digest text.
    pub fn issue(
        lease: &super::BlobRootLease,
        crypto: &CryptoDescriptor,
        residency: &ObjectResidencyKey,
    ) -> Result<Self, BlobError> {
        lease.validate()?;
        crypto.validate()?;
        residency.validate()?;
        let scope = Self {
            dest_root_generation: lease.root_generation,
            dest_key_lineage: crypto.key_lineage.clone(),
            dest_key_generation: crypto.key_generation,
            residency_digest: residency.key_digest()?,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), BlobError> {
        if self.dest_root_generation == 0 || self.dest_key_generation == 0 {
            return Err(BlobError::InvalidField {
                field: "backup_scope.generation",
                reason: "must be greater than zero",
            });
        }
        validate_hex_field(&self.residency_digest, "backup_scope.residency_digest")?;
        Ok(())
    }

    /// Re-verifies this scope against live owner-validated inputs.
    ///
    /// Generation drift of the destination root refuses with
    /// [`BlobError::StaleFence`]; a rotated destination key binding refuses as
    /// a field mismatch; a residency digest that no longer matches the exact
    /// residency identity refuses as [`BlobError::IntegrityMismatch`].
    pub fn verify_against(
        &self,
        lease: &super::BlobRootLease,
        crypto: &CryptoDescriptor,
        residency: &ObjectResidencyKey,
    ) -> Result<(), BlobError> {
        lease.validate()?;
        crypto.validate()?;
        residency.validate()?;
        if lease.root_generation != self.dest_root_generation {
            return Err(BlobError::StaleFence);
        }
        if crypto.key_lineage != self.dest_key_lineage
            || crypto.key_generation != self.dest_key_generation
        {
            return Err(BlobError::InvalidField {
                field: "backup_scope.crypto",
                reason: "does not match the issued destination key binding",
            });
        }
        if residency.key_digest()? != self.residency_digest {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Admitted destination root generation.
    #[must_use]
    pub fn dest_root_generation(&self) -> u64 {
        self.dest_root_generation
    }

    /// Destination key lineage re-sealed envelopes must carry.
    #[must_use]
    pub fn dest_key_lineage(&self) -> &super::BlobId {
        &self.dest_key_lineage
    }

    /// Destination key generation; always greater than zero.
    #[must_use]
    pub fn dest_key_generation(&self) -> u64 {
        self.dest_key_generation
    }

    /// Exact residency-key digest of the residency identity under import.
    #[must_use]
    pub fn residency_digest(&self) -> &str {
        &self.residency_digest
    }
}

impl<'de> Deserialize<'de> for BlobBackupScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobBackupScopeWire::deserialize(deserializer)?;
        let value = Self {
            dest_root_generation: wire.dest_root_generation,
            dest_key_lineage: wire.dest_key_lineage,
            dest_key_generation: wire.dest_key_generation,
            residency_digest: wire.residency_digest,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Per-residency sealed capture evidence for one blob member.
///
/// Records the exact [`BlobLocator`] captured, the sealed-envelope and
/// plaintext digests observed by the envelope owner, the envelope
/// [`CryptoDescriptor`], and the residency-key digest derived from the
/// validated locator. The crypto key lineage must equal the locator's
/// residency encryption-key domain: an envelope bound to a foreign lineage
/// cannot ride on this residency's evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SealedBlobCaptureRecord {
    locator: BlobLocator,
    sealed_sha256: String,
    plaintext_sha256: String,
    crypto: CryptoDescriptor,
    residency_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedBlobCaptureRecordWire {
    locator: BlobLocator,
    sealed_sha256: String,
    plaintext_sha256: String,
    crypto: CryptoDescriptor,
    residency_digest: String,
}

impl SealedBlobCaptureRecord {
    /// Records capture evidence from owner-validated inputs.
    ///
    /// Validates the locator and crypto descriptor through their real owner
    /// contracts, binds the envelope lineage to the locator's residency
    /// key-lineage domain, checks both digest shapes, and derives the
    /// residency digest from the validated locator.
    pub fn capture(
        locator: BlobLocator,
        sealed_sha256: String,
        plaintext_sha256: String,
        crypto: CryptoDescriptor,
    ) -> Result<Self, BlobError> {
        let record = Self {
            residency_digest: locator.residency_key_digest()?,
            locator,
            sealed_sha256,
            plaintext_sha256,
            crypto,
        };
        record.validate()?;
        Ok(record)
    }

    /// Re-validates the recorded evidence bindings.
    pub fn validate(&self) -> Result<(), BlobError> {
        self.locator.validate()?;
        self.crypto.validate()?;
        if self.crypto.key_lineage != self.locator.residency.encryption_key_domain_id {
            return Err(BlobError::InvalidField {
                field: "capture.crypto_lineage",
                reason: "must equal the locator residency key lineage",
            });
        }
        validate_hex_field(&self.sealed_sha256, "capture.sealed_sha256")?;
        validate_hex_field(&self.plaintext_sha256, "capture.plaintext_sha256")?;
        if self.locator.residency_key_digest()? != self.residency_digest {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Exact locator captured.
    #[must_use]
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    /// Digest of the sealed envelope bytes.
    #[must_use]
    pub fn sealed_sha256(&self) -> &str {
        &self.sealed_sha256
    }

    /// Plaintext digest attested by the envelope owner.
    #[must_use]
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    /// Envelope crypto descriptor bound to the residency key lineage.
    #[must_use]
    pub fn crypto(&self) -> &CryptoDescriptor {
        &self.crypto
    }

    /// Residency-key digest derived from the validated locator.
    #[must_use]
    pub fn residency_digest(&self) -> &str {
        &self.residency_digest
    }
}

impl<'de> Deserialize<'de> for SealedBlobCaptureRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SealedBlobCaptureRecordWire::deserialize(deserializer)?;
        let value = Self {
            locator: wire.locator,
            sealed_sha256: wire.sealed_sha256,
            plaintext_sha256: wire.plaintext_sha256,
            crypto: wire.crypto,
            residency_digest: wire.residency_digest,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}
