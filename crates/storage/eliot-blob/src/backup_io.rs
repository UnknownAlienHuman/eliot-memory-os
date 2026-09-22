//! Owner-side verification for sealed-blob backup scope and capture evidence
//! (issue #956, slice 1).
//!
//! This module performs no staging, no reads, and mints no receipts. It
//! verifies presentation against owner-held truth only:
//! [`verify_destination_scope`] re-checks the provider-neutral scope bindings
//! and then resolves the destination descriptor through the real injected
//! [`BlobKeyPort`], proving the destination owner actually holds the admitted
//! key lineage (a foreign lineage refuses with `ProviderUnavailable`, never
//! invented success); [`verify_capture_record`] re-validates recorded capture
//! evidence through the owner contracts. Decryptability and key availability
//! stay attested by the envelope/key owners — ciphertext presence here is
//! never plaintext authentication or key possession.

use eliot_blob_api::{
    BlobError, BlobRootLease, CryptoDescriptor, ObjectResidencyKey,
    backup_io::{BlobBackupScope, SealedBlobCaptureRecord},
};

use super::{BlobKeyPort, BlobKeySelection};

/// Verifies an admitted destination scope against live owner state.
///
/// Re-validates the scope bindings against the presented destination lease,
/// crypto descriptor, and residency identity, then resolves the descriptor
/// through `key_port`. Success returns the owner-issued key selection the
/// restore path must seal under; any refusal fails the import closed.
///
/// # Errors
///
/// Returns binding, fence, integrity, or provider errors: stale/drifted scope
/// bindings, or [`BlobError::ProviderUnavailable`] when the destination owner
/// does not hold the admitted lineage.
pub fn verify_destination_scope(
    key_port: &dyn BlobKeyPort,
    scope: &BlobBackupScope,
    lease: &BlobRootLease,
    crypto: &CryptoDescriptor,
    residency: &ObjectResidencyKey,
) -> Result<BlobKeySelection, BlobError> {
    scope.verify_against(lease, crypto, residency)?;
    key_port.resolve(crypto)
}

/// Re-validates recorded sealed capture evidence through the owner contracts.
///
/// # Errors
///
/// Returns locator, crypto, lineage-binding, digest, or integrity errors when
/// the record no longer describes one coherent sealed member.
pub fn verify_capture_record(record: &SealedBlobCaptureRecord) -> Result<(), BlobError> {
    record.validate()
}
