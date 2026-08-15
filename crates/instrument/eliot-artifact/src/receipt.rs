//! Non-caller-mintable verified receipts.

use crate::{ArtifactError, ArtifactIdentity, ArtifactManifest};
use eliot_contracts::{ClockReading, ReceiptId};

mod sealed {
    /// A construction token private to this module. External crates cannot name
    /// or construct this type, so [`VerifiedReceipt`] can only be minted by the
    /// verification functions below.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Proof(pub(crate) ());
}

/// A receipt proving that an artifact identity or manifest was recomputed.
///
/// This is an implementation proof, not a public capability. It deliberately
/// stays crate-private: the public I-01 surface exposes verified artifact data
/// only through [`crate::VerifiedArtifact`] and its owner-issued read receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedReceipt {
    receipt_id: ReceiptId,
    identity: ArtifactIdentity,
    verified_at: ClockReading,
    _sealed: sealed::Proof,
}

impl VerifiedReceipt {
    /// Returns the content-addressed receipt identity.
    pub fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    /// Returns the verified artifact identity.
    pub fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Returns the verification clock.
    pub fn verified_at(&self) -> &ClockReading {
        &self.verified_at
    }
}

/// Verifies that exact bytes satisfy an artifact identity, minting an internal receipt.
pub(crate) fn verify_content(
    identity: &ArtifactIdentity,
    content: &[u8],
    verified_at: ClockReading,
) -> Result<VerifiedReceipt, ArtifactError> {
    identity.validate()?;
    identity.verify_content(content)?;
    verified_at
        .validate()
        .map_err(|_| ArtifactError::InvalidInterval {
            field: "verified_at",
        })?;
    let receipt_id = ReceiptId::new(format!("verified:{}", identity.content.digest_hex))?;
    Ok(VerifiedReceipt {
        receipt_id,
        identity: identity.clone(),
        verified_at,
        _sealed: sealed::Proof(()),
    })
}

/// Verifies a canonical manifest by recomputing its identity, minting an internal receipt.
pub(crate) fn verify_manifest(
    manifest: &ArtifactManifest,
    verified_at: ClockReading,
) -> Result<VerifiedReceipt, ArtifactError> {
    manifest.validate()?;
    verified_at
        .validate()
        .map_err(|_| ArtifactError::InvalidInterval {
            field: "verified_at",
        })?;
    let receipt_id = ReceiptId::new(format!("verified:{}", manifest.identity.content.digest_hex))?;
    Ok(VerifiedReceipt {
        receipt_id,
        identity: manifest.identity.clone(),
        verified_at,
        _sealed: sealed::Proof(()),
    })
}
