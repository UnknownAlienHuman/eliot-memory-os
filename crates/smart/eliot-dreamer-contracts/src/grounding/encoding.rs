//! Canonical encoding helpers for versioned grounding preimages.

use crate::{ContractViolation, canonical_bytes, digest_hex};
use serde::Serialize;

/// Encodes a v2 value without dropping fields or normalizing meaningful text.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractViolation> {
    canonical_bytes(value)
}
/// Computes the canonical digest used by every retained preimage.
pub fn digest<T: Serialize>(value: &T) -> Result<String, ContractViolation> {
    Ok(digest_hex(&canonical(value)?))
}
