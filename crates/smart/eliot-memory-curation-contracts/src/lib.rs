//! Provider-neutral, read-only memory curation screening contracts.
//!
//! This crate owns vocabulary and intrinsic validation only. It does not
//! execute a screen, read a store, select a semantic kind, or apply a
//! lifecycle/action transition.

#![forbid(unsafe_code)]

mod coverage;
mod eligibility;
mod error;
mod finding;
mod identity;
mod legacy;
mod profile;
mod protection;
mod result;
mod source;

pub use coverage::*;
pub use eligibility::*;
pub use error::*;
pub use finding::*;
pub use identity::*;
pub use legacy::*;
pub use profile::*;
pub use protection::*;
pub use result::*;
pub use source::*;

/// Contract name for deterministic shape identities.
pub const CONTRACT_NAME: &str = "eliot.smart.memory-curation-screen";
/// Current wire version of this contract surface.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

/// Compute the digest of a serializable contract using canonical JSON bytes.
pub fn contract_digest<T: serde::Serialize>(value: &T) -> Result<Digest, ContractError> {
    let bytes = eliot_contracts::canonical_json_bytes(value)
        .map_err(|error| ContractError::Canonicalization(error.to_string()))?;
    Digest::from_bytes(&bytes)
}

pub(crate) fn text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::ControlCharacter { field });
    }
    Ok(())
}

pub(crate) fn unique<T: Ord + Clone>(
    items: &[T],
    field: &'static str,
) -> Result<(), ContractError> {
    let mut sorted = items.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|window| window[0] == window[1]) {
        return Err(ContractError::Duplicate { field });
    }
    Ok(())
}
