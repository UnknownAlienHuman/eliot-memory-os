//! Pure parsing and validation of the repository's accepted normative receipt.
//!
//! This module does not read files or discover repository state.  Its parser
//! receives receipt bytes from an explicit caller and returns only the two
//! document identities used by bootstrap artifacts.

use eliot_contracts::sha256_hex;
use serde::Deserialize;
use thiserror::Error;

use crate::NormativePair;

pub(crate) const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const RECEIPT_SCHEMA: &str = "eliot-normative-pair-v2-sharded";
const RECEIPT_STATUS: &str = "accepted";
const RECEIPT_BRANCH: &str = "main";
const RECEIPT_LAYOUT: &str = "eliot-doc-shards-v1";
const PAIR_KEY_ALGORITHM: &str = "sha256-domain-separated-v1";
const PAIR_KEY_INPUT: &str = "UTF-8 domain tag eliot-normative-pair-v1 and lowercase document digests separated and terminated by NUL bytes";
const ARCHITECTURE_PATH: &str = "docs/architecture/architecture/manifest.json";
const ARCHITECTURE_ENTRY_PATH: &str = "docs/architecture/architecture/README.md";
const ARCHITECTURE_COMPATIBILITY_PATH: &str = "docs/architecture/ELIOT_ARCHITECTURE.md";
const IMPLEMENTATION_PATH: &str = "docs/architecture/implementation/manifest.json";
const IMPLEMENTATION_ENTRY_PATH: &str = "docs/architecture/implementation/README.md";
const IMPLEMENTATION_COMPATIBILITY_PATH: &str = "docs/architecture/ELIOT_IMPLEMENTATION.md";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NormativePairReceipt {
    schema_version: String,
    status: String,
    adopted_at: String,
    decision_ref: String,
    repository_authority_branch: String,
    historical_material_location: String,
    content_layout: String,
    pair_key_algorithm: String,
    pair_key_input: String,
    pair_key: String,
    architecture_path: String,
    architecture_entry_path: String,
    architecture_compatibility_path: String,
    architecture_revision: String,
    architecture_edition: String,
    architecture_sha256: String,
    implementation_path: String,
    implementation_entry_path: String,
    implementation_compatibility_path: String,
    implementation_revision: String,
    implementation_edition: String,
    implementation_sha256: String,
    supersedes_architecture_sha256: String,
    supersedes_implementation_sha256: String,
}

/// Failure while decoding the accepted normative-pair receipt.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NormativePairReceiptError {
    /// The caller supplied more than the bounded receipt envelope.
    #[error("normative pair receipt exceeds {MAX_RECEIPT_BYTES} bytes")]
    InputTooLarge,
    /// The receipt is not UTF-8 TOML input.
    #[error("normative pair receipt is not UTF-8")]
    InvalidUtf8,
    /// TOML syntax or duplicate keys are invalid.
    #[error("normative pair receipt TOML is invalid: {0}")]
    Toml(String),
    /// A required metadata field is blank or contains control characters.
    #[error("normative pair receipt field {field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// A receipt digest is not a bare lowercase SHA-256 value.
    #[error("normative pair receipt digest field {field} is invalid")]
    InvalidDigest { field: &'static str },
    /// The external pair key is not the key derived from its two digests.
    #[error("normative pair receipt pair_key does not match its document digests")]
    PairKeyMismatch,
    /// The current pair repeats its complete predecessor identity.
    #[error("normative pair receipt repeats its complete superseded identity")]
    CurrentEqualsSuperseded,
}

/// Parse the accepted receipt supplied by an explicit repository boundary.
///
/// The parser validates receipt structure and the external pair-key binding;
/// it does not read shards and does not establish document authenticity,
/// currentness, or runtime support.
pub fn parse_normative_pair_receipt(
    bytes: &[u8],
) -> Result<NormativePair, NormativePairReceiptError> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(NormativePairReceiptError::InputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NormativePairReceiptError::InvalidUtf8)?;
    let receipt: NormativePairReceipt =
        toml::from_str(text).map_err(|error| NormativePairReceiptError::Toml(error.to_string()))?;
    validate_receipt(&receipt)?;
    Ok(NormativePair {
        architecture_sha256: receipt.architecture_sha256,
        implementation_sha256: receipt.implementation_sha256,
    })
}

fn validate_receipt(receipt: &NormativePairReceipt) -> Result<(), NormativePairReceiptError> {
    for (field, value) in [
        ("adopted_at", receipt.adopted_at.as_str()),
        ("decision_ref", receipt.decision_ref.as_str()),
        (
            "historical_material_location",
            receipt.historical_material_location.as_str(),
        ),
        (
            "architecture_revision",
            receipt.architecture_revision.as_str(),
        ),
        (
            "architecture_edition",
            receipt.architecture_edition.as_str(),
        ),
        (
            "implementation_revision",
            receipt.implementation_revision.as_str(),
        ),
        (
            "implementation_edition",
            receipt.implementation_edition.as_str(),
        ),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(NormativePairReceiptError::InvalidField {
                field,
                reason: "must be non-blank and free of control characters",
            });
        }
    }
    validate_fixed_fields(receipt)?;
    validate_digests(receipt)?;
    validate_pair_key(receipt)
}

fn validate_fixed_fields(receipt: &NormativePairReceipt) -> Result<(), NormativePairReceiptError> {
    for (field, actual, expected) in [
        (
            "schema_version",
            receipt.schema_version.as_str(),
            RECEIPT_SCHEMA,
        ),
        ("status", receipt.status.as_str(), RECEIPT_STATUS),
        (
            "repository_authority_branch",
            receipt.repository_authority_branch.as_str(),
            RECEIPT_BRANCH,
        ),
        (
            "content_layout",
            receipt.content_layout.as_str(),
            RECEIPT_LAYOUT,
        ),
        (
            "pair_key_algorithm",
            receipt.pair_key_algorithm.as_str(),
            PAIR_KEY_ALGORITHM,
        ),
        (
            "pair_key_input",
            receipt.pair_key_input.as_str(),
            PAIR_KEY_INPUT,
        ),
        (
            "architecture_path",
            receipt.architecture_path.as_str(),
            ARCHITECTURE_PATH,
        ),
        (
            "architecture_entry_path",
            receipt.architecture_entry_path.as_str(),
            ARCHITECTURE_ENTRY_PATH,
        ),
        (
            "architecture_compatibility_path",
            receipt.architecture_compatibility_path.as_str(),
            ARCHITECTURE_COMPATIBILITY_PATH,
        ),
        (
            "implementation_path",
            receipt.implementation_path.as_str(),
            IMPLEMENTATION_PATH,
        ),
        (
            "implementation_entry_path",
            receipt.implementation_entry_path.as_str(),
            IMPLEMENTATION_ENTRY_PATH,
        ),
        (
            "implementation_compatibility_path",
            receipt.implementation_compatibility_path.as_str(),
            IMPLEMENTATION_COMPATIBILITY_PATH,
        ),
    ] {
        if actual != expected {
            return Err(NormativePairReceiptError::InvalidField {
                field,
                reason: "does not match the accepted receipt contract",
            });
        }
    }
    Ok(())
}

fn validate_digests(receipt: &NormativePairReceipt) -> Result<(), NormativePairReceiptError> {
    for (field, value) in [
        ("architecture_sha256", receipt.architecture_sha256.as_str()),
        (
            "implementation_sha256",
            receipt.implementation_sha256.as_str(),
        ),
        (
            "supersedes_architecture_sha256",
            receipt.supersedes_architecture_sha256.as_str(),
        ),
        (
            "supersedes_implementation_sha256",
            receipt.supersedes_implementation_sha256.as_str(),
        ),
    ] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(NormativePairReceiptError::InvalidDigest { field });
        }
    }
    if receipt.architecture_sha256 == receipt.supersedes_architecture_sha256
        && receipt.implementation_sha256 == receipt.supersedes_implementation_sha256
    {
        return Err(NormativePairReceiptError::CurrentEqualsSuperseded);
    }
    Ok(())
}

fn validate_pair_key(receipt: &NormativePairReceipt) -> Result<(), NormativePairReceiptError> {
    let pair_key_input = [
        b"eliot-normative-pair-v1\0".as_slice(),
        receipt.architecture_sha256.as_bytes(),
        b"\0".as_slice(),
        receipt.implementation_sha256.as_bytes(),
        b"\0".as_slice(),
    ]
    .concat();
    let expected_pair_key = format!("sha256:{}", sha256_hex(&pair_key_input));
    if receipt.pair_key != expected_pair_key {
        return Err(NormativePairReceiptError::PairKeyMismatch);
    }
    Ok(())
}
