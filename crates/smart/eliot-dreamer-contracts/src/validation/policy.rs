//! Provider-neutral validation policy identity.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DreamDraftValidationError, bounds::MAX_CANONICAL_BYTES, error::summarize_contract};
use crate::ContractViolation;

const POLICY_SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_ID: usize = 256;

/// Caller-supplied immutable policy identity for one validation invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationPolicy {
    /// Exact policy schema version.
    pub schema_version: u32,
    /// Non-blank policy identity, also required by `job.policy_ref`.
    pub policy_id: String,
    /// Explicit policy revision; zero is not a valid frozen revision.
    pub policy_revision: u64,
    /// Maximum bytes for each receipt-excluded canonical preimage.
    pub max_canonical_bytes: u64,
    /// SHA-256 of the receipt-excluded policy preimage.
    pub canonical_digest: String,
}

#[derive(Serialize)]
struct PolicyPreimage<'a> {
    schema_version: u32,
    policy_id: &'a str,
    policy_revision: u64,
    max_canonical_bytes: u64,
}

impl ValidationPolicy {
    /// Creates an unsealed policy that must be sealed before use.
    #[must_use]
    pub fn new(
        policy_id: impl Into<String>,
        policy_revision: u64,
        max_canonical_bytes: u64,
    ) -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            policy_id: policy_id.into(),
            policy_revision,
            max_canonical_bytes,
            canonical_digest: String::new(),
        }
    }

    /// Seals the policy from its receipt-excluded canonical preimage.
    pub fn seal(&mut self) -> Result<(), DreamDraftValidationError> {
        validate_policy_id(&self.policy_id)?;
        self.canonical_digest.clear();
        let bytes = canonical_bytes(self)?;
        self.canonical_digest = crate::digest_hex(&bytes);
        Ok(())
    }

    /// Validates policy shape and recomputes its canonical digest.
    pub fn validate(&self) -> Result<(), DreamDraftValidationError> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return Err(summarize_contract(
                "validation policy",
                &ContractViolation::BindingMismatch {
                    field: "policy.schema_version",
                    reason: "unsupported policy schema version".to_owned(),
                },
            ));
        }
        validate_policy_id(&self.policy_id)?;
        if self.policy_revision == 0
            || self.max_canonical_bytes == 0
            || self.max_canonical_bytes > MAX_CANONICAL_BYTES as u64
            || self.canonical_digest.len() != 64
            || !self
                .canonical_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(summarize_contract(
                "validation policy",
                &ContractViolation::BindingMismatch {
                    field: "policy.identity_or_limit",
                    reason: "policy revision, digest or byte ceiling is invalid".to_owned(),
                },
            ));
        }
        let expected = crate::digest_hex(&canonical_bytes(self)?);
        if expected != self.canonical_digest {
            return Err(summarize_contract(
                "validation policy",
                &ContractViolation::BindingMismatch {
                    field: "policy.canonical_digest",
                    reason: "policy digest does not match its receipt-excluded preimage".to_owned(),
                },
            ));
        }
        Ok(())
    }
}

fn validate_policy_id(value: &str) -> Result<(), DreamDraftValidationError> {
    if value.len() > MAX_POLICY_ID || value.trim().is_empty() || value.chars().any(char::is_control)
    {
        return Err(summarize_contract(
            "validation policy",
            &ContractViolation::BindingMismatch {
                field: "policy.policy_id",
                reason: "policy identity is blank, too long, or malformed".to_owned(),
            },
        ));
    }
    Ok(())
}

fn canonical_bytes(policy: &ValidationPolicy) -> Result<Vec<u8>, DreamDraftValidationError> {
    let bytes = crate::canonical_bytes(&PolicyPreimage {
        schema_version: policy.schema_version,
        policy_id: &policy.policy_id,
        policy_revision: policy.policy_revision,
        max_canonical_bytes: policy.max_canonical_bytes,
    })
    .map_err(|error| DreamDraftValidationError::Encoding {
        field: "validation_policy",
        detail: error.to_string(),
    })?;
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(DreamDraftValidationError::Bound {
            field: "validation_policy",
            maximum: MAX_CANONICAL_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}
