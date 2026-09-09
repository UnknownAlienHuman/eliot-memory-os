//! Explicit grounding policy and independent ceilings.

use crate::{error::ContractViolation, grounding::claims::ClaimKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_OUTPUT_BYTES: u64 = 1_048_576;
const MAX_SUBCLAIMS: u32 = 16_384;
const MAX_SUPPORT_HANDLES: u32 = 64;
const MAX_NONMATERIAL_CLASSES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundingPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub revision: String,
    pub permitted_kinds: BTreeSet<ClaimKind>,
    pub permitted_nonmaterial_classes: BTreeSet<String>,
    pub max_claims: u32,
    pub max_subclaims_per_claim: u32,
    pub max_support_handles_per_claim: u32,
    pub max_output_bytes: u64,
    pub digest: String,
}

impl GroundingPolicy {
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            policy_id: &'a str,
            revision: &'a str,
            permitted_kinds: &'a BTreeSet<ClaimKind>,
            permitted_nonmaterial_classes: &'a BTreeSet<String>,
            max_claims: u32,
            max_subclaims_per_claim: u32,
            max_support_handles_per_claim: u32,
            max_output_bytes: u64,
        }
        crate::grounding::encoding::digest(&Preimage {
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            revision: &self.revision,
            permitted_kinds: &self.permitted_kinds,
            permitted_nonmaterial_classes: &self.permitted_nonmaterial_classes,
            max_claims: self.max_claims,
            max_subclaims_per_claim: self.max_subclaims_per_claim,
            max_support_handles_per_claim: self.max_support_handles_per_claim,
            max_output_bytes: self.max_output_bytes,
        })
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, super::GROUNDING_SCHEMA_VERSION)?;
        text(&self.policy_id, "policy_id")?;
        text(&self.revision, "revision")?;
        if self.max_claims == 0
            || self.max_subclaims_per_claim == 0
            || self.max_support_handles_per_claim == 0
            || self.max_output_bytes == 0
        {
            return Err(ContractViolation::Budget {
                dimension: "grounding_policy",
                reason: "all ceilings must be explicit and non-zero".into(),
            });
        }
        if self.max_claims as usize > super::MAX_CLAIMS {
            return Err(ContractViolation::Budget {
                dimension: "max_claims",
                reason: "policy exceeds contract ceiling".into(),
            });
        }
        if self.permitted_kinds.is_empty()
            || self.permitted_nonmaterial_classes.len() > MAX_NONMATERIAL_CLASSES
            || self.max_subclaims_per_claim > MAX_SUBCLAIMS
            || self.max_support_handles_per_claim > MAX_SUPPORT_HANDLES
            || self.max_output_bytes > MAX_OUTPUT_BYTES
        {
            return Err(ContractViolation::Budget {
                dimension: "grounding_policy",
                reason: "policy exceeds canonical lower-owner ceilings".into(),
            });
        }
        for class in &self.permitted_nonmaterial_classes {
            text(class, "permitted_nonmaterial_classes")?;
        }
        digest(&self.digest, "digest")?;
        if self.computed_digest()? != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "policy_digest",
                reason: "policy preimage digest mismatch".into(),
            });
        }
        Ok(())
    }
}
fn text(v: &str, f: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_text(v, f, 4096)
}
fn digest(v: &str, f: &'static str) -> Result<(), ContractViolation> {
    if crate::error::is_hex64_lower(v) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field: f,
            reason: "expected lowercase SHA-256 digest".into(),
        })
    }
}
