//! Versioned provider-authored CC-002 output wire.
//!
//! The provider returns one object containing both its v1 hypothesis draft and
//! its typed grounding claims. Runtime lineage is joined from the admitted
//! execution; the provider output never supplies or replaces that lineage.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::draft::ModelDraft;
use crate::error::{ContractViolation, check_schema_version, check_vec_bound};
use crate::grounding::{MaterialClaim, MAX_CLAIMS, NonMaterialClaim};
use crate::screen::ScreenBinding;

/// Exact schema version accepted for the provider output envelope.
pub const PROVIDER_OUTPUT_SCHEMA_VERSION: u32 = 2;

/// One provider-authored pair of hypothesis and typed grounding members.
///
/// The model draft remains its existing v1 contract. The envelope version is
/// independently v2 so grounding arrays and an optional screen binding are
/// explicit members of the original provider payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderOutputV2 {
    /// Exact provider-output envelope version; must be 2.
    pub schema_version: u32,
    /// Existing hypothesis-only v1 model draft.
    pub draft: ModelDraft,
    /// Typed provider-authored grounding data from the same payload.
    pub grounding: ProviderGroundingOutputV2,
}

/// Typed grounding members authored in the provider's same v2 output object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderGroundingOutputV2 {
    /// Provider-authored material claims; no claim is inferred from prose.
    pub claims: Vec<MaterialClaim>,
    /// Provider-authored non-material residue, retained as such.
    pub non_material_claims: Vec<NonMaterialClaim>,
    /// Optional screen binding supplied in the same original payload.
    pub screen: Option<ScreenBinding>,
}

impl ProviderOutputV2 {
    /// Validates the exact envelope version, existing v1 draft and typed
    /// grounding members without deriving any grounding data.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_schema_version(self.schema_version, PROVIDER_OUTPUT_SCHEMA_VERSION)?;
        self.draft.validate()?;
        check_vec_bound(
            self.grounding.claims.len(),
            MAX_CLAIMS,
            "grounding.claims",
        )?;
        check_vec_bound(
            self.grounding.non_material_claims.len(),
            MAX_CLAIMS,
            "grounding.non_material_claims",
        )?;
        for claim in &self.grounding.claims {
            claim.validate()?;
        }
        for claim in &self.grounding.non_material_claims {
            claim.validate()?;
        }
        if let Some(screen) = &self.grounding.screen {
            screen.validate()?;
        }
        Ok(())
    }
}

/// Produces the exact schema value for publication as a new native
/// `OutputSchema` role. Callers must publish these bytes through the existing
/// canonical/artifact owner and retain its original recipe, reference and
/// named-read result; this helper does not issue or substitute a schema ref.
pub fn provider_output_schema_v2() -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(schemars::schema_for!(ProviderOutputV2))
}
