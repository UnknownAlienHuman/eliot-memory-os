//! Epistemic Context provider contribution (#223, review repair).
//!
//! [`EpistemicContextContribution`] is a thin Smart-side envelope over the
//! owner-neutral [`ProviderContribution`]: it carries the validated owner
//! contribution plus this package's shared [`ProviderId`]. Scope, fence,
//! revision, and coverage provenance arrive exclusively through the owner
//! envelope, which itself echoes only the validated admission envelope;
//! there is no caller-supplied scope/fence and no synthetic construction
//! from raw digest or claim fields. [`from_contribution`] accepts an owner
//! contribution (re-validated on entry), never loose fields, so digests and
//! claims always arrive via an admitted position.
//!
//! The owner-neutral contribution contract stays the single contribution
//! authority (CC-PROVIDER-CONTRIBUTION-SCHEMA): this envelope is the
//! package's own provider framing over frozen shared types, not a parallel
//! contribution schema and not a W9 unblock.

#![forbid(unsafe_code)]

use eliot_context_contracts::ProviderId;
use eliot_epistemic_contracts::{
    CurrentEpistemicPosition, ProviderContribution,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";
/// Stable provider label carried by every contribution from this package.
pub const PROVIDER_LABEL: &str = "smart.epistemic.context-provider";

/// Contribution failure: every case fails closed with its reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContributionError {
    /// An upstream epistemic shape is invalid.
    #[error("epistemic context contribution: {0}")]
    Upstream(#[from] eliot_epistemic_contracts::ContractError),
    /// The provider identity is not this package.
    #[error("epistemic context contribution: invalid field {field}: {reason}")]
    InvalidField {
        /// Field at fault.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
}

/// Thin Smart-side envelope over an owner contribution.
///
/// The owner envelope identifies exactly one admission; the provider label
/// names this package as the contributing Smart provider. Fence
/// compatibility is gated at the consumer edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicContextContribution {
    /// Validated owner-neutral contribution, envelope-bound.
    pub contribution: ProviderContribution,
    /// Shared provider identity of this contribution.
    pub provider: ProviderId,
}

impl EpistemicContextContribution {
    /// Contribute the admitted position through the owner envelope.
    ///
    /// The owner rejects superseded positions and runs closed validation;
    /// this adapter only attaches the provider identity afterward.
    pub fn from_position(
        position: &CurrentEpistemicPosition,
    ) -> Result<Self, ContributionError> {
        let contribution = ProviderContribution::contribute(position)?;
        Self::from_contribution(contribution)
    }

    /// Adapt an owner contribution by attaching the provider identity.
    ///
    /// The owner envelope is re-validated on entry. This accepts a whole
    /// owner contribution, never loose digest or claim fields.
    pub fn from_contribution(
        contribution: ProviderContribution,
    ) -> Result<Self, ContributionError> {
        contribution.validate()?;
        let adapted = Self {
            contribution,
            provider: ProviderId::new(PROVIDER_LABEL).map_err(|_| {
                ContributionError::InvalidField {
                    field: "contribution.provider",
                    reason: "provider label is invalid",
                }
            })?,
        };
        adapted.validate()?;
        Ok(adapted)
    }

    /// Validate the owner envelope plus the provider identity.
    pub fn validate(&self) -> Result<(), ContributionError> {
        self.contribution.validate()?;
        if self.provider.as_str() != PROVIDER_LABEL {
            return Err(ContributionError::InvalidField {
                field: "contribution.provider",
                reason: "provider identity is not this package",
            });
        }
        Ok(())
    }

    /// Revalidate this contribution against currently admitted owner state.
    ///
    /// The caller supplies the live position (read through the admission
    /// owner, not this package); every echoed field is compared and each
    /// drift reports its exact aspect. This performs no store I/O itself:
    /// liveness comes from the supplied live state, and canonical store
    /// readback stays with the admission owner.
    pub fn revalidate_against_live(
        &self,
        live: &CurrentEpistemicPosition,
    ) -> Result<(), ContributionError> {
        use eliot_epistemic_contracts::Currentness;
        self.validate()?;
        live.validate()?;
        if live.currentness != Currentness::Current {
            return Err(ContributionError::InvalidField {
                field: "revalidation.currentness",
                reason: "live position is not current",
            });
        }
        let inner = &self.contribution;
        if inner.position_digest != live.digest {
            return Err(ContributionError::InvalidField {
                field: "revalidation.position_digest",
                reason: "live owner state advanced",
            });
        }
        if inner.claim != live.claim {
            return Err(ContributionError::InvalidField {
                field: "revalidation.claim",
                reason: "live owner state advanced",
            });
        }
        if inner.owner != live.admission.owner {
            return Err(ContributionError::InvalidField {
                field: "revalidation.owner",
                reason: "live owner state advanced",
            });
        }
        if inner.position != live.admission.position
            || inner.position_revision != live.admission.position_revision
        {
            return Err(ContributionError::InvalidField {
                field: "revalidation.position",
                reason: "live owner state advanced",
            });
        }
        if inner.scope != live.admission.scope || inner.fence != live.admission.fence {
            return Err(ContributionError::InvalidField {
                field: "revalidation.scope_fence",
                reason: "live owner state advanced",
            });
        }
        if inner.source_revision != live.admission.revision
            || inner.coverage_digest != live.admission.coverage_digest
            || inner.receipt_digest != live.admission.digest
        {
            return Err(ContributionError::InvalidField {
                field: "revalidation.revision_coverage_receipt",
                reason: "live owner state advanced",
            });
        }
        Ok(())
    }

    /// Track one position across two owner reads: contribute from the
    /// initial position, then revalidate against the live one.
    ///
    /// This is the production-consumer orchestration for epistemic
    /// liveness: a single call chains contribution and readback. Both
    /// positions arrive through the admission owner (no store I/O here);
    /// canonical store readback stays owner-side. Any advance between the
    /// reads fails closed with the exact drifted aspect.
    pub fn track_position(
        initial: &CurrentEpistemicPosition,
        live: &CurrentEpistemicPosition,
    ) -> Result<Self, ContributionError> {
        let contributed = Self::from_position(initial)?;
        contributed.revalidate_against_live(live)?;
        Ok(contributed)
    }
}
