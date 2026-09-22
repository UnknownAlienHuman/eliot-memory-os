//! Epistemic Context provider contribution (#223).
//!
//! [`EpistemicContextContribution`] carries the admitted
//! [`CurrentEpistemicPosition`] into context candidates as a typed read-only
//! envelope: the shared [`ProviderId`], the position digest and [`ClaimId`]
//! echoed exactly, one scope, and one carried [`StateFence`]. The constructor
//! rejects superseded positions and never resolves, acquires, ranks, stores,
//! or applies anything.
//!
//! Fence compatibility is gated at the consumer edge, not inferred here.
//! The owner-neutral `ProviderContribution` stays `NOT_FROZEN` in
//! `crates/smart/cognitive-rev12-contract-schema-freeze.toml`
//! (CC-PROVIDER-CONTRIBUTION-SCHEMA): this envelope is the package's own
//! output protocol over frozen shared types, not a parallel contribution
//! schema.

#![forbid(unsafe_code)]

use eliot_context_contracts::ProviderId;
use eliot_contracts::{ContractVersion, StateFence};
use eliot_epistemic_contracts::{
    CONTRACT_VERSION, ClaimId, CurrentEpistemicPosition, Currentness,
};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";
/// Stable provider label carried by every contribution from this package.
pub const PROVIDER_LABEL: &str = "smart.epistemic.context-provider";
/// Maximum Unicode scalar values accepted for one scope identity.
pub const MAX_SCOPE_CHARS: usize = 256;

/// Contribution failure: every case fails closed with its reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContributionError {
    /// An upstream epistemic shape is invalid.
    #[error("epistemic context contribution: {0}")]
    Upstream(#[from] eliot_epistemic_contracts::ContractError),
    /// The admitted position is superseded and contributes nothing.
    #[error("epistemic context contribution: position is superseded")]
    SupersededPosition,
    /// The contribution version drifted from the frozen contract version.
    #[error("epistemic context contribution: version drift")]
    VersionMismatch,
    /// A digest, scope, or fence shape is invalid.
    #[error("epistemic context contribution: invalid field {field}: {reason}")]
    InvalidField {
        /// Field at fault.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
}

fn digest(value: &str, field: &'static str) -> Result<(), ContributionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ContributionError::InvalidField {
            field,
            reason: "must be 64 lowercase hex characters",
        });
    }
    Ok(())
}

/// Read-only Context provider contribution of an admitted position.
///
/// The digest and claim identify the exact admitted view this contribution
/// reads; they prove nothing beyond it. `state_fence` is carried for the
/// consumer edge to gate; this package infers no compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicContextContribution {
    /// Frozen contract version this contribution was written against.
    pub contract_version: ContractVersion,
    /// Shared provider identity of this contribution.
    pub provider: ProviderId,
    /// Digest of the admitted position view, echoed exactly.
    pub position_digest: String,
    /// Governed claim identity of the admitted position, echoed exactly.
    pub claim: ClaimId,
    /// Exact work scope the contribution is offered under.
    pub scope_id: WorkScopeId,
    /// Fence carried for the consumer edge to gate.
    pub state_fence: StateFence,
}

impl EpistemicContextContribution {
    /// Contribute the admitted position under one scope and fence.
    ///
    /// Rejects superseded positions: only a current position contributes.
    pub fn from_position(
        position: &CurrentEpistemicPosition,
        scope_id: WorkScopeId,
        state_fence: StateFence,
    ) -> Result<Self, ContributionError> {
        if position.currentness != Currentness::Current {
            return Err(ContributionError::SupersededPosition);
        }
        Self::from_parts(
            position.digest.clone(),
            position.claim.clone(),
            position.currentness,
            scope_id,
            state_fence,
        )
    }

    /// Contribute from explicit admitted evidence fields.
    ///
    /// Exists so the echo/validation rules stay testable without an
    /// admission envelope; the envelope path is [`from_position`].
    pub fn from_parts(
        position_digest: String,
        claim: ClaimId,
        currentness: Currentness,
        scope_id: WorkScopeId,
        state_fence: StateFence,
    ) -> Result<Self, ContributionError> {
        if currentness != Currentness::Current {
            return Err(ContributionError::SupersededPosition);
        }
        let contribution = Self {
            contract_version: CONTRACT_VERSION,
            provider: ProviderId::new(PROVIDER_LABEL).map_err(|_| {
                ContributionError::InvalidField {
                    field: "contribution.provider",
                    reason: "provider label is invalid",
                }
            })?,
            position_digest,
            claim,
            scope_id,
            state_fence,
        };
        contribution.validate()?;
        Ok(contribution)
    }

    /// Validate version, digest, claim, scope, and fence shape.
    pub fn validate(&self) -> Result<(), ContributionError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContributionError::VersionMismatch);
        }
        digest(&self.position_digest, "contribution.position_digest")?;
        if self.claim.as_str().trim().is_empty() {
            return Err(ContributionError::InvalidField {
                field: "contribution.claim",
                reason: "must be non-blank",
            });
        }
        if self.scope_id.as_str().chars().count() > MAX_SCOPE_CHARS {
            return Err(ContributionError::InvalidField {
                field: "contribution.scope_id",
                reason: "scope identity exceeds 256 characters",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ContributionError::InvalidField {
                field: "contribution.state_fence",
                reason: "fence interval is invalid",
            })?;
        Ok(())
    }
}
