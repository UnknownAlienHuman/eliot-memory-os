//! Epistemic Context provider contribution (#223, review repair).
//!
//! [`EpistemicContextContribution`] is a thin read-only envelope over one
//! admitted [`CurrentEpistemicPosition`]: the shared [`ProviderId`], the
//! position digest and [`ClaimId`] echoed exactly, and the admission
//! envelope's scope, fence, source revision, and coverage digest echoed
//! exactly. The constructor takes only the admitted position, so scope,
//! fence, revision, and coverage provenance cannot be supplied
//! independently, and there is no synthetic construction path. A later
//! consumer gate recovers the full provenance relationship from the echoed
//! envelope fields. Superseded positions contribute nothing.
//!
//! The owner-neutral `ProviderContribution` stays `NOT_FROZEN` in
//! `crates/smart/cognitive-rev12-contract-schema-freeze.toml`
//! (CC-PROVIDER-CONTRIBUTION-SCHEMA): this envelope is the package's own
//! output protocol over frozen shared types, bound to a validated admission,
//! not a parallel contribution schema and not a W9 unblock.

#![forbid(unsafe_code)]

use eliot_context_contracts::ProviderId;
use eliot_contracts::{ContractVersion, StateFence};
use eliot_epistemic_contracts::{CONTRACT_VERSION, ClaimId, CurrentEpistemicPosition, Currentness};
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
    /// The admitted position is superseded and contributes nothing.
    #[error("epistemic context contribution: position is superseded")]
    SupersededPosition,
    /// The contribution version drifted from the frozen contract version.
    #[error("epistemic context contribution: version drift")]
    VersionMismatch,
    /// A digest, scope, revision, provider, or fence shape is invalid.
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

fn nonblank(value: &str, field: &'static str) -> Result<(), ContributionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContributionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Read-only Context provider contribution of an admitted position.
///
/// Every envelope-bound field echoes the admitted position exactly: the
/// digest and claim identify the view, while the admission scope, fence,
/// source revision, and coverage digest recover the provenance relationship
/// a consumer gate needs. Nothing here resolves, acquires, ranks, stores, or
/// applies, and fence compatibility is gated at the consumer edge.
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
    /// Scope echoed from the admission envelope.
    pub admission_scope: String,
    /// Fence echoed from the admission envelope.
    pub admission_fence: StateFence,
    /// Source revision echoed from the admission envelope.
    pub admission_revision: String,
    /// Coverage denominator digest echoed from the admission envelope.
    pub coverage_digest: String,
}

impl EpistemicContextContribution {
    /// Contribute the admitted position.
    ///
    /// Scope, fence, revision, and coverage provenance are read from the
    /// position's admission envelope, never supplied by the caller. Only a
    /// current position contributes.
    pub fn from_position(
        position: &CurrentEpistemicPosition,
    ) -> Result<Self, ContributionError> {
        if position.currentness != Currentness::Current {
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
            position_digest: position.digest.clone(),
            claim: position.claim.clone(),
            admission_scope: position.admission.scope.clone(),
            admission_fence: position.admission.fence.clone(),
            admission_revision: position.admission.revision.clone(),
            coverage_digest: position.admission.coverage_digest.clone(),
        };
        contribution.validate()?;
        Ok(contribution)
    }

    /// Validate version, provider identity, digest, claim, and every echoed
    /// envelope field.
    pub fn validate(&self) -> Result<(), ContributionError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContributionError::VersionMismatch);
        }
        if self.provider.as_str() != PROVIDER_LABEL {
            return Err(ContributionError::InvalidField {
                field: "contribution.provider",
                reason: "provider identity is not this package",
            });
        }
        digest(&self.position_digest, "contribution.position_digest")?;
        nonblank(self.claim.as_str(), "contribution.claim")?;
        nonblank(&self.admission_scope, "contribution.admission_scope")?;
        self.admission_fence
            .validate()
            .map_err(|_| ContributionError::InvalidField {
                field: "contribution.admission_fence",
                reason: "fence interval is invalid",
            })?;
        nonblank(
            &self.admission_revision,
            "contribution.admission_revision",
        )?;
        digest(&self.coverage_digest, "contribution.coverage_digest")?;
        Ok(())
    }
}
