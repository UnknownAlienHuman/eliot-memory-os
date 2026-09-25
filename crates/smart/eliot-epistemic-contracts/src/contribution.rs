//! Owner-neutral provider contribution envelope (CC-PROVIDER-CONTRIBUTION-SCHEMA).
//!
//! [`ProviderContribution`] binds one admitted [`CurrentEpistemicPosition`]
//! into the neutral handoff Smart providers consume. Every envelope-bound
//! field is echoed from the validated admission envelope: the position
//! digest and claim, the admission owner, position identity and revision,
//! scope, fence, source revision, and coverage and receipt digests. The
//! constructor takes only the admitted position, so no envelope field can
//! be supplied independently, and there is no synthetic construction path.
//! Per-field echoes give readback exact attribution: owner, position,
//! scope, fence, revision, and coverage each revalidate separately
//! against live owner state.
//!
//! Ownership is provider-neutral: the contributing provider is the admitted
//! position owner itself. This envelope carries no per-provider identity,
//! request state, or consumer framing; Smart-side provider envelopes are
//! thin adapters over this type, never parallel contribution schemas.
//!
//! Denominator and omission semantics reuse the frozen epistemic doctrine:
//! completeness is derived, never claimed. [`ProviderContribution::contribute`]
//! runs the position's closed validation (shape plus frozen-digest
//! recompute), so a contribution covers exactly its named receipt envelope
//! or fails closed. Partial contributions and omission entries do not
//! exist: missing or invalid governing material is an error, never a gap.
//! Currentness is the owner's verdict at contribution time; only a current
//! position contributes, and consumers re-gate liveness at their own edge.
//!
//! This module performs no resolution, acquisition, ranking, storage, or
//! application. It is a static handoff record, not edge, product, or
//! W9-consumer proof.

#![forbid(unsafe_code)]

use eliot_contracts::{SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::admitted::{
    AdmittedKind, CurrentEpistemicPosition, Currentness, PositionId, PositionRevision,
};
use crate::error::{ContractError, MAX_SHORT_TEXT, validate_bounded_text, validate_digest};
use crate::identity::ClaimId;

/// Owner-neutral contribution of one admitted epistemic position.
///
/// The digest, claim, scope, fence, revision, coverage, and receipt fields
/// jointly name exactly one admission envelope. A contribution whose fields
/// disagree was never produced by [`ProviderContribution::contribute`] and
/// fails [`ProviderContribution::validate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderContribution {
    /// Frozen contract version this contribution was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Marker binding this document to the admitted-view decoding.
    pub view_kind: AdmittedKind,
    /// Digest of the admitted position view, echoed exactly.
    pub position_digest: String,
    /// Governed claim identity of the admitted position, echoed exactly.
    pub claim: ClaimId,
    /// Source owning the admitted position, echoed exactly.
    pub owner: SourceId,
    /// Currentness observed at contribution time; always current.
    pub currentness: Currentness,
    /// Exact position identity admitted, echoed exactly.
    pub position: PositionId,
    /// Exact position revision admitted, echoed exactly.
    pub position_revision: PositionRevision,
    /// Scope echoed from the admission envelope.
    pub scope: String,
    /// Fence echoed from the admission envelope.
    pub fence: StateFence,
    /// Source revision echoed from the admission envelope.
    pub source_revision: String,
    /// Coverage denominator digest echoed from the admission envelope.
    pub coverage_digest: String,
    /// Envelope digest echoed from the admission receipt.
    pub receipt_digest: String,
}

impl ProviderContribution {
    /// Contribute the admitted position.
    ///
    /// Rejects superseded positions and runs the position's closed
    /// validation first, so completeness is derived from the governing
    /// records, not claimed by the caller.
    pub fn contribute(position: &CurrentEpistemicPosition) -> Result<Self, ContractError> {
        if position.currentness != Currentness::Current {
            return Err(ContractError::ImpossibleCombination {
                field: "contribution.currentness",
            });
        }
        position.validate()?;
        let contribution = Self {
            contract_version: crate::CONTRACT_VERSION,
            view_kind: AdmittedKind::CurrentEpistemicPosition,
            position_digest: position.digest.clone(),
            claim: position.claim.clone(),
            owner: position.admission.owner.clone(),
            currentness: Currentness::Current,
            position: position.admission.position.clone(),
            position_revision: position.admission.position_revision,
            scope: position.admission.scope.clone(),
            fence: position.admission.fence.clone(),
            source_revision: position.admission.revision.clone(),
            coverage_digest: position.admission.coverage_digest.clone(),
            receipt_digest: position.receipt_identity().to_owned(),
        };
        contribution.validate()?;
        Ok(contribution)
    }

    /// Validate version, marker, currentness, digest shapes, text bounds,
    /// and fence shape.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(ContractError::ImpossibleCombination {
                field: "contribution.contract_version",
            });
        }
        if self.view_kind != AdmittedKind::CurrentEpistemicPosition {
            return Err(ContractError::ImpossibleCombination {
                field: "contribution.view_kind",
            });
        }
        if self.currentness != Currentness::Current {
            return Err(ContractError::ImpossibleCombination {
                field: "contribution.currentness",
            });
        }
        validate_digest(&self.position_digest, "contribution.position_digest")?;
        validate_bounded_text(&self.scope, "contribution.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "contribution.fence",
            })?;
        validate_bounded_text(
            &self.source_revision,
            "contribution.source_revision",
            MAX_SHORT_TEXT,
        )?;
        validate_digest(&self.coverage_digest, "contribution.coverage_digest")?;
        validate_digest(&self.receipt_digest, "contribution.receipt_digest")?;
        Ok(())
    }
}
