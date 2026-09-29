//! The live publication grant that stands between a build candidate and the
//! pure evaluator.
//!
//! `I12.15` step 1 admits a build candidate as *proposed* index material, never
//! as a live publication. A self-consistent candidate proves only that its own
//! recorded digest matches its own content; it says nothing about whether the
//! publication that would carry it is still current, still unrevoked, or still
//! built under the normalization and relation-registry revisions this request
//! is issued against.
//!
//! This module owns that resolution so the pure evaluator does not have to. The
//! caller resolves one [`PublicationGrant`] from owner-produced evidence and
//! hands it to [`crate::evaluate_published_activation`]. Three properties are
//! deliberate:
//!
//! - A grant is refused unless the candidate is an explicitly self-closed
//!   published snapshot. An open compatibility candidate is never promoted into
//!   a grant by being well formed.
//! - Every binding is *compared* with this operation's content: the scope,
//!   fence, normalization profile and relation-registry revision recorded in the
//!   publication are checked against the ones the caller resolved, not merely
//!   observed to exist.
//! - The two coverage domains stay apart. A limited direct read is an explicit
//!   limitation, never a silent `Complete`; optional relation coverage is
//!   never substituted for a direct grant, and a direct grant is never
//!   withdrawn because relation evidence is absent.

use eliot_contracts::StateFence;
use eliot_cue_contracts::{
    ActivationRequest, CueContractError, CueSnapshotBuildCandidate, NormalizationProfile,
    RelationEdge, SnapshotId, SnapshotInvalidation, WorkScopeId,
};
use serde::{Deserialize, Serialize};

use crate::error::ActivationError;

/// Bounded text ceiling for one owner-supplied disclosure or registry handle.
const MAX_HANDLE_BYTES: usize = 256;
/// Hard ceiling on the number of invalidation records one grant may consider.
const MAX_INVALIDATIONS: usize = 64;

/// The current disclosure and influence state a grant is resolved under.
///
/// This is a pointer to owner state, not a claim: the caller supplies the exact
/// handles its own owners resolved, and the grant binds them so a later result
/// cannot be read as if it ran under different disclosure or influence state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DisclosureInfluenceState {
    /// Disclosure handle resolved by the disclosure owner for this operation.
    pub disclosure_handle: String,
    /// Influence handle resolved by the influence owner for this operation.
    pub influence_handle: String,
}

impl DisclosureInfluenceState {
    /// Binds two owner-resolved handles.
    ///
    /// # Errors
    /// Rejects an empty, control-bearing or over-long handle in either
    /// position. This is a shape check on caller-supplied text, not an
    /// authority decision.
    pub fn new(
        disclosure_handle: String,
        influence_handle: String,
    ) -> Result<Self, ActivationError> {
        check_handle(&disclosure_handle, "publication.disclosure_handle")?;
        check_handle(&influence_handle, "publication.influence_handle")?;
        Ok(Self {
            disclosure_handle,
            influence_handle,
        })
    }
}

/// Why the direct read is explicitly limited rather than answered.
///
/// Every variant names a direct-domain comparison that failed. None of them
/// states that optional relation coverage is missing, and none of them claims
/// the direct snapshot is absent: a limited direct read is an unknown or stale
/// direct answer, which is a different claim from "searched and found nothing".
///
/// A candidate that is not a self-closed publication, and a publication an
/// invalidation names, are not limited reads: both are refused outright by
/// [`PublicationGrant::resolve`] as [`ActivationError::StaleInput`] or a
/// contract error, because there is no publication to limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum DirectReadLimit {
    /// The publication's own scope does not match the scope this operation is
    /// admitted in.
    ScopeMismatch,
    /// The publication was built under an earlier causal fence.
    FenceMoved,
    /// The publication was built under a different normalization revision.
    NormalizationChanged,
    /// At least one published relation edge carries a relation-registry
    /// revision other than the one this operation resolved.
    RegistryChanged,
}

/// One direct-domain binding whose comparison against this operation failed.
///
/// A limitation is a named comparison, never an absence of comparison: each
/// entry records what was compared and which way it failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DirectReadLimitation {
    /// The direct-domain cause.
    pub limit: DirectReadLimit,
    /// Bounded text naming the exact binding that was compared.
    pub binding: String,
}

/// An immutable, validated live-publication grant for one activation request.
///
/// The grant carries the exact publication, fence, scope, normalization and
/// registry identity it was resolved from, so a result computed under it can
/// name what it was authorized against. Constructing a grant is the caller's
/// composition act; nothing here acquires, starts or rebuilds an owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PublicationGrant {
    /// Exact published candidate this grant authorizes.
    pub candidate: CueSnapshotBuildCandidate,
    /// The scope the publication grant was issued under.
    pub scope_id: WorkScopeId,
    /// The causal fence the publication was issued against.
    pub state_fence: StateFence,
    /// Normalization revision the publication was built under.
    pub normalization_profile: NormalizationProfile,
    /// Relation-registry revision this operation resolved.
    pub registry_revision: String,
    /// Disclosure and influence state the grant was resolved under.
    pub disclosure: DisclosureInfluenceState,
    /// Explicit direct-read limitation, when the direct domain cannot be
    /// answered as published. `None` means the direct read is granted.
    pub direct_limit: Option<DirectReadLimit>,
    /// Every direct-domain binding this grant could not admit, in a fixed
    /// order. A granted direct read carries no entries.
    pub direct_limitations: Vec<DirectReadLimitation>,
}

impl PublicationGrant {
    /// Resolves the live publication this request is authorized to read.
    ///
    /// Resolution is closed over the supplied evidence. It refuses a candidate
    /// that is not an explicitly self-closed publication, refuses a publication
    /// an invalidation names, and otherwise records every direct-domain binding
    /// whose recorded value differs from the one this operation resolved.
    /// Optional relation coverage is never consulted to grant the direct
    /// domain, so a direct-only request never requires relation material.
    ///
    /// # Errors
    /// Refuses an over-long invalidation set or owner handle, an invalidation
    /// set this owner cannot validate, and a candidate that is not an
    /// explicitly self-closed publication. A retired publication is reported as
    /// [`ActivationError::StaleInput`], never as an absent snapshot.
    pub fn resolve(
        candidate: CueSnapshotBuildCandidate,
        scope_id: WorkScopeId,
        state_fence: StateFence,
        normalization_profile: NormalizationProfile,
        registry_revision: String,
        disclosure: DisclosureInfluenceState,
        invalidations: &[SnapshotInvalidation],
    ) -> Result<Self, ActivationError> {
        check_handle(&registry_revision, "publication.registry_revision")?;
        if invalidations.len() > MAX_INVALIDATIONS {
            return Err(ActivationError::Limit {
                field: "publication.invalidations",
            });
        }
        for invalidation in invalidations {
            invalidation.validate()?;
        }
        // A build candidate is not a publication grant, however well formed.
        candidate.validate_published()?;
        if retires(&candidate.snapshot.snapshot_id, invalidations) {
            return Err(ActivationError::StaleInput);
        }
        let direct_limitations = compare_bindings(
            &candidate,
            &scope_id,
            &state_fence,
            &normalization_profile,
            &registry_revision,
        );
        let direct_limit = direct_limitations.first().map(|entry| entry.limit);
        Ok(Self {
            candidate,
            scope_id,
            state_fence,
            normalization_profile,
            registry_revision,
            disclosure,
            direct_limit,
            direct_limitations,
        })
    }

    /// Whether this grant carries a complete direct read.
    #[must_use]
    pub const fn is_direct_granted(&self) -> bool {
        self.direct_limit.is_none()
    }

    /// Whether this grant authorizes exactly the supplied request.
    ///
    /// The request is compared against the grant's own bound identity. A
    /// request issued against a different snapshot, fence or scope is a
    /// different operation and is refused rather than evaluated under a grant
    /// that was never issued for it.
    ///
    /// # Errors
    /// Refuses a request whose snapshot, fence or scope differs from the grant.
    pub fn validate_for(
        &self,
        request: &ActivationRequest,
        scope_id: &WorkScopeId,
    ) -> Result<(), ActivationError> {
        if request.snapshot_id != self.candidate.snapshot.snapshot_id
            || request.state_fence != self.state_fence
            || &self.scope_id != scope_id
            || request.normalization_profile != self.normalization_profile
        {
            return Err(ActivationError::ProfileBinding);
        }
        Ok(())
    }
}

/// Whether a recorded invalidation retires exactly this publication.
///
/// Only an invalidation naming this snapshot is evidence about it. An
/// invalidation about some other snapshot is unrelated and is never reused as
/// this operation's revocation.
fn retires(snapshot_id: &SnapshotId, invalidations: &[SnapshotInvalidation]) -> bool {
    invalidations
        .iter()
        .any(|invalidation| &invalidation.snapshot_id == snapshot_id)
}

/// Compares every direct-domain binding of the publication against the
/// identity this operation resolved, recording each mismatch.
///
/// The order is fixed so the same publication and the same resolved identity
/// always produce the same limitation list.
fn compare_bindings(
    candidate: &CueSnapshotBuildCandidate,
    scope_id: &WorkScopeId,
    state_fence: &StateFence,
    normalization_profile: &NormalizationProfile,
    registry_revision: &str,
) -> Vec<DirectReadLimitation> {
    let mut limitations = Vec::new();
    if &candidate.scope_id != scope_id {
        limitations.push(limitation(
            DirectReadLimit::ScopeMismatch,
            "publication.scope",
        ));
    }
    if &candidate.snapshot.state_fence != state_fence {
        limitations.push(limitation(
            DirectReadLimit::FenceMoved,
            "publication.state_fence",
        ));
    }
    if &candidate.snapshot.rebuild.normalization_profile != normalization_profile {
        limitations.push(limitation(
            DirectReadLimit::NormalizationChanged,
            "publication.normalization_profile",
        ));
    }
    for edge in &candidate.relation_edges {
        if edge.registry_revision != registry_revision
            && !limitations
                .iter()
                .any(|entry| entry.limit == DirectReadLimit::RegistryChanged)
        {
            limitations.push(relation_limitation(edge));
        }
    }
    limitations
}

/// One named registry mismatch against a published edge's own recorded
/// revision.
fn relation_limitation(edge: &RelationEdge) -> DirectReadLimitation {
    DirectReadLimitation {
        limit: DirectReadLimit::RegistryChanged,
        binding: edge.relation_edge_id.as_str().to_owned(),
    }
}

/// Records one named mismatch.
fn limitation(limit: DirectReadLimit, binding: &'static str) -> DirectReadLimitation {
    DirectReadLimitation {
        limit,
        binding: binding.to_owned(),
    }
}

/// Rejects an empty, control-bearing or over-long owner handle.
fn check_handle(value: &str, field: &'static str) -> Result<(), ActivationError> {
    if value.trim().is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(map_text(value, field));
    }
    Ok(())
}

/// Maps a rejected handle onto the contract's own bounded-text error.
fn map_text(value: &str, field: &'static str) -> ActivationError {
    if value.len() > MAX_HANDLE_BYTES {
        return ActivationError::Contract(CueContractError::BoundExceeded {
            field,
            limit: MAX_HANDLE_BYTES,
        });
    }
    ActivationError::Contract(CueContractError::InvalidText { field })
}
