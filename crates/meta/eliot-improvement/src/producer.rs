//! Owner-bound learning candidate producer (#1869).
//!
//! Turns a closed, backlog-active reusable candidate plus an owner-verified
//! permit into a learning-marked [`ContextCandidate`]. Owner-bound by
//! construction:
//!
//! - The function takes `&VerifiedLearningAdmission`, which only the
//!   Governor owner flow yields (`issue` + `verify` in
//!   `eliot-governor::learning_admission`). Without a live owner issuance
//!   there is no call.
//! - The candidate must resolve to an ACTIVE [`BoundedBacklog`] entry:
//!   `admit`/`admit_governed` grants production eligibility and `archive`
//!   revokes it, so stale/ownerless/low-value backlog exits cannot be
//!   re-emitted.
//! - Campaign origin, target task, exact fence, overlay/candidate subject,
//!   and cited issuance digest must equal the permit-bound values; closure
//!   and owner must be present. The emitted mark is covered by the atom
//!   canonical digest, so downstream screens and measurements bind it.
//! - Drafts are never produced: this producer emits only admitted local
//!   updates for a compatible attempt, never speculative deltas.
//!
//! The embedded `expires_at_unix_secs` is enforced downstream against the
//! owner/host clock by the governed screens; the producer never decides
//! liveness itself.

use blake3::Hasher;
use eliot_context_contracts::{
    AtomRepresentation, AuthorityClass, ContextBinding, ContextCandidate, LearningProvenance,
    LossPolicy, MeasurementRef, PrivacyClass, ProviderRole, SourceSnapshot,
};
use eliot_contracts::fences_match_exact;
use eliot_evidence::EpistemicStatus;
use eliot_governor::VerifiedLearningAdmission;

use crate::candidate_bounds::{BoundedBacklog, BoundsError};

/// Inputs for producing one learning-marked atom.
///
/// `binding` is the compilation identity the atom is produced for (built by
/// the compiling context); the producer verifies its task and fence against
/// the verified permit rather than trusting them. Source/provider/measure
/// fields are caller-supplied lineage carried verbatim and validated for
/// shape; their authority comes from the verified permit, never from the
/// strings themselves.
pub struct LearningProduction<'a> {
    pub backlog: &'a BoundedBacklog,
    pub candidate_id: &'a str,
    pub closure_ref: &'a str,
    pub owner: &'a str,
    pub binding: &'a ContextBinding,
    pub atom_id: &'a str,
    pub provider_role: &'a ProviderRole,
    pub source_id: &'a str,
    pub source_owner: &'a str,
    pub snapshot_id: &'a str,
    pub source_revision: &'a str,
    pub content: &'a str,
    pub overlay_id: Option<&'a str>,
    pub expires_at_unix_secs: Option<u64>,
    pub measurement_digest: &'a str,
    pub measurement_serializer: &'a str,
    pub verified: &'a VerifiedLearningAdmission<'a>,
}

/// Produce one learning-marked candidate bound to an owner-verified permit.
///
/// Refuses archived/unknown backlog entries, permit-subject mismatches,
/// unclosed or ownerless reusables, task/fence drift, and malformed
/// production identity before emitting anything.
pub fn produce_learning_candidate(
    request: LearningProduction<'_>,
) -> Result<ContextCandidate, BoundsError> {
    let permit = request.verified.permit();
    // Registry proof: only an ACTIVE backlog entry admitted under the
    // permit-bound Governor authority may be (re)produced, and the
    // presented owner and source must equal those retained identities —
    // never arbitrary caller labels.
    let retained = request
        .backlog
        .entry_for(request.candidate_id)
        .ok_or(BoundsError::NotBacklogAdmitted)?;
    if retained.admitted_under_authority.as_deref() != Some(permit.authority_ref()) {
        return Err(BoundsError::GovernorAuthorityUnconfirmed);
    }
    let retained_owner = retained
        .owner
        .as_deref()
        .ok_or(BoundsError::OwnerlessRecord)?;
    if request.owner.trim() != retained_owner {
        return Err(BoundsError::GovernorAuthorityUnconfirmed);
    }
    if request.source_owner.trim() != permit.authority_ref() {
        return Err(BoundsError::GovernorAuthorityUnconfirmed);
    }
    // Subject proof: the permit must bind this exact reusable candidate.
    if Some(request.candidate_id) != permit.candidate_id() {
        return Err(BoundsError::ReusableBackingMismatch);
    }
    // Closure proof: reusables must be closed and owned.
    if request.closure_ref.trim().is_empty() {
        return Err(BoundsError::UnclosedReusable);
    }
    if request.owner.trim().is_empty() {
        return Err(BoundsError::OwnerlessRecord);
    }
    // Task/fence proof: the compilation identity must be the admitted one.
    if request.binding.task_id.as_str() != permit.target_task_id() {
        return Err(BoundsError::CrossTaskAdmissionMismatch);
    }
    if !fences_match_exact(&request.binding.state_fence, permit.fence()) {
        return Err(BoundsError::StaleStateFence);
    }
    // Overlay proof: the bound overlay subject must match when bound.
    match (request.overlay_id, permit.overlay_id()) {
        (Some(claimed), Some(bound)) if claimed == bound => {}
        (None, None) => {}
        _ => return Err(BoundsError::OverlayBackingMismatch),
    }
    if request.content.trim().is_empty() {
        return Err(BoundsError::MissingField("learning.content"));
    }
    let atom_id = eliot_contracts::ArtifactId::new(request.atom_id)
        .map_err(|_| BoundsError::InvalidProduction("learning.atom_id"))?;
    let source_id = eliot_contracts::SourceId::new(request.source_id)
        .map_err(|_| BoundsError::InvalidProduction("learning.source_id"))?;
    let source_owner = eliot_context_contracts::ProviderId::new(request.source_owner)
        .map_err(|_| BoundsError::InvalidProduction("learning.source_owner"))?;
    let snapshot_id = eliot_contracts::ArtifactId::new(request.snapshot_id)
        .map_err(|_| BoundsError::InvalidProduction("learning.snapshot_id"))?;
    if request.source_revision.trim().is_empty() {
        return Err(BoundsError::MissingField("learning.source_revision"));
    }
    if request.measurement_digest.trim().is_empty() {
        return Err(BoundsError::MissingField("learning.measurement_digest"));
    }
    if request.measurement_serializer.trim().is_empty() {
        return Err(BoundsError::MissingField("learning.measurement_serializer"));
    }
    let mut content_hasher = Hasher::new();
    content_hasher.update(request.content.as_bytes());
    let candidate = ContextCandidate {
        binding: request.binding.clone(),
        atom_id,
        provider_role: request.provider_role.clone(),
        source: SourceSnapshot {
            source_id,
            owner: source_owner,
            snapshot_id,
            revision: request.source_revision.to_string(),
            content_sha256: content_hasher.finalize().to_hex().to_string(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: request.content.to_string(),
        },
        learning: Some(LearningProvenance {
            campaign_id: permit.source_campaign_id().to_string(),
            overlay_id: request.overlay_id.map(str::to_string),
            candidate_id: Some(request.candidate_id.to_string()),
            closure_ref: Some(request.closure_ref.to_string()),
            owner: Some(request.owner.to_string()),
            draft: false,
            expires_at_unix_secs: request.expires_at_unix_secs,
            permit_digest: permit.digest().to_string(),
        }),
        loss_policy: LossPolicy::Summarizable,
        availability: eliot_context_contracts::AtomAvailability::PresentCurrent,
        protected: false,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: eliot_evidence::Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: request.measurement_digest.to_string(),
            serializer: request.measurement_serializer.to_string(),
        },
        dependencies: Vec::new(),
        proof: eliot_context_contracts::ProofBinding {
            evidence_id: eliot_contracts::ArtifactId::new(request.atom_id)
                .map_err(|_| BoundsError::InvalidProduction("learning.atom_id"))?,
            ceiling: eliot_receipts::ProofCeiling::Observation,
        },
    };
    request
        .provider_role
        .validate()
        .map_err(|_| BoundsError::InvalidProduction("learning.provider_role"))?;
    candidate
        .validate()
        .map_err(|_| BoundsError::InvalidProduction("learning.candidate"))?;
    Ok(candidate)
}
