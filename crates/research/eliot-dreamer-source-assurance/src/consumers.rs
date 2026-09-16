//! Dreamer and Governor consumer adapters.
//!
//! Both adapters preserve the complete assurance envelope. The Dreamer
//! envelope binds the immutable result to its exact evidence set: coverage
//! cannot be broadened and dissent cannot be stripped without breaking
//! re-verification. The Governor adapter emits candidate and evidence
//! metadata only; permitted influence is decided by the Governor through its
//! normal admission path, never here.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assess::{AssuranceResult, Completeness, SupportCeiling, assess};
use crate::digest_json;
use crate::error::RoleSeparationError;
use crate::portfolio::FrozenEvidenceSet;

/// Immutable envelope handed to Dreamer consumers.
///
/// The envelope carries the complete assurance result together with the exact
/// frozen evidence set it was computed from. Adapters offer no operation that
/// widens coverage, drops a blind boundary, or removes a contradiction: any
/// such mutation breaks [`verify_dreamer_envelope`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DreamerEnvelope {
    /// The complete assurance result.
    pub result: AssuranceResult,
    /// The exact frozen evidence set the result was computed from.
    pub evidence: FrozenEvidenceSet,
    /// Digest binding the result digest to the evidence-set digest.
    pub envelope_digest: String,
}

/// Candidate and evidence metadata handed to the Governor.
///
/// This is admission input, not an admission decision: it carries identities,
/// completeness, per-claim ceilings, and a contradiction flag. It expresses
/// no permitted influence, no authority, and no completion state; the
/// Governor decides influence through its normal admission path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernorCandidateMetadata {
    /// Frozen set identity.
    pub set_id: String,
    /// Frozen set revision.
    pub revision: String,
    /// Digest of the frozen input.
    pub set_digest: String,
    /// Digest of the assurance result.
    pub result_digest: String,
    /// Completeness of the assurance result.
    pub completeness: Completeness,
    /// Per-claim support ceilings, ordered by claim.
    pub ceilings: Vec<SupportCeiling>,
    /// Whether any claim carries both support and contradiction.
    pub contradiction_present: bool,
}

/// Bind an assurance result to its exact evidence set for Dreamer.
///
/// Fails when the result was not computed from this exact evidence: the
/// envelope never silently pairs a result with foreign evidence.
pub fn dreamer_envelope(
    result: &AssuranceResult,
    evidence: &FrozenEvidenceSet,
) -> Result<DreamerEnvelope, RoleSeparationError> {
    evidence.verify_digest()?;
    if result.set_digest != evidence.set_digest {
        return Err(RoleSeparationError::EnvelopeBindingMismatch);
    }
    let recomputed = assess(evidence)?;
    if recomputed.ne(result) {
        return Err(RoleSeparationError::EnvelopeBindingMismatch);
    }
    let envelope_digest = digest_json(&EnvelopeDigestMaterial {
        result_digest: &result.result_digest,
        set_digest: &evidence.set_digest,
    })?;
    Ok(DreamerEnvelope {
        result: result.clone(),
        evidence: evidence.clone(),
        envelope_digest,
    })
}

/// Re-verify a Dreamer envelope against its embedded evidence.
///
/// Recomputes the evidence digest, the assessment, and the envelope binding.
/// A broadened coverage, a stripped contradiction or blind boundary, or any
/// other post-freeze mutation fails here instead of reaching a consumer.
pub fn verify_dreamer_envelope(envelope: &DreamerEnvelope) -> Result<(), RoleSeparationError> {
    envelope.evidence.verify_digest()?;
    if envelope.result.set_digest != envelope.evidence.set_digest {
        return Err(RoleSeparationError::EnvelopeVerificationFailed);
    }
    let recomputed = assess(&envelope.evidence)?;
    if recomputed.ne(&envelope.result) {
        return Err(RoleSeparationError::EnvelopeVerificationFailed);
    }
    let expected = digest_json(&EnvelopeDigestMaterial {
        result_digest: &envelope.result.result_digest,
        set_digest: &envelope.evidence.set_digest,
    })?;
    if expected != envelope.envelope_digest {
        return Err(RoleSeparationError::EnvelopeVerificationFailed);
    }
    Ok(())
}

/// Project an assurance result to Governor candidate metadata.
///
/// The projection copies identities, completeness, ceilings, and the
/// contradiction flag. It adds nothing and decides nothing: influence stays
/// with the Governor admission path.
pub fn governor_candidate(result: &AssuranceResult) -> GovernorCandidateMetadata {
    GovernorCandidateMetadata {
        set_id: result.set_id.clone(),
        revision: result.revision.clone(),
        set_digest: result.set_digest.clone(),
        result_digest: result.result_digest.clone(),
        completeness: result.completeness.clone(),
        ceilings: result.ceilings.clone(),
        contradiction_present: result.ceilings.iter().any(|ceiling| {
            !ceiling.supporting_roots.is_empty() && !ceiling.contradicting_roots.is_empty()
        }),
    }
}

#[derive(Serialize)]
struct EnvelopeDigestMaterial<'a> {
    result_digest: &'a str,
    set_digest: &'a str,
}
