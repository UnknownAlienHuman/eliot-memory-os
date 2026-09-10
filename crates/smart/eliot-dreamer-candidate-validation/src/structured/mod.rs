//! Pure A-05 semantic validation for the A-14b structured grounding handoff.
//!
//! A03 owns the lossless carrier and its intrinsic owner joins. This module
//! owns the pre-handler semantic gate and the v2 receipt adapter. It performs
//! no grounding, source lookup, handler execution, Curation postflight, or
//! authority promotion.

#![forbid(unsafe_code)]

mod bounds;
mod receipt;
mod validate;

use eliot_dreamer_contracts::validation::DreamDraftValidationError;
use eliot_dreamer_contracts::validation::MAX_CANONICAL_BYTES;
use eliot_dreamer_contracts::validation::structured::GroundingValidationInput;
use serde::{Deserialize, Serialize};

use crate::RejectionCode;

/// Complete structured input retained when the v2 semantic gate rejects a
/// well-formed carrier. The original grounding, ledger, manifest, policy,
/// usage, preservation report, and optional rival declaration remain intact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredCandidateRejectionReport {
    /// Full supplied A-14b/A-05 carrier, retained without normalization.
    pub input: GroundingValidationInput,
    /// Stable semantic rejection class.
    pub code: RejectionCode,
    /// Bounded static diagnostic; it carries no authority claim.
    pub detail: String,
    /// Receipt-excluded digest of the complete structured input.
    pub input_digest: String,
}

/// Result of one structured A-05 pre-handler validation call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StructuredCandidateValidationOutcome {
    /// The retained grounding passed the common gate and receipt binding.
    Accepted(Box<eliot_dreamer_contracts::validation::structured::ValidatedGroundingCandidate>),
    /// A semantically rejected carrier retained all supplied evidence.
    Rejected(Box<StructuredCandidateRejectionReport>),
}

/// Validates one complete A-14b structured grounding handoff before any
/// typed Dreamer handler runs.
///
/// A03 intrinsic failures are returned as typed contract errors. Semantic
/// failures are returned as inert retained reports. The Curation handler's
/// typed request/result is deliberately outside this common pre-handler API;
/// its separate post-handler carrier remains a later owner concern.
pub fn validate_grounding_candidate_at(
    input: &GroundingValidationInput,
) -> Result<StructuredCandidateValidationOutcome, DreamDraftValidationError> {
    bounds::stream_size(input, "structured.input", MAX_CANONICAL_BYTES)?;
    validate::validate_shallow_shape(input)?;
    validate::validate_owner_shape(input)?;

    if let Some((code, detail)) = validate::validate_identity(input) {
        return reject_with_digest(input, code, detail);
    }
    if let Some((code, detail)) = validate::validate_unsafe_ceilings(input) {
        return reject_with_digest(input, code, detail);
    }
    input.grounded.validate().map_err(|error| {
        eliot_dreamer_contracts::validation::error::summarize_contract("grounded", &error)
    })?;
    let (input_digest, input_bytes) = input.input_digest_and_size()?;
    if let Some((code, detail)) = validate::validate_lineage(input) {
        return validate::reject(input, code, detail, input_digest);
    }
    if let Some((code, detail)) = validate::validate_budget_deadline(input, input_bytes) {
        return validate::reject(input, code, detail, input_digest);
    }
    input.validate()?;
    if let Some(detail) = validate::validate_preservation_evidence(input) {
        return validate::reject(
            input,
            RejectionCode::PreservationFailed,
            detail,
            input_digest,
        );
    }
    if let Some((code, detail)) = validate::validate_family(input) {
        return validate::reject(input, code, detail, input_digest);
    }
    validate::assemble_accepted(input, input_digest)
}

fn reject_with_digest(
    input: &GroundingValidationInput,
    code: RejectionCode,
    detail: &'static str,
) -> Result<StructuredCandidateValidationOutcome, DreamDraftValidationError> {
    let (input_digest, _) = input.input_digest_and_size()?;
    validate::reject(input, code, detail, input_digest)
}
