#![forbid(unsafe_code)]

//! Typed Product Pulse projection for the native Curation screen edge.
//!
//! The Pulse is deliberately a candidate-only observation.  It carries the
//! exact native screen payload and the route identities used to produce it,
//! but it does not contain an execution authorization, a semantic kind, or a
//! source mutation.  The legacy A-31 test carrier may still return a curation
//! result without a Pulse; the real current-daemon source route always sets
//! `screen_result` and the cycle digests.

use eliot_contracts::{PolicyRevision, StateFence};
use eliot_memory_curation_contracts::{
    CurationFinding, CurationScreenResult, Digest, FiniteDenominator, ProfileId,
    ProtectionAssessment, ResultState, SourceIdentity,
};
use serde::{Deserialize, Serialize};

/// Proof ceiling for a screen result that has not crossed an owner/verifier
/// boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "candidate-only")]
pub enum CurationProofCeiling {
    /// A deterministic screen observation and reversible candidate record only.
    CandidateOnly,
}

/// The typed Product Pulse attached to the native Curation result.
///
/// `screen_result` is optional only for the historical A-31 test carrier,
/// which has no native screen payload.  The production current-daemon route
/// always carries `Some`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurationProductPulse {
    /// Stable route identity for this consumer edge.
    pub route_id: String,
    /// Exact immutable source identity screened by the native owner.
    pub source: SourceIdentity,
    /// Exact native screen profile identity.
    pub policy_id: ProfileId,
    /// Exact native screen policy revision.
    pub policy_revision: PolicyRevision,
    /// Fence used by both source and request binding.
    pub state_fence: StateFence,
    /// Native result disposition, never promoted to semantic success.
    pub disposition: ResultState,
    /// Finite denominator copied from the native result.
    pub denominator: FiniteDenominator,
    /// Structural findings copied from the native result.
    pub findings: Vec<CurationFinding>,
    /// Protection assessments copied from the native result.
    pub protection: Vec<ProtectionAssessment>,
    /// Explicit omissions, including unavailable owner evidence and source
    /// content that the bounded carrier did not load.
    pub omissions: Vec<String>,
    /// Candidate-only proof ceiling.
    pub proof_ceiling: CurationProofCeiling,
    /// Digest of the complete native screen result.
    pub result_digest: Digest,
    /// Coverage digest of the frozen cycle sample.
    pub cycle_sample_digest: String,
    /// Digest of the one-cycle inert plan.
    pub cycle_plan_digest: String,
    /// Full native screen payload, when this is the production screen route.
    #[serde(default)]
    pub screen_result: Option<CurationScreenResult>,
}

impl CurationProductPulse {
    /// Projects the native screen result and frozen cycle digests into the
    /// public Product Pulse shape.  The caller supplies the carrier's
    /// explicit omission list; the screen frontier is appended without
    /// dropping any identity.
    pub(crate) fn from_native(
        result: &CurationScreenResult,
        omissions: &[String],
        cycle_sample_digest: &str,
        cycle_plan_digest: &str,
    ) -> Self {
        let mut all_omissions = omissions.to_vec();
        all_omissions.extend(
            result
                .coverage
                .frontier
                .remaining
                .iter()
                .map(|member| format!("screen_frontier:{}", member.as_str())),
        );
        all_omissions.sort();
        all_omissions.dedup();
        Self {
            route_id: crate::CURATION_PRODUCT_ROUTE_ID.to_owned(),
            source: result.source.identity.clone(),
            policy_id: result.request.profile.profile_id.clone(),
            policy_revision: result.request.profile.policy_revision,
            state_fence: result.request.binding.state_fence.clone(),
            disposition: result.state,
            denominator: result.coverage.denominator.clone(),
            findings: result.findings.clone(),
            protection: result.protection.clone(),
            omissions: all_omissions,
            proof_ceiling: CurationProofCeiling::CandidateOnly,
            result_digest: result.result_digest.clone(),
            cycle_sample_digest: cycle_sample_digest.to_owned(),
            cycle_plan_digest: cycle_plan_digest.to_owned(),
            screen_result: Some(result.clone()),
        }
    }
}
