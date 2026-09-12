use eliot_conformance_contracts::{
    CapabilitySupportRow, ContractMaturity, EvidenceDomain, EvidenceExecutionStatus,
    ImplementationSupport, SupportObservationState,
};
use serde::{Deserialize, Serialize};

use crate::{
    ImplementationBriefError,
    validation::{
        MAX_ID_BYTES, MAX_TEXT_BYTES, canonical_digest, check_digest, check_id, check_text,
        sorted_unique_strings,
    },
};

/// Independent proof stage. No stage implies any later stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStage {
    Source,
    Compile,
    Unit,
    Property,
    Package,
    Integration,
    Edge,
    Runtime,
    Product,
    Release,
}

impl ProofStage {
    /// Number of closed proof-stage variants.
    pub const COUNT: usize = 10;
}

/// Observation/evaluation result retained separately from support axes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerdict {
    Passed,
    Failed,
    Partial,
    Skipped,
    Simulated,
    Missing,
    Unavailable,
    Unknown,
    Conflicted,
    NotApplicable,
}

/// Exact build/runtime target to which an evidence record applies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentEvidenceTarget {
    pub source_tree_digest: String,
    pub artifact_digest: Option<String>,
    pub configuration_digest: Option<String>,
    pub platform: String,
    pub toolchain: String,
    pub features: Vec<String>,
    pub environment_digest: String,
    pub observation_window_ref: String,
    pub target_digest: String,
}

#[derive(Serialize)]
struct TargetDigestPreimage<'a> {
    source_tree_digest: &'a str,
    artifact_digest: &'a Option<String>,
    configuration_digest: &'a Option<String>,
    platform: &'a str,
    toolchain: &'a str,
    features: &'a [String],
    environment_digest: &'a str,
    observation_window_ref: &'a str,
}

impl CurrentEvidenceTarget {
    fn digest_preimage(&self) -> TargetDigestPreimage<'_> {
        TargetDigestPreimage {
            source_tree_digest: &self.source_tree_digest,
            artifact_digest: &self.artifact_digest,
            configuration_digest: &self.configuration_digest,
            platform: &self.platform,
            toolchain: &self.toolchain,
            features: &self.features,
            environment_digest: &self.environment_digest,
            observation_window_ref: &self.observation_window_ref,
        }
    }

    /// Canonicalizes features and seals the target identity.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        self.features = sorted_unique_strings(&self.features, "evidence.target.features")?;
        self.target_digest =
            canonical_digest(&self.digest_preimage(), "evidence.target.target_digest")?;
        self.validate()
    }

    /// Validates exact source/artifact/configuration/environment binding.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        check_digest(
            &self.source_tree_digest,
            "evidence.target.source_tree_digest",
        )?;
        if let Some(value) = &self.artifact_digest {
            check_digest(value, "evidence.target.artifact_digest")?;
        }
        if let Some(value) = &self.configuration_digest {
            check_digest(value, "evidence.target.configuration_digest")?;
        }
        check_text(&self.platform, "evidence.target.platform", MAX_ID_BYTES)?;
        check_text(
            &self.toolchain,
            "evidence.target.toolchain",
            MAX_ID_BYTES,
        )?;
        let features = sorted_unique_strings(&self.features, "evidence.target.features")?;
        if features != self.features {
            return Err(ImplementationBriefError::Invalid {
                field: "evidence.target.features",
                reason: "collection is not in canonical order",
            });
        }
        check_digest(
            &self.environment_digest,
            "evidence.target.environment_digest",
        )?;
        check_text(
            &self.observation_window_ref,
            "evidence.target.observation_window_ref",
            MAX_ID_BYTES,
        )?;
        check_digest(&self.target_digest, "evidence.target.target_digest")?;
        if self.target_digest
            != canonical_digest(&self.digest_preimage(), "evidence.target.target_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "evidence.target.target_digest",
            });
        }
        Ok(())
    }
}

/// One evidence-to-mechanism/obligation/stage join.
///
/// The owner-neutral support row remains in `ConformanceContractSet`; this
/// record binds it to the Implementation denominator without duplicating the
/// support vocabulary. `expected_target_digest` is the admitted target identity
/// against which the observed target is evaluated; it is not recomputed from
/// the observation after the fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationEvidence {
    pub schema_version: u32,
    pub evidence_id: String,
    pub mechanism_id: String,
    pub obligation_id: String,
    pub stage: ProofStage,
    pub support_claim_ref: String,
    pub target: CurrentEvidenceTarget,
    pub expected_target_digest: String,
    pub verdict: EvidenceVerdict,
    pub detail: String,
    pub evidence_digest: String,
}

#[derive(Serialize)]
struct EvidenceDigestPreimage<'a> {
    schema_version: u32,
    evidence_id: &'a str,
    mechanism_id: &'a str,
    obligation_id: &'a str,
    stage: ProofStage,
    support_claim_ref: &'a str,
    target: &'a CurrentEvidenceTarget,
    expected_target_digest: &'a str,
    verdict: EvidenceVerdict,
    detail: &'a str,
}

impl ImplementationEvidence {
    fn digest_preimage(&self) -> EvidenceDigestPreimage<'_> {
        EvidenceDigestPreimage {
            schema_version: self.schema_version,
            evidence_id: &self.evidence_id,
            mechanism_id: &self.mechanism_id,
            obligation_id: &self.obligation_id,
            stage: self.stage,
            support_claim_ref: &self.support_claim_ref,
            target: &self.target,
            expected_target_digest: &self.expected_target_digest,
            verdict: self.verdict,
            detail: &self.detail,
        }
    }

    /// Seals target and record identities.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        self.target.seal()?;
        self.evidence_digest =
            canonical_digest(&self.digest_preimage(), "evidence.evidence_digest")?;
        self.validate()
    }

    /// Validates the evidence join independent of the referenced support row.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "evidence.schema_version",
                reason: "unsupported schema version",
            });
        }
        check_id(&self.evidence_id, "evidence.evidence_id")?;
        check_id(&self.mechanism_id, "evidence.mechanism_id")?;
        check_id(&self.obligation_id, "evidence.obligation_id")?;
        check_id(&self.support_claim_ref, "evidence.support_claim_ref")?;
        self.target.validate()?;
        check_digest(
            &self.expected_target_digest,
            "evidence.expected_target_digest",
        )?;
        check_text(&self.detail, "evidence.detail", MAX_TEXT_BYTES)?;
        check_digest(&self.evidence_digest, "evidence.evidence_digest")?;
        if self.evidence_digest
            != canonical_digest(&self.digest_preimage(), "evidence.evidence_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "evidence.evidence_digest",
            });
        }
        Ok(())
    }
}

/// Lossless independent status vector exposed in the output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAxisSnapshot {
    pub evidence_id: String,
    pub stage: ProofStage,
    pub target: CurrentEvidenceTarget,
    pub expected_target_digest: String,
    pub target_compatible: bool,
    pub verdict: EvidenceVerdict,
    pub contract_ref: String,
    pub support_claim_ref: String,
    pub scope_ref: String,
    pub claim_domain: Option<EvidenceDomain>,
    pub required_dependency_domains: Vec<EvidenceDomain>,
    pub contract_maturity: ContractMaturity,
    pub implementation_support: ImplementationSupport,
    pub evidence_execution_status: EvidenceExecutionStatus,
    pub support_observation_state: SupportObservationState,
    pub proof_profile_ref: Option<String>,
    pub source_handles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub blind_boundaries: Vec<String>,
    pub invalidation_set: Vec<String>,
    pub evaluated_at_ms: u64,
    pub detail: String,
}

impl EvidenceAxisSnapshot {
    /// Builds the immutable output vector from one link and support row.
    pub(crate) fn from_parts(
        evidence: &ImplementationEvidence,
        row: &CapabilitySupportRow,
    ) -> Self {
        Self {
            evidence_id: evidence.evidence_id.clone(),
            stage: evidence.stage,
            target: evidence.target.clone(),
            expected_target_digest: evidence.expected_target_digest.clone(),
            target_compatible: evidence.expected_target_digest == evidence.target.target_digest,
            verdict: evidence.verdict,
            contract_ref: row.contract_ref.clone(),
            support_claim_ref: row.support_claim_ref.clone(),
            scope_ref: row.scope_ref.clone(),
            claim_domain: row.claim_domain,
            required_dependency_domains: row.required_dependency_domains.clone(),
            contract_maturity: row.contract_maturity,
            implementation_support: row.implementation_support,
            evidence_execution_status: row.evidence_execution_status,
            support_observation_state: row.support_observation_state,
            proof_profile_ref: row.proof_profile_ref.clone(),
            source_handles: row.source_handles.clone(),
            evidence_refs: row.evidence_refs.clone(),
            blind_boundaries: row.blind_boundaries.clone(),
            invalidation_set: row.invalidation_set.clone(),
            evaluated_at_ms: row.evaluated_at_ms,
            detail: evidence.detail.clone(),
        }
    }
}
