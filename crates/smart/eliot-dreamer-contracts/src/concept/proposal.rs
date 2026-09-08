//! Structured Concept/Abstraction proposal values.

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_evidence::EvidenceFreshness;
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::classification::{CriterionApplicability, CriterionStatus, NamedEvidence};
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, is_hex64_lower};
use crate::relation::RelationPreservation;

pub(crate) const MAX_TEXT: usize = 1024;
pub(crate) const MAX_ITEMS: usize = 256;
pub(crate) const SCHEMA_VERSION: u32 = 1;
const MAX_PROPOSAL_BYTES: usize = 4 * 1024 * 1024;

fn check_id(id: &ArtifactId, field: &'static str) -> Result<(), ContractViolation> {
    check_text(id.as_str(), field, MAX_TEXT)
}

fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "must be lowercase sha256".to_owned(),
        })
    }
}

fn check_ids(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    for (index, id) in values.iter().enumerate() {
        check_id(id, field)?;
        if values[..index].contains(id) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate identity".to_owned(),
            });
        }
    }
    Ok(())
}

/// Semantic mode inside the single Concept wire kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConceptMode {
    Concept,
    Abstraction,
}

/// Local finite coverage state; `Unknown` is explicit and carries no claim.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConceptCoverage {
    Complete,
    Partial,
    Unknown,
}

/// Local Concept case role; it is not a global Curation kind or epistemic status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConceptCaseKind {
    Positive,
    Counterexample,
    Borderline,
    Unknown,
}

/// Local criterion role. Support remains represented by [`CriterionStatus`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConceptCriterionRole {
    Necessary,
    Sufficient,
    Characteristic,
    Exclusion,
}

/// Exact admitted source/member identity used by every Concept reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptSourceRef {
    pub source_id: ArtifactId,
    pub source_revision: String,
    pub content_digest: String,
    pub admission: ReceiptIdentity,
    pub task_id: TaskId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub freshness: EvidenceFreshness,
}

impl ConceptSourceRef {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.source_id, "concept.source_id")?;
        check_text(&self.source_revision, "concept.source_revision", MAX_TEXT)?;
        check_digest(&self.content_digest, "concept.content_digest")?;
        check_text(
            self.admission.receipt_id.as_str(),
            "concept.admission_id",
            MAX_TEXT,
        )?;
        check_digest(&self.admission.canonical_sha256, "concept.admission_digest")?;
        check_text(self.task_id.as_str(), "concept.task_id", MAX_TEXT)?;
        check_text(self.scope_id.as_str(), "concept.scope_id", MAX_TEXT)?;
        check_fence(&self.state_fence)
    }
}

/// One named parameter in an applicability boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptParameter {
    pub name: String,
    pub value: String,
}

impl ConceptParameter {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.name, "concept.parameter.name", MAX_TEXT)?;
        check_text(&self.value, "concept.parameter.value", MAX_TEXT)
    }
}

/// Explicit scope and transfer boundary for a proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptApplicability {
    pub domain: String,
    pub population: String,
    pub role: String,
    pub environment: String,
    pub time: String,
    pub version: String,
    pub parameters: Vec<ConceptParameter>,
    pub exclusions: Vec<String>,
    pub source_refs: Vec<ArtifactId>,
}

impl ConceptApplicability {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.domain, "concept.applicability.domain"),
            (&self.population, "concept.applicability.population"),
            (&self.role, "concept.applicability.role"),
            (&self.environment, "concept.applicability.environment"),
            (&self.time, "concept.applicability.time"),
            (&self.version, "concept.applicability.version"),
        ] {
            check_text(value, field, MAX_TEXT)?;
        }
        check_vec_bound(
            self.parameters.len(),
            MAX_ITEMS,
            "concept.applicability.parameters",
        )?;
        self.parameters
            .iter()
            .try_for_each(ConceptParameter::validate)?;
        check_vec_bound(
            self.exclusions.len(),
            MAX_ITEMS,
            "concept.applicability.exclusions",
        )?;
        self.exclusions
            .iter()
            .try_for_each(|value| check_text(value, "concept.applicability.exclusion", MAX_TEXT))?;
        check_ids(&self.source_refs, "concept.applicability.source_refs")
    }
}

/// Evidence item with explicit source and dependence closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptEvidence {
    pub named: NamedEvidence,
    pub source_refs: Vec<ArtifactId>,
    pub freshness: EvidenceFreshness,
}

impl ConceptEvidence {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.named.validate()?;
        check_ids(&self.source_refs, "concept.evidence.source_refs")?;
        if self.freshness != self.named.foundation_evidence_envelope.freshness {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.evidence.freshness",
                reason: "wrapper freshness must equal canonical foundation freshness".to_owned(),
            });
        }
        let mut wrapper_sources = self.source_refs.clone();
        let mut named_sources = self.named.source_handles.clone();
        wrapper_sources.sort();
        named_sources.sort();
        if wrapper_sources != named_sources {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.evidence.source_refs",
                reason: "wrapper source_refs must equal NamedEvidence source_handles".to_owned(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn evidence_id(&self) -> &ArtifactId {
        &self.named.id
    }
}

/// One positive, counterexample, borderline or unknown case.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptCase {
    pub case_id: ArtifactId,
    pub kind: ConceptCaseKind,
    pub source_ref: ArtifactId,
    pub evidence_refs: Vec<ArtifactId>,
    pub note: String,
}

impl ConceptCase {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.case_id, "concept.case_id")?;
        check_id(&self.source_ref, "concept.case.source_ref")?;
        check_ids(&self.evidence_refs, "concept.case.evidence_refs")?;
        check_text(&self.note, "concept.case.note", MAX_TEXT)
    }
}

/// One defining or excluding criterion with independent support state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptCriterion {
    pub criterion_id: ArtifactId,
    pub role: ConceptCriterionRole,
    pub applicability: CriterionApplicability,
    pub status: CriterionStatus,
    pub statement: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub exception_refs: Vec<ArtifactId>,
}

impl ConceptCriterion {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.criterion_id, "concept.criterion_id")?;
        check_text(&self.statement, "concept.criterion.statement", MAX_TEXT)?;
        check_ids(&self.evidence_refs, "concept.criterion.evidence_refs")?;
        check_ids(&self.exception_refs, "concept.criterion.exception_refs")
    }
}

/// Existing Concept neighborhood item with its retained immutable proposal.
///
/// The digest authenticates only the supplied serialized proposal shape; it
/// does not establish semantic equivalence or current-state authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptSnapshot {
    pub concept_id: ArtifactId,
    pub proposal: Box<ConceptProposal>,
    pub revision: String,
    pub content_digest: String,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub source_refs: Vec<ArtifactId>,
    pub evidence_refs: Vec<ArtifactId>,
}

impl ConceptSnapshot {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.concept_id, "concept.snapshot.id")?;
        self.proposal.validate()?;
        if self.proposal.concept_id != self.concept_id {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.snapshot.concept_id",
                reason: "snapshot identity differs from retained proposal identity".to_owned(),
            });
        }
        if concept_proposal_digest(&self.proposal)? != self.content_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.snapshot.digest",
                reason: "snapshot digest differs from retained proposal content".to_owned(),
            });
        }
        check_text(&self.revision, "concept.snapshot.revision", MAX_TEXT)?;
        check_digest(&self.content_digest, "concept.snapshot.digest")?;
        check_text(
            self.scope_id.as_str(),
            "concept.snapshot.scope_id",
            MAX_TEXT,
        )?;
        check_fence(&self.state_fence)?;
        check_ids(&self.source_refs, "concept.snapshot.source_refs")?;
        check_ids(&self.evidence_refs, "concept.snapshot.evidence_refs")
    }
}

/// Immutable existing Concept neighborhood supplied by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptNeighborhood {
    pub expected_total: u32,
    pub concepts: Vec<ConceptSnapshot>,
    pub omitted_refs: Vec<ArtifactId>,
    pub coverage: ConceptCoverage,
}

impl ConceptNeighborhood {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let expected =
            usize::try_from(self.expected_total).map_err(|_| ContractViolation::OutOfBounds {
                field: "concept.neighborhood.expected_total",
                min: 0,
                max: 1024,
                got: i64::MAX,
            })?;
        check_vec_bound(expected, 1024, "concept.neighborhood.expected_total")?;
        let actual = self
            .concepts
            .len()
            .checked_add(self.omitted_refs.len())
            .ok_or(ContractViolation::OutOfBounds {
                field: "concept.neighborhood.denominator",
                min: 0,
                max: 1024,
                got: i64::MAX,
            })?;
        if actual != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.neighborhood.denominator",
                reason: "processed plus omitted concepts must equal expected_total".to_owned(),
            });
        }
        if matches!(self.coverage, ConceptCoverage::Complete) && !self.omitted_refs.is_empty() {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.neighborhood.coverage",
                reason: "complete neighborhood cannot omit members".to_owned(),
            });
        }
        if self.omitted_refs.iter().any(|id| {
            self.concepts
                .iter()
                .any(|concept| &concept.concept_id == id)
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.neighborhood.omitted_refs",
                reason: "omitted concept identity is already processed".to_owned(),
            });
        }
        let concept_ids = self
            .concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect::<Vec<_>>();
        check_ids(&concept_ids, "concept.neighborhood.concepts")?;
        self.concepts
            .iter()
            .try_for_each(ConceptSnapshot::validate)?;
        check_ids(&self.omitted_refs, "concept.neighborhood.omitted_refs")
    }
}

/// Immutable verifier identity retained with a discriminator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptVerifierRef {
    pub verifier_id: ArtifactId,
    pub revision: String,
    pub digest: String,
}

impl ConceptVerifierRef {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.verifier_id, "concept.verifier.id")?;
        check_text(&self.revision, "concept.verifier.revision", MAX_TEXT)?;
        check_digest(&self.digest, "concept.verifier.digest")
    }
}

/// A supplied rival or no-generalization interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptDiscriminator {
    pub alternative_id: Option<ArtifactId>,
    pub predicted_distinction: String,
    pub falsification_condition: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub verifier: ConceptVerifierRef,
}

impl ConceptDiscriminator {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(id) = &self.alternative_id {
            check_id(id, "concept.discriminator.alternative_id")?;
        }
        check_text(
            &self.predicted_distinction,
            "concept.discriminator.prediction",
            MAX_TEXT,
        )?;
        check_text(
            &self.falsification_condition,
            "concept.discriminator.falsification_condition",
            MAX_TEXT,
        )?;
        check_ids(&self.evidence_refs, "concept.discriminator.evidence_refs")?;
        if self.evidence_refs.is_empty() {
            return Err(ContractViolation::MissingField(
                "concept.discriminator.evidence_refs",
            ));
        }
        self.verifier.validate()
    }
}

/// A dependency retained as an exact identity and digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptDependency {
    pub dependency_id: ArtifactId,
    pub revision: String,
    pub content_digest: String,
    pub source_refs: Vec<ArtifactId>,
}

impl ConceptDependency {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.dependency_id, "concept.dependency_id")?;
        check_text(&self.revision, "concept.dependency.revision", MAX_TEXT)?;
        check_digest(&self.content_digest, "concept.dependency.digest")?;
        check_ids(&self.source_refs, "concept.dependency.source_refs")
    }
}

/// Complete structured Concept/Abstraction proposal; all references are local IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptProposal {
    pub schema_version: u32,
    pub concept_id: ArtifactId,
    pub mode: ConceptMode,
    pub name: String,
    pub definition: String,
    pub criteria: Vec<ConceptCriterion>,
    pub applicability: ConceptApplicability,
    pub cases: Vec<ConceptCase>,
    pub case_expected_total: u32,
    pub case_omitted_refs: Vec<ArtifactId>,
    pub case_coverage: ConceptCoverage,
    pub evidence: Vec<ConceptEvidence>,
    pub rivals: Vec<ConceptDiscriminator>,
    pub discriminator: ConceptDiscriminator,
    pub dependencies: Vec<ConceptDependency>,
    pub source_refs: Vec<ArtifactId>,
    pub policy_digest: String,
    pub proof_ceiling: ProofCeiling,
    pub preservation: RelationPreservation,
}

/// Canonical content identity for one retained immutable Concept proposal.
///
/// Criteria, cases, and dependencies retain their supplied row order. Reference,
/// evidence, omission, and dependence-group collections are normalized as sets.
pub fn concept_proposal_digest(proposal: &ConceptProposal) -> Result<String, ContractViolation> {
    preflight_proposal(proposal)?;
    proposal.validate()?;
    let normalized = normalized_proposal(proposal);
    Ok(crate::encoding::digest_hex(
        &crate::encoding::canonical_bytes(&normalized)?,
    ))
}

fn preflight_proposal(proposal: &ConceptProposal) -> Result<(), ContractViolation> {
    let mut writer = BoundedWriter {
        len: 0,
        max: MAX_PROPOSAL_BYTES,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, proposal) {
        Ok(()) => Ok(()),
        Err(_error) if writer.exceeded => Err(ContractViolation::OutOfBounds {
            field: "concept.proposal_bytes",
            min: 0,
            max: i64::try_from(MAX_PROPOSAL_BYTES).unwrap_or(i64::MAX),
            got: i64::try_from(writer.len).unwrap_or(i64::MAX),
        }),
        Err(error) => Err(ContractViolation::Malformed {
            field: "concept.proposal",
            reason: error.to_string(),
        }),
    }
}

struct BoundedWriter {
    len: usize,
    max: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized Concept proposal length overflow"))?;
        if next > self.max {
            self.len = self.max.checked_add(1).unwrap_or(self.max);
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized Concept proposal exceeds bound",
            ));
        }
        self.len = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn normalized_proposal(proposal: &ConceptProposal) -> ConceptProposal {
    let mut normalized = proposal.clone();
    normalized.preservation = normalized_preservation(&normalized.preservation);
    normalized.source_refs.sort();
    normalized.applicability.source_refs.sort();
    normalized.applicability.exclusions.sort();
    normalized
        .evidence
        .sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    normalized.evidence.iter_mut().for_each(|evidence| {
        evidence.source_refs.sort();
        evidence.named.source_handles.sort();
        evidence.named.dependence_groups.sort();
    });
    normalized.criteria.iter_mut().for_each(|criterion| {
        criterion.evidence_refs.sort();
        criterion.exception_refs.sort();
    });
    normalized
        .cases
        .iter_mut()
        .for_each(|case_| case_.evidence_refs.sort());
    normalized
        .rivals
        .iter_mut()
        .for_each(|rival| rival.evidence_refs.sort());
    normalized.discriminator.evidence_refs.sort();
    normalized.case_omitted_refs.sort();
    normalized
        .dependencies
        .iter_mut()
        .for_each(|dependency| dependency.source_refs.sort());
    normalized
}

pub(crate) fn normalized_preservation(preservation: &RelationPreservation) -> RelationPreservation {
    let mut normalized = preservation.clone();
    normalized
        .verdicts
        .sort_by_key(|verdict| verdict.dimension.as_str());
    normalized
}

impl ConceptProposal {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "concept.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        check_id(&self.concept_id, "concept.id")?;
        check_text(&self.name, "concept.name", MAX_TEXT)?;
        check_text(&self.definition, "concept.definition", MAX_TEXT)?;
        check_digest(&self.policy_digest, "concept.policy_digest")?;
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "concept proposal exceeds CandidateArtifact proof ceiling".to_owned(),
            ));
        }
        check_vec_bound(self.criteria.len(), MAX_ITEMS, "concept.criteria")?;
        self.criteria
            .iter()
            .try_for_each(ConceptCriterion::validate)?;
        self.applicability.validate()?;
        check_vec_bound(self.cases.len(), MAX_ITEMS, "concept.cases")?;
        self.cases.iter().try_for_each(ConceptCase::validate)?;
        let expected = usize::try_from(self.case_expected_total).map_err(|_| {
            ContractViolation::OutOfBounds {
                field: "concept.cases.expected_total",
                min: 0,
                max: 1024,
                got: i64::MAX,
            }
        })?;
        check_vec_bound(expected, 1024, "concept.cases.expected_total")?;
        check_ids(&self.case_omitted_refs, "concept.cases.omitted_refs")?;
        if self
            .case_omitted_refs
            .iter()
            .any(|id| self.cases.iter().any(|case_| &case_.case_id == id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.cases.omitted_refs",
                reason: "omitted case identity is already processed".to_owned(),
            });
        }
        let actual = self
            .cases
            .len()
            .checked_add(self.case_omitted_refs.len())
            .ok_or(ContractViolation::OutOfBounds {
                field: "concept.cases.denominator",
                min: 0,
                max: 1024,
                got: i64::MAX,
            })?;
        if actual != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.cases.denominator",
                reason: "processed plus omitted cases must equal expected_total".to_owned(),
            });
        }
        if matches!(self.case_coverage, ConceptCoverage::Complete)
            && !self.case_omitted_refs.is_empty()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.cases.complete",
                reason: "complete case denominator cannot omit members".to_owned(),
            });
        }
        check_vec_bound(self.evidence.len(), MAX_ITEMS, "concept.evidence")?;
        self.evidence
            .iter()
            .try_for_each(ConceptEvidence::validate)?;
        check_vec_bound(self.rivals.len(), MAX_ITEMS, "concept.rivals")?;
        self.rivals
            .iter()
            .try_for_each(ConceptDiscriminator::validate)?;
        self.discriminator.validate()?;
        check_vec_bound(self.dependencies.len(), MAX_ITEMS, "concept.dependencies")?;
        self.dependencies
            .iter()
            .try_for_each(ConceptDependency::validate)?;
        check_ids(&self.source_refs, "concept.source_refs")?;
        self.validate_unique_identity_sets()?;
        self.preservation.validate()
    }

    fn validate_unique_identity_sets(&self) -> Result<(), ContractViolation> {
        let criterion_ids = self
            .criteria
            .iter()
            .map(|criterion| criterion.criterion_id.clone())
            .collect::<Vec<_>>();
        check_ids(&criterion_ids, "concept.criteria")?;
        let case_ids = self
            .cases
            .iter()
            .map(|case_| case_.case_id.clone())
            .collect::<Vec<_>>();
        check_ids(&case_ids, "concept.cases")?;
        let evidence_ids = self
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id().clone())
            .collect::<Vec<_>>();
        check_ids(&evidence_ids, "concept.evidence")?;
        let dependency_ids = self
            .dependencies
            .iter()
            .map(|dependency| dependency.dependency_id.clone())
            .collect::<Vec<_>>();
        check_ids(&dependency_ids, "concept.dependencies")?;
        let rival_ids = self
            .rivals
            .iter()
            .filter_map(|rival| rival.alternative_id.clone())
            .collect::<Vec<_>>();
        check_ids(&rival_ids, "concept.rivals.alternative_id")
    }
}
