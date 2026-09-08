//! Provider-neutral taxonomy and criterion contracts for post-admission work.
//!
//! A-03 records the owner supplied registry snapshot and denominator. A-21
//! interprets applicability and chooses among the retained alternatives. This
//! module contains no ranking, confidence, source-count or ontology logic.

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};

const MAX_TEXT: usize = 1024;
const MAX_ITEMS: usize = 256;

/// The twelve canonical I12.4 record families.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassificationRecordFamily {
    SourceRecord,
    ObservationRecord,
    Interpretation,
    AssumptionRecord,
    DecisionRecord,
    ExperienceRecord,
    CommitmentRecord,
    TaskRecord,
    ControlRecord,
    ArtifactRecord,
    ProjectionRecord,
    AuditRecord,
}

impl ClassificationRecordFamily {
    /// Returns the exact I12.4 wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceRecord => "source_record",
            Self::ObservationRecord => "observation_record",
            Self::Interpretation => "interpretation",
            Self::AssumptionRecord => "assumption_record",
            Self::DecisionRecord => "decision_record",
            Self::ExperienceRecord => "experience_record",
            Self::CommitmentRecord => "commitment_record",
            Self::TaskRecord => "task_record",
            Self::ControlRecord => "control_record",
            Self::ArtifactRecord => "artifact_record",
            Self::ProjectionRecord => "projection_record",
            Self::AuditRecord => "audit_record",
        }
    }
}

/// Exact #653 criterion roles. Role, applicability, value and status remain
/// separate fields so no role can be smuggled in as a support score.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassificationCriterionRole {
    Necessary,
    Sufficient,
    Characteristic,
    Exclusion,
}

/// Applicability supplied by the taxonomy owner or resolved by A-21.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CriterionApplicability {
    Required,
    Optional,
    Conditional,
    NotApplicable,
    Unknown,
}

/// Independent criterion observation status. It is not an aggregate grade.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CriterionStatus {
    Supported,
    Partial,
    Unsupported,
    Contradicted,
    Unknown,
}

/// Coverage of the supplied alternative denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TaxonomyCoverage {
    Complete,
    Partial,
    Unknown,
}

/// A known alternative retained for A-21 selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyAlternative {
    pub alternative_id: ArtifactId,
    pub family: ClassificationRecordFamily,
    pub subtype_ref: Option<String>,
    pub criterion_refs: Vec<ArtifactId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub counterevidence_refs: Vec<ArtifactId>,
}

impl TaxonomyAlternative {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.alternative_id, "taxonomy.alternative_id")?;
        if let Some(subtype) = &self.subtype_ref {
            check_text(subtype, "taxonomy.subtype_ref", MAX_TEXT)?;
        }
        check_id_set(&self.criterion_refs, "taxonomy.criterion_refs")?;
        check_id_set(&self.evidence_refs, "taxonomy.evidence_refs")?;
        check_id_set(&self.counterevidence_refs, "taxonomy.counterevidence_refs")
    }
}

/// Exact accepted alias/refinement mapping owned by the registry snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyAliasMapping {
    pub alias_id: ArtifactId,
    pub canonical_alternative_id: ArtifactId,
    pub refinement_of: Option<ArtifactId>,
}

impl TaxonomyAliasMapping {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.alias_id, "taxonomy.alias_id")?;
        check_id(
            &self.canonical_alternative_id,
            "taxonomy.canonical_alternative_id",
        )?;
        if let Some(parent) = &self.refinement_of {
            check_id(parent, "taxonomy.refinement_of")?;
        }
        Ok(())
    }
}

/// One owner criterion with explicit applicability and independent status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroundedCriterion {
    pub criterion_id: ArtifactId,
    pub role: ClassificationCriterionRole,
    pub applicability: CriterionApplicability,
    pub evidence_refs: Vec<ArtifactId>,
    pub rationale: String,
}

impl GroundedCriterion {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.criterion_id, "taxonomy.criterion_id")?;
        check_id_set(&self.evidence_refs, "taxonomy.criterion.evidence_refs")?;
        check_text(&self.rationale, "taxonomy.criterion.rationale", MAX_TEXT)
    }
}

/// Immutable registry snapshot and explicit complete/partial denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyDenominator {
    pub owner: String,
    pub schema: String,
    pub revision: String,
    /// Digest of the normalized owner snapshot, including alternatives and mappings.
    pub digest: String,
    pub coverage: TaxonomyCoverage,
    pub declared_families: Vec<ClassificationRecordFamily>,
    pub declared_alternative_ids: Vec<ArtifactId>,
    pub provided_alternative_ids: Vec<ArtifactId>,
    pub omitted_alternative_ids: Vec<ArtifactId>,
    pub alternatives: Vec<TaxonomyAlternative>,
    pub criteria: Vec<GroundedCriterion>,
    pub missing_criteria: Vec<ArtifactId>,
    pub alias_mappings: Vec<TaxonomyAliasMapping>,
}

impl TaxonomyDenominator {
    /// Computes the digest of the normalized registry snapshot without the
    /// self-referential digest field.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        super::input::preflight_serialized(self, 4 * 1024 * 1024, "taxonomy.snapshot_bytes")?;
        check_text(&self.owner, "taxonomy.owner", MAX_TEXT)?;
        check_text(&self.schema, "taxonomy.schema", MAX_TEXT)?;
        check_text(&self.revision, "taxonomy.revision", MAX_TEXT)?;
        check_vec_bound(
            self.declared_families.len(),
            MAX_ITEMS,
            "taxonomy.declared_families",
        )?;
        check_vec_bound(
            self.declared_alternative_ids.len(),
            MAX_ITEMS,
            "taxonomy.declared_alternative_ids",
        )?;
        check_vec_bound(
            self.provided_alternative_ids.len(),
            MAX_ITEMS,
            "taxonomy.provided_alternative_ids",
        )?;
        check_vec_bound(
            self.omitted_alternative_ids.len(),
            MAX_ITEMS,
            "taxonomy.omitted_alternative_ids",
        )?;
        check_vec_bound(
            self.missing_criteria.len(),
            MAX_ITEMS,
            "taxonomy.missing_criteria",
        )?;
        check_vec_bound(self.alternatives.len(), MAX_ITEMS, "taxonomy.alternatives")?;
        check_vec_bound(self.criteria.len(), MAX_ITEMS, "taxonomy.criteria")?;
        check_vec_bound(
            self.alias_mappings.len(),
            MAX_ITEMS,
            "taxonomy.alias_mappings",
        )?;
        self.alternatives
            .iter()
            .try_for_each(TaxonomyAlternative::validate)?;
        self.criteria
            .iter()
            .try_for_each(GroundedCriterion::validate)?;
        self.alias_mappings
            .iter()
            .try_for_each(TaxonomyAliasMapping::validate)?;
        let mut declared_families = self.declared_families.clone();
        declared_families.sort_by_key(|family| family.as_str());
        let mut declared_alternative_ids = self.declared_alternative_ids.clone();
        let mut provided_alternative_ids = self.provided_alternative_ids.clone();
        let mut omitted_alternative_ids = self.omitted_alternative_ids.clone();
        let mut missing_criteria = self.missing_criteria.clone();
        let mut alternatives = self.alternatives.clone();
        let mut criteria = self.criteria.clone();
        let mut alias_mappings = self.alias_mappings.clone();
        declared_alternative_ids.sort_by_key(|id| id.as_str().to_owned());
        provided_alternative_ids.sort_by_key(|id| id.as_str().to_owned());
        omitted_alternative_ids.sort_by_key(|id| id.as_str().to_owned());
        missing_criteria.sort_by_key(|id| id.as_str().to_owned());
        alternatives.sort_by_key(|alternative| alternative.alternative_id.as_str().to_owned());
        criteria.sort_by_key(|criterion| criterion.criterion_id.as_str().to_owned());
        alias_mappings.sort_by_key(|mapping| mapping.alias_id.as_str().to_owned());
        for alternative in &mut alternatives {
            alternative
                .criterion_refs
                .sort_by_key(|id| id.as_str().to_owned());
            alternative
                .evidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
            alternative
                .counterevidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
        }
        for criterion in &mut criteria {
            criterion
                .evidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
        }
        let preimage = TaxonomyDigestPreimage {
            owner: &self.owner,
            schema: &self.schema,
            revision: &self.revision,
            coverage: self.coverage,
            declared_families: &declared_families,
            declared_alternative_ids: &declared_alternative_ids,
            provided_alternative_ids: &provided_alternative_ids,
            omitted_alternative_ids: &omitted_alternative_ids,
            alternatives: &alternatives,
            criteria: &criteria,
            missing_criteria: &missing_criteria,
            alias_mappings: &alias_mappings,
        };
        Ok(crate::encoding::digest_hex(
            &crate::encoding::canonical_bytes(&preimage)?,
        ))
    }

    /// Validates identities, denominator closure and reference closure.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        super::input::preflight_serialized(self, 4 * 1024 * 1024, "taxonomy.snapshot_bytes")?;
        self.validate_identity_phase()?;
        self.validate_reference_phase()?;
        self.validate_alias_phase()?;
        self.validate_coverage_phase()
    }

    fn validate_identity_phase(&self) -> Result<(), ContractViolation> {
        check_text(&self.owner, "taxonomy.owner", MAX_TEXT)?;
        check_text(&self.schema, "taxonomy.schema", MAX_TEXT)?;
        check_text(&self.revision, "taxonomy.revision", MAX_TEXT)?;
        if !is_hex64_lower(&self.digest) {
            return Err(ContractViolation::Malformed {
                field: "taxonomy.digest",
                reason: "expected lowercase SHA-256".to_owned(),
            });
        }
        check_vec_bound(
            self.declared_families.len(),
            MAX_ITEMS,
            "taxonomy.declared_families",
        )?;
        unique_families(&self.declared_families)?;
        check_id_set(
            &self.declared_alternative_ids,
            "taxonomy.declared_alternative_ids",
        )?;
        check_id_set(
            &self.provided_alternative_ids,
            "taxonomy.provided_alternative_ids",
        )?;
        check_id_set(
            &self.omitted_alternative_ids,
            "taxonomy.omitted_alternative_ids",
        )?;
        check_id_set(&self.missing_criteria, "taxonomy.missing_criteria")?;
        check_vec_bound(self.alternatives.len(), MAX_ITEMS, "taxonomy.alternatives")?;
        check_vec_bound(self.criteria.len(), MAX_ITEMS, "taxonomy.criteria")?;
        check_vec_bound(
            self.alias_mappings.len(),
            MAX_ITEMS,
            "taxonomy.alias_mappings",
        )?;
        reject_overlap(
            &self.provided_alternative_ids,
            &self.omitted_alternative_ids,
            "taxonomy.alternative_ids",
        )?;
        let alternative_ids: Vec<ArtifactId> = self
            .alternatives
            .iter()
            .map(|a| a.alternative_id.clone())
            .collect();
        check_id_set(&alternative_ids, "taxonomy.alternatives")?;
        if !same_set(&alternative_ids, &self.provided_alternative_ids) {
            return Err(ContractViolation::BindingMismatch {
                field: "taxonomy.provided_alternative_ids",
                reason: "provided IDs must exactly match alternatives in canonical order"
                    .to_owned(),
            });
        }
        if self.declared_alternative_ids.len()
            != self.provided_alternative_ids.len() + self.omitted_alternative_ids.len()
            || self.declared_alternative_ids.iter().any(|id| {
                !self.provided_alternative_ids.contains(id)
                    && !self.omitted_alternative_ids.contains(id)
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "taxonomy.declared_alternative_ids",
                reason: "declared IDs must close provided and omitted denominator".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_reference_phase(&self) -> Result<(), ContractViolation> {
        let criterion_ids: Vec<ArtifactId> = self
            .criteria
            .iter()
            .map(|c| c.criterion_id.clone())
            .collect();
        check_id_set(&criterion_ids, "taxonomy.criteria")?;
        reject_overlap(&criterion_ids, &self.missing_criteria, "taxonomy.criteria")?;
        for alternative in &self.alternatives {
            alternative.validate()?;
            if !self.declared_families.contains(&alternative.family) {
                return Err(ContractViolation::BindingMismatch {
                    field: "taxonomy.family",
                    reason: "alternative family outside declared families".to_owned(),
                });
            }
            for criterion in &alternative.criterion_refs {
                if !criterion_ids.contains(criterion) && !self.missing_criteria.contains(criterion)
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "taxonomy.criterion_refs",
                        reason: "criterion reference is neither provided nor explicitly missing"
                            .to_owned(),
                    });
                }
            }
        }
        for criterion in &self.criteria {
            criterion.validate()?;
        }
        Ok(())
    }

    fn validate_alias_phase(&self) -> Result<(), ContractViolation> {
        let declared = &self.declared_alternative_ids;
        let mut alias_ids = Vec::with_capacity(self.alias_mappings.len());
        for mapping in &self.alias_mappings {
            mapping.validate()?;
            if alias_ids.contains(&mapping.alias_id) || declared.contains(&mapping.alias_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "taxonomy.alias_mappings",
                    reason: "alias identity is duplicated or collides with an alternative"
                        .to_owned(),
                });
            }
            alias_ids.push(mapping.alias_id.clone());
            if !declared.contains(&mapping.canonical_alternative_id)
                || mapping
                    .refinement_of
                    .as_ref()
                    .is_some_and(|id| !declared.contains(id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "taxonomy.alias_mappings",
                    reason: "alias/refinement mapping points outside declared alternatives"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_coverage_phase(&self) -> Result<(), ContractViolation> {
        if self.coverage == TaxonomyCoverage::Complete && !self.omitted_alternative_ids.is_empty() {
            return Err(ContractViolation::BindingMismatch {
                field: "taxonomy.coverage",
                reason: "complete denominator cannot omit alternatives".to_owned(),
            });
        }
        if self.coverage == TaxonomyCoverage::Complete && !self.missing_criteria.is_empty() {
            return Err(ContractViolation::BindingMismatch {
                field: "taxonomy.coverage",
                reason: "complete denominator cannot have missing criteria".to_owned(),
            });
        }
        if self.digest != self.computed_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "taxonomy.digest",
                reason: "digest does not match normalized registry snapshot".to_owned(),
            });
        }
        Ok(())
    }
}

/// Exact independent I9.7 preservation dimensions for this transformation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassificationPreservationDimension {
    Coverage,
    Preservation,
    Faithfulness,
    Lineage,
    Reversibility,
    SourceAuthority,
    DependencyClosure,
}

/// One independent verdict; failed or unknown remains visible for abstention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationPreservationVerdict {
    pub dimension: ClassificationPreservationDimension,
    pub passed: bool,
    pub known: bool,
    pub note: String,
}

/// Seven named I9.7 verdicts. They are never averaged or collapsed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationPreservation {
    pub verdicts: Vec<ClassificationPreservationVerdict>,
}

impl ClassificationPreservation {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        const ALL: [ClassificationPreservationDimension; 7] = [
            ClassificationPreservationDimension::Coverage,
            ClassificationPreservationDimension::Preservation,
            ClassificationPreservationDimension::Faithfulness,
            ClassificationPreservationDimension::Lineage,
            ClassificationPreservationDimension::Reversibility,
            ClassificationPreservationDimension::SourceAuthority,
            ClassificationPreservationDimension::DependencyClosure,
        ];
        if self.verdicts.len() != ALL.len() {
            return Err(ContractViolation::Preservation(
                "classification requires seven I9.7 verdicts".to_owned(),
            ));
        }
        for verdict in &self.verdicts {
            check_text(&verdict.note, "classification.preservation.note", MAX_TEXT)?;
            if !ALL.contains(&verdict.dimension)
                || self
                    .verdicts
                    .iter()
                    .filter(|other| other.dimension == verdict.dimension)
                    .count()
                    != 1
            {
                return Err(ContractViolation::Preservation(
                    "preservation dimensions must be unique".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Returns true only when all seven dimensions are known and passing.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.validate().is_ok() && self.verdicts.iter().all(|v| v.known && v.passed)
    }
}

fn check_id(id: &ArtifactId, field: &'static str) -> Result<(), ContractViolation> {
    check_text(id.as_str(), field, MAX_TEXT)
}

fn check_refs(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    values.iter().try_for_each(|value| check_id(value, field))
}

fn check_id_set(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_refs(values, field)?;
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate identity".to_owned(),
            });
        }
    }
    Ok(())
}

fn reject_overlap(
    left: &[ArtifactId],
    right: &[ArtifactId],
    field: &'static str,
) -> Result<(), ContractViolation> {
    if left.iter().any(|id| right.contains(id)) {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "provided and omitted IDs overlap".to_owned(),
        });
    }
    Ok(())
}

fn unique_families(values: &[ClassificationRecordFamily]) -> Result<(), ContractViolation> {
    for (index, family) in values.iter().enumerate() {
        if values[..index].contains(family) {
            return Err(ContractViolation::BindingMismatch {
                field: "taxonomy.declared_families",
                reason: format!("duplicate family {}", family.as_str()),
            });
        }
    }
    Ok(())
}

fn same_set(left: &[ArtifactId], right: &[ArtifactId]) -> bool {
    left.len() == right.len() && left.iter().all(|id| right.contains(id))
}

#[derive(Serialize)]
struct TaxonomyDigestPreimage<'a> {
    owner: &'a str,
    schema: &'a str,
    revision: &'a str,
    coverage: TaxonomyCoverage,
    declared_families: &'a [ClassificationRecordFamily],
    declared_alternative_ids: &'a [ArtifactId],
    provided_alternative_ids: &'a [ArtifactId],
    omitted_alternative_ids: &'a [ArtifactId],
    alternatives: &'a [TaxonomyAlternative],
    criteria: &'a [GroundedCriterion],
    missing_criteria: &'a [ArtifactId],
    alias_mappings: &'a [TaxonomyAliasMapping],
}
