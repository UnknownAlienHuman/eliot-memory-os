//! Bounded, explicit policy for the pure classification selector.

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::{
    ClassificationInput, ContractViolation, ExternalGradeRef, canonical_bytes, digest_hex,
};
use eliot_epistemic_contracts::{EvidenceGrade, GradeAssignment};
use eliot_evidence::EpistemicStatus;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A grade owned by the C1 epistemic contract and bound to one evidence item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGradeBinding {
    pub evidence_id: ArtifactId,
    pub reference: ExternalGradeRef,
    pub assignment: GradeAssignment,
}

/// Independent ceilings for one bounded selector invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationPolicy {
    pub policy_digest: String,
    pub minimum_grade: EvidenceGrade,
    pub maximum_grade: EvidenceGrade,
    pub target_status: EpistemicStatus,
    pub grade_bindings: Vec<EvidenceGradeBinding>,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_features: u64,
    pub max_alternatives: u64,
    pub max_evidence: u64,
    pub max_source_refs: u64,
    /// Explicit preflight workload score for the selector; it is not a CPU or
    /// runtime operation count.
    pub max_work_units: u64,
    pub max_stu: u64,
    /// Explicit caller supplied STU usage, kept independent from work units.
    pub observed_stu: u64,
    pub now_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
    pub cancellation_requested: bool,
}

impl Default for ClassificationPolicy {
    fn default() -> Self {
        Self {
            policy_digest: String::new(),
            minimum_grade: EvidenceGrade::Grounded,
            maximum_grade: EvidenceGrade::ScienceGrade,
            target_status: EpistemicStatus::Observed,
            grade_bindings: Vec::new(),
            max_input_bytes: 4 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_features: 256,
            max_alternatives: 256,
            max_evidence: 256,
            max_source_refs: 256,
            max_work_units: 65_536,
            max_stu: 65_536,
            observed_stu: 0,
            now_ms: None,
            deadline_ms: None,
            cancellation_requested: false,
        }
    }
}

impl ClassificationPolicy {
    /// Computes the policy identity without the self-referential digest field.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct PolicyPreimage<'a> {
            minimum_grade: EvidenceGrade,
            maximum_grade: EvidenceGrade,
            target_status: EpistemicStatus,
            grade_bindings: &'a [EvidenceGradeBinding],
            max_input_bytes: u64,
            max_output_bytes: u64,
            max_features: u64,
            max_alternatives: u64,
            max_evidence: u64,
            max_source_refs: u64,
            max_work_units: u64,
            max_stu: u64,
            now_ms: Option<u64>,
            deadline_ms: Option<u64>,
            cancellation_requested: bool,
            observed_stu: u64,
        }
        self.validate_grade_bindings()?;
        let mut grade_bindings = self.grade_bindings.clone();
        grade_bindings.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        let preimage = PolicyPreimage {
            minimum_grade: self.minimum_grade,
            maximum_grade: self.maximum_grade,
            target_status: self.target_status,
            grade_bindings: &grade_bindings,
            max_input_bytes: self.max_input_bytes,
            max_output_bytes: self.max_output_bytes,
            max_features: self.max_features,
            max_alternatives: self.max_alternatives,
            max_evidence: self.max_evidence,
            max_source_refs: self.max_source_refs,
            max_work_units: self.max_work_units,
            max_stu: self.max_stu,
            now_ms: self.now_ms,
            deadline_ms: self.deadline_ms,
            cancellation_requested: self.cancellation_requested,
            observed_stu: self.observed_stu,
        };
        canonical_bytes(&preimage).map(|bytes| digest_hex(&bytes))
    }
}

/// Planned and observed dimensions retained with the result for independent
/// budget accounting. `work_units` is the explicit preflight workload score.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetReceipt {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub feature_count: u64,
    pub alternative_count: u64,
    pub evidence_count: u64,
    pub source_ref_count: u64,
    pub work_units: u64,
    pub stu: u64,
}

/// Computes the digest carried by an external grade reference. The digest
/// deliberately excludes only the reference's own digest field and binds all
/// other reference identity plus the complete canonical C1 assignment.
pub fn grade_binding_digest(binding: &EvidenceGradeBinding) -> Result<String, ContractViolation> {
    #[derive(Serialize)]
    struct GradePre<'a> {
        evidence_id: &'a ArtifactId,
        owner: &'a str,
        schema: &'a str,
        revision: &'a str,
        record_id: &'a ArtifactId,
        assignment: &'a GradeAssignment,
    }
    validate_grade_binding(binding)?;
    let reference = &binding.reference;
    canonical_bytes(&GradePre {
        evidence_id: &binding.evidence_id,
        owner: &reference.owner,
        schema: &reference.schema,
        revision: &reference.revision,
        record_id: &reference.record_id,
        assignment: &binding.assignment,
    })
    .map(|bytes| digest_hex(&bytes))
}

impl ClassificationPolicy {
    fn validate_grade_bindings(&self) -> Result<(), ContractViolation> {
        if self.grade_bindings.len() > 256 {
            return Err(ContractViolation::OutOfBounds {
                field: "classification.grade_bindings",
                min: 0,
                max: 256,
                got: i64::try_from(self.grade_bindings.len()).unwrap_or(i64::MAX),
            });
        }
        for (index, binding) in self.grade_bindings.iter().enumerate() {
            validate_grade_binding(binding)?;
            if self.grade_bindings[..index]
                .iter()
                .any(|prior| prior.evidence_id == binding.evidence_id)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.grade",
                    reason: "duplicate evidence grade binding".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Checks policy identity and all input-side independent bounds before cloning.
    pub fn preflight(
        &self,
        input: &ClassificationInput,
    ) -> Result<BudgetReceipt, ContractViolation> {
        if self.cancellation_requested {
            return Err(ContractViolation::Budget {
                dimension: "cancellation",
                reason: "classification cancelled before evaluation".to_owned(),
            });
        }
        if self.minimum_grade.rank() > self.maximum_grade.rank() {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.policy.grade",
                reason: "minimum grade exceeds policy ceiling".to_owned(),
            });
        }
        self.validate_grade_bindings()?;
        if let Some(deadline) = self.deadline_ms {
            let now = self.now_ms.ok_or(ContractViolation::Budget {
                dimension: "deadline",
                reason: "deadline supplied without an explicit observation time".to_owned(),
            })?;
            if now >= deadline {
                return Err(ContractViolation::Budget {
                    dimension: "deadline",
                    reason: "classification deadline elapsed".to_owned(),
                });
            }
        }
        if self.policy_digest != self.computed_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.policy_digest",
                reason: "policy digest does not match execution policy".to_owned(),
            });
        }
        input.preflight()?;
        let input_bytes = bounded_len(
            serde_json::to_vec(input)
                .map_err(|_| ContractViolation::Malformed {
                    field: "classification.input_bytes",
                    reason: "input serialization failed".to_owned(),
                })?
                .len(),
            "input_bytes",
        )?;
        let feature_count = bounded_len(input.features.len(), "features")?;
        let alternative_count = bounded_len(input.taxonomy.alternatives.len(), "alternatives")?;
        let evidence_count = bounded_len(input.evidence.len(), "evidence")?;
        let source_ref_count = input
            .evidence
            .iter()
            .try_fold(input.target.source_handles.len(), |acc, e| {
                acc.checked_add(e.source_handles.len())
            })
            .and_then(|n| {
                input
                    .features
                    .iter()
                    .try_fold(n, |acc, f| acc.checked_add(f.evidence_refs.len()))
            })
            .ok_or(ContractViolation::Budget {
                dimension: "source_refs",
                reason: "source count overflow".to_owned(),
            })?;
        let source_ref_count = bounded_len(source_ref_count, "source_refs")?;
        cap(input_bytes, self.max_input_bytes, "input_bytes")?;
        cap(feature_count, self.max_features, "features")?;
        cap(alternative_count, self.max_alternatives, "alternatives")?;
        cap(evidence_count, self.max_evidence, "evidence")?;
        cap(source_ref_count, self.max_source_refs, "source_refs")?;
        let work_units = feature_count
            .checked_add(alternative_count)
            .and_then(|n| n.checked_add(evidence_count))
            .and_then(|n| n.checked_add(source_ref_count))
            .and_then(|n| n.checked_add(alternative_count.checked_mul(feature_count)?))
            .ok_or(ContractViolation::Budget {
                dimension: "work_units",
                reason: "work count overflow".to_owned(),
            })?;
        cap(work_units, self.max_work_units, "work_units")?;
        cap(self.observed_stu, self.max_stu, "stu")?;
        Ok(BudgetReceipt {
            input_bytes,
            output_bytes: 0,
            feature_count,
            alternative_count,
            evidence_count,
            source_ref_count,
            work_units,
            stu: self.observed_stu,
        })
    }

    /// Returns the exact supplied C1 grade binding for evidence, if present.
    pub fn grade_for(
        &self,
        evidence_id: &ArtifactId,
    ) -> Result<&GradeAssignment, ContractViolation> {
        self.validate_grade_bindings()?;
        let mut found = None;
        for binding in &self.grade_bindings {
            binding
                .assignment
                .validate()
                .map_err(|_| ContractViolation::BindingMismatch {
                    field: "classification.grade",
                    reason: "invalid C1 GradeAssignment".to_owned(),
                })?;
            if binding.evidence_id == *evidence_id {
                if found.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "classification.grade",
                        reason: "duplicate evidence grade binding".to_owned(),
                    });
                }
                found = Some(&binding.assignment);
            }
        }
        found.ok_or(ContractViolation::BindingMismatch {
            field: "classification.grade",
            reason: format!("missing C1 grade binding for {evidence_id}"),
        })
    }

    /// Returns the complete binding, including the exact C0 external reference.
    pub fn grade_binding_for(
        &self,
        evidence_id: &ArtifactId,
    ) -> Result<&EvidenceGradeBinding, ContractViolation> {
        self.validate_grade_bindings()?;
        let mut found = None;
        for binding in &self.grade_bindings {
            if binding.evidence_id == *evidence_id {
                if found.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "classification.grade",
                        reason: "duplicate evidence grade binding".to_owned(),
                    });
                }
                found = Some(binding);
            }
        }
        found.ok_or(ContractViolation::BindingMismatch {
            field: "classification.grade",
            reason: format!("missing C1 grade binding for {evidence_id}"),
        })
    }
}

fn validate_grade_binding(binding: &EvidenceGradeBinding) -> Result<(), ContractViolation> {
    if binding.evidence_id.as_str().trim().is_empty() || binding.evidence_id.as_str().len() > 1024 {
        return Err(ContractViolation::Malformed {
            field: "classification.grade.evidence_id",
            reason: "invalid evidence identity".to_owned(),
        });
    }
    for (field, value) in [
        (
            "classification.grade.owner",
            binding.reference.owner.as_str(),
        ),
        (
            "classification.grade.schema",
            binding.reference.schema.as_str(),
        ),
        (
            "classification.grade.revision",
            binding.reference.revision.as_str(),
        ),
    ] {
        if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(ContractViolation::Malformed {
                field,
                reason: "invalid grade reference text".to_owned(),
            });
        }
    }
    if binding.reference.record_id.as_str().trim().is_empty()
        || binding.reference.record_id.as_str().len() > 1024
    {
        return Err(ContractViolation::Malformed {
            field: "classification.grade.record_id",
            reason: "invalid grade record identity".to_owned(),
        });
    }
    if binding.reference.digest.len() != 64
        || !binding
            .reference
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractViolation::Malformed {
            field: "classification.grade.digest",
            reason: "grade digest must be lowercase hex".to_owned(),
        });
    }
    binding
        .assignment
        .validate()
        .map_err(|_| ContractViolation::BindingMismatch {
            field: "classification.grade",
            reason: "invalid C1 GradeAssignment".to_owned(),
        })
}

fn bounded_len(value: usize, field: &'static str) -> Result<u64, ContractViolation> {
    u64::try_from(value).map_err(|_| ContractViolation::Budget {
        dimension: field,
        reason: "count cannot be represented".to_owned(),
    })
}

fn cap(value: u64, max: u64, dimension: &'static str) -> Result<(), ContractViolation> {
    if value > max {
        return Err(ContractViolation::Budget {
            dimension,
            reason: format!("{value} exceeds {max}"),
        });
    }
    Ok(())
}
