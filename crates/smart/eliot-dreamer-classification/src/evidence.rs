//! Evidence qualification for semantic classification.
//!
//! This layer only evaluates supplied foundation envelopes and C1 grade
//! assignments. It never retrieves, rewrites, or promotes evidence.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::{ClassificationInput, ContractViolation};
use eliot_epistemic_contracts::{EvidenceGrade, GradeAssignment};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceFreshness,
};

use crate::policy::ClassificationPolicy;

/// The reason a supplied evidence item cannot establish a semantic feature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceQuality {
    Qualified,
    Unknown(String),
    Unsupported(String),
}

/// Retained source and dependence closure for one alternative trace.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvidenceTrace {
    pub evidence_refs: Vec<ArtifactId>,
    pub counterevidence_refs: Vec<ArtifactId>,
    pub source_handles: Vec<ArtifactId>,
    pub dependence_groups: Vec<String>,
    pub grade_floor: Option<EvidenceGrade>,
    pub grade_assignment: Option<GradeAssignment>,
    pub omitted_evidence: Vec<ArtifactId>,
}

/// Validates C1 grade bindings and foundation evidence before selection.
pub fn validate_evidence(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
) -> Result<(), ContractViolation> {
    for evidence in &input.evidence {
        let Some(binding) = policy
            .grade_bindings
            .iter()
            .find(|binding| binding.evidence_id == evidence.id)
        else {
            if evidence.external_grade.is_none() {
                continue;
            }
            return Err(ContractViolation::BindingMismatch {
                field: "classification.grade.reference",
                reason: format!(
                    "evidence {} does not retain the exact grade reference",
                    evidence.id
                ),
            });
        };
        let Some(external_grade) = evidence.external_grade.as_ref() else {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.grade.reference",
                reason: format!(
                    "evidence {} has a binding but no retained grade reference",
                    evidence.id
                ),
            });
        };
        if external_grade != &binding.reference {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.grade.reference",
                reason: format!(
                    "evidence {} does not retain the exact grade reference",
                    evidence.id
                ),
            });
        }
        let assignment_digest = crate::policy::grade_binding_digest(binding)?;
        if binding.reference.digest != assignment_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.grade.digest",
                reason: "grade reference digest does not bind GradeAssignment bytes".to_owned(),
            });
        }
        let assignment = &binding.assignment;
        assignment
            .validate()
            .map_err(|_| ContractViolation::BindingMismatch {
                field: "classification.grade",
                reason: "invalid C1 GradeAssignment".to_owned(),
            })?;
        if let Some(grade) = assignment.known_grade() {
            if grade.rank() < policy.minimum_grade.rank() {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.grade",
                    reason: format!("evidence {} is below minimum grade", evidence.id),
                });
            }
            if grade.rank() > policy.maximum_grade.rank() {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.grade",
                    reason: format!("evidence {} exceeds policy grade ceiling", evidence.id),
                });
            }
        }
    }
    for binding in &policy.grade_bindings {
        if !input
            .evidence
            .iter()
            .any(|evidence| evidence.id == binding.evidence_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.grade",
                reason: format!(
                    "grade binding {} is not retained by input",
                    binding.evidence_id
                ),
            });
        }
    }
    Ok(())
}

/// Classifies one evidence reference without changing the supplied envelope.
pub fn quality(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
    evidence_id: &ArtifactId,
) -> Result<EvidenceQuality, ContractViolation> {
    let evidence = input
        .evidence
        .iter()
        .find(|item| item.id == *evidence_id)
        .ok_or(ContractViolation::BindingMismatch {
            field: "classification.evidence_refs",
            reason: "evidence reference is not retained".to_owned(),
        })?;
    let Some(binding) = policy
        .grade_bindings
        .iter()
        .find(|binding| binding.evidence_id == *evidence_id)
    else {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.grade.reference",
            reason: format!("evidence {evidence_id} has no grade binding"),
        });
    };
    let Some(external_grade) = evidence.external_grade.as_ref() else {
        return Ok(EvidenceQuality::Unknown(
            "external grade reference is missing".to_owned(),
        ));
    };
    if external_grade != &binding.reference {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.grade.reference",
            reason: format!("evidence {evidence_id} does not retain the exact grade reference"),
        });
    }
    if crate::policy::grade_binding_digest(binding)? != binding.reference.digest {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.grade.digest",
            reason: "grade reference digest does not bind GradeAssignment bytes".to_owned(),
        });
    }
    let grade = &binding.assignment;
    let Some(grade) = grade.known_grade() else {
        return Ok(EvidenceQuality::Unknown(
            "C1 evidence grade is unknown".to_owned(),
        ));
    };
    if grade.rank() < policy.minimum_grade.rank() {
        return Ok(EvidenceQuality::Unsupported(
            "evidence grade below policy minimum".to_owned(),
        ));
    }
    let envelope = &evidence.foundation_evidence_envelope;
    if matches!(
        envelope.freshness,
        EvidenceFreshness::Stale
            | EvidenceFreshness::Unknown
            | EvidenceFreshness::KnownOlderSnapshot
    ) {
        return Ok(EvidenceQuality::Unknown(
            "evidence freshness is stale or unknown".to_owned(),
        ));
    }
    if !matches!(
        envelope.status,
        EpistemicStatus::Supported | EpistemicStatus::Verified
    ) {
        return Ok(EvidenceQuality::Unknown(
            "evidence status cannot establish a feature".to_owned(),
        ));
    }
    if envelope.assertability != Assertability::Assertable {
        return Ok(EvidenceQuality::Unsupported(
            "evidence is not assertable".to_owned(),
        ));
    }
    if !matches!(
        envelope.coverage,
        EvidenceCoverage::CompleteForScope | EvidenceCoverage::NotApplicable
    ) {
        return Ok(EvidenceQuality::Unknown(
            "evidence coverage is incomplete".to_owned(),
        ));
    }
    if matches!(
        envelope.authority,
        EvidenceAuthority::SourceIdentity
            | EvidenceAuthority::ModelInterpretation
            | EvidenceAuthority::HeuristicStatic
    ) {
        return Ok(EvidenceQuality::Unsupported(
            "heuristic or model evidence cannot establish class".to_owned(),
        ));
    }
    Ok(EvidenceQuality::Qualified)
}

/// Builds a deterministic trace while deduplicating dependent source groups.
pub fn trace_for(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
    refs: &[ArtifactId],
    counter_refs: &[ArtifactId],
) -> Result<EvidenceTrace, ContractViolation> {
    let mut trace = EvidenceTrace {
        evidence_refs: refs.to_vec(),
        counterevidence_refs: counter_refs.to_vec(),
        ..EvidenceTrace::default()
    };
    let mut grades = Vec::new();
    for id in refs.iter().chain(counter_refs) {
        let evidence = input.evidence.iter().find(|item| item.id == *id).ok_or(
            ContractViolation::BindingMismatch {
                field: "classification.evidence_refs",
                reason: "trace references unretained evidence".to_owned(),
            },
        )?;
        match quality(input, policy, id)? {
            EvidenceQuality::Qualified => {}
            EvidenceQuality::Unknown(_) | EvidenceQuality::Unsupported(_) => {
                trace.omitted_evidence.push(id.clone());
            }
        }
        for handle in &evidence.source_handles {
            if !trace.source_handles.contains(handle) {
                trace.source_handles.push(handle.clone());
            }
        }
        for group in &evidence.dependence_groups {
            if !trace.dependence_groups.contains(group) {
                trace.dependence_groups.push(group.clone());
            }
        }
        if let Some(binding) = policy
            .grade_bindings
            .iter()
            .find(|binding| binding.evidence_id == *id)
        {
            grades.push(binding.assignment.clone());
        } else {
            grades.push(
                GradeAssignment::unknown("missing C1 grade binding").map_err(|_| {
                    ContractViolation::BindingMismatch {
                        field: "classification.grade",
                        reason: "cannot represent unknown grade".to_owned(),
                    }
                })?,
            );
        }
    }
    if !grades.is_empty() {
        let weakest =
            GradeAssignment::weakest(&grades).map_err(|_| ContractViolation::BindingMismatch {
                field: "classification.grade",
                reason: "cannot aggregate grade assignments".to_owned(),
            })?;
        trace.grade_floor = weakest.known_grade();
        trace.grade_assignment = Some(weakest);
    }
    trace
        .source_handles
        .sort_by_key(|id| id.as_str().to_owned());
    trace.dependence_groups.sort();
    trace.evidence_refs.sort_by_key(|id| id.as_str().to_owned());
    trace
        .counterevidence_refs
        .sort_by_key(|id| id.as_str().to_owned());
    trace
        .omitted_evidence
        .sort_by_key(|id| id.as_str().to_owned());
    Ok(trace)
}

/// Returns the set of source/dependence identities that are actually retained.
pub fn retained_source_set(input: &ClassificationInput) -> BTreeSet<String> {
    input
        .target
        .source_handles
        .iter()
        .map(|id| id.as_str().to_owned())
        .chain(
            input
                .evidence
                .iter()
                .flat_map(|e| e.source_handles.iter().map(|id| id.as_str().to_owned())),
        )
        .collect()
}

/// Returns a stable display spelling for a C1 grade assignment.
#[must_use]
pub fn grade_name(assignment: &GradeAssignment) -> &'static str {
    assignment
        .known_grade()
        .map_or("UNKNOWN", EvidenceGrade::wire_name)
}
