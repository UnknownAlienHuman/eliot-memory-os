//! Deterministic necessary/sufficient/exclusion selection over a frozen registry.

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::{
    ClassificationCriterionRole, ClassificationInput, CriterionApplicability, CriterionStatus,
    PriorAssignmentRef, TaxonomyAlternative, TaxonomyCoverage,
};
use eliot_epistemic_contracts::{EvidenceGrade, GradeAssignment};
use serde::{Deserialize, Serialize};

use crate::evidence::{EvidenceQuality, quality};
use crate::policy::ClassificationPolicy;

/// Resolution of one criterion, preserving unknown and contradiction states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CriterionResolution {
    True,
    False,
    Unknown,
    Unsupported,
    Contradicted,
}

/// Evidence-backed explanation for one considered taxonomy alternative.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AlternativeTrace {
    pub alternative_id: ArtifactId,
    pub family: String,
    pub subtype: Option<String>,
    pub supporting_criteria: Vec<ArtifactId>,
    pub excluding_criteria: Vec<ArtifactId>,
    pub unknown_criteria: Vec<ArtifactId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub counterevidence_refs: Vec<ArtifactId>,
    pub grade_floor: Option<EvidenceGrade>,
    pub grade_assignment: Option<GradeAssignment>,
    pub omitted_evidence: Vec<ArtifactId>,
    pub explanation: String,
}

/// The selector result before the candidate closure is assembled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionKind {
    Candidate {
        alternative_id: ArtifactId,
        refinement: bool,
    },
    Duplicate {
        alternative_id: ArtifactId,
    },
    Conflict {
        alternative_id: ArtifactId,
    },
    Ambiguous,
    Incomplete,
    Unsupported,
    Abstention,
}

/// Complete deterministic selection report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionReport {
    pub kind: SelectionKind,
    pub traces: Vec<AlternativeTrace>,
    pub omitted_alternatives: Vec<ArtifactId>,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AlternativeState {
    Qualified,
    RuledOut,
    Unresolved,
}

/// Selects at most one existing alternative using only qualified evidence.
pub fn select(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
) -> Result<SelectionReport, eliot_dreamer_contracts::ContractViolation> {
    input.validate()?;
    policy.preflight(input)?;
    crate::evidence::validate_evidence(input, policy)?;
    if input.taxonomy.coverage != TaxonomyCoverage::Complete {
        return Ok(SelectionReport {
            kind: SelectionKind::Incomplete,
            traces: traces(input, policy)?,
            omitted_alternatives: input.taxonomy.omitted_alternative_ids.clone(),
            reason: "taxonomy denominator is partial or unknown".to_owned(),
        });
    }
    let mut traces = Vec::with_capacity(input.taxonomy.alternatives.len());
    let mut eligible = Vec::new();
    let mut unresolved_rival = false;
    for alternative in &input.taxonomy.alternatives {
        let (trace, state) = evaluate(alternative, input, policy)?;
        if state == AlternativeState::Qualified {
            eligible.push(alternative.alternative_id.clone());
        }
        if state == AlternativeState::Unresolved {
            unresolved_rival = true;
        }
        traces.push(trace);
    }
    if eligible.len() > 1 {
        return Ok(SelectionReport {
            kind: SelectionKind::Ambiguous,
            traces,
            omitted_alternatives: Vec::new(),
            reason: "multiple alternatives satisfy the grounded rules".to_owned(),
        });
    }
    let sole_legal = input.taxonomy.alternatives.len() == 1
        && input.taxonomy.declared_alternative_ids.len() == 1;
    let selected = eligible.first().cloned();
    let Some(selected) = selected else {
        return Ok(SelectionReport {
            kind: if unresolved_rival {
                SelectionKind::Abstention
            } else {
                SelectionKind::Unsupported
            },
            traces,
            omitted_alternatives: Vec::new(),
            reason: if unresolved_rival {
                "a live rival has unknown or partial discriminators".to_owned()
            } else {
                "no alternative has qualified necessary and sufficient evidence".to_owned()
            },
        });
    };
    if unresolved_rival && !sole_legal {
        return Ok(SelectionReport {
            kind: SelectionKind::Abstention,
            traces,
            omitted_alternatives: Vec::new(),
            reason: "an alternative retains unknown or partial live evidence".to_owned(),
        });
    }
    let refinement = input
        .prior_assignment
        .as_ref()
        .is_some_and(|prior| is_refinement(prior, &selected, input));
    let kind = match input.prior_assignment.as_ref() {
        Some(prior)
            if prior.selected_alternative_id.as_ref() == Some(&selected)
                && prior.selected_family.as_deref()
                    == alternative(input, &selected).map(|a| a.family.as_str())
                && prior.selected_subtype.as_deref()
                    == alternative(input, &selected).and_then(|a| a.subtype_ref.as_deref()) =>
        {
            SelectionKind::Duplicate {
                alternative_id: selected,
            }
        }
        Some(_) if refinement => SelectionKind::Candidate {
            alternative_id: selected,
            refinement: true,
        },
        Some(_) => SelectionKind::Conflict {
            alternative_id: selected,
        },
        None => SelectionKind::Candidate {
            alternative_id: selected,
            refinement: false,
        },
    };
    Ok(SelectionReport {
        kind,
        traces,
        omitted_alternatives: Vec::new(),
        reason: "grounded discriminator set selected a known alternative".to_owned(),
    })
}

fn traces(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
) -> Result<Vec<AlternativeTrace>, eliot_dreamer_contracts::ContractViolation> {
    input
        .taxonomy
        .alternatives
        .iter()
        .map(|a| evaluate(a, input, policy).map(|(trace, _)| trace))
        .collect()
}

fn evaluate(
    alternative: &TaxonomyAlternative,
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
) -> Result<(AlternativeTrace, AlternativeState), eliot_dreamer_contracts::ContractViolation> {
    let mut state = EvalState::default();
    for criterion_id in &alternative.criterion_refs {
        let Some(criterion) = input
            .taxonomy
            .criteria
            .iter()
            .find(|c| c.criterion_id == *criterion_id)
        else {
            state.unknown.push(criterion_id.clone());
            state.set(UNCERTAIN);
            continue;
        };
        inspect_criterion(criterion_id, criterion, input, policy, &mut state)?;
    }
    let eligible = !state.has(NECESSARY_FALSE)
        && !state.has(NECESSARY_UNKNOWN)
        && !state.has(EXCLUDED)
        && state.has(HAS_SUFFICIENT)
        && !state.has(UNCERTAIN);
    let alternative_state = if state.has(NECESSARY_FALSE) || state.has(EXCLUDED) {
        AlternativeState::RuledOut
    } else if eligible {
        AlternativeState::Qualified
    } else {
        AlternativeState::Unresolved
    };
    let explanation = format!(
        "necessary={}, sufficient={}, exclusion={}, unknown={}",
        !state.has(NECESSARY_FALSE) && !state.has(NECESSARY_UNKNOWN),
        state.has(HAS_SUFFICIENT),
        state.has(EXCLUDED),
        state.has(UNCERTAIN) || state.has(NECESSARY_UNKNOWN) || !state.has(HAS_SUFFICIENT_RULE)
    );
    let refs = unique_refs(input, alternative);
    let evidence_trace =
        crate::evidence::trace_for(input, policy, &refs, &alternative.counterevidence_refs)?;
    state.supporting.sort();
    state.excluding.sort();
    state.unknown.sort();
    Ok((
        AlternativeTrace {
            alternative_id: alternative.alternative_id.clone(),
            family: alternative.family.as_str().to_owned(),
            subtype: alternative.subtype_ref.clone(),
            supporting_criteria: state.supporting,
            excluding_criteria: state.excluding,
            unknown_criteria: state.unknown,
            evidence_refs: refs,
            counterevidence_refs: evidence_trace.counterevidence_refs,
            grade_floor: evidence_trace.grade_floor,
            grade_assignment: evidence_trace.grade_assignment,
            omitted_evidence: evidence_trace.omitted_evidence,
            explanation,
        },
        alternative_state,
    ))
}

#[derive(Default)]
struct EvalState {
    supporting: Vec<ArtifactId>,
    excluding: Vec<ArtifactId>,
    unknown: Vec<ArtifactId>,
    flags: u8,
}

const NECESSARY_FALSE: u8 = 1;
const NECESSARY_UNKNOWN: u8 = 2;
const HAS_SUFFICIENT: u8 = 4;
const HAS_SUFFICIENT_RULE: u8 = 8;
const UNCERTAIN: u8 = 16;
const EXCLUDED: u8 = 32;

impl EvalState {
    fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
    fn set(&mut self, flag: u8) {
        self.flags |= flag;
    }
}

fn inspect_criterion(
    criterion_id: &ArtifactId,
    criterion: &eliot_dreamer_contracts::GroundedCriterion,
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
    state: &mut EvalState,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    let grounding_ok = criterion.applicability == CriterionApplicability::Required
        && !criterion.evidence_refs.is_empty()
        && criterion
            .evidence_refs
            .iter()
            .try_fold(true, |ok, evidence_id| {
                Ok::<bool, eliot_dreamer_contracts::ContractViolation>(
                    ok && matches!(
                        quality(input, policy, evidence_id)?,
                        EvidenceQuality::Qualified
                    ),
                )
            })?;
    if !grounding_ok {
        state.set(UNCERTAIN);
        push_unique(&mut state.unknown, criterion_id);
    }
    let resolution = if grounding_ok {
        resolve_criterion(input, policy, criterion_id)?
    } else {
        CriterionResolution::Unknown
    };
    match criterion.role {
        ClassificationCriterionRole::Necessary => {
            if resolution == CriterionResolution::False {
                state.set(NECESSARY_FALSE);
            }
            if matches!(
                resolution,
                CriterionResolution::Unknown
                    | CriterionResolution::Unsupported
                    | CriterionResolution::Contradicted
            ) {
                state.set(NECESSARY_UNKNOWN);
            }
        }
        ClassificationCriterionRole::Sufficient => {
            state.set(HAS_SUFFICIENT_RULE);
            if resolution == CriterionResolution::True {
                state.set(HAS_SUFFICIENT);
            }
            if matches!(
                resolution,
                CriterionResolution::Unknown
                    | CriterionResolution::Unsupported
                    | CriterionResolution::Contradicted
            ) {
                state.set(UNCERTAIN);
            }
        }
        ClassificationCriterionRole::Characteristic => {
            if matches!(
                resolution,
                CriterionResolution::Unknown
                    | CriterionResolution::Unsupported
                    | CriterionResolution::Contradicted
            ) {
                state.set(UNCERTAIN);
            }
        }
        ClassificationCriterionRole::Exclusion => {
            if resolution == CriterionResolution::True {
                state.set(EXCLUDED);
            }
            if matches!(
                resolution,
                CriterionResolution::Unknown
                    | CriterionResolution::Unsupported
                    | CriterionResolution::Contradicted
            ) {
                state.set(UNCERTAIN);
            }
        }
    }
    match (criterion.role, resolution) {
        (ClassificationCriterionRole::Necessary, CriterionResolution::False)
        | (ClassificationCriterionRole::Exclusion, CriterionResolution::True) => {
            state.excluding.push(criterion_id.clone());
        }
        (_, CriterionResolution::True) => state.supporting.push(criterion_id.clone()),
        (
            _,
            CriterionResolution::Unknown
            | CriterionResolution::Unsupported
            | CriterionResolution::Contradicted,
        ) => push_unique(&mut state.unknown, criterion_id),
        _ => {}
    }
    Ok(())
}

fn push_unique(values: &mut Vec<ArtifactId>, value: &ArtifactId) {
    if !values.contains(value) {
        values.push(value.clone());
    }
}

fn resolve_criterion(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
    criterion_id: &ArtifactId,
) -> Result<CriterionResolution, eliot_dreamer_contracts::ContractViolation> {
    let features: Vec<_> = input
        .features
        .iter()
        .filter(|f| f.criterion_id == *criterion_id)
        .collect();
    if features.is_empty() {
        return Ok(CriterionResolution::Unknown);
    }
    let mut observed = None;
    for feature in features {
        if feature.applicability != CriterionApplicability::Required
            || feature.evidence_refs.is_empty()
        {
            return Ok(CriterionResolution::Unknown);
        }
        let mut evidence_state = CriterionResolution::True;
        for evidence_id in &feature.evidence_refs {
            match quality(input, policy, evidence_id)? {
                EvidenceQuality::Qualified => {}
                EvidenceQuality::Unknown(_) => return Ok(CriterionResolution::Unknown),
                EvidenceQuality::Unsupported(_) => {
                    evidence_state = CriterionResolution::Unsupported;
                }
            }
        }
        let current = if evidence_state == CriterionResolution::Unsupported {
            evidence_state
        } else {
            match (feature.value, feature.status) {
                (Some(true), CriterionStatus::Supported) => CriterionResolution::True,
                (Some(false), CriterionStatus::Supported) => CriterionResolution::False,
                (Some(true | false), CriterionStatus::Partial | CriterionStatus::Unknown)
                | (None, _) => CriterionResolution::Unknown,
                (_, CriterionStatus::Unsupported) => CriterionResolution::Unsupported,
                (_, CriterionStatus::Contradicted) => CriterionResolution::Contradicted,
            }
        };
        if let Some(previous) = observed
            && previous != current
        {
            return Ok(CriterionResolution::Unknown);
        }
        observed = Some(current);
    }
    Ok(observed.unwrap_or(CriterionResolution::Unknown))
}

fn unique_refs(input: &ClassificationInput, alternative: &TaxonomyAlternative) -> Vec<ArtifactId> {
    let mut refs = alternative.evidence_refs.clone();
    for criterion_id in &alternative.criterion_refs {
        if let Some(criterion) = input
            .taxonomy
            .criteria
            .iter()
            .find(|c| c.criterion_id == *criterion_id)
        {
            refs.extend(criterion.evidence_refs.iter().cloned());
            refs.extend(
                input
                    .features
                    .iter()
                    .filter(|f| f.criterion_id == *criterion_id)
                    .flat_map(|f| f.evidence_refs.iter().cloned()),
            );
        }
    }
    refs.sort_by_key(|id| id.as_str().to_owned());
    refs.dedup();
    refs
}

fn alternative<'a>(
    input: &'a ClassificationInput,
    id: &ArtifactId,
) -> Option<&'a TaxonomyAlternative> {
    input
        .taxonomy
        .alternatives
        .iter()
        .find(|alternative| alternative.alternative_id == *id)
}

fn is_refinement(
    prior: &PriorAssignmentRef,
    selected: &ArtifactId,
    input: &ClassificationInput,
) -> bool {
    let Some(previous) = prior.selected_alternative_id.as_ref() else {
        return false;
    };
    let Some(alternative) = input
        .taxonomy
        .alternatives
        .iter()
        .find(|a| a.alternative_id == *selected)
    else {
        return false;
    };
    prior.selected_family.as_deref() == Some(alternative.family.as_str())
        && input.taxonomy.alias_mappings.iter().any(|mapping| {
            mapping.canonical_alternative_id == *selected
                && mapping.refinement_of.as_ref() == Some(previous)
        })
}
