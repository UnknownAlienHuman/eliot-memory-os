//! Evidence and denominator accounting for one Concept proposal.

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::{
    ConceptCaseKind, ConceptCoverage, ConceptDisposition, ConceptInput, ConceptMode,
    ConceptProposal, ContractViolation, CriterionStatus,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceFreshness,
};

/// Immutable ledger of evidence roles and explicit omissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceLedger {
    pub evidence_ids: Vec<ArtifactId>,
    pub source_ids: Vec<ArtifactId>,
    pub independent_groups: Vec<String>,
    pub strong_evidence: Vec<ArtifactId>,
    pub strong_source_ids: Vec<ArtifactId>,
    pub independent_support: bool,
    pub supported_criteria: usize,
    pub uncertain_criteria: usize,
    pub contradicted_criteria: usize,
    pub qualified_contradictions: usize,
    pub qualified_counterexamples: usize,
    pub positive_cases: usize,
    pub counterexamples: usize,
    pub borderline_cases: usize,
    pub unknown_cases: usize,
    pub omitted_sources: usize,
    pub omitted_cases: usize,
    pub coverage_complete: bool,
}

/// Semantic assessment retained for deterministic synthesis.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceAssessment {
    pub grounded_definition: bool,
    pub discriminator_supported: bool,
    pub has_counterevidence: bool,
    pub has_unknowns: bool,
    pub has_contradiction: bool,
    pub partial_scope: bool,
}

/// Builds an evidence ledger after structural A03 validation.
pub fn build_ledger(input: &ConceptInput) -> Result<EvidenceLedger, ContractViolation> {
    input.validate()?;
    let (evidence_ids, groups) = evidence_identity(input);
    let source_ids = source_identity(input);
    let mut ledger = EvidenceLedger {
        evidence_ids,
        source_ids,
        independent_groups: groups,
        strong_evidence: Vec::new(),
        strong_source_ids: Vec::new(),
        independent_support: false,
        supported_criteria: 0,
        uncertain_criteria: 0,
        contradicted_criteria: 0,
        qualified_contradictions: 0,
        qualified_counterexamples: 0,
        positive_cases: 0,
        counterexamples: 0,
        borderline_cases: 0,
        unknown_cases: 0,
        omitted_sources: input.sources.denominator.omitted.len(),
        omitted_cases: input.proposal.case_omitted_refs.len(),
        coverage_complete: input.sources.denominator.coverage == ConceptCoverage::Complete
            && input.proposal.case_coverage == ConceptCoverage::Complete
            && input.neighborhood.coverage == ConceptCoverage::Complete
            && input.neighborhood.omitted_refs.is_empty(),
    };
    ledger.strong_evidence = strong_evidence(input);
    for evidence in &input.proposal.evidence {
        if ledger.strong_evidence.contains(evidence.evidence_id()) {
            for source_id in &evidence.source_refs {
                if !ledger.strong_source_ids.contains(source_id) {
                    ledger.strong_source_ids.push(source_id.clone());
                }
            }
        }
    }
    count_criteria(input, &mut ledger)?;
    count_cases(input, &mut ledger)?;
    Ok(ledger)
}

fn evidence_identity(input: &ConceptInput) -> (Vec<ArtifactId>, Vec<String>) {
    let mut evidence_ids = Vec::with_capacity(input.proposal.evidence.len());
    let mut groups = Vec::new();
    for evidence in &input.proposal.evidence {
        evidence_ids.push(evidence.evidence_id().clone());
        for group in &evidence.named.dependence_groups {
            if !groups.contains(group) {
                groups.push(group.clone());
            }
        }
    }
    (evidence_ids, groups)
}

fn source_identity(input: &ConceptInput) -> Vec<ArtifactId> {
    input
        .sources
        .sources
        .iter()
        .map(|source| source.source_id.clone())
        .collect()
}

fn strong_evidence(input: &ConceptInput) -> Vec<ArtifactId> {
    input
        .proposal
        .evidence
        .iter()
        .filter(|evidence| evidence_is_strong(evidence))
        .map(|evidence| evidence.evidence_id().clone())
        .collect()
}

/// Returns whether one retained evidence item has a qualified own provenance.
pub(crate) fn evidence_is_strong(evidence: &eliot_dreamer_contracts::ConceptEvidence) -> bool {
    let envelope = &evidence.named.foundation_evidence_envelope;
    matches!(
        envelope.status,
        EpistemicStatus::Supported | EpistemicStatus::Verified
    ) && matches!(
        envelope.freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    ) && matches!(
        envelope.coverage,
        EvidenceCoverage::CompleteForScope | EvidenceCoverage::NotApplicable
    ) && envelope.assertability == Assertability::Assertable
        && !matches!(
            envelope.authority,
            EvidenceAuthority::ModelInterpretation
                | EvidenceAuthority::HeuristicStatic
                | EvidenceAuthority::SourceIdentity
        )
        && evidence
            .source_refs
            .iter()
            .any(|id| id.as_str() == envelope.provenance.source_id.as_str())
}

fn count_criteria(
    input: &ConceptInput,
    ledger: &mut EvidenceLedger,
) -> Result<(), ContractViolation> {
    for criterion in &input.proposal.criteria {
        let qualified = !criterion.evidence_refs.is_empty()
            && criterion
                .evidence_refs
                .iter()
                .chain(&criterion.exception_refs)
                .all(|id| ledger.strong_evidence.contains(id));
        match criterion.status {
            CriterionStatus::Supported => {
                let counter = if qualified {
                    &mut ledger.supported_criteria
                } else {
                    &mut ledger.uncertain_criteria
                };
                checked_increment(counter, "concept.criteria")?;
            }
            CriterionStatus::Partial | CriterionStatus::Unsupported | CriterionStatus::Unknown => {
                checked_increment(&mut ledger.uncertain_criteria, "concept.criteria")?;
            }
            CriterionStatus::Contradicted => {
                checked_increment(&mut ledger.contradicted_criteria, "concept.criteria")?;
                if qualified {
                    checked_increment(&mut ledger.qualified_contradictions, "concept.criteria")?;
                } else {
                    checked_increment(&mut ledger.uncertain_criteria, "concept.criteria")?;
                }
            }
        }
    }
    Ok(())
}

fn count_cases(input: &ConceptInput, ledger: &mut EvidenceLedger) -> Result<(), ContractViolation> {
    for case in &input.proposal.cases {
        let qualified = !case.evidence_refs.is_empty()
            && case.evidence_refs.iter().all(|id| {
                input.proposal.evidence.iter().any(|evidence| {
                    evidence.evidence_id() == id
                        && evidence.source_refs.contains(&case.source_ref)
                        && ledger.strong_evidence.contains(id)
                })
            });
        match case.kind {
            ConceptCaseKind::Positive if qualified => {
                checked_increment(&mut ledger.positive_cases, "concept.cases")?;
            }
            ConceptCaseKind::Positive | ConceptCaseKind::Unknown => {
                checked_increment(&mut ledger.unknown_cases, "concept.cases")?;
            }
            ConceptCaseKind::Counterexample => {
                checked_increment(&mut ledger.counterexamples, "concept.cases")?;
                if qualified {
                    checked_increment(&mut ledger.qualified_counterexamples, "concept.cases")?;
                } else {
                    checked_increment(&mut ledger.unknown_cases, "concept.cases")?;
                }
            }
            ConceptCaseKind::Borderline => {
                checked_increment(&mut ledger.borderline_cases, "concept.cases")?;
            }
        }
    }
    Ok(())
}

impl EvidenceLedger {
    /// Evaluates grounding without treating repetition or prose as proof.
    #[must_use]
    pub fn assess(&self, proposal: &ConceptProposal, _mode: ConceptMode) -> EvidenceAssessment {
        let criterion_grounded = |criterion: &eliot_dreamer_contracts::ConceptCriterion| {
            !criterion.statement.trim().is_empty()
                && !criterion.evidence_refs.is_empty()
                && criterion
                    .evidence_refs
                    .iter()
                    .chain(&criterion.exception_refs)
                    .all(|id| self.strong_evidence.contains(id))
        };
        let mandatory_supported = proposal.criteria.iter().all(|criterion| {
            !matches!(
                criterion.applicability,
                eliot_dreamer_contracts::CriterionApplicability::Required
                    | eliot_dreamer_contracts::CriterionApplicability::Conditional
            ) || criterion.status == CriterionStatus::Supported
        });
        let grounded_definition = !proposal.name.trim().is_empty()
            && !proposal.definition.trim().is_empty()
            && !proposal.criteria.is_empty()
            && proposal.criteria.iter().all(criterion_grounded)
            && mandatory_supported
            && !proposal.applicability.source_refs.is_empty()
            && proposal
                .applicability
                .source_refs
                .iter()
                .all(|id| self.strong_source_ids.contains(id))
            && self.supported_criteria > 0
            && !self.evidence_ids.is_empty();
        let discriminator_supported = !proposal
            .discriminator
            .predicted_distinction
            .trim()
            .is_empty()
            && !proposal
                .discriminator
                .falsification_condition
                .trim()
                .is_empty()
            && !proposal.discriminator.evidence_refs.is_empty()
            && proposal
                .discriminator
                .evidence_refs
                .iter()
                .all(|id| self.strong_evidence.contains(id));
        let has_unknowns = self.uncertain_criteria > 0
            || self.borderline_cases > 0
            || self.unknown_cases > 0
            || self.omitted_sources > 0
            || self.omitted_cases > 0
            || !self.independent_support
            || self.qualified_counterexamples < self.counterexamples;
        let partial_scope = !self.coverage_complete || self.counterexamples > 0;
        EvidenceAssessment {
            grounded_definition,
            discriminator_supported,
            has_counterevidence: self.qualified_counterexamples > 0
                || self.qualified_contradictions > 0,
            has_unknowns,
            has_contradiction: self.qualified_contradictions > 0,
            partial_scope,
        }
    }

    /// Chooses a conservative local disposition from the retained ledger.
    #[must_use]
    pub fn disposition(assessment: EvidenceAssessment) -> ConceptDisposition {
        if assessment.has_contradiction {
            return ConceptDisposition::Conflict;
        }
        if !assessment.grounded_definition {
            return ConceptDisposition::Insufficient;
        }
        if assessment.has_unknowns || assessment.partial_scope {
            return ConceptDisposition::Hypothesis;
        }
        ConceptDisposition::Candidate
    }
}

fn checked_increment(value: &mut usize, field: &'static str) -> Result<(), ContractViolation> {
    *value = value.checked_add(1).ok_or(ContractViolation::Budget {
        dimension: field,
        reason: "ledger counter overflow".to_owned(),
    })?;
    Ok(())
}
