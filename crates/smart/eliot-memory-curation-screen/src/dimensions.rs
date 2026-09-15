use std::collections::BTreeSet;

use eliot_memory_curation_contracts::{
    ContractError, CurationDimension, CurationFinding, DimensionOutcome, DimensionVerdict,
    FindingId, MemberDimensions, MemberId, ProtectionAssessment, ProtectionDecision,
};

/// Assesses the five independent curation dimensions for one member.
///
/// Every input is already supplied by the caller: the fail-closed protection
/// assessment, the structural findings observed for the member, the
/// owner-selected target/reference partition role, and the source
/// availability/denominator state. No store is read, no model is invoked, no
/// scalar confidence or utility participates, and no lifecycle transition is
/// proposed: the lifecycle verdict only records whether the member is a
/// reversible forward candidate or an immutable reference.
pub fn assess_dimensions(
    member_id: &MemberId,
    assessment: &ProtectionAssessment,
    findings: &[CurationFinding],
    immutable: bool,
    source_available: bool,
    denominator_complete: bool,
) -> Result<MemberDimensions, ContractError> {
    let mut by_dimension: std::collections::BTreeMap<CurationDimension, BTreeSet<FindingId>> =
        CurationDimension::ALL
            .iter()
            .map(|dimension| (*dimension, BTreeSet::new()))
            .collect();
    for finding in findings
        .iter()
        .filter(|finding| finding.member_id == *member_id)
    {
        by_dimension
            .get_mut(&finding.class.dimension())
            .ok_or(ContractError::Reconciliation {
                field: "dimensions.dimension",
            })?
            .insert(finding.finding_id.clone());
    }
    let flagged = |dimension: CurationDimension| -> bool {
        by_dimension
            .get(&dimension)
            .is_some_and(|ids| !ids.is_empty())
    };
    let verdict = |dimension: CurationDimension, outcome: DimensionOutcome| -> DimensionVerdict {
        // Only a flagged dimension retains finding identities, so a protected
        // or unknown verdict never duplicates a finding already retained in
        // the screen result. The contracts validator enforces this shape.
        let finding_ids = if outcome == DimensionOutcome::Flagged {
            by_dimension.get(&dimension).cloned().unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        DimensionVerdict {
            dimension,
            outcome,
            finding_ids,
        }
    };
    let existence = if flagged(CurationDimension::Existence) {
        DimensionOutcome::Flagged
    } else if !source_available || !denominator_complete {
        DimensionOutcome::Unknown
    } else {
        DimensionOutcome::Clear
    };
    let support = if flagged(CurationDimension::Support) {
        DimensionOutcome::Flagged
    } else {
        DimensionOutcome::Clear
    };
    let lifecycle = if immutable {
        DimensionOutcome::Reference
    } else {
        DimensionOutcome::Clear
    };
    let accessibility = if immutable {
        DimensionOutcome::Reference
    } else {
        match assessment.decision {
            ProtectionDecision::Protected => DimensionOutcome::Protected,
            ProtectionDecision::Unknown => DimensionOutcome::Unknown,
            ProtectionDecision::Unprotected => DimensionOutcome::Clear,
        }
    };
    let influence = match assessment.decision {
        ProtectionDecision::Protected => DimensionOutcome::Protected,
        ProtectionDecision::Unknown => DimensionOutcome::Unknown,
        ProtectionDecision::Unprotected => {
            if flagged(CurationDimension::PermittedInfluence) {
                DimensionOutcome::Flagged
            } else {
                DimensionOutcome::Clear
            }
        }
    };
    let assessed = MemberDimensions {
        member_id: member_id.clone(),
        verdicts: vec![
            verdict(CurationDimension::Existence, existence),
            verdict(CurationDimension::Support, support),
            verdict(CurationDimension::Lifecycle, lifecycle),
            verdict(CurationDimension::Accessibility, accessibility),
            verdict(CurationDimension::PermittedInfluence, influence),
        ],
    };
    assessed.validate()?;
    Ok(assessed)
}
