use std::collections::{BTreeMap, BTreeSet};

use eliot_memory_curation_contracts::{
    ContractError, CurationScreenRequest, ProtectionAssessment, ProtectionDecision,
    ProtectionEvidence, ProtectionEvidenceState, ProtectionOutcome, RuleId, SourceSnapshot,
};

fn required_rules(request: &CurationScreenRequest) -> BTreeSet<RuleId> {
    request
        .profile
        .rules
        .iter()
        .map(|rule| rule.rule_id.clone())
        .collect()
}

fn required_classes(
    request: &CurationScreenRequest,
) -> BTreeSet<eliot_memory_curation_contracts::ProtectionClass> {
    request
        .profile
        .rules
        .iter()
        .flat_map(|rule| rule.required_protection.iter().copied())
        .collect()
}

fn assessment_for_member(
    source: &SourceSnapshot,
    member_id: &eliot_memory_curation_contracts::MemberId,
    evidence: &[ProtectionEvidence],
    all_rules: &BTreeSet<RuleId>,
    required: &BTreeSet<eliot_memory_curation_contracts::ProtectionClass>,
) -> Result<ProtectionAssessment, ContractError> {
    let member_evidence = evidence
        .iter()
        .filter(|item| item.member_id == *member_id)
        .cloned()
        .collect::<Vec<_>>();
    let mut positive = false;
    let mut uncertain = false;
    let mut clear = BTreeSet::new();
    for item in &member_evidence {
        if item.state != ProtectionEvidenceState::CurrentVerified || item.invalidated_by.is_some() {
            uncertain = true;
        } else {
            match item.outcome {
                ProtectionOutcome::Present => positive = true,
                ProtectionOutcome::Absent => {
                    clear.insert(item.class);
                }
                ProtectionOutcome::Unknown => uncertain = true,
            }
        }
    }
    let decision = if positive {
        ProtectionDecision::Protected
    } else if uncertain || required.iter().any(|class| !clear.contains(class)) {
        ProtectionDecision::Unknown
    } else {
        ProtectionDecision::Unprotected
    };
    let assessment = ProtectionAssessment {
        source: source.identity.clone(),
        member_id: member_id.clone(),
        applicable_rule_ids: all_rules.clone(),
        required: required.clone(),
        evidence: member_evidence,
        decision,
    };
    assessment.validate()?;
    Ok(assessment)
}

/// Derives canonical A19c protection assessments from owner evidence. No
/// evidence is fabricated: a missing or uncertain required class is Unknown.
pub(crate) fn derive_protection_assessments(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    evidence: &[ProtectionEvidence],
) -> Result<Vec<ProtectionAssessment>, ContractError> {
    let mut seen = BTreeSet::new();
    let member_ids = source.member_ids();
    let mut grouped = BTreeMap::new();
    for item in evidence {
        item.validate(&source.identity)?;
        if !member_ids.contains(&item.member_id) {
            return Err(ContractError::BindingMismatch {
                field: "protection.member",
            });
        }
        if !seen.insert(item.evidence_id.clone()) {
            return Err(ContractError::Duplicate {
                field: "protection.evidence",
            });
        }
        grouped
            .entry(item.member_id.clone())
            .or_insert_with(Vec::new)
            .push(item.clone());
    }
    for member_evidence in grouped.values_mut() {
        member_evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    }
    let all_rules = required_rules(request);
    let required = required_classes(request);
    source
        .members
        .iter()
        .map(|member| {
            assessment_for_member(
                source,
                &member.member_id,
                grouped.get(&member.member_id).map_or(&[], Vec::as_slice),
                &all_rules,
                &required,
            )
        })
        .collect()
}
