use std::collections::{BTreeMap, BTreeSet};

use eliot_memory_curation_contracts::{
    ContractError, CurationFinding, CurationScreenRequest, CurationScreenResult, Eligibility,
    EligibilityStatus, FindingClass, FindingId, FindingProof, MemberCoverage, MemberDisposition,
    MemberSets, ProtectionAssessment, ProtectionDecision, ResultState, ScreenCoverage,
    ScreenFrontier, SourceAvailability, SourceMember, SourceSnapshot, WorkUsage, contract_digest,
};
use serde::Serialize;
use thiserror::Error;

use crate::{bounds, protection, rules};

/// Errors returned by the pure screening boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CurationScreenError {
    /// The caller requested cancellation; no screen result was fabricated.
    #[error("screen cancelled before bounded evaluation")]
    Cancelled,
    /// The supplied records do not satisfy the canonical contract.
    #[error("screen contract error: {0}")]
    Contract(#[from] ContractError),
}

#[derive(Serialize)]
struct FindingPayload<'a> {
    source: &'a eliot_memory_curation_contracts::SourceIdentity,
    profile_id: &'a eliot_memory_curation_contracts::ProfileId,
    member_id: &'a eliot_memory_curation_contracts::MemberId,
    rule_id: &'a eliot_memory_curation_contracts::RuleId,
    class: FindingClass,
    evidence: &'a BTreeSet<eliot_contracts::ArtifactId>,
    invariant: &'a str,
    proof: FindingProof,
}

fn finding(
    request: &CurationScreenRequest,
    member: &SourceMember,
    rule: &eliot_memory_curation_contracts::RuleSpec,
    class: FindingClass,
    evidence: BTreeSet<eliot_contracts::ArtifactId>,
    invariant: &'static str,
) -> Result<CurationFinding, ContractError> {
    let proof = FindingProof::Deterministic;
    let digest = contract_digest(&FindingPayload {
        source: &request.source,
        profile_id: &request.profile.profile_id,
        member_id: &member.member_id,
        rule_id: &rule.rule_id,
        class,
        evidence: &evidence,
        invariant,
        proof,
    })?;
    Ok(CurationFinding {
        finding_id: FindingId::new(digest.as_str())?,
        source: request.source.clone(),
        profile_id: request.profile.profile_id.clone(),
        member_id: member.member_id.clone(),
        rule_id: rule.rule_id.clone(),
        class,
        evidence,
        invariant: invariant.to_owned(),
        proof,
        invalidated_by: None,
        digest,
    })
}

fn structural_findings(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    protection: &[ProtectionAssessment],
    resolved: &[(
        eliot_memory_curation_contracts::RuleSpec,
        rules::SupportedRule,
    )],
) -> Result<Vec<CurationFinding>, ContractError> {
    let mut findings = Vec::new();
    for member in &source.members {
        let unprotected = protection
            .iter()
            .find(|item| item.member_id == member.member_id)
            .is_some_and(|item| item.decision == ProtectionDecision::Unprotected);
        if !unprotected || source.availability != SourceAvailability::Available {
            continue;
        }
        for (rule, supported) in resolved {
            match supported {
                rules::SupportedRule::ProvenanceGap if member.evidence.provenance.is_empty() => {
                    findings.push(finding(
                        request,
                        member,
                        rule,
                        FindingClass::ProvenanceGap,
                        BTreeSet::new(),
                        "member has no supplied provenance handle",
                    )?);
                }
                rules::SupportedRule::ConflictAmbiguity if !member.evidence.conflict.is_empty() => {
                    findings.push(finding(
                        request,
                        member,
                        rule,
                        FindingClass::ConflictAmbiguity,
                        member.evidence.conflict.clone(),
                        "member retains one or more conflict references",
                    )?);
                }
                _ => {}
            }
        }
    }
    Ok(findings)
}

fn source_status(availability: SourceAvailability) -> EligibilityStatus {
    match availability {
        SourceAvailability::Available => EligibilityStatus::EligibleForSemanticCuration,
        SourceAvailability::Partial => EligibilityStatus::IncompleteTruncated,
        SourceAvailability::Stale | SourceAvailability::Unavailable => {
            EligibilityStatus::StaleUnavailable
        }
        SourceAvailability::Blocked
        | SourceAvailability::Malformed
        | SourceAvailability::Unknown => EligibilityStatus::UnknownBlocked,
    }
}

fn member_decision(
    request: &CurationScreenRequest,
    member_id: &eliot_memory_curation_contracts::MemberId,
    assessment: &ProtectionAssessment,
    findings: &BTreeSet<FindingId>,
    base_status: EligibilityStatus,
) -> (EligibilityStatus, bool, MemberDisposition) {
    let immutable = request.partition.immutable_references.contains(member_id);
    let status = if immutable {
        EligibilityStatus::OutsideScope
    } else if !findings.is_empty() {
        EligibilityStatus::UnknownBlocked
    } else if base_status != EligibilityStatus::EligibleForSemanticCuration {
        base_status
    } else {
        match assessment.decision {
            ProtectionDecision::Protected => EligibilityStatus::Protected,
            ProtectionDecision::Unknown => EligibilityStatus::UnknownBlocked,
            ProtectionDecision::Unprotected => EligibilityStatus::EligibleForSemanticCuration,
        }
    };
    let eligible = status == EligibilityStatus::EligibleForSemanticCuration
        && assessment.decision == ProtectionDecision::Unprotected
        && !immutable;
    let disposition = if immutable {
        MemberDisposition::PreservedReference
    } else if eligible {
        MemberDisposition::Eligible
    } else if assessment.decision == ProtectionDecision::Protected {
        MemberDisposition::Protected
    } else {
        MemberDisposition::Blocked
    };
    (status, eligible, disposition)
}

fn eligibility_and_coverage(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    protection: &[ProtectionAssessment],
    findings: &[CurationFinding],
) -> Result<(Vec<Eligibility>, ScreenCoverage, ResultState), ContractError> {
    let mut finding_ids = BTreeMap::<_, BTreeSet<_>>::new();
    for item in findings {
        finding_ids
            .entry(item.member_id.clone())
            .or_default()
            .insert(item.finding_id.clone());
    }

    let mut eligibility = Vec::with_capacity(source.members.len());
    let mut coverage_members = Vec::with_capacity(source.members.len());
    let mut blocked = matches!(
        source.availability,
        SourceAvailability::Stale
            | SourceAvailability::Unavailable
            | SourceAvailability::Blocked
            | SourceAvailability::Malformed
            | SourceAvailability::Unknown
    );
    for assessment in protection {
        if assessment.decision == ProtectionDecision::Unknown {
            blocked = true;
        }
    }
    let base_status = if source.denominator.is_complete() {
        source_status(source.availability)
    } else {
        EligibilityStatus::IncompleteTruncated
    };
    for member in &source.members {
        let assessment = protection
            .iter()
            .find(|item| item.member_id == member.member_id)
            .ok_or(ContractError::BindingMismatch {
                field: "screen.protection.member",
            })?;
        let member_findings = finding_ids
            .get(&member.member_id)
            .cloned()
            .unwrap_or_default();
        let (status, eligible, disposition) = member_decision(
            request,
            &member.member_id,
            assessment,
            &member_findings,
            base_status,
        );
        eligibility.push(Eligibility {
            source: source.identity.clone(),
            member_id: member.member_id.clone(),
            protection: assessment.decision,
            finding_ids: member_findings.clone(),
            status,
        });
        coverage_members.push(MemberCoverage {
            member_id: member.member_id.clone(),
            disposition,
            finding_ids: member_findings,
            eligible,
        });
    }
    let processed_items =
        u64::try_from(coverage_members.len()).map_err(|_| ContractError::Bound {
            field: "coverage.processed_items",
        })?;
    let frontier = ScreenFrontier {
        complete: !blocked && source.denominator.is_complete(),
        remaining: Vec::new(),
    };
    let state = if blocked {
        ResultState::Blocked
    } else if source.denominator.is_complete() {
        ResultState::Complete
    } else {
        ResultState::Partial
    };
    let coverage = ScreenCoverage {
        denominator: source.denominator.clone(),
        start_position: 0,
        members: coverage_members,
        frontier,
        usage: WorkUsage {
            processed_items,
            work_units: 0,
            input_bytes: 0,
            output_bytes: 0,
        },
        next_cursor: None,
        digest: eliot_memory_curation_contracts::Digest::new("0".repeat(64))?,
    };
    Ok((eligibility, coverage, state))
}

fn seal_result(
    mut result: CurationScreenResult,
    input_bytes: u64,
    work_units: u64,
) -> Result<CurationScreenResult, ContractError> {
    let max_output = result
        .request
        .profile
        .limits
        .max_output_bytes
        .min(bounds::MAX_OUTPUT_BYTES);
    result.coverage.usage.input_bytes = input_bytes;
    result.coverage.usage.work_units = work_units;
    // Updating usage changes only a decimal counter. Twenty-one passes cover
    // every possible u64 digit width plus one final stability check.
    for _ in 0..21 {
        result.coverage.digest = result.coverage.computed_digest()?;
        result.result_digest = result.computed_digest()?;
        let encoded = eliot_contracts::canonical_json_bytes(&result)
            .map_err(|error| ContractError::Canonicalization(error.to_string()))?;
        let output_bytes = u64::try_from(encoded.len()).map_err(|_| ContractError::Bound {
            field: "result.output_bytes",
        })?;
        if output_bytes > max_output {
            return Err(ContractError::Bound {
                field: "result.output_bytes",
            });
        }
        if result.coverage.usage.output_bytes == output_bytes {
            result.validate()?;
            return Ok(result);
        }
        result.coverage.usage.output_bytes = output_bytes;
    }
    Err(ContractError::Reconciliation {
        field: "result.output_bytes",
    })
}

fn validate_preconditions(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
) -> Result<(), CurationScreenError> {
    if request.cursor.is_some() {
        return Err(ContractError::Unsupported {
            field: "request.cursor",
        }
        .into());
    }
    if request.profile.limits.deadline_ms.is_some()
        || request.profile.limits.cancellation_grace_ms.is_some()
    {
        return Err(ContractError::Unsupported {
            field: "profile.limits.time",
        }
        .into());
    }
    if request.cancellation_requested {
        return Err(CurationScreenError::Cancelled);
    }
    if source.page.has_more || !source.page.frontier.is_empty() {
        return Err(ContractError::Unsupported {
            field: "source.page.frontier",
        }
        .into());
    }
    if source.members.len() != source.denominator.declared_member_ids.len() {
        return Err(ContractError::Unsupported {
            field: "source.observed_members",
        }
        .into());
    }
    Ok(())
}

fn budget_phase(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    evidence: &[eliot_memory_curation_contracts::ProtectionEvidence],
) -> Result<(u64, u64), CurationScreenError> {
    let summary = bounds::preflight(request, source, evidence)?;
    let member_count = u64::try_from(source.members.len()).map_err(|_| ContractError::Bound {
        field: "source.members",
    })?;
    let rule_count =
        u64::try_from(request.profile.rules.len()).map_err(|_| ContractError::Bound {
            field: "profile.rules",
        })?;
    let work_units = member_count
        .checked_add(
            u64::try_from(evidence.len()).map_err(|_| ContractError::Bound {
                field: "protection.evidence",
            })?,
        )
        .and_then(|value| value.checked_add(member_count.checked_mul(rule_count)?))
        .ok_or(ContractError::Bound {
            field: "screen.work_units",
        })?;
    if work_units > bounds::MAX_WORK_UNITS || work_units > request.profile.limits.max_work_units {
        return Err(ContractError::Bound {
            field: "screen.work_units",
        }
        .into());
    }
    let input_bytes = bounds::encoded_input_bytes(request, source, evidence)?;
    let expansion_units = member_count
        .checked_mul(rule_count.checked_add(3).ok_or(ContractError::Bound {
            field: "screen.output_allocation",
        })?)
        .ok_or(ContractError::Bound {
            field: "screen.output_allocation",
        })?;
    let multiplier = expansion_units.checked_add(1).ok_or(ContractError::Bound {
        field: "screen.output_allocation",
    })?;
    let estimated_output = input_bytes
        .checked_mul(multiplier)
        .and_then(|value| value.checked_add(expansion_units.checked_mul(512)?))
        .ok_or(ContractError::Bound {
            field: "screen.output_allocation",
        })?;
    if estimated_output > bounds::MAX_OUTPUT_BYTES {
        return Err(ContractError::Bound {
            field: "screen.output_allocation",
        }
        .into());
    }
    if member_count > request.profile.limits.max_items {
        return Err(ContractError::Bound {
            field: "screen.items",
        }
        .into());
    }
    if summary.references as u64 > request.profile.limits.max_references {
        return Err(ContractError::Bound {
            field: "screen.references",
        }
        .into());
    }
    if input_bytes > request.profile.limits.max_bytes {
        return Err(ContractError::Bound {
            field: "screen.input_bytes",
        }
        .into());
    }
    Ok((input_bytes, work_units))
}

/// Runs one bounded, read-only screen over all supplied source members.
///
/// Continuation cursors, live deadlines, and cancellation-grace clocks are
/// unsupported in this pure single-call prototype. The caller must provide the
/// complete observed prefix declared by the source snapshot; no truncation or
/// cursor is fabricated by this function.
pub fn screen_memory_curation(
    request: &CurationScreenRequest,
    source: &SourceSnapshot,
    evidence: &[eliot_memory_curation_contracts::ProtectionEvidence],
) -> Result<CurationScreenResult, CurationScreenError> {
    validate_preconditions(request, source)?;
    let (input_bytes, work_units) = budget_phase(request, source, evidence)?;
    request.validate_snapshot(source)?;
    if request.profile.schema_revision.value() != 1 {
        return Err(ContractError::Unsupported {
            field: "profile.schema_revision",
        }
        .into());
    }
    rules::validate_requested_findings(&request.profile)?;
    let resolved = rules::resolve_profile(&request.profile.rules)?;
    let protection = protection::derive_protection_assessments(request, source, evidence)?;
    let findings = structural_findings(request, source, &protection, &resolved)?;
    let (eligibility, mut coverage, state) =
        eligibility_and_coverage(request, source, &protection, &findings)?;
    let member_sets = MemberSets {
        changed_targets: request.partition.changed_targets.clone(),
        immutable_references: request.partition.immutable_references.clone(),
    };
    coverage.usage.work_units = work_units;
    let result = CurationScreenResult {
        request: request.clone(),
        source: source.clone(),
        findings,
        protection,
        eligibility,
        coverage,
        member_sets,
        state,
        result_digest: eliot_memory_curation_contracts::Digest::new("0".repeat(64))?,
    };
    Ok(seal_result(result, input_bytes, work_units)?)
}
