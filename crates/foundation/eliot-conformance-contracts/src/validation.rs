use std::collections::BTreeSet;

use crate::{
    CapabilitySupportRow, ConformanceContractError, ConformanceContractSet, ContractMaturity,
    DomainCoverage, EvidenceDomain, EvidenceExecutionStatus, ImplementationSupport,
    SupportObservationState, CONTRACT_VERSION, MAX_SET_ITEMS, MAX_SUPPORT_ROWS, MAX_TEXT_BYTES,
};

/// Canonicalizes and validates all five domain rows.
pub fn canonicalize_domain_coverage(
    mut coverage: Vec<DomainCoverage>,
) -> Result<Vec<DomainCoverage>, ConformanceContractError> {
    for row in &mut coverage {
        canonicalize_text_set("domain_coverage.source_handles", &mut row.source_handles)?;
        canonicalize_text_set("domain_coverage.evidence_refs", &mut row.evidence_refs)?;
        canonicalize_text_set("domain_coverage.blind_boundaries", &mut row.blind_boundaries)?;
        canonicalize_text_set("domain_coverage.invalidation_set", &mut row.invalidation_set)?;
    }
    coverage.sort_by_key(|row| row.domain);
    validate_domain_coverage(&coverage)?;
    Ok(coverage)
}

/// Validates an already canonical exact five-domain coverage set.
pub fn validate_domain_coverage(
    coverage: &[DomainCoverage],
) -> Result<(), ConformanceContractError> {
    let mut seen = BTreeSet::new();
    for row in coverage {
        validate_domain_row(row)?;
        if !seen.insert(row.domain) {
            return Err(ConformanceContractError::DuplicateDomain { domain: row.domain });
        }
    }

    for domain in EvidenceDomain::ALL {
        if !seen.contains(&domain) {
            return Err(ConformanceContractError::MissingDomain { domain });
        }
    }

    if !coverage
        .iter()
        .map(|row| row.domain)
        .eq(EvidenceDomain::ALL)
    {
        return Err(ConformanceContractError::NonCanonicalCollection {
            field: "domain_coverage",
        });
    }
    Ok(())
}

/// Canonicalizes one support row. This does not prove that current domain
/// evidence satisfies the row; use [`validate_capability_support_row`] for that.
pub fn canonicalize_capability_support_row(
    mut row: CapabilitySupportRow,
) -> Result<CapabilitySupportRow, ConformanceContractError> {
    canonicalize_domain_set(
        "support.required_dependency_domains",
        &mut row.required_dependency_domains,
    )?;
    canonicalize_text_set("support.source_handles", &mut row.source_handles)?;
    canonicalize_text_set("support.evidence_refs", &mut row.evidence_refs)?;
    canonicalize_text_set("support.blind_boundaries", &mut row.blind_boundaries)?;
    canonicalize_text_set("support.invalidation_set", &mut row.invalidation_set)?;
    validate_capability_support_row_shape(&row)?;
    Ok(row)
}

/// Validates one support row against the exact current five-domain coverage.
pub fn validate_capability_support_row(
    row: &CapabilitySupportRow,
    coverage: &[DomainCoverage],
) -> Result<(), ConformanceContractError> {
    validate_capability_support_row_shape(row)?;
    validate_domain_coverage(coverage)?;

    let Some(claim_domain) = row.claim_domain else {
        return Ok(());
    };
    let claim_coverage = coverage_for(coverage, claim_domain)?;
    if row.support_observation_state != claim_coverage.state {
        return Err(ConformanceContractError::ClaimObservationMismatch {
            domain: claim_domain,
            claimed: row.support_observation_state,
            observed: claim_coverage.state,
        });
    }

    for domain in &row.required_dependency_domains {
        let dependency = coverage_for(coverage, *domain)?;
        validate_dependency_time(dependency, row.evaluated_at_ms)?;
        if row.implementation_support == ImplementationSupport::CurrentVerified {
            validate_current_domain(dependency, row.evaluated_at_ms)?;
            continue;
        }
        let expired = dependency
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= row.evaluated_at_ms);
        if (dependency.state == SupportObservationState::Stale || expired)
            && row.implementation_support != ImplementationSupport::Stale
        {
            return Err(ConformanceContractError::InvalidSupportCombination {
                reason: "a stale or expired required dependency requires STALE implementation support",
            });
        }
    }
    Ok(())
}

/// Canonicalizes and validates a support claim set against exact domain coverage.
pub fn canonicalize_support_claim_set(
    rows: Vec<CapabilitySupportRow>,
    coverage: &[DomainCoverage],
) -> Result<Vec<CapabilitySupportRow>, ConformanceContractError> {
    validate_domain_coverage(coverage)?;
    validate_collection_bound("support_rows", rows.len(), MAX_SUPPORT_ROWS)?;
    let mut rows = rows
        .into_iter()
        .map(canonicalize_capability_support_row)
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| support_row_key(left).cmp(&support_row_key(right)));
    validate_support_claim_set(&rows, coverage)?;
    Ok(rows)
}

/// Validates an already canonical support claim set against exact coverage.
pub fn validate_support_claim_set(
    rows: &[CapabilitySupportRow],
    coverage: &[DomainCoverage],
) -> Result<(), ConformanceContractError> {
    validate_domain_coverage(coverage)?;
    validate_collection_bound("support_rows", rows.len(), MAX_SUPPORT_ROWS)?;

    let mut claim_refs = BTreeSet::new();
    let mut contract_scope_claims = BTreeSet::new();
    for row in rows {
        validate_capability_support_row(row, coverage)?;
        if !claim_refs.insert(row.support_claim_ref.clone()) {
            return Err(ConformanceContractError::DuplicateClaim {
                support_claim_ref: row.support_claim_ref.clone(),
            });
        }
        let owner_key = (
            row.contract_ref.clone(),
            row.scope_ref.clone(),
            row.claim_domain,
        );
        if !contract_scope_claims.insert(owner_key) {
            return Err(ConformanceContractError::DuplicateContractScopeClaim {
                contract_ref: row.contract_ref.clone(),
                scope_ref: row.scope_ref.clone(),
                claim_domain: row.claim_domain,
            });
        }
    }

    for pair in rows.windows(2) {
        if support_row_key(&pair[0]) >= support_row_key(&pair[1]) {
            return Err(ConformanceContractError::NonCanonicalCollection {
                field: "support_rows",
            });
        }
    }
    Ok(())
}

/// Canonicalizes and validates one complete contract set.
pub fn canonicalize_contract_set(
    mut contract_set: ConformanceContractSet,
) -> Result<ConformanceContractSet, ConformanceContractError> {
    validate_contract_version(contract_set.contract_version)?;
    contract_set.domain_coverage =
        canonicalize_domain_coverage(contract_set.domain_coverage)?;
    contract_set.support_rows = canonicalize_support_claim_set(
        contract_set.support_rows,
        &contract_set.domain_coverage,
    )?;
    validate_conformance_contract_set(&contract_set)?;
    Ok(contract_set)
}

/// Validates five-domain coverage and all support rows at one exact boundary.
pub fn validate_conformance_contract_set(
    contract_set: &ConformanceContractSet,
) -> Result<(), ConformanceContractError> {
    validate_contract_version(contract_set.contract_version)?;
    if contract_set.evaluated_at_ms == 0 {
        return Err(ConformanceContractError::InvalidTime {
            field: "contract_set.evaluated_at_ms",
        });
    }
    validate_domain_coverage(&contract_set.domain_coverage)?;
    for row in &contract_set.support_rows {
        if row.evaluated_at_ms != contract_set.evaluated_at_ms {
            return Err(ConformanceContractError::EvaluationBoundaryMismatch);
        }
    }
    validate_support_claim_set(&contract_set.support_rows, &contract_set.domain_coverage)
}

fn validate_capability_support_row_shape(
    row: &CapabilitySupportRow,
) -> Result<(), ConformanceContractError> {
    validate_contract_version(row.contract_version)?;
    validate_text("support.contract_ref", &row.contract_ref)?;
    validate_text("support.support_claim_ref", &row.support_claim_ref)?;
    validate_text("support.scope_ref", &row.scope_ref)?;
    validate_optional_text("support.proof_profile_ref", row.proof_profile_ref.as_deref())?;
    validate_optional_text(
        "support.compatibility_rule_ref",
        row.compatibility_rule_ref.as_deref(),
    )?;
    validate_optional_text(
        "support.not_applicable_reason_ref",
        row.not_applicable_reason_ref.as_deref(),
    )?;
    validate_domain_set(
        "support.required_dependency_domains",
        &row.required_dependency_domains,
    )?;
    validate_text_set("support.source_handles", &row.source_handles)?;
    validate_text_set("support.evidence_refs", &row.evidence_refs)?;
    validate_text_set("support.blind_boundaries", &row.blind_boundaries)?;
    validate_text_set("support.invalidation_set", &row.invalidation_set)?;
    if row.evaluated_at_ms == 0 {
        return Err(ConformanceContractError::InvalidTime {
            field: "support.evaluated_at_ms",
        });
    }

    if row.implementation_support == ImplementationSupport::NotApplicable {
        if row.claim_domain.is_some()
            || !row.required_dependency_domains.is_empty()
            || row.evidence_execution_status != EvidenceExecutionStatus::NotExecuted
            || row.proof_profile_ref.is_some()
            || row.not_applicable_reason_ref.is_none()
        {
            return Err(ConformanceContractError::InvalidSupportCombination {
                reason: "NOT_APPLICABLE requires no claim domain, dependencies, execution, or proof profile and requires an explicit reason",
            });
        }
        return Ok(());
    }

    if row.not_applicable_reason_ref.is_some() {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "not_applicable_reason_ref is valid only for NOT_APPLICABLE support",
        });
    }

    let claim_domain = row.claim_domain.ok_or(
        ConformanceContractError::InvalidSupportCombination {
            reason: "a support claim must name its evidence domain",
        },
    )?;
    if !row.required_dependency_domains.contains(&claim_domain) {
        return Err(ConformanceContractError::MissingRequiredDomain {
            domain: claim_domain,
        });
    }

    if row.contract_maturity == ContractMaturity::Retired
        && row.implementation_support.is_current_exposure()
        && row.compatibility_rule_ref.is_none()
    {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "current exposure of a retired contract requires an explicit compatibility rule",
        });
    }

    if row.support_observation_state == SupportObservationState::Stale
        && row.implementation_support != ImplementationSupport::Stale
    {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "STALE claim observation requires STALE implementation support",
        });
    }

    if row.implementation_support == ImplementationSupport::CurrentVerified {
        validate_current_verified_shape(row)?;
    }
    Ok(())
}

fn validate_current_verified_shape(
    row: &CapabilitySupportRow,
) -> Result<(), ConformanceContractError> {
    if row.support_observation_state != SupportObservationState::Observed {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "CURRENT_VERIFIED requires OBSERVED support state",
        });
    }
    if matches!(
        row.contract_maturity,
        ContractMaturity::Skeleton | ContractMaturity::Retired
    ) {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "CURRENT_VERIFIED requires a non-skeleton, non-retired contract",
        });
    }
    if row.evidence_execution_status != EvidenceExecutionStatus::Executed {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "CURRENT_VERIFIED requires EXECUTED evidence",
        });
    }
    if row.proof_profile_ref.is_none() {
        return Err(ConformanceContractError::MissingProofProfile);
    }
    if row.source_handles.is_empty() {
        return Err(ConformanceContractError::MissingEvidence {
            field: "support.source_handles",
        });
    }
    if row.evidence_refs.is_empty() {
        return Err(ConformanceContractError::MissingEvidence {
            field: "support.evidence_refs",
        });
    }
    if row.invalidation_set.is_empty() {
        return Err(ConformanceContractError::MissingInvalidationSet);
    }
    if !row.blind_boundaries.is_empty() {
        return Err(ConformanceContractError::InvalidSupportCombination {
            reason: "CURRENT_VERIFIED cannot retain an unresolved blind boundary",
        });
    }
    Ok(())
}

fn validate_domain_row(row: &DomainCoverage) -> Result<(), ConformanceContractError> {
    validate_contract_version(row.contract_version)?;
    validate_text_set("domain_coverage.source_handles", &row.source_handles)?;
    validate_text_set("domain_coverage.evidence_refs", &row.evidence_refs)?;
    validate_text_set("domain_coverage.blind_boundaries", &row.blind_boundaries)?;
    validate_text_set("domain_coverage.invalidation_set", &row.invalidation_set)?;
    validate_domain_time(row)?;

    if row.state != SupportObservationState::Unknown {
        if row.observed_at_ms.is_none() {
            return Err(ConformanceContractError::InvalidTime {
                field: "domain_coverage.observed_at_ms",
            });
        }
        if row.source_handles.is_empty() && row.evidence_refs.is_empty() {
            return Err(ConformanceContractError::MissingEvidence {
                field: "domain_coverage.source_or_evidence",
            });
        }
        if row.invalidation_set.is_empty() {
            return Err(ConformanceContractError::MissingInvalidationSet);
        }
    }
    Ok(())
}

fn validate_current_domain(
    coverage: &DomainCoverage,
    evaluated_at_ms: u64,
) -> Result<(), ConformanceContractError> {
    if !coverage.state.satisfies_current_dependency() {
        return Err(ConformanceContractError::DomainNotCurrent {
            domain: coverage.domain,
            state: coverage.state,
        });
    }
    if !coverage.blind_boundaries.is_empty() {
        return Err(ConformanceContractError::DomainBlind {
            domain: coverage.domain,
        });
    }
    if coverage.source_handles.is_empty() {
        return Err(ConformanceContractError::MissingEvidence {
            field: "domain_coverage.source_handles",
        });
    }
    if coverage.evidence_refs.is_empty() {
        return Err(ConformanceContractError::MissingEvidence {
            field: "domain_coverage.evidence_refs",
        });
    }
    if coverage.invalidation_set.is_empty() {
        return Err(ConformanceContractError::MissingInvalidationSet);
    }
    validate_dependency_time(coverage, evaluated_at_ms)?;
    if let Some(expired_at_ms) = coverage.expires_at_ms
        && expired_at_ms <= evaluated_at_ms
    {
        return Err(ConformanceContractError::DomainExpired {
            domain: coverage.domain,
            expired_at_ms,
            evaluated_at_ms,
        });
    }
    Ok(())
}

fn validate_dependency_time(
    coverage: &DomainCoverage,
    evaluated_at_ms: u64,
) -> Result<(), ConformanceContractError> {
    if let Some(observed_at_ms) = coverage.observed_at_ms
        && observed_at_ms > evaluated_at_ms
    {
        return Err(ConformanceContractError::InvalidTime {
            field: "domain_coverage.observed_at_ms",
        });
    }
    Ok(())
}

fn coverage_for(
    coverage: &[DomainCoverage],
    domain: EvidenceDomain,
) -> Result<&DomainCoverage, ConformanceContractError> {
    coverage
        .iter()
        .find(|row| row.domain == domain)
        .ok_or(ConformanceContractError::MissingDomain { domain })
}

fn validate_contract_version(actual: u16) -> Result<(), ConformanceContractError> {
    if actual == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ConformanceContractError::UnsupportedContractVersion {
            expected: CONTRACT_VERSION,
            actual,
        })
    }
}

fn validate_domain_time(row: &DomainCoverage) -> Result<(), ConformanceContractError> {
    if let Some(expires_at_ms) = row.expires_at_ms {
        let observed_at_ms = row.observed_at_ms.ok_or(
            ConformanceContractError::InvalidTime {
                field: "domain_coverage.expires_at_ms",
            },
        )?;
        if expires_at_ms <= observed_at_ms {
            return Err(ConformanceContractError::InvalidTime {
                field: "domain_coverage.expires_at_ms",
            });
        }
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ConformanceContractError> {
    if value.is_empty() {
        return Err(ConformanceContractError::InvalidText {
            field,
            reason: "must not be empty",
        });
    }
    if value.trim() != value {
        return Err(ConformanceContractError::InvalidText {
            field,
            reason: "must not contain leading or trailing whitespace",
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ConformanceContractError::InvalidText {
            field,
            reason: "exceeds the maximum UTF-8 byte length",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ConformanceContractError::InvalidText {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConformanceContractError> {
    value.map_or(Ok(()), |value| validate_text(field, value))
}

fn canonicalize_text_set(
    field: &'static str,
    values: &mut Vec<String>,
) -> Result<(), ConformanceContractError> {
    validate_collection_bound(field, values.len(), MAX_SET_ITEMS)?;
    for value in values.iter() {
        validate_text(field, value)?;
    }
    values.sort();
    if let Some(pair) = values.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(ConformanceContractError::DuplicateValue {
            field,
            value: pair[0].clone(),
        });
    }
    Ok(())
}

fn validate_text_set(
    field: &'static str,
    values: &[String],
) -> Result<(), ConformanceContractError> {
    validate_collection_bound(field, values.len(), MAX_SET_ITEMS)?;
    for value in values {
        validate_text(field, value)?;
    }
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(ConformanceContractError::DuplicateValue {
                field,
                value: pair[0].clone(),
            });
        }
        if pair[0] > pair[1] {
            return Err(ConformanceContractError::NonCanonicalCollection { field });
        }
    }
    Ok(())
}

fn canonicalize_domain_set(
    field: &'static str,
    values: &mut Vec<EvidenceDomain>,
) -> Result<(), ConformanceContractError> {
    validate_collection_bound(field, values.len(), EvidenceDomain::ALL.len())?;
    values.sort();
    if let Some(pair) = values.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(ConformanceContractError::DuplicateValue {
            field,
            value: format!("{:?}", pair[0]),
        });
    }
    Ok(())
}

fn validate_domain_set(
    field: &'static str,
    values: &[EvidenceDomain],
) -> Result<(), ConformanceContractError> {
    validate_collection_bound(field, values.len(), EvidenceDomain::ALL.len())?;
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(ConformanceContractError::DuplicateValue {
                field,
                value: format!("{:?}", pair[0]),
            });
        }
        if pair[0] > pair[1] {
            return Err(ConformanceContractError::NonCanonicalCollection { field });
        }
    }
    Ok(())
}

fn validate_collection_bound(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ConformanceContractError> {
    if actual > maximum {
        Err(ConformanceContractError::CollectionTooLarge {
            field,
            maximum,
            actual,
        })
    } else {
        Ok(())
    }
}

fn support_row_key(
    row: &CapabilitySupportRow,
) -> (&str, &str, Option<EvidenceDomain>, &str) {
    (
        row.contract_ref.as_str(),
        row.scope_ref.as_str(),
        row.claim_domain,
        row.support_claim_ref.as_str(),
    )
}
