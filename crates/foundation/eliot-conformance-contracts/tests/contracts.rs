use std::collections::BTreeSet;

use eliot_conformance_contracts::{
    CapabilitySupportRow, ConformanceContractError, ConformanceContractSet, ContractMaturity,
    DomainCoverage, EvidenceDomain, EvidenceExecutionStatus, ImplementationSupport,
    SupportObservationState, CONTRACT_VERSION, canonicalize_capability_support_row,
    canonicalize_contract_set, canonicalize_domain_coverage, canonicalize_support_claim_set,
    validate_capability_support_row, validate_conformance_contract_set,
    validate_domain_coverage, validate_support_claim_set,
};
use serde_json::json;

const EVALUATED_AT: u64 = 1_000;

fn coverage() -> Vec<DomainCoverage> {
    EvidenceDomain::ALL
        .into_iter()
        .map(|domain| {
            let name = format!("{domain:?}").to_ascii_lowercase();
            DomainCoverage {
                contract_version: CONTRACT_VERSION,
                domain,
                state: SupportObservationState::Observed,
                source_handles: vec![format!("source:{name}:v1")],
                evidence_refs: vec![format!("evidence:{name}:v1")],
                blind_boundaries: Vec::new(),
                observed_at_ms: Some(900),
                expires_at_ms: Some(1_100),
                invalidation_set: vec![format!("invalidate:{name}:v1")],
            }
        })
        .collect()
}

fn verified_row() -> CapabilitySupportRow {
    CapabilitySupportRow {
        contract_version: CONTRACT_VERSION,
        contract_ref: "contract:runtime:v1".to_owned(),
        support_claim_ref: "claim:runtime:v1".to_owned(),
        scope_ref: "scope:project-a".to_owned(),
        claim_domain: Some(EvidenceDomain::Runtime),
        required_dependency_domains: vec![
            EvidenceDomain::Source,
            EvidenceDomain::Build,
            EvidenceDomain::Runtime,
        ],
        support_observation_state: SupportObservationState::Observed,
        contract_maturity: ContractMaturity::Stable,
        implementation_support: ImplementationSupport::CurrentVerified,
        evidence_execution_status: EvidenceExecutionStatus::Executed,
        proof_profile_ref: Some("proof:runtime:v1".to_owned()),
        source_handles: vec!["source:runtime-owner:v1".to_owned()],
        evidence_refs: vec!["evidence:runtime-proof:v1".to_owned()],
        blind_boundaries: Vec::new(),
        invalidation_set: vec!["invalidate:runtime:v1".to_owned()],
        compatibility_rule_ref: None,
        not_applicable_reason_ref: None,
        evaluated_at_ms: EVALUATED_AT,
    }
}

fn unverified_row(domain: EvidenceDomain, claim: &str) -> CapabilitySupportRow {
    CapabilitySupportRow {
        contract_version: CONTRACT_VERSION,
        contract_ref: "contract:multi-domain:v1".to_owned(),
        support_claim_ref: claim.to_owned(),
        scope_ref: "scope:project-a".to_owned(),
        claim_domain: Some(domain),
        required_dependency_domains: vec![domain],
        support_observation_state: SupportObservationState::Observed,
        contract_maturity: ContractMaturity::Compatible,
        implementation_support: ImplementationSupport::CurrentUnverified,
        evidence_execution_status: EvidenceExecutionStatus::NotExecuted,
        proof_profile_ref: None,
        source_handles: vec![format!("source:{domain:?}").to_ascii_lowercase()],
        evidence_refs: Vec::new(),
        blind_boundaries: Vec::new(),
        invalidation_set: vec![format!("invalidate:{domain:?}").to_ascii_lowercase()],
        compatibility_rule_ref: None,
        not_applicable_reason_ref: None,
        evaluated_at_ms: EVALUATED_AT,
    }
}

fn contract_set() -> ConformanceContractSet {
    ConformanceContractSet {
        contract_version: CONTRACT_VERSION,
        evaluated_at_ms: EVALUATED_AT,
        domain_coverage: coverage(),
        support_rows: vec![verified_row()],
    }
}

#[test]
fn exact_contract_validates_and_uses_normative_wire_values() {
    validate_conformance_contract_set(&contract_set()).expect("valid contract set");
    assert_eq!(
        serde_json::to_value(EvidenceDomain::Source).unwrap(),
        json!("SOURCE")
    );
    assert_eq!(
        serde_json::to_value(ImplementationSupport::CurrentVerified).unwrap(),
        json!("CURRENT_VERIFIED")
    );
    assert_eq!(
        serde_json::to_value(SupportObservationState::NotRunning).unwrap(),
        json!("NOT_RUNNING")
    );
}

#[test]
fn missing_duplicate_and_noncanonical_domains_fail_closed() {
    let mut missing = coverage();
    missing.pop();
    assert!(matches!(
        validate_domain_coverage(&missing),
        Err(ConformanceContractError::MissingDomain {
            domain: EvidenceDomain::Integrations
        })
    ));

    let mut duplicate = coverage();
    duplicate[4].domain = EvidenceDomain::Store;
    assert!(matches!(
        validate_domain_coverage(&duplicate),
        Err(ConformanceContractError::DuplicateDomain {
            domain: EvidenceDomain::Store
        })
    ));

    let mut noncanonical = coverage();
    noncanonical.swap(0, 1);
    assert_eq!(
        validate_domain_coverage(&noncanonical),
        Err(ConformanceContractError::NonCanonicalCollection {
            field: "domain_coverage"
        })
    );
}

#[test]
fn current_verified_requires_executed_unblinded_exact_evidence() {
    let domains = coverage();

    let mut row = verified_row();
    row.evidence_execution_status = EvidenceExecutionStatus::NotExecuted;
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));

    let mut row = verified_row();
    row.evidence_execution_status = EvidenceExecutionStatus::Simulated;
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));

    let mut row = verified_row();
    row.proof_profile_ref = None;
    assert_eq!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::MissingProofProfile)
    );

    let mut row = verified_row();
    row.source_handles.clear();
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::MissingEvidence {
            field: "support.source_handles"
        })
    ));

    let mut row = verified_row();
    row.evidence_refs.clear();
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::MissingEvidence {
            field: "support.evidence_refs"
        })
    ));

    let mut row = verified_row();
    row.invalidation_set.clear();
    assert_eq!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::MissingInvalidationSet)
    );

    let mut row = verified_row();
    row.blind_boundaries = vec!["blind:provider".to_owned()];
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));
}

#[test]
fn source_only_observation_cannot_verify_runtime_support() {
    let mut domains = coverage();
    let runtime = domains
        .iter_mut()
        .find(|row| row.domain == EvidenceDomain::Runtime)
        .unwrap();
    runtime.state = SupportObservationState::Unknown;
    runtime.source_handles.clear();
    runtime.evidence_refs.clear();
    runtime.invalidation_set.clear();
    runtime.observed_at_ms = None;
    runtime.expires_at_ms = None;
    runtime.blind_boundaries = vec!["runtime:not-observed".to_owned()];

    let mut row = verified_row();
    row.support_observation_state = SupportObservationState::Unknown;
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));

    row.implementation_support = ImplementationSupport::CurrentUnverified;
    row.evidence_execution_status = EvidenceExecutionStatus::NotExecuted;
    row.proof_profile_ref = None;
    row.evidence_refs.clear();
    validate_capability_support_row(&row, &domains)
        .expect("unknown runtime observation may remain explicitly unverified");
}

#[test]
fn observation_states_remain_distinct() {
    let states = [
        SupportObservationState::Observed,
        SupportObservationState::NotRunning,
        SupportObservationState::Unavailable,
        SupportObservationState::Unknown,
        SupportObservationState::Stale,
        SupportObservationState::Conflicted,
    ];
    let encoded = states
        .into_iter()
        .map(|state| serde_json::to_string(&state).unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(encoded.len(), states.len());
}

#[test]
fn retired_current_exposure_requires_compatibility_and_cannot_be_verified() {
    let domains = coverage();
    let mut row = verified_row();
    row.contract_maturity = ContractMaturity::Retired;
    row.implementation_support = ImplementationSupport::CurrentUnverified;
    row.evidence_execution_status = EvidenceExecutionStatus::NotExecuted;
    row.proof_profile_ref = None;
    row.evidence_refs.clear();
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));

    row.compatibility_rule_ref = Some("compat:legacy-runtime:v1".to_owned());
    validate_capability_support_row(&row, &domains)
        .expect("retired compatibility exposure remains explicitly unverified");

    row.implementation_support = ImplementationSupport::CurrentVerified;
    row.evidence_execution_status = EvidenceExecutionStatus::Executed;
    row.proof_profile_ref = Some("proof:runtime:v1".to_owned());
    row.evidence_refs = vec!["evidence:runtime:v1".to_owned()];
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));
}

#[test]
fn not_applicable_has_no_domain_dependency_or_execution_claim() {
    let domains = coverage();
    let mut row = verified_row();
    row.implementation_support = ImplementationSupport::NotApplicable;
    row.claim_domain = None;
    row.required_dependency_domains.clear();
    row.support_observation_state = SupportObservationState::Unknown;
    row.evidence_execution_status = EvidenceExecutionStatus::NotExecuted;
    row.proof_profile_ref = None;
    row.source_handles.clear();
    row.evidence_refs.clear();
    row.invalidation_set.clear();
    row.not_applicable_reason_ref = Some("reason:not-used-on-this-platform".to_owned());
    validate_capability_support_row(&row, &domains).expect("valid not-applicable row");

    row.evidence_execution_status = EvidenceExecutionStatus::Executed;
    assert!(matches!(
        validate_capability_support_row(&row, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));
}

#[test]
fn canonicalization_is_permutation_invariant_and_strict_validation_rejects_drift() {
    let mut left = contract_set();
    left.domain_coverage.reverse();
    left.support_rows[0].source_handles =
        vec!["source:z".to_owned(), "source:a".to_owned()];

    let mut right = contract_set();
    right.support_rows[0].source_handles =
        vec!["source:a".to_owned(), "source:z".to_owned()];

    let left = canonicalize_contract_set(left).expect("left canonicalization");
    let right = canonicalize_contract_set(right).expect("right canonicalization");
    assert_eq!(left, right);

    let mut noncanonical = verified_row();
    noncanonical.source_handles = vec!["source:z".to_owned(), "source:a".to_owned()];
    assert!(matches!(
        validate_capability_support_row(&noncanonical, &coverage()),
        Err(ConformanceContractError::NonCanonicalCollection { .. })
    ));

    let mut duplicate = verified_row();
    duplicate.evidence_refs = vec!["evidence:x".to_owned(), "evidence:x".to_owned()];
    assert!(matches!(
        canonicalize_capability_support_row(duplicate),
        Err(ConformanceContractError::DuplicateValue { .. })
    ));
}

#[test]
fn claim_identity_is_unique_but_distinct_domains_may_share_contract_and_scope() {
    let domains = coverage();
    let source = unverified_row(EvidenceDomain::Source, "claim:source:v1");
    let runtime = unverified_row(EvidenceDomain::Runtime, "claim:runtime:v2");
    let rows = canonicalize_support_claim_set(vec![runtime, source], &domains)
        .expect("different domain claims are distinct");
    validate_support_claim_set(&rows, &domains).expect("canonical rows validate");

    let first = verified_row();
    let mut duplicate_claim = first.clone();
    duplicate_claim.contract_ref = "contract:other:v1".to_owned();
    duplicate_claim.scope_ref = "scope:other".to_owned();
    assert!(matches!(
        canonicalize_support_claim_set(vec![first.clone(), duplicate_claim], &domains),
        Err(ConformanceContractError::DuplicateClaim { .. })
    ));

    let mut duplicate_owner = first.clone();
    duplicate_owner.support_claim_ref = "claim:runtime:second".to_owned();
    assert!(matches!(
        canonicalize_support_claim_set(vec![first, duplicate_owner], &domains),
        Err(ConformanceContractError::DuplicateContractScopeClaim { .. })
    ));
}

#[test]
fn stale_dependency_invalidates_only_claims_that_require_it() {
    let mut domains = coverage();
    let store = domains
        .iter_mut()
        .find(|row| row.domain == EvidenceDomain::Store)
        .unwrap();
    store.state = SupportObservationState::Stale;

    validate_capability_support_row(&verified_row(), &domains)
        .expect("runtime claim does not depend on store");

    let mut store_claim = unverified_row(EvidenceDomain::Store, "claim:store:v1");
    store_claim.support_observation_state = SupportObservationState::Stale;
    assert!(matches!(
        validate_capability_support_row(&store_claim, &domains),
        Err(ConformanceContractError::InvalidSupportCombination { .. })
    ));

    store_claim.implementation_support = ImplementationSupport::Stale;
    validate_capability_support_row(&store_claim, &domains)
        .expect("stale evidence is represented as stale support");
}

#[test]
fn expired_or_future_dependency_evidence_fails_closed() {
    let mut domains = coverage();
    let runtime = domains
        .iter_mut()
        .find(|row| row.domain == EvidenceDomain::Runtime)
        .unwrap();
    runtime.expires_at_ms = Some(EVALUATED_AT);
    assert!(matches!(
        validate_capability_support_row(&verified_row(), &domains),
        Err(ConformanceContractError::DomainExpired {
            domain: EvidenceDomain::Runtime,
            ..
        })
    ));

    let mut domains = coverage();
    let runtime = domains
        .iter_mut()
        .find(|row| row.domain == EvidenceDomain::Runtime)
        .unwrap();
    runtime.observed_at_ms = Some(EVALUATED_AT + 1);
    runtime.expires_at_ms = Some(EVALUATED_AT + 100);
    assert_eq!(
        validate_capability_support_row(&verified_row(), &domains),
        Err(ConformanceContractError::InvalidTime {
            field: "domain_coverage.observed_at_ms"
        })
    );
}

#[test]
fn evaluation_boundary_and_contract_version_are_exact() {
    let mut set = contract_set();
    set.support_rows[0].evaluated_at_ms += 1;
    assert_eq!(
        validate_conformance_contract_set(&set),
        Err(ConformanceContractError::EvaluationBoundaryMismatch)
    );

    let mut set = contract_set();
    set.contract_version += 1;
    assert!(matches!(
        validate_conformance_contract_set(&set),
        Err(ConformanceContractError::UnsupportedContractVersion { .. })
    ));
}

#[test]
fn unknown_wire_values_and_fields_fail_closed() {
    assert!(serde_json::from_value::<EvidenceDomain>(json!("NETWORK")).is_err());
    let mut value = serde_json::to_value(verified_row()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("passed".to_owned(), json!(true));
    assert!(serde_json::from_value::<CapabilitySupportRow>(value).is_err());
}

#[test]
fn unknown_domain_can_remain_explicitly_empty_without_becoming_support() {
    let mut domains = coverage();
    let integrations = domains
        .iter_mut()
        .find(|row| row.domain == EvidenceDomain::Integrations)
        .unwrap();
    integrations.state = SupportObservationState::Unknown;
    integrations.source_handles.clear();
    integrations.evidence_refs.clear();
    integrations.invalidation_set.clear();
    integrations.observed_at_ms = None;
    integrations.expires_at_ms = None;
    validate_domain_coverage(&domains).expect("explicit unknown domain is valid coverage");

    let mut row = unverified_row(EvidenceDomain::Integrations, "claim:integrations:v1");
    row.support_observation_state = SupportObservationState::Unknown;
    row.source_handles.clear();
    row.invalidation_set.clear();
    validate_capability_support_row(&row, &domains)
        .expect("unknown observation remains explicitly current-unverified");
}

#[test]
fn canonical_domain_helper_restores_order_but_not_duplicate_identity() {
    let mut rows = coverage();
    rows.reverse();
    let rows = canonicalize_domain_coverage(rows).expect("permutation canonicalizes");
    assert!(rows
        .iter()
        .map(|row| row.domain)
        .eq(EvidenceDomain::ALL));

    let mut duplicate = coverage();
    duplicate[4].domain = EvidenceDomain::Store;
    assert!(matches!(
        canonicalize_domain_coverage(duplicate),
        Err(ConformanceContractError::DuplicateDomain { .. })
    ));
}
