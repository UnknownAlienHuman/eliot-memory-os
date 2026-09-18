//! First bootstrap-consumer fixture for #744 (public API only).

use eliot_conformance_contracts::{
    CONTRACT_VERSION, CapabilitySupportRow, CauseHypothesisStatus, ConformanceContractError,
    ContractMaturity, DenominatorCompleteness, DimensionOutcome, DimensionStatus, DomainCoverage,
    EvidenceCeilings, EvidenceDomain, EvidenceExecutionStatus, ImplementationSupport,
    MetricMeasurement, MetricPresence, ObservationCore, ObservationWindow, OwnerBinding, Priority,
    ProductContractRef, QualityDenominator, QualityLimits, Recurrence,
    SELF_QUALITY_CONTRACT_VERSION, SelfQualityDiagnosisCandidate, SelfQualityDimension,
    SelfQualityHandoff, SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation,
    SelfQualityPolicy, Severity, SourceIdentity, SupportObservationState,
    canonicalize_self_quality_input, digest_candidate, digest_self_quality_input,
    digest_self_quality_policy, validate_candidate_against_input, validate_capability_support_row,
    validate_capability_support_row_against_coverage, validate_compatibility_version,
    validate_domain_coverage, validate_handoff, validate_self_quality_input,
};

const AT: u64 = 1_000;
const HEAD: &str = "git:head:abc123";

fn cov(domain: EvidenceDomain) -> DomainCoverage {
    let (state, handle, ev, obs, inv) = match domain {
        EvidenceDomain::Source => (
            SupportObservationState::Observed,
            "git:rev-parse",
            vec![HEAD.to_owned()],
            Some(900),
            vec![HEAD.to_owned()],
        ),
        EvidenceDomain::Runtime => (
            SupportObservationState::NotRunning,
            "capture:unavailable",
            Vec::new(),
            Some(900),
            vec![HEAD.to_owned()],
        ),
        _ => (
            SupportObservationState::Unknown,
            "capture:unavailable",
            Vec::new(),
            None,
            Vec::new(),
        ),
    };
    DomainCoverage {
        contract_version: CONTRACT_VERSION,
        domain,
        state,
        source_handles: vec![handle.to_owned()],
        evidence_refs: ev,
        blind_boundaries: Vec::new(),
        observed_at_ms: obs,
        expires_at_ms: None,
        invalidation_set: inv,
    }
}

fn honest() -> CapabilitySupportRow {
    CapabilitySupportRow {
        contract_version: CONTRACT_VERSION,
        contract_ref: "c:bootstrap:v1".to_owned(),
        support_claim_ref: "k:honest:v1".to_owned(),
        scope_ref: "s:cap:v1".to_owned(),
        claim_domain: Some(EvidenceDomain::Source),
        required_dependency_domains: vec![EvidenceDomain::Source],
        support_observation_state: SupportObservationState::Observed,
        contract_maturity: ContractMaturity::Compatible,
        implementation_support: ImplementationSupport::CurrentUnverified,
        evidence_execution_status: EvidenceExecutionStatus::NotExecuted,
        proof_profile_ref: None,
        source_handles: vec!["git:rev-parse".to_owned()],
        evidence_refs: Vec::new(),
        blind_boundaries: Vec::new(),
        invalidation_set: vec![HEAD.to_owned()],
        compatibility_rule_ref: None,
        not_applicable_reason_ref: None,
        evaluated_at_ms: AT,
    }
}

fn forged() -> CapabilitySupportRow {
    CapabilitySupportRow {
        support_claim_ref: "k:forged:v1".to_owned(),
        required_dependency_domains: vec![EvidenceDomain::Source, EvidenceDomain::Runtime],
        contract_maturity: ContractMaturity::Stable,
        implementation_support: ImplementationSupport::CurrentVerified,
        evidence_execution_status: EvidenceExecutionStatus::Executed,
        proof_profile_ref: Some("p:v1".to_owned()),
        evidence_refs: vec![HEAD.to_owned()],
        ..honest()
    }
}

fn hexed(label: &str) -> String {
    let mut o = String::new();
    for b in label.bytes().chain(std::iter::repeat(0x9e)) {
        o.push_str(&format!("{b:02x}"));
        if o.len() >= 32 {
            break;
        }
    }
    o
}

fn obs(label: &str, dim: SelfQualityDimension, fam_product: bool) -> SelfQualityObservation {
    let core = ObservationCore {
        observation_ref: format!("o:{label}:v1"),
        dimension: dim,
        owner: OwnerBinding {
            owner_ref: "own:v1".to_owned(),
            schema_ref: "sch:v1".to_owned(),
            revision_ref: "rev:r1".to_owned(),
            content_digest: hexed(label),
        },
        window: ObservationWindow {
            observed_from_ms: 900,
            observed_to_ms: 1_100,
            environment_ref: "env:p".to_owned(),
            platform_ref: "plat:l".to_owned(),
            toolchain_ref: "tc:r194".to_owned(),
        },
        metric: MetricMeasurement {
            metric_ref: format!("m:{label}:v1"),
            value: 1.0,
            unit_ref: "u:r".to_owned(),
            normalization_ref: "n:z".to_owned(),
            population_ref: "pop:e100".to_owned(),
            presence: MetricPresence::Value,
        },
        completeness: DenominatorCompleteness::Complete,
        status: DimensionStatus::Pass,
        counterevidence_refs: vec![format!("c:{label}:v1")],
        confounder_refs: vec![format!("f:{label}:v1")],
        intervention_refs: vec![format!("i:{label}:v1")],
    };
    if fam_product {
        SelfQualityObservation::Product(core)
    } else {
        SelfQualityObservation::Liveness(core)
    }
}

fn input(observations: Vec<SelfQualityObservation>) -> SelfQualityInput {
    SelfQualityInput {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        input_ref: "in:v1".to_owned(),
        product: ProductContractRef {
            contract_version: SELF_QUALITY_CONTRACT_VERSION,
            objective_ref: "o:v1".to_owned(),
            acceptance_ref: "a:v1".to_owned(),
            recovery_ref: "r:v1".to_owned(),
        },
        source: SourceIdentity {
            contract_version: SELF_QUALITY_CONTRACT_VERSION,
            source_ref: "s:v1".to_owned(),
            artifact_ref: "b:1".to_owned(),
            configuration_ref: "c:p1".to_owned(),
            generation_ref: "g:1".to_owned(),
            task_ref: "t:b1".to_owned(),
            scope_ref: "s:b1".to_owned(),
            fence_ref: "f:s".to_owned(),
        },
        observations,
        prior_history: Vec::new(),
        policy: SelfQualityPolicy {
            contract_version: SELF_QUALITY_CONTRACT_VERSION,
            policy_ref: "pol:v1".to_owned(),
            schema_ref: "sch:v1".to_owned(),
            revision_ref: "rev:r1".to_owned(),
            rules_digest: hexed("rules"),
            limits: QualityLimits {
                max_observations: 256,
                max_history: 128,
                max_handoffs: 16,
                max_bytes: 1 << 20,
                max_depth: 16,
                max_work_units: 1 << 20,
                max_output_refs: 64,
                max_time_ms: 3_600_000,
            },
        },
        ceilings: EvidenceCeilings {
            privacy_ceiling_ref: "cp:v1".to_owned(),
            authority_ceiling_ref: "ca:v1".to_owned(),
            proof_ceiling_ref: "cf:v1".to_owned(),
        },
        denominator: QualityDenominator {
            expected_dimensions: 2,
            supplied_dimensions: 2,
            expected_sources: 1,
            supplied_sources: 1,
            expected_members: 2,
            supplied_members: 2,
            completeness: DenominatorCompleteness::Complete,
        },
        created_at_ms: 2_000,
    }
}

#[test]
fn bootstrap_five_domain_closure_accepts_honest_and_rejects_forgery() {
    let coverage: Vec<DomainCoverage> = EvidenceDomain::ALL.into_iter().map(cov).collect();
    validate_domain_coverage(&coverage).expect("five-domain coverage validates");
    let good = honest();
    validate_capability_support_row(&good).expect("honest shape validates");
    validate_capability_support_row_against_coverage(&good, &coverage)
        .expect("CURRENT_UNVERIFIED accepts");
    assert!(
        matches!(
            validate_capability_support_row_against_coverage(&forged(), &coverage),
            Err(ConformanceContractError::DomainNotCurrent {
                domain: EvidenceDomain::Runtime,
                ..
            })
        ),
        "forged CURRENT_VERIFIED fails closed"
    );
    let mut dup = coverage.clone();
    dup[4].domain = EvidenceDomain::Store;
    assert!(matches!(
        validate_domain_coverage(&dup),
        Err(ConformanceContractError::DuplicateDomain { .. })
    ));
    let mut unknown = honest();
    unknown.support_claim_ref = "k:unknown:v1".to_owned();
    unknown.claim_domain = Some(EvidenceDomain::Build);
    unknown.required_dependency_domains = vec![EvidenceDomain::Build];
    unknown.support_observation_state = SupportObservationState::Unknown;
    unknown.implementation_support = ImplementationSupport::CurrentVerified;
    unknown.evidence_execution_status = EvidenceExecutionStatus::Executed;
    unknown.proof_profile_ref = Some("p:v1".to_owned());
    unknown.evidence_refs = vec![HEAD.to_owned()];
    assert!(
        validate_capability_support_row_against_coverage(&unknown, &coverage).is_err(),
        "UNKNOWN promotion fails closed"
    );
}

#[test]
fn self_quality_candidate_handoff_round_trip_at_v1() {
    let fwd = input(vec![
        obs("a", SelfQualityDimension::ReliabilityAvailability, false),
        obs("b", SelfQualityDimension::ProductOutcome, true),
    ]);
    let rev = input(vec![
        obs("b", SelfQualityDimension::ProductOutcome, true),
        obs("a", SelfQualityDimension::ReliabilityAvailability, false),
    ]);
    assert_eq!(
        digest_self_quality_input(&fwd),
        digest_self_quality_input(&rev),
        "input digest order-independent"
    );
    let settled = canonicalize_self_quality_input(fwd).expect("canonical input validates");
    validate_self_quality_input(&settled).expect("v1 input validates");
    let handoff = SelfQualityHandoff {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        handoff_ref: "h:dev:v1".to_owned(),
        owner: SelfQualityHandoffOwner::DevelopmentDiagnosis675,
        symptom_refs: vec!["s:dev:v1".to_owned()],
        problem_refs: vec!["p:dev:v1".to_owned()],
        evidence_refs: vec!["e:dev:v1".to_owned()],
        missing_evidence_refs: vec!["m:dev:v1".to_owned()],
        applicability_refs: vec!["a:dev:v1".to_owned()],
        priority: Priority::Medium,
        constraint_refs: vec!["c:dev:v1".to_owned()],
        invalidation_set: vec!["x:dev:v1".to_owned()],
    };
    validate_handoff(&handoff).expect("inert handoff validates");
    let outcome = |dim| DimensionOutcome {
        dimension: dim,
        status: DimensionStatus::Pass,
        severity: Severity::Negligible,
        priority: Priority::None,
        hypothesis: CauseHypothesisStatus::Symptom,
        recurrence: Recurrence::OneShot,
    };
    let candidate = SelfQualityDiagnosisCandidate {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        candidate_ref: "cand:v1".to_owned(),
        input_digest: digest_self_quality_input(&settled),
        policy_digest: digest_self_quality_policy(&settled.policy),
        outcomes: vec![
            outcome(SelfQualityDimension::ProductOutcome),
            outcome(SelfQualityDimension::ReliabilityAvailability),
        ],
        overall_severity: Severity::Negligible,
        overall_priority: Priority::None,
        symptom_refs: vec!["s:b:v1".to_owned()],
        mechanism_refs: Vec::new(),
        counterevidence_refs: vec!["c:b:v1".to_owned()],
        handoffs: vec![handoff],
        expires_at_ms: 3_000,
    };
    validate_candidate_against_input(&candidate, &settled).expect("candidate binds v1 digests");
    let digest_a = digest_candidate(&candidate);
    let mut reordered = candidate.clone();
    reordered.outcomes.reverse();
    assert_eq!(
        digest_a,
        digest_candidate(&reordered),
        "candidate digest order-independent"
    );
    assert_eq!(
        reordered.handoffs[0].owner,
        SelfQualityHandoffOwner::DevelopmentDiagnosis675
    );
    validate_compatibility_version(SELF_QUALITY_CONTRACT_VERSION).expect("v1 compat");
    assert!(
        validate_compatibility_version(SELF_QUALITY_CONTRACT_VERSION + 1).is_err(),
        "wrong version rejected"
    );
}
