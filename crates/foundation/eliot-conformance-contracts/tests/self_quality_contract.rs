//! Contract proof for issue #971: bounded Self-Quality evidence + diagnosis.
//!
//! Exactly 20 cases (`// WORK_UNIT_CASE: 971/1..20`), one substantive test
//! per matrix row. Helpers build real contract values through the public
//! crate-root API; every test executes validation, canonicalization, or
//! digest logic and asserts the outcome.

use std::collections::BTreeSet;

use eliot_conformance_contracts::{
    BlockedDiagnosis, CONTRACT_SCHEMA, CONTRACT_VERSION, CapabilitySupportRow,
    CauseHypothesisStatus, ConflictedDiagnosis, ConformanceContractSet, ContractMaturity,
    DenominatorCompleteness, DimensionOutcome, DimensionStatus, DomainCoverage, EvidenceCeilings,
    EvidenceDomain, EvidenceExecutionStatus, ImplementationSupport, IncompleteDiagnosis,
    InterventionState, MetricMeasurement, MetricPresence, NoActionDisposition,
    NoProblemDisposition, ObservationCore, ObservationWindow, OwnerBinding, PriorDiagnosisRecord,
    Priority,     ProductContractRef, QualityDenominator, QualityLimits, Recurrence, SELF_QUALITY_CANDIDATE_SCHEMA,
    SELF_QUALITY_CONTRACT_VERSION, SELF_QUALITY_HANDOFF_SCHEMA, SELF_QUALITY_SCHEMA,
    SelfQualityContractError, SelfQualityDiagnosisCandidate, SelfQualityDimension,
    SelfQualityHandoff, SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation,
    SelfQualityPolicy, Severity, SourceIdentity, SupportObservationState, UnknownDiagnosis,
    canonicalize_dimension_outcomes, canonicalize_handoffs, canonicalize_observations,
    canonicalize_self_quality_input, digest_candidate, digest_self_quality_input,
    digest_self_quality_policy, validate_candidate_against_input, validate_compatibility_version,
    validate_conformance_contract_set, validate_denominator, validate_handoff,
    validate_no_action_against_input, validate_no_problem_against_input, validate_observation,
    validate_self_quality_input,
};
use serde_json::json;

const CREATED_AT: u64 = 2_000;

fn digest_for(label: &str) -> String {
    let mut out = String::new();
    for byte in label.bytes().chain(std::iter::repeat(0x9e)) {
        out.push_str(&format!("{byte:02x}"));
        if out.len() >= 32 {
            break;
        }
    }
    out
}

fn product_ref() -> ProductContractRef {
    ProductContractRef {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        objective_ref: "product:objective:v1".to_owned(),
        acceptance_ref: "product:acceptance:v1".to_owned(),
        recovery_ref: "product:recovery:v1".to_owned(),
    }
}

fn source_identity() -> SourceIdentity {
    SourceIdentity {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        source_ref: "source:repo:v1".to_owned(),
        artifact_ref: "artifact:build-42".to_owned(),
        configuration_ref: "config:prod:v3".to_owned(),
        generation_ref: "generation:7".to_owned(),
        task_ref: "task:diagnose-a".to_owned(),
        scope_ref: "scope:project-a".to_owned(),
        fence_ref: "fence:stable".to_owned(),
    }
}

fn window() -> ObservationWindow {
    ObservationWindow {
        observed_from_ms: 900,
        observed_to_ms: 1_100,
        environment_ref: "environment:prod".to_owned(),
        platform_ref: "platform:linux-x86_64".to_owned(),
        toolchain_ref: "toolchain:rust-1.94".to_owned(),
    }
}

fn owner(label: &str) -> OwnerBinding {
    OwnerBinding {
        owner_ref: format!("owner:{label}:v1"),
        schema_ref: format!("schema:{label}:v1"),
        revision_ref: format!("revision:{label}:r1"),
        content_digest: digest_for(label),
    }
}

fn measured_metric(label: &str) -> MetricMeasurement {
    MetricMeasurement {
        metric_ref: format!("metric:{label}:v1"),
        value: 1.0,
        unit_ref: "unit:ratio".to_owned(),
        normalization_ref: "normalization:z-score".to_owned(),
        population_ref: "population:edge-sample-100".to_owned(),
        presence: MetricPresence::Value,
    }
}

fn core(
    label: &str,
    dimension: SelfQualityDimension,
    status: DimensionStatus,
    metric: MetricMeasurement,
) -> ObservationCore {
    ObservationCore {
        observation_ref: format!("observation:{label}:v1"),
        dimension,
        owner: owner(label),
        window: window(),
        metric,
        completeness: DenominatorCompleteness::Complete,
        status,
        counterevidence_refs: vec![format!("counterevidence:{label}:v1")],
        confounder_refs: vec![format!("confounder:{label}:v1")],
        intervention_refs: vec![format!("intervention:{label}:v1")],
    }
}

fn trio_observations() -> Vec<SelfQualityObservation> {
    // Canonical family order: LIVENESS < PRODUCT < SERVICE.
    vec![
        SelfQualityObservation::Liveness(core(
            "liveness",
            SelfQualityDimension::ReliabilityAvailability,
            DimensionStatus::Pass,
            measured_metric("liveness"),
        )),
        SelfQualityObservation::Product(core(
            "product",
            SelfQualityDimension::ProductOutcome,
            DimensionStatus::Pass,
            measured_metric("product"),
        )),
        SelfQualityObservation::Service(core(
            "service",
            SelfQualityDimension::PerformanceResources,
            DimensionStatus::Pass,
            measured_metric("service"),
        )),
    ]
}

fn denominator_for(observations: &[SelfQualityObservation]) -> QualityDenominator {
    let dimensions: BTreeSet<SelfQualityDimension> = observations
        .iter()
        .map(|item| item.core().dimension)
        .collect();
    let sources: BTreeSet<&str> = observations
        .iter()
        .map(|item| item.core().owner.owner_ref.as_str())
        .collect();
    QualityDenominator {
        expected_dimensions: dimensions.len() as u32,
        supplied_dimensions: dimensions.len() as u32,
        expected_sources: sources.len() as u32,
        supplied_sources: sources.len() as u32,
        expected_members: observations.len() as u32,
        supplied_members: observations.len() as u32,
        completeness: DenominatorCompleteness::Complete,
    }
}

fn policy() -> SelfQualityPolicy {
    SelfQualityPolicy {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        policy_ref: "policy:self-quality:v1".to_owned(),
        schema_ref: "schema:policy:v1".to_owned(),
        revision_ref: "revision:policy:r1".to_owned(),
        rules_digest: digest_for("policy-rules"),
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
    }
}

fn ceilings() -> EvidenceCeilings {
    EvidenceCeilings {
        privacy_ceiling_ref: "ceiling:privacy:v1".to_owned(),
        authority_ceiling_ref: "ceiling:authority:v1".to_owned(),
        proof_ceiling_ref: "ceiling:proof:v1".to_owned(),
    }
}

fn history() -> Vec<PriorDiagnosisRecord> {
    vec![
        PriorDiagnosisRecord {
            diagnosis_ref: "diagnosis:previous:v1".to_owned(),
            intervention_ref: "intervention:observe:v1".to_owned(),
            intervention_state: InterventionState::Observed,
            recurrence: Recurrence::OneShot,
            hypothesis_status: CauseHypothesisStatus::Symptom,
            source_ref: "source:repo:v1".to_owned(),
            configuration_ref: "config:prod:v3".to_owned(),
            environment_ref: "environment:prod".to_owned(),
            observed_at_ms: 500,
        },
        PriorDiagnosisRecord {
            diagnosis_ref: "diagnosis:previous:v2".to_owned(),
            intervention_ref: "intervention:none:v1".to_owned(),
            intervention_state: InterventionState::NotAttempted,
            recurrence: Recurrence::Unknown,
            hypothesis_status: CauseHypothesisStatus::Hypothesis,
            source_ref: "source:repo:v1".to_owned(),
            configuration_ref: "config:prod:v3".to_owned(),
            environment_ref: "environment:prod".to_owned(),
            observed_at_ms: 800,
        },
    ]
}

fn valid_input() -> SelfQualityInput {
    let observations = trio_observations();
    let denominator = denominator_for(&observations);
    SelfQualityInput {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        input_ref: "input:self-quality:v1".to_owned(),
        product: product_ref(),
        source: source_identity(),
        observations,
        prior_history: history(),
        policy: policy(),
        ceilings: ceilings(),
        denominator,
        created_at_ms: CREATED_AT,
    }
}

fn valid_candidate(input: &SelfQualityInput) -> SelfQualityDiagnosisCandidate {
    let mut outcomes: Vec<DimensionOutcome> = input
        .observations
        .iter()
        .map(|observation| DimensionOutcome {
            dimension: observation.core().dimension,
            status: DimensionStatus::Pass,
            severity: Severity::Negligible,
            priority: Priority::None,
            hypothesis: CauseHypothesisStatus::Symptom,
            recurrence: Recurrence::OneShot,
        })
        .collect();
    outcomes.sort_by_key(|outcome| outcome.dimension);
    outcomes.dedup_by_key(|outcome| outcome.dimension);
    SelfQualityDiagnosisCandidate {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        candidate_ref: "candidate:self-quality:v1".to_owned(),
        input_digest: digest_self_quality_input(input),
        policy_digest: digest_self_quality_policy(&input.policy),
        outcomes,
        overall_severity: Severity::Negligible,
        overall_priority: Priority::None,
        symptom_refs: vec!["symptom:liveness:v1".to_owned()],
        mechanism_refs: Vec::new(),
        counterevidence_refs: vec!["counterevidence:liveness:v1".to_owned()],
        handoffs: Vec::new(),
        expires_at_ms: CREATED_AT + 1_000,
    }
}

fn valid_handoff(owner_kind: SelfQualityHandoffOwner, label: &str) -> SelfQualityHandoff {
    SelfQualityHandoff {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        handoff_ref: format!("handoff:{label}:v1"),
        owner: owner_kind,
        symptom_refs: vec![format!("symptom:{label}:v1")],
        problem_refs: vec![format!("problem:{label}:v1")],
        evidence_refs: vec![format!("evidence:{label}:v1")],
        missing_evidence_refs: vec![format!("missing:{label}:v1")],
        applicability_refs: vec![format!("applicability:{label}:v1")],
        priority: Priority::Medium,
        constraint_refs: vec![format!("constraint:{label}:v1")],
        invalidation_set: vec![format!("invalidate:{label}:v1")],
    }
}

// WORK_UNIT_CASE: 971/1
#[test]
fn source_bound_input_policy_diagnosis_handoff_vocabulary() {
    let input = valid_input();
    validate_self_quality_input(&input).expect("valid closed input");
    let candidate = valid_candidate(&input);
    validate_candidate_against_input(&candidate, &input).expect("valid candidate");
    let handoff = valid_handoff(SelfQualityHandoffOwner::DevelopmentDiagnosis675, "dev");
    validate_handoff(&handoff).expect("valid handoff");

    assert_eq!(SELF_QUALITY_CONTRACT_VERSION, 1);
    assert_eq!(SELF_QUALITY_SCHEMA, "eliot.self-quality.input.v1");
    assert_eq!(
        SELF_QUALITY_CANDIDATE_SCHEMA,
        "eliot.self-quality.candidate.v1"
    );
    assert_eq!(SELF_QUALITY_HANDOFF_SCHEMA, "eliot.self-quality.handoff.v1");
    assert_eq!(
        serde_json::to_value(DenominatorCompleteness::Complete).unwrap(),
        json!("COMPLETE")
    );
    assert_eq!(
        serde_json::to_value(MetricPresence::NoEventZero).unwrap(),
        json!("NO_EVENT_ZERO")
    );
    assert_eq!(
        serde_json::to_value(SelfQualityHandoffOwner::ConflictAnalysis673).unwrap(),
        json!("CONFLICT_ANALYSIS_673")
    );
    assert_eq!(
        serde_json::to_value(CauseHypothesisStatus::ProvenCause).unwrap(),
        json!("PROVEN_CAUSE")
    );
    validate_compatibility_version(SELF_QUALITY_CONTRACT_VERSION).expect("exact version");
    assert!(matches!(
        validate_compatibility_version(SELF_QUALITY_CONTRACT_VERSION + 1),
        Err(SelfQualityContractError::UnsupportedContractVersion { .. })
    ));
}

// WORK_UNIT_CASE: 971/2
#[test]
fn existing_conformance_types_unchanged() {
    let coverage: Vec<DomainCoverage> = EvidenceDomain::ALL
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
        .collect();
    let row = CapabilitySupportRow {
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
        evaluated_at_ms: 1_000,
    };
    let set = ConformanceContractSet {
        contract_version: CONTRACT_VERSION,
        evaluated_at_ms: 1_000,
        domain_coverage: coverage,
        support_rows: vec![row],
    };
    validate_conformance_contract_set(&set).expect("existing semantics unchanged");
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
    assert_ne!(CONTRACT_SCHEMA, SELF_QUALITY_SCHEMA);
}

// WORK_UNIT_CASE: 971/3
#[test]
fn product_objective_acceptance_recovery_not_metric_targets() {
    let product = product_ref();
    assert_ne!(product.objective_ref, product.acceptance_ref);
    assert_ne!(product.objective_ref, product.recovery_ref);

    let metric_substitute = json!({
        "contract_version": SELF_QUALITY_CONTRACT_VERSION,
        "metric_targets": ["metric:proxy:v1"],
    });
    assert!(serde_json::from_value::<ProductContractRef>(metric_substitute).is_err());

    let mut missing_objective = product_ref();
    missing_objective.objective_ref.clear();
    let mut input = valid_input();
    input.product = missing_objective;
    assert!(matches!(
        validate_self_quality_input(&input),
        Err(SelfQualityContractError::InvalidText { .. })
    ));

    let mut conflated = product_ref();
    conflated.acceptance_ref = conflated.objective_ref.clone();
    input.product = conflated;
    assert!(matches!(
        validate_self_quality_input(&input),
        Err(SelfQualityContractError::DuplicateValue { .. })
    ));

    let roundtrip: ProductContractRef =
        serde_json::from_value(serde_json::to_value(product_ref()).unwrap()).unwrap();
    assert_eq!(roundtrip, product_ref());
}

// WORK_UNIT_CASE: 971/4
#[test]
fn source_artifact_configuration_generation_task_fence_load_bearing() {
    validate_self_quality_input(&valid_input()).expect("valid source identity");
    let fields: [fn(&mut SourceIdentity); 7] = [
        |source| source.source_ref.clear(),
        |source| source.artifact_ref.clear(),
        |source| source.configuration_ref.clear(),
        |source| source.generation_ref.clear(),
        |source| source.task_ref.clear(),
        |source| source.scope_ref.clear(),
        |source| source.fence_ref.clear(),
    ];
    for clear in fields {
        let mut input = valid_input();
        clear(&mut input.source);
        assert!(
            validate_self_quality_input(&input).is_err(),
            "cleared source binding must fail"
        );
    }
    let mut duplicated = valid_input();
    duplicated.source.fence_ref = duplicated.source.scope_ref.clone();
    assert!(matches!(
        validate_self_quality_input(&duplicated),
        Err(SelfQualityContractError::DuplicateValue { .. })
    ));
}

// WORK_UNIT_CASE: 971/5
#[test]
fn owner_schema_revision_digest_window_environment_required() {
    validate_self_quality_input(&valid_input()).expect("valid bindings");
    let mut missing_owner = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut missing_owner.observations[0] {
        inner.owner.owner_ref.clear();
    }
    assert!(validate_self_quality_input(&missing_owner).is_err());

    let mut missing_schema = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut missing_schema.observations[0] {
        inner.owner.schema_ref.clear();
    }
    assert!(validate_self_quality_input(&missing_schema).is_err());

    let mut missing_revision = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut missing_revision.observations[0] {
        inner.owner.revision_ref.clear();
    }
    assert!(validate_self_quality_input(&missing_revision).is_err());

    let mut bad_digest = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut bad_digest.observations[0] {
        inner.owner.content_digest = "not-hex!!".to_owned();
    }
    assert!(matches!(
        validate_self_quality_input(&bad_digest),
        Err(SelfQualityContractError::InvalidDigest { .. })
    ));

    let mut bad_window = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut bad_window.observations[0] {
        inner.window.observed_from_ms = inner.window.observed_to_ms;
    }
    assert!(matches!(
        validate_self_quality_input(&bad_window),
        Err(SelfQualityContractError::InvalidWindow { .. })
    ));

    let mut missing_env = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut missing_env.observations[0] {
        inner.window.environment_ref.clear();
    }
    assert!(validate_self_quality_input(&missing_env).is_err());
}

// WORK_UNIT_CASE: 971/6
#[test]
fn complete_partial_unknown_denominator() {
    let wires: BTreeSet<String> = [
        DenominatorCompleteness::Complete,
        DenominatorCompleteness::Partial,
        DenominatorCompleteness::Unknown,
    ]
    .into_iter()
    .map(|value| serde_json::to_string(&value).unwrap())
    .collect();
    assert_eq!(wires.len(), 3);

    let observations = trio_observations();
    let complete = denominator_for(&observations);
    validate_denominator(&complete).expect("complete denominator");
    assert_eq!(complete.completeness, DenominatorCompleteness::Complete);

    let partial = QualityDenominator {
        expected_dimensions: complete.supplied_dimensions + 2,
        expected_sources: complete.supplied_sources + 2,
        expected_members: complete.supplied_members + 2,
        completeness: DenominatorCompleteness::Partial,
        ..complete
    };
    validate_denominator(&partial).expect("partial denominator");
    let mut partial_input = valid_input();
    partial_input.denominator = partial;
    validate_self_quality_input(&partial_input).expect("partial input validates");

    let unknown = QualityDenominator {
        expected_dimensions: 0,
        supplied_dimensions: 0,
        expected_sources: 0,
        supplied_sources: 0,
        expected_members: 0,
        supplied_members: 0,
        completeness: DenominatorCompleteness::Unknown,
    };
    validate_denominator(&unknown).expect("unknown standalone denominator");
    let mut unknown_input = valid_input();
    unknown_input.denominator = unknown;
    assert!(matches!(
        validate_self_quality_input(&unknown_input),
        Err(SelfQualityContractError::InvalidDenominator { .. })
    ));

    let mut overstated = complete;
    overstated.supplied_members += 1;
    assert!(matches!(
        validate_denominator(&overstated),
        Err(SelfQualityContractError::InvalidDenominator { .. })
    ));
}

// WORK_UNIT_CASE: 971/7
#[test]
fn zero_no_event_distinct_from_unavailable_unmeasured() {
    let wires: BTreeSet<String> = [
        MetricPresence::NoEventZero,
        MetricPresence::Value,
        MetricPresence::Unavailable,
        MetricPresence::Unmeasured,
    ]
    .into_iter()
    .map(|value| serde_json::to_string(&value).unwrap())
    .collect();
    assert_eq!(wires.len(), 4);

    let mut zero = measured_metric("zero");
    zero.value = 0.0;
    zero.presence = MetricPresence::NoEventZero;
    validate_observation(&SelfQualityObservation::Runtime(core(
        "zero",
        SelfQualityDimension::RealEdgeEvidence,
        DimensionStatus::Pass,
        zero,
    )))
    .expect("observed zero");

    let mut false_zero = measured_metric("false-zero");
    false_zero.value = 1.0;
    false_zero.presence = MetricPresence::NoEventZero;
    assert!(matches!(
        validate_observation(&SelfQualityObservation::Runtime(core(
            "false-zero",
            SelfQualityDimension::RealEdgeEvidence,
            DimensionStatus::Pass,
            false_zero,
        ))),
        Err(SelfQualityContractError::InvalidMetric { .. })
    ));

    let mut unavailable = measured_metric("unavailable");
    unavailable.value = 0.0;
    unavailable.presence = MetricPresence::Unavailable;
    validate_observation(&SelfQualityObservation::Runtime(core(
        "unavailable",
        SelfQualityDimension::RealEdgeEvidence,
        DimensionStatus::Missing,
        unavailable,
    )))
    .expect("unavailable with missing status");

    let mut missing_as_value = measured_metric("missing-value");
    missing_as_value.presence = MetricPresence::Unavailable;
    assert!(matches!(
        validate_observation(&SelfQualityObservation::Runtime(core(
            "missing-value",
            SelfQualityDimension::RealEdgeEvidence,
            DimensionStatus::Missing,
            missing_as_value,
        ))),
        Err(SelfQualityContractError::InvalidMetric { .. })
    ));

    let mut missing_claimed = measured_metric("missing-claimed");
    missing_claimed.value = 0.0;
    missing_claimed.presence = MetricPresence::Unmeasured;
    assert!(matches!(
        validate_observation(&SelfQualityObservation::Runtime(core(
            "missing-claimed",
            SelfQualityDimension::RealEdgeEvidence,
            DimensionStatus::Pass,
            missing_claimed,
        ))),
        Err(SelfQualityContractError::MissingEvidence { .. })
    ));
}

// WORK_UNIT_CASE: 971/8
#[test]
fn metric_unit_normalization_population_exact() {
    validate_self_quality_input(&valid_input()).expect("valid metric identity");
    for clear in [
        |metric: &mut MetricMeasurement| metric.unit_ref.clear(),
        |metric: &mut MetricMeasurement| metric.normalization_ref.clear(),
        |metric: &mut MetricMeasurement| metric.population_ref.clear(),
    ] as [fn(&mut MetricMeasurement); 3]
    {
        let mut input = valid_input();
        if let SelfQualityObservation::Liveness(inner) = &mut input.observations[0] {
            clear(&mut inner.metric);
        }
        assert!(validate_self_quality_input(&input).is_err());
    }

    let first = measured_metric("exact");
    let mut second = measured_metric("exact");
    second.unit_ref = "unit:milliseconds".to_owned();
    assert_ne!(first, second);
    validate_observation(&SelfQualityObservation::Runtime(core(
        "exact-a",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
        first,
    )))
    .expect("first unit triple");
    validate_observation(&SelfQualityObservation::Runtime(core(
        "exact-b",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
        second,
    )))
    .expect("second unit triple");
}

// WORK_UNIT_CASE: 971/9
#[test]
fn liveness_service_semantic_recovery_product_distinct() {
    let live = SelfQualityObservation::Liveness(core(
        "live",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Pass,
        measured_metric("live"),
    ));
    let service = SelfQualityObservation::Service(core(
        "service-9",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Pass,
        measured_metric("service-9"),
    ));
    let semantic = SelfQualityObservation::Semantic(core(
        "semantic",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        measured_metric("semantic"),
    ));
    let recovery = SelfQualityObservation::Recovery(core(
        "recovery",
        SelfQualityDimension::AcceptanceRecovery,
        DimensionStatus::Pass,
        measured_metric("recovery"),
    ));
    let product = SelfQualityObservation::Product(core(
        "product-9",
        SelfQualityDimension::ProductOutcome,
        DimensionStatus::Pass,
        measured_metric("product-9"),
    ));
    for observation in [&live, &service, &semantic, &recovery, &product] {
        validate_observation(observation).expect("structural variant validates");
    }
    let keys: BTreeSet<String> = [&live, &service, &semantic, &recovery, &product]
        .into_iter()
        .map(|observation| {
            serde_json::to_value(observation)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone()
        })
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "LIVENESS".to_owned(),
            "SERVICE".to_owned(),
            "SEMANTIC".to_owned(),
            "RECOVERY".to_owned(),
            "PRODUCT".to_owned(),
        ])
    );
    let live_json = serde_json::to_value(&live).unwrap();
    let revived: SelfQualityObservation = serde_json::from_value(live_json.clone()).unwrap();
    assert_eq!(revived, live);
    assert_ne!(serde_json::to_value(&service).unwrap(), live_json);
}

// WORK_UNIT_CASE: 971/10
#[test]
fn learning_delivery_use_outcome_closure_distinct() {
    let delivery = SelfQualityObservation::LearningDelivery(core(
        "learning-delivery",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        measured_metric("learning-delivery"),
    ));
    let used = SelfQualityObservation::LearningUse(core(
        "learning-use",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        measured_metric("learning-use"),
    ));
    let outcome = SelfQualityObservation::LearningOutcome(core(
        "learning-outcome",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Partial,
        measured_metric("learning-outcome"),
    ));
    let closure = SelfQualityObservation::LearningClosure(core(
        "learning-closure",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        measured_metric("learning-closure"),
    ));
    for observation in [&delivery, &used, &outcome, &closure] {
        validate_observation(observation).expect("learning stage validates");
    }
    let keys: BTreeSet<String> = [&delivery, &used, &outcome, &closure]
        .into_iter()
        .map(|observation| {
            serde_json::to_value(observation)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone()
        })
        .collect();
    assert_eq!(keys.len(), 4);
    assert!(keys.contains("LEARNING_DELIVERY"));
    assert!(keys.contains("LEARNING_USE"));
    assert!(keys.contains("LEARNING_OUTCOME"));
    assert!(keys.contains("LEARNING_CLOSURE"));
    assert_eq!(
        eliot_conformance_contracts::ISSUE_A37_LEARNING_CLOSURE,
        819,
        "A-37 learning closure is #819, never #809"
    );
    assert_ne!(eliot_conformance_contracts::ISSUE_A37_LEARNING_CLOSURE, 809);
}

// WORK_UNIT_CASE: 971/11
#[test]
fn symptom_hypothesis_cause_recurrence_lineage_distinct() {
    let hypothesis_wires: BTreeSet<String> = [
        CauseHypothesisStatus::Symptom,
        CauseHypothesisStatus::Hypothesis,
        CauseHypothesisStatus::ProvenCause,
    ]
    .into_iter()
    .map(|value| serde_json::to_string(&value).unwrap())
    .collect();
    assert_eq!(hypothesis_wires.len(), 3);
    let recurrence_wires: BTreeSet<String> = [
        Recurrence::OneShot,
        Recurrence::Persistent,
        Recurrence::Recurrent,
        Recurrence::Flaky,
        Recurrence::Unknown,
    ]
    .into_iter()
    .map(|value| serde_json::to_string(&value).unwrap())
    .collect();
    assert_eq!(recurrence_wires.len(), 5);
    let lineage_wires: BTreeSet<String> = [
        InterventionState::Observed,
        InterventionState::Censored,
        InterventionState::NotAttempted,
        InterventionState::Applied,
        InterventionState::RolledBack,
        InterventionState::Partial,
        InterventionState::Failed,
        InterventionState::Unknown,
    ]
    .into_iter()
    .map(|value| serde_json::to_string(&value).unwrap())
    .collect();
    assert_eq!(lineage_wires.len(), 8);

    let proven_pass = DimensionOutcome {
        dimension: SelfQualityDimension::Correctness,
        status: DimensionStatus::Pass,
        severity: Severity::Negligible,
        priority: Priority::None,
        hypothesis: CauseHypothesisStatus::ProvenCause,
        recurrence: Recurrence::OneShot,
    };
    assert!(matches!(
        eliot_conformance_contracts::validate_dimension_outcome(&proven_pass),
        Err(SelfQualityContractError::InvalidHypothesis { .. })
    ));
    let proven_fail = DimensionOutcome {
        status: DimensionStatus::Fail,
        severity: Severity::High,
        priority: Priority::High,
        hypothesis: CauseHypothesisStatus::ProvenCause,
        ..proven_pass
    };
    eliot_conformance_contracts::validate_dimension_outcome(&proven_fail)
        .expect("proven cause of a failure");

    let input = valid_input();
    let mut candidate = valid_candidate(&input);
    candidate.outcomes[0].hypothesis = CauseHypothesisStatus::ProvenCause;
    candidate.outcomes[0].status = DimensionStatus::Fail;
    candidate.outcomes[0].severity = Severity::High;
    candidate.outcomes[0].priority = Priority::High;
    candidate.overall_severity = Severity::High;
    candidate.overall_priority = Priority::High;
    assert!(matches!(
        validate_candidate_against_input(&candidate, &input),
        Err(SelfQualityContractError::MissingEvidence { .. })
    ));
    candidate.mechanism_refs = vec!["mechanism:root-cause:v1".to_owned()];
    validate_candidate_against_input(&candidate, &input).expect("mechanism bound to proof");

    let mut invented = valid_candidate(&input);
    invented.mechanism_refs = vec!["mechanism:guess:v1".to_owned()];
    assert!(matches!(
        validate_candidate_against_input(&invented, &input),
        Err(SelfQualityContractError::InvalidHypothesis { .. })
    ));
}

// WORK_UNIT_CASE: 971/12
#[test]
fn dimensions_severity_priority_not_pass_scalar() {
    let with_scalar = json!({
        "dimension": "CORRECTNESS",
        "status": "PASS",
        "severity": "NEGLIGIBLE",
        "priority": "NONE",
        "hypothesis": "SYMPTOM",
        "recurrence": "ONE_SHOT",
        "pass": true,
    });
    assert!(serde_json::from_value::<DimensionOutcome>(with_scalar).is_err());

    let low = DimensionOutcome {
        dimension: SelfQualityDimension::ReliabilityAvailability,
        status: DimensionStatus::Fail,
        severity: Severity::Low,
        priority: Priority::Low,
        hypothesis: CauseHypothesisStatus::Hypothesis,
        recurrence: Recurrence::Recurrent,
    };
    let high = DimensionOutcome {
        severity: Severity::High,
        priority: Priority::Urgent,
        ..low
    };
    eliot_conformance_contracts::validate_dimension_outcome(&low).expect("low axis");
    eliot_conformance_contracts::validate_dimension_outcome(&high).expect("high axis");
    assert_ne!(low, high);

    let input = valid_input();
    let mut candidate = valid_candidate(&input);
    // Input dimensions in canonical order: ProductOutcome, ReliabilityAvailability,
    // PerformanceResources. The failing axis replaces the first passing outcome.
    candidate.outcomes = vec![
        DimensionOutcome {
            dimension: SelfQualityDimension::ProductOutcome,
            status: DimensionStatus::Pass,
            severity: Severity::Negligible,
            priority: Priority::None,
            hypothesis: CauseHypothesisStatus::Symptom,
            recurrence: Recurrence::OneShot,
        },
        low,
        DimensionOutcome {
            dimension: SelfQualityDimension::PerformanceResources,
            status: DimensionStatus::Pass,
            severity: Severity::Negligible,
            priority: Priority::None,
            hypothesis: CauseHypothesisStatus::Symptom,
            recurrence: Recurrence::OneShot,
        },
    ];
    candidate.overall_severity = Severity::Negligible;
    candidate.overall_priority = Priority::None;
    assert!(matches!(
        validate_candidate_against_input(&candidate, &input),
        Err(SelfQualityContractError::InvalidSeverityCombination { .. })
    ));
    candidate.overall_severity = Severity::Low;
    candidate.overall_priority = Priority::Low;
    validate_candidate_against_input(&candidate, &input).expect("maxima aggregate");
}

// WORK_UNIT_CASE: 971/13
#[test]
fn no_problem_no_action_distinct_from_missing_evidence() {
    let input = valid_input();
    let digest = digest_self_quality_input(&input);
    let dimensions: Vec<SelfQualityDimension> = input
        .observations
        .iter()
        .map(|item| item.core().dimension)
        .collect();
    let no_problem = NoProblemDisposition {
        input_digest: digest.clone(),
        completed_dimensions: dimensions,
        window: window(),
    };
    validate_no_problem_against_input(&no_problem, &input).expect("backed no-problem");
    let no_action = NoActionDisposition {
        input_digest: digest.clone(),
        justification_refs: vec!["justification:tolerated:v1".to_owned()],
        tolerated_dimensions: Vec::new(),
    };
    validate_no_action_against_input(&no_action, &input).expect("backed no-action");

    let mut partial_input = valid_input();
    if let SelfQualityObservation::Product(inner) = &mut partial_input.observations[1] {
        inner.status = DimensionStatus::Partial;
    }
    let partial_no_problem = NoProblemDisposition {
        input_digest: digest_self_quality_input(&partial_input),
        completed_dimensions: partial_input
            .observations
            .iter()
            .map(|item| item.core().dimension)
            .collect(),
        window: window(),
    };
    assert!(matches!(
        validate_no_problem_against_input(&partial_no_problem, &partial_input),
        Err(SelfQualityContractError::InvalidSeverityCombination { .. })
    ));
    assert!(validate_no_problem_against_input(&no_problem, &partial_input).is_err());
    let partial_no_action = NoActionDisposition {
        input_digest: digest_self_quality_input(&partial_input),
        justification_refs: vec!["justification:partial:v1".to_owned()],
        tolerated_dimensions: vec![SelfQualityDimension::ProductOutcome],
    };
    validate_no_action_against_input(&partial_no_action, &partial_input)
        .expect("tolerated partial no-action");

    let mut missing_input = valid_input();
    if let SelfQualityObservation::Product(inner) = &mut missing_input.observations[1] {
        inner.status = DimensionStatus::Missing;
        inner.metric.value = 0.0;
        inner.metric.presence = MetricPresence::Unmeasured;
    }
    validate_self_quality_input(&missing_input).expect("missing is representable");
    assert!(validate_no_problem_against_input(&no_problem, &missing_input).is_err());
    let missing_no_action = NoActionDisposition {
        input_digest: digest_self_quality_input(&missing_input),
        justification_refs: vec!["justification:missing:v1".to_owned()],
        tolerated_dimensions: Vec::new(),
    };
    assert!(validate_no_action_against_input(&missing_no_action, &missing_input).is_err());
    let incomplete = IncompleteDiagnosis {
        input_digest: digest_self_quality_input(&missing_input),
        missing_evidence_refs: vec!["missing:product:v1".to_owned()],
    };
    eliot_conformance_contracts::validate_incomplete_against_input(&incomplete, &missing_input)
        .expect("incomplete names its gap");
}

// WORK_UNIT_CASE: 971/14
#[test]
fn every_input_family_without_generic_value_or_duplicate_schema() {
    let observations = vec![
        SelfQualityObservation::Conformance(core(
            "conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Pass,
            measured_metric("conformance"),
        )),
        SelfQualityObservation::SourceBuild(core(
            "source-build",
            SelfQualityDimension::Correctness,
            DimensionStatus::Pass,
            measured_metric("source-build"),
        )),
        SelfQualityObservation::RealEdge(core(
            "real-edge",
            SelfQualityDimension::RealEdgeEvidence,
            DimensionStatus::Pass,
            measured_metric("real-edge"),
        )),
        SelfQualityObservation::Runtime(core(
            "runtime-14",
            SelfQualityDimension::ReliabilityAvailability,
            DimensionStatus::Pass,
            measured_metric("runtime-14"),
        )),
        SelfQualityObservation::Liveness(core(
            "liveness-14",
            SelfQualityDimension::ReliabilityAvailability,
            DimensionStatus::Pass,
            measured_metric("liveness-14"),
        )),
        SelfQualityObservation::Service(core(
            "service-14",
            SelfQualityDimension::PerformanceResources,
            DimensionStatus::Pass,
            measured_metric("service-14"),
        )),
        SelfQualityObservation::Semantic(core(
            "semantic-14",
            SelfQualityDimension::Correctness,
            DimensionStatus::Pass,
            measured_metric("semantic-14"),
        )),
        SelfQualityObservation::Recovery(core(
            "recovery-14",
            SelfQualityDimension::AcceptanceRecovery,
            DimensionStatus::Pass,
            measured_metric("recovery-14"),
        )),
        SelfQualityObservation::Product(core(
            "product-14",
            SelfQualityDimension::ProductOutcome,
            DimensionStatus::Pass,
            measured_metric("product-14"),
        )),
        SelfQualityObservation::ContextFloor(core(
            "context-floor",
            SelfQualityDimension::ContextQuality,
            DimensionStatus::Pass,
            measured_metric("context-floor"),
        )),
        SelfQualityObservation::ContextSelection(core(
            "context-selection",
            SelfQualityDimension::ContextQuality,
            DimensionStatus::Pass,
            measured_metric("context-selection"),
        )),
        SelfQualityObservation::ContextQuality(core(
            "context-quality",
            SelfQualityDimension::ContextQuality,
            DimensionStatus::Pass,
            measured_metric("context-quality"),
        )),
        SelfQualityObservation::ContextEconomy(core(
            "context-economy",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            measured_metric("context-economy"),
        )),
        SelfQualityObservation::DreamerGrounding(core(
            "dreamer-grounding",
            SelfQualityDimension::DreamerQuality,
            DimensionStatus::Pass,
            measured_metric("dreamer-grounding"),
        )),
        SelfQualityObservation::DreamerCandidate(core(
            "dreamer-candidate",
            SelfQualityDimension::DreamerQuality,
            DimensionStatus::Pass,
            measured_metric("dreamer-candidate"),
        )),
        SelfQualityObservation::DreamerController(core(
            "dreamer-controller",
            SelfQualityDimension::DreamerQuality,
            DimensionStatus::Pass,
            measured_metric("dreamer-controller"),
        )),
        SelfQualityObservation::LearningDelivery(core(
            "learning-delivery-14",
            SelfQualityDimension::LearningQuality,
            DimensionStatus::Pass,
            measured_metric("learning-delivery-14"),
        )),
        SelfQualityObservation::LearningUse(core(
            "learning-use-14",
            SelfQualityDimension::LearningQuality,
            DimensionStatus::Pass,
            measured_metric("learning-use-14"),
        )),
        SelfQualityObservation::LearningOutcome(core(
            "learning-outcome-14",
            SelfQualityDimension::LearningQuality,
            DimensionStatus::Pass,
            measured_metric("learning-outcome-14"),
        )),
        SelfQualityObservation::LearningClosure(core(
            "learning-closure-14",
            SelfQualityDimension::LearningQuality,
            DimensionStatus::Pass,
            measured_metric("learning-closure-14"),
        )),
        SelfQualityObservation::MemoryProvenance(core(
            "memory-provenance",
            SelfQualityDimension::MemoryQuality,
            DimensionStatus::Pass,
            measured_metric("memory-provenance"),
        )),
        SelfQualityObservation::MemoryConflict(core(
            "memory-conflict",
            SelfQualityDimension::MemoryQuality,
            DimensionStatus::Pass,
            measured_metric("memory-conflict"),
        )),
        SelfQualityObservation::SecurityPrivacy(core(
            "security-privacy",
            SelfQualityDimension::SecurityPrivacy,
            DimensionStatus::Pass,
            measured_metric("security-privacy"),
        )),
        SelfQualityObservation::ErasureInfluence(core(
            "erasure-influence",
            SelfQualityDimension::SecurityPrivacy,
            DimensionStatus::Pass,
            measured_metric("erasure-influence"),
        )),
        SelfQualityObservation::PerformanceResources(core(
            "performance-resources",
            SelfQualityDimension::PerformanceResources,
            DimensionStatus::Pass,
            measured_metric("performance-resources"),
        )),
        SelfQualityObservation::CostQuota(core(
            "cost-quota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            measured_metric("cost-quota"),
        )),
        SelfQualityObservation::HumanAttention(core(
            "human-attention",
            SelfQualityDimension::HumanBurden,
            DimensionStatus::Pass,
            measured_metric("human-attention"),
        )),
        SelfQualityObservation::RecoveryCompatibility(core(
            "recovery-compatibility",
            SelfQualityDimension::Compatibility,
            DimensionStatus::Pass,
            measured_metric("recovery-compatibility"),
        )),
    ];
    assert_eq!(observations.len(), 28);
    let families: BTreeSet<&str> = observations
        .iter()
        .map(SelfQualityObservation::family_name)
        .collect();
    assert_eq!(families.len(), 28);
    for observation in &observations {
        validate_observation(observation).expect("every family validates");
    }

    let mut generic = serde_json::to_value(&observations[4]).unwrap();
    generic
        .as_object_mut()
        .unwrap()
        .get_mut("LIVENESS")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("value".to_owned(), json!({"arbitrary": [1, 2, 3]}));
    assert!(serde_json::from_value::<SelfQualityObservation>(generic).is_err());
    assert!(serde_json::from_value::<SelfQualityObservation>(json!({"TELEMETRY": {}})).is_err());
}

// WORK_UNIT_CASE: 971/15
#[test]
fn exact_handoff_owners_including_correct_a37() {
    let wires: BTreeSet<String> = SelfQualityHandoffOwner::ALL
        .into_iter()
        .map(|owner_kind| serde_json::to_string(&owner_kind).unwrap())
        .collect();
    assert_eq!(wires.len(), 11);
    assert_eq!(SelfQualityHandoffOwner::ALL.len(), 11);

    assert_eq!(
        SelfQualityHandoffOwner::ConflictAnalysis673.issue_number(),
        Some(673)
    );
    assert_eq!(
        SelfQualityHandoffOwner::DevelopmentDiagnosis675.issue_number(),
        Some(675)
    );
    assert_eq!(
        SelfQualityHandoffOwner::MaintenancePlan677.issue_number(),
        Some(677)
    );
    assert_eq!(
        SelfQualityHandoffOwner::ConfigurationAssistance679.issue_number(),
        Some(679)
    );
    assert_eq!(
        SelfQualityHandoffOwner::Instrumentation.issue_number(),
        None
    );
    assert_eq!(
        SelfQualityHandoffOwner::IncidentRecovery.issue_number(),
        None
    );
    assert_eq!(
        SelfQualityHandoffOwner::UnsupportedOwner.issue_number(),
        None
    );
    assert!(SelfQualityHandoffOwner::HumanPolicy.is_human());
    assert!(!SelfQualityHandoffOwner::Instrumentation.is_human());

    assert_eq!(eliot_conformance_contracts::ISSUE_A37_LEARNING_CLOSURE, 819);
    assert_eq!(
        eliot_conformance_contracts::ISSUE_A36_LEARNING_ACTIVATION,
        620
    );
    assert_eq!(
        eliot_conformance_contracts::ISSUE_A39_CONFLICT_ANALYSIS,
        673
    );
    assert_eq!(
        eliot_conformance_contracts::ISSUE_A40_DEVELOPMENT_DIAGNOSIS,
        675
    );
    assert_eq!(eliot_conformance_contracts::ISSUE_A41_MAINTENANCE_PLAN, 677);
    assert_eq!(
        eliot_conformance_contracts::ISSUE_A42_CONFIGURATION_ASSISTANCE,
        679
    );

    for (owner_kind, label) in [
        (SelfQualityHandoffOwner::Instrumentation, "instrumentation"),
        (SelfQualityHandoffOwner::ConflictAnalysis673, "conflict"),
        (
            SelfQualityHandoffOwner::DevelopmentDiagnosis675,
            "development",
        ),
        (SelfQualityHandoffOwner::MaintenancePlan677, "maintenance"),
        (
            SelfQualityHandoffOwner::ConfigurationAssistance679,
            "configuration",
        ),
        (SelfQualityHandoffOwner::IncidentRecovery, "incident"),
        (SelfQualityHandoffOwner::HumanObjective, "human-objective"),
        (SelfQualityHandoffOwner::HumanPolicy, "human-policy"),
        (SelfQualityHandoffOwner::HumanPrivacy, "human-privacy"),
        (SelfQualityHandoffOwner::HumanCostRisk, "human-cost"),
        (SelfQualityHandoffOwner::UnsupportedOwner, "unsupported"),
    ] {
        validate_handoff(&valid_handoff(owner_kind, label)).expect("owner handoff");
    }
}

// WORK_UNIT_CASE: 971/16
#[test]
fn handoff_cannot_encode_job_issue_plan_executable_effect_promotion_finish() {
    let handoff = valid_handoff(SelfQualityHandoffOwner::MaintenancePlan677, "plan-proof");
    validate_handoff(&handoff).expect("valid handoff");
    let base = serde_json::to_value(&handoff).unwrap();
    for forbidden in [
        "job_ref",
        "issue_ref",
        "plan_ref",
        "executable_ref",
        "effect_token",
        "promotion_ref",
        "finish_token",
    ] {
        let mut tampered = base.clone();
        tampered
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), json!("forged:token:v1"));
        assert!(
            serde_json::from_value::<SelfQualityHandoff>(tampered).is_err(),
            "{forbidden} must be rejected"
        );
    }
    let keys: BTreeSet<String> = base.as_object().unwrap().keys().cloned().collect();
    for forbidden in [
        "job_ref",
        "issue_ref",
        "plan_ref",
        "executable_ref",
        "effect_token",
        "promotion_ref",
        "finish_token",
    ] {
        assert!(!keys.contains(forbidden));
    }
}

// WORK_UNIT_CASE: 971/17
#[test]
fn unknown_duplicate_raw_fields_variants_protected_defaults_rejected() {
    let mut unknown_field = serde_json::to_value(valid_input()).unwrap();
    unknown_field
        .as_object_mut()
        .unwrap()
        .insert("diagnosis".to_owned(), json!({"score": 1}));
    assert!(serde_json::from_value::<SelfQualityInput>(unknown_field).is_err());

    let unknown_variant = json!({"dimension": "VIBES"});
    assert!(serde_json::from_value::<SelfQualityDimension>(unknown_variant).is_err());

    let mut duplicated = trio_observations();
    duplicated.push(duplicated[0].clone());
    assert!(matches!(
        canonicalize_observations(duplicated),
        Err(SelfQualityContractError::DuplicateObservation { .. })
    ));

    let mut protected = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut protected.observations[0] {
        inner.owner.owner_ref = "default".to_owned();
    }
    assert!(matches!(
        validate_self_quality_input(&protected),
        Err(SelfQualityContractError::ProtectedDefault { .. })
    ));

    let mut zero_version = valid_input();
    zero_version.contract_version = 0;
    assert!(matches!(
        validate_self_quality_input(&zero_version),
        Err(SelfQualityContractError::UnsupportedContractVersion { .. })
    ));

    let mut duplicate_dims = valid_candidate(&valid_input());
    duplicate_dims.outcomes.push(duplicate_dims.outcomes[0]);
    assert!(canonicalize_dimension_outcomes(duplicate_dims.outcomes).is_err());

    let mut duplicate_handoffs = vec![
        valid_handoff(SelfQualityHandoffOwner::Instrumentation, "dup"),
        valid_handoff(SelfQualityHandoffOwner::Instrumentation, "dup"),
    ];
    duplicate_handoffs[1].symptom_refs = vec!["symptom:other:v1".to_owned()];
    assert!(canonicalize_handoffs(duplicate_handoffs).is_err());
}

// WORK_UNIT_CASE: 971/18
#[test]
fn bounds_overflow_semantic_order_digest_redaction() {
    let bulk_labels: Vec<String> = (0..257).map(|index| format!("bulk-{index:04}")).collect();
    let bulk_metrics: Vec<String> = (0..257)
        .map(|index| format!("bulk-metric-{index:04}"))
        .collect();
    let oversized: Vec<SelfQualityObservation> = bulk_labels
        .iter()
        .zip(bulk_metrics.iter())
        .map(|(label, metric)| {
            SelfQualityObservation::Runtime(core(
                label,
                SelfQualityDimension::ReliabilityAvailability,
                DimensionStatus::Pass,
                measured_metric(metric),
            ))
        })
        .collect();
    assert!(matches!(
        canonicalize_observations(oversized),
        Err(SelfQualityContractError::CollectionTooLarge { .. })
    ));

    let mut overlong = valid_input();
    if let SelfQualityObservation::Liveness(inner) = &mut overlong.observations[0] {
        inner.observation_ref = "r".repeat(1_025);
    }
    assert!(matches!(
        validate_self_quality_input(&overlong),
        Err(SelfQualityContractError::InvalidText { .. })
    ));

    let mut nan = measured_metric("nan");
    nan.value = f64::NAN;
    assert!(matches!(
        validate_observation(&SelfQualityObservation::Runtime(core(
            "nan",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            nan,
        ))),
        Err(SelfQualityContractError::InvalidMetric { .. })
    ));

    let mut swapped = valid_input();
    swapped.observations.swap(0, 1);
    assert!(matches!(
        validate_self_quality_input(&swapped),
        Err(SelfQualityContractError::NonCanonicalCollection { .. })
    ));
    let restored = canonicalize_self_quality_input(swapped).expect("order canonicalizes");
    validate_self_quality_input(&restored).expect("restored input validates");

    let input = valid_input();
    let first = digest_self_quality_input(&input);
    let second = digest_self_quality_input(&input);
    assert_eq!(first, second);
    assert_eq!(first.len(), 16);
    let mut permuted = valid_input();
    permuted.observations.reverse();
    assert_eq!(digest_self_quality_input(&permuted), first);
    let mut reduced = valid_input();
    reduced.observations.pop();
    reduced.denominator = denominator_for(&reduced.observations);
    assert_ne!(digest_self_quality_input(&reduced), first);

    let mut secret = measured_metric("secret");
    secret.value = 999.123_456;
    secret.presence = MetricPresence::Unavailable;
    let err = validate_observation(&SelfQualityObservation::Runtime(core(
        "secret",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        secret,
    )))
    .unwrap_err();
    assert!(!format!("{err}").contains("999.123"));
}

// WORK_UNIT_CASE: 971/19
#[test]
fn independent_consumer_compiles_through_public_contracts_standalone() {
    let mut observations = trio_observations();
    observations.reverse();
    let denominator = denominator_for(&trio_observations());
    let input = SelfQualityInput {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        input_ref: "input:consumer:v1".to_owned(),
        product: product_ref(),
        source: source_identity(),
        observations,
        prior_history: history(),
        policy: policy(),
        ceilings: ceilings(),
        denominator,
        created_at_ms: CREATED_AT,
    };
    let canonical = canonicalize_self_quality_input(input).expect("consumer canonicalizes");
    validate_self_quality_input(&canonical).expect("consumer input validates");
    let candidate = valid_candidate(&canonical);
    validate_candidate_against_input(&candidate, &canonical).expect("consumer candidate");
    let handoff = valid_handoff(SelfQualityHandoffOwner::Instrumentation, "consumer");
    validate_handoff(&handoff).expect("consumer handoff");
    let mut with_handoff = candidate;
    with_handoff.handoffs = canonicalize_handoffs(vec![handoff]).expect("consumer handoffs");
    with_handoff.candidate_ref = "candidate:consumer:v1".to_owned();
    validate_candidate_against_input(&with_handoff, &canonical).expect("candidate with handoff");
    let _ = digest_candidate(&with_handoff);

    let forward = canonicalize_self_quality_input(valid_input()).expect("forward order");
    assert_eq!(
        forward.observations,
        canonicalize_self_quality_input(valid_input())
            .unwrap()
            .observations
    );
    assert_ne!(CONTRACT_SCHEMA, SELF_QUALITY_SCHEMA);
}

// WORK_UNIT_CASE: 971/20
#[test]
fn no_algorithm_live_read_mutable_state_or_authority() {
    let input = valid_input();
    let snapshot = input.clone();
    validate_self_quality_input(&input).expect("pure validation");
    assert_eq!(input, snapshot, "validation never mutates its input");
    assert_eq!(
        digest_self_quality_input(&input),
        digest_self_quality_input(&snapshot)
    );

    let empty = SelfQualityInput {
        observations: Vec::new(),
        denominator: QualityDenominator {
            expected_dimensions: 0,
            supplied_dimensions: 0,
            expected_sources: 0,
            supplied_sources: 0,
            expected_members: 0,
            supplied_members: 0,
            completeness: DenominatorCompleteness::Unknown,
        },
        ..valid_input()
    };
    assert!(matches!(
        validate_self_quality_input(&empty),
        Err(SelfQualityContractError::EmptyCoverage)
    ));

    let mut unrepairable = trio_observations();
    unrepairable.push(unrepairable[0].clone());
    assert!(canonicalize_observations(unrepairable).is_err());

    let candidate = valid_candidate(&input);
    let mut forged = candidate;
    forged.input_digest = digest_for("forged-input");
    assert!(matches!(
        validate_candidate_against_input(&forged, &input),
        Err(SelfQualityContractError::DigestMismatch { .. })
    ));
    let mut forged_policy = valid_candidate(&input);
    forged_policy.policy_digest = digest_for("forged-policy");
    assert!(matches!(
        validate_candidate_against_input(&forged_policy, &input),
        Err(SelfQualityContractError::DigestMismatch { .. })
    ));

    let blocked = BlockedDiagnosis {
        input_digest: digest_self_quality_input(&input),
        blocker_refs: vec!["blocker:privacy:v1".to_owned()],
    };
    eliot_conformance_contracts::validate_blocked_against_input(&blocked, &input)
        .expect("blocked binds digest");
    let conflicted = ConflictedDiagnosis {
        input_digest: digest_self_quality_input(&input),
        conflict_refs: vec!["evidence:a:v1".to_owned()],
    };
    assert!(
        eliot_conformance_contracts::validate_conflicted_against_input(&conflicted, &input)
            .is_err()
    );
    let unknown = UnknownDiagnosis {
        input_digest: digest_self_quality_input(&input),
        unknown_refs: vec!["unknown:scope:v1".to_owned()],
    };
    eliot_conformance_contracts::validate_unknown_against_input(&unknown, &input)
        .expect("unknown binds digest");
}
