#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::BTreeSet;

use eliot_conformance_contracts::{
    DenominatorCompleteness, DimensionStatus, EvidenceCeilings, ISSUE_A36_LEARNING_ACTIVATION,
    ISSUE_A37_LEARNING_CLOSURE, ISSUE_A39_CONFLICT_ANALYSIS, ISSUE_A40_DEVELOPMENT_DIAGNOSIS,
    ISSUE_A41_MAINTENANCE_PLAN, ISSUE_A42_CONFIGURATION_ASSISTANCE, MetricMeasurement,
    MetricPresence, NoActionDisposition, ObservationCore, ObservationWindow, OwnerBinding,
    Priority, ProductContractRef, QualityDenominator, QualityLimits, SELF_QUALITY_CANDIDATE_SCHEMA,
    SELF_QUALITY_CONTRACT_VERSION, SELF_QUALITY_HANDOFF_SCHEMA, SELF_QUALITY_SCHEMA,
    SelfQualityContractError, SelfQualityDimension, SelfQualityHandoffOwner, SelfQualityInput,
    SelfQualityObservation, SelfQualityPolicy, Severity, SourceIdentity, digest_self_quality_input,
    validate_candidate_against_input, validate_denominator, validate_no_action_against_input,
    validate_no_problem_against_input, validate_observation, validate_product_contract_ref,
    validate_self_quality_input, validate_source_identity,
};
use eliot_contracts::sha256_hex;
use eliot_self_quality::{
    CAUSAL_PROPERTY, CRATE_NAME, META_AGENT_ORDER, MODULE_ID, RUNTIME_LAYER, SOURCE_LAYER,
    SelfQualityOutcome, diagnose_self_quality, module_digest,
};

const CREATED_AT_MS: u64 = 1_700_000_000_000;
const OBSERVED_FROM_MS: u64 = 1_699_999_000_000;
const OBSERVED_TO_MS: u64 = 1_699_999_900_000;
const HEX_DIGEST: &str = "ab12cd34ef56ab12cd34ef56ab12cd34";

fn test_window(environment_ref: &str) -> ObservationWindow {
    ObservationWindow {
        observed_from_ms: OBSERVED_FROM_MS,
        observed_to_ms: OBSERVED_TO_MS,
        environment_ref: environment_ref.to_owned(),
        platform_ref: "platform-linux-820a-001".to_owned(),
        toolchain_ref: "toolchain-rust-820a-001".to_owned(),
    }
}

fn test_owner(owner_ref: &str) -> OwnerBinding {
    OwnerBinding {
        owner_ref: owner_ref.to_owned(),
        schema_ref: "owner-schema-820a-001".to_owned(),
        revision_ref: "owner-revision-820a-001".to_owned(),
        content_digest: HEX_DIGEST.to_owned(),
    }
}

fn test_metric(metric_ref: &str, value: f64, presence: MetricPresence) -> MetricMeasurement {
    MetricMeasurement {
        metric_ref: metric_ref.to_owned(),
        value,
        unit_ref: "unit-count-820a-001".to_owned(),
        normalization_ref: "normalization-none-820a-001".to_owned(),
        population_ref: "population-snapshot-820a-001".to_owned(),
        presence,
    }
}

fn test_core(
    observation_ref: &str,
    dimension: SelfQualityDimension,
    status: DimensionStatus,
    value: f64,
    presence: MetricPresence,
) -> ObservationCore {
    ObservationCore {
        observation_ref: observation_ref.to_owned(),
        dimension,
        owner: test_owner("owner-evidence-alpha-001"),
        window: test_window("env-prod-820a-001"),
        metric: test_metric("metric-self-quality-820a-001", value, presence),
        completeness: DenominatorCompleteness::Complete,
        status,
        counterevidence_refs: Vec::new(),
        confounder_refs: Vec::new(),
        intervention_refs: Vec::new(),
    }
}

fn test_product() -> ProductContractRef {
    ProductContractRef {
        contract_version: 1,
        objective_ref: "objective-self-quality-820a-001".to_owned(),
        acceptance_ref: "acceptance-self-quality-820a-001".to_owned(),
        recovery_ref: "recovery-self-quality-820a-001".to_owned(),
    }
}

fn test_source() -> SourceIdentity {
    SourceIdentity {
        contract_version: 1,
        source_ref: "source-self-quality-820a-001".to_owned(),
        artifact_ref: "artifact-self-quality-820a-001".to_owned(),
        configuration_ref: "configuration-self-quality-820a-001".to_owned(),
        generation_ref: "generation-self-quality-820a-001".to_owned(),
        task_ref: "task-self-quality-820a-001".to_owned(),
        scope_ref: "scope-self-quality-820a-001".to_owned(),
        fence_ref: "fence-self-quality-820a-001".to_owned(),
    }
}

fn test_policy() -> SelfQualityPolicy {
    SelfQualityPolicy {
        contract_version: 1,
        policy_ref: "policy-self-quality-820a-001".to_owned(),
        schema_ref: "schema-self-quality-820a-001".to_owned(),
        revision_ref: "revision-self-quality-820a-001".to_owned(),
        rules_digest: HEX_DIGEST.to_owned(),
        limits: QualityLimits {
            max_observations: 16,
            max_history: 16,
            max_handoffs: 16,
            max_bytes: 1_048_576,
            max_depth: 8,
            max_work_units: 1_048_576,
            max_output_refs: 64,
            max_time_ms: 86_400_000,
        },
    }
}

fn test_ceilings() -> EvidenceCeilings {
    EvidenceCeilings {
        privacy_ceiling_ref: "ceiling-privacy-820a-001".to_owned(),
        authority_ceiling_ref: "ceiling-authority-820a-001".to_owned(),
        proof_ceiling_ref: "ceiling-proof-820a-001".to_owned(),
    }
}

fn complete_denominator(observations: &[SelfQualityObservation]) -> QualityDenominator {
    let mut dimensions = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for observation in observations {
        dimensions.insert(observation.core().dimension);
        sources.insert(observation.core().owner.owner_ref.clone());
    }
    let dimension_count = u32::try_from(dimensions.len()).expect("observation count fits in u32");
    let source_count = u32::try_from(sources.len()).expect("observation count fits in u32");
    let member_count = u32::try_from(observations.len()).expect("observation count fits in u32");
    QualityDenominator {
        expected_dimensions: dimension_count,
        supplied_dimensions: dimension_count,
        expected_sources: source_count,
        supplied_sources: source_count,
        expected_members: member_count,
        supplied_members: member_count,
        completeness: DenominatorCompleteness::Complete,
    }
}

fn sort_observations(observations: Vec<SelfQualityObservation>) -> Vec<SelfQualityObservation> {
    let mut sorted = observations;
    sorted.sort_by(|left, right| {
        (left.family_name(), left.core().observation_ref.as_str())
            .cmp(&(right.family_name(), right.core().observation_ref.as_str()))
    });
    sorted
}

fn test_input(
    observations: Vec<SelfQualityObservation>,
    denominator: QualityDenominator,
    input_ref: &str,
) -> SelfQualityInput {
    SelfQualityInput {
        contract_version: 1,
        input_ref: input_ref.to_owned(),
        product: test_product(),
        source: test_source(),
        observations,
        prior_history: Vec::new(),
        policy: test_policy(),
        ceilings: test_ceilings(),
        denominator,
        created_at_ms: CREATED_AT_MS,
    }
}

// WORK_UNIT_CASE: 820/1
#[test]
fn meta_identity_exact_and_distinct_from_a37() {
    assert_eq!(MODULE_ID, "meta.self_quality.diagnosis");
    assert_eq!(CRATE_NAME, "eliot-self-quality");
    assert_eq!(META_AGENT_ORDER, 38_u32);
    assert_eq!(SOURCE_LAYER, "C1");
    assert_eq!(RUNTIME_LAYER, "R7");
    assert_eq!(CAUSAL_PROPERTY, "bounded self-quality diagnosis candidate");
    let preimage = "meta.self_quality.diagnosis|eliot-self-quality|38|C1|R7|eliot.self-quality.input.v1|eliot.self-quality.candidate.v1|eliot.self-quality.handoff.v1";
    assert_eq!(module_digest(), sha256_hex(preimage.as_bytes()));
    assert_eq!(module_digest().len(), 64);
    let a37_digest = sha256_hex("meta.learning.closure|eliot-improvement|37".as_bytes());
    assert_ne!(module_digest(), a37_digest);
    let module_toml = include_str!("../module.toml");
    assert!(module_toml.contains("meta.self_quality.diagnosis"));
    assert!(module_toml.contains("agent_order = 38"));
    let cargo_toml = include_str!("../Cargo.toml");
    assert!(cargo_toml.contains("eliot-self-quality"));
    assert_ne!(MODULE_ID, "meta.learning.closure");
}

// WORK_UNIT_CASE: 820/2
#[test]
fn contract_vocabulary_frozen_971() {
    assert_eq!(SelfQualityDimension::ALL.len(), 16);
    assert_eq!(
        SelfQualityDimension::ALL[0],
        SelfQualityDimension::Correctness
    );
    assert_eq!(
        SelfQualityDimension::ALL[15],
        SelfQualityDimension::Compatibility
    );
    assert_eq!(SelfQualityHandoffOwner::ALL.len(), 11);
    assert_eq!(ISSUE_A39_CONFLICT_ANALYSIS, 673);
    assert_eq!(ISSUE_A40_DEVELOPMENT_DIAGNOSIS, 675);
    assert_eq!(ISSUE_A41_MAINTENANCE_PLAN, 677);
    assert_eq!(ISSUE_A42_CONFIGURATION_ASSISTANCE, 679);
    assert_eq!(ISSUE_A36_LEARNING_ACTIVATION, 620);
    assert_eq!(ISSUE_A37_LEARNING_CLOSURE, 819);
    assert_eq!(SELF_QUALITY_SCHEMA, "eliot.self-quality.input.v1");
    assert_eq!(
        SELF_QUALITY_CANDIDATE_SCHEMA,
        "eliot.self-quality.candidate.v1"
    );
    assert_eq!(SELF_QUALITY_HANDOFF_SCHEMA, "eliot.self-quality.handoff.v1");
    assert_eq!(SELF_QUALITY_CONTRACT_VERSION, 1);
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
        SelfQualityHandoffOwner::UnsupportedOwner.issue_number(),
        None
    );
    assert!(SelfQualityHandoffOwner::HumanPolicy.is_human());
    assert!(!SelfQualityHandoffOwner::DevelopmentDiagnosis675.is_human());
}

// WORK_UNIT_CASE: 820/3
#[test]
fn valid_bounded_diagnosis_candidate() {
    let fail = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-fail-001",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        0.75,
        MetricPresence::Value,
    ));
    let pass = SelfQualityObservation::CostQuota(test_core(
        "obs-costquota-pass-001",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        3.0,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![pass, fail]);
    let denominator = complete_denominator(&observations);
    let input = test_input(observations, denominator, "input-self-quality-820a-003");
    let outcome = match diagnose_self_quality(&input) {
        Ok(outcome) => outcome,
        Err(error) => panic!("valid candidate input must diagnose: {error}"),
    };
    let candidate = match outcome {
        SelfQualityOutcome::Candidate(candidate) => candidate,
        SelfQualityOutcome::NoProblem(_)
        | SelfQualityOutcome::NoAction(_)
        | SelfQualityOutcome::Incomplete(_)
        | SelfQualityOutcome::Unknown(_)
        | SelfQualityOutcome::Blocked(_)
        | SelfQualityOutcome::Conflicted(_) => {
            panic!("Correctness Fail must yield a Candidate")
        }
    };
    validate_candidate_against_input(&candidate, &input)
        .expect("candidate must validate against its input");
    // A Correctness Fail maps to Critical/Urgent per the frozen decision tree;
    // the overall is the per-dimension maxima.
    assert_eq!(candidate.overall_severity, Severity::Critical);
    assert_eq!(candidate.overall_priority, Priority::Urgent);
    assert_eq!(candidate.outcomes.len(), 2);
    assert!(!candidate.symptom_refs.is_empty());
    assert!(candidate.mechanism_refs.is_empty());
}

// WORK_UNIT_CASE: 820/4
#[test]
fn valid_no_action_for_tolerated_partial() {
    let pass = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-pass-004",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let partial = SelfQualityObservation::CostQuota(test_core(
        "obs-costquota-partial-004",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Partial,
        0.5,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![pass, partial]);
    let denominator = complete_denominator(&observations);
    let input = test_input(observations, denominator, "input-self-quality-820a-004");
    let outcome = match diagnose_self_quality(&input) {
        Ok(outcome) => outcome,
        Err(error) => panic!("valid no-action input must diagnose: {error}"),
    };
    let disposition = match outcome {
        SelfQualityOutcome::NoAction(disposition) => disposition,
        SelfQualityOutcome::Candidate(_)
        | SelfQualityOutcome::NoProblem(_)
        | SelfQualityOutcome::Incomplete(_)
        | SelfQualityOutcome::Unknown(_)
        | SelfQualityOutcome::Blocked(_)
        | SelfQualityOutcome::Conflicted(_) => {
            panic!("Pass plus Partial must yield NoAction")
        }
    };
    validate_no_action_against_input(&disposition, &input)
        .expect("no-action must validate against its input");
    assert!(!disposition.tolerated_dimensions.is_empty());
    assert!(!disposition.justification_refs.is_empty());
}

// WORK_UNIT_CASE: 820/5
#[test]
fn product_mismatch_rejected_with_control() {
    let mut aliased = test_product();
    aliased.acceptance_ref = aliased.objective_ref.clone();
    assert!(validate_product_contract_ref(&aliased).is_err());

    let fail = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-fail-005",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        0.5,
        MetricPresence::Value,
    ));
    let pass = SelfQualityObservation::CostQuota(test_core(
        "obs-costquota-pass-005",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![pass, fail]);
    let denominator = complete_denominator(&observations);
    let mut bad_input = test_input(observations, denominator, "input-self-quality-820a-005");
    bad_input.product.acceptance_ref = bad_input.product.objective_ref.clone();
    assert!(
        diagnose_self_quality(&bad_input).is_err(),
        "duplicated product refs must not diagnose"
    );

    validate_product_contract_ref(&test_product()).expect("distinct product refs must validate");
}

// WORK_UNIT_CASE: 820/6
#[test]
fn source_mismatch_rejected() {
    let mut aliased = test_source();
    aliased.artifact_ref = aliased.source_ref.clone();
    assert!(validate_source_identity(&aliased).is_err());

    let mut empty_artifact = test_source();
    empty_artifact.artifact_ref = String::new();
    assert!(validate_source_identity(&empty_artifact).is_err());
}

// WORK_UNIT_CASE: 820/7
#[test]
fn task_scope_fence_mismatch_rejected() {
    let mut aliased = test_source();
    aliased.scope_ref = aliased.task_ref.clone();
    assert!(validate_source_identity(&aliased).is_err());

    let mut empty_fence = test_source();
    empty_fence.fence_ref = String::new();
    assert!(validate_source_identity(&empty_fence).is_err());
}

// WORK_UNIT_CASE: 820/8
#[test]
fn complete_denominator_yields_no_problem() {
    let first = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-pass-008",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let second = SelfQualityObservation::CostQuota(test_core(
        "obs-costquota-pass-008",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        2.0,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![first, second]);
    let denominator = complete_denominator(&observations);
    validate_denominator(&denominator).expect("computed complete denominator must validate");
    let input = test_input(observations, denominator, "input-self-quality-820a-008");
    let outcome = match diagnose_self_quality(&input) {
        Ok(outcome) => outcome,
        Err(error) => panic!("all-Pass input must diagnose: {error}"),
    };
    let disposition = match outcome {
        SelfQualityOutcome::NoProblem(disposition) => disposition,
        SelfQualityOutcome::Candidate(_)
        | SelfQualityOutcome::NoAction(_)
        | SelfQualityOutcome::Incomplete(_)
        | SelfQualityOutcome::Unknown(_)
        | SelfQualityOutcome::Blocked(_)
        | SelfQualityOutcome::Conflicted(_) => {
            panic!("all-Pass complete input must yield NoProblem")
        }
    };
    validate_no_problem_against_input(&disposition, &input)
        .expect("no-problem must validate against its input");
}

// WORK_UNIT_CASE: 820/9
#[test]
fn incomplete_denominator_names_shortfall() {
    let first = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-pass-009",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let second = SelfQualityObservation::CostQuota(test_core(
        "obs-costquota-pass-009",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        2.0,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![first, second]);
    let supplied = complete_denominator(&observations);
    let denominator = QualityDenominator {
        expected_dimensions: supplied.supplied_dimensions + 1,
        supplied_dimensions: supplied.supplied_dimensions,
        expected_sources: supplied.supplied_sources,
        supplied_sources: supplied.supplied_sources,
        expected_members: supplied.supplied_members,
        supplied_members: supplied.supplied_members,
        completeness: DenominatorCompleteness::Partial,
    };
    let input = test_input(observations, denominator, "input-self-quality-820a-009");
    let outcome = match diagnose_self_quality(&input) {
        Ok(outcome) => outcome,
        Err(error) => panic!("partial-denominator input must diagnose: {error}"),
    };
    let diagnosis = match outcome {
        SelfQualityOutcome::Incomplete(diagnosis) => diagnosis,
        SelfQualityOutcome::Candidate(_)
        | SelfQualityOutcome::NoAction(_)
        | SelfQualityOutcome::NoProblem(_)
        | SelfQualityOutcome::Unknown(_)
        | SelfQualityOutcome::Blocked(_)
        | SelfQualityOutcome::Conflicted(_) => {
            panic!("partial denominator must yield Incomplete, never Candidate/NoAction/NoProblem")
        }
    };
    assert!(!diagnosis.missing_evidence_refs.is_empty());
    let rejection = NoActionDisposition {
        input_digest: digest_self_quality_input(&input),
        justification_refs: vec!["tolerated:CostQuota".to_owned()],
        tolerated_dimensions: vec![SelfQualityDimension::CostQuota],
    };
    assert!(validate_no_action_against_input(&rejection, &input).is_err());
}

// WORK_UNIT_CASE: 820/10
#[test]
fn every_observation_disposition_validates() {
    let cases: [(DimensionStatus, MetricPresence, f64, &str); 6] = [
        (
            DimensionStatus::Pass,
            MetricPresence::Value,
            1.0,
            "obs-disposition-pass-010",
        ),
        (
            DimensionStatus::Fail,
            MetricPresence::Value,
            0.5,
            "obs-disposition-fail-010",
        ),
        (
            DimensionStatus::Partial,
            MetricPresence::Value,
            0.25,
            "obs-disposition-partial-010",
        ),
        (
            DimensionStatus::Inconclusive,
            MetricPresence::NoEventZero,
            0.0,
            "obs-disposition-inconclusive-010",
        ),
        (
            DimensionStatus::NotApplicable,
            MetricPresence::Unmeasured,
            0.0,
            "obs-disposition-notapplicable-010",
        ),
        (
            DimensionStatus::Missing,
            MetricPresence::Unavailable,
            0.0,
            "obs-disposition-missing-010",
        ),
    ];
    for (status, presence, value, observation_ref) in cases {
        let observation = SelfQualityObservation::Conformance(test_core(
            observation_ref,
            SelfQualityDimension::Correctness,
            status,
            value,
            presence,
        ));
        assert!(validate_observation(&observation).is_ok());
    }
}

// WORK_UNIT_CASE: 820/11
#[test]
fn duplicates_do_not_inflate_denominator() {
    let first = SelfQualityObservation::Conformance(test_core(
        "obs-aaa-same-dim-011",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let second = SelfQualityObservation::Service(test_core(
        "obs-zzz-same-dim-011",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        2.0,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![first, second]);
    let computed = complete_denominator(&observations);
    assert_eq!(computed.supplied_dimensions, 1);
    let mut inflated = computed;
    inflated.expected_dimensions = 2;
    inflated.supplied_dimensions = 2;
    let bad_input = test_input(
        observations,
        inflated,
        "input-self-quality-820a-011-inflated",
    );
    let error =
        validate_self_quality_input(&bad_input).expect_err("inflated denominator must be rejected");
    assert!(matches!(
        error,
        SelfQualityContractError::InvalidDenominator { .. }
    ));

    let shared = test_core(
        "obs-dup-ref-011",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    );
    let dup_first = SelfQualityObservation::Conformance(shared.clone());
    let dup_second = SelfQualityObservation::Service(shared);
    let dup_observations = sort_observations(vec![dup_first, dup_second]);
    let dup_denominator = complete_denominator(&dup_observations);
    let dup_input = test_input(
        dup_observations,
        dup_denominator,
        "input-self-quality-820a-011-duplicate",
    );
    let error = validate_self_quality_input(&dup_input)
        .expect_err("duplicate observation refs must be rejected");
    assert!(matches!(
        error,
        SelfQualityContractError::DuplicateObservation { .. }
    ));
}

// WORK_UNIT_CASE: 820/12
#[test]
fn stale_window_rejected_and_env_changes_digest() {
    let mut future_core = test_core(
        "obs-future-012",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    );
    future_core.window.observed_to_ms = CREATED_AT_MS + 1_000;
    let future_observations =
        sort_observations(vec![SelfQualityObservation::Conformance(future_core)]);
    let future_denominator = complete_denominator(&future_observations);
    let future_input = test_input(
        future_observations,
        future_denominator,
        "input-self-quality-820a-012-future",
    );
    let error = validate_self_quality_input(&future_input)
        .expect_err("evidence from the future must be rejected");
    assert!(matches!(
        error,
        SelfQualityContractError::FutureEvidence { .. }
    ));

    let single_first = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-env-012",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let single_second = SelfQualityObservation::CostQuota(test_core(
        "obs-costquota-env-012",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        2.0,
        MetricPresence::Value,
    ));
    let single_observations = sort_observations(vec![single_first, single_second]);
    let single_denominator = complete_denominator(&single_observations);
    let single_input = test_input(
        single_observations,
        single_denominator,
        "input-self-quality-820a-012",
    );
    validate_self_quality_input(&single_input).expect("single-env input must validate");

    let mixed_first = SelfQualityObservation::Conformance(test_core(
        "obs-conformance-env-012",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let mut mixed_core = test_core(
        "obs-costquota-env-012",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        2.0,
        MetricPresence::Value,
    );
    mixed_core.window.environment_ref = "env-staging-820a-002".to_owned();
    let mixed_second = SelfQualityObservation::CostQuota(mixed_core);
    let mixed_observations = sort_observations(vec![mixed_first, mixed_second]);
    let mixed_denominator = complete_denominator(&mixed_observations);
    let mixed_input = test_input(
        mixed_observations,
        mixed_denominator,
        "input-self-quality-820a-012",
    );
    validate_self_quality_input(&mixed_input).expect("mixed-env input must validate");
    assert_ne!(
        digest_self_quality_input(&single_input),
        digest_self_quality_input(&mixed_input)
    );
}

// WORK_UNIT_CASE: 820/13
#[test]
fn liveness_pass_with_service_fail_is_candidate() {
    let liveness = SelfQualityObservation::Liveness(test_core(
        "obs-liveness-pass-013",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let service = SelfQualityObservation::Service(test_core(
        "obs-service-fail-013",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Fail,
        0.5,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![liveness, service]);
    let denominator = complete_denominator(&observations);
    let input = test_input(observations, denominator, "input-self-quality-820a-013");
    let outcome = match diagnose_self_quality(&input) {
        Ok(outcome) => outcome,
        Err(error) => panic!("liveness/service input must diagnose: {error}"),
    };
    let candidate = match outcome {
        SelfQualityOutcome::Candidate(candidate) => candidate,
        SelfQualityOutcome::NoProblem(_)
        | SelfQualityOutcome::NoAction(_)
        | SelfQualityOutcome::Incomplete(_)
        | SelfQualityOutcome::Unknown(_)
        | SelfQualityOutcome::Blocked(_)
        | SelfQualityOutcome::Conflicted(_) => {
            panic!("Service Fail must yield a Candidate")
        }
    };
    let service_outcome = candidate
        .outcomes
        .iter()
        .find(|outcome| outcome.dimension == SelfQualityDimension::ReliabilityAvailability)
        .expect("service dimension must survive aggregation");
    assert_eq!(service_outcome.status, DimensionStatus::Fail);
    let liveness_outcome = candidate
        .outcomes
        .iter()
        .find(|outcome| outcome.dimension == SelfQualityDimension::PerformanceResources)
        .expect("liveness dimension must survive aggregation");
    assert_eq!(liveness_outcome.status, DimensionStatus::Pass);
    assert_eq!(candidate.overall_severity, Severity::High);
}

// WORK_UNIT_CASE: 820/14
#[test]
fn volume_does_not_imply_delta_failure() {
    let liveness = SelfQualityObservation::Liveness(test_core(
        "obs-liveness-volume-014",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Pass,
        1_000_000.0,
        MetricPresence::Value,
    ));
    let service = SelfQualityObservation::Service(test_core(
        "obs-service-delta-014",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        1.0,
        MetricPresence::Value,
    ));
    let observations = sort_observations(vec![liveness, service]);
    let denominator = complete_denominator(&observations);
    let input = test_input(observations, denominator, "input-self-quality-820a-014");
    let outcome = match diagnose_self_quality(&input) {
        Ok(outcome) => outcome,
        Err(error) => panic!("all-Pass volume input must diagnose: {error}"),
    };
    let disposition = match outcome {
        SelfQualityOutcome::NoProblem(disposition) => disposition,
        SelfQualityOutcome::Candidate(_)
        | SelfQualityOutcome::NoAction(_)
        | SelfQualityOutcome::Incomplete(_)
        | SelfQualityOutcome::Unknown(_)
        | SelfQualityOutcome::Blocked(_)
        | SelfQualityOutcome::Conflicted(_) => {
            panic!("all-Pass input must yield NoProblem")
        }
    };
    assert!(
        !disposition
            .completed_dimensions
            .contains(&SelfQualityDimension::ProductOutcome)
    );
    validate_no_problem_against_input(&disposition, &input)
        .expect("no-problem must validate against its input");
}
