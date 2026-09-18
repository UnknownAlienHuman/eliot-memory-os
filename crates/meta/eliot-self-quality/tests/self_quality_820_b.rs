#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::BTreeSet;

use eliot_conformance_contracts::ISSUE_A37_LEARNING_CLOSURE;
use eliot_self_quality::{
    CauseHypothesisStatus, DenominatorCompleteness, DimensionStatus, EvidenceCeilings,
    InterventionState, MetricMeasurement, MetricPresence, ObservationCore, ObservationWindow,
    OwnerBinding, PriorDiagnosisRecord, ProductContractRef, QualityDenominator, QualityLimits,
    Recurrence, SELF_QUALITY_CONTRACT_VERSION, SelfQualityContractError, SelfQualityDimension,
    SelfQualityError, SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation,
    SelfQualityOutcome, SelfQualityPolicy, SourceIdentity, diagnose_self_quality,
    digest_self_quality_input, validate_self_quality_input,
};

const CREATED_AT: u64 = 1_700_000_000_000;
const OBS_FROM: u64 = 1_699_999_000_000;
const OBS_TO: u64 = 1_699_999_900_000;
const DIGEST_HEX: &str = "ab12cd34ef56ab12cd34ef56ab12cd34";

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

fn ceilings_ref() -> EvidenceCeilings {
    EvidenceCeilings {
        privacy_ceiling_ref: "ceiling:privacy:v1".to_owned(),
        authority_ceiling_ref: "ceiling:authority:v1".to_owned(),
        proof_ceiling_ref: "ceiling:proof:v1".to_owned(),
    }
}

fn policy_ref() -> SelfQualityPolicy {
    SelfQualityPolicy {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        policy_ref: "policy:self-quality:v1".to_owned(),
        schema_ref: "schema:policy:v1".to_owned(),
        revision_ref: "revision:policy:r1".to_owned(),
        rules_digest: DIGEST_HEX.to_owned(),
        limits: QualityLimits {
            max_observations: 256,
            max_history: 128,
            max_handoffs: 16,
            max_bytes: 1 << 20,
            max_depth: 16,
            max_work_units: 1 << 20,
            max_output_refs: 64,
            max_time_ms: 86_400_000,
        },
    }
}

fn window_for(env: &str) -> ObservationWindow {
    ObservationWindow {
        observed_from_ms: OBS_FROM,
        observed_to_ms: OBS_TO,
        environment_ref: env.to_owned(),
        platform_ref: "platform:linux-x86_64".to_owned(),
        toolchain_ref: "toolchain:rust-1.94".to_owned(),
    }
}

fn owner_for(tag: &str) -> OwnerBinding {
    OwnerBinding {
        owner_ref: format!("owner:{tag}:v1"),
        schema_ref: format!("schema:{tag}:v1"),
        revision_ref: format!("revision:{tag}:r1"),
        content_digest: DIGEST_HEX.to_owned(),
    }
}

fn make_metric(
    metric_ref: &str,
    unit_ref: &str,
    value: f64,
    presence: MetricPresence,
) -> MetricMeasurement {
    MetricMeasurement {
        metric_ref: metric_ref.to_owned(),
        value,
        unit_ref: unit_ref.to_owned(),
        normalization_ref: "normalization:raw".to_owned(),
        population_ref: "population:edge-sample-100".to_owned(),
        presence,
    }
}

fn make_core(
    obs_ref: &str,
    dim: SelfQualityDimension,
    status: DimensionStatus,
    metric: MetricMeasurement,
    owner_tag: &str,
    env: &str,
) -> ObservationCore {
    ObservationCore {
        observation_ref: obs_ref.to_owned(),
        dimension: dim,
        owner: owner_for(owner_tag),
        window: window_for(env),
        metric,
        completeness: DenominatorCompleteness::Complete,
        status,
        counterevidence_refs: Vec::new(),
        confounder_refs: Vec::new(),
        intervention_refs: Vec::new(),
    }
}

fn complete_denominator(obs: &[SelfQualityObservation]) -> QualityDenominator {
    let dims: BTreeSet<SelfQualityDimension> =
        obs.iter().map(|item| item.core().dimension).collect();
    let sources: BTreeSet<&str> = obs
        .iter()
        .map(|item| item.core().owner.owner_ref.as_str())
        .collect();
    QualityDenominator {
        expected_dimensions: u32::try_from(dims.len()).expect("dims fit"),
        supplied_dimensions: u32::try_from(dims.len()).expect("dims fit"),
        expected_sources: u32::try_from(sources.len()).expect("sources fit"),
        supplied_sources: u32::try_from(sources.len()).expect("sources fit"),
        expected_members: u32::try_from(obs.len()).expect("members fit"),
        supplied_members: u32::try_from(obs.len()).expect("members fit"),
        completeness: DenominatorCompleteness::Complete,
    }
}

fn make_input(
    observations: Vec<SelfQualityObservation>,
    history: Vec<PriorDiagnosisRecord>,
) -> SelfQualityInput {
    let mut ordered = observations;
    ordered.sort_by(|left, right| {
        (left.family_name(), left.core().observation_ref.as_str())
            .cmp(&(right.family_name(), right.core().observation_ref.as_str()))
    });
    let denominator = complete_denominator(&ordered);
    SelfQualityInput {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        input_ref: "input:self-quality:v1".to_owned(),
        product: product_ref(),
        source: source_identity(),
        observations: ordered,
        prior_history: history,
        policy: policy_ref(),
        ceilings: ceilings_ref(),
        denominator,
        created_at_ms: CREATED_AT,
    }
}

// WORK_UNIT_CASE: 820/15
#[test]
fn package_tests_edge_missing_yields_unknown() {
    let real_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::RealEdgeEvidence,
        DimensionStatus::Missing,
        make_metric(
            "metric:real-edge:v1",
            "unit:count",
            0.0,
            MetricPresence::Unavailable,
        ),
        "real-edge",
        "environment:prod",
    );
    let real_ref = real_core.observation_ref.clone();
    let real_obs = SelfQualityObservation::RealEdge(real_core);
    let build_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::Compatibility,
        DimensionStatus::Pass,
        make_metric(
            "metric:source-build:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "source-build",
        "environment:prod",
    );
    let build_obs = SelfQualityObservation::SourceBuild(build_core);
    let input = make_input(vec![real_obs, build_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid edge-missing input");
    assert!(matches!(outcome, SelfQualityOutcome::Unknown(_)));
    match outcome {
        SelfQualityOutcome::Unknown(disposition) => {
            assert!(disposition.unknown_refs.contains(&real_ref));
        }
        _ => panic!("expected Unknown for edge Missing without Fail"),
    }
}

// WORK_UNIT_CASE: 820/16
#[test]
fn proxy_metric_identity_stays_opaque_with_no_action() {
    let product_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::ProductOutcome,
        DimensionStatus::Pass,
        make_metric(
            "proxy:clicks-through",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "product-proxy",
        "environment:prod",
    );
    let product_obs = SelfQualityObservation::Product(product_core);
    let service_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Partial,
        make_metric(
            "metric:service-latency:v1",
            "unit:millis",
            2.0,
            MetricPresence::Value,
        ),
        "service-partial",
        "environment:prod",
    );
    let service_obs = SelfQualityObservation::Service(service_core);
    let input = make_input(vec![product_obs, service_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid proxy input");
    assert!(matches!(outcome, SelfQualityOutcome::NoAction(_)));
    let metric_refs: Vec<&str> = input
        .observations
        .iter()
        .map(|item| item.core().metric.metric_ref.as_str())
        .collect();
    assert!(!metric_refs.contains(&input.product.objective_ref.as_str()));
    assert!(!metric_refs.contains(&input.product.acceptance_ref.as_str()));
    assert!(!metric_refs.contains(&input.product.recovery_ref.as_str()));
    let mut altered = input.clone();
    for item in &mut altered.observations {
        if item.family_name() == "PRODUCT" {
            let SelfQualityObservation::Product(core_mut) = item else {
                panic!("expected product family")
            };
            core_mut.metric.metric_ref = "direct:acceptance-probe".to_owned();
        }
    }
    assert_ne!(
        digest_self_quality_input(&input),
        digest_self_quality_input(&altered),
        "proxy metric identity preserved verbatim"
    );
}

// WORK_UNIT_CASE: 820/17
#[test]
fn missing_product_instrumentation_yields_unknown() {
    let live_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Pass,
        make_metric(
            "metric:liveness:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "liveness-pass",
        "environment:prod",
    );
    let live_obs = SelfQualityObservation::Liveness(live_core);
    let prod_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::ProductOutcome,
        DimensionStatus::Missing,
        make_metric(
            "metric:product:v1",
            "unit:count",
            0.0,
            MetricPresence::Unavailable,
        ),
        "product-missing",
        "environment:prod",
    );
    let prod_obs = SelfQualityObservation::Product(prod_core);
    let svc_core = make_core(
        "obs:003:v1",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
        make_metric(
            "metric:service:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "service-pass",
        "environment:prod",
    );
    let svc_obs = SelfQualityObservation::Service(svc_core);
    let input = make_input(vec![live_obs, prod_obs, svc_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid missing-product input");
    match outcome {
        SelfQualityOutcome::Unknown(disposition) => {
            assert!(!disposition.unknown_refs.is_empty());
        }
        _ => panic!("expected Unknown for Missing product without Fail"),
    }
}

// WORK_UNIT_CASE: 820/18
#[test]
fn every_dimension_rolls_up_independently() {
    fn wrap_family(slot: usize, core: ObservationCore) -> SelfQualityObservation {
        match slot {
            0 => SelfQualityObservation::Conformance(core),
            1 => SelfQualityObservation::ContextEconomy(core),
            2 => SelfQualityObservation::ContextFloor(core),
            3 => SelfQualityObservation::ContextQuality(core),
            4 => SelfQualityObservation::ContextSelection(core),
            5 => SelfQualityObservation::CostQuota(core),
            6 => SelfQualityObservation::DreamerCandidate(core),
            7 => SelfQualityObservation::DreamerController(core),
            8 => SelfQualityObservation::DreamerGrounding(core),
            9 => SelfQualityObservation::ErasureInfluence(core),
            10 => SelfQualityObservation::HumanAttention(core),
            11 => SelfQualityObservation::LearningClosure(core),
            12 => SelfQualityObservation::LearningDelivery(core),
            13 => SelfQualityObservation::LearningOutcome(core),
            14 => SelfQualityObservation::LearningUse(core),
            _ => SelfQualityObservation::Liveness(core),
        }
    }
    let cycle = [
        DimensionStatus::Pass,
        DimensionStatus::Fail,
        DimensionStatus::Partial,
        DimensionStatus::Inconclusive,
    ];
    let mut observations = Vec::new();
    let mut expected: Vec<(SelfQualityDimension, DimensionStatus)> = Vec::new();
    for (slot, dim) in SelfQualityDimension::ALL.iter().enumerate() {
        let status = cycle[(slot + 2) % 4];
        expected.push((*dim, status));
        let obs_ref = format!("obs:{:03}:v1", slot + 1);
        let owner_tag = format!("dim-{slot:02}");
        let core = make_core(
            obs_ref.as_str(),
            *dim,
            status,
            make_metric(
                format!("metric:dim-{slot:02}:v1").as_str(),
                "unit:count",
                1.0,
                MetricPresence::Value,
            ),
            owner_tag.as_str(),
            "environment:prod",
        );
        observations.push(wrap_family(slot, core));
    }
    let input = make_input(observations, Vec::new());
    assert_eq!(input.denominator.supplied_dimensions, 16);
    assert_eq!(input.denominator.supplied_members, 16);
    let outcome = diagnose_self_quality(&input).expect("valid sixteen-dimension input");
    match outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            assert_eq!(
                candidate.overall_severity,
                eliot_self_quality::Severity::Critical
            );
            assert_eq!(
                candidate.overall_priority,
                eliot_self_quality::Priority::Urgent
            );
            for (dim, status) in expected {
                let found = candidate
                    .outcomes
                    .iter()
                    .find(|item| item.dimension == dim)
                    .expect("every dimension present");
                assert_eq!(found.status, status);
            }
            let security = candidate
                .outcomes
                .iter()
                .find(|item| item.dimension == SelfQualityDimension::SecurityPrivacy)
                .expect("security outcome present");
            assert_eq!(security.status, DimensionStatus::Fail);
            assert_eq!(security.severity, eliot_self_quality::Severity::Critical);
            assert_eq!(security.priority, eliot_self_quality::Priority::Urgent);
        }
        _ => panic!("expected Candidate for sixteen-dimension mix with Fail"),
    }
}

// WORK_UNIT_CASE: 820/19
#[test]
fn cost_and_latency_passes_cannot_dilute_failure() {
    let conform_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Fail,
        make_metric(
            "metric:reliability:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "reliability-fail",
        "environment:prod",
    );
    let conform_obs = SelfQualityObservation::Conformance(conform_core);
    let cost_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        make_metric("metric:cost:v1", "unit:count", 1.0, MetricPresence::Value),
        "cost-pass",
        "environment:prod",
    );
    let cost_obs = SelfQualityObservation::CostQuota(cost_core);
    let perf_core = make_core(
        "obs:003:v1",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
        make_metric(
            "metric:performance:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "performance-pass",
        "environment:prod",
    );
    let perf_obs = SelfQualityObservation::PerformanceResources(perf_core);
    let input = make_input(vec![conform_obs, cost_obs, perf_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid cost-latency input");
    match outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            assert_eq!(
                candidate.overall_severity,
                eliot_self_quality::Severity::High
            );
            assert_eq!(
                candidate.overall_priority,
                eliot_self_quality::Priority::High
            );
        }
        _ => panic!("expected Candidate when one dimension fails"),
    }
}

// WORK_UNIT_CASE: 820/20
#[test]
fn no_scalar_hides_the_worst_dimension() {
    let conform_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Fail,
        make_metric(
            "metric:reliability:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "reliability-fail",
        "environment:prod",
    );
    let conform_obs = SelfQualityObservation::Conformance(conform_core);
    let cost_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Pass,
        make_metric("metric:cost:v1", "unit:count", 1.0, MetricPresence::Value),
        "cost-pass",
        "environment:prod",
    );
    let cost_obs = SelfQualityObservation::CostQuota(cost_core);
    let perf_core = make_core(
        "obs:003:v1",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
        make_metric(
            "metric:performance:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "performance-pass",
        "environment:prod",
    );
    let perf_obs = SelfQualityObservation::PerformanceResources(perf_core);
    let prod_pass_core = make_core(
        "obs:004:v1",
        SelfQualityDimension::ProductOutcome,
        DimensionStatus::Pass,
        make_metric(
            "metric:product-pass:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "product-pass",
        "environment:prod",
    );
    let prod_pass_ref = prod_pass_core.observation_ref.clone();
    let prod_pass_obs = SelfQualityObservation::Product(prod_pass_core);
    let prod_missing_core = make_core(
        "obs:005:v1",
        SelfQualityDimension::ProductOutcome,
        DimensionStatus::Missing,
        make_metric(
            "metric:product-missing:v1",
            "unit:count",
            0.0,
            MetricPresence::Unavailable,
        ),
        "product-missing",
        "environment:prod",
    );
    let prod_missing_ref = prod_missing_core.observation_ref.clone();
    let prod_missing_obs = SelfQualityObservation::Product(prod_missing_core);
    let input = make_input(
        vec![
            conform_obs,
            cost_obs,
            perf_obs,
            prod_pass_obs,
            prod_missing_obs,
        ],
        Vec::new(),
    );
    let outcome = diagnose_self_quality(&input).expect("valid scalar-check input");
    match outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            assert_eq!(
                candidate.overall_severity,
                eliot_self_quality::Severity::High
            );
            // Verify that the missing dimension is preserved alongside failure and
            // routes to an inert instrumentation handoff scoped strictly to the missing evidence.
            let missing_outcome = candidate
                .outcomes
                .iter()
                .find(|item| item.dimension == SelfQualityDimension::ProductOutcome)
                .expect("missing product dimension must survive in outcomes");
            assert_eq!(missing_outcome.status, DimensionStatus::Missing);

            let instr_handoff = candidate
                .handoffs
                .iter()
                .find(|h| h.owner == SelfQualityHandoffOwner::Instrumentation)
                .expect("missing dimension must produce an instrumentation handoff");
            assert!(
                instr_handoff
                    .missing_evidence_refs
                    .contains(&prod_missing_ref),
                "instrumentation handoff must reference the missing observation"
            );
            assert!(
                !instr_handoff.missing_evidence_refs.contains(&prod_pass_ref),
                "instrumentation handoff must not leak passing observation into missing refs"
            );
            assert!(
                !instr_handoff.evidence_refs.contains(&prod_pass_ref),
                "instrumentation handoff must not leak passing observation into evidence refs"
            );
            assert!(
                !instr_handoff.symptom_refs.contains(&prod_pass_ref),
                "instrumentation handoff must not leak passing observation into symptom refs"
            );

            let value = serde_json::to_value(&candidate).expect("candidate serializes");
            let forbidden = ["score", "average", "scalar", "mean", "aggregate"];
            let top = value.as_object().expect("candidate is object");
            for key in top.keys() {
                assert!(
                    !forbidden.contains(&key.as_str()),
                    "forbidden top-level key {key}"
                );
            }
            let entries = top.get("outcomes").expect("outcomes present");
            let outcome_list = entries.as_array().expect("outcomes array");
            for entry in outcome_list {
                let fields = entry.as_object().expect("outcome object");
                for key in fields.keys() {
                    assert!(
                        !forbidden.contains(&key.as_str()),
                        "forbidden outcome key {key}"
                    );
                }
            }
        }
        _ => panic!("expected Candidate for scalar check"),
    }
}

// WORK_UNIT_CASE: 820/21
#[test]
fn unit_and_window_mismatch_stays_visible() {
    let first_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        make_metric(
            "metric:correctness:v1",
            "unit:ratio-a",
            1.0,
            MetricPresence::Value,
        ),
        "correctness-first",
        "environment:prod-a",
    );
    let first_obs = SelfQualityObservation::Conformance(first_core);
    let first_ref = "obs:001:v1".to_owned();
    let second_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        make_metric(
            "metric:correctness:v1",
            "unit:ratio-b",
            2.0,
            MetricPresence::Value,
        ),
        "correctness-second",
        "environment:prod-b",
    );
    let second_obs = SelfQualityObservation::Semantic(second_core);
    let second_ref = "obs:002:v1".to_owned();
    let input = make_input(vec![first_obs, second_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid mismatch input");
    match outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            let mut union: BTreeSet<String> = BTreeSet::new();
            for item in &candidate.symptom_refs {
                union.insert(item.clone());
            }
            for item in &candidate.counterevidence_refs {
                union.insert(item.clone());
            }
            assert!(union.contains(&first_ref));
            assert!(union.contains(&second_ref));
        }
        _ => panic!("expected Candidate for unit mismatch"),
    }
    let lone_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        make_metric(
            "metric:correctness:v1",
            "unit:ratio-a",
            1.0,
            MetricPresence::Value,
        ),
        "correctness-first",
        "environment:prod-a",
    );
    let lone_input = make_input(
        vec![SelfQualityObservation::Conformance(lone_core)],
        Vec::new(),
    );
    assert_ne!(
        digest_self_quality_input(&input),
        digest_self_quality_input(&lone_input),
        "two-observation digest differs from single-observation digest"
    );
}

// WORK_UNIT_CASE: 820/22
#[test]
fn zero_and_missing_measurements_stay_distinct() {
    let build_ok = |presence: MetricPresence, value: f64, status: DimensionStatus| {
        let core = make_core(
            "obs:001:v1",
            SelfQualityDimension::ReliabilityAvailability,
            status,
            make_metric("metric:service:v1", "unit:count", value, presence),
            "service-single",
            "environment:prod",
        );
        make_input(vec![SelfQualityObservation::Service(core)], Vec::new())
    };
    let zero_pass = build_ok(MetricPresence::NoEventZero, 0.0, DimensionStatus::Pass);
    assert!(diagnose_self_quality(&zero_pass).is_ok());
    let missing_absent = build_ok(MetricPresence::Unavailable, 0.0, DimensionStatus::Missing);
    assert!(diagnose_self_quality(&missing_absent).is_ok());
    let zero_missing = build_ok(MetricPresence::NoEventZero, 0.0, DimensionStatus::Missing);
    assert!(diagnose_self_quality(&zero_missing).is_err());
    let value_missing = build_ok(MetricPresence::Value, 1.0, DimensionStatus::Missing);
    assert!(diagnose_self_quality(&value_missing).is_err());
    let unmeasured_pass = build_ok(MetricPresence::Unmeasured, 0.0, DimensionStatus::Pass);
    assert!(matches!(
        diagnose_self_quality(&unmeasured_pass),
        Err(SelfQualityError::Contract(
            SelfQualityContractError::MissingEvidence { .. }
        ))
    ));
}

// WORK_UNIT_CASE: 820/23
#[test]
fn counterevidence_conflict_keeps_both_sides() {
    let failing_ref = "obs:001:v1".to_owned();
    let passing_ref = "obs:002:v1".to_owned();
    let mut failing_core = make_core(
        failing_ref.as_str(),
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        make_metric(
            "metric:correctness-fail:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "correctness-fail",
        "environment:prod",
    );
    failing_core.counterevidence_refs = vec![passing_ref.clone()];
    let failing_obs = SelfQualityObservation::Conformance(failing_core);
    let passing_core = make_core(
        passing_ref.as_str(),
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        make_metric(
            "metric:correctness-pass:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "correctness-pass",
        "environment:prod",
    );
    let passing_obs = SelfQualityObservation::Semantic(passing_core);
    let input = make_input(vec![failing_obs, passing_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid conflict input");
    match outcome {
        SelfQualityOutcome::Conflicted(disposition) => {
            assert!(disposition.conflict_refs.len() >= 2);
            assert!(disposition.conflict_refs.contains(&failing_ref));
            assert!(disposition.conflict_refs.contains(&passing_ref));
        }
        _ => panic!("expected Conflicted for counterevidence mix"),
    }
}

// WORK_UNIT_CASE: 820/24
#[test]
fn privacy_failure_hits_the_hard_boundary() {
    let private_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::SecurityPrivacy,
        DimensionStatus::Fail,
        make_metric(
            "metric:privacy:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "privacy-fail",
        "environment:prod",
    );
    let private_obs = SelfQualityObservation::SecurityPrivacy(private_core);
    let input = make_input(vec![private_obs], Vec::new());
    let outcome = diagnose_self_quality(&input).expect("valid privacy input");
    match outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            assert_eq!(
                candidate.overall_severity,
                eliot_self_quality::Severity::Critical
            );
            assert_eq!(
                candidate.overall_priority,
                eliot_self_quality::Priority::Urgent
            );
            let routed = candidate.handoffs.iter().any(|item| {
                item.owner == eliot_self_quality::SelfQualityHandoffOwner::HumanPrivacy
                    || item.owner == eliot_self_quality::SelfQualityHandoffOwner::IncidentRecovery
            });
            assert!(
                routed,
                "privacy finding routes to HumanPrivacy or IncidentRecovery"
            );
        }
        _ => panic!("expected Candidate for privacy Fail"),
    }
}

// WORK_UNIT_CASE: 820/25
#[test]
fn context_families_stay_distinct() {
    let economy_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::ContextQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:context-economy:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "context-economy",
        "environment:prod",
    );
    let floor_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::ContextQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:context-floor:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "context-floor",
        "environment:prod",
    );
    let quality_core = make_core(
        "obs:003:v1",
        SelfQualityDimension::ContextQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:context-quality:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "context-quality",
        "environment:prod",
    );
    let selection_core = make_core(
        "obs:004:v1",
        SelfQualityDimension::ContextQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:context-selection:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "context-selection",
        "environment:prod",
    );
    let input = make_input(
        vec![
            SelfQualityObservation::ContextEconomy(economy_core),
            SelfQualityObservation::ContextFloor(floor_core),
            SelfQualityObservation::ContextSelection(selection_core),
            SelfQualityObservation::ContextQuality(quality_core),
        ],
        Vec::new(),
    );
    validate_self_quality_input(&input).expect("context input validates");
    let families: BTreeSet<&str> = input
        .observations
        .iter()
        .map(SelfQualityObservation::family_name)
        .collect();
    assert_eq!(families.len(), 4);
    let before = digest_self_quality_input(&input);
    let mut swapped = input.clone();
    for item in &mut swapped.observations {
        if item.family_name() == "CONTEXT_QUALITY" {
            let core = item.core().clone();
            *item = SelfQualityObservation::ContextEconomy(core);
        }
    }
    assert_ne!(
        before,
        digest_self_quality_input(&swapped),
        "family swap changes digest"
    );
}

// WORK_UNIT_CASE: 820/26
#[test]
fn dreamer_families_stay_distinct() {
    let candidate_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::DreamerQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:dreamer-candidate:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "dreamer-candidate",
        "environment:prod",
    );
    let controller_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::DreamerQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:dreamer-controller:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "dreamer-controller",
        "environment:prod",
    );
    let grounding_core = make_core(
        "obs:003:v1",
        SelfQualityDimension::DreamerQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:dreamer-grounding:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "dreamer-grounding",
        "environment:prod",
    );
    let input = make_input(
        vec![
            SelfQualityObservation::DreamerCandidate(candidate_core),
            SelfQualityObservation::DreamerController(controller_core),
            SelfQualityObservation::DreamerGrounding(grounding_core),
        ],
        Vec::new(),
    );
    validate_self_quality_input(&input).expect("dreamer input validates");
    assert_eq!(input.denominator.supplied_dimensions, 1);
    assert_eq!(input.denominator.supplied_members, 3);
    let outcome = diagnose_self_quality(&input).expect("dreamer all-pass diagnoses");
    assert!(matches!(outcome, SelfQualityOutcome::NoProblem(_)));
    let families: BTreeSet<&str> = input
        .observations
        .iter()
        .map(SelfQualityObservation::family_name)
        .collect();
    assert_eq!(families.len(), 3);
    let before = digest_self_quality_input(&input);
    let mut swapped = input.clone();
    for item in &mut swapped.observations {
        if item.family_name() == "DREAMER_GROUNDING" {
            let core = item.core().clone();
            *item = SelfQualityObservation::DreamerCandidate(core);
        }
    }
    assert_ne!(
        before,
        digest_self_quality_input(&swapped),
        "dreamer family swap changes digest"
    );
}

// WORK_UNIT_CASE: 820/27
#[test]
fn learning_closure_arrives_via_a37_819() {
    assert_eq!(ISSUE_A37_LEARNING_CLOSURE, 819);
    let closure_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:learning-closure:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "learning-closure",
        "environment:prod",
    );
    let delivery_core = make_core(
        "obs:002:v1",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:learning-delivery:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "learning-delivery",
        "environment:prod",
    );
    let outcome_core = make_core(
        "obs:003:v1",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:learning-outcome:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "learning-outcome",
        "environment:prod",
    );
    let use_core = make_core(
        "obs:004:v1",
        SelfQualityDimension::LearningQuality,
        DimensionStatus::Pass,
        make_metric(
            "metric:learning-use:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "learning-use",
        "environment:prod",
    );
    let input = make_input(
        vec![
            SelfQualityObservation::LearningClosure(closure_core),
            SelfQualityObservation::LearningDelivery(delivery_core),
            SelfQualityObservation::LearningOutcome(outcome_core),
            SelfQualityObservation::LearningUse(use_core),
        ],
        Vec::new(),
    );
    validate_self_quality_input(&input).expect("learning input validates");
    let families: BTreeSet<&str> = input
        .observations
        .iter()
        .map(SelfQualityObservation::family_name)
        .collect();
    assert_eq!(families.len(), 4);
    assert!(families.contains("LEARNING_CLOSURE"));
    let before = digest_self_quality_input(&input);
    let mut swapped = input.clone();
    for item in &mut swapped.observations {
        if item.family_name() == "LEARNING_CLOSURE" {
            let core = item.core().clone();
            *item = SelfQualityObservation::LearningDelivery(core);
        }
    }
    assert_ne!(
        before,
        digest_self_quality_input(&swapped),
        "closure replacement changes digest"
    );
}

// WORK_UNIT_CASE: 820/28
#[test]
fn symptom_promotes_to_hypothesis_never_proven_cause() {
    let mut lone_core = make_core(
        "obs:001:v1",
        SelfQualityDimension::ReliabilityAvailability,
        DimensionStatus::Fail,
        make_metric(
            "metric:reliability:v1",
            "unit:count",
            1.0,
            MetricPresence::Value,
        ),
        "reliability-fail",
        "environment:prod",
    );
    lone_core.intervention_refs = vec!["intervention:fix:v1".to_owned()];
    let lone_obs = SelfQualityObservation::Service(lone_core);
    let bare_input = make_input(vec![lone_obs], Vec::new());
    let bare_outcome = diagnose_self_quality(&bare_input).expect("bare fail diagnoses");
    match bare_outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            assert!(candidate.mechanism_refs.is_empty());
            let flagged = candidate
                .outcomes
                .iter()
                .find(|item| item.dimension == SelfQualityDimension::ReliabilityAvailability)
                .expect("failing dimension present");
            assert_eq!(flagged.hypothesis, CauseHypothesisStatus::Symptom);
            assert!(
                candidate
                    .outcomes
                    .iter()
                    .all(|item| { item.hypothesis != CauseHypothesisStatus::ProvenCause })
            );
        }
        _ => panic!("expected Candidate for bare Fail"),
    }
    let mut linked_core = bare_input.observations[0].core().clone();
    linked_core.intervention_refs = vec!["intervention:fix:v1".to_owned()];
    let linked_obs = SelfQualityObservation::Service(linked_core);
    let history = vec![PriorDiagnosisRecord {
        diagnosis_ref: "diagnosis:history-001:v1".to_owned(),
        intervention_ref: "intervention:fix:v1".to_owned(),
        intervention_state: InterventionState::Applied,
        recurrence: Recurrence::Recurrent,
        hypothesis_status: CauseHypothesisStatus::Hypothesis,
        source_ref: "source:repo:v1".to_owned(),
        configuration_ref: "config:history:v1".to_owned(),
        environment_ref: "environment:prod".to_owned(),
        observed_at_ms: 1_699_999_500_000,
    }];
    let linked_input = make_input(vec![linked_obs], history);
    let linked_outcome = diagnose_self_quality(&linked_input).expect("linked fail diagnoses");
    match linked_outcome {
        SelfQualityOutcome::Candidate(candidate) => {
            let flagged = candidate
                .outcomes
                .iter()
                .find(|item| item.dimension == SelfQualityDimension::ReliabilityAvailability)
                .expect("failing dimension present");
            assert_eq!(flagged.hypothesis, CauseHypothesisStatus::Hypothesis);
            assert!(
                candidate
                    .outcomes
                    .iter()
                    .all(|item| { item.hypothesis != CauseHypothesisStatus::ProvenCause })
            );
        }
        _ => panic!("expected Candidate for linked Fail"),
    }
}
