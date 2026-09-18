#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

//! W4 work unit: self-quality decision-tree edge coverage (820/43..820/56).

use std::collections::BTreeSet;

use eliot_conformance_contracts::{
    canonicalize_observations, canonicalize_self_quality_input, validate_limits,
};
use eliot_self_quality::{
    CauseHypothesisStatus, DenominatorCompleteness, DimensionOutcome, DimensionStatus,
    EvidenceCeilings, InterventionState, MetricMeasurement, MetricPresence, ObservationCore,
    ObservationWindow, OwnerBinding, PriorDiagnosisRecord, Priority, ProductContractRef,
    QualityDenominator, QualityLimits, Recurrence, SelfQualityContractError, SelfQualityDimension,
    SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation, SelfQualityOutcome,
    SelfQualityPolicy, Severity, SourceIdentity, diagnose_self_quality, digest_candidate,
    digest_self_quality_input, make_handoff, route_owner, validate_candidate_against_input,
    validate_dimension_outcome, validate_handoff, validate_self_quality_input,
};

const CREATED_AT_MS: u64 = 1_700_000_000_000;
const INPUT_REF: &str = "sq-input-001";

fn hex_byte(byte: u8) -> String {
    format!("{byte:02x}").repeat(16)
}

fn product_ref() -> ProductContractRef {
    ProductContractRef {
        contract_version: 1,
        objective_ref: "product-objective-001".to_owned(),
        acceptance_ref: "product-acceptance-001".to_owned(),
        recovery_ref: "product-recovery-001".to_owned(),
    }
}

fn source_identity() -> SourceIdentity {
    SourceIdentity {
        contract_version: 1,
        source_ref: "source-001".to_owned(),
        artifact_ref: "artifact-001".to_owned(),
        configuration_ref: "configuration-001".to_owned(),
        generation_ref: "generation-001".to_owned(),
        task_ref: "task-001".to_owned(),
        scope_ref: "scope-001".to_owned(),
        fence_ref: "fence-001".to_owned(),
    }
}

fn observation_window(stale: bool) -> ObservationWindow {
    if stale {
        ObservationWindow {
            observed_from_ms: CREATED_AT_MS - 200_000,
            observed_to_ms: CREATED_AT_MS - 100_000,
            environment_ref: "env-test-001".to_owned(),
            platform_ref: "platform-test-001".to_owned(),
            toolchain_ref: "toolchain-test-001".to_owned(),
        }
    } else {
        ObservationWindow {
            observed_from_ms: CREATED_AT_MS - 20_000,
            observed_to_ms: CREATED_AT_MS - 10_000,
            environment_ref: "env-test-001".to_owned(),
            platform_ref: "platform-test-001".to_owned(),
            toolchain_ref: "toolchain-test-001".to_owned(),
        }
    }
}

fn owner_binding(tag: &str) -> OwnerBinding {
    OwnerBinding {
        owner_ref: format!("owner-{tag}"),
        schema_ref: format!("schema-{tag}"),
        revision_ref: format!("revision-{tag}"),
        content_digest: hex_byte(0xab),
    }
}

fn metric_for(status: DimensionStatus) -> MetricMeasurement {
    if status == DimensionStatus::Missing {
        MetricMeasurement {
            metric_ref: "metric-quality-001".to_owned(),
            value: 0.0,
            unit_ref: "unit-count-001".to_owned(),
            normalization_ref: "norm-none-001".to_owned(),
            population_ref: "population-all-001".to_owned(),
            presence: MetricPresence::Unavailable,
        }
    } else {
        MetricMeasurement {
            metric_ref: "metric-quality-001".to_owned(),
            value: 1.0,
            unit_ref: "unit-count-001".to_owned(),
            normalization_ref: "norm-none-001".to_owned(),
            population_ref: "population-all-001".to_owned(),
            presence: MetricPresence::Value,
        }
    }
}

fn observation_core(
    dimension: SelfQualityDimension,
    status: DimensionStatus,
    observation_ref: &str,
    owner_tag: &str,
    stale: bool,
) -> ObservationCore {
    ObservationCore {
        observation_ref: observation_ref.to_owned(),
        dimension,
        owner: owner_binding(owner_tag),
        window: observation_window(stale),
        metric: metric_for(status),
        completeness: DenominatorCompleteness::Complete,
        status,
        counterevidence_refs: Vec::new(),
        confounder_refs: Vec::new(),
        intervention_refs: Vec::new(),
    }
}

fn wrap_family(family: &str, core: ObservationCore) -> SelfQualityObservation {
    match family {
        "Conformance" => SelfQualityObservation::Conformance(core),
        "Recovery" => SelfQualityObservation::Recovery(core),
        "SecurityPrivacy" => SelfQualityObservation::SecurityPrivacy(core),
        "CostQuota" => SelfQualityObservation::CostQuota(core),
        "Product" => SelfQualityObservation::Product(core),
        "MemoryProvenance" => SelfQualityObservation::MemoryProvenance(core),
        "SourceBuild" => SelfQualityObservation::SourceBuild(core),
        "DreamerCandidate" => SelfQualityObservation::DreamerCandidate(core),
        "LearningOutcome" => SelfQualityObservation::LearningOutcome(core),
        _ => unreachable!("unknown test family {family}"),
    }
}

fn make_observation(
    family: &str,
    dimension: SelfQualityDimension,
    status: DimensionStatus,
    observation_ref: &str,
    owner_tag: &str,
    stale: bool,
) -> SelfQualityObservation {
    wrap_family(
        family,
        observation_core(dimension, status, observation_ref, owner_tag, stale),
    )
}

fn sort_observations(observations: Vec<SelfQualityObservation>) -> Vec<SelfQualityObservation> {
    let mut sorted = observations;
    sorted.sort_by(|left, right| {
        (left.family_name(), left.core().observation_ref.as_str())
            .cmp(&(right.family_name(), right.core().observation_ref.as_str()))
    });
    sorted
}

fn denominator_complete_for(observations: &[SelfQualityObservation]) -> QualityDenominator {
    let mut dimensions = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for observation in observations {
        dimensions.insert(observation.core().dimension);
        sources.insert(observation.core().owner.owner_ref.clone());
    }
    let dimension_count = u32::try_from(dimensions.len()).expect("dimension count fits in u32");
    let source_count = u32::try_from(sources.len()).expect("source count fits in u32");
    let member_count = u32::try_from(observations.len()).expect("member count fits in u32");
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

fn default_limits() -> QualityLimits {
    QualityLimits {
        max_observations: 256,
        max_history: 128,
        max_handoffs: 16,
        max_bytes: 1 << 20,
        max_depth: 8,
        max_work_units: 1 << 20,
        max_output_refs: 64,
        max_time_ms: 3_600_000,
    }
}

fn default_policy_with_limits(limits: QualityLimits) -> SelfQualityPolicy {
    SelfQualityPolicy {
        contract_version: 1,
        policy_ref: "policy-sq-001".to_owned(),
        schema_ref: "schema-policy-001".to_owned(),
        revision_ref: "revision-policy-001".to_owned(),
        rules_digest: hex_byte(0xcd),
        limits,
    }
}

fn ceilings() -> EvidenceCeilings {
    EvidenceCeilings {
        privacy_ceiling_ref: "ceiling-privacy-001".to_owned(),
        authority_ceiling_ref: "ceiling-authority-001".to_owned(),
        proof_ceiling_ref: "ceiling-proof-001".to_owned(),
    }
}

fn assemble_input(
    observations: Vec<SelfQualityObservation>,
    denominator: QualityDenominator,
    limits: QualityLimits,
    history: Vec<PriorDiagnosisRecord>,
) -> SelfQualityInput {
    SelfQualityInput {
        contract_version: 1,
        input_ref: INPUT_REF.to_owned(),
        product: product_ref(),
        source: source_identity(),
        observations: sort_observations(observations),
        prior_history: history,
        policy: default_policy_with_limits(limits),
        ceilings: ceilings(),
        denominator,
        created_at_ms: CREATED_AT_MS,
    }
}

fn complete_input(observations: Vec<SelfQualityObservation>) -> SelfQualityInput {
    let denominator = denominator_complete_for(&observations);
    assemble_input(observations, denominator, default_limits(), Vec::new())
}

fn history_record(tag: &str, observed_at_ms: u64) -> PriorDiagnosisRecord {
    PriorDiagnosisRecord {
        diagnosis_ref: format!("diagnosis-{tag}"),
        intervention_ref: format!("intervention-{tag}"),
        intervention_state: InterventionState::Applied,
        recurrence: Recurrence::Unknown,
        hypothesis_status: CauseHypothesisStatus::Symptom,
        source_ref: format!("history-source-{tag}"),
        configuration_ref: format!("history-configuration-{tag}"),
        environment_ref: format!("history-environment-{tag}"),
        observed_at_ms,
    }
}

#[allow(clippy::too_many_lines)]
fn core_mut(observation: &mut SelfQualityObservation) -> &mut ObservationCore {
    match observation {
        SelfQualityObservation::Conformance(inner)
        | SelfQualityObservation::SourceBuild(inner)
        | SelfQualityObservation::RealEdge(inner)
        | SelfQualityObservation::Runtime(inner)
        | SelfQualityObservation::Liveness(inner)
        | SelfQualityObservation::Service(inner)
        | SelfQualityObservation::Semantic(inner)
        | SelfQualityObservation::Recovery(inner)
        | SelfQualityObservation::Product(inner)
        | SelfQualityObservation::ContextFloor(inner)
        | SelfQualityObservation::ContextSelection(inner)
        | SelfQualityObservation::ContextQuality(inner)
        | SelfQualityObservation::ContextEconomy(inner)
        | SelfQualityObservation::DreamerGrounding(inner)
        | SelfQualityObservation::DreamerCandidate(inner)
        | SelfQualityObservation::DreamerController(inner)
        | SelfQualityObservation::LearningDelivery(inner)
        | SelfQualityObservation::LearningUse(inner)
        | SelfQualityObservation::LearningOutcome(inner)
        | SelfQualityObservation::LearningClosure(inner)
        | SelfQualityObservation::MemoryProvenance(inner)
        | SelfQualityObservation::MemoryConflict(inner)
        | SelfQualityObservation::SecurityPrivacy(inner)
        | SelfQualityObservation::ErasureInfluence(inner)
        | SelfQualityObservation::PerformanceResources(inner)
        | SelfQualityObservation::CostQuota(inner)
        | SelfQualityObservation::HumanAttention(inner)
        | SelfQualityObservation::RecoveryCompatibility(inner) => inner,
    }
}

// WORK_UNIT_CASE: 820/43
#[test]
fn self_quality_820_43_decomposition_not_blended() {
    let failing_correctness = make_observation(
        "Conformance",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
        "obs-001-correctness",
        "alpha",
        false,
    );
    let failing_cost = make_observation(
        "CostQuota",
        SelfQualityDimension::CostQuota,
        DimensionStatus::Fail,
        "obs-002-costquota",
        "beta",
        false,
    );
    let input = complete_input(vec![failing_correctness, failing_cost]);
    validate_self_quality_input(&input).expect("fixture must validate");
    let SelfQualityOutcome::Candidate(candidate) =
        diagnose_self_quality(&input).expect("diagnose must succeed")
    else {
        unreachable!("two failing dimensions must yield a candidate")
    };
    assert_eq!(candidate.handoffs.len(), 2);
    let mut owners = BTreeSet::new();
    for handoff in &candidate.handoffs {
        owners.insert(handoff.owner);
    }
    assert_eq!(owners.len(), 2);
    assert!(owners.contains(&SelfQualityHandoffOwner::DevelopmentDiagnosis675));
    assert!(owners.contains(&SelfQualityHandoffOwner::HumanCostRisk));
    let correctness_ref = "obs-001-correctness".to_owned();
    let cost_ref = "obs-002-costquota".to_owned();
    for handoff in &candidate.handoffs {
        let claims_correctness = handoff.symptom_refs.contains(&correctness_ref);
        let claims_cost = handoff.symptom_refs.contains(&cost_ref);
        assert!(
            claims_correctness || claims_cost,
            "every handoff must name its own dimension refs"
        );
        assert!(
            !(claims_correctness && claims_cost),
            "no handoff may blend both dimensions"
        );
        for symptom in &handoff.symptom_refs {
            assert!(
                symptom == &correctness_ref || symptom == &cost_ref,
                "symptom refs stay inside one dimension"
            );
        }
    }
}

// WORK_UNIT_CASE: 820/44
#[test]
fn self_quality_820_44_unknown_owner_never_routed() {
    let handoff = make_handoff(
        "handoff-unsupported-001",
        SelfQualityHandoffOwner::UnsupportedOwner,
        &["symptom-unsupported-001".to_owned()],
        &["problem-unsupported-001".to_owned()],
        &["evidence-unsupported-001".to_owned()],
        &[],
        &["applies-unsupported-001".to_owned()],
        Priority::Medium,
        &["ceiling-privacy-001".to_owned()],
        &["invalidate-unsupported-001".to_owned()],
    )
    .expect("hand-built unsupported handoff must be structurally valid");
    validate_handoff(&handoff).expect("unsupported handoff validates structurally");
    let families = [
        "Conformance",
        "Recovery",
        "SecurityPrivacy",
        "CostQuota",
        "Product",
        "MemoryProvenance",
        "SourceBuild",
        "DreamerCandidate",
        "LearningOutcome",
    ];
    for dimension in SelfQualityDimension::ALL {
        for family in families {
            let observation = make_observation(
                family,
                dimension,
                DimensionStatus::Pass,
                "obs-sweep-001",
                "sweep",
                false,
            );
            let owner = route_owner(&observation);
            assert!(
                owner != SelfQualityHandoffOwner::UnsupportedOwner,
                "route must never yield UnsupportedOwner for {dimension:?}/{family}"
            );
        }
    }
}

// WORK_UNIT_CASE: 820/45
#[test]
fn self_quality_820_45_no_action_needs_complete_current_evidence() {
    let fresh_input = complete_input(vec![make_observation(
        "Conformance",
        SelfQualityDimension::Correctness,
        DimensionStatus::Partial,
        "obs-001-partial",
        "alpha",
        false,
    )]);
    let fresh_outcome =
        diagnose_self_quality(&fresh_input).expect("fresh partial input must diagnose");
    assert!(matches!(fresh_outcome, SelfQualityOutcome::NoAction(_)));

    let mut short_denominator = denominator_complete_for(&fresh_input.observations);
    short_denominator.expected_members += 1;
    short_denominator.completeness = DenominatorCompleteness::Partial;
    let short_input = assemble_input(
        vec![make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Partial,
            "obs-001-partial",
            "alpha",
            false,
        )],
        short_denominator,
        default_limits(),
        Vec::new(),
    );
    let short_outcome =
        diagnose_self_quality(&short_input).expect("partial denominator must diagnose");
    assert!(matches!(short_outcome, SelfQualityOutcome::Incomplete(_)));
    assert!(!matches!(short_outcome, SelfQualityOutcome::NoAction(_)));

    let mut stale_limits = default_limits();
    stale_limits.max_time_ms = 1_000;
    let stale_observations = vec![make_observation(
        "Conformance",
        SelfQualityDimension::Correctness,
        DimensionStatus::Partial,
        "obs-001-partial",
        "alpha",
        true,
    )];
    let stale_denominator = denominator_complete_for(&stale_observations);
    let stale_input = assemble_input(
        stale_observations,
        stale_denominator,
        stale_limits,
        Vec::new(),
    );
    let stale_outcome = diagnose_self_quality(&stale_input).expect("stale input must diagnose");
    assert!(matches!(stale_outcome, SelfQualityOutcome::Unknown(_)));
    assert!(!matches!(stale_outcome, SelfQualityOutcome::NoAction(_)));
}

// WORK_UNIT_CASE: 820/46
#[test]
fn self_quality_820_46_silence_is_not_no_action() {
    let empty = assemble_input(
        Vec::new(),
        QualityDenominator {
            expected_dimensions: 2,
            supplied_dimensions: 0,
            expected_sources: 2,
            supplied_sources: 0,
            expected_members: 2,
            supplied_members: 0,
            completeness: DenominatorCompleteness::Unknown,
        },
        default_limits(),
        Vec::new(),
    );
    let empty_error = validate_self_quality_input(&empty).expect_err("empty coverage must fail");
    assert_eq!(empty_error, SelfQualityContractError::EmptyCoverage);

    let passing = vec![make_observation(
        "Conformance",
        SelfQualityDimension::Correctness,
        DimensionStatus::Pass,
        "obs-001-pass",
        "alpha",
        false,
    )];
    let mut short_denominator = denominator_complete_for(&passing);
    short_denominator.expected_members += 1;
    short_denominator.completeness = DenominatorCompleteness::Partial;
    let short_input = assemble_input(passing, short_denominator, default_limits(), Vec::new());
    let outcome = diagnose_self_quality(&short_input).expect("partial denominator must diagnose");
    assert!(matches!(outcome, SelfQualityOutcome::Incomplete(_)));
    assert!(!matches!(outcome, SelfQualityOutcome::NoAction(_)));
    assert!(!matches!(outcome, SelfQualityOutcome::NoProblem(_)));
}

// WORK_UNIT_CASE: 820/47
#[test]
fn self_quality_820_47_every_limit_independent() {
    let passing_pair = vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Pass,
            "obs-001-pass",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            "obs-002-pass",
            "beta",
            false,
        ),
    ];
    let mut observation_cap = default_limits();
    observation_cap.max_observations = 1;
    let capped_observations = assemble_input(
        passing_pair.clone(),
        denominator_complete_for(&passing_pair),
        observation_cap,
        Vec::new(),
    );
    assert!(
        validate_self_quality_input(&capped_observations).is_err(),
        "max_observations must bind independently"
    );

    let history_pair = vec![
        history_record("alpha", CREATED_AT_MS - 20_000),
        history_record("beta", CREATED_AT_MS - 10_000),
    ];
    let mut history_cap = default_limits();
    history_cap.max_history = 1;
    let capped_history = assemble_input(
        passing_pair.clone(),
        denominator_complete_for(&passing_pair),
        history_cap,
        history_pair,
    );
    assert!(
        validate_self_quality_input(&capped_history).is_err(),
        "max_history must bind independently"
    );

    let failing_pair = vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Fail,
            "obs-002-fail",
            "beta",
            false,
        ),
    ];
    let mut handoff_cap = default_limits();
    handoff_cap.max_handoffs = 1;
    let capped_handoffs = assemble_input(
        failing_pair.clone(),
        denominator_complete_for(&failing_pair),
        handoff_cap,
        Vec::new(),
    );
    assert!(
        diagnose_self_quality(&capped_handoffs).is_err(),
        "max_handoffs must bind independently"
    );

    let mut byte_cap = default_limits();
    byte_cap.max_bytes = 0;
    assert!(
        validate_limits(&byte_cap).is_err(),
        "max_bytes must bind independently"
    );

    let mut time_cap = default_limits();
    time_cap.max_time_ms = 99_999_999_999;
    assert!(
        validate_limits(&time_cap).is_err(),
        "max_time_ms must bind independently"
    );

    let mut depth_cap = default_limits();
    depth_cap.max_depth = 0;
    assert!(
        validate_limits(&depth_cap).is_err(),
        "max_depth must bind independently"
    );

    let mut output_cap = default_limits();
    output_cap.max_output_refs = 0;
    assert!(
        validate_limits(&output_cap).is_err(),
        "max_output_refs must bind independently"
    );
}

// WORK_UNIT_CASE: 820/48
#[test]
fn self_quality_820_48_replay_and_changed_identity() {
    let input = complete_input(vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            "obs-002-pass",
            "beta",
            false,
        ),
    ]);
    let first_digest = digest_self_quality_input(&input);
    let second_digest = digest_self_quality_input(&input);
    assert_eq!(first_digest, second_digest);

    let mut permuted = input.clone();
    permuted.observations.reverse();
    let canonical =
        canonicalize_self_quality_input(permuted).expect("permuted input must canonicalize");
    assert_eq!(digest_self_quality_input(&canonical), first_digest);

    let mut mutated = input.clone();
    core_mut(&mut mutated.observations[0]).metric.value = 2.0;
    let mutated_digest = digest_self_quality_input(&mutated);
    assert_ne!(
        mutated_digest, first_digest,
        "a changed metric value must change the digest"
    );

    let SelfQualityOutcome::Candidate(candidate) =
        diagnose_self_quality(&input).expect("original must diagnose")
    else {
        unreachable!("failing input must yield a candidate")
    };
    let mismatch = validate_candidate_against_input(&candidate, &mutated)
        .expect_err("mutated input must not validate");
    assert!(matches!(
        mismatch,
        SelfQualityContractError::DigestMismatch { .. }
    ));
}

// WORK_UNIT_CASE: 820/49
#[test]
fn self_quality_820_49_permutations_share_identity() {
    let input = complete_input(vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            "obs-002-pass",
            "beta",
            false,
        ),
        make_observation(
            "Product",
            SelfQualityDimension::ProductOutcome,
            DimensionStatus::Pass,
            "obs-003-pass",
            "gamma",
            false,
        ),
    ]);
    let canonical_digest = digest_self_quality_input(&input);

    let mut forward_shuffle = input.observations.clone();
    forward_shuffle.reverse();
    let mut rotated_shuffle = input.observations.clone();
    rotated_shuffle.rotate_left(1);
    let canonical_forward =
        canonicalize_observations(forward_shuffle).expect("forward shuffle must canonicalize");
    let canonical_rotated =
        canonicalize_observations(rotated_shuffle).expect("rotated shuffle must canonicalize");
    let forward_refs: Vec<&str> = canonical_forward
        .iter()
        .map(|observation| observation.core().observation_ref.as_str())
        .collect();
    let rotated_refs: Vec<&str> = canonical_rotated
        .iter()
        .map(|observation| observation.core().observation_ref.as_str())
        .collect();
    assert_eq!(forward_refs, rotated_refs);

    let mut permuted_input = input.clone();
    permuted_input.observations.reverse();
    assert_eq!(digest_self_quality_input(&permuted_input), canonical_digest);

    let SelfQualityOutcome::Candidate(candidate) =
        diagnose_self_quality(&input).expect("fixture must diagnose")
    else {
        unreachable!("failing input must yield a candidate")
    };
    let mut permuted_candidate = candidate.clone();
    permuted_candidate.outcomes.reverse();
    assert_eq!(
        digest_candidate(&candidate),
        digest_candidate(&permuted_candidate)
    );
}

// WORK_UNIT_CASE: 820/50
#[test]
fn self_quality_820_50_malformed_never_panics() {
    let build_base = || {
        complete_input(vec![
            make_observation(
                "Conformance",
                SelfQualityDimension::Correctness,
                DimensionStatus::Pass,
                "obs-001-pass",
                "alpha",
                false,
            ),
            make_observation(
                "CostQuota",
                SelfQualityDimension::CostQuota,
                DimensionStatus::Pass,
                "obs-002-pass",
                "beta",
                false,
            ),
        ])
    };
    for index in 0..12 {
        let mut input = build_base();
        match index {
            0 => {
                input.input_ref = String::new();
            }
            1 => {
                input.input_ref = " x".to_owned();
            }
            2 => {
                input.input_ref = "a\nb".to_owned();
            }
            3 => {
                input.input_ref = "default".to_owned();
            }
            4 => {
                input.input_ref = "a".repeat(1025);
            }
            5 => {
                core_mut(&mut input.observations[0]).owner.content_digest = "zz".to_owned();
            }
            6 => {
                core_mut(&mut input.observations[0]).metric.value = f64::NAN;
            }
            7 => {
                core_mut(&mut input.observations[0]).metric.value = f64::INFINITY;
            }
            8 => {
                let duplicate = input.observations[0].core().observation_ref.clone();
                core_mut(&mut input.observations[1]).observation_ref = duplicate;
            }
            9 => {
                input.observations.reverse();
            }
            10 => {
                let closed_at = input.observations[0].core().window.observed_to_ms;
                core_mut(&mut input.observations[0]).window.observed_from_ms = closed_at;
            }
            11 => {
                input.created_at_ms = 0;
            }
            _ => unreachable!("mutator table holds twelve entries"),
        }
        assert!(
            validate_self_quality_input(&input).is_err(),
            "mutator {index} must be rejected by validation"
        );
        assert!(
            diagnose_self_quality(&input).is_err(),
            "mutator {index} must be rejected by diagnosis"
        );
    }
}

// WORK_UNIT_CASE: 820/51
#[test]
fn self_quality_820_51_complete_accounts_all() {
    let input = complete_input(vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Fail,
            "obs-002-fail",
            "beta",
            false,
        ),
        make_observation(
            "Product",
            SelfQualityDimension::ProductOutcome,
            DimensionStatus::Pass,
            "obs-003-pass",
            "gamma",
            false,
        ),
    ]);
    let mut dimensions = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for observation in &input.observations {
        dimensions.insert(observation.core().dimension);
        sources.insert(observation.core().owner.owner_ref.clone());
    }
    assert_eq!(
        input.denominator.supplied_dimensions,
        u32::try_from(dimensions.len()).expect("dimension count fits in u32")
    );
    assert_eq!(
        input.denominator.supplied_sources,
        u32::try_from(sources.len()).expect("source count fits in u32")
    );
    assert_eq!(
        input.denominator.supplied_members,
        u32::try_from(input.observations.len()).expect("member count fits in u32")
    );
    let SelfQualityOutcome::Candidate(candidate) =
        diagnose_self_quality(&input).expect("complete input must diagnose")
    else {
        unreachable!("failing input must yield a candidate")
    };
    assert_eq!(candidate.outcomes.len(), dimensions.len());
    for dimension in &dimensions {
        assert!(
            candidate
                .outcomes
                .iter()
                .any(|outcome| &outcome.dimension == dimension),
            "every observed dimension must appear in outcomes"
        );
    }
}

// WORK_UNIT_CASE: 820/52
#[test]
fn self_quality_820_52_weakest_ceiling_never_reduced() {
    let negligible_fail = DimensionOutcome {
        dimension: SelfQualityDimension::Correctness,
        status: DimensionStatus::Fail,
        severity: Severity::Negligible,
        priority: Priority::High,
        hypothesis: CauseHypothesisStatus::Symptom,
        recurrence: Recurrence::Unknown,
    };
    assert!(matches!(
        validate_dimension_outcome(&negligible_fail),
        Err(SelfQualityContractError::InvalidSeverityCombination { .. })
    ));
    let severe_pass = DimensionOutcome {
        dimension: SelfQualityDimension::Correctness,
        status: DimensionStatus::Pass,
        severity: Severity::High,
        priority: Priority::High,
        hypothesis: CauseHypothesisStatus::Symptom,
        recurrence: Recurrence::Unknown,
    };
    assert!(matches!(
        validate_dimension_outcome(&severe_pass),
        Err(SelfQualityContractError::InvalidSeverityCombination { .. })
    ));

    let high_input = complete_input(vec![
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Fail,
            "obs-002-fail",
            "alpha",
            false,
        ),
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Pass,
            "obs-001-pass",
            "beta",
            false,
        ),
    ]);
    let SelfQualityOutcome::Candidate(high_candidate) =
        diagnose_self_quality(&high_input).expect("cost failure must diagnose")
    else {
        unreachable!("failing input must yield a candidate")
    };
    assert_eq!(high_candidate.overall_severity, Severity::High);
    assert_eq!(high_candidate.overall_priority, Priority::High);

    let critical_input = complete_input(vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            "obs-002-pass",
            "beta",
            false,
        ),
    ]);
    let SelfQualityOutcome::Candidate(critical_candidate) =
        diagnose_self_quality(&critical_input).expect("correctness failure must diagnose")
    else {
        unreachable!("failing input must yield a candidate")
    };
    assert_eq!(critical_candidate.overall_severity, Severity::Critical);
    assert_eq!(critical_candidate.overall_priority, Priority::Urgent);
}

// WORK_UNIT_CASE: 820/53
#[test]
fn self_quality_820_53_removed_evidence_invalidates() {
    let full = complete_input(vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            "obs-002-pass",
            "beta",
            false,
        ),
    ]);
    let digest_full = digest_self_quality_input(&full);
    let mut trimmed = full.observations.clone();
    trimmed.pop();
    let reduced_denominator = denominator_complete_for(&trimmed);
    let reduced = assemble_input(trimmed, reduced_denominator, default_limits(), Vec::new());
    validate_self_quality_input(&reduced).expect("reduced input must stay valid");
    let digest_reduced = digest_self_quality_input(&reduced);
    assert_ne!(
        digest_full, digest_reduced,
        "removing evidence must change the digest"
    );
    let SelfQualityOutcome::Candidate(candidate) =
        diagnose_self_quality(&full).expect("full input must diagnose")
    else {
        unreachable!("failing input must yield a candidate")
    };
    let mismatch = validate_candidate_against_input(&candidate, &reduced)
        .expect_err("reduced input must not validate");
    assert!(matches!(
        mismatch,
        SelfQualityContractError::DigestMismatch { .. }
    ));
}

// WORK_UNIT_CASE: 820/54
#[test]
fn self_quality_820_54_no_plan_job_or_mutation() {
    let input = complete_input(vec![
        make_observation(
            "Conformance",
            SelfQualityDimension::Correctness,
            DimensionStatus::Fail,
            "obs-001-fail",
            "alpha",
            false,
        ),
        make_observation(
            "CostQuota",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Pass,
            "obs-002-pass",
            "beta",
            false,
        ),
    ]);
    let digest_before = digest_self_quality_input(&input);
    let snapshot_before = serde_json::to_value(&input).expect("input must serialize");
    let outcome = diagnose_self_quality(&input).expect("fixture must diagnose");
    let snapshot_after = serde_json::to_value(&input).expect("input must serialize");
    assert_eq!(snapshot_before, snapshot_after);
    let SelfQualityOutcome::Candidate(candidate) = outcome else {
        unreachable!("failing input must yield a candidate")
    };
    let text = serde_json::to_string(&candidate).expect("candidate must serialize");
    for needle in ["plan", "job", "applied", "repair", "mutation", "finish"] {
        assert!(
            !text.contains(needle),
            "outcome JSON must not contain {needle}"
        );
    }
    assert!(
        !text.contains("\"effect\""),
        "outcome JSON must not carry an effect key"
    );
    let repeat = diagnose_self_quality(&input).expect("diagnose must be repeatable");
    assert!(matches!(repeat, SelfQualityOutcome::Candidate(_)));
    let digest_after = digest_self_quality_input(&input);
    assert_eq!(digest_before, digest_after);
}

// WORK_UNIT_CASE: 820/55
#[test]
fn self_quality_820_55_no_midwave_planner_imports() {
    const CARGO_TOML: &str = include_str!("../Cargo.toml");
    const LIB_RS: &str = include_str!("../src/lib.rs");
    const DIAGNOSE_RS: &str = include_str!("../src/diagnose.rs");
    const ROUTING_RS: &str = include_str!("../src/routing.rs");
    const IDENTITY_RS: &str = include_str!("../src/identity.rs");
    const ERROR_RS: &str = include_str!("../src/error.rs");
    let forbidden = [
        "eliot-dreamer-conflict-analysis",
        "eliot-dreamer-development-diagnosis",
        "eliot-dreamer-maintenance-plan",
        "eliot-dreamer-configuration-plan",
        "eliot-dreamer-orchestration-plan",
        "eliot-dreamer-contracts",
    ];
    for needle in forbidden {
        assert!(
            !CARGO_TOML.contains(needle),
            "Cargo.toml must not reference {needle}"
        );
        assert!(
            !LIB_RS.contains(needle),
            "lib.rs must not reference {needle}"
        );
        assert!(
            !DIAGNOSE_RS.contains(needle),
            "diagnose.rs must not reference {needle}"
        );
        assert!(
            !ROUTING_RS.contains(needle),
            "routing.rs must not reference {needle}"
        );
        assert!(
            !IDENTITY_RS.contains(needle),
            "identity.rs must not reference {needle}"
        );
        assert!(
            !ERROR_RS.contains(needle),
            "error.rs must not reference {needle}"
        );
    }
}

// WORK_UNIT_CASE: 820/56
#[test]
fn self_quality_820_56_no_live_execution_paths() {
    const CARGO_TOML: &str = include_str!("../Cargo.toml");
    const LIB_RS: &str = include_str!("../src/lib.rs");
    const DIAGNOSE_RS: &str = include_str!("../src/diagnose.rs");
    const ROUTING_RS: &str = include_str!("../src/routing.rs");
    const IDENTITY_RS: &str = include_str!("../src/identity.rs");
    const ERROR_RS: &str = include_str!("../src/error.rs");
    let sources = [
        CARGO_TOML,
        LIB_RS,
        DIAGNOSE_RS,
        ROUTING_RS,
        IDENTITY_RS,
        ERROR_RS,
    ];
    let forbidden = [
        "tokio",
        "std::fs",
        "std::net",
        "std::process",
        "std::env::",
        "reqwest",
        "surreal",
        "wasmtime",
        "std::thread",
        "async fn",
        "await",
        "fn main",
    ];
    for needle in forbidden {
        for source in sources {
            assert!(
                !source.contains(needle),
                "cell sources must not contain {needle}"
            );
        }
    }
}
