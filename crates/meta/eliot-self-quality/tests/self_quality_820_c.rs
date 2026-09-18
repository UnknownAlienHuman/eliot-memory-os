#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

//! Work-unit cases 820/29..42 (writer W3) for `eliot-self-quality`.
//!
//! Fixture rules honoured throughout: `contract_version` 1, trimmed
//! non-empty texts without control characters, 32-char lowercase hex digests,
//! 3 distinct product refs, 7 distinct source refs, fresh windows bounded by
//! `created_at`, canonical observation order, chronological history, exact
//! denominator counts, and sane policy limits.

use eliot_self_quality::{
    BlockedDiagnosis, CauseHypothesisStatus, ConflictedDiagnosis, DenominatorCompleteness,
    DimensionOutcome, DimensionStatus, EvidenceCeilings, InterventionState, MetricMeasurement,
    MetricPresence, ObservationCore, ObservationWindow, OwnerBinding, PriorDiagnosisRecord,
    Priority, ProductContractRef, QualityDenominator, QualityLimits, Recurrence,
    SELF_QUALITY_CONTRACT_VERSION, SelfQualityContractError, SelfQualityDiagnosisCandidate,
    SelfQualityDimension, SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation,
    SelfQualityOutcome, SelfQualityPolicy, Severity, SourceIdentity, diagnose_self_quality,
    digest_candidate, digest_self_quality_input, digest_self_quality_policy, make_handoff,
    route_owner, validate_candidate_against_input, validate_dimension_outcome,
};

const CREATED_AT_MS: u64 = 1_700_000_000_000;
const OBSERVED_FROM_MS: u64 = 1_699_999_000_000;
const OBSERVED_TO_MS: u64 = 1_699_999_500_000;
const HEX_DIGEST: &str = "ab12cd34ef56ab12cd34ef56ab12cd34";
const DEFAULT_CONFIG: &str = "config:prod:v3";
const OTHER_CONFIG: &str = "config:other:v9";

fn product() -> ProductContractRef {
    ProductContractRef {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        objective_ref: "product:objective:v1".to_owned(),
        acceptance_ref: "product:acceptance:v1".to_owned(),
        recovery_ref: "product:recovery:v1".to_owned(),
    }
}

fn source(configuration_ref: &str) -> SourceIdentity {
    SourceIdentity {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        source_ref: "source:repo:v1".to_owned(),
        artifact_ref: "artifact:build-42".to_owned(),
        configuration_ref: configuration_ref.to_owned(),
        generation_ref: "generation:7".to_owned(),
        task_ref: "task:diagnose-a".to_owned(),
        scope_ref: "scope:project-a".to_owned(),
        fence_ref: "fence:stable".to_owned(),
    }
}

fn policy() -> SelfQualityPolicy {
    SelfQualityPolicy {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        policy_ref: "policy:self-quality:v1".to_owned(),
        schema_ref: "schema:self-quality:v1".to_owned(),
        revision_ref: "revision:self-quality:r1".to_owned(),
        rules_digest: HEX_DIGEST.to_owned(),
        limits: QualityLimits {
            max_observations: 256,
            max_history: 128,
            max_handoffs: 16,
            max_bytes: 1_048_576,
            max_depth: 16,
            max_work_units: 1_000,
            max_output_refs: 64,
            max_time_ms: 86_400_000,
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

fn window() -> ObservationWindow {
    ObservationWindow {
        observed_from_ms: OBSERVED_FROM_MS,
        observed_to_ms: OBSERVED_TO_MS,
        environment_ref: "environment:prod".to_owned(),
        platform_ref: "platform:linux-x86_64".to_owned(),
        toolchain_ref: "toolchain:rust-1p94".to_owned(),
    }
}

fn owner(tag: &str) -> OwnerBinding {
    OwnerBinding {
        owner_ref: format!("owner:{tag}:v1"),
        schema_ref: format!("schema:{tag}:v1"),
        revision_ref: format!("revision:{tag}:r1"),
        content_digest: HEX_DIGEST.to_owned(),
    }
}

fn value_metric(tag: &str) -> MetricMeasurement {
    MetricMeasurement {
        metric_ref: format!("metric:{tag}:v1"),
        value: 1.0,
        unit_ref: "unit:ratio".to_owned(),
        normalization_ref: "normalization:z-score".to_owned(),
        population_ref: "population:edge-sample-100".to_owned(),
        presence: MetricPresence::Value,
    }
}

fn core(
    observation_ref: &str,
    owner_tag: &str,
    dimension: SelfQualityDimension,
    status: DimensionStatus,
) -> ObservationCore {
    ObservationCore {
        observation_ref: observation_ref.to_owned(),
        dimension,
        owner: owner(owner_tag),
        window: window(),
        metric: value_metric(owner_tag),
        completeness: DenominatorCompleteness::Complete,
        status,
        counterevidence_refs: Vec::new(),
        confounder_refs: Vec::new(),
        intervention_refs: Vec::new(),
    }
}

fn history_record(
    tag: &str,
    source_ref: &str,
    configuration_ref: &str,
    state: InterventionState,
    recurrence: Recurrence,
    observed_at_ms: u64,
) -> PriorDiagnosisRecord {
    PriorDiagnosisRecord {
        diagnosis_ref: format!("diagnosis:{tag}:v1"),
        intervention_ref: format!("intervention:{tag}:v1"),
        intervention_state: state,
        recurrence,
        hypothesis_status: CauseHypothesisStatus::Symptom,
        source_ref: source_ref.to_owned(),
        configuration_ref: configuration_ref.to_owned(),
        environment_ref: "environment:prod".to_owned(),
        observed_at_ms,
    }
}

fn complete_denominator(observations: &[SelfQualityObservation]) -> QualityDenominator {
    let mut dimensions = std::collections::BTreeSet::new();
    let mut sources = std::collections::BTreeSet::new();
    for observation in observations {
        dimensions.insert(observation.core().dimension);
        sources.insert(observation.core().owner.owner_ref.clone());
    }
    let dimension_count = u32::try_from(dimensions.len()).expect("few dimensions");
    let source_count = u32::try_from(sources.len()).expect("few sources");
    let member_count = u32::try_from(observations.len()).expect("few observations");
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

fn assemble(
    mut observations: Vec<SelfQualityObservation>,
    history: Vec<PriorDiagnosisRecord>,
    configuration_ref: &str,
) -> SelfQualityInput {
    observations.sort_by(|left, right| {
        (left.family_name(), left.core().observation_ref.as_str())
            .cmp(&(right.family_name(), right.core().observation_ref.as_str()))
    });
    let denominator = complete_denominator(&observations);
    SelfQualityInput {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        input_ref: "input:self-quality-820-c:v1".to_owned(),
        product: product(),
        source: source(configuration_ref),
        observations,
        prior_history: history,
        policy: policy(),
        ceilings: ceilings(),
        denominator,
        created_at_ms: CREATED_AT_MS,
    }
}

fn expect_candidate(outcome: SelfQualityOutcome) -> SelfQualityDiagnosisCandidate {
    let mut slot: Option<SelfQualityDiagnosisCandidate> = None;
    if let SelfQualityOutcome::Candidate(candidate) = outcome {
        slot = Some(candidate);
    }
    slot.expect("expected Candidate outcome")
}

fn expect_blocked(outcome: SelfQualityOutcome) -> BlockedDiagnosis {
    let mut slot: Option<BlockedDiagnosis> = None;
    if let SelfQualityOutcome::Blocked(blocked) = outcome {
        slot = Some(blocked);
    }
    slot.expect("expected Blocked outcome")
}

fn expect_conflicted(outcome: SelfQualityOutcome) -> ConflictedDiagnosis {
    let mut slot: Option<ConflictedDiagnosis> = None;
    if let SelfQualityOutcome::Conflicted(conflicted) = outcome {
        slot = Some(conflicted);
    }
    slot.expect("expected Conflicted outcome")
}

// WORK_UNIT_CASE: 820/29
#[test]
fn self_quality_820_29_chronology_without_discriminator_stays_symptom() {
    let fail = SelfQualityObservation::Conformance(core(
        "obs-029-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let history = vec![
        history_record(
            "029-first",
            "source:other:v1",
            OTHER_CONFIG,
            InterventionState::Observed,
            Recurrence::OneShot,
            1_699_999_100_000,
        ),
        history_record(
            "029-second",
            "source:other:v1",
            OTHER_CONFIG,
            InterventionState::Applied,
            Recurrence::Persistent,
            1_699_999_200_000,
        ),
    ];
    let input = assemble(vec![fail], history, DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/29");
    let candidate = expect_candidate(outcome);
    assert!(candidate.mechanism_refs.is_empty());
    assert!(!candidate.symptom_refs.is_empty());
    assert!(
        candidate
            .symptom_refs
            .contains(&"obs-029-conformance-fail".to_owned())
    );
    let rolled = candidate
        .outcomes
        .iter()
        .find(|item| item.dimension == SelfQualityDimension::Correctness)
        .expect("correctness outcome present");
    assert!(matches!(rolled.hypothesis, CauseHypothesisStatus::Symptom));
}

// WORK_UNIT_CASE: 820/30
#[test]
fn self_quality_820_30_falsifiable_mechanism_at_ceiling() {
    let fail = SelfQualityObservation::Conformance(core(
        "obs-030-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let input_digest = digest_self_quality_input(&input);
    let policy_digest = digest_self_quality_policy(&input.policy);
    let handoff = make_handoff(
        "handoff-030-dev-0",
        SelfQualityHandoffOwner::DevelopmentDiagnosis675,
        &["obs-030-conformance-fail".to_owned()],
        &["problem:Correctness".to_owned()],
        &["obs-030-conformance-fail".to_owned()],
        &[],
        &["applies:Correctness".to_owned()],
        Priority::Urgent,
        &["ceiling:privacy-authority-proof".to_owned()],
        &["invalidate:input:self-quality-820-c:v1".to_owned()],
    )
    .expect("handoff 820/30");
    let candidate = SelfQualityDiagnosisCandidate {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        candidate_ref: "candidate:self-quality-030:v1".to_owned(),
        input_digest,
        policy_digest,
        outcomes: vec![DimensionOutcome {
            dimension: SelfQualityDimension::Correctness,
            status: DimensionStatus::Fail,
            severity: Severity::Critical,
            priority: Priority::Urgent,
            hypothesis: CauseHypothesisStatus::ProvenCause,
            recurrence: Recurrence::Unknown,
        }],
        overall_severity: Severity::Critical,
        overall_priority: Priority::Urgent,
        symptom_refs: vec!["obs-030-conformance-fail".to_owned()],
        mechanism_refs: vec!["mechanism:falsifiable-001".to_owned()],
        counterevidence_refs: Vec::new(),
        handoffs: vec![handoff],
        expires_at_ms: CREATED_AT_MS + 3_600_000,
    };
    validate_candidate_against_input(&candidate, &input).expect("falsifiable candidate valid");
    let proven_pass = DimensionOutcome {
        dimension: SelfQualityDimension::Correctness,
        status: DimensionStatus::Pass,
        severity: Severity::Negligible,
        priority: Priority::None,
        hypothesis: CauseHypothesisStatus::ProvenCause,
        recurrence: Recurrence::Unknown,
    };
    let error = validate_dimension_outcome(&proven_pass).expect_err("proven pass rejected");
    assert!(matches!(
        error,
        SelfQualityContractError::InvalidHypothesis { .. }
    ));
    let mut missing_mechanism = candidate.clone();
    missing_mechanism.mechanism_refs = Vec::new();
    let error = validate_candidate_against_input(&missing_mechanism, &input)
        .expect_err("empty mechanism rejected");
    assert!(matches!(
        error,
        SelfQualityContractError::MissingEvidence { .. }
    ));
}

// WORK_UNIT_CASE: 820/31
#[test]
fn self_quality_820_31_missing_discriminator_routes_instrumentation() {
    let fail = SelfQualityObservation::Conformance(core(
        "obs-031-a-conformance",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let inconclusive = SelfQualityObservation::ContextQuality(core(
        "obs-031-b-context",
        "beta",
        SelfQualityDimension::ContextQuality,
        DimensionStatus::Inconclusive,
    ));
    let input = assemble(vec![fail, inconclusive], Vec::new(), DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/31");
    let candidate = expect_candidate(outcome);
    let handoff = candidate
        .handoffs
        .iter()
        .find(|item| item.owner == SelfQualityHandoffOwner::Instrumentation)
        .expect("instrumentation handoff present");
    assert!(matches!(
        handoff.owner,
        SelfQualityHandoffOwner::Instrumentation
    ));
    assert_eq!(
        handoff.missing_evidence_refs,
        vec!["obs-031-b-context".to_owned()]
    );
}

// WORK_UNIT_CASE: 820/32
#[test]
fn self_quality_820_32_complete_recurrence_history_links() {
    let mut failing = core(
        "obs-032-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    );
    failing.intervention_refs = vec!["intervention:fix-032:v1".to_owned()];
    let history = vec![
        history_record(
            "032-first",
            "source:other:v1",
            OTHER_CONFIG,
            InterventionState::Observed,
            Recurrence::OneShot,
            1_699_999_100_000,
        ),
        history_record(
            "032-second",
            "source:other:v1",
            OTHER_CONFIG,
            InterventionState::Applied,
            Recurrence::Persistent,
            1_699_999_200_000,
        ),
        history_record(
            "032-third",
            "source:other:v1",
            OTHER_CONFIG,
            InterventionState::RolledBack,
            Recurrence::Recurrent,
            1_699_999_300_000,
        ),
    ];
    let input = assemble(
        vec![SelfQualityObservation::Conformance(failing)],
        history,
        DEFAULT_CONFIG,
    );
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/32");
    let candidate = expect_candidate(outcome);
    let rolled = candidate
        .outcomes
        .iter()
        .find(|item| item.dimension == SelfQualityDimension::Correctness)
        .expect("correctness outcome present");
    assert!(matches!(rolled.recurrence, Recurrence::Recurrent));
}

// WORK_UNIT_CASE: 820/33
#[test]
fn self_quality_820_33_recurrence_variants_validate_and_digest() {
    let outcome_for = |recurrence: Recurrence| DimensionOutcome {
        dimension: SelfQualityDimension::Correctness,
        status: DimensionStatus::Fail,
        severity: Severity::High,
        priority: Priority::High,
        hypothesis: CauseHypothesisStatus::Hypothesis,
        recurrence,
    };
    for recurrence in [
        Recurrence::OneShot,
        Recurrence::Persistent,
        Recurrence::Recurrent,
        Recurrence::Flaky,
    ] {
        validate_dimension_outcome(&outcome_for(recurrence)).expect("recurrence valid");
    }
    let fail = SelfQualityObservation::Conformance(core(
        "obs-033-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let input_digest = digest_self_quality_input(&input);
    let policy_digest = digest_self_quality_policy(&input.policy);
    let candidate_for = |recurrence: Recurrence| SelfQualityDiagnosisCandidate {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        candidate_ref: "candidate:self-quality-033:v1".to_owned(),
        input_digest: input_digest.clone(),
        policy_digest: policy_digest.clone(),
        outcomes: vec![outcome_for(recurrence)],
        overall_severity: Severity::High,
        overall_priority: Priority::High,
        symptom_refs: vec!["obs-033-conformance-fail".to_owned()],
        mechanism_refs: Vec::new(),
        counterevidence_refs: Vec::new(),
        handoffs: Vec::new(),
        expires_at_ms: CREATED_AT_MS + 3_600_000,
    };
    let digests = [
        digest_candidate(&candidate_for(Recurrence::OneShot)),
        digest_candidate(&candidate_for(Recurrence::Persistent)),
        digest_candidate(&candidate_for(Recurrence::Recurrent)),
        digest_candidate(&candidate_for(Recurrence::Flaky)),
    ];
    let distinct: std::collections::BTreeSet<String> = digests.into_iter().collect();
    assert_eq!(distinct.len(), 4);
}

// WORK_UNIT_CASE: 820/34
#[test]
fn self_quality_820_34_empty_history_leaves_recurrence_unknown() {
    let fail = SelfQualityObservation::Conformance(core(
        "obs-034-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/34");
    let candidate = expect_candidate(outcome);
    let rolled = candidate
        .outcomes
        .iter()
        .find(|item| item.dimension == SelfQualityDimension::Correctness)
        .expect("correctness outcome present");
    assert!(matches!(rolled.recurrence, Recurrence::Unknown));
}

// WORK_UNIT_CASE: 820/35
#[test]
fn self_quality_820_35_equivalent_failed_intervention_blocks() {
    let fail = SelfQualityObservation::Conformance(core(
        "obs-035-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let record = history_record(
        "035-failed",
        "source:repo:v1",
        DEFAULT_CONFIG,
        InterventionState::Failed,
        Recurrence::Persistent,
        1_699_999_200_000,
    );
    let expected_blocker = record.intervention_ref.clone();
    let input = assemble(vec![fail], vec![record], DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/35");
    let blocked = expect_blocked(outcome);
    assert_eq!(blocked.blocker_refs, vec![expected_blocker]);
}

// WORK_UNIT_CASE: 820/36
#[test]
fn self_quality_820_36_changed_mechanism_does_not_block() {
    let fail = SelfQualityObservation::Conformance(core(
        "obs-036-conformance-fail",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    ));
    let record = history_record(
        "036-failed",
        "source:repo:v1",
        "config:old:v1",
        InterventionState::Failed,
        Recurrence::Persistent,
        1_699_999_200_000,
    );
    let input = assemble(vec![fail], vec![record], DEFAULT_CONFIG);
    let baseline_digest = digest_self_quality_input(&input);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/36");
    let candidate = expect_candidate(outcome);
    assert!(
        candidate
            .symptom_refs
            .contains(&"obs-036-conformance-fail".to_owned())
    );
    let mut altered = input.clone();
    altered.source.configuration_ref = "config:canary:v9".to_owned();
    assert_ne!(digest_self_quality_input(&altered), baseline_digest);
}

// WORK_UNIT_CASE: 820/37
#[test]
fn self_quality_820_37_unknown_effect_routes_incident() {
    let fail = SelfQualityObservation::Recovery(core(
        "obs-037-recovery-fail",
        "alpha",
        SelfQualityDimension::ReconciliationUnknownEffects,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/37");
    let candidate = expect_candidate(outcome);
    assert!(
        candidate
            .handoffs
            .iter()
            .any(|item| item.owner == SelfQualityHandoffOwner::IncidentRecovery)
    );
}

// WORK_UNIT_CASE: 820/38
#[test]
fn self_quality_820_38_conflict_names_sides_without_resolution() {
    let mut conflicting = core(
        "obs-038-a-main",
        "alpha",
        SelfQualityDimension::Correctness,
        DimensionStatus::Fail,
    );
    conflicting.counterevidence_refs = vec!["obs-038-b-counter".to_owned()];
    let main = SelfQualityObservation::Conformance(conflicting);
    let counter = SelfQualityObservation::Service(core(
        "obs-038-b-counter",
        "beta",
        SelfQualityDimension::PerformanceResources,
        DimensionStatus::Pass,
    ));
    let input = assemble(vec![main, counter], Vec::new(), DEFAULT_CONFIG);
    let main_observation = input
        .observations
        .iter()
        .find(|item| item.core().observation_ref == "obs-038-a-main")
        .expect("conflicting observation present");
    assert!(matches!(
        route_owner(main_observation),
        SelfQualityHandoffOwner::ConflictAnalysis673
    ));
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/38");
    assert!(matches!(outcome, SelfQualityOutcome::Conflicted(_)));
    let conflicted = expect_conflicted(outcome);
    assert!(conflicted.conflict_refs.len() >= 2);
    assert!(
        conflicted
            .conflict_refs
            .contains(&"obs-038-a-main".to_owned())
    );
    assert!(
        conflicted
            .conflict_refs
            .contains(&"obs-038-b-counter".to_owned())
    );
}

// WORK_UNIT_CASE: 820/39
#[test]
fn self_quality_820_39_development_handoff_creates_no_experiment() {
    let fail = SelfQualityObservation::DreamerCandidate(core(
        "obs-039-dreamer-fail",
        "alpha",
        SelfQualityDimension::DreamerQuality,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/39");
    let candidate = expect_candidate(outcome);
    assert!(
        candidate
            .handoffs
            .iter()
            .any(|item| item.owner == SelfQualityHandoffOwner::DevelopmentDiagnosis675)
    );
    let json = serde_json::to_string(&candidate).expect("serialize 820/39");
    for forbidden in ["experiment", "plan", "job", "effect"] {
        assert!(
            !json.contains(&format!("\"{forbidden}\"")),
            "forbidden key {forbidden} present"
        );
    }
}

// WORK_UNIT_CASE: 820/40
#[test]
fn self_quality_820_40_maintenance_handoff_carries_refs_only() {
    let fail = SelfQualityObservation::MemoryProvenance(core(
        "obs-040-memory-fail",
        "alpha",
        SelfQualityDimension::MemoryQuality,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/40");
    let candidate = expect_candidate(outcome);
    let handoff = candidate
        .handoffs
        .iter()
        .find(|item| item.owner == SelfQualityHandoffOwner::MaintenancePlan677)
        .expect("maintenance handoff present");
    assert!(
        handoff
            .problem_refs
            .contains(&"memory-repair:obs-040-memory-fail".to_owned())
    );
    let json = serde_json::to_string(&candidate).expect("serialize 820/40");
    for forbidden in ["plan", "schedule", "job"] {
        assert!(
            !json.contains(&format!("\"{forbidden}\"")),
            "forbidden key {forbidden} present"
        );
    }
}

// WORK_UNIT_CASE: 820/41
#[test]
fn self_quality_820_41_configuration_handoff_carries_no_mutation() {
    let fail = SelfQualityObservation::RecoveryCompatibility(core(
        "obs-041-recoverycompat-fail",
        "alpha",
        SelfQualityDimension::Compatibility,
        DimensionStatus::Fail,
    ));
    let input = assemble(vec![fail], Vec::new(), DEFAULT_CONFIG);
    let outcome = diagnose_self_quality(&input).expect("diagnose 820/41");
    let candidate = expect_candidate(outcome);
    assert!(
        candidate
            .handoffs
            .iter()
            .any(|item| item.owner == SelfQualityHandoffOwner::ConfigurationAssistance679)
    );
    let json = serde_json::to_string(&candidate).expect("serialize 820/41");
    for forbidden in ["delta", "apply", "mutation"] {
        assert!(
            !json.contains(&format!("\"{forbidden}\"")),
            "forbidden key {forbidden} present"
        );
    }
}

// WORK_UNIT_CASE: 820/42
#[test]
fn self_quality_820_42_human_owners_stay_in_handoffs_only() {
    let cost = assemble(
        vec![SelfQualityObservation::CostQuota(core(
            "obs-042-a-cost",
            "alpha",
            SelfQualityDimension::CostQuota,
            DimensionStatus::Fail,
        ))],
        Vec::new(),
        DEFAULT_CONFIG,
    );
    let attention = assemble(
        vec![SelfQualityObservation::HumanAttention(core(
            "obs-042-b-attention",
            "beta",
            SelfQualityDimension::HumanBurden,
            DimensionStatus::Fail,
        ))],
        Vec::new(),
        DEFAULT_CONFIG,
    );
    let privacy = assemble(
        vec![SelfQualityObservation::SecurityPrivacy(core(
            "obs-042-c-privacy",
            "gamma",
            SelfQualityDimension::SecurityPrivacy,
            DimensionStatus::Fail,
        ))],
        Vec::new(),
        DEFAULT_CONFIG,
    );
    let cases: [(&SelfQualityInput, SelfQualityHandoffOwner, Severity); 3] = [
        (
            &cost,
            SelfQualityHandoffOwner::HumanCostRisk,
            Severity::High,
        ),
        (
            &attention,
            SelfQualityHandoffOwner::HumanPolicy,
            Severity::High,
        ),
        (
            &privacy,
            SelfQualityHandoffOwner::HumanPrivacy,
            Severity::Critical,
        ),
    ];
    for (input, expected_owner, expected_severity) in cases {
        let observation = input
            .observations
            .first()
            .expect("single observation present");
        assert!(matches!(route_owner(observation), owner if owner == expected_owner));
        assert!(expected_owner.is_human());
        let outcome = diagnose_self_quality(input).expect("diagnose 820/42");
        let candidate = expect_candidate(outcome);
        assert!(
            candidate
                .handoffs
                .iter()
                .any(|item| item.owner == expected_owner)
        );
        assert!(
            candidate
                .outcomes
                .iter()
                .all(|item| item.status == DimensionStatus::Fail)
        );
        assert_eq!(candidate.overall_severity, expected_severity);
    }
}
