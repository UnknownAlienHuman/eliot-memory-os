//! Authority-preserving `ArchitectureSelfQuery` → `ArchitectureBrief` proof.
//!
//! Issue #649 proof matrix: `WORK_UNIT_CASE 649/1..30` — one substantive
//! [`project_architecture_brief`] case per marker over exact validated
//! job/profile closures, accepted Architecture snapshot bytes and finite
//! anchor/dependency denominators. No I/O, clock, retrieval or model work;
//! every normative material statement stays bound to its accepted source
//! handle, byte range, revision and digest.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::assigning_clones
)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, PolicyRevision, ReceiptId, ResourceGeneration, SourceId,
    StateFence, sha256_hex,
};
use eliot_dreamer_architecture_brief::project_architecture_brief;
use eliot_dreamer_contracts::validation::{
    InputPreimage, OutputContext, PROOF_CEILING, VALIDATOR_CONTRACT, budget_digest, bundle_digest,
    input_digest_and_size, model_digest, output_digest, preservation_digest,
};
use eliot_dreamer_contracts::{
    ArchitectureAnchor, ArchitectureAnchorClass, ArchitectureApplicability,
    ArchitectureApplicabilityBasis, ArchitectureApplicabilityState, ArchitectureBriefDisposition,
    ArchitectureBriefSectionKind, ArchitectureDependencyDenominator, ArchitectureDependencyKind,
    ArchitectureDependencyMember, ArchitectureSourceSnapshot, ArchitectureSourceStatus,
    ArchitectureStatementModality, AttemptBinding, BudgetLimits, BudgetUsage, BundleCompleteness,
    BundleMaterial, ClaimResidue, DreamInputBundle, DreamJobInput, GroundedDreamDraft, JobClass,
    ModelDraft, NormativePairBinding, OmissionHandle, PRESERVATION_DIMENSIONS,
    PreservationDimension, PreservationReport, Requester, RequesterOrigin, SelfQueryContractError,
    SelfQueryInput, SelfQueryOutputProfile, SelfQueryPolicy, SelfQueryProfile, SourceDisposition,
    SupportState, ValidatedCandidate, ValidatedDreamDraft, ValidationPolicy, ValidationReceipt,
    parse_job_class,
};
use eliot_epistemic_contracts::{DisclosureClass, PositionAssertability, PrivacyHandling};
use eliot_receipts::{EffectClass, ProofCeiling};

const POLICY_ID: &str = "validator-649";
const TASK_ID: &str = "task-649";
const SCOPE_ID: &str = "scope-649";
const SOURCE_HANDLE: &str = "arch-source-649";
const DENOMINATOR_ID: &str = "den-649-1";
const QUESTION: &str = "What does the accepted Architecture require for this scope?";

#[derive(Clone)]
struct AnchorSpec {
    anchor_id: String,
    class: ArchitectureAnchorClass,
    modality: ArchitectureStatementModality,
    text: String,
    deps: Vec<String>,
    state: ArchitectureApplicabilityState,
    basis: ArchitectureApplicabilityBasis,
    evidence: Vec<String>,
    reason: String,
    denom_kind: ArchitectureDependencyKind,
    required: bool,
}

impl AnchorSpec {
    fn new(
        anchor_id: &str,
        class: ArchitectureAnchorClass,
        modality: ArchitectureStatementModality,
        text: &str,
    ) -> Self {
        Self {
            anchor_id: anchor_id.into(),
            class,
            modality,
            text: text.into(),
            deps: Vec::new(),
            state: ArchitectureApplicabilityState::Applicable,
            basis: ArchitectureApplicabilityBasis::Structural,
            evidence: vec![format!("ev-649-{anchor_id}")],
            reason: format!("structural role evidence for {anchor_id}"),
            denom_kind: ArchitectureDependencyKind::Interpretation,
            required: true,
        }
    }
}

struct BuildOpts {
    job_class: JobClass,
    preservation_passing: bool,
    source_status: Option<ArchitectureSourceStatus>,
    anchors: Vec<AnchorSpec>,
    denominator_complete: bool,
    extra_members: Vec<(String, String, ArchitectureDependencyKind, bool)>,
    model_statement: String,
    bundle_omissions: Vec<(String, String, bool, Option<String>)>,
    question: String,
    profile_output: SelfQueryOutputProfile,
}

fn default_anchors() -> Vec<AnchorSpec> {
    vec![
        AnchorSpec::new(
            "arch-649-a1",
            ArchitectureAnchorClass::Intent,
            ArchitectureStatementModality::Must,
            "Intent: the brief preserves accepted Architecture meaning.",
        ),
        AnchorSpec {
            denom_kind: ArchitectureDependencyKind::HardBoundary,
            ..AnchorSpec::new(
                "arch-649-a2",
                ArchitectureAnchorClass::HardBoundary,
                ArchitectureStatementModality::Must,
                "Boundary: implementation evidence never overrides Architecture.",
            )
        },
    ]
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            job_class: JobClass::ArchitectureSelfQuery,
            preservation_passing: true,
            source_status: Some(ArchitectureSourceStatus::Accepted),
            anchors: default_anchors(),
            denominator_complete: true,
            extra_members: Vec::new(),
            model_statement: "A bounded hypothesis about this scope.".into(),
            bundle_omissions: Vec::new(),
            question: QUESTION.into(),
            profile_output: SelfQueryOutputProfile::ArchitectureBrief,
        }
    }
}

fn test_fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage"),
        NonZeroU64::new(1).expect("non-zero sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn generous_budget() -> BudgetLimits {
    BudgetLimits {
        input_bytes: Some(1_048_576),
        output_bytes: Some(1_048_576),
        source_width: Some(512),
        reference_width: Some(512),
        model_calls: Some(64),
        attempts: Some(16),
        candidates: Some(16),
        wall_ms: Some(600_000),
        work_fan_out: Some(32),
        report_bytes: Some(1_048_576),
        max_stu: Some(10_000),
    }
}

fn passing_preservation(failing: bool) -> PreservationReport {
    PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(|name| {
                let passed = !(failing && *name == "coverage");
                eliot_dreamer_contracts::candidate::DimensionVerdict {
                    dimension: PreservationDimension::parse(name).expect("dimension"),
                    passed,
                    known: true,
                    note: format!("{name} retained for 649"),
                }
            })
            .collect(),
    }
}

fn pair_for(arch_digest: &str) -> NormativePairBinding {
    let implementation_digest = sha256_hex(b"implementation-649");
    let mut preimage = b"eliot-normative-pair-v1\0".to_vec();
    preimage.extend_from_slice(arch_digest.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(implementation_digest.as_bytes());
    preimage.push(0);
    NormativePairBinding {
        architecture_digest: arch_digest.into(),
        implementation_digest,
        pair_key: format!("sha256:{}", sha256_hex(&preimage)),
        document_set: "doc-set-649".into(),
        architecture_revision: "arch-r649".into(),
        implementation_revision: "impl-r649".into(),
        accepted_by: SourceId::new("source-649").expect("source id"),
        acceptance_receipt: ReceiptId::new("receipt-649").expect("receipt id"),
    }
}

fn assemble(opts: &BuildOpts) -> SelfQueryInput {
    let fence = test_fence();
    let manifest_digest = sha256_hex(b"manifest-649");
    let job = DreamJobInput {
        schema_version: 1,
        job_class: opts.job_class,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".into(),
            session: None,
        },
        operation_id: "op-649".into(),
        idempotency_key: "idem-649".into(),
        task_id: TASK_ID.into(),
        scope_id: SCOPE_ID.into(),
        state_fence: fence.clone(),
        privacy_profile: "local_only".into(),
        contract_ref: "contract-649".into(),
        policy_ref: POLICY_ID.into(),
        budget: generous_budget(),
        deadline_ms: None,
        frozen_manifest_digest: manifest_digest.clone(),
    };
    let job_id = job.canonical_id();

    let source_bytes: Vec<u8> = opts
        .anchors
        .iter()
        .flat_map(|spec| spec.text.as_bytes().to_vec())
        .collect();
    let source = opts.source_status.map(|status| {
        let digest = sha256_hex(&source_bytes);
        let pair = pair_for(&digest);
        ArchitectureSourceSnapshot {
            schema_version: 1,
            source_handle: ArtifactId::new(SOURCE_HANDLE).expect("source handle"),
            owner: SourceId::new("source-649").expect("owner"),
            revision: "arch-r649".into(),
            digest,
            status,
            pair,
            acceptance_receipt: Some(ReceiptId::new("receipt-649").expect("receipt")),
            bytes: source_bytes.clone(),
            supersedes: Vec::new(),
            invalidation: Vec::new(),
        }
    });

    let mut materials = Vec::new();
    if source
        .as_ref()
        .is_some_and(|source| !source.bytes.is_empty())
    {
        let source = source.as_ref().expect("source material");
        materials.push(BundleMaterial {
            handle: SOURCE_HANDLE.into(),
            disposition: SourceDisposition::Required,
            bytes: u64::try_from(source.bytes.len()).expect("source len"),
            digest: source.digest.clone(),
        });
    }
    let omissions = opts
        .bundle_omissions
        .iter()
        .map(
            |(handle, reason, reversible, nonrecoverable)| OmissionHandle {
                handle: handle.clone(),
                reason: reason.clone(),
                reversible: *reversible,
                scope_id: SCOPE_ID.into(),
                task_id: TASK_ID.into(),
                digest: sha256_hex(handle.as_bytes()),
                nonrecoverable_reason: nonrecoverable.clone(),
            },
        )
        .collect();
    let bundle = DreamInputBundle {
        schema_version: 1,
        job_id: job_id.clone(),
        scope_id: SCOPE_ID.into(),
        task_id: TASK_ID.into(),
        state_fence: fence.clone(),
        manifest_digest: manifest_digest.clone(),
        materials,
        omissions,
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    };

    let model_sources = vec![SOURCE_HANDLE.into()];
    let model = ModelDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        statement: opts.model_statement.clone(),
        source_handles: model_sources,
        counterevidence: vec!["coverage is limited".into()],
        uncertainty: "bounded unknown".into(),
        expected_benefit: "retain authority separation".into(),
        recommended_probes: vec!["read the accepted source".into()],
        invalidation_conditions: vec!["accepted source changes".into()],
        declared_confirmed_handles: Vec::new(),
    };
    let draft_digest = model_digest(&model).expect("model digest");
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        residues: vec![ClaimResidue {
            claim: opts.model_statement.clone(),
            state: SupportState::Supported,
            detail: "retained as model grounding".into(),
        }],
        coverage_note: "one accounted residue".into(),
    };
    let mut validator_policy = ValidationPolicy::new(POLICY_ID, 1, 1_048_576);
    validator_policy.seal().expect("validator policy");
    let usage = BudgetUsage {
        input_bytes: 1_000,
        output_bytes: 1_000,
        source_width: 1,
        reference_width: 1,
        candidates: 1,
        report_bytes: 1_000,
        stu_used: 1,
        ..BudgetUsage::default()
    };
    let preservation = passing_preservation(!opts.preservation_passing);
    let bundle_hash = bundle_digest(&bundle).expect("bundle digest");
    let input_preimage = InputPreimage {
        job: &job,
        bundle: &bundle,
        model: &model,
        grounded: &grounded,
        policy: &validator_policy,
        usage,
        preservation: &preservation,
        observation_time_ms: None,
        cancellation_requested: false,
    };
    let (input_hash, _) = input_digest_and_size(&input_preimage).expect("input digest");
    let (output_hash, _) = output_digest(&OutputContext {
        job: &job,
        bundle: &bundle,
        model: &model,
        grounded: &grounded,
        preservation: &preservation,
        policy: &validator_policy,
        usage: &usage,
        observation_time_ms: None,
        cancellation_requested: false,
        draft_digest: &draft_digest,
        bundle_digest: &bundle_hash,
        terminal_disposition: "accepted",
    })
    .expect("output digest");
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: VALIDATOR_CONTRACT.into(),
        validator_policy: POLICY_ID.into(),
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        bundle_digest: bundle_hash,
        manifest_digest: manifest_digest.clone(),
        task_id: TASK_ID.into(),
        scope_id: SCOPE_ID.into(),
        input_digest: input_hash,
        output_digest: output_hash,
        terminal_disposition: "accepted".into(),
        proof_ceiling: PROOF_CEILING.into(),
        state_fence: fence.clone(),
        preservation_digest: preservation_digest(&preservation).expect("preservation"),
        budget_digest: budget_digest(&job, &usage).expect("budget"),
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest,
        scope_id: SCOPE_ID.into(),
        task_id: TASK_ID.into(),
        state_fence: fence,
    };
    let validated_candidate = ValidatedCandidate {
        job,
        bundle,
        model,
        grounded,
        preservation: preservation.clone(),
        usage,
        policy: validator_policy,
        observation_time_ms: None,
        cancellation_requested: false,
        validated,
    };
    validated_candidate
        .validate_binding()
        .expect("fixture candidate binding");

    let mut profile = SelfQueryProfile {
        schema_version: 1,
        job_class: JobClass::ArchitectureSelfQuery,
        output_profile: opts.profile_output,
        profile_id: "arch-brief-v1".into(),
        profile_digest: String::new(),
    };
    profile.profile_digest = profile.compute_digest().expect("profile digest");

    let mut offset = 0usize;
    let anchors = opts
        .anchors
        .iter()
        .map(|spec| {
            let start = offset;
            offset += spec.text.len();
            ArchitectureAnchor {
                schema_version: 1,
                anchor_id: ArtifactId::new(&spec.anchor_id).expect("anchor id"),
                source_handle: ArtifactId::new(SOURCE_HANDLE).expect("anchor handle"),
                revision: "arch-r649".into(),
                source_digest: sha256_hex(&source_bytes),
                byte_start: u64::try_from(start).expect("byte start"),
                byte_end: u64::try_from(offset).expect("byte end"),
                class: spec.class,
                modality: spec.modality,
                text: spec.text.clone(),
                applicability: ArchitectureApplicability {
                    state: spec.state,
                    basis: spec.basis,
                    evidence_refs: spec
                        .evidence
                        .iter()
                        .map(|id| ArtifactId::new(id).expect("evidence id"))
                        .collect(),
                    reason: spec.reason.clone(),
                },
                dependency_refs: spec
                    .deps
                    .iter()
                    .map(|id| ArtifactId::new(id).expect("dep id"))
                    .collect(),
            }
        })
        .collect::<Vec<_>>();

    let mut members = opts
        .anchors
        .iter()
        .enumerate()
        .map(|(index, spec)| ArchitectureDependencyMember {
            member_id: ArtifactId::new(format!("den-649-m{index}")).expect("member id"),
            anchor_id: ArtifactId::new(&spec.anchor_id).expect("member anchor"),
            source_handle: ArtifactId::new(SOURCE_HANDLE).expect("member handle"),
            kind: spec.denom_kind,
            required: spec.required,
        })
        .collect::<Vec<_>>();
    for (member_id, anchor_id, kind, required) in &opts.extra_members {
        members.push(ArchitectureDependencyMember {
            member_id: ArtifactId::new(member_id).expect("extra member"),
            anchor_id: ArtifactId::new(anchor_id).expect("extra anchor"),
            source_handle: ArtifactId::new(SOURCE_HANDLE).expect("extra handle"),
            kind: *kind,
            required: *required,
        });
    }
    let mut denominator = ArchitectureDependencyDenominator {
        schema_version: 1,
        denominator_id: ArtifactId::new(DENOMINATOR_ID).expect("denominator id"),
        members,
        complete: opts.denominator_complete,
        digest: String::new(),
    };
    denominator.digest = denominator.compute_digest().expect("denominator digest");

    let policy = SelfQueryPolicy {
        schema_version: 1,
        policy_id: POLICY_ID.into(),
        policy_revision: PolicyRevision::new(1).expect("policy revision"),
        privacy: PrivacyHandling::Unrestricted,
        disclosure: DisclosureClass::Open,
        authority_ceiling: PositionAssertability::HypothesisCandidate,
        effect_ceiling: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        max_items: 4_000,
        max_reference_width: 400,
        max_input_bytes: 1_048_576,
        max_output_bytes: 1_048_576,
        max_stu: 9_000,
        max_work: 100_000,
        now_ms: None,
        deadline_ms: None,
        cancellation_requested: false,
    };

    SelfQueryInput {
        schema_version: 1,
        validated_candidate,
        profile,
        attempt: AttemptBinding {
            attempt_id: "attempt-649-1".into(),
            attempt_number: 1,
            maximum_attempts: 3,
            predecessor: None,
            invalidation_refs: Vec::new(),
        },
        question: opts.question.clone(),
        source_bundle_handle: source.as_ref().map(|_| SOURCE_HANDLE.into()),
        source,
        anchors,
        denominator,
        policy,
        usage,
        preservation,
        invalidation_conditions: Vec::new(),
    }
}

fn base_input() -> SelfQueryInput {
    assemble(&BuildOpts::default())
}

fn statement_texts(input: &SelfQueryInput) -> Vec<String> {
    let projection = project_architecture_brief(input).expect("projection");
    projection
        .candidate
        .sections
        .iter()
        .flat_map(|section| section.statements.iter().map(|s| s.text.clone()))
        .collect()
}

// WORK_UNIT_CASE: 649/1
#[test]
fn minimal_accepted_architecture_brief_is_complete() {
    let input = base_input();
    let projection = project_architecture_brief(&input).expect("minimal brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    assert_eq!(projection.question, input.question);
    assert_eq!(projection.candidate.sections.len(), 2);
    let texts = statement_texts(&input);
    assert_eq!(texts.len(), 2);
    assert!(
        texts.contains(&"Intent: the brief preserves accepted Architecture meaning.".to_owned())
    );
    assert!(
        texts.contains(
            &"Boundary: implementation evidence never overrides Architecture.".to_owned()
        )
    );
    projection.validate().expect("projection validates");
    projection
        .validate_against(&input)
        .expect("projection binds input");
    assert_eq!(projection.projection_digest.len(), 64);
    assert_eq!(projection.candidate.output_digest.len(), 64);
    assert_eq!(
        projection.candidate.input_digest,
        input.input_digest().expect("digest")
    );
    assert!(projection.total_output_bytes > 0);
}

// WORK_UNIT_CASE: 649/2
#[test]
fn multiple_anchors_and_global_hard_boundaries_are_required() {
    let mut base = default_anchors();
    base.push(AnchorSpec {
        denom_kind: ArchitectureDependencyKind::GlobalBoundary,
        ..AnchorSpec::new(
            "arch-649-a3",
            ArchitectureAnchorClass::HardBoundary,
            ArchitectureStatementModality::Must,
            "Boundary: the global fence holds for every scope.",
        )
    });
    let opts = BuildOpts {
        anchors: base,
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("global boundary brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let invariants = projection
        .candidate
        .sections
        .iter()
        .find(|section| section.kind == ArchitectureBriefSectionKind::InvariantsAndHardBoundaries)
        .expect("invariants section");
    assert_eq!(invariants.statements.len(), 2);
    assert!(projection.candidate.frontier.is_empty());

    let hidden = BuildOpts {
        denominator_complete: false,
        extra_members: vec![(
            "den-649-mx".into(),
            "arch-649-global-hidden".into(),
            ArchitectureDependencyKind::GlobalBoundary,
            true,
        )],
        ..BuildOpts::default()
    };
    let hidden_input = assemble(&hidden);
    let hidden_projection = project_architecture_brief(&hidden_input).expect("hidden boundary");
    assert_ne!(
        hidden_projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    assert!(
        hidden_projection
            .candidate
            .frontier
            .iter()
            .any(|entry| entry.contains("arch-649-global-hidden")),
        "hidden global boundary must surface, got {:?}",
        hidden_projection.candidate.frontier
    );
    assert!(
        hidden_projection
            .candidate
            .expansion_handles
            .iter()
            .any(|handle| handle.as_str() == "arch-649-global-hidden")
    );
}

// WORK_UNIT_CASE: 649/3
#[test]
fn wrong_job_or_implementation_profile_is_rejected_without_new_jobs() {
    let mut input = base_input();
    input.profile.output_profile = SelfQueryOutputProfile::ImplementationBrief;
    input.profile.profile_digest = input.profile.compute_digest().expect("digest");
    let err = project_architecture_brief(&input).expect_err("implementation profile");
    assert_eq!(
        err,
        SelfQueryContractError::BindingMismatch {
            field: "input.profile.output_profile",
        }
    );

    let wrong_job = assemble(&BuildOpts {
        job_class: JobClass::Orientation,
        ..BuildOpts::default()
    });
    let err = project_architecture_brief(&wrong_job).expect_err("wrong job class");
    assert_eq!(
        err,
        SelfQueryContractError::BindingMismatch {
            field: "input.job.job_class",
        }
    );
    assert!(parse_job_class("other").is_err());
    assert!(parse_job_class("architecture_brief_extra").is_err());
    assert!(serde_json::from_str::<SelfQueryOutputProfile>("\"implementation_extra\"").is_err());
}

// WORK_UNIT_CASE: 649/4
#[test]
fn non_accepted_source_states_never_yield_complete() {
    for status in [
        ArchitectureSourceStatus::Draft,
        ArchitectureSourceStatus::Rejected,
        ArchitectureSourceStatus::Superseded,
        ArchitectureSourceStatus::Stale,
    ] {
        let input = assemble(&BuildOpts {
            source_status: Some(status),
            ..BuildOpts::default()
        });
        let projection = project_architecture_brief(&input).expect("non-accepted brief");
        assert_eq!(
            projection.candidate.disposition,
            ArchitectureBriefDisposition::Unsupported,
            "status {status:?} must be unsupported"
        );
        assert!(projection.candidate.sections.is_empty());
    }
    let unavailable = assemble(&BuildOpts {
        source_status: Some(ArchitectureSourceStatus::Unavailable),
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&unavailable).expect("unavailable brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::NoSource
    );
    assert!(projection.candidate.sections.is_empty());
}

// WORK_UNIT_CASE: 649/5
#[test]
fn pair_revision_and_hash_mismatches_are_rejected() {
    let mut revision = base_input();
    revision.source.as_mut().expect("source").revision = "arch-rX".into();
    assert!(project_architecture_brief(&revision).is_err());

    let mut digest = base_input();
    digest.source.as_mut().expect("source").digest = "b".repeat(64);
    assert!(project_architecture_brief(&digest).is_err());

    let mut pair_key = base_input();
    pair_key.source.as_mut().expect("source").pair.pair_key = format!("sha256:{}", "c".repeat(64));
    assert!(project_architecture_brief(&pair_key).is_err());

    let mut anchor_digest = base_input();
    anchor_digest.anchors[0].source_digest = "d".repeat(64);
    assert!(project_architecture_brief(&anchor_digest).is_err());

    let mut byte_range = base_input();
    let end = byte_range.source.as_ref().expect("source").bytes.len();
    byte_range.anchors[0].byte_end = u64::try_from(end + 100).expect("range");
    let err = project_architecture_brief(&byte_range).expect_err("byte range");
    assert!(matches!(err, SelfQueryContractError::Range { .. }));

    let mut text = base_input();
    text.anchors[0].text.push_str(" extra");
    let err = project_architecture_brief(&text).expect_err("text binding");
    assert_eq!(
        err,
        SelfQueryContractError::BindingMismatch {
            field: "anchor.text",
        }
    );
}

// WORK_UNIT_CASE: 649/6
#[test]
fn duplicate_or_same_id_changed_anchors_and_members_are_rejected() {
    let mut duplicate = base_input();
    let clone = duplicate.anchors[0].clone();
    duplicate.anchors.push(clone);
    let err = project_architecture_brief(&duplicate).expect_err("duplicate anchor");
    assert_eq!(
        err,
        SelfQueryContractError::Duplicate {
            field: "input.anchors",
        }
    );

    let mut changed = base_input();
    let mut ghost = changed.anchors[0].clone();
    ghost.byte_start = changed.anchors[1].byte_start;
    ghost.byte_end = changed.anchors[1].byte_end;
    ghost.text = changed.anchors[1].text.clone();
    changed.anchors.push(ghost);
    let err = project_architecture_brief(&changed).expect_err("same-id changed anchor");
    assert_eq!(
        err,
        SelfQueryContractError::Duplicate {
            field: "input.anchors",
        }
    );

    let mut members = base_input();
    let clone = members.denominator.members[0].clone();
    members.denominator.members.push(clone);
    members.denominator.digest = members.denominator.compute_digest().expect("member digest");
    let err = project_architecture_brief(&members).expect_err("duplicate member");
    assert_eq!(
        err,
        SelfQueryContractError::Duplicate {
            field: "denominator.members",
        }
    );
}

// WORK_UNIT_CASE: 649/7
#[test]
fn task_attempt_scope_fence_bundle_manifest_and_grounding_mismatches_fail() {
    let mut task = base_input();
    task.validated_candidate.bundle.task_id = "task-X".into();
    let err = project_architecture_brief(&task).expect_err("task binding");
    assert_eq!(
        err,
        SelfQueryContractError::BindingMismatch {
            field: "input.validated_candidate",
        }
    );

    let mut scope = base_input();
    scope.validated_candidate.bundle.scope_id = "scope-X".into();
    assert!(project_architecture_brief(&scope).is_err());

    let mut manifest = base_input();
    manifest.validated_candidate.bundle.manifest_digest = "e".repeat(64);
    assert!(project_architecture_brief(&manifest).is_err());

    let mut fence = base_input();
    fence.validated_candidate.bundle.state_fence = test_fence();
    fence.validated_candidate.bundle.job_id = "job-X".into();
    assert!(project_architecture_brief(&fence).is_err());

    let mut grounded = base_input();
    grounded.validated_candidate.grounded.draft_digest = "f".repeat(64);
    assert!(project_architecture_brief(&grounded).is_err());

    let mut attempt = base_input();
    attempt.attempt.attempt_number = 99;
    let err = project_architecture_brief(&attempt).expect_err("attempt bound");
    assert!(matches!(err, SelfQueryContractError::Bound { .. }));
}

// WORK_UNIT_CASE: 649/8
#[test]
fn direct_and_transitive_governing_anchors_resolve_in_dependency_order() {
    let chain = [
        (
            "arch-649-c1",
            vec!["arch-649-c2"],
            "Segment one requires segment two.",
        ),
        (
            "arch-649-c2",
            vec!["arch-649-c3"],
            "Segment two requires segment three.",
        ),
        ("arch-649-c3", Vec::new(), "Segment three stands alone."),
    ];
    let opts = BuildOpts {
        anchors: chain
            .iter()
            .map(|(id, deps, text)| AnchorSpec {
                deps: deps.iter().map(|dep| (*dep).into()).collect(),
                ..AnchorSpec::new(
                    id,
                    ArchitectureAnchorClass::Intent,
                    ArchitectureStatementModality::Must,
                    text,
                )
            })
            .collect(),
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("chain brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    assert_eq!(projection.candidate.sections.len(), 1);
    let order = projection.candidate.sections[0]
        .statements
        .iter()
        .map(|statement| statement.anchor_id.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(order, vec!["arch-649-c3", "arch-649-c2", "arch-649-c1"]);

    let broken = BuildOpts {
        anchors: vec![AnchorSpec {
            deps: vec!["arch-649-absent".into()],
            ..AnchorSpec::new(
                "arch-649-c1",
                ArchitectureAnchorClass::Intent,
                ArchitectureStatementModality::Must,
                "Segment one requires a missing anchor.",
            )
        }],
        denominator_complete: false,
        ..BuildOpts::default()
    };
    let broken_input = assemble(&broken);
    let broken_projection = project_architecture_brief(&broken_input).expect("broken chain");
    assert_ne!(
        broken_projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    assert!(
        broken_projection
            .candidate
            .frontier
            .iter()
            .any(|entry| entry == "missing dependency:arch-649-absent"),
        "missing transitive dependency must surface, got {:?}",
        broken_projection.candidate.frontier
    );
}

// WORK_UNIT_CASE: 649/9
#[test]
fn partial_denominator_cannot_claim_complete_coverage() {
    let input = assemble(&BuildOpts {
        denominator_complete: false,
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&input).expect("partial brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Partial
    );
    assert_eq!(projection.candidate.sections.len(), 2);
    assert!(!projection.candidate.denominator.complete);
    projection
        .validate_against(&input)
        .expect("partial brief still binds");
}

// WORK_UNIT_CASE: 649/10
#[test]
fn missing_interpretation_dependency_yields_partial_with_expansion() {
    let input = assemble(&BuildOpts {
        denominator_complete: false,
        extra_members: vec![(
            "den-649-mx".into(),
            "arch-649-absent-interp".into(),
            ArchitectureDependencyKind::Interpretation,
            true,
        )],
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&input).expect("missing dependency");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Partial
    );
    assert!(
        projection
            .candidate
            .frontier
            .iter()
            .any(|entry| entry == "missing denominator anchor:arch-649-absent-interp"),
        "missing member must surface, got {:?}",
        projection.candidate.frontier
    );
    assert!(
        projection
            .candidate
            .expansion_handles
            .iter()
            .any(|handle| handle.as_str() == "arch-649-absent-interp")
    );
}

// WORK_UNIT_CASE: 649/11
#[test]
fn every_anchor_class_is_retained_in_its_section() {
    let classes = vec![
        (
            "arch-649-k1",
            ArchitectureAnchorClass::Intent,
            "Intent text one.",
        ),
        (
            "arch-649-k2",
            ArchitectureAnchorClass::Rationale,
            "Rationale text two.",
        ),
        (
            "arch-649-k3",
            ArchitectureAnchorClass::Guarantee,
            "Guarantee text three.",
        ),
        (
            "arch-649-k4",
            ArchitectureAnchorClass::Owner,
            "Owner text four.",
        ),
        (
            "arch-649-k5",
            ArchitectureAnchorClass::NonGoal,
            "Non-goal text five.",
        ),
        (
            "arch-649-k6",
            ArchitectureAnchorClass::OpenQuestion,
            "Open question text six.",
        ),
        (
            "arch-649-k7",
            ArchitectureAnchorClass::Precedence,
            "Precedence text seven.",
        ),
        (
            "arch-649-k8",
            ArchitectureAnchorClass::FailureBehavior,
            "Failure behavior text eight.",
        ),
    ];
    let opts = BuildOpts {
        anchors: classes
            .iter()
            .map(|(id, class, text)| {
                AnchorSpec::new(id, *class, ArchitectureStatementModality::Must, text)
            })
            .collect(),
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("full class brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let kinds = projection
        .candidate
        .sections
        .iter()
        .map(|section| section.kind)
        .collect::<BTreeSet<_>>();
    for kind in [
        ArchitectureBriefSectionKind::IntentAndRationale,
        ArchitectureBriefSectionKind::InvariantsAndHardBoundaries,
        ArchitectureBriefSectionKind::OwnersAndForbiddenTransfers,
        ArchitectureBriefSectionKind::BehaviorAndFailureConditions,
        ArchitectureBriefSectionKind::NonGoalsAndOpenQuestions,
        ArchitectureBriefSectionKind::PrecedenceAndSupersession,
    ] {
        assert!(kinds.contains(&kind), "missing section {kind:?}");
    }
    let intent = projection
        .candidate
        .sections
        .iter()
        .find(|section| section.kind == ArchitectureBriefSectionKind::IntentAndRationale)
        .expect("intent section");
    assert_eq!(intent.statements.len(), 2);
    let texts = statement_texts(&input);
    assert_eq!(texts.len(), 8);
    for (_, _, text) in &classes {
        assert!(texts.contains(&(*text).to_owned()), "missing {text}");
    }
}

// WORK_UNIT_CASE: 649/12
#[test]
fn modalities_are_preserved_and_never_strengthened() {
    let modalities = [
        ArchitectureStatementModality::Must,
        ArchitectureStatementModality::May,
        ArchitectureStatementModality::Target,
        ArchitectureStatementModality::Empirical,
        ArchitectureStatementModality::Open,
    ];
    let opts = BuildOpts {
        anchors: modalities
            .iter()
            .enumerate()
            .map(|(index, modality)| {
                AnchorSpec::new(
                    &format!("arch-649-m{}", index + 1),
                    ArchitectureAnchorClass::Intent,
                    *modality,
                    &format!("Modality statement number {}.", index + 1),
                )
            })
            .collect(),
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("modality brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let section = projection
        .candidate
        .sections
        .iter()
        .find(|section| section.kind == ArchitectureBriefSectionKind::IntentAndRationale)
        .expect("intent section");
    assert_eq!(section.statements.len(), 5);
    for (statement, expected) in section.statements.iter().zip(modalities.iter()) {
        assert_eq!(statement.modality, *expected);
    }

    let unknown = BuildOpts {
        anchors: vec![AnchorSpec {
            state: ArchitectureApplicabilityState::Unknown,
            evidence: Vec::new(),
            reason: "awaiting owner ruling".into(),
            ..AnchorSpec::new(
                "arch-649-u1",
                ArchitectureAnchorClass::Intent,
                ArchitectureStatementModality::Open,
                "Unresolved statement awaiting ruling.",
            )
        }],
        denominator_complete: false,
        ..BuildOpts::default()
    };
    let unknown_input = assemble(&unknown);
    let unknown_projection = project_architecture_brief(&unknown_input).expect("unknown brief");
    assert_ne!(
        unknown_projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let gap = unknown_projection
        .candidate
        .gaps
        .iter()
        .find(|gap| gap.gap_id.as_str() == "gap:arch-649-u1")
        .expect("unknown gap");
    assert_eq!(
        gap.state,
        eliot_dreamer_contracts::ArchitectureBriefGapState::Unknown
    );
}

// WORK_UNIT_CASE: 649/13
#[test]
fn implementation_observations_cannot_override_architecture() {
    let input = assemble(&BuildOpts {
        model_statement: "Implementation removes the boundary; code is the authority.".into(),
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&input).expect("override attempt");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let texts = statement_texts(&input);
    assert!(
        texts.contains(&"Intent: the brief preserves accepted Architecture meaning.".to_owned())
    );
    assert!(
        !texts
            .iter()
            .any(|text| text.contains("code is the authority"))
    );
    assert_eq!(
        projection.model_synthesis.model.statement,
        "Implementation removes the boundary; code is the authority."
    );
    assert_eq!(
        projection.rival_models.availability,
        eliot_dreamer_architecture_brief::DataAvailability::NotRetainedByV1
    );
}

// WORK_UNIT_CASE: 649/14
#[test]
fn code_and_runtime_behavior_cannot_override_architecture() {
    let input = assemble(&BuildOpts {
        model_statement: "Runtime observation: the boundary is not enforced in builds.".into(),
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&input).expect("runtime attempt");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let texts = statement_texts(&input);
    assert!(
        !texts
            .iter()
            .any(|text| text.contains("not enforced in builds"))
    );
    assert!(
        texts.contains(
            &"Boundary: implementation evidence never overrides Architecture.".to_owned()
        )
    );
    assert_eq!(projection.candidate.usage.model_calls, 0);
    assert_eq!(projection.candidate.usage.attempts, 0);
    assert_eq!(projection.candidate.usage.wall_ms, 0);
    assert_eq!(
        projection.candidate.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    assert_eq!(projection.candidate.effect_ceiling, EffectClass::Candidate);
}

// WORK_UNIT_CASE: 649/15
#[test]
fn evidence_keeps_separate_status_with_owner_gap_mapping() {
    let mut base = default_anchors();
    base.push(AnchorSpec {
        state: ArchitectureApplicabilityState::Unknown,
        evidence: vec!["ev-649-u9".into()],
        reason: "awaiting owner ruling on scope".into(),
        ..AnchorSpec::new(
            "arch-649-u9",
            ArchitectureAnchorClass::OpenQuestion,
            ArchitectureStatementModality::Open,
            "Scope question awaiting owner ruling here.",
        )
    });
    let opts = BuildOpts {
        anchors: base,
        denominator_complete: false,
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("evidence brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Partial
    );
    let gap = projection
        .candidate
        .gaps
        .iter()
        .find(|gap| gap.gap_id.as_str() == "gap:arch-649-u9")
        .expect("owner gap");
    assert_eq!(gap.owner, "architecture-source-closure");
    assert_eq!(gap.detail, "awaiting owner ruling on scope");
    assert_eq!(
        gap.evidence_refs
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec!["ev-649-u9".to_owned()]
    );
    assert_eq!(
        projection.model_synthesis.model,
        input.validated_candidate.model
    );
    assert_eq!(
        projection.model_synthesis.grounded,
        input.validated_candidate.grounded
    );
}

// WORK_UNIT_CASE: 649/16
#[test]
fn conflicting_accepted_anchors_are_both_retained() {
    let opts = BuildOpts {
        anchors: vec![
            AnchorSpec {
                denom_kind: ArchitectureDependencyKind::HardBoundary,
                ..AnchorSpec::new(
                    "arch-649-f1",
                    ArchitectureAnchorClass::HardBoundary,
                    ArchitectureStatementModality::Must,
                    "Boundary: allow external sync.",
                )
            },
            AnchorSpec {
                denom_kind: ArchitectureDependencyKind::HardBoundary,
                ..AnchorSpec::new(
                    "arch-649-f2",
                    ArchitectureAnchorClass::HardBoundary,
                    ArchitectureStatementModality::Must,
                    "Boundary: forbid external sync.",
                )
            },
        ],
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("conflict brief");
    let texts = statement_texts(&input);
    assert!(texts.contains(&"Boundary: allow external sync.".to_owned()));
    assert!(texts.contains(&"Boundary: forbid external sync.".to_owned()));
    assert_eq!(projection.candidate.sections.len(), 1);
    assert_eq!(projection.candidate.sections[0].statements.len(), 2);
}

// WORK_UNIT_CASE: 649/17
#[test]
fn superseded_history_is_never_current_authority() {
    let superseded = assemble(&BuildOpts {
        source_status: Some(ArchitectureSourceStatus::Superseded),
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&superseded).expect("superseded brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Unsupported
    );
    assert!(projection.candidate.sections.is_empty());

    let mut lineage = base_input();
    lineage
        .source
        .as_mut()
        .expect("source")
        .supersedes
        .push(ArtifactId::new("arch-source-648").expect("old handle"));
    lineage
        .source
        .as_mut()
        .expect("source")
        .validate()
        .expect("lineage source validates");
    let current = project_architecture_brief(&lineage).expect("lineage brief");
    assert_eq!(
        current.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let texts = statement_texts(&lineage);
    assert!(
        texts.contains(&"Intent: the brief preserves accepted Architecture meaning.".to_owned())
    );
}

// WORK_UNIT_CASE: 649/18
#[test]
fn invented_unbound_statements_are_rejected() {
    let input = base_input();
    let projection = project_architecture_brief(&input).expect("base brief");
    let mut tampered = projection.clone();
    let mut ghost = tampered.candidate.sections[0].statements[0].clone();
    ghost.statement_id = ArtifactId::new("statement:arch-649-ghost").expect("ghost id");
    ghost.anchor_id = ArtifactId::new("arch-649-ghost").expect("ghost anchor");
    ghost.text = "Invented constitutional requirement.".into();
    tampered.candidate.sections[0].statements.push(ghost);
    assert!(tampered.candidate.validate().is_err());

    let anchor_ids = input
        .anchors
        .iter()
        .map(|anchor| anchor.anchor_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    for section in &projection.candidate.sections {
        for statement in &section.statements {
            assert!(anchor_ids.contains(statement.anchor_id.as_str()));
        }
    }
}

// WORK_UNIT_CASE: 649/19
#[test]
fn hidden_boundary_or_non_goal_exclusion_blocks_completeness() {
    let opts = BuildOpts {
        anchors: vec![
            AnchorSpec::new(
                "arch-649-a1",
                ArchitectureAnchorClass::Intent,
                ArchitectureStatementModality::Must,
                "Intent: the brief preserves accepted Architecture meaning.",
            ),
            AnchorSpec {
                state: ArchitectureApplicabilityState::NotApplicable,
                evidence: vec!["ev-649-a2".into()],
                reason: "out of scope for this question".into(),
                denom_kind: ArchitectureDependencyKind::HardBoundary,
                ..AnchorSpec::new(
                    "arch-649-a2",
                    ArchitectureAnchorClass::HardBoundary,
                    ArchitectureStatementModality::Must,
                    "Boundary: implementation evidence never overrides Architecture.",
                )
            },
            AnchorSpec {
                state: ArchitectureApplicabilityState::NotApplicable,
                evidence: vec!["ev-649-a3".into()],
                reason: "explicitly deferred non-goal".into(),
                ..AnchorSpec::new(
                    "arch-649-a3",
                    ArchitectureAnchorClass::NonGoal,
                    ArchitectureStatementModality::Open,
                    "Non-goal: deferred telemetry scope.",
                )
            },
        ],
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("exclusion brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Blocked
    );
    assert!(
        projection
            .candidate
            .frontier
            .iter()
            .any(|entry| entry.contains("arch-649-a2")),
        "excluded required boundary must surface, got {:?}",
        projection.candidate.frontier
    );
    let texts = statement_texts(&input);
    assert!(
        !texts.contains(
            &"Boundary: implementation evidence never overrides Architecture.".to_owned()
        )
    );
}

// WORK_UNIT_CASE: 649/20
#[test]
fn partial_output_preserves_omissions_and_expansion() {
    let input = assemble(&BuildOpts {
        denominator_complete: false,
        extra_members: vec![(
            "den-649-mx".into(),
            "arch-649-absent-exp".into(),
            ArchitectureDependencyKind::Interpretation,
            false,
        )],
        bundle_omissions: vec![(
            "gap-649-a".into(),
            "gap-a awaits a future source".into(),
            true,
            None,
        )],
        ..BuildOpts::default()
    });
    let projection = project_architecture_brief(&input).expect("omission brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Partial
    );
    let omission = projection
        .candidate
        .omissions
        .iter()
        .find(|omission| omission.handle.as_str() == "gap-649-a")
        .expect("omission retained");
    assert_eq!(omission.reason, "gap-a awaits a future source");
    assert!(omission.reversible);
    assert!(
        projection
            .candidate
            .expansion_handles
            .iter()
            .any(|handle| handle.as_str() == "arch-649-absent-exp")
    );
    assert!(!projection.candidate.frontier.is_empty());
}

// WORK_UNIT_CASE: 649/21
#[test]
fn privacy_authority_effect_and_proof_ceilings_hold() {
    let input = base_input();
    let projection = project_architecture_brief(&input).expect("ceiling brief");
    assert_eq!(projection.candidate.privacy, input.policy.privacy);
    assert_eq!(
        projection.candidate.authority_ceiling,
        input.policy.authority_ceiling
    );
    assert_eq!(projection.candidate.disclosure, input.policy.disclosure);
    assert_eq!(projection.candidate.effect_ceiling, EffectClass::Candidate);
    assert_eq!(
        projection.candidate.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );

    let mut effect = base_input();
    effect.policy.effect_ceiling = EffectClass::ExternalEffect;
    assert!(project_architecture_brief(&effect).is_err());

    let mut proof = base_input();
    proof.policy.proof_ceiling = ProofCeiling::ScopedVerification;
    assert!(project_architecture_brief(&proof).is_err());
}

// WORK_UNIT_CASE: 649/22
#[test]
fn independent_bounds_enforce_exact_fit_and_one_over() {
    let mut exact = base_input();
    exact.policy.max_items = 4;
    assert!(project_architecture_brief(&exact).is_ok());

    let mut over = base_input();
    over.policy.max_items = 3;
    let err = project_architecture_brief(&over).expect_err("one over items");
    assert!(matches!(err, SelfQueryContractError::Bound { .. }));

    let mut work = base_input();
    work.policy.max_work = 1;
    let err = project_architecture_brief(&work).expect_err("work bound");
    assert_eq!(
        err,
        SelfQueryContractError::Bound {
            field: "projection.work_units",
            maximum: 1,
            actual: 2,
        }
    );

    let mut output = base_input();
    output.policy.max_output_bytes = 8;
    assert!(project_architecture_brief(&output).is_err());

    let sized = base_input();
    let wire_len = serde_json::to_vec(&sized).expect("input wire").len();
    let mut fit = base_input();
    fit.policy.max_input_bytes = u64::try_from(wire_len).expect("wire len");
    assert!(project_architecture_brief(&fit).is_ok());
    // Margin covers the digit-width shrinkage of the mutated bound itself.
    let mut tight = base_input();
    tight.policy.max_input_bytes = u64::try_from(wire_len - 64).expect("wire len");
    let err = project_architecture_brief(&tight).expect_err("tight input bound");
    assert!(matches!(err, SelfQueryContractError::Bound { .. }));
}

// WORK_UNIT_CASE: 649/23
#[test]
fn projection_is_deterministic_with_canonical_set_order() {
    let input = base_input();
    let first = project_architecture_brief(&input).expect("first");
    let second = project_architecture_brief(&input).expect("second");
    assert_eq!(first, second);
    assert_eq!(first.projection_digest, second.projection_digest);
    let kinds = first
        .candidate
        .sections
        .iter()
        .map(|section| section.kind)
        .collect::<Vec<_>>();
    assert!(kinds.windows(2).all(|pair| pair[0] <= pair[1]));
    for section in &first.candidate.sections {
        section.validate().expect("section digest");
    }
}

// WORK_UNIT_CASE: 649/24
#[test]
fn replay_is_stable_but_changed_requests_never_reuse_digests() {
    let first = base_input();
    let replay = base_input();
    assert_eq!(
        first.input_digest().expect("digest"),
        replay.input_digest().expect("digest")
    );
    let first_projection = project_architecture_brief(&first).expect("first");
    let replay_projection = project_architecture_brief(&replay).expect("replay");
    assert_eq!(
        first_projection.candidate.candidate_id,
        replay_projection.candidate.candidate_id
    );
    assert_eq!(
        first_projection.candidate.output_digest,
        replay_projection.candidate.output_digest
    );

    let mut changed = base_input();
    changed.question = "What does the accepted Architecture forbid here?".into();
    assert_ne!(
        first.input_digest().expect("digest"),
        changed.input_digest().expect("digest")
    );
    let changed_projection = project_architecture_brief(&changed).expect("changed");
    assert_ne!(
        first_projection.candidate.candidate_id,
        changed_projection.candidate.candidate_id
    );
    assert_eq!(
        changed_projection.question,
        "What does the accepted Architecture forbid here?"
    );
}

// WORK_UNIT_CASE: 649/25
#[test]
fn seven_preservation_dimensions_and_receipt_hold_without_rerunning_validation() {
    let input = assemble(&BuildOpts {
        preservation_passing: false,
        ..BuildOpts::default()
    });
    assert!(input.preservation.overall().is_err());
    let projection = project_architecture_brief(&input).expect("failed preservation");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Partial
    );
    assert_eq!(projection.candidate.preservation, input.preservation);
    assert_eq!(projection.candidate.preservation.verdicts.len(), 7);

    let passing = base_input();
    assert!(passing.preservation.overall().is_ok());
    assert_eq!(
        project_architecture_brief(&passing)
            .expect("passing")
            .candidate
            .disposition,
        ArchitectureBriefDisposition::Complete
    );

    let mut tampered = base_input();
    tampered.validated_candidate.validated.receipt.input_digest = "a".repeat(64);
    assert!(project_architecture_brief(&tampered).is_err());
}

// WORK_UNIT_CASE: 649/26
#[test]
fn missing_accepted_source_yields_no_source_without_acceptance() {
    let opts = BuildOpts {
        source_status: None,
        anchors: Vec::new(),
        denominator_complete: false,
        ..BuildOpts::default()
    };
    let input = assemble(&opts);
    let projection = project_architecture_brief(&input).expect("absent source");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::NoSource
    );
    assert!(projection.candidate.sections.is_empty());
    projection
        .validate_against(&input)
        .expect("no-source brief still binds");

    let unavailable = assemble(&BuildOpts {
        source_status: Some(ArchitectureSourceStatus::Unavailable),
        ..BuildOpts::default()
    });
    let blocked = project_architecture_brief(&unavailable).expect("unavailable source");
    assert_eq!(
        blocked.candidate.disposition,
        ArchitectureBriefDisposition::NoSource
    );
    assert!(blocked.candidate.sections.is_empty());
}

// WORK_UNIT_CASE: 649/27
#[test]
fn malformed_and_property_inputs_are_bounded() {
    let mut empty = base_input();
    empty.question.clear();
    assert!(project_architecture_brief(&empty).is_err());

    let mut control = base_input();
    control.question = "What?\0".into();
    assert!(project_architecture_brief(&control).is_err());

    let mut version = base_input();
    version.schema_version = 2;
    assert!(project_architecture_brief(&version).is_err());

    let mut items = base_input();
    items.policy.max_items = 0;
    assert!(project_architecture_brief(&items).is_err());

    let input = base_input();
    let mut value = serde_json::to_value(&input).expect("input json");
    value
        .as_object_mut()
        .expect("input object")
        .insert("probe_649".into(), serde_json::json!(1));
    let err = serde_json::from_value::<SelfQueryInput>(value).expect_err("unknown field");
    assert!(err.to_string().contains("unknown field"));

    let projection = project_architecture_brief(&input).expect("base brief");
    let mut tampered = projection.clone();
    tampered.total_output_bytes += 1;
    assert!(tampered.validate().is_err());
}

// WORK_UNIT_CASE: 649/28
#[test]
fn every_material_statement_binds_its_accepted_source() {
    let input = base_input();
    let source = input.source.as_ref().expect("accepted source");
    let projection = project_architecture_brief(&input).expect("bound brief");
    let mut checked = 0;
    for section in &projection.candidate.sections {
        for statement in &section.statements {
            assert_eq!(
                statement.source_handle.as_str(),
                source.source_handle.as_str()
            );
            assert_eq!(statement.source_revision, source.revision);
            assert_eq!(statement.source_digest, source.digest);
            let start = usize::try_from(statement.byte_start).expect("start");
            let end = usize::try_from(statement.byte_end).expect("end");
            assert!(start < end && end <= source.bytes.len());
            let excerpt = std::str::from_utf8(&source.bytes[start..end]).expect("utf8");
            assert_eq!(excerpt, statement.text);
            checked += 1;
        }
    }
    assert_eq!(checked, 2);

    let mut tampered = projection.clone();
    tampered.candidate.sections[0].statements[0]
        .text
        .push_str(" forged");
    assert!(tampered.candidate.validate().is_err());
}

// WORK_UNIT_CASE: 649/29
#[test]
fn complete_brief_accounts_every_applicable_member() {
    let input = base_input();
    let projection = project_architecture_brief(&input).expect("accounted brief");
    assert_eq!(
        projection.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
    let applicable = input
        .anchors
        .iter()
        .filter(|anchor| {
            matches!(
                anchor.applicability.state,
                ArchitectureApplicabilityState::Applicable
                    | ArchitectureApplicabilityState::Conditional
            )
        })
        .map(|anchor| anchor.anchor_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let emitted = projection
        .candidate
        .sections
        .iter()
        .flat_map(|section| {
            section
                .statements
                .iter()
                .map(|statement| statement.anchor_id.as_str().to_owned())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(applicable, emitted);
    for member in &projection.candidate.denominator.members {
        assert!(emitted.contains(member.anchor_id.as_str()));
        assert_eq!(
            member.source_handle.as_str(),
            input
                .source
                .as_ref()
                .expect("source")
                .source_handle
                .as_str()
        );
    }
    assert_eq!(projection.candidate.usage.reference_width, 6);
    assert_eq!(projection.candidate.usage.source_width, 1);
    assert_eq!(projection.candidate.usage.candidates, 1);
    assert!(projection.candidate.frontier.is_empty());
    assert!(projection.candidate.gaps.is_empty());
}

// WORK_UNIT_CASE: 649/30
#[test]
fn projection_is_pure_with_no_acquisition_or_effect() {
    let input = base_input();
    let before = input.clone();
    let first = project_architecture_brief(&input).expect("first");
    let second = project_architecture_brief(&input).expect("second");
    assert_eq!(input, before, "projection must not mutate its input");
    assert_eq!(first, second, "projection must be a pure function");
    assert_eq!(first.candidate.usage.model_calls, 0);
    assert_eq!(first.candidate.usage.work_fan_out, 0);
    assert_eq!(first.candidate.usage.report_bytes, 0);
    assert_eq!(first.candidate.usage.stu_used, 0);
    assert_eq!(first.candidate.effect_ceiling, EffectClass::Candidate);
    assert_eq!(
        first.candidate.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    assert_eq!(
        input.source.as_ref().expect("source").bytes,
        before.source.as_ref().expect("source").bytes
    );
    assert_eq!(
        first.candidate.disposition,
        ArchitectureBriefDisposition::Complete
    );
}
