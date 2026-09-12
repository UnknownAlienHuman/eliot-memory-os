#![allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]

use eliot_conformance_contracts::{
    CONTRACT_VERSION, CapabilitySupportRow, ConformanceContractSet, ContractMaturity,
    DomainCoverage, EvidenceDomain, EvidenceExecutionStatus, ImplementationSupport,
    SupportObservationState, canonicalize_contract_set,
};
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, PolicyRevision, ReceiptId, ResourceGeneration, SourceId,
    StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::validation::{
    InputPreimage, OutputContext, PROOF_CEILING, VALIDATOR_CONTRACT, budget_digest,
    bundle_digest, input_digest_and_size, model_digest, output_digest, preservation_digest,
};
use eliot_dreamer_contracts::{
    ArchitectureAnchor, ArchitectureAnchorClass, ArchitectureApplicability,
    ArchitectureApplicabilityBasis, ArchitectureApplicabilityState, ArchitectureDependencyDenominator,
    ArchitectureDependencyKind, ArchitectureDependencyMember, ArchitectureSourceSnapshot,
    ArchitectureSourceStatus, ArchitectureStatementModality, AttemptBinding, BudgetLimits,
    BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobInput, GroundedDreamDraft, JobClass, ModelDraft, NormativePairBinding,
    PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester,
    RequesterOrigin, SelfQueryInput, SelfQueryOutputProfile, SelfQueryPolicy, SelfQueryProfile,
    SourceDisposition, SupportState, ValidatedCandidate, ValidatedDreamDraft, ValidationPolicy,
    ValidationReceipt,
};
use eliot_dreamer_implementation_brief::{
    ArchitectureAlignment, CurrentEvidenceTarget, EvidenceVerdict, ImplementationBriefInput,
    ImplementationDenominator, ImplementationEvidence, ImplementationMechanism,
    ImplementationObligation, ImplementationSourceSnapshot, ImplementationSourceStatus,
    ImplementationStatement, ImplementationStatementKind, ProofStage,
    IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
};
use eliot_epistemic_contracts::{DisclosureClass, PositionAssertability, PrivacyHandling};
use eliot_receipts::{EffectClass, ProofCeiling};

pub fn fixture() -> ImplementationBriefInput {
    let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    let architecture_bytes = b"Kernel validates mechanically; Governor owns semantic admission.".to_vec();
    let implementation_bytes = b"Use one named transition validator under the current State Fence.".to_vec();
    let architecture_digest = sha256_hex(&architecture_bytes);
    let implementation_digest = sha256_hex(&implementation_bytes);
    let accepted_by = SourceId::new("normative-owner").expect("source id");
    let acceptance_receipt = ReceiptId::new("normative-receipt").expect("receipt id");
    let pair = pair(
        architecture_digest.clone(),
        implementation_digest.clone(),
        accepted_by.clone(),
        acceptance_receipt.clone(),
    );
    let architecture_handle = ArtifactId::new("architecture-source").expect("artifact id");
    let architecture_source = ArchitectureSourceSnapshot {
        schema_version: 1,
        source_handle: architecture_handle.clone(),
        owner: accepted_by.clone(),
        revision: "architecture-r1".to_owned(),
        digest: architecture_digest.clone(),
        status: ArchitectureSourceStatus::Accepted,
        pair: pair.clone(),
        acceptance_receipt: Some(acceptance_receipt.clone()),
        bytes: architecture_bytes.clone(),
        supersedes: Vec::new(),
        invalidation: Vec::new(),
    };
    architecture_source.validate().expect("architecture source");
    let architecture_anchor = ArchitectureAnchor {
        schema_version: 1,
        anchor_id: ArtifactId::new("arch-1").expect("anchor id"),
        source_handle: architecture_handle.clone(),
        revision: "architecture-r1".to_owned(),
        source_digest: architecture_digest.clone(),
        byte_start: 0,
        byte_end: architecture_bytes.len() as u64,
        class: ArchitectureAnchorClass::HardBoundary,
        modality: ArchitectureStatementModality::Must,
        text: String::from_utf8(architecture_bytes.clone()).expect("utf8"),
        applicability: ArchitectureApplicability {
            state: ArchitectureApplicabilityState::Applicable,
            basis: ArchitectureApplicabilityBasis::Structural,
            evidence_refs: vec![ArtifactId::new("arch-evidence-1").expect("evidence id")],
            reason: "the question addresses this exact runtime boundary".to_owned(),
        },
        dependency_refs: Vec::new(),
    };
    architecture_anchor
        .validate_against(&architecture_source)
        .expect("anchor");
    let mut architecture_denominator = ArchitectureDependencyDenominator {
        schema_version: 1,
        denominator_id: ArtifactId::new("architecture-denominator").expect("denominator id"),
        members: vec![ArchitectureDependencyMember {
            member_id: ArtifactId::new("architecture-member-1").expect("member id"),
            anchor_id: architecture_anchor.anchor_id.clone(),
            source_handle: architecture_handle.clone(),
            kind: ArchitectureDependencyKind::HardBoundary,
            required: true,
        }],
        complete: true,
        digest: String::new(),
    };
    architecture_denominator.digest = architecture_denominator
        .compute_digest()
        .expect("architecture denominator digest");
    architecture_denominator
        .validate()
        .expect("architecture denominator");

    let job = DreamJobInput {
        schema_version: 1,
        job_class: JobClass::ArchitectureSelfQuery,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "operation-651".to_owned(),
        idempotency_key: "idempotency-651".to_owned(),
        task_id: "task-651".to_owned(),
        scope_id: "scope-651".to_owned(),
        state_fence: fence.clone(),
        privacy_profile: "local-only".to_owned(),
        contract_ref: "self-query-contract-v1".to_owned(),
        policy_ref: "validator-651".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(4 * 1024 * 1024),
            output_bytes: Some(4 * 1024 * 1024),
            source_width: Some(64),
            reference_width: Some(64),
            model_calls: Some(1),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(60_000),
            work_fan_out: Some(64),
            report_bytes: Some(4 * 1024 * 1024),
            max_stu: Some(100),
        },
        deadline_ms: None,
        frozen_manifest_digest: sha256_hex(b"manifest-651"),
    };
    let job_id = job.canonical_id();
    let mut bundle = DreamInputBundle {
        schema_version: 1,
        job_id: job_id.clone(),
        scope_id: job.scope_id.clone(),
        task_id: job.task_id.clone(),
        state_fence: fence.clone(),
        manifest_digest: job.frozen_manifest_digest.clone(),
        materials: vec![BundleMaterial {
            handle: architecture_handle.as_str().to_owned(),
            disposition: SourceDisposition::Required,
            bytes: architecture_bytes.len() as u64,
            digest: architecture_digest.clone(),
        }],
        omissions: Vec::new(),
        completeness: BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("architecture-denominator".to_owned()),
    };
    let model = ModelDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        statement: "Implementation must remain subordinate to Architecture.".to_owned(),
        source_handles: vec![architecture_handle.as_str().to_owned()],
        counterevidence: vec!["current runtime evidence remains separately evaluated".to_owned()],
        uncertainty: "runtime and Product evidence may be absent".to_owned(),
        expected_benefit: "produce an exact candidate Implementation brief".to_owned(),
        recommended_probes: vec!["evaluate the declared obligation".to_owned()],
        invalidation_conditions: vec!["accepted normative pair changes".to_owned()],
        declared_confirmed_handles: Vec::new(),
    };
    let draft_digest = model_digest(&model).expect("model digest");
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        residues: vec![ClaimResidue {
            claim: model.statement.clone(),
            state: SupportState::Supported,
            detail: "retained as a candidate-only grounded statement".to_owned(),
        }],
        coverage_note: "one exact Architecture source is accounted".to_owned(),
    };
    let mut validation_policy = ValidationPolicy::new("validator-651", 1, 4 * 1024 * 1024);
    validation_policy.seal().expect("validation policy");
    let usage = BudgetUsage {
        input_bytes: 4096,
        output_bytes: 4096,
        source_width: 1,
        reference_width: 1,
        candidates: 1,
        report_bytes: 4096,
        stu_used: 1,
        ..BudgetUsage::default()
    };
    let preservation = PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(|name| eliot_dreamer_contracts::candidate::DimensionVerdict {
                dimension: PreservationDimension::parse(name).expect("dimension"),
                passed: true,
                known: true,
                note: format!("{name} retained"),
            })
            .collect(),
    };
    let bundle_hash = bundle_digest(&bundle).expect("bundle digest");
    let (input_hash, _) = input_digest_and_size(&InputPreimage {
        job: &job,
        bundle: &bundle,
        model: &model,
        grounded: &grounded,
        policy: &validation_policy,
        usage,
        preservation: &preservation,
        observation_time_ms: None,
        cancellation_requested: false,
    })
    .expect("input digest");
    let (output_hash, _) = output_digest(&OutputContext {
        job: &job,
        bundle: &bundle,
        model: &model,
        grounded: &grounded,
        preservation: &preservation,
        policy: &validation_policy,
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
        validator_contract: VALIDATOR_CONTRACT.to_owned(),
        validator_policy: validation_policy.policy_id.clone(),
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        bundle_digest: bundle_hash,
        manifest_digest: bundle.manifest_digest.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        input_digest: input_hash,
        output_digest: output_hash,
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: PROOF_CEILING.to_owned(),
        state_fence: fence.clone(),
        preservation_digest: preservation_digest(&preservation).expect("preservation digest"),
        budget_digest: budget_digest(&job, &usage).expect("budget digest"),
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest,
        scope_id: job.scope_id.clone(),
        task_id: job.task_id.clone(),
        state_fence: fence.clone(),
    };
    let candidate = ValidatedCandidate {
        job: job.clone(),
        bundle: bundle.clone(),
        model,
        grounded,
        preservation: preservation.clone(),
        usage,
        policy: validation_policy,
        observation_time_ms: None,
        cancellation_requested: false,
        validated,
    };
    candidate.validate_binding().expect("candidate binding");

    let mut profile = SelfQueryProfile {
        schema_version: 1,
        job_class: JobClass::ArchitectureSelfQuery,
        output_profile: SelfQueryOutputProfile::ImplementationBrief,
        profile_id: "implementation-brief-v1".to_owned(),
        profile_digest: String::new(),
    };
    profile.profile_digest = profile.compute_digest().expect("profile digest");
    let self_query = SelfQueryInput {
        schema_version: 1,
        validated_candidate: candidate,
        profile,
        attempt: AttemptBinding {
            attempt_id: "attempt-651-1".to_owned(),
            attempt_number: 1,
            maximum_attempts: 2,
            predecessor: None,
            invalidation_refs: Vec::new(),
        },
        question: "What is currently implemented for the governed transition boundary?".to_owned(),
        source_bundle_handle: Some(architecture_handle.as_str().to_owned()),
        source: Some(architecture_source),
        anchors: vec![architecture_anchor],
        denominator: architecture_denominator,
        policy: SelfQueryPolicy {
            schema_version: 1,
            policy_id: "validator-651".to_owned(),
            policy_revision: PolicyRevision::new(1).expect("policy revision"),
            privacy: PrivacyHandling::Unrestricted,
            disclosure: DisclosureClass::Open,
            authority_ceiling: PositionAssertability::PlanningOnly,
            effect_ceiling: EffectClass::Candidate,
            proof_ceiling: ProofCeiling::CandidateArtifact,
            max_items: 4096,
            max_reference_width: 64,
            max_input_bytes: 4 * 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            max_stu: 100,
            max_work: 4096,
            now_ms: None,
            deadline_ms: None,
            cancellation_requested: false,
        },
        usage,
        preservation,
        invalidation_conditions: vec!["accepted normative pair changes".to_owned()],
    };
    self_query.validate().expect("self query");

    let mut statement = ImplementationStatement {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        statement_id: "statement-1".to_owned(),
        mechanism_id: "mechanism-1".to_owned(),
        kind: ImplementationStatementKind::Mechanism,
        source_handle: "implementation-source".to_owned(),
        source_revision: "implementation-r1".to_owned(),
        source_digest: implementation_digest.clone(),
        architecture_refs: vec!["arch-1".to_owned()],
        dependency_refs: Vec::new(),
        alignment: ArchitectureAlignment::Compatible,
        text: String::from_utf8(implementation_bytes).expect("implementation utf8"),
        statement_digest: String::new(),
    };
    statement.seal().expect("statement");
    let mut implementation_source = ImplementationSourceSnapshot {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        source_handle: "implementation-source".to_owned(),
        owner: accepted_by.as_str().to_owned(),
        revision: "implementation-r1".to_owned(),
        source_digest: implementation_digest,
        status: ImplementationSourceStatus::Accepted,
        acceptance_receipt: Some(acceptance_receipt.as_str().to_owned()),
        complete: true,
        statements: vec![statement],
        supersedes: Vec::new(),
        invalidation_refs: Vec::new(),
        snapshot_digest: String::new(),
    };
    implementation_source.seal().expect("implementation source");

    let mut mechanism = ImplementationMechanism {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        mechanism_id: "mechanism-1".to_owned(),
        owner: "governor-transition-owner".to_owned(),
        description: "one named transition validator under the current State Fence".to_owned(),
        architecture_refs: vec!["arch-1".to_owned()],
        statement_refs: vec!["statement-1".to_owned()],
        dependency_refs: Vec::new(),
        obligation_refs: vec!["obligation-1".to_owned()],
        contract_refs: vec!["implementation-contract-v1".to_owned()],
        mechanism_digest: String::new(),
    };
    mechanism.seal().expect("mechanism");
    let mut obligation = ImplementationObligation {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        obligation_id: "obligation-1".to_owned(),
        mechanism_id: "mechanism-1".to_owned(),
        owner: "governor-transition-owner".to_owned(),
        description: "source must prove the exact transition implementation".to_owned(),
        required_stages: vec![ProofStage::Source],
        required_domains: vec![EvidenceDomain::Source],
        architecture_refs: vec!["arch-1".to_owned()],
        statement_refs: vec!["statement-1".to_owned()],
        obligation_digest: String::new(),
    };
    obligation.seal().expect("obligation");

    let evaluated_at_ms = 100;
    let conformance = canonicalize_contract_set(ConformanceContractSet {
        contract_version: CONTRACT_VERSION,
        evaluated_at_ms,
        domain_coverage: EvidenceDomain::ALL
            .iter()
            .copied()
            .map(|domain| {
                if domain == EvidenceDomain::Source {
                    DomainCoverage {
                        contract_version: CONTRACT_VERSION,
                        domain,
                        state: SupportObservationState::Observed,
                        source_handles: vec!["implementation-source".to_owned()],
                        evidence_refs: vec!["source-evidence-1".to_owned()],
                        blind_boundaries: Vec::new(),
                        observed_at_ms: Some(90),
                        expires_at_ms: Some(200),
                        invalidation_set: vec!["source-tree".to_owned()],
                    }
                } else {
                    DomainCoverage {
                        contract_version: CONTRACT_VERSION,
                        domain,
                        state: SupportObservationState::Unknown,
                        source_handles: Vec::new(),
                        evidence_refs: Vec::new(),
                        blind_boundaries: Vec::new(),
                        observed_at_ms: None,
                        expires_at_ms: None,
                        invalidation_set: Vec::new(),
                    }
                }
            })
            .collect(),
        support_rows: vec![CapabilitySupportRow {
            contract_version: CONTRACT_VERSION,
            contract_ref: "implementation-contract-v1".to_owned(),
            support_claim_ref: "support-claim-1".to_owned(),
            scope_ref: job.scope_id.clone(),
            claim_domain: Some(EvidenceDomain::Source),
            required_dependency_domains: vec![EvidenceDomain::Source],
            support_observation_state: SupportObservationState::Observed,
            contract_maturity: ContractMaturity::Stable,
            implementation_support: ImplementationSupport::CurrentVerified,
            evidence_execution_status: EvidenceExecutionStatus::Executed,
            proof_profile_ref: Some("source-proof-v1".to_owned()),
            source_handles: vec!["implementation-source".to_owned()],
            evidence_refs: vec!["source-evidence-1".to_owned()],
            blind_boundaries: Vec::new(),
            invalidation_set: vec!["source-tree".to_owned()],
            compatibility_rule_ref: None,
            not_applicable_reason_ref: None,
            evaluated_at_ms,
        }],
    })
    .expect("conformance");

    let mut target = CurrentEvidenceTarget {
        source_tree_digest: sha256_hex(b"source-tree-651"),
        artifact_digest: None,
        configuration_digest: None,
        platform: "source".to_owned(),
        toolchain: "rust-source-inspection".to_owned(),
        features: vec!["default".to_owned()],
        environment_digest: sha256_hex(b"environment-651"),
        observation_window_ref: "observation-window-651".to_owned(),
        target_digest: String::new(),
    };
    target.seal().expect("target");
    let mut evidence = ImplementationEvidence {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        evidence_id: "evidence-1".to_owned(),
        mechanism_id: "mechanism-1".to_owned(),
        obligation_id: "obligation-1".to_owned(),
        stage: ProofStage::Source,
        support_claim_ref: "support-claim-1".to_owned(),
        target,
        verdict: EvidenceVerdict::Passed,
        detail: "the exact source mechanism is present and validated".to_owned(),
        evidence_digest: String::new(),
    };
    evidence.seal().expect("evidence");
    let mut denominator = ImplementationDenominator {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        denominator_id: "implementation-denominator-1".to_owned(),
        mechanism_ids: vec!["mechanism-1".to_owned()],
        obligation_ids: vec!["obligation-1".to_owned()],
        evidence_ids: vec!["evidence-1".to_owned()],
        complete: true,
        denominator_digest: String::new(),
    };
    denominator.seal().expect("implementation denominator");

    let mut input = ImplementationBriefInput {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        self_query,
        implementation_source: Some(implementation_source),
        mechanisms: vec![mechanism],
        obligations: vec![obligation],
        evidence: vec![evidence],
        conformance,
        denominator,
        invalidation_conditions: vec!["source or evidence identity changes".to_owned()],
        input_digest: String::new(),
    };
    input.seal().expect("implementation input");
    input
}

pub fn reseal(input: &mut ImplementationBriefInput) {
    input.input_digest.clear();
    input.seal().expect("reseal implementation input");
}

pub fn set_single_stage(input: &mut ImplementationBriefInput, stage: ProofStage) {
    input.obligations[0].required_stages = vec![stage];
    input.evidence[0].stage = stage;
    reseal(input);
}

fn pair(
    architecture_digest: String,
    implementation_digest: String,
    accepted_by: SourceId,
    acceptance_receipt: ReceiptId,
) -> NormativePairBinding {
    let mut preimage = b"eliot-normative-pair-v1\0".to_vec();
    preimage.extend_from_slice(architecture_digest.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(implementation_digest.as_bytes());
    preimage.push(0);
    NormativePairBinding {
        architecture_digest,
        implementation_digest,
        pair_key: format!("sha256:{}", sha256_hex(&preimage)),
        document_set: "accepted-normative-pair".to_owned(),
        architecture_revision: "architecture-r1".to_owned(),
        implementation_revision: "implementation-r1".to_owned(),
        accepted_by,
        acceptance_receipt,
    }
}
