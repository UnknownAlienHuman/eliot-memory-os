#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_contracts::{
    AuthorityEpoch, ReceiptId, ResourceGeneration, SourceId, StateFence, canonical_json_bytes,
    sha256_hex,
};
use eliot_dreamer_contracts::validation::{
    InputPreimage, OutputContext, PROOF_CEILING, VALIDATOR_CONTRACT, budget_digest, bundle_digest,
    input_digest_and_size, model_digest, output_digest, preservation_digest,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobInput, GroundedDreamDraft, JobClass, ModelDraft, PRESERVATION_DIMENSIONS,
    PreservationDimension, PreservationReport, Requester, RequesterOrigin, SourceDisposition,
    SupportState, ValidatedCandidate, ValidatedDreamDraft, ValidationPolicy, ValidationReceipt,
};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, CanonicalEvidenceHandle, CoverageCepMember, CoverageEvidenceMember,
    CurrentEpistemicPositionHandle, LocalOrientationFrame, OrientationCoverageDenominator,
    OrientationDisposition, OrientationPolicy, project_orientation,
};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
    PositionId, PositionRevision,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};

fn fixture(
    partial: bool,
) -> (
    AdmittedOrientationJob,
    DreamInputBundle,
    ValidatedCandidate,
    OrientationPolicy,
    Vec<CurrentEpistemicPositionHandle>,
) {
    let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    let job = DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Orientation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".into(),
            session: None,
        },
        operation_id: "op-1".into(),
        idempotency_key: "idem-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence.clone(),
        privacy_profile: "local_only".into(),
        contract_ref: "contract-1".into(),
        policy_ref: "validator-1".into(),
        budget: BudgetLimits {
            input_bytes: Some(1_048_576),
            output_bytes: Some(1_048_576),
            source_width: Some(8),
            reference_width: Some(8),
            model_calls: Some(1),
            attempts: Some(1),
            candidates: Some(1),
            wall_ms: Some(1_000),
            work_fan_out: Some(1),
            report_bytes: Some(1_048_576),
            max_stu: Some(100),
        },
        deadline_ms: None,
        frozen_manifest_digest: sha256_hex(b"manifest-1"),
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
            handle: "frame".into(),
            disposition: SourceDisposition::Required,
            bytes: 1,
            digest: sha256_hex(b"placeholder"),
        }],
        omissions: vec![],
        completeness: if partial {
            BundleCompleteness::PartialForScope
        } else {
            BundleCompleteness::CompleteForScope
        },
        authoritative_denominator: (!partial).then_some("denom-1".into()),
    };
    let frame = LocalOrientationFrame::new(
        "What is known?",
        "bound goal",
        vec!["stay local".into()],
        "attempt-1",
        "DreamPacket",
        "frame",
        &job,
    )
    .expect("frame shape");
    bundle.materials[0].bytes = frame.body_bytes;
    bundle.materials[0].digest = frame.body_digest.clone();
    let receipt = AdmittedReceipt::new(AdmittedReceiptParams {
        receipt_id: ReceiptId::new("receipt-628").unwrap(),
        payload_digest: sha256_hex(b"payload-628"),
        owner: SourceId::new("source-628").unwrap(),
        revision: "r1".into(),
        scope: job.scope_id.clone(),
        fence: fence.clone(),
        evidence_digest: sha256_hex(b"evidence-628"),
        coverage_digest: sha256_hex(b"coverage-628"),
        conflict_digest: sha256_hex(b"conflict-628"),
        proof_digest: sha256_hex(b"proof-628"),
        position: PositionId::new("position-628").unwrap(),
        position_revision: PositionRevision::genesis(),
    })
    .unwrap();
    let cep = CurrentEpistemicPosition::new(
        receipt,
        Currentness::Current,
        BTreeSet::new(),
        ClaimId::new("claim-628").unwrap(),
    )
    .unwrap();
    let cep_bytes = canonical_json_bytes(&cep).unwrap();
    bundle.materials.push(BundleMaterial {
        handle: "cep".into(),
        disposition: SourceDisposition::Required,
        bytes: cep_bytes.len() as u64,
        digest: sha256_hex(&cep_bytes),
    });
    let receipt2 = AdmittedReceipt::new(AdmittedReceiptParams {
        receipt_id: ReceiptId::new("receipt-629").unwrap(),
        payload_digest: sha256_hex(b"payload-629"),
        owner: SourceId::new("source-629").unwrap(),
        revision: "r1".into(),
        scope: job.scope_id.clone(),
        fence: fence.clone(),
        evidence_digest: sha256_hex(b"evidence-629"),
        coverage_digest: sha256_hex(b"coverage-629"),
        conflict_digest: sha256_hex(b"conflict-629"),
        proof_digest: sha256_hex(b"proof-629"),
        position: PositionId::new("position-629").unwrap(),
        position_revision: PositionRevision::genesis(),
    })
    .unwrap();
    let cep2 = CurrentEpistemicPosition::new(
        receipt2,
        Currentness::Current,
        BTreeSet::new(),
        ClaimId::new("claim-629").unwrap(),
    )
    .unwrap();
    let cep2_bytes = canonical_json_bytes(&cep2).unwrap();
    bundle.materials.push(BundleMaterial {
        handle: "cep-2".into(),
        disposition: SourceDisposition::Required,
        bytes: cep2_bytes.len() as u64,
        digest: sha256_hex(&cep2_bytes),
    });
    let envelope = EvidenceEnvelope {
        authority: EvidenceAuthority::SourceIdentity,
        freshness: EvidenceFreshness::ExactCandidate,
        coverage: EvidenceCoverage::CompleteForScope,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        provenance: Provenance {
            source_id: SourceId::new("source-628").unwrap(),
            capture_route: "orientation-fixture".into(),
            scope: job.scope_id.clone(),
            raw_handle: Some("raw:orientation:628".into()),
            revision: Some("r1".into()),
        },
        verification: None,
        state_fence: fence.clone(),
    };
    let envelope_bytes = canonical_json_bytes(&envelope).unwrap();
    bundle.materials.push(BundleMaterial {
        handle: "evidence".into(),
        disposition: SourceDisposition::Required,
        bytes: envelope_bytes.len() as u64,
        digest: sha256_hex(&envelope_bytes),
    });
    let mut envelope2 = envelope.clone();
    envelope2.provenance.raw_handle = Some("raw:orientation:629".into());
    let envelope2_bytes = canonical_json_bytes(&envelope2).unwrap();
    bundle.materials.push(BundleMaterial {
        handle: "evidence-2".into(),
        disposition: SourceDisposition::Required,
        bytes: envelope2_bytes.len() as u64,
        digest: sha256_hex(&envelope2_bytes),
    });
    let coverage_denominator = if partial {
        None
    } else {
        let mut denominator = OrientationCoverageDenominator {
            source_handle: "denominator".into(),
            operation_id: job.operation_id.clone(),
            idempotency_key: job.idempotency_key.clone(),
            task_id: job.task_id.clone(),
            scope_id: job.scope_id.clone(),
            state_fence: fence.clone(),
            frame_source_handle: "frame".into(),
            cep_members: vec![
                CoverageCepMember {
                    source_handle: "cep".into(),
                    position_id: PositionId::new("position-628").unwrap(),
                    position_revision: PositionRevision::genesis(),
                    canonical_view_digest: cep.digest.clone(),
                },
                CoverageCepMember {
                    source_handle: "cep-2".into(),
                    position_id: PositionId::new("position-629").unwrap(),
                    position_revision: PositionRevision::genesis(),
                    canonical_view_digest: cep2.digest.clone(),
                },
            ],
            evidence_members: vec![
                CoverageEvidenceMember {
                    source_handle: "evidence".into(),
                    canonical_envelope_digest: sha256_hex(&envelope_bytes),
                },
                CoverageEvidenceMember {
                    source_handle: "evidence-2".into(),
                    canonical_envelope_digest: sha256_hex(&envelope2_bytes),
                },
            ],
            known_empty_sections: vec![
                "architecture_implications".into(),
                "relation_candidates".into(),
                "safe_external_handoff".into(),
            ],
            body_bytes: 0,
            body_digest: String::new(),
        };
        denominator.seal().unwrap();
        bundle.materials.push(BundleMaterial {
            handle: "denominator".into(),
            disposition: SourceDisposition::Required,
            bytes: denominator.body_bytes,
            digest: denominator.body_digest.clone(),
        });
        Some(denominator)
    };
    let model = ModelDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        statement: "A bounded hypothesis".into(),
        source_handles: vec!["frame".into()],
        counterevidence: vec!["coverage is limited".into()],
        uncertainty: "unknown".into(),
        expected_benefit: "choose a useful next read".into(),
        recommended_probes: vec!["inspect the outcome".into()],
        invalidation_conditions: vec!["new evidence differs".into()],
        declared_confirmed_handles: vec![],
    };
    let draft_digest = model_digest(&model).expect("model digest");
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        residues: vec![ClaimResidue {
            claim: "A bounded hypothesis".into(),
            state: SupportState::Supported,
            detail: "retained as model grounding".into(),
        }],
        coverage_note: "one accounted residue".into(),
    };
    let mut validator_policy = ValidationPolicy::new("validator-1", 1, 1_048_576);
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
    let preservation = PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(
                |name| eliot_dreamer_contracts::candidate::DimensionVerdict {
                    dimension: PreservationDimension::parse(name).expect("dimension"),
                    passed: true,
                    known: true,
                    note: format!("{name} retained"),
                },
            )
            .collect(),
    };
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
        validator_policy: validator_policy.policy_id.clone(),
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        bundle_digest: bundle_hash,
        manifest_digest: bundle.manifest_digest.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        input_digest: input_hash,
        output_digest: output_hash,
        terminal_disposition: "accepted".into(),
        proof_ceiling: PROOF_CEILING.into(),
        state_fence: fence.clone(),
        preservation_digest: preservation_digest(&preservation).expect("preservation digest"),
        budget_digest: budget_digest(&job, &usage).expect("budget digest"),
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest,
        scope_id: job.scope_id.clone(),
        task_id: job.task_id.clone(),
        state_fence: fence,
    };
    let candidate = ValidatedCandidate {
        job: job.clone(),
        bundle: bundle.clone(),
        model,
        grounded,
        preservation,
        usage,
        policy: validator_policy,
        observation_time_ms: None,
        cancellation_requested: false,
        validated,
    };
    let mut orientation_policy = OrientationPolicy::new("orientation-1", 1, 1_048_576);
    orientation_policy.seal().expect("orientation policy");
    candidate.validate_binding().expect("candidate binding");
    let admitted = AdmittedOrientationJob {
        job,
        frame,
        admitted_evidence: vec![
            CanonicalEvidenceHandle {
                source_handle: "evidence".into(),
                envelope,
            },
            CanonicalEvidenceHandle {
                source_handle: "evidence-2".into(),
                envelope: envelope2,
            },
        ],
        coverage_denominator,
    };
    let cep_handle = CurrentEpistemicPositionHandle {
        source_handle: "cep".into(),
        position: cep,
    };
    let cep_handle2 = CurrentEpistemicPositionHandle {
        source_handle: "cep-2".into(),
        position: cep2,
    };
    (
        admitted,
        bundle,
        candidate,
        orientation_policy,
        vec![cep_handle, cep_handle2],
    )
}

#[test]
fn projects_minimal_complete_packet() {
    let (job, bundle, candidate, policy, handles) = fixture(false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    assert_eq!(packet.sections.len(), 11);
    assert_eq!(packet.model_draft, candidate.model);
    assert_eq!(packet.grounded_draft, candidate.grounded);
    let mut permuted_job = job.clone();
    permuted_job.admitted_evidence.reverse();
    let mut permuted_handles = handles.clone();
    permuted_handles.reverse();
    let replay = project_orientation(
        &permuted_job,
        &bundle,
        &candidate,
        &permuted_handles,
        &policy,
    )
    .expect("permuted projection");
    assert_eq!(packet, replay);
    packet
        .validate_against(&job, &bundle, &candidate, &handles, &policy)
        .expect("input rebinding");
}

#[test]
fn preserves_model_and_grounding_without_promoting_residue_to_evidence() {
    let (job, bundle, candidate, policy, handles) = fixture(false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.anchored_evidence_by_status.len(), 2);
    assert_eq!(
        packet.anchored_evidence_by_status[0].envelope,
        job.admitted_evidence[0].envelope
    );
    assert_eq!(
        packet.anchored_evidence_by_status[1].envelope,
        job.admitted_evidence[1].envelope
    );
    assert_eq!(
        packet.synthesized_interpretations[0].statement,
        candidate.model.statement
    );
    assert_eq!(
        packet.recommended_probes_or_next_actions[0].status,
        "model_recommendation_inert"
    );
}

#[test]
fn rejects_wrong_job_class() {
    let (mut job, bundle, candidate, policy, handles) = fixture(false);
    job.job.job_class = JobClass::Curation;
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &policy).is_err());
}

#[test]
fn frame_question_is_bound_to_material_body() {
    let (mut job, bundle, candidate, policy, handles) = fixture(false);
    job.frame.question = "different question".into();
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &policy).is_err());
}

#[test]
fn partial_bundle_remains_explicit_and_replay_is_stable() {
    let (job, bundle, candidate, policy, handles) = fixture(true);
    let first = project_orientation(&job, &bundle, &candidate, &handles, &policy)
        .expect("partial projection");
    let second = project_orientation(&job, &bundle, &candidate, &handles, &policy)
        .expect("replay projection");
    assert_eq!(first, second);
    assert_eq!(first.disposition, OrientationDisposition::Partial);
}
