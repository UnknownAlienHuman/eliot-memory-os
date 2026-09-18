#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::relation::RelationPreservationDimension;
use eliot_dreamer_contracts::validation::{
    InputPreimage, OutputContext, PROOF_CEILING, VALIDATOR_CONTRACT, budget_digest, bundle_digest,
    input_digest_and_size, model_digest, output_digest, preservation_digest,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobAdmission, GroundedDreamDraft, JobClass, ModelDraft, OmissionHandle,
    PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester, RequesterOrigin,
    SourceDisposition, SupportState, ValidatedCandidate, ValidatedDreamDraft, ValidationPolicy,
    ValidationReceipt,
};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, CanonicalEvidenceHandle, CoverageCepMember, CoverageEvidenceMember,
    CurrentEpistemicPositionHandle, LocalOrientationFrame, OrientationCoverageDenominator,
    OrientationDisposition, OrientationError, OrientationPacketCandidate, OrientationPolicy,
    OrientationResidue, project_orientation,
};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
    PositionId, PositionRevision,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};
use std::num::NonZeroU64;

// Issue #628 proof matrix: `WORK_UNIT_CASE 628/1..37` — one substantive
// `project_orientation` case per marker. The five original tests keep their
// assertions (three strengthened with sibling-class/sibling-binding coverage)
// while the remaining markers close the deferred 37-case matrix.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
struct FixtureOptions {
    requester_origin: RequesterOrigin,
    requester_session: Option<String>,
    privacy_profile: String,
    evidence2_status: EpistemicStatus,
    evidence2_freshness: EvidenceFreshness,
    cep2_superseded: bool,
    counterevidence: Vec<String>,
    recommended_probes: Vec<String>,
    residue_state: SupportState,
    declared_confirmed_handles: Vec<String>,
    extra_model_source: Option<String>,
    extra_omissions: bool,
    partial: bool,
    nonrecoverable_omission: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            requester_origin: RequesterOrigin::Human,
            requester_session: None,
            privacy_profile: "local_only".into(),
            evidence2_status: EpistemicStatus::Observed,
            evidence2_freshness: EvidenceFreshness::ExactCandidate,
            cep2_superseded: false,
            counterevidence: vec!["coverage is limited".into()],
            recommended_probes: vec!["inspect the outcome".into()],
            residue_state: SupportState::Supported,
            declared_confirmed_handles: Vec::new(),
            extra_model_source: None,
            extra_omissions: false,
            partial: false,
            nonrecoverable_omission: false,
        }
    }
}

fn assemble(
    options: &FixtureOptions,
) -> (
    AdmittedOrientationJob,
    DreamInputBundle,
    ValidatedCandidate,
    OrientationPolicy,
    Vec<CurrentEpistemicPositionHandle>,
) {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    let fence = StateFence::new(epoch, ResourceGeneration::genesis());
    let job = DreamJobAdmission {
        schema_version: 1,
        job_class: JobClass::Orientation,
        requester: Requester {
            origin: options.requester_origin,
            principal: "alice".into(),
            session: options.requester_session.clone(),
        },
        operation_id: "op-1".into(),
        idempotency_key: "idem-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence.clone(),
        privacy_profile: options.privacy_profile.clone(),
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
        completeness: if options.partial {
            BundleCompleteness::PartialForScope
        } else {
            BundleCompleteness::CompleteForScope
        },
        authoritative_denominator: (!options.partial).then_some("denom-1".into()),
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
    let (cep2_currentness, cep2_supersession) = if options.cep2_superseded {
        (
            Currentness::Superseded,
            BTreeSet::from(
                [ArtifactId::new("artifact-628-supersedes").expect("supersession link")],
            ),
        )
    } else {
        (Currentness::Current, BTreeSet::new())
    };
    let cep2 = CurrentEpistemicPosition::new(
        receipt2,
        cep2_currentness,
        cep2_supersession,
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
    envelope2.status = options.evidence2_status;
    envelope2.freshness = options.evidence2_freshness;
    let envelope2_bytes = canonical_json_bytes(&envelope2).unwrap();
    bundle.materials.push(BundleMaterial {
        handle: "evidence-2".into(),
        disposition: SourceDisposition::Required,
        bytes: envelope2_bytes.len() as u64,
        digest: sha256_hex(&envelope2_bytes),
    });
    if options.nonrecoverable_omission {
        bundle.omissions.push(OmissionHandle {
            handle: "missing-source".into(),
            reason: "source was not supplied".into(),
            reversible: false,
            scope_id: job.scope_id.clone(),
            task_id: job.task_id.clone(),
            digest: sha256_hex(b"orientation-nonrecoverable-omission"),
            nonrecoverable_reason: Some("provider permanently unavailable".into()),
        });
    }
    if options.extra_omissions {
        bundle.omissions.push(OmissionHandle {
            handle: "gap-a".into(),
            reason: "gap-a awaits a future source".into(),
            reversible: true,
            scope_id: job.scope_id.clone(),
            task_id: job.task_id.clone(),
            digest: sha256_hex(b"orientation-gap-a"),
            nonrecoverable_reason: None,
        });
        bundle.omissions.push(OmissionHandle {
            handle: "gap-b".into(),
            reason: "gap-b source retired".into(),
            reversible: false,
            scope_id: job.scope_id.clone(),
            task_id: job.task_id.clone(),
            digest: sha256_hex(b"orientation-gap-b"),
            nonrecoverable_reason: Some("source retired; recovery impossible".into()),
        });
    }
    let coverage_denominator = if options.partial {
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
    let mut model_sources = vec!["frame".into()];
    if let Some(extra) = &options.extra_model_source {
        model_sources.push(extra.clone());
    }
    let model = ModelDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        statement: "A bounded hypothesis".into(),
        source_handles: model_sources,
        counterevidence: options.counterevidence.clone(),
        uncertainty: "unknown".into(),
        expected_benefit: "choose a useful next read".into(),
        recommended_probes: options.recommended_probes.clone(),
        invalidation_conditions: vec!["new evidence differs".into()],
        declared_confirmed_handles: options.declared_confirmed_handles.clone(),
    };
    let draft_digest = model_digest(&model).expect("model digest");
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id: job_id.clone(),
        draft_digest: draft_digest.clone(),
        residues: vec![ClaimResidue {
            claim: "A bounded hypothesis".into(),
            state: options.residue_state,
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

fn fixture(
    partial: bool,
    nonrecoverable_omission: bool,
) -> (
    AdmittedOrientationJob,
    DreamInputBundle,
    ValidatedCandidate,
    OrientationPolicy,
    Vec<CurrentEpistemicPositionHandle>,
) {
    let assembled = assemble(&FixtureOptions {
        partial,
        nonrecoverable_omission,
        ..FixtureOptions::default()
    });
    assembled.2.validate_binding().expect("candidate binding");
    assembled
}

fn assemble_with(
    build: impl FnOnce(&mut FixtureOptions),
) -> (
    AdmittedOrientationJob,
    DreamInputBundle,
    ValidatedCandidate,
    OrientationPolicy,
    Vec<CurrentEpistemicPositionHandle>,
) {
    let mut options = FixtureOptions::default();
    build(&mut options);
    assemble(&options)
}

fn packet_value(packet: &OrientationPacketCandidate) -> serde_json::Value {
    let bytes = canonical_json_bytes(packet).expect("packet canonical bytes");
    serde_json::from_slice(&bytes).expect("packet json value")
}

fn collect_object_keys(value: &serde_json::Value, keys: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                keys.insert(key.clone());
                collect_object_keys(nested, keys);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_object_keys(item, keys);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

fn packet_keys(packet: &OrientationPacketCandidate) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    collect_object_keys(&packet_value(packet), &mut keys);
    keys
}

// WORK_UNIT_CASE: 628/1
#[test]
fn projects_minimal_complete_packet() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    assert_eq!(packet.schema_version, 2);
    assert_eq!(
        packet
            .preservation
            .verdicts
            .iter()
            .map(|verdict| verdict.dimension)
            .collect::<Vec<_>>(),
        RelationPreservationDimension::all()
    );
    assert_eq!(packet.sections.len(), 11);
    assert_eq!(packet.model_draft, candidate.model);
    assert_eq!(packet.grounded_draft, candidate.grounded);
    assert_eq!(packet.resolved_epistemic_position_handles, handles);
    assert_eq!(packet.rival_models_and_dissent.len(), 1);
    assert_eq!(
        packet.rival_models_and_dissent[0].text,
        candidate.model.counterevidence[0]
    );
    let mut old_shape = serde_json::to_value(&packet).expect("packet json");
    old_shape["schema_version"] = serde_json::json!(1);
    assert!(serde_json::from_value::<OrientationPacketCandidate>(old_shape).is_err());
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

// WORK_UNIT_CASE: 628/10
#[test]
fn preserves_model_and_grounding_without_promoting_residue_to_evidence() {
    let (job, bundle, candidate, policy, handles) = fixture(false, true);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Partial);
    assert_eq!(packet.omission_handles, candidate.bundle.omissions);
    assert_eq!(packet.unknowns_and_gaps.len(), 1);
    assert_eq!(
        packet.unknowns_and_gaps[0].text,
        candidate.bundle.omissions[0].reason
    );
    assert_eq!(
        packet.unknowns_and_gaps[0].source,
        candidate.bundle.omissions[0].handle
    );
    let reversibility = packet
        .preservation
        .verdicts
        .iter()
        .find(|verdict| verdict.dimension == RelationPreservationDimension::Reversibility)
        .expect("reversibility verdict");
    assert!(!reversibility.passed);
    let preservation_section = packet
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "preservation")
        .expect("preservation section");
    assert!(
        preservation_section
            .items
            .iter()
            .any(|item| item == "reversibility:false")
    );
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

// WORK_UNIT_CASE: 628/3
#[test]
fn rejects_wrong_job_class() {
    let (mut job, bundle, candidate, policy, handles) = fixture(false, false);
    job.job.job_class = JobClass::Curation;
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &policy).is_err());
    for class in [
        JobClass::Clarification,
        JobClass::ResearchSynthesis,
        JobClass::ArchitectureSelfQuery,
        JobClass::DevelopmentDiagnosis,
        JobClass::Maintenance,
        JobClass::OrchestrationPlanning,
        JobClass::ConfigurationAssistance,
    ] {
        job.job.job_class = class;
        assert!(
            project_orientation(&job, &bundle, &candidate, &handles, &policy).is_err(),
            "{class:?} must never project as Orientation"
        );
    }
}

// WORK_UNIT_CASE: 628/4
#[test]
fn frame_question_is_bound_to_material_body() {
    let (mut job, bundle, candidate, policy, handles) = fixture(false, false);
    job.frame.question = "different question".into();
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &policy).is_err());
    let (mut task_job, task_bundle, task_candidate, task_policy, task_handles) =
        fixture(false, false);
    task_job.job.task_id = "task-9".into();
    assert!(
        project_orientation(
            &task_job,
            &task_bundle,
            &task_candidate,
            &task_handles,
            &task_policy
        )
        .is_err()
    );
    let (mut scope_job, scope_bundle, scope_candidate, scope_policy, scope_handles) =
        fixture(false, false);
    scope_job.job.scope_id = "scope-9".into();
    assert!(
        project_orientation(
            &scope_job,
            &scope_bundle,
            &scope_candidate,
            &scope_handles,
            &scope_policy
        )
        .is_err()
    );
    let (mut fence_job, fence_bundle, fence_candidate, fence_policy, fence_handles) =
        fixture(false, false);
    fence_job.job.state_fence.resource_generation =
        ResourceGeneration::new(2).expect("bumped generation");
    assert!(
        project_orientation(
            &fence_job,
            &fence_bundle,
            &fence_candidate,
            &fence_handles,
            &fence_policy
        )
        .is_err()
    );
    let (manifest_job, mut manifest_bundle, manifest_candidate, manifest_policy, manifest_handles) =
        fixture(false, false);
    manifest_bundle.manifest_digest = sha256_hex(b"tampered-manifest");
    assert!(
        project_orientation(
            &manifest_job,
            &manifest_bundle,
            &manifest_candidate,
            &manifest_handles,
            &manifest_policy
        )
        .is_err()
    );
    let (draft_job, draft_bundle, mut draft_candidate, draft_policy, draft_handles) =
        fixture(false, false);
    draft_candidate.model.statement = "A rewritten hypothesis".into();
    assert!(
        project_orientation(
            &draft_job,
            &draft_bundle,
            &draft_candidate,
            &draft_handles,
            &draft_policy
        )
        .is_err()
    );
    let (cep_job, cep_bundle, cep_candidate, cep_policy, mut cep_handles) = fixture(false, false);
    cep_handles[0].source_handle = "ghost-cep".into();
    assert!(
        project_orientation(
            &cep_job,
            &cep_bundle,
            &cep_candidate,
            &cep_handles,
            &cep_policy
        )
        .is_err()
    );
    let (mut attempt_job, attempt_bundle, attempt_candidate, attempt_policy, attempt_handles) =
        fixture(false, false);
    attempt_job.frame.attempt = "attempt-9".into();
    assert!(
        project_orientation(
            &attempt_job,
            &attempt_bundle,
            &attempt_candidate,
            &attempt_handles,
            &attempt_policy
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 628/31
#[test]
fn partial_bundle_remains_explicit_and_replay_is_stable() {
    let (job, bundle, candidate, policy, handles) = fixture(true, false);
    let first = project_orientation(&job, &bundle, &candidate, &handles, &policy)
        .expect("partial projection");
    let second = project_orientation(&job, &bundle, &candidate, &handles, &policy)
        .expect("replay projection");
    assert_eq!(first, second);
    assert_eq!(first.disposition, OrientationDisposition::Partial);
    let mut evolved_policy = OrientationPolicy::new("orientation-2", 1, 1_048_576);
    evolved_policy.seal().expect("evolved policy");
    let evolved = project_orientation(&job, &bundle, &candidate, &handles, &evolved_policy)
        .expect("policy-evolved projection");
    assert_ne!(first.input_digest, evolved.input_digest);
    assert_ne!(
        first.provenance.policy_digest,
        evolved.provenance.policy_digest
    );
    assert!(
        first
            .validate_against(&job, &bundle, &candidate, &handles, &evolved_policy)
            .is_err()
    );
}

// WORK_UNIT_CASE: 628/2
#[test]
fn exact_orientation_vocabulary_is_closed() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    assert_eq!(job.job.job_class, JobClass::Orientation);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.schema_version, 2);
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    let kinds: Vec<&str> = packet
        .sections
        .iter()
        .map(|section| section.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        vec![
            "constraints",
            "evidence_coverage",
            "identity_task_frame",
            "inert_probes",
            "interpretations_rivals_dissent",
            "omissions_expansion_frontier_invalidation",
            "positions",
            "preservation",
            "relation_candidates",
            "safe_external_handoff",
            "unknowns_gaps",
        ]
    );
    assert_eq!(
        serde_json::to_value(JobClass::Orientation).expect("class json"),
        serde_json::json!("orientation")
    );
    assert_eq!(
        serde_json::to_value(RequesterOrigin::Human).expect("origin json"),
        serde_json::json!("human")
    );
    assert_eq!(
        serde_json::to_value(packet.disposition).expect("disposition json"),
        serde_json::json!("complete")
    );
    assert_eq!(
        serde_json::to_value(packet.sections[0].kind).expect("kind json"),
        serde_json::json!("constraints")
    );
}

// WORK_UNIT_CASE: 628/5
#[test]
fn requester_origin_and_session_survive_verbatim() {
    for (origin, session) in [
        (RequesterOrigin::Human, None),
        (
            RequesterOrigin::AdmittedAgent,
            Some("agent-session-9".to_owned()),
        ),
        (RequesterOrigin::SchedulePolicy, None),
    ] {
        let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
            options.requester_origin = origin;
            options.requester_session = session.clone();
        });
        candidate.validate_binding().expect("candidate binding");
        let packet =
            project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
        assert_eq!(packet.provenance.requester_origin, origin);
        assert_eq!(packet.provenance.requester_principal, "alice");
        assert_eq!(packet.provenance.requester_session, session);
        assert_eq!(packet.disposition, OrientationDisposition::Complete);
    }
}

// WORK_UNIT_CASE: 628/6
#[test]
fn generic_request_closes_without_self_scope_or_brief_handles() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    assert_eq!(job.job.scope_id, "scope-1");
    assert!(!job.job.scope_id.contains("self"));
    assert_eq!(candidate.model.source_handles, vec!["frame".to_owned()]);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    for forbidden in [
        "self_scope",
        "self_query",
        "architecture_brief",
        "implementation_brief",
    ] {
        assert!(
            !wire.contains(forbidden),
            "generic packet must not carry {forbidden}"
        );
    }
}

// WORK_UNIT_CASE: 628/7
#[test]
fn outside_manifest_source_rejected_and_stale_evidence_preserved() {
    let (ghost_job, ghost_bundle, ghost_candidate, ghost_policy, ghost_handles) =
        assemble_with(|options| {
            options.extra_model_source = Some("ghost-handle".into());
        });
    assert!(
        project_orientation(
            &ghost_job,
            &ghost_bundle,
            &ghost_candidate,
            &ghost_handles,
            &ghost_policy
        )
        .is_err()
    );
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.evidence2_status = EpistemicStatus::Stale;
        options.evidence2_freshness = EvidenceFreshness::Stale;
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    let stale = packet
        .anchored_evidence_by_status
        .iter()
        .find(|evidence| evidence.source_handle == "evidence-2")
        .expect("stale evidence retained");
    assert_eq!(stale.envelope.status, EpistemicStatus::Stale);
    assert_eq!(stale.envelope.freshness, EvidenceFreshness::Stale);
    assert_eq!(
        packet.anchored_evidence_by_status.len(),
        job.admitted_evidence.len()
    );
}

// WORK_UNIT_CASE: 628/8
#[test]
fn varied_position_and_evidence_status_are_preserved() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.evidence2_status = EpistemicStatus::Contested;
        options.cep2_superseded = true;
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    assert_eq!(packet.resolved_epistemic_position_handles.len(), 2);
    assert_eq!(
        packet.resolved_epistemic_position_handles[0]
            .position
            .currentness,
        Currentness::Current
    );
    assert_eq!(
        packet.resolved_epistemic_position_handles[1]
            .position
            .currentness,
        Currentness::Superseded
    );
    assert!(
        !packet.resolved_epistemic_position_handles[1]
            .position
            .supersession
            .is_empty()
    );
    let statuses: Vec<EpistemicStatus> = packet
        .anchored_evidence_by_status
        .iter()
        .map(|evidence| evidence.envelope.status)
        .collect();
    assert_eq!(
        statuses,
        vec![EpistemicStatus::Observed, EpistemicStatus::Contested]
    );
    let positions = packet
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "positions")
        .expect("positions section");
    assert_eq!(positions.items.len(), 2);
}

// WORK_UNIT_CASE: 628/9
#[test]
fn partial_denominator_marks_positions_unknown() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.partial = true;
    });
    candidate.validate_binding().expect("candidate binding");
    let partial =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(partial.disposition, OrientationDisposition::Partial);
    assert!(partial.coverage_denominator.is_none());
    assert!(partial.source_coverage.denominator_digest.is_none());
    for name in ["positions", "evidence_coverage"] {
        let section = partial
            .sections
            .iter()
            .find(|section| section.kind.as_str() == name)
            .expect("section present");
        assert!(
            !section.known,
            "{name} must stay unknown without a denominator"
        );
    }
    let (full_job, full_bundle, full_candidate, full_policy, full_handles) = fixture(false, false);
    let full = project_orientation(
        &full_job,
        &full_bundle,
        &full_candidate,
        &full_handles,
        &full_policy,
    )
    .expect("projection");
    for name in ["positions", "evidence_coverage"] {
        let section = full
            .sections
            .iter()
            .find(|section| section.kind.as_str() == name)
            .expect("section present");
        assert!(section.known, "{name} is known with a denominator");
    }
}

// WORK_UNIT_CASE: 628/11
#[test]
fn exact_duplicate_rivals_preserve_every_lineage() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.counterevidence = vec!["same rival".into(), "same rival".into()];
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.rival_models_and_dissent.len(), 2);
    for rival in &packet.rival_models_and_dissent {
        assert_eq!(rival.kind, "counterevidence");
        assert_eq!(rival.text, "same rival");
        assert_eq!(rival.source, "model_draft");
    }
    assert_eq!(
        packet.synthesized_interpretations[0].counterevidence,
        vec!["same rival".to_owned(), "same rival".to_owned()]
    );
}

// WORK_UNIT_CASE: 628/12
#[test]
fn materially_different_rivals_stay_separate() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.counterevidence = vec!["rival alpha".into(), "rival beta".into()];
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let texts: Vec<&str> = packet
        .rival_models_and_dissent
        .iter()
        .map(|rival| rival.text.as_str())
        .collect();
    assert_eq!(texts, vec!["rival alpha", "rival beta"]);
    assert_ne!(
        packet.rival_models_and_dissent[0],
        packet.rival_models_and_dissent[1]
    );
}

// WORK_UNIT_CASE: 628/13
#[test]
fn winner_injection_rejected_and_dissent_never_collapsed() {
    let (crowned_job, crowned_bundle, crowned_candidate, crowned_policy, crowned_handles) =
        assemble_with(|options| {
            options.declared_confirmed_handles = vec!["evidence".into()];
        });
    assert!(
        project_orientation(
            &crowned_job,
            &crowned_bundle,
            &crowned_candidate,
            &crowned_handles,
            &crowned_policy
        )
        .is_err()
    );
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(
        packet.rival_models_and_dissent.len(),
        candidate.model.counterevidence.len()
    );
    assert!(!packet.rival_models_and_dissent.is_empty());
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    for forbidden in ["winner", "consensus", "majority"] {
        assert!(
            !wire.contains(forbidden),
            "packet must not inject {forbidden}"
        );
    }
}

// WORK_UNIT_CASE: 628/14
#[test]
fn hidden_counterevidence_or_omission_is_rejected() {
    let (job, bundle, candidate, policy, handles) = fixture(false, true);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(
        packet.rival_models_and_dissent.len(),
        candidate.model.counterevidence.len()
    );
    assert_eq!(
        packet.unknowns_and_gaps.len(),
        candidate.bundle.omissions.len()
    );
    assert_eq!(
        packet.unknowns_and_gaps[0].text,
        candidate.bundle.omissions[0].reason
    );
    let mut censored = packet.clone();
    censored.rival_models_and_dissent.pop();
    assert!(
        censored
            .validate_against(&job, &bundle, &candidate, &handles, &policy)
            .is_err()
    );
    let mut gapless = packet.clone();
    gapless.unknowns_and_gaps.clear();
    assert!(
        gapless
            .validate_against(&job, &bundle, &candidate, &handles, &policy)
            .is_err()
    );
}

// WORK_UNIT_CASE: 628/15
#[test]
fn relation_projection_stays_explicit() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert!(packet.hidden_relation_candidates.is_empty());
    let relations = packet
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "relation_candidates")
        .expect("relation section");
    assert!(relations.known);
    assert!(relations.items.is_empty());
    let (open_job, open_bundle, open_candidate, open_policy, open_handles) =
        assemble_with(|options| {
            options.partial = true;
        });
    open_candidate
        .validate_binding()
        .expect("candidate binding");
    let open = project_orientation(
        &open_job,
        &open_bundle,
        &open_candidate,
        &open_handles,
        &open_policy,
    )
    .expect("projection");
    assert_eq!(
        open.hidden_relation_candidates,
        vec![OrientationResidue {
            kind: "unsupported".into(),
            text: "typed relation projection is outside the basic Orientation owner".into(),
            source: "orientation_contract".into(),
        }]
    );
    let open_relations = open
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "relation_candidates")
        .expect("relation section");
    assert!(!open_relations.known);
    assert_eq!(
        open_relations.items,
        vec!["relation candidates are not admitted".to_owned()]
    );
}

// WORK_UNIT_CASE: 628/16
#[test]
fn missing_source_scope_and_fence_bindings_rejected() {
    let (ghost_job, ghost_bundle, ghost_candidate, ghost_policy, mut ghost_handles) =
        fixture(false, false);
    ghost_handles[0].source_handle = "ghost-cep".into();
    assert!(
        project_orientation(
            &ghost_job,
            &ghost_bundle,
            &ghost_candidate,
            &ghost_handles,
            &ghost_policy
        )
        .is_err()
    );
    let (mut missing_job, missing_bundle, missing_candidate, missing_policy, missing_handles) =
        fixture(false, false);
    missing_job.admitted_evidence[0].source_handle = "ghost-evidence".into();
    assert!(
        project_orientation(
            &missing_job,
            &missing_bundle,
            &missing_candidate,
            &missing_handles,
            &missing_policy
        )
        .is_err()
    );
    let (mut scope_job, scope_bundle, scope_candidate, scope_policy, scope_handles) =
        fixture(false, false);
    scope_job.job.scope_id = "scope-9".into();
    assert!(
        project_orientation(
            &scope_job,
            &scope_bundle,
            &scope_candidate,
            &scope_handles,
            &scope_policy
        )
        .is_err()
    );
    let (mut fence_job, fence_bundle, fence_candidate, fence_policy, fence_handles) =
        fixture(false, false);
    fence_job.job.state_fence.resource_generation =
        ResourceGeneration::new(2).expect("bumped generation");
    assert!(
        project_orientation(
            &fence_job,
            &fence_bundle,
            &fence_candidate,
            &fence_handles,
            &fence_policy
        )
        .is_err()
    );
    let (mut denom_job, denom_bundle, denom_candidate, denom_policy, denom_handles) =
        fixture(false, false);
    denom_job
        .coverage_denominator
        .as_mut()
        .expect("denominator")
        .cep_members
        .pop();
    assert!(
        project_orientation(
            &denom_job,
            &denom_bundle,
            &denom_candidate,
            &denom_handles,
            &denom_policy
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 628/17
#[test]
fn similarity_signals_cannot_create_relations() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert!(packet.hidden_relation_candidates.is_empty());
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    for forbidden in [
        "similarity",
        "proximity",
        "co-occurrence",
        "co_occurrence",
        "chronology",
        "confidence",
        "frequency",
    ] {
        assert!(
            !wire.contains(forbidden),
            "no {forbidden} signal may mint a relation"
        );
    }
    let (open_job, open_bundle, open_candidate, open_policy, open_handles) =
        assemble_with(|options| {
            options.partial = true;
        });
    open_candidate
        .validate_binding()
        .expect("candidate binding");
    let open = project_orientation(
        &open_job,
        &open_bundle,
        &open_candidate,
        &open_handles,
        &open_policy,
    )
    .expect("projection");
    assert_eq!(open.hidden_relation_candidates.len(), 1);
    assert_eq!(open.hidden_relation_candidates[0].kind, "unsupported");
}

// WORK_UNIT_CASE: 628/18
#[test]
fn unsupported_causal_relation_stays_limited() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.partial = true;
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(
        packet.hidden_relation_candidates,
        vec![OrientationResidue {
            kind: "unsupported".into(),
            text: "typed relation projection is outside the basic Orientation owner".into(),
            source: "orientation_contract".into(),
        }]
    );
    let keys = packet_keys(&packet);
    assert!(!keys.iter().any(|key| key.contains("causal")));
    assert!(!keys.iter().any(|key| key.contains("edge")));
}

// WORK_UNIT_CASE: 628/19
#[test]
fn material_gap_denominator_carries_one_disposition_per_gap() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.extra_omissions = true;
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Partial);
    assert_eq!(packet.unknowns_and_gaps.len(), 2);
    assert_eq!(packet.unknowns_and_gaps[0].kind, "unavailable");
    assert_eq!(
        packet.unknowns_and_gaps[0].text,
        "gap-a awaits a future source"
    );
    assert_eq!(packet.unknowns_and_gaps[0].source, "gap-a");
    assert_eq!(packet.unknowns_and_gaps[1].kind, "unavailable");
    assert_eq!(packet.unknowns_and_gaps[1].text, "gap-b source retired");
    assert_eq!(packet.unknowns_and_gaps[1].source, "gap-b");
    let unknowns = packet
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "unknowns_gaps")
        .expect("unknowns section");
    assert_eq!(
        unknowns.items,
        vec![
            "gap-a awaits a future source".to_owned(),
            "gap-b source retired".to_owned(),
        ]
    );
}

// WORK_UNIT_CASE: 628/20
#[test]
fn bounded_existing_probe_stays_inert() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.recommended_probes_or_next_actions.len(), 1);
    assert_eq!(
        packet.recommended_probes_or_next_actions[0].text,
        "inspect the outcome"
    );
    assert_eq!(
        packet.recommended_probes_or_next_actions[0].status,
        "model_recommendation_inert"
    );
    assert!(
        packet.recommended_probes_or_next_actions[0]
            .result_space
            .is_none()
    );
    assert_eq!(packet.budget_usage, candidate.usage);
    assert_eq!(
        packet.invalidation_conditions,
        candidate.model.invalidation_conditions
    );
    assert!(
        packet
            .model_routes_and_cost
            .text
            .contains("input_bytes=1000")
    );
    assert!(packet.model_routes_and_cost.text.contains("stu_used=1"));
}

// WORK_UNIT_CASE: 628/21
#[test]
fn probe_execution_text_cannot_become_live() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.recommended_probes = vec![
            "execute probe alpha now".into(),
            "result: alpha passed".into(),
            "live-route: probe/beta".into(),
        ];
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    assert_eq!(packet.recommended_probes_or_next_actions.len(), 3);
    for probe in &packet.recommended_probes_or_next_actions {
        assert_eq!(probe.status, "model_recommendation_inert");
        assert!(probe.result_space.is_none());
    }
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    assert!(!wire.contains("executing"));
    assert!(!wire.contains("probe_plan"));
}

// WORK_UNIT_CASE: 628/22
#[test]
fn projection_is_pure_with_no_planning_call() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let first =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let second =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("reprojection");
    assert_eq!(first, second);
    assert_eq!(first.packet_id, second.packet_id);
    for probe in &first.recommended_probes_or_next_actions {
        assert_eq!(probe.status, "model_recommendation_inert");
        assert!(probe.result_space.is_none());
    }
    let wire = serde_json::to_string(&packet_value(&first)).expect("packet json");
    for forbidden in ["probe_plan", "planning_call", "a-17b", "reserve_probe"] {
        assert!(
            !wire.contains(forbidden),
            "no planning artifact: {forbidden}"
        );
    }
}

// WORK_UNIT_CASE: 628/23
#[test]
fn ambiguity_stays_partial_not_a_question() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.partial = true;
        options.nonrecoverable_omission = true;
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Partial);
    assert!(!packet.unknowns_and_gaps.is_empty());
    for gap in &packet.unknowns_and_gaps {
        assert_eq!(gap.kind, "unavailable");
    }
    let mut emitted: Vec<&str> = Vec::new();
    emitted.push(packet.synthesized_interpretations[0].statement.as_str());
    emitted.push(packet.synthesized_interpretations[0].uncertainty.as_str());
    emitted.push(
        packet.synthesized_interpretations[0]
            .expected_benefit
            .as_str(),
    );
    for rival in &packet.rival_models_and_dissent {
        emitted.push(rival.text.as_str());
    }
    for gap in &packet.unknowns_and_gaps {
        emitted.push(gap.text.as_str());
    }
    for probe in &packet.recommended_probes_or_next_actions {
        emitted.push(probe.text.as_str());
    }
    for text in emitted {
        assert!(
            !text.ends_with('?'),
            "projection must not emit a question: {text}"
        );
    }
    for probe in &packet.recommended_probes_or_next_actions {
        assert_eq!(probe.status, "model_recommendation_inert");
    }
}

// WORK_UNIT_CASE: 628/24
#[test]
fn no_clarification_candidate_emitted() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    assert!(!wire.to_lowercase().contains("clarification"));
    assert!(!wire.contains("question_candidate"));
    let (mut clarify_job, clarify_bundle, clarify_candidate, clarify_policy, clarify_handles) =
        fixture(false, false);
    clarify_job.job.job_class = JobClass::Clarification;
    assert!(
        project_orientation(
            &clarify_job,
            &clarify_bundle,
            &clarify_candidate,
            &clarify_handles,
            &clarify_policy
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 628/25
#[test]
fn no_brief_payload_or_algorithm() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    for forbidden in [
        "architecture_brief",
        "implementation_brief",
        "brief_payload",
    ] {
        assert!(!wire.contains(forbidden), "no brief artifact: {forbidden}");
    }
    assert_eq!(packet.architecture_implications.kind, "known_empty");
    assert_eq!(
        packet.architecture_implications.text,
        "no architecture implications admitted"
    );
    let (mut query_job, query_bundle, query_candidate, query_policy, query_handles) =
        fixture(false, false);
    query_job.job.job_class = JobClass::ArchitectureSelfQuery;
    assert!(
        project_orientation(
            &query_job,
            &query_bundle,
            &query_candidate,
            &query_handles,
            &query_policy
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 628/26
#[test]
fn all_required_sections_with_exact_omission_accounting() {
    let (job, bundle, candidate, policy, handles) = fixture(false, true);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.sections.len(), 11);
    let kinds: Vec<&str> = packet
        .sections
        .iter()
        .map(|section| section.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        vec![
            "constraints",
            "evidence_coverage",
            "identity_task_frame",
            "inert_probes",
            "interpretations_rivals_dissent",
            "omissions_expansion_frontier_invalidation",
            "positions",
            "preservation",
            "relation_candidates",
            "safe_external_handoff",
            "unknowns_gaps",
        ]
    );
    assert_eq!(packet.omission_handles, candidate.bundle.omissions);
    let unknowns = packet
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "unknowns_gaps")
        .expect("unknowns section");
    assert_eq!(unknowns.items, vec!["source was not supplied".to_owned()]);
    let frontier = packet
        .sections
        .iter()
        .find(|section| section.kind.as_str() == "omissions_expansion_frontier_invalidation")
        .expect("frontier section");
    assert_eq!(frontier.items, candidate.model.invalidation_conditions);
    packet
        .validate_against(&job, &bundle, &candidate, &handles, &policy)
        .expect("input rebinding");
}

// WORK_UNIT_CASE: 628/27
#[test]
fn exact_output_fit_one_over_frontier() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let exact = u64::try_from(canonical_json_bytes(&packet).expect("packet bytes").len())
        .expect("output length");
    assert!(exact > 512);
    let mut fitting = OrientationPolicy::new("orientation-1", 1, exact);
    fitting.seal().expect("fitting policy");
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &fitting).is_ok());
    let mut one_over = OrientationPolicy::new("orientation-1", 1, exact - 1);
    one_over.seal().expect("one-over policy");
    let err = project_orientation(&job, &bundle, &candidate, &handles, &one_over)
        .expect_err("one byte over must not fit");
    assert!(matches!(err, OrientationError::Bounded(_)));
    let mut tiny = OrientationPolicy::new("orientation-1", 1, 64);
    tiny.seal().expect("tiny policy");
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &tiny).is_err());
}

// WORK_UNIT_CASE: 628/28
#[test]
fn privacy_authority_effect_proof_escalation_rejected() {
    let (public_job, public_bundle, public_candidate, public_policy, public_handles) =
        assemble_with(|options| {
            options.privacy_profile = "public-internet".into();
        });
    assert!(
        project_orientation(
            &public_job,
            &public_bundle,
            &public_candidate,
            &public_handles,
            &public_policy
        )
        .is_err()
    );
    let (job, bundle, mut candidate, policy, handles) = fixture(false, false);
    candidate.validated.receipt.proof_ceiling = "floor-zero".into();
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &policy).is_err());
    let (contract_job, contract_bundle, mut contract_candidate, contract_policy, contract_handles) =
        fixture(false, false);
    contract_candidate.validated.receipt.validator_contract = "other-validator".into();
    assert!(
        project_orientation(
            &contract_job,
            &contract_bundle,
            &contract_candidate,
            &contract_handles,
            &contract_policy
        )
        .is_err()
    );
    let (clean_job, clean_bundle, clean_candidate, clean_policy, clean_handles) =
        fixture(false, false);
    let packet = project_orientation(
        &clean_job,
        &clean_bundle,
        &clean_candidate,
        &clean_handles,
        &clean_policy,
    )
    .expect("projection");
    assert_eq!(packet.provenance.privacy_profile, "local_only");
    let authority = packet
        .preservation
        .verdicts
        .iter()
        .find(|verdict| verdict.dimension == RelationPreservationDimension::SourceAuthority)
        .expect("source authority verdict");
    assert!(authority.passed);
    assert!(authority.known);
    assert!(!packet_keys(&packet).contains("effect"));
}

// WORK_UNIT_CASE: 628/29
#[test]
fn seven_preservation_dimensions_and_bad_receipt_rejected() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let dimensions: Vec<RelationPreservationDimension> = packet
        .preservation
        .verdicts
        .iter()
        .map(|verdict| verdict.dimension)
        .collect();
    assert_eq!(dimensions, RelationPreservationDimension::all());
    assert_eq!(packet.upstream_preservation.verdicts.len(), 7);
    assert_eq!(packet.upstream_preservation, candidate.preservation);
    assert!(
        packet
            .preservation
            .verdicts
            .iter()
            .all(|verdict| verdict.passed && verdict.known)
    );
    let (rejected_job, rejected_bundle, mut rejected_candidate, rejected_policy, rejected_handles) =
        fixture(false, false);
    rejected_candidate.validated.receipt.terminal_disposition = "rejected".into();
    assert!(
        project_orientation(
            &rejected_job,
            &rejected_bundle,
            &rejected_candidate,
            &rejected_handles,
            &rejected_policy
        )
        .is_err()
    );
    let (digest_job, digest_bundle, mut digest_candidate, digest_policy, digest_handles) =
        fixture(false, false);
    digest_candidate.validated.receipt.input_digest = sha256_hex(b"tampered-input");
    assert!(
        project_orientation(
            &digest_job,
            &digest_bundle,
            &digest_candidate,
            &digest_handles,
            &digest_policy
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 628/30
#[test]
fn canonical_order_and_digest_stable_under_permutation() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
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
    assert_eq!(packet.packet_id, replay.packet_id);
    assert_eq!(packet.input_digest, replay.input_digest);
    assert_eq!(packet.output_digest, replay.output_digest);
    let kinds: Vec<&str> = packet
        .sections
        .iter()
        .map(|section| section.kind.as_str())
        .collect();
    let mut ordered = kinds.clone();
    ordered.sort_unstable();
    assert_eq!(kinds, ordered);
}

// WORK_UNIT_CASE: 628/32
#[test]
fn malformed_input_never_panics() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    assert!(project_orientation(&job, &bundle, &candidate, &[], &policy).is_err());
    let (mut empty_job, empty_bundle, empty_candidate, empty_policy, empty_handles) =
        fixture(false, false);
    empty_job.admitted_evidence.clear();
    assert!(
        project_orientation(
            &empty_job,
            &empty_bundle,
            &empty_candidate,
            &empty_handles,
            &empty_policy
        )
        .is_err()
    );
    assert!(
        LocalOrientationFrame::new(
            "",
            "goal",
            Vec::new(),
            "attempt",
            "contract",
            "frame",
            &candidate.job,
        )
        .is_err()
    );
    let unsealed = OrientationPolicy::new("orientation-1", 1, 1_048_576);
    assert!(project_orientation(&job, &bundle, &candidate, &handles, &unsealed).is_err());
    assert!(
        OrientationPolicy::new("orientation-1", 0, 1_048_576)
            .seal()
            .is_err()
    );
    assert!(
        OrientationPolicy::new("orientation-1", 1, 0)
            .seal()
            .is_err()
    );
}

// WORK_UNIT_CASE: 628/33
#[test]
fn every_material_item_resolves_or_is_explicit() {
    let (job, bundle, candidate, policy, handles) = fixture(false, true);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.source_materials, candidate.bundle.materials);
    let expected_sources: Vec<String> = candidate
        .bundle
        .materials
        .iter()
        .map(|material| material.handle.clone())
        .collect();
    assert_eq!(packet.provenance.source_handles, expected_sources);
    assert_eq!(
        packet.rival_models_and_dissent.len(),
        candidate.model.counterevidence.len()
    );
    assert_eq!(
        packet.unknowns_and_gaps.len(),
        candidate.bundle.omissions.len()
    );
    assert_eq!(
        packet.recommended_probes_or_next_actions.len(),
        candidate.model.recommended_probes.len()
    );
    assert_eq!(
        packet.invalidation_conditions,
        candidate.model.invalidation_conditions
    );
    assert_eq!(
        packet.synthesized_interpretations[0].statement,
        candidate.model.statement
    );
    assert_eq!(packet.grounded_draft, candidate.grounded);
    assert_eq!(packet.model_draft, candidate.model);
}

// WORK_UNIT_CASE: 628/34
#[test]
fn complete_implies_complete_denominators() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    assert_eq!(
        candidate.bundle.completeness,
        BundleCompleteness::CompleteForScope
    );
    assert!(candidate.bundle.authoritative_denominator.is_some());
    assert!(packet.coverage_denominator.is_some());
    assert!(packet.source_coverage.denominator_digest.is_some());
    assert!(packet.sections.iter().all(|section| section.known));
    let (open_job, open_bundle, open_candidate, open_policy, open_handles) =
        assemble_with(|options| {
            options.residue_state = SupportState::OutsideManifest;
        });
    open_candidate
        .validate_binding()
        .expect("candidate binding");
    let open = project_orientation(
        &open_job,
        &open_bundle,
        &open_candidate,
        &open_handles,
        &open_policy,
    )
    .expect("projection");
    assert_eq!(open.disposition, OrientationDisposition::Partial);
    assert_eq!(
        open.grounded_draft.residues[0].state,
        SupportState::OutsideManifest
    );
}

// WORK_UNIT_CASE: 628/35
#[test]
fn changed_inputs_invalidate_prior_digest() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    let mut scoped = job.clone();
    scoped.job.scope_id = "scope-9".into();
    assert!(
        packet
            .validate_against(&scoped, &bundle, &candidate, &handles, &policy)
            .is_err()
    );
    let mut fenced = job.clone();
    fenced.job.state_fence.resource_generation =
        ResourceGeneration::new(2).expect("bumped generation");
    assert!(
        packet
            .validate_against(&fenced, &bundle, &candidate, &handles, &policy)
            .is_err()
    );
    let mut resourced = job.clone();
    resourced.admitted_evidence[0].source_handle = "ghost-evidence".into();
    assert!(
        packet
            .validate_against(&resourced, &bundle, &candidate, &handles, &policy)
            .is_err()
    );
    let mut redrafted = candidate.clone();
    redrafted.model.statement = "A changed hypothesis".into();
    assert!(
        packet
            .validate_against(&job, &bundle, &redrafted, &handles, &policy)
            .is_err()
    );
    let mut evolved_policy = OrientationPolicy::new("orientation-2", 1, 1_048_576);
    evolved_policy.seal().expect("evolved policy");
    let evolved = project_orientation(&job, &bundle, &candidate, &handles, &evolved_policy)
        .expect("policy-evolved projection");
    assert_ne!(packet.input_digest, evolved.input_digest);
    assert_ne!(packet.output_digest, evolved.output_digest);
}

// WORK_UNIT_CASE: 628/36
#[test]
fn no_rival_or_probe_algorithm_dependencies() {
    let (job, bundle, candidate, policy, handles) = fixture(false, false);
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(
        packet.synthesized_interpretations[0].statement,
        candidate.model.statement
    );
    assert_eq!(
        packet.synthesized_interpretations[0].uncertainty,
        candidate.model.uncertainty
    );
    assert_eq!(
        packet.synthesized_interpretations[0].expected_benefit,
        candidate.model.expected_benefit
    );
    assert_eq!(
        packet.synthesized_interpretations[0].source_handles,
        candidate.model.source_handles
    );
    for rival in &packet.rival_models_and_dissent {
        assert_eq!(rival.kind, "counterevidence");
        assert_eq!(rival.source, "model_draft");
        assert!(candidate.model.counterevidence.contains(&rival.text));
    }
    for probe in &packet.recommended_probes_or_next_actions {
        assert_eq!(probe.status, "model_recommendation_inert");
        assert!(probe.result_space.is_none());
        assert!(candidate.model.recommended_probes.contains(&probe.text));
    }
    assert!(packet.hidden_relation_candidates.is_empty());
    let wire = serde_json::to_string(&packet_value(&packet)).expect("packet json");
    for forbidden in ["probe_plan", "rival_plan", "consensus"] {
        assert!(
            !wire.contains(forbidden),
            "no algorithm artifact: {forbidden}"
        );
    }
}

// WORK_UNIT_CASE: 628/37
#[test]
fn no_model_provider_store_authority_effect_finish_path() {
    let (job, bundle, candidate, policy, handles) = assemble_with(|options| {
        options.requester_origin = RequesterOrigin::AdmittedAgent;
    });
    candidate.validate_binding().expect("candidate binding");
    let packet =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("projection");
    assert_eq!(packet.disposition, OrientationDisposition::Complete);
    let keys = packet_keys(&packet);
    for forbidden in [
        "effect",
        "effects",
        "finish",
        "delivery",
        "provider",
        "acquisition",
        "store",
        "human_interaction",
        "self_query",
        "model_call",
        "authority_grant",
        "clarification",
    ] {
        assert!(
            !keys.contains(forbidden),
            "packet must not carry {forbidden}"
        );
    }
    let replay =
        project_orientation(&job, &bundle, &candidate, &handles, &policy).expect("reprojection");
    assert_eq!(packet, replay);
}
