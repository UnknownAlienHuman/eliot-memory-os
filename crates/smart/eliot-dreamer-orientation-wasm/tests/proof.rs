//! Issue #632 proof matrix: exactly cases 1..15, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{
    EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_dreamer_contracts::relation::RelationPreservationDimension;
use eliot_dreamer_contracts::validation::{
    InputPreimage, OutputContext, PROOF_CEILING, VALIDATOR_CONTRACT, budget_digest, bundle_digest,
    input_digest_and_size, model_digest, output_digest, preservation_digest,
};
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobInput, GroundedDreamDraft, JobClass, ModelDraft, OmissionHandle,
    PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport, Requester, RequesterOrigin,
    SourceDisposition, SupportState, ValidatedCandidate, ValidatedDreamDraft, ValidationPolicy,
    ValidationReceipt,
};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, CanonicalEvidenceHandle, CoverageCepMember, CoverageEvidenceMember,
    CurrentEpistemicPositionHandle, LocalOrientationFrame, OrientationCoverageDenominator,
    OrientationDisposition, OrientationError, OrientationPolicy, project_orientation,
};
use eliot_dreamer_orientation_wasm::{
    CallLedger, GUEST_ABI_VERSION, GUEST_TARGET, GuestError, GuestRequest, HANDLER_SUBTYPE,
    TOOLCHAIN_CHANNEL, WORLD_NAME, WORLD_PACKAGE, check_wasm_imports, decode_request,
    decode_response, descriptor, descriptor_digest, disposition_as_str, encode_request,
    encode_response, handle_request_typed, handle_with_ledger, is_forbidden_import,
    list_wasm_imports, parse_disposition, qualified_export_name, run,
};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
    PositionId, PositionRevision,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};

type NativeFive = (
    AdmittedOrientationJob,
    DreamInputBundle,
    ValidatedCandidate,
    OrientationPolicy,
    Vec<CurrentEpistemicPositionHandle>,
);

fn fixture_native(partial: bool, nonrecoverable_omission: bool, statement: &str) -> NativeFive {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A"),
        NonZeroU64::new(1).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    let fence = StateFence::new(epoch, ResourceGeneration::genesis());
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
    if nonrecoverable_omission {
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
        statement: statement.into(),
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

fn guest_request(partial: bool, omission: bool, statement: &str) -> (GuestRequest, NativeFive) {
    let five = fixture_native(partial, omission, statement);
    let (admitted, bundle, candidate, policy, handles) = five.clone();
    let request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        admitted,
        bundle,
        candidate,
        positions: handles,
        policy,
    };
    (request, five)
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

// WORK_UNIT_CASE: 632/1
#[test]
fn exact_world_subtype_descriptor_abi_and_target_readiness() {
    let descriptor = descriptor();
    assert_eq!(descriptor.world_package, WORLD_PACKAGE);
    assert_eq!(descriptor.world, WORLD_NAME);
    assert_eq!(descriptor.export_name, "run");
    assert_eq!(descriptor.handler_subtype, HANDLER_SUBTYPE);
    assert_eq!(descriptor.abi_version, GUEST_ABI_VERSION);
    assert_eq!(descriptor.target, GUEST_TARGET);
    assert_eq!(descriptor.toolchain_channel, TOOLCHAIN_CHANNEL);
    assert!(descriptor.capability_envelope.is_empty());
    let wit = String::from_utf8(eliot_dreamer_orientation_wasm::GUEST_WIT_BYTES.to_vec())
        .expect("guest.wit is UTF-8");
    assert!(wit.contains("package eliot:wasm@1.0.0"));
    assert!(wit.contains("world guest"));
    assert!(wit.contains("export run"));
    assert_eq!(
        descriptor.wit_digest,
        sha256_hex(eliot_dreamer_orientation_wasm::GUEST_WIT_BYTES)
    );
    assert_eq!(qualified_export_name(), format!("{WORLD_NAME}#run"));
    assert_eq!(eliot_dreamer_orientation_wasm::wit_export_name(), "run");
    // #870 readiness: pinned target and channel from the owning toolchain file.
    let toolchain = String::from_utf8(eliot_dreamer_orientation_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("rust-toolchain.toml is UTF-8");
    assert!(toolchain.contains("wasm32-wasip2"));
    assert!(toolchain.contains(TOOLCHAIN_CHANNEL));
    assert_eq!(GUEST_TARGET, eliot_wasm_runtime::DEFAULT_GUEST_TARGET);
    assert_eq!(descriptor_digest(), descriptor_digest());
    // ContractChallenge path (#756, OPEN): the typed world is frozen in-test
    // as expected-but-absent; the accepted WIT has no such arm to consume.
    assert_eq!(descriptor.expected_typed_world, "dreamer-handler");
    assert_eq!(descriptor.typed_world_status, "EXPECTED_NOT_ACCEPTED");
    assert!(!wit.contains("dreamer-handler"));
}

// WORK_UNIT_CASE: 632/2
#[test]
fn wrong_subtype_payload_version_descriptor_rejected_before_call() {
    let (mut request, _) = guest_request(false, false, "A bounded hypothesis");
    for mutate in [
        |request: &mut GuestRequest| request.handler_subtype = "curation".into(),
        |request: &mut GuestRequest| request.world = "dreamer-handler".into(),
        |request: &mut GuestRequest| request.abi_version = 999,
        |request: &mut GuestRequest| request.handler_subtype = String::new(),
    ] {
        let mut bad = request.clone();
        mutate(&mut bad);
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&bad, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert_eq!(response.native_calls, 0);
        assert!(response.packet.is_none());
        assert!(matches!(
            response.error,
            Some(GuestError::RejectedEnvelope(_))
        ));
    }
    request.handler_subtype = HANDLER_SUBTYPE.to_owned();
    // Undecodable and trailing-garbage payloads never reach native either.
    assert!(run(&[0xFF, 0xFE, 0x00]).is_err());
    let mut trailing = encode_request(&request).expect("encode");
    trailing.extend_from_slice(b"trailing");
    assert!(run(&trailing).is_err());
}

// WORK_UNIT_CASE: 632/3
#[test]
fn exhaustive_input_output_error_conversion() {
    let natives = [
        OrientationError::WrongJobClass,
        OrientationError::Invalid("field"),
        OrientationError::Unsupported("shape"),
        OrientationError::Binding("binding"),
        OrientationError::Bound,
        OrientationError::Bounded("limit"),
        OrientationError::RevalidationRequired,
        OrientationError::Cancelled,
        OrientationError::Encoding("stage"),
        OrientationError::Internal,
    ];
    let mut seen = BTreeSet::new();
    for native in &natives {
        let guest = GuestError::from(native);
        let json = canonical_json_bytes(&guest).expect("guest error json");
        assert!(seen.insert(json), "every native error maps distinctly");
    }
    assert_eq!(seen.len(), 10);
    let (request, _) = guest_request(false, false, "A bounded hypothesis");
    let bytes = encode_request(&request).expect("encode");
    assert_eq!(decode_request(&bytes).expect("decode"), request);
    let response = handle_request_typed(&request);
    let response_bytes = encode_response(&response).expect("encode response");
    assert_eq!(decode_response(&response_bytes).expect("decode"), response);
}

// WORK_UNIT_CASE: 632/4
#[test]
fn every_orientation_disposition_round_trips() {
    let all = [
        OrientationDisposition::Complete,
        OrientationDisposition::Partial,
        OrientationDisposition::Blocked,
        OrientationDisposition::RevalidationRequired,
        OrientationDisposition::Unsupported,
        OrientationDisposition::Abstention,
        OrientationDisposition::Cancelled,
        OrientationDisposition::Bound,
        OrientationDisposition::Invalid,
        OrientationDisposition::Internal,
    ];
    let mut codes = BTreeSet::new();
    for disposition in all {
        let code = disposition_as_str(disposition);
        assert!(codes.insert(code), "disposition codes are distinct");
        assert_eq!(parse_disposition(code), Some(disposition));
    }
    assert_eq!(codes.len(), 10);
    assert_eq!(parse_disposition("winner"), None);
    assert_eq!(parse_disposition("other"), None);
    let (complete, _) = guest_request(false, false, "A bounded hypothesis");
    let complete = handle_request_typed(&complete).packet.expect("packet");
    assert_eq!(complete.disposition, OrientationDisposition::Complete);
    let (partial, _) = guest_request(true, false, "A bounded hypothesis");
    let partial = handle_request_typed(&partial).packet.expect("packet");
    assert_eq!(partial.disposition, OrientationDisposition::Partial);
}

// WORK_UNIT_CASE: 632/5
#[test]
fn complete_packet_preserves_all_sections() {
    let (request, (admitted, bundle, candidate, policy, handles)) =
        guest_request(false, false, "A bounded hypothesis");
    let response = handle_request_typed(&request);
    assert_eq!(response.native_calls, 1);
    assert!(response.error.is_none());
    let packet = response.packet.expect("packet");
    assert_eq!(packet.schema_version, 2);
    assert_eq!(packet.sections.len(), 11);
    let mut kinds: Vec<&str> = packet.sections.iter().map(|s| s.kind.as_str()).collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        [
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
    assert_eq!(packet.source_coverage.material_count, 6);
    assert_eq!(packet.provenance.operation_id, "op-1");
    assert_eq!(packet.provenance.task_id, "task-1");
    assert_eq!(packet.provenance.scope_id, "scope-1");
    assert_eq!(
        packet
            .preservation
            .verdicts
            .iter()
            .map(|verdict| verdict.dimension)
            .collect::<Vec<_>>(),
        RelationPreservationDimension::all()
    );
    assert_eq!(packet.input_digest.len(), 64);
    assert_eq!(packet.output_digest.len(), 64);
    assert_eq!(packet.packet_id.len(), 64);
    packet
        .validate_against(&admitted, &bundle, &candidate, &handles, &policy)
        .expect("admitted input rebinding");
}

// WORK_UNIT_CASE: 632/6
#[test]
fn rivals_conflicts_gaps_probes_clarification_preserved() {
    let (request, (_, _, candidate, _, _)) = guest_request(false, true, "A bounded hypothesis");
    let response = handle_request_typed(&request);
    let packet = response.packet.expect("packet");
    assert_eq!(packet.disposition, OrientationDisposition::Partial);
    assert_eq!(packet.rival_models_and_dissent.len(), 1);
    assert_eq!(
        packet.rival_models_and_dissent[0].text,
        candidate.model.counterevidence[0]
    );
    assert_eq!(packet.unknowns_and_gaps.len(), 1);
    assert_eq!(
        packet.unknowns_and_gaps[0].text,
        candidate.bundle.omissions[0].reason
    );
    assert_eq!(
        packet.unknowns_and_gaps[0].source,
        candidate.bundle.omissions[0].handle
    );
    assert_eq!(packet.recommended_probes_or_next_actions.len(), 1);
    for probe in &packet.recommended_probes_or_next_actions {
        assert_eq!(probe.status, "model_recommendation_inert");
        assert_eq!(probe.text, candidate.model.recommended_probes[0]);
    }
    assert_eq!(
        packet.invalidation_conditions,
        candidate.model.invalidation_conditions
    );
    assert_eq!(
        packet.synthesized_interpretations[0].statement,
        candidate.model.statement
    );
    assert_eq!(
        packet.synthesized_interpretations[0].counterevidence,
        candidate.model.counterevidence
    );
    let reversibility = packet
        .preservation
        .verdicts
        .iter()
        .find(|verdict| verdict.dimension == RelationPreservationDimension::Reversibility)
        .expect("reversibility verdict");
    assert!(!reversibility.passed);
}

// WORK_UNIT_CASE: 632/7
#[test]
fn stale_identity_and_all_bounds_rejected() {
    let (request, _) = guest_request(false, false, "A bounded hypothesis");
    // Stale fence: same shape, different epoch lineage.
    let mut stale = request.clone();
    let epoch = EpochId::new(
        EpochLineageId::new("660e8400-e29b-41d4-a716-446655440001").expect("stale lineage"),
        NonZeroU64::new(2).expect("non-zero sequence"),
    )
    .expect("stale epoch");
    stale.admitted.job.state_fence = StateFence::new(epoch, ResourceGeneration::genesis());
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&stale, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert!(response.packet.is_none());
    assert!(matches!(
        response.error,
        Some(GuestError::BindingMismatch(_))
    ));
    // Tampered frame body.
    let mut tampered = request.clone();
    tampered.admitted.frame.question = "different question".into();
    assert!(handle_request_typed(&tampered).packet.is_none());
    // Supplied bundle must equal the candidate bundle.
    let mut split = request.clone();
    split.bundle.manifest_digest = sha256_hex(b"other-manifest");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&split, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::BindingMismatch(_))
    ));
    // Output ceiling: a 64-byte policy cannot carry the packet.
    let mut tight = request.clone();
    tight.policy = OrientationPolicy::new("orientation-1", 1, 64);
    tight.policy.seal().expect("seal tight policy");
    let response = handle_request_typed(&tight);
    assert!(response.packet.is_none());
    assert!(matches!(response.error, Some(GuestError::BoundedLimit(_))));
    // Guest byte ceiling at the boundary.
    assert!(decode_request(&vec![0u8; 2_097_152]).is_err());
}

// WORK_UNIT_CASE: 632/8
#[test]
fn native_component_full_field_and_digest_parity() {
    let (request, (admitted, bundle, candidate, policy, handles)) =
        guest_request(false, false, "A bounded hypothesis");
    let native =
        project_orientation(&admitted, &bundle, &candidate, &handles, &policy).expect("native");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    let packet = response.packet.expect("packet");
    assert!(response.error.is_none());
    assert_eq!(packet, native);
    assert_eq!(packet.input_digest, native.input_digest);
    assert_eq!(packet.output_digest, native.output_digest);
    // Parity also holds through the `run` byte boundary.
    let bytes = run(&encode_request(&request).expect("encode")).expect("run");
    let through_bytes = decode_response(&bytes)
        .expect("decode")
        .packet
        .expect("packet");
    assert_eq!(through_bytes, native);
}

// WORK_UNIT_CASE: 632/9
#[test]
fn permutation_and_non_ascii_determinism() {
    let (request, _) = guest_request(false, false, "A bounded hypothesis");
    let first = encode_response(&handle_request_typed(&request)).expect("encode");
    let mut permuted = request.clone();
    permuted.admitted.admitted_evidence.reverse();
    permuted.positions.reverse();
    let replay = encode_response(&handle_request_typed(&permuted)).expect("encode");
    assert_eq!(first, replay);
    for statement in [
        "境界knowing — what holds? ✓",
        "Was gilt? Ünïcodéiß ∑ donc ✓",
        "假设🎯 rival-free? naïve façade",
        "A bounded hypothesis",
    ] {
        let (request, _) = guest_request(false, false, statement);
        let first = encode_response(&handle_request_typed(&request)).expect("encode");
        let (again, _) = guest_request(false, false, statement);
        let second = encode_response(&handle_request_typed(&again)).expect("encode");
        assert_eq!(first, second);
        let packet = decode_response(&first)
            .expect("decode")
            .packet
            .expect("packet");
        assert_eq!(packet.synthesized_interpretations[0].statement, statement);
    }
}

// WORK_UNIT_CASE: 632/10
#[test]
fn forbidden_import_fixture_rejected_before_execution() {
    for forbidden in eliot_dreamer_orientation_wasm::FORBIDDEN_IMPORT_SUBSTRINGS {
        assert!(
            is_forbidden_import(&format!("cap:{forbidden}"), "f"),
            "gate covers {forbidden}"
        );
    }
    for required in [
        "filesystem",
        "stdio",
        "network",
        "env",
        "args",
        "clock",
        "random",
        "process",
        "thread",
        "credential",
        "store",
        "kernel",
        "provider",
    ] {
        assert!(
            eliot_dreamer_orientation_wasm::FORBIDDEN_IMPORT_SUBSTRINGS
                .iter()
                .any(|forbidden| required.contains(forbidden) || forbidden.contains(required)),
            "issue namespace {required} is gated"
        );
    }
    for (module, name) in [
        ("wasi:filesystem/types@0.2.10", "stat"),
        ("wasi:sockets/tcp@0.2.10", "connect"),
        ("wasi:http/outgoing-handler@0.2.10", "handle"),
        ("wasi:cli/stdin@0.2.10", "get-stdin"),
        ("wasi:clocks/wall-clock@0.2.10", "now"),
        ("wasi:random/random@0.2.10", "get-random-bytes"),
    ] {
        let wasm = wat::parse_str(format!("(module (import \"{module}\" \"{name}\" (func)))"))
            .expect("wasi fixture");
        let error = check_wasm_imports(&wasm).expect_err("forbidden import must fail");
        assert_eq!(
            error,
            eliot_dreamer_orientation_wasm::DescriptorError::ForbiddenImport {
                module: module.into(),
                name: name.into(),
            }
        );
    }
    let benign =
        wat::parse_str("(module (func (export \"run\") (param i32) (result i32) local.get 0))")
            .expect("benign fixture");
    assert_eq!(list_wasm_imports(&benign).expect("imports"), vec![]);
    assert!(
        check_wasm_imports(&benign)
            .expect("benign passes")
            .is_empty()
    );
    assert!(check_wasm_imports(b"not a module").is_err());
}

// WORK_UNIT_CASE: 632/11
#[test]
fn exactly_one_native_call_no_duplicate_algorithm() {
    let (request, _) = guest_request(false, false, "A bounded hypothesis");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.packet.is_some());
    // Structural proof: exactly one native call site outside tests.
    let mut sites = 0;
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        sites += read_src(name).matches("project_orientation(").count();
    }
    assert_eq!(sites, 1);
}

// WORK_UNIT_CASE: 632/12
#[test]
fn no_generic_serialization_escape() {
    let (request, _) = guest_request(false, false, "A bounded hypothesis");
    let bytes = encode_request(&request).expect("encode");
    let json = String::from_utf8(bytes).expect("canonical UTF-8");
    let injected = json.replacen('{', "{\"guest_unknown_field\":1,", 1);
    assert!(decode_request(injected.as_bytes()).is_err());
    // Canonical bytes are stable through decode/re-encode.
    let decoded = decode_request(json.as_bytes()).expect("decode");
    assert_eq!(
        encode_request(&decoded).expect("re-encode"),
        json.as_bytes()
    );
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source = read_src(name);
        for forbidden in [
            "serde_json::Value",
            "unimplemented!",
            "todo!",
            "std::process",
            "std::fs",
            "tokio",
            "reqwest",
            "surrealdb",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
}

// WORK_UNIT_CASE: 632/13
#[test]
fn standalone_capsule_through_e_host() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let (request, _) = guest_request(false, false, "A bounded hypothesis");
    let input = encode_request(&request).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-632-capsule").expect("invocation"),
        CapabilityId::new("fixture-orientation-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-632").expect("work unit"),
        WorkScopeRef::new("fixture-scope-632").expect("scope"),
        ExecutionContour::Shadow,
        input,
        632,
        false,
    )
    .expect("capsule request");
    invocation.validate().expect("capsule digest");
    // #758/#760 are OPEN: no engine/port surface is injected, so the real
    // facade must return the typed PLAN_GAP instead of executing.
    let mut runtime = WasmRuntime::new(None);
    let result = runtime.execute(invocation);
    assert_eq!(
        result.receipt.disposition,
        InvocationDisposition::Unavailable
    );
    assert_eq!(result.receipt.error, Some(RuntimeError::PlanGap));
    assert!(result.output.is_none());
    assert!(result.proposed_effects.is_empty());
    assert!(result.observed_state_delta.is_none());
    assert!(!result.receipt.reconciliation_required);
    // Cancellation preserves the real host's typed rejection path.
    let cancelled = InvocationRequest::new(
        InvocationId::new("fixture-632-cancelled").expect("invocation"),
        CapabilityId::new("fixture-orientation-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-632").expect("work unit"),
        WorkScopeRef::new("fixture-scope-632").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        632,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 632/14
#[test]
fn build_artifact_identity_and_admission_state() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-dreamer-orientation-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // Controller-owned handoff (issue #632): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-dreamer-orientation-wasm"));
    // Frozen toolchain identity matches the owning file.
    let toolchain = String::from_utf8(eliot_dreamer_orientation_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("toolchain UTF-8");
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert!(toolchain.contains("wasm32-wasip2"));
}

// WORK_UNIT_CASE: 632/15
#[test]
fn property_output_equals_native_without_proof_authority_effect() {
    let statements = [
        "A bounded hypothesis",
        "境界knowing — what holds? ✓",
        "Was gilt? Ünïcodéiß ∑",
        "second hypothesis variant",
    ];
    for statement in statements {
        for reverse in [false, true] {
            let (mut request, (admitted, bundle, candidate, policy, handles)) =
                guest_request(false, false, statement);
            if reverse {
                request.admitted.admitted_evidence.reverse();
                request.positions.reverse();
            }
            let native = project_orientation(&admitted, &bundle, &candidate, &handles, &policy)
                .expect("native");
            let response = handle_request_typed(&request);
            assert!(response.error.is_none());
            let packet = response.packet.as_ref().expect("packet");
            assert_eq!(*packet, native);
            assert!(matches!(
                packet.disposition,
                OrientationDisposition::Complete | OrientationDisposition::Partial
            ));
            // The response envelope carries no proof/authority/effect surface.
            let json = String::from_utf8(encode_response(&response).expect("encode"))
                .expect("response UTF-8");
            for absent in [
                "\"authority_granted\"",
                "\"effect\"",
                "\"finish\"",
                "\"promotion\"",
                "\"executed_probe\"",
                "\"answer\"",
            ] {
                assert!(!json.contains(absent), "response must not raise {absent}");
            }
            for probe in &packet.recommended_probes_or_next_actions {
                assert_eq!(probe.status, "model_recommendation_inert");
            }
        }
    }
}
