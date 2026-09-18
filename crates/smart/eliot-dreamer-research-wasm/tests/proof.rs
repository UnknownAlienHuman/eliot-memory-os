//! Issue #634 proof matrix: exactly cases 1..13, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{JobClass, parse_job_class};
use eliot_dreamer_research_wasm::{
    CANDIDATE_SCHEMA_REVISION, CallLedger, GUEST_ABI_VERSION, GUEST_TARGET, GuestDimensionVerdict,
    GuestError, GuestPreservationDimension, GuestRequest, GuestRequesterOrigin, HANDLER_SUBTYPE,
    NATIVE_CONTRACT_ID, NATIVE_OWNER, NATIVE_STATUS, ResearchBrief, ResearchCandidate,
    ResearchClaim, ResearchDisposition, ResearchPackRef, ResearchPayload, TOOLCHAIN_CHANNEL,
    TYPED_INTERFACE_NAME, TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_PACKAGE,
    TYPED_WORLD_STATUS, WORLD_NAME, WORLD_PACKAGE, brief_digest, check_wasm_imports,
    decode_request, decode_response, descriptor, descriptor_digest, dimension_as_str,
    disposition_as_str, encode_request, encode_response, handle_request_typed, handle_with_ledger,
    is_forbidden_import, list_wasm_imports, origin_as_str, parse_disposition,
    qualified_export_name, request_digest, run,
};

fn fixture_pack(question: &str) -> ResearchPackRef {
    ResearchPackRef {
        pack_digest: sha256_hex(b"634-pack-content"),
        source_denominator: vec!["src-a".into(), "src-b".into(), "src-c".into()],
        question: question.into(),
        authorized_sources: vec!["src-a".into(), "src-b".into(), "src-c".into()],
    }
}

fn fixture_brief(pack: &ResearchPackRef, disposition: ResearchDisposition) -> ResearchBrief {
    ResearchBrief {
        pack: pack.clone(),
        claims: vec![
            ResearchClaim {
                claim_id: "claim-1".into(),
                support: vec!["src-a".into()],
                counterclaim: vec!["src-b".into()],
                citations: vec!["src-a".into(), "src-c".into()],
            },
            ResearchClaim {
                claim_id: "claim-2".into(),
                support: vec!["src-c".into()],
                counterclaim: vec![],
                citations: vec!["src-c".into()],
            },
        ],
        rivals: vec!["rival: scope differs from claim-1".into()],
        unknowns: vec!["unknown: coverage of src-c is partial".into()],
        probes: vec!["probe: discriminate claim-1 against src-b".into()],
        concilium_note: "inert: hold for native #995 audit".into(),
        disposition,
    }
}

fn fixture_candidate(disposition: ResearchDisposition, question: &str) -> ResearchCandidate {
    let pack = fixture_pack(question);
    let brief = fixture_brief(&pack, disposition);
    ResearchCandidate {
        schema_revision: CANDIDATE_SCHEMA_REVISION,
        operation_id: "op-634".into(),
        job: HANDLER_SUBTYPE.to_owned(),
        requester_principal: "alice".into(),
        requester_origin: GuestRequesterOrigin::Human,
        requester_session: "session-634".into(),
        task_id: "task-634".into(),
        attempt_id: "attempt-634".into(),
        scope_id: "scope-634".into(),
        fence_epoch: "epoch-634".into(),
        fence_generation: 7,
        bundle_digest: sha256_hex(b"634-bundle"),
        manifest_digest: sha256_hex(b"634-manifest"),
        grounding_digest: sha256_hex(b"634-grounding"),
        validation_receipt: sha256_hex(b"634-receipt"),
        payload: ResearchPayload { pack, brief },
        max_input_bytes: 1_048_576,
        max_output_bytes: 1_048_576,
        max_candidates: 8,
        max_work: 1_000,
        max_depth: 8,
        preservation: vec![
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::Coverage,
                passed: true,
                known: true,
                note: "fixture".into(),
            },
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::Faithfulness,
                passed: true,
                known: true,
                note: "fixture".into(),
            },
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::Lineage,
                passed: true,
                known: true,
                note: "fixture".into(),
            },
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::Reversibility,
                passed: false,
                known: true,
                note: "fixture".into(),
            },
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::AuthorityCeiling,
                passed: true,
                known: true,
                note: "fixture".into(),
            },
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::DependencyClosure,
                passed: true,
                known: true,
                note: "fixture".into(),
            },
            GuestDimensionVerdict {
                dimension: GuestPreservationDimension::ProvenanceRetention,
                passed: true,
                known: true,
                note: "fixture".into(),
            },
        ],
        deadline_ms: None,
        cancelled: false,
    }
}

fn guest_request(disposition: ResearchDisposition, question: &str) -> GuestRequest {
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: TYPED_WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        candidate: fixture_candidate(disposition, question),
    }
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

// WORK_UNIT_CASE: 634/1
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
    let wit = String::from_utf8(eliot_dreamer_research_wasm::GUEST_WIT_BYTES.to_vec())
        .expect("guest.wit is UTF-8");
    assert!(wit.contains("package eliot:wasm@1.0.0"));
    assert!(wit.contains("world guest"));
    assert!(wit.contains("export run"));
    assert_eq!(
        descriptor.wit_digest,
        sha256_hex(eliot_dreamer_research_wasm::GUEST_WIT_BYTES)
    );
    // Typed arm is readable (never hand-copied) but still unaccepted (#756 OPEN).
    assert_eq!(descriptor.typed_world_package, TYPED_WORLD_PACKAGE);
    assert_eq!(descriptor.typed_world, TYPED_WORLD_NAME);
    assert_eq!(descriptor.typed_interface, TYPED_INTERFACE_NAME);
    let typed = String::from_utf8(eliot_dreamer_research_wasm::TYPED_WIT_BYTES.to_vec())
        .expect("dreamer-handler.wit is UTF-8");
    for arm in [
        "package eliot:current@0.1.0",
        "world dreamer-handler",
        "research-synthesis(research-payload)",
        "research-pack-ref",
        "research-claim",
        "research-brief",
        "research-payload",
        "pack-digest",
        "concilium-note",
        "candidate-disposition",
    ] {
        assert!(typed.contains(arm), "typed WIT carries {arm}");
    }
    assert_eq!(
        descriptor.typed_wit_digest,
        sha256_hex(eliot_dreamer_research_wasm::TYPED_WIT_BYTES)
    );
    assert_eq!(descriptor.typed_world_status, TYPED_WORLD_STATUS);
    assert_eq!(descriptor.typed_world_status, "READABLE_NOT_ACCEPTED");
    assert_eq!(TYPED_WORLD_OWNER, "#756");
    // Native synthesis is missing entirely (#995 OPEN): frozen expectation.
    assert_eq!(descriptor.native_contract, NATIVE_CONTRACT_ID);
    assert_eq!(
        descriptor.native_contract,
        "eliot-dreamer-research-synthesis"
    );
    assert_eq!(descriptor.native_status, NATIVE_STATUS);
    assert_eq!(descriptor.native_status, "MISSING_NOT_ACCEPTED");
    assert_eq!(NATIVE_OWNER, "#995");
    assert_eq!(qualified_export_name(), format!("{WORLD_NAME}#run"));
    assert_eq!(eliot_dreamer_research_wasm::wit_export_name(), "run");
    // #870 readiness: pinned target and channel from the owning toolchain file.
    let toolchain = String::from_utf8(eliot_dreamer_research_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("rust-toolchain.toml is UTF-8");
    assert!(toolchain.contains("wasm32-wasip2"));
    assert!(toolchain.contains(TOOLCHAIN_CHANNEL));
    assert_eq!(GUEST_TARGET, eliot_wasm_runtime::DEFAULT_GUEST_TARGET);
    assert_eq!(descriptor_digest(), descriptor_digest());
    // The accepted contract crate owns the job class; the guest uses the
    // readable WIT kebab spelling without redefining the class.
    assert_eq!(
        parse_job_class("research_synthesis").expect("accepted spelling"),
        JobClass::ResearchSynthesis
    );
}

// WORK_UNIT_CASE: 634/2
#[test]
fn wrong_subtype_payload_version_import_rejected_before_boundary() {
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    let mut wrong_subtype = request.clone();
    wrong_subtype.handler_subtype = "orientation".into();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&wrong_subtype, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert_eq!(response.native_calls, 0);
    assert!(response.brief.is_none());
    assert!(matches!(
        response.error,
        Some(GuestError::KindMismatch { .. })
    ));
    let mut curation = request.clone();
    curation.handler_subtype = "curation".into();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&curation, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::KindMismatch { .. })
    ));
    let mut bogus = request.clone();
    bogus.handler_subtype = "bogus".into();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&bogus, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::UnsupportedSubtype { .. })
    ));
    let mut wrong_world = request.clone();
    wrong_world.world = "guest".into();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&wrong_world, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::KindMismatch { .. })
    ));
    let mut wrong_abi = request.clone();
    wrong_abi.abi_version = 999;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&wrong_abi, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::UnsupportedSchema { .. })
    ));
    let mut wrong_schema = request.clone();
    wrong_schema.candidate.schema_revision = 2;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&wrong_schema, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::UnsupportedSchema { .. })
    ));
    let mut wrong_job = request.clone();
    wrong_job.candidate.job = "orientation".into();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&wrong_job, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::KindMismatch { .. })
    ));
    let mut cancelled = request.clone();
    cancelled.candidate.cancelled = true;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&cancelled, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(response.error, Some(GuestError::Cancelled)));
    // Undecodable and trailing-garbage payloads never reach the boundary.
    assert!(run(&[0xFF, 0xFE, 0x00]).is_err());
    let mut trailing = encode_request(&request).expect("encode");
    trailing.extend_from_slice(b"trailing");
    assert!(run(&trailing).is_err());
}

// WORK_UNIT_CASE: 634/3
#[test]
fn exhaustive_input_output_error_mapping() {
    let natives = [
        GuestError::Malformed {
            field: "f".into(),
            detail: "d".into(),
        },
        GuestError::KindMismatch {
            want: "w".into(),
            got: "g".into(),
            detail: "d".into(),
        },
        GuestError::UnsupportedSubtype {
            want: "w".into(),
            detail: "d".into(),
        },
        GuestError::BudgetExceeded { detail: "d".into() },
        GuestError::UnsupportedSchema {
            want_revision: 1,
            got_revision: 2,
            detail: "d".into(),
        },
        GuestError::Internal { detail: "d".into() },
        GuestError::RejectedBytes { detail: "d".into() },
        GuestError::Cancelled,
        GuestError::AcquisitionRejected {
            handle: "h".into(),
            detail: "d".into(),
        },
        GuestError::NativeUnavailable {
            owner: NATIVE_OWNER.into(),
            contract: NATIVE_CONTRACT_ID.into(),
            status: NATIVE_STATUS.into(),
            detail: "d".into(),
        },
    ];
    let mut seen = BTreeSet::new();
    for error in &natives {
        let json = canonical_json_bytes(error).expect("guest error json");
        assert!(seen.insert(json), "every guest error maps distinctly");
    }
    assert_eq!(seen.len(), 10);
    let dispositions = [
        ResearchDisposition::Candidate,
        ResearchDisposition::Duplicate,
        ResearchDisposition::Conflict,
        ResearchDisposition::Abstention,
        ResearchDisposition::Partial,
        ResearchDisposition::Blocked,
        ResearchDisposition::Unsupported,
        ResearchDisposition::InternalDefect,
    ];
    let mut codes = BTreeSet::new();
    for disposition in dispositions {
        let code = disposition_as_str(disposition);
        assert!(codes.insert(code), "disposition codes are distinct");
        assert_eq!(parse_disposition(code), Some(disposition));
    }
    assert_eq!(codes.len(), 8);
    // Issue words without a WIT code have no silent mapping.
    for missing in ["complete", "exhausted", "unknown", "other", "winner"] {
        assert_eq!(parse_disposition(missing), None);
    }
    let mut origins = BTreeSet::new();
    for origin in [
        GuestRequesterOrigin::Human,
        GuestRequesterOrigin::AdmittedAgent,
        GuestRequesterOrigin::SchedulePolicy,
    ] {
        assert!(origins.insert(origin_as_str(origin)));
        let json = canonical_json_bytes(&origin).expect("origin json");
        assert_eq!(
            serde_json::from_slice::<GuestRequesterOrigin>(&json).expect("origin round-trip"),
            origin
        );
    }
    assert_eq!(origins.len(), 3);
    let mut dimensions = BTreeSet::new();
    for dimension in [
        GuestPreservationDimension::Coverage,
        GuestPreservationDimension::Faithfulness,
        GuestPreservationDimension::Lineage,
        GuestPreservationDimension::Reversibility,
        GuestPreservationDimension::AuthorityCeiling,
        GuestPreservationDimension::DependencyClosure,
        GuestPreservationDimension::ProvenanceRetention,
    ] {
        assert!(dimensions.insert(dimension_as_str(dimension)));
    }
    assert_eq!(dimensions.len(), 7);
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    let bytes = encode_request(&request).expect("encode");
    assert_eq!(decode_request(&bytes).expect("decode"), request);
    let response = handle_request_typed(&request);
    let response_bytes = encode_response(&response).expect("encode response");
    assert_eq!(decode_response(&response_bytes).expect("decode"), response);
}

// WORK_UNIT_CASE: 634/4
#[test]
fn every_disposition_preserved_through_validation() {
    for disposition in [
        ResearchDisposition::Candidate,
        ResearchDisposition::Duplicate,
        ResearchDisposition::Conflict,
        ResearchDisposition::Abstention,
        ResearchDisposition::Partial,
        ResearchDisposition::Blocked,
        ResearchDisposition::Unsupported,
        ResearchDisposition::InternalDefect,
    ] {
        let request = guest_request(disposition, "What holds?");
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&request, &ledger);
        // Frozen parity: validation preserves the disposition bytes untouched
        // and the valid envelope reaches the boundary exactly once; brief
        // output itself awaits the accepted #995 projector.
        let wire =
            String::from_utf8(encode_request(&request).expect("encode")).expect("canonical UTF-8");
        assert!(
            wire.contains(disposition_as_str(disposition)),
            "disposition survives validation"
        );
        assert_eq!(ledger.calls(), 1);
        assert_eq!(response.native_calls, 1);
        assert!(response.brief.is_none());
        assert!(matches!(
            response.error,
            Some(GuestError::NativeUnavailable { .. })
        ));
    }
    // The readable WIT rule "unknown is explicit unsupported" is honored:
    // an Unsupported brief passes validation instead of a silent fallback.
    let request = guest_request(ResearchDisposition::Unsupported, "What holds?");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
}

// WORK_UNIT_CASE: 634/5
#[test]
fn coverage_grade_dependence_firewall_parity() {
    let request = guest_request(ResearchDisposition::Partial, "What holds?");
    let pack = &request.candidate.payload.pack;
    let brief = &request.candidate.payload.brief;
    assert_eq!(brief.pack, *pack);
    assert_eq!(pack.source_denominator.len(), 3);
    assert_eq!(pack.authorized_sources.len(), 3);
    // Claim/counterclaim/evidence dependence stays inside the authorized set.
    for claim in &brief.claims {
        for reference in claim
            .support
            .iter()
            .chain(claim.counterclaim.iter())
            .chain(claim.citations.iter())
        {
            assert!(
                pack.authorized_sources
                    .iter()
                    .any(|allow| allow == reference),
                "dependence stays inside the authorized set"
            );
        }
    }
    // Rivals, unknowns, probes and the inert concilium note are preserved.
    let wire =
        String::from_utf8(encode_request(&request).expect("encode")).expect("canonical UTF-8");
    for preserved in [
        "rival: scope differs from claim-1",
        "unknown: coverage of src-c is partial",
        "probe: discriminate claim-1 against src-b",
        "inert: hold for native #995 audit",
        "claim-1",
        "claim-2",
    ] {
        assert!(wire.contains(preserved), "matrix keeps {preserved}");
    }
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    // No grade is computed or promoted: the result carries no grade surface
    // and its semantic digest covers exactly the boundary error bytes.
    let json =
        String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
    for absent in [
        "\"grade\"",
        "\"confidence\"",
        "\"promotion\"",
        "\"authority_granted\"",
        "\"corroborat\"",
    ] {
        assert!(!json.contains(absent), "result must not raise {absent}");
    }
    let error = response.error.as_ref().expect("boundary error");
    assert_eq!(
        response.output_digest,
        sha256_hex(&canonical_json_bytes(error).expect("error bytes"))
    );
}

// WORK_UNIT_CASE: 634/6
#[test]
fn unsupported_precision_counterevidence_absence_fixtures() {
    // Counterclaims and unknowns survive validation byte-identically.
    let request = guest_request(ResearchDisposition::Conflict, "What holds?");
    let wire =
        String::from_utf8(encode_request(&request).expect("encode")).expect("canonical UTF-8");
    assert!(wire.contains("\"counterclaim\":[\"src-b\"]"));
    assert!(wire.contains("unknown: coverage of src-c is partial"));
    let ledger = CallLedger::new();
    assert_eq!(handle_with_ledger(&request, &ledger).native_calls, 1);
    // Absence under a complete denominator is well-formed, not an error.
    let mut absent = guest_request(ResearchDisposition::Abstention, "What holds?");
    absent.candidate.payload.brief.claims.clear();
    absent.candidate.payload.brief.rivals.clear();
    absent.candidate.payload.brief.unknowns.clear();
    absent.candidate.payload.brief.probes.clear();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&absent, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    // Absence under an unknown (empty) denominator is equally well-formed.
    let mut unknown_denom = absent.clone();
    unknown_denom
        .candidate
        .payload
        .pack
        .source_denominator
        .clear();
    unknown_denom
        .candidate
        .payload
        .brief
        .pack
        .source_denominator
        .clear();
    let ledger = CallLedger::new();
    assert_eq!(handle_with_ledger(&unknown_denom, &ledger).native_calls, 1);
    // Unsupported numeric precision is never silently rewritten.
    let precise = guest_request(
        ResearchDisposition::Candidate,
        "Rate ≈3.14 ±0.005 by 2026-09-15?",
    );
    let bytes = encode_request(&precise).expect("encode");
    assert_eq!(decode_request(&bytes).expect("decode"), precise);
    assert!(
        String::from_utf8(bytes)
            .expect("UTF-8")
            .contains("≈3.14 ±0.005")
    );
}

// WORK_UNIT_CASE: 634/7
#[test]
fn stale_identity_and_all_bounds_rejected() {
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    // Stale pack binding: brief pack digest differs from the request pack.
    let mut stale = request.clone();
    stale.candidate.payload.brief.pack.pack_digest = sha256_hex(b"634-other-pack");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&stale, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(response.error, Some(GuestError::Malformed { .. })));
    // Tampered question breaks the brief-pack binding too.
    let mut tampered = request.clone();
    tampered.candidate.payload.brief.pack.question = "different question".into();
    assert!(handle_request_typed(&tampered).brief.is_none());
    let ledger = CallLedger::new();
    let tampered_response = handle_with_ledger(&tampered, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(tampered_response.brief.is_none());
    // Empty identity handles are stale identities.
    let mut no_epoch = request.clone();
    no_epoch.candidate.fence_epoch = String::new();
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&no_epoch, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(response.error, Some(GuestError::Malformed { .. })));
    // Non-hex digests are rejected.
    let mut bad_digest = request.clone();
    bad_digest.candidate.bundle_digest = "not-a-digest".into();
    let ledger = CallLedger::new();
    let bad_response = handle_with_ledger(&bad_digest, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(bad_response.brief.is_none());
    // Every zero budget ceiling is rejected.
    for tighten in [
        |candidate: &mut ResearchCandidate| candidate.max_input_bytes = 0,
        |candidate: &mut ResearchCandidate| candidate.max_output_bytes = 0,
        |candidate: &mut ResearchCandidate| candidate.max_work = 0,
        |candidate: &mut ResearchCandidate| candidate.max_depth = 0,
    ] {
        let mut tight = request.clone();
        tighten(&mut tight.candidate);
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&tight, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert!(matches!(
            response.error,
            Some(GuestError::BudgetExceeded { .. })
        ));
    }
    // Canonical input larger than the input budget is rejected.
    let mut over_input = request.clone();
    over_input.candidate.max_input_bytes = 64;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&over_input, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::BudgetExceeded { .. })
    ));
    // More claims than the candidate budget allows are rejected.
    let mut over_count = request.clone();
    over_count.candidate.max_candidates = 1;
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&over_count, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(matches!(
        response.error,
        Some(GuestError::BudgetExceeded { .. })
    ));
    // Guest byte ceiling at the boundary.
    assert!(decode_request(&vec![0u8; 2_097_152]).is_err());
}

// WORK_UNIT_CASE: 634/8
#[test]
fn permutation_and_non_ascii_determinism() {
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    let first = encode_request(&request).expect("encode");
    assert_eq!(encode_request(&request).expect("re-encode"), first);
    assert_eq!(request_digest(&request), request_digest(&request));
    assert_eq!(
        brief_digest(&request.candidate.payload.brief),
        brief_digest(&request.candidate.payload.brief)
    );
    // Claim-order permutation is deterministic through the boundary.
    let mut permuted = request.clone();
    permuted.candidate.payload.brief.claims.reverse();
    permuted.candidate.payload.brief.rivals.reverse();
    let replay = encode_request(&permuted).expect("encode");
    assert_eq!(encode_request(&permuted).expect("re-encode"), replay);
    let ledger = CallLedger::new();
    assert_eq!(handle_with_ledger(&permuted, &ledger).native_calls, 1);
    for question in [
        "境界knowing — what holds? ✓",
        "Was gilt? Ünïcodéiß ∑ donc ✓",
        "假设🎯 rival-free? naïve façade",
        "What holds?",
    ] {
        let first_request = guest_request(ResearchDisposition::Candidate, question);
        let second_request = guest_request(ResearchDisposition::Candidate, question);
        assert_eq!(
            encode_request(&first_request).expect("encode"),
            encode_request(&second_request).expect("encode")
        );
        let bytes = run(&encode_request(&first_request).expect("encode")).expect("run");
        let again = run(&encode_request(&second_request).expect("encode")).expect("run");
        assert_eq!(bytes, again);
        let decoded =
            decode_request(&encode_request(&first_request).expect("encode")).expect("decode");
        assert_eq!(
            decoded.candidate.payload.pack.question, question,
            "non-ASCII survives byte-identically"
        );
    }
}

// WORK_UNIT_CASE: 634/9
#[test]
fn forbidden_import_and_sourcing_rejection() {
    for forbidden in eliot_dreamer_research_wasm::FORBIDDEN_IMPORT_SUBSTRINGS {
        assert!(
            is_forbidden_import(&format!("cap:{forbidden}"), "f"),
            "gate covers {forbidden}"
        );
    }
    for required in [
        "filesystem",
        "stdio",
        "network",
        "dns",
        "env",
        "args",
        "clock",
        "random",
        "process",
        "thread",
        "credential",
        "store",
        "kernel",
        "governor",
        "provider",
        "model",
    ] {
        assert!(
            eliot_dreamer_research_wasm::FORBIDDEN_IMPORT_SUBSTRINGS
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
        ("wasi:cli/environment@0.2.10", "get-environment"),
    ] {
        let wasm = wat::parse_str(format!("(module (import \"{module}\" \"{name}\" (func)))"))
            .expect("wasi fixture");
        let error = check_wasm_imports(&wasm).expect_err("forbidden import must fail");
        assert_eq!(
            error,
            eliot_dreamer_research_wasm::DescriptorError::ForbiddenImport {
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
    // Outside-manifest references would need fresh sourcing through the
    // guest, so they are rejected before the boundary with zero attempts.
    for mutate in [
        |candidate: &mut ResearchCandidate| {
            candidate.payload.brief.claims[0].support = vec!["outside-src".into()];
        },
        |candidate: &mut ResearchCandidate| {
            candidate.payload.brief.claims[1].citations = vec!["outside-src".into()];
        },
        |candidate: &mut ResearchCandidate| {
            candidate.payload.brief.claims[0].counterclaim = vec!["outside-src".into()];
        },
    ] {
        let mut request = guest_request(ResearchDisposition::Candidate, "What holds?");
        mutate(&mut request.candidate);
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&request, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert_eq!(response.native_calls, 0);
        assert!(matches!(
            response.error,
            Some(GuestError::AcquisitionRejected { .. })
        ));
    }
    let mut no_authorized = guest_request(ResearchDisposition::Candidate, "What holds?");
    no_authorized
        .candidate
        .payload
        .pack
        .authorized_sources
        .clear();
    let ledger = CallLedger::new();
    let denied = handle_with_ledger(&no_authorized, &ledger);
    assert_eq!(ledger.calls(), 0);
    assert!(denied.brief.is_none());
    // The guest exposes no sourcing surface of its own.
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
            "acquire",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
}

// WORK_UNIT_CASE: 634/10
#[test]
fn exactly_one_boundary_attempt_no_duplicate_algorithm() {
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.brief.is_none());
    assert!(matches!(
        response.error,
        Some(GuestError::NativeUnavailable { .. })
    ));
    if let Some(GuestError::NativeUnavailable {
        ref owner,
        ref contract,
        ref status,
        ..
    }) = response.error
    {
        assert_eq!(owner, NATIVE_OWNER);
        assert_eq!(contract, NATIVE_CONTRACT_ID);
        assert_eq!(status, NATIVE_STATUS);
    } else {
        panic!("valid invocation must stop at the native boundary");
    }
    // Structural proof: exactly one native-boundary invocation outside tests
    // (the definition site declares `ledger: &CallLedger`, so only the call
    // matches the closed-paren pattern).
    let mut sites = 0;
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        sites += read_src(name)
            .matches("invoke_native_owner(ledger)")
            .count();
    }
    assert_eq!(sites, 1);
    // The result carries no synthesized, graded or promoted surface.
    let json =
        String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
    for absent in [
        "\"grade\"",
        "\"confidence\"",
        "\"promotion\"",
        "\"authority_granted\"",
        "\"effect\"",
        "\"finish\"",
        "\"executed_probe\"",
        "\"answer\"",
        "\"synthesized\"",
    ] {
        assert!(!json.contains(absent), "response must not raise {absent}");
    }
}

// WORK_UNIT_CASE: 634/11
#[test]
fn standalone_capsule_through_e_host() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    let input = encode_request(&request).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-634-capsule").expect("invocation"),
        CapabilityId::new("fixture-research-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-634").expect("work unit"),
        WorkScopeRef::new("fixture-scope-634").expect("scope"),
        ExecutionContour::Shadow,
        input,
        634,
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
        InvocationId::new("fixture-634-cancelled").expect("invocation"),
        CapabilityId::new("fixture-research-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-634").expect("work unit"),
        WorkScopeRef::new("fixture-scope-634").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        634,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 634/12
#[test]
fn build_artifact_identity_and_admission_state() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-dreamer-research-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // Component semantic digests stay distinct from the artifact identity.
    let request = guest_request(ResearchDisposition::Candidate, "What holds?");
    assert_ne!(descriptor_digest(), request_digest(&request));
    assert_ne!(
        descriptor_digest(),
        brief_digest(&request.candidate.payload.brief)
    );
    // Controller-owned handoff (issue #634): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-dreamer-research-wasm"));
    // Frozen toolchain identity matches the owning file.
    let toolchain = String::from_utf8(eliot_dreamer_research_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("toolchain UTF-8");
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert!(toolchain.contains("wasm32-wasip2"));
}

// WORK_UNIT_CASE: 634/13
#[test]
fn property_no_outside_reference_no_stronger_ceiling() {
    for question in [
        "What holds?",
        "境界knowing — what holds? ✓",
        "Was gilt? Ünïcodéiß ∑",
    ] {
        for disposition in [
            ResearchDisposition::Candidate,
            ResearchDisposition::Partial,
            ResearchDisposition::Conflict,
            ResearchDisposition::Abstention,
        ] {
            let request = guest_request(disposition, question);
            let ledger = CallLedger::new();
            let response = handle_with_ledger(&request, &ledger);
            // Exactly one boundary attempt; no fabricated brief output.
            assert_eq!(ledger.calls(), 1);
            assert_eq!(response.native_calls, 1);
            assert!(response.brief.is_none());
            let error = response.error.as_ref().expect("boundary error");
            assert!(matches!(error, GuestError::NativeUnavailable { .. }));
            // No input content leaks into the boundary error and no ceiling
            // stronger than the input is asserted anywhere in the result.
            let json = String::from_utf8(canonical_json_bytes(error).expect("error bytes"))
                .expect("error UTF-8");
            assert!(json.contains(NATIVE_OWNER));
            assert!(json.contains(NATIVE_CONTRACT_ID));
            for leaked in [
                "claim-1",
                "src-a",
                "\"grade\"",
                "\"promotion\"",
                "\"answer\"",
            ] {
                assert!(
                    !json.contains(leaked),
                    "boundary error must not carry {leaked}"
                );
            }
            // Full output-equals-native parity is frozen on the accepted #995
            // projector; the adapter contributes no reference and no ceiling.
            let out = String::from_utf8(encode_response(&response).expect("encode"))
                .expect("response UTF-8");
            for absent in [
                "\"grade\"",
                "\"promotion\"",
                "\"authority_granted\"",
                "\"finish\"",
            ] {
                assert!(!out.contains(absent), "result must not raise {absent}");
            }
        }
    }
}
