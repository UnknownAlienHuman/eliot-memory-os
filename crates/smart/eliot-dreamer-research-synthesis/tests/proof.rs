//! Issue #995 proof matrix: exactly cases 1..24, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_dreamer_research_synthesis::{
    CancellationView, CanonicalWriter, Citation, ClaimDisposition, ClaimKind,
    ConciliumRecommendation, CounterSearchStatus, Counterclaim, DenominatorKind, DraftConcilium,
    DraftUnknown, EvidenceGrade, Freshness, GroundedDraft, InputReceipt, JobBinding, OmissionKind,
    OmittedSource, Precision, PrecisionKind, PreservationDimension, ProbeBasis, ProbeResidueReason,
    RequesterOrigin, ResearchBrief, ResearchPack, RivalStance, SYNTHESIS_JOB_CLASS,
    SYNTHESIS_SCHEMA_REVISION, SourceAuthority, SourceCard, StructuredClaim, StructuredProbe,
    StructuredRival, SynthesisBounds, SynthesisDisposition, SynthesisError, SynthesisOutcome,
    SynthesisPolicy, SynthesisRequest, brief_canonical_len, brief_raw_digest,
    brief_semantic_digest, claim_disposition_as_str, draft_content_digest, evidence_grade_as_str,
    guest_parity_disposition, is_digest, is_handle, is_text, mirror_preservation,
    omission_kind_rank, pack_content_digest, parse_evidence_grade, parse_requester_origin,
    preservation_dimension_as_str, preservation_dimensions, redact_value, request_canonical_len,
    request_digest, requester_origin_as_str, sha256, sha256_hex, source_authority_rank,
    synthesis_disposition_as_str, synthesize, terminal_digest,
};

fn card(
    handle: &str,
    grade: EvidenceGrade,
    authority: SourceAuthority,
    freshness: Freshness,
    lineage: &str,
) -> SourceCard {
    SourceCard {
        handle: handle.to_owned(),
        grade,
        authority,
        freshness,
        competence: format!("competence of {handle}"),
        privacy_class: "internal".to_owned(),
        allowed_use: "brief-use".to_owned(),
        lineage_group: lineage.to_owned(),
        transformed: false,
    }
}

fn cite(handle: &str, precision: Precision, kind: PrecisionKind) -> Citation {
    Citation {
        source_handle: handle.to_owned(),
        precision,
        kind,
    }
}

fn seal(request: &mut SynthesisRequest) {
    request.pack.pack_digest = pack_content_digest(&request.pack);
    request.draft.draft_digest = draft_content_digest(&request.draft);
}

fn base_request() -> SynthesisRequest {
    let mut request = SynthesisRequest {
        schema_revision: SYNTHESIS_SCHEMA_REVISION,
        binding: JobBinding {
            operation_id: "op-995-base".to_owned(),
            job_class: SYNTHESIS_JOB_CLASS.to_owned(),
            idempotency_key: "idem-995-base".to_owned(),
            requester_principal: "alice".to_owned(),
            requester_origin: RequesterOrigin::Human,
            requester_session: "session-995".to_owned(),
            task_id: "task-995".to_owned(),
            attempt_id: "attempt-995-base".to_owned(),
            scope_id: "scope-995".to_owned(),
            fence_epoch: "epoch-995".to_owned(),
            fence_generation: 7,
        },
        pack: ResearchPack {
            pack_digest: String::new(),
            question: "Which handle holds under fence 7?".to_owned(),
            task_id: "task-995".to_owned(),
            scope_id: "scope-995".to_owned(),
            fence_epoch: "epoch-995".to_owned(),
            fence_generation: 7,
            bundle_digest: sha256_hex(b"995-bundle"),
            manifest_digest: sha256_hex(b"995-manifest"),
            sources: vec![
                card(
                    "src-a",
                    EvidenceGrade::E2,
                    SourceAuthority::Competent,
                    Freshness::Fresh,
                    "group-alpha",
                ),
                card(
                    "src-b",
                    EvidenceGrade::E1,
                    SourceAuthority::Limited,
                    Freshness::Fresh,
                    "group-beta",
                ),
                card(
                    "src-c",
                    EvidenceGrade::E3,
                    SourceAuthority::Authoritative,
                    Freshness::Fresh,
                    "group-alpha",
                ),
            ],
            source_denominator: vec!["src-a".to_owned(), "src-b".to_owned(), "src-c".to_owned()],
            coverage_denominator: DenominatorKind::CompleteScope,
            counter_search: CounterSearchStatus::Complete,
            missing_source_classes: Vec::new(),
            omitted_sources: Vec::new(),
        },
        draft: GroundedDraft {
            draft_digest: String::new(),
            grounding_digest: sha256_hex(b"995-grounding"),
            task_id: "task-995".to_owned(),
            scope_id: "scope-995".to_owned(),
            question: "Which handle holds under fence 7?".to_owned(),
            claims: vec![
                StructuredClaim {
                    claim_id: "claim-1".to_owned(),
                    kind: ClaimKind::Factual,
                    statement: "Handle H holds.".to_owned(),
                    support: vec![
                        cite("src-a", Precision::Exact, PrecisionKind::Documentary),
                        cite("src-c", Precision::Exact, PrecisionKind::Documentary),
                    ],
                    counterclaims: vec![Counterclaim {
                        counterclaim_id: "cc-1".to_owned(),
                        kind: ClaimKind::Factual,
                        source_handle: "src-b".to_owned(),
                        citations: vec![cite(
                            "src-b",
                            Precision::Exact,
                            PrecisionKind::Documentary,
                        )],
                        statement: "Handle H wobbles under load.".to_owned(),
                    }],
                    grounded_relation: false,
                    scope_note: "as stated, no wider scope".to_owned(),
                },
                StructuredClaim {
                    claim_id: "claim-2".to_owned(),
                    kind: ClaimKind::Factual,
                    statement: "Handle K is parked.".to_owned(),
                    support: vec![cite("src-c", Precision::Exact, PrecisionKind::Documentary)],
                    counterclaims: Vec::new(),
                    grounded_relation: false,
                    scope_note: "as stated".to_owned(),
                },
            ],
            rivals: vec![StructuredRival {
                rival_id: "rival-1".to_owned(),
                position: "Alternative framing of H.".to_owned(),
                stance: RivalStance::Alternative,
                target_claim: "claim-1".to_owned(),
                minority: true,
                evidence: vec![cite("src-b", Precision::Exact, PrecisionKind::Documentary)],
            }],
            unknowns: vec![DraftUnknown {
                unknown_id: "u-1".to_owned(),
                detail: "Coverage window of src-c.".to_owned(),
            }],
            probes: vec![StructuredProbe {
                probe_id: "probe-1".to_owned(),
                basis: ProbeBasis::SuppliedDiscriminative,
                discriminates: vec!["rival-1".to_owned(), "u-1".to_owned()],
                outcomes: vec!["H holds".to_owned(), "H fails".to_owned()],
                verifier: "verifier-1".to_owned(),
                owner: "owner-1".to_owned(),
                cost_class: "low".to_owned(),
                applicability: "while fence 7 stands".to_owned(),
            }],
            concilium: DraftConcilium {
                owner: "governor".to_owned(),
                evidence_refs: vec!["src-a".to_owned()],
                positions: vec!["Framing of H stands.".to_owned()],
                review_objective: "Review the candidate brief for fence 7.".to_owned(),
            },
        },
        receipt: InputReceipt {
            receipt_digest: sha256_hex(b"995-receipt"),
            task_id: "task-995".to_owned(),
            scope_id: "scope-995".to_owned(),
            fence_epoch: "epoch-995".to_owned(),
            fence_generation: 7,
            bundle_digest: sha256_hex(b"995-bundle"),
            manifest_digest: sha256_hex(b"995-manifest"),
            grounding_digest: sha256_hex(b"995-grounding"),
            validator_revision: "validator-3".to_owned(),
        },
        policy: SynthesisPolicy {
            policy_digest: sha256_hex(b"995-policy"),
            revision: "policy-1".to_owned(),
            valid_through_generation: 9,
            allow_partial: true,
            authorize_supplied_discriminative: true,
            probe_allowlist: Vec::new(),
            canonical_transforms: Vec::new(),
            concilium_allowed: true,
            freshness_floor: Freshness::Fresh,
        },
        bounds: SynthesisBounds {
            max_input_bytes: 1_048_576,
            max_output_bytes: 1_048_576,
            max_claims: 8,
            max_rivals: 8,
            max_references: 64,
            max_probes: 8,
            max_work: 100_000,
        },
        cancellation: CancellationView {
            cancelled: false,
            now_ms: None,
            deadline_ms: None,
        },
    };
    seal(&mut request);
    request
}

fn run(request: &SynthesisRequest) -> SynthesisOutcome {
    synthesize(request).expect("valid fixture must synthesize")
}

fn brief_of(outcome: &SynthesisOutcome) -> &ResearchBrief {
    outcome.brief.as_ref().expect("brief must exist")
}

fn verdict<'a>(
    brief: &'a ResearchBrief,
    id: &str,
) -> &'a eliot_dreamer_research_synthesis::ClaimVerdict {
    brief
        .claim_matrix
        .iter()
        .find(|row| row.claim_id == id)
        .unwrap_or_else(|| panic!("missing verdict {id}"))
}

// WORK_UNIT_CASE: 995/1
#[test]
fn valid_minimal_pack_to_brief() {
    let request = base_request();
    let outcome = run(&request);
    assert_eq!(outcome.disposition, SynthesisDisposition::Complete);
    let brief = brief_of(&outcome);
    assert_eq!(brief.disposition, SynthesisDisposition::Complete);
    assert_eq!(brief.pack_digest, request.pack.pack_digest);
    assert_eq!(brief.question, request.pack.question);
    assert_eq!(brief.claim_matrix.len(), 3);
    let first = verdict(brief, "claim-1");
    assert_eq!(first.disposition, ClaimDisposition::Contested);
    assert!(!first.is_counterclaim);
    assert_eq!(first.support, vec!["src-a".to_owned(), "src-c".to_owned()]);
    assert_eq!(first.counter_evidence, vec!["src-b".to_owned()]);
    assert_eq!(first.weakest_grade, EvidenceGrade::E2);
    assert_eq!(first.authority, SourceAuthority::Competent);
    let counter = verdict(brief, "cc-1");
    assert!(counter.is_counterclaim);
    assert_eq!(counter.disposition, ClaimDisposition::Supported);
    let second = verdict(brief, "claim-2");
    assert_eq!(second.disposition, ClaimDisposition::Supported);
    assert_eq!(second.weakest_grade, EvidenceGrade::E3);
    assert_eq!(second.authority, SourceAuthority::Authoritative);
    assert_eq!(brief.probes.len(), 1);
    assert_eq!(brief.probes[0].probe_id, "probe-1");
    assert_eq!(brief.concilium.effect_count, 0);
    assert_eq!(brief.concilium.owner, "governor");
    assert!(!brief.concilium.suppressed);
    assert_eq!(
        brief.coverage.represented_sources,
        vec!["src-a".to_owned(), "src-b".to_owned(), "src-c".to_owned()]
    );
    assert_eq!(outcome.input_digest, request_digest(&request));
    assert_eq!(outcome.output_digest, brief.semantic_digest);
    assert_eq!(outcome.inherited_receipt, request.receipt);
    assert_eq!(brief.raw_digest, brief_raw_digest(brief));
    assert_eq!(brief.semantic_digest, brief_semantic_digest(brief));
    assert!(outcome.work_used > 0);
    assert!(brief.brief_id.starts_with("brief-"));
}

// WORK_UNIT_CASE: 995/2
#[test]
fn wrong_job_profile_schema_rejected() {
    let mut wrong_job = base_request();
    wrong_job.binding.job_class = "orientation".to_owned();
    assert!(matches!(
        synthesize(&wrong_job),
        Err(SynthesisError::KindMismatch { .. })
    ));
    let mut unknown_job = base_request();
    unknown_job.binding.job_class = "dream-teleport".to_owned();
    assert!(matches!(
        synthesize(&unknown_job),
        Err(SynthesisError::KindMismatch { .. })
    ));
    let mut wrong_schema = base_request();
    wrong_schema.schema_revision = 99;
    assert!(matches!(
        synthesize(&wrong_schema),
        Err(SynthesisError::UnsupportedSchema { .. })
    ));
    assert_eq!(parse_requester_origin("machine-ghost"), None);
    assert_eq!(parse_evidence_grade("E7"), None);
    assert_eq!(
        requester_origin_as_str(RequesterOrigin::SchedulePolicy),
        "schedule-policy"
    );
}

// WORK_UNIT_CASE: 995/3
#[test]
fn binding_mismatches_fail_closed() {
    let mut task = base_request();
    task.draft.task_id = "task-other".to_owned();
    seal(&mut task);
    assert!(matches!(
        synthesize(&task),
        Err(SynthesisError::ReferenceMismatch { .. })
    ));
    let mut scope = base_request();
    scope.pack.scope_id = "scope-other".to_owned();
    seal(&mut scope);
    assert!(matches!(
        synthesize(&scope),
        Err(SynthesisError::ReferenceMismatch { .. })
    ));
    let mut fence = base_request();
    fence.binding.fence_generation = 8;
    assert!(matches!(
        synthesize(&fence),
        Err(SynthesisError::ReferenceMismatch { .. })
    ));
    let mut question = base_request();
    question.draft.question = "Another question?".to_owned();
    seal(&mut question);
    assert!(matches!(
        synthesize(&question),
        Err(SynthesisError::ReferenceMismatch { .. })
    ));
    let mut bundle = base_request();
    bundle.receipt.bundle_digest = sha256_hex(b"other-bundle");
    assert!(matches!(
        synthesize(&bundle),
        Err(SynthesisError::ReferenceMismatch { .. })
    ));
    let mut forged = base_request();
    forged.pack.pack_digest = "f".repeat(64);
    assert!(matches!(
        synthesize(&forged),
        Err(SynthesisError::ReferenceMismatch { .. })
    ));
}

// WORK_UNIT_CASE: 995/4
#[test]
fn duplicate_ids_collapse_or_fail() {
    let mut changed = base_request();
    let mut repeat = changed.draft.claims[1].clone();
    repeat.statement = "Handle K is retired.".to_owned();
    changed.draft.claims.push(repeat);
    seal(&mut changed);
    assert!(matches!(
        synthesize(&changed),
        Err(SynthesisError::Malformed { .. })
    ));
    let mut identical = base_request();
    identical
        .draft
        .claims
        .push(identical.draft.claims[1].clone());
    seal(&mut identical);
    let outcome = run(&identical);
    assert_eq!(outcome.disposition, SynthesisDisposition::Partial);
    let brief = brief_of(&outcome);
    assert_eq!(brief.claim_matrix.len(), 4);
    let dupe = verdict(brief, "claim-2");
    assert_eq!(
        brief
            .claim_matrix
            .iter()
            .filter(|row| row.claim_id == "claim-2"
                && row.disposition == ClaimDisposition::DuplicateCollapsed)
            .count(),
        1
    );
    assert_eq!(dupe.disposition, ClaimDisposition::Supported);
}

// WORK_UNIT_CASE: 995/5
#[test]
fn every_material_input_has_one_disposition() {
    let request = base_request();
    let outcome = run(&request);
    let brief = brief_of(&outcome);
    let mut expected = vec!["claim-1", "cc-1", "claim-2"];
    expected.sort_unstable();
    let mut observed: Vec<&str> = brief
        .claim_matrix
        .iter()
        .map(|row| row.claim_id.as_str())
        .collect();
    observed.sort_unstable();
    assert_eq!(observed, expected);
    assert!(
        brief
            .claim_matrix
            .iter()
            .all(|row| { !claim_disposition_as_str(row.disposition).is_empty() })
    );
    assert_eq!(
        brief
            .claim_matrix
            .iter()
            .filter(|row| row.is_counterclaim)
            .count(),
        1
    );
}

// WORK_UNIT_CASE: 995/6
#[test]
fn outside_manifest_references_rejected() {
    let mut ghost = base_request();
    ghost.draft.claims[0].support.push(cite(
        "src-ghost",
        Precision::Exact,
        PrecisionKind::Documentary,
    ));
    seal(&mut ghost);
    match synthesize(&ghost) {
        Err(SynthesisError::AcquisitionRejected { handle, .. }) => {
            assert!(handle.contains("src-ghost"));
        }
        other => panic!("expected firewall rejection, got {other:?}"),
    }
    let mut concilium_ghost = base_request();
    concilium_ghost.draft.concilium.evidence_refs = vec!["src-ghost".to_owned()];
    match synthesize(&concilium_ghost) {
        Err(SynthesisError::AcquisitionRejected { handle, .. }) => {
            assert!(handle.contains("src-ghost"));
        }
        other => panic!("expected concilium firewall rejection, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 995/7
#[test]
fn repetition_cannot_inflate_grade_or_coverage() {
    let mut request = base_request();
    let mut repeated = Vec::new();
    for _ in 0..5 {
        repeated.push(cite("src-a", Precision::Exact, PrecisionKind::Documentary));
    }
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-3".to_owned(),
        kind: ClaimKind::Factual,
        statement: "Handle H holds repeatedly.".to_owned(),
        support: repeated,
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as stated".to_owned(),
    });
    seal(&mut request);
    let outcome = run(&request);
    let brief = brief_of(&outcome);
    let third = verdict(brief, "claim-3");
    assert_eq!(third.support, vec!["src-a".to_owned()]);
    assert_eq!(third.weakest_grade, EvidenceGrade::E2);
    let alpha = brief
        .dependence
        .iter()
        .find(|group| group.lineage_group == "group-alpha")
        .expect("alpha group");
    assert_eq!(alpha.independent_roots, 2);
    assert!(alpha.members.contains(&"src-a".to_owned()));
    let cited_once = brief
        .coverage
        .cited_sources
        .iter()
        .filter(|handle| handle.as_str() == "src-a")
        .count();
    assert_eq!(cited_once, 1);
}

// WORK_UNIT_CASE: 995/8
#[test]
fn unknown_independence_stays_unknown() {
    let mut request = base_request();
    request.pack.sources.push(card(
        "src-u",
        EvidenceGrade::E1,
        SourceAuthority::Unknown,
        Freshness::Fresh,
        "unknown",
    ));
    request.pack.source_denominator.push("src-u".to_owned());
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-4".to_owned(),
        kind: ClaimKind::Factual,
        statement: "Handle Z flickers.".to_owned(),
        support: vec![cite("src-u", Precision::Exact, PrecisionKind::Documentary)],
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as stated".to_owned(),
    });
    seal(&mut request);
    let outcome = run(&request);
    assert_eq!(outcome.disposition, SynthesisDisposition::Partial);
    let brief = brief_of(&outcome);
    let fourth = verdict(brief, "claim-4");
    assert!(fourth.lineage_groups.contains(&"unknown".to_owned()));
    let unknown_group = brief
        .dependence
        .iter()
        .find(|group| group.unknown)
        .expect("unknown group retained");
    assert_eq!(unknown_group.lineage_group, "unknown");
    assert!(unknown_group.members.contains(&"src-u".to_owned()));
    let lineage = outcome
        .preservation
        .iter()
        .find(|row| row.dimension == PreservationDimension::Lineage)
        .expect("lineage verdict");
    assert!(!lineage.known);
}

// WORK_UNIT_CASE: 995/9
#[test]
fn weakest_grade_and_claim_authority() {
    let mut request = base_request();
    request.draft.claims[1].support = vec![
        cite("src-b", Precision::Exact, PrecisionKind::Documentary),
        cite("src-c", Precision::Exact, PrecisionKind::Documentary),
    ];
    seal(&mut request);
    let outcome = run(&request);
    let brief = brief_of(&outcome);
    let second = verdict(brief, "claim-2");
    assert_eq!(second.disposition, ClaimDisposition::Supported);
    assert_eq!(second.weakest_grade, EvidenceGrade::E1);
    assert_eq!(second.authority, SourceAuthority::Limited);
    let mut withheld = base_request();
    let mut denied = card(
        "src-w",
        EvidenceGrade::E3,
        SourceAuthority::Authoritative,
        Freshness::Fresh,
        "group-beta",
    );
    denied.privacy_class = "deny-brief".to_owned();
    withheld.pack.sources.push(denied);
    withheld.pack.source_denominator.push("src-w".to_owned());
    withheld.draft.claims.push(StructuredClaim {
        claim_id: "claim-w".to_owned(),
        kind: ClaimKind::Factual,
        statement: "Sealed handle W holds.".to_owned(),
        support: vec![cite("src-w", Precision::Exact, PrecisionKind::Documentary)],
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as stated".to_owned(),
    });
    seal(&mut withheld);
    let denied_outcome = run(&withheld);
    assert_eq!(denied_outcome.disposition, SynthesisDisposition::Partial);
    let denied_brief = brief_of(&denied_outcome);
    assert_eq!(
        verdict(denied_brief, "claim-w").disposition,
        ClaimDisposition::Withheld
    );
}

// WORK_UNIT_CASE: 995/10
#[test]
fn stale_or_transformed_evidence_cannot_raise_precision() {
    let mut stale = base_request();
    stale.pack.sources[1].freshness = Freshness::Stale;
    stale.policy.freshness_floor = Freshness::Stale;
    seal(&mut stale);
    let stale_outcome = run(&stale);
    let stale_brief = brief_of(&stale_outcome);
    let counter = verdict(stale_brief, "cc-1");
    assert_eq!(counter.disposition, ClaimDisposition::Supported);
    assert!(
        counter
            .precision_notes
            .iter()
            .any(|note| note.contains("capped to qualified"))
    );
    let mut shifted = base_request();
    shifted.pack.sources[0].transformed = true;
    seal(&mut shifted);
    let shifted_outcome = run(&shifted);
    let shifted_brief = brief_of(&shifted_outcome);
    assert!(
        verdict(shifted_brief, "claim-1")
            .precision_notes
            .iter()
            .any(|note| note.contains("capped to qualified"))
    );
    let mut unknown_fresh = base_request();
    unknown_fresh.pack.sources[0].freshness = Freshness::Unknown;
    unknown_fresh.policy.freshness_floor = Freshness::Unknown;
    seal(&mut unknown_fresh);
    let unknown_outcome = run(&unknown_fresh);
    let unknown_brief = brief_of(&unknown_outcome);
    assert!(
        verdict(unknown_brief, "claim-1")
            .precision_notes
            .iter()
            .any(|note| note.contains("capped to qualified"))
    );
}

// WORK_UNIT_CASE: 995/11
#[test]
fn numeric_time_version_precision() {
    let mut request = base_request();
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-n".to_owned(),
        kind: ClaimKind::Numeric,
        statement: "Latency is 12ms.".to_owned(),
        support: vec![cite(
            "src-a",
            Precision::Unsupported,
            PrecisionKind::Numeric,
        )],
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as measured".to_owned(),
    });
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-t".to_owned(),
        kind: ClaimKind::Time,
        statement: "Rotation happened at dawn.".to_owned(),
        support: vec![cite("src-b", Precision::Qualified, PrecisionKind::Time)],
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as observed".to_owned(),
    });
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-v".to_owned(),
        kind: ClaimKind::Version,
        statement: "Protocol is at v3.".to_owned(),
        support: vec![cite("src-c", Precision::Exact, PrecisionKind::Version)],
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as released".to_owned(),
    });
    seal(&mut request);
    let outcome = run(&request);
    assert_eq!(outcome.disposition, SynthesisDisposition::Partial);
    let brief = brief_of(&outcome);
    assert_eq!(
        verdict(brief, "claim-n").disposition,
        ClaimDisposition::PrecisionLimited
    );
    assert_eq!(
        verdict(brief, "claim-t").disposition,
        ClaimDisposition::Supported
    );
    assert_eq!(
        verdict(brief, "claim-v").disposition,
        ClaimDisposition::Supported
    );
}

// WORK_UNIT_CASE: 995/12
#[test]
fn causal_claims_need_grounded_relations() {
    let mut request = base_request();
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-c1".to_owned(),
        kind: ClaimKind::Causal,
        statement: "Load causes the wobble.".to_owned(),
        support: vec![cite("src-a", Precision::Exact, PrecisionKind::Causal)],
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as hypothesized".to_owned(),
    });
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-c2".to_owned(),
        kind: ClaimKind::Causal,
        statement: "Heat causes the drift.".to_owned(),
        support: vec![cite("src-c", Precision::Exact, PrecisionKind::Causal)],
        counterclaims: Vec::new(),
        grounded_relation: true,
        scope_note: "as grounded".to_owned(),
    });
    request.draft.claims.push(StructuredClaim {
        claim_id: "claim-c3".to_owned(),
        kind: ClaimKind::Causal,
        statement: "Noise causes the jitter.".to_owned(),
        support: vec![cite("src-c", Precision::Exact, PrecisionKind::Documentary)],
        counterclaims: Vec::new(),
        grounded_relation: true,
        scope_note: "as grounded".to_owned(),
    });
    seal(&mut request);
    let causal_outcome = run(&request);
    let brief = brief_of(&causal_outcome);
    assert_eq!(
        verdict(brief, "claim-c1").disposition,
        ClaimDisposition::PrecisionLimited
    );
    assert_eq!(
        verdict(brief, "claim-c2").disposition,
        ClaimDisposition::Supported
    );
    assert_eq!(
        verdict(brief, "claim-c3").disposition,
        ClaimDisposition::PrecisionLimited
    );
}

// WORK_UNIT_CASE: 995/13
#[test]
fn absence_needs_complete_coverage() {
    let absence = StructuredClaim {
        claim_id: "claim-abs".to_owned(),
        kind: ClaimKind::Absence,
        statement: "No handle Q exists.".to_owned(),
        support: Vec::new(),
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "frozen scope".to_owned(),
    };
    let mut proven = base_request();
    proven.draft.claims.push(absence.clone());
    seal(&mut proven);
    let proven_outcome = run(&proven);
    assert_eq!(proven_outcome.disposition, SynthesisDisposition::Complete);
    assert_eq!(
        verdict(brief_of(&proven_outcome), "claim-abs").disposition,
        ClaimDisposition::AbsentScopeComplete
    );
    let mut sampled = base_request();
    sampled.pack.coverage_denominator = DenominatorKind::Sampled;
    sampled.draft.claims.push(absence.clone());
    seal(&mut sampled);
    let sampled_outcome = run(&sampled);
    assert_eq!(sampled_outcome.disposition, SynthesisDisposition::Partial);
    assert_eq!(
        verdict(brief_of(&sampled_outcome), "claim-abs").disposition,
        ClaimDisposition::AbsentScopeIncomplete
    );
    let mut unsearched = base_request();
    unsearched.pack.counter_search = CounterSearchStatus::NotRun;
    unsearched.draft.claims.push(absence);
    seal(&mut unsearched);
    assert_eq!(
        verdict(brief_of(&run(&unsearched)), "claim-abs").disposition,
        ClaimDisposition::AbsentScopeIncomplete
    );
}

// WORK_UNIT_CASE: 995/14
#[test]
fn rivals_conflicts_minority_retained() {
    let mut request = base_request();
    request.draft.rivals.push(StructuredRival {
        rival_id: "rival-2".to_owned(),
        position: "H holds in every lane.".to_owned(),
        stance: RivalStance::Supports,
        target_claim: "claim-1".to_owned(),
        minority: true,
        evidence: vec![cite("src-c", Precision::Exact, PrecisionKind::Documentary)],
    });
    request.draft.rivals.push(StructuredRival {
        rival_id: "rival-3".to_owned(),
        position: "H holds in no lane.".to_owned(),
        stance: RivalStance::Opposes,
        target_claim: "claim-1".to_owned(),
        minority: false,
        evidence: vec![cite("src-b", Precision::Exact, PrecisionKind::Documentary)],
    });
    seal(&mut request);
    let outcome = run(&request);
    assert_eq!(outcome.disposition, SynthesisDisposition::Conflicted);
    let brief = brief_of(&outcome);
    assert_eq!(brief.rivals.len(), 3);
    assert!(brief.rivals.iter().any(|rival| rival.minority));
    let opposed: Vec<&str> = brief
        .rivals
        .iter()
        .filter(|rival| rival.target_claim == "claim-1")
        .map(|rival| rival.rival_id.as_str())
        .collect();
    assert!(opposed.contains(&"rival-2"));
    assert!(opposed.contains(&"rival-3"));
    assert_eq!(
        verdict(brief, "cc-1").disposition,
        ClaimDisposition::Supported
    );
}

// WORK_UNIT_CASE: 995/15
#[test]
fn missing_classes_and_gaps_visible() {
    let mut request = base_request();
    request.pack.missing_source_classes = vec!["operator-logs: route unavailable".to_owned()];
    request.pack.omitted_sources = vec![OmittedSource {
        handle: "src-d".to_owned(),
        reason: "provider unavailable".to_owned(),
    }];
    seal(&mut request);
    let outcome = run(&request);
    assert_eq!(outcome.disposition, SynthesisDisposition::Partial);
    let brief = brief_of(&outcome);
    assert_eq!(
        brief.coverage.missing_classes,
        vec!["operator-logs: route unavailable".to_owned()]
    );
    assert_eq!(brief.coverage.omitted_sources.len(), 1);
    assert_eq!(brief.coverage.omitted_sources[0].handle, "src-d");
    assert!(
        !brief
            .coverage
            .represented_sources
            .contains(&"src-d".to_owned())
    );
}

// WORK_UNIT_CASE: 995/16
#[test]
fn discriminative_vs_residue_probes() {
    let mut request = base_request();
    request.draft.probes.push(StructuredProbe {
        probe_id: "probe-2".to_owned(),
        basis: ProbeBasis::SuppliedDiscriminative,
        discriminates: vec!["u-1".to_owned()],
        outcomes: vec!["only".to_owned()],
        verifier: "verifier-2".to_owned(),
        owner: "owner-2".to_owned(),
        cost_class: "low".to_owned(),
        applicability: "always".to_owned(),
    });
    request.draft.probes.push(StructuredProbe {
        probe_id: "probe-3".to_owned(),
        basis: ProbeBasis::SuppliedDiscriminative,
        discriminates: vec!["ghost-9".to_owned()],
        outcomes: vec!["yes".to_owned(), "no".to_owned()],
        verifier: "verifier-3".to_owned(),
        owner: "owner-3".to_owned(),
        cost_class: "low".to_owned(),
        applicability: "always".to_owned(),
    });
    request.policy.canonical_transforms = vec!["narrow-scope".to_owned()];
    request.draft.probes.push(StructuredProbe {
        probe_id: "probe-5".to_owned(),
        basis: ProbeBasis::CanonicalTransform("narrow-scope".to_owned()),
        discriminates: vec!["u-1".to_owned()],
        outcomes: vec!["holds".to_owned(), "fails".to_owned()],
        verifier: "verifier-5".to_owned(),
        owner: "owner-5".to_owned(),
        cost_class: "low".to_owned(),
        applicability: "while fence 7 stands".to_owned(),
    });
    seal(&mut request);
    let request_outcome = run(&request);
    let brief = brief_of(&request_outcome);
    let recommended: Vec<&str> = brief
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect();
    assert!(recommended.contains(&"probe-1"));
    assert!(recommended.contains(&"probe-5"));
    let residue = |id: &str| {
        brief
            .probe_residue
            .iter()
            .find(|left| left.probe_id == id)
            .unwrap_or_else(|| panic!("missing residue {id}"))
    };
    assert_eq!(
        residue("probe-2").reason,
        ProbeResidueReason::Nondiscriminative
    );
    assert_eq!(residue("probe-3").reason, ProbeResidueReason::UnknownTarget);
    let mut locked = base_request();
    locked.policy.authorize_supplied_discriminative = false;
    seal(&mut locked);
    let locked_outcome = run(&locked);
    let locked_brief = brief_of(&locked_outcome);
    assert!(locked_brief.probes.is_empty());
    assert_eq!(
        locked_brief.probe_residue[0].reason,
        ProbeResidueReason::Unauthorized
    );
}

// WORK_UNIT_CASE: 995/17
#[test]
fn concilium_is_inert_and_owner_bound() {
    let base = base_request();
    let base_outcome = run(&base);
    let brief = brief_of(&base_outcome);
    let concilium: &ConciliumRecommendation = &brief.concilium;
    assert_eq!(concilium.owner, "governor");
    assert_eq!(concilium.effect_count, 0);
    assert!(!concilium.suppressed);
    assert_eq!(concilium.evidence_refs, vec!["src-a".to_owned()]);
    assert_eq!(
        concilium.review_objective,
        "Review the candidate brief for fence 7."
    );
    let mut suppressed = base_request();
    suppressed.policy.concilium_allowed = false;
    seal(&mut suppressed);
    let quiet = run(&suppressed);
    assert_eq!(quiet.disposition, SynthesisDisposition::Partial);
    let quiet_brief = brief_of(&quiet);
    assert!(quiet_brief.concilium.suppressed);
    assert_eq!(quiet_brief.concilium.effect_count, 0);
    assert!(quiet_brief.concilium.evidence_refs.is_empty());
    assert!(
        quiet
            .omitted
            .iter()
            .any(|omission| omission.kind == OmissionKind::Concilium)
    );
}

// WORK_UNIT_CASE: 995/18
#[test]
fn every_disposition_and_failure_reachable() {
    assert_eq!(
        run(&base_request()).disposition,
        SynthesisDisposition::Complete
    );
    let mut partial = base_request();
    partial.pack.missing_source_classes = vec!["logs: withheld".to_owned()];
    seal(&mut partial);
    assert_eq!(run(&partial).disposition, SynthesisDisposition::Partial);
    let mut exhausted = base_request();
    exhausted.bounds.max_work = 3;
    assert_eq!(run(&exhausted).disposition, SynthesisDisposition::Exhausted);
    let mut abstained = base_request();
    abstained.draft.claims.clear();
    abstained.draft.rivals.clear();
    seal(&mut abstained);
    assert_eq!(run(&abstained).disposition, SynthesisDisposition::Abstained);
    let mut blocked = base_request();
    blocked.cancellation.cancelled = true;
    assert_eq!(run(&blocked).disposition, SynthesisDisposition::Blocked);
    assert!(run(&blocked).brief.is_none());
    let mut unsupported = base_request();
    unsupported.draft.claims.clear();
    unsupported.draft.rivals.clear();
    unsupported.draft.unknowns.clear();
    unsupported.draft.claims.push(StructuredClaim {
        claim_id: "claim-lone".to_owned(),
        kind: ClaimKind::Factual,
        statement: "Nothing backs this.".to_owned(),
        support: Vec::new(),
        counterclaims: Vec::new(),
        grounded_relation: false,
        scope_note: "as stated".to_owned(),
    });
    seal(&mut unsupported);
    assert_eq!(
        run(&unsupported).disposition,
        SynthesisDisposition::Unsupported
    );
    let mut conflicted = base_request();
    conflicted.draft.rivals.push(StructuredRival {
        rival_id: "rival-s".to_owned(),
        position: "H holds.".to_owned(),
        stance: RivalStance::Supports,
        target_claim: "claim-1".to_owned(),
        minority: false,
        evidence: vec![cite("src-a", Precision::Exact, PrecisionKind::Documentary)],
    });
    conflicted.draft.rivals.push(StructuredRival {
        rival_id: "rival-o".to_owned(),
        position: "H fails.".to_owned(),
        stance: RivalStance::Opposes,
        target_claim: "claim-1".to_owned(),
        minority: false,
        evidence: vec![cite("src-b", Precision::Exact, PrecisionKind::Documentary)],
    });
    seal(&mut conflicted);
    assert_eq!(
        run(&conflicted).disposition,
        SynthesisDisposition::Conflicted
    );
    let mut unknown = unsupported.clone();
    unknown.pack.coverage_denominator = DenominatorKind::Unknown;
    seal(&mut unknown);
    assert_eq!(run(&unknown).disposition, SynthesisDisposition::Unknown);
    let mut broken = base_request();
    broken.pack.question = String::new();
    assert!(matches!(
        synthesize(&broken),
        Err(SynthesisError::Malformed { .. })
    ));
}

// WORK_UNIT_CASE: 995/19
#[test]
fn every_bound_holds_one_over_with_denominator() {
    let mut claims = base_request();
    claims.bounds.max_claims = 1;
    let cut = run(&claims);
    assert_eq!(cut.disposition, SynthesisDisposition::Partial);
    let claim_omission = cut
        .omitted
        .iter()
        .find(|omission| omission.kind == OmissionKind::Claims)
        .expect("claims omission");
    assert_eq!((claim_omission.denominator, claim_omission.omitted), (2, 1));
    let mut rivals = base_request();
    rivals.draft.rivals.push(StructuredRival {
        rival_id: "rival-2".to_owned(),
        position: "Second framing.".to_owned(),
        stance: RivalStance::Alternative,
        target_claim: "claim-2".to_owned(),
        minority: true,
        evidence: Vec::new(),
    });
    rivals.bounds.max_rivals = 1;
    seal(&mut rivals);
    let rival_cut = run(&rivals);
    let rival_omission = rival_cut
        .omitted
        .iter()
        .find(|omission| omission.kind == OmissionKind::Rivals)
        .expect("rivals omission");
    assert_eq!((rival_omission.denominator, rival_omission.omitted), (2, 1));
    let mut references = base_request();
    references.bounds.max_references = 4;
    let ref_cut = run(&references);
    assert_eq!(ref_cut.disposition, SynthesisDisposition::Partial);
    assert!(
        ref_cut
            .omitted
            .iter()
            .any(|omission| omission.kind == OmissionKind::References)
    );
    let mut probes = base_request();
    probes.draft.probes.push(StructuredProbe {
        probe_id: "probe-1b".to_owned(),
        basis: ProbeBasis::SuppliedDiscriminative,
        discriminates: vec!["u-1".to_owned()],
        outcomes: vec!["holds".to_owned(), "fails".to_owned()],
        verifier: "verifier-1b".to_owned(),
        owner: "owner-1b".to_owned(),
        cost_class: "low".to_owned(),
        applicability: "while fence 7 stands".to_owned(),
    });
    probes.bounds.max_probes = 1;
    seal(&mut probes);
    let probe_cut = run(&probes);
    let probe_brief = brief_of(&probe_cut);
    assert_eq!(probe_brief.probes.len(), 1);
    assert_eq!(
        probe_brief.probe_residue[0].reason,
        ProbeResidueReason::Budget
    );
    assert!(
        probe_cut
            .omitted
            .iter()
            .any(|omission| omission.kind == OmissionKind::Probes)
    );
    let mut work = base_request();
    work.bounds.max_work = 3;
    let tired = run(&work);
    assert_eq!(tired.disposition, SynthesisDisposition::Exhausted);
    assert!(
        tired
            .omitted
            .iter()
            .any(|omission| omission.kind == OmissionKind::Work)
    );
    let request = base_request();
    let exact = request_canonical_len(&request);
    let mut tight = request.clone();
    tight.bounds.max_input_bytes = exact.saturating_sub(1);
    assert!(matches!(
        synthesize(&tight),
        Err(SynthesisError::BudgetExceeded { .. })
    ));
    let mut fitting = request.clone();
    fitting.bounds.max_input_bytes = exact;
    assert_eq!(run(&fitting).disposition, SynthesisDisposition::Complete);
    let mut zero = base_request();
    zero.bounds.max_claims = 0;
    assert!(matches!(
        synthesize(&zero),
        Err(SynthesisError::BudgetExceeded { .. })
    ));
    let mut wide = base_request();
    for index in 0..8 {
        wide.draft.probes.push(StructuredProbe {
            probe_id: format!("probe-L{index}"),
            basis: ProbeBasis::SuppliedDiscriminative,
            discriminates: vec!["u-1".to_owned()],
            outcomes: vec!["holds".to_owned(), "fails".to_owned()],
            verifier: "verifier-L".to_owned(),
            owner: "owner-L".to_owned(),
            cost_class: "low".to_owned(),
            applicability: "x".repeat(400),
        });
    }
    seal(&mut wide);
    let full = run(&wide);
    let full_len = brief_canonical_len(brief_of(&full));
    let mut elided = wide.clone();
    elided.bounds.max_output_bytes = full_len.saturating_sub(1);
    let slim = run(&elided);
    assert_eq!(slim.disposition, SynthesisDisposition::Partial);
    let slim_brief = brief_of(&slim);
    assert!(slim_brief.probes.is_empty());
    assert!(!slim_brief.unknowns.is_empty());
    assert!(
        slim.omitted
            .iter()
            .any(|omission| omission.kind == OmissionKind::OutputBytes)
    );
}

// WORK_UNIT_CASE: 995/20
#[test]
fn cancellation_deadline_and_stale_policy_block() {
    let request = base_request();
    let mut cancelled = request.clone();
    cancelled.cancellation.cancelled = true;
    let stopped = run(&cancelled);
    assert_eq!(stopped.disposition, SynthesisDisposition::Blocked);
    assert!(stopped.brief.is_none());
    assert_eq!(
        stopped.output_digest,
        terminal_digest(SynthesisDisposition::Blocked, &stopped.input_digest)
    );
    let mut late = request.clone();
    late.cancellation.now_ms = Some(200);
    late.cancellation.deadline_ms = Some(100);
    assert_eq!(run(&late).disposition, SynthesisDisposition::Blocked);
    let mut stale = request.clone();
    stale.policy.valid_through_generation = 5;
    assert_eq!(run(&stale).disposition, SynthesisDisposition::Blocked);
    let mut timely = request.clone();
    timely.cancellation.now_ms = Some(50);
    timely.cancellation.deadline_ms = Some(100);
    assert_eq!(run(&timely).disposition, SynthesisDisposition::Complete);
}

// WORK_UNIT_CASE: 995/21
#[test]
fn preservation_receipt_and_no_second_pass() {
    let request = base_request();
    let outcome = run(&request);
    let brief = brief_of(&outcome);
    assert_eq!(brief.preservation.len(), 7);
    let names: Vec<&str> = brief
        .preservation
        .iter()
        .map(|row| preservation_dimension_as_str(row.dimension))
        .collect();
    assert_eq!(
        names,
        vec![
            "coverage",
            "preservation",
            "faithfulness",
            "lineage",
            "reversibility",
            "source-authority",
            "dependency-closure"
        ]
    );
    assert!(
        brief
            .preservation
            .iter()
            .all(|row| row.passed && row.known && !row.note.trim().is_empty())
    );
    let mut seen = BTreeSet::new();
    for row in &brief.preservation {
        assert!(seen.insert(row.dimension));
    }
    assert_eq!(preservation_dimensions().len(), 7);
    assert_eq!(outcome.preservation, brief.preservation);
    assert_eq!(mirror_preservation(brief), brief.preservation);
    assert_eq!(outcome.inherited_receipt, request.receipt);
    assert_eq!(
        outcome.inherited_receipt.receipt_digest,
        sha256_hex(b"995-receipt")
    );
}

// WORK_UNIT_CASE: 995/22
#[test]
fn ordering_replay_and_digest_separation() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(sha256(b"abc").len(), 32);
    let request = base_request();
    let first = run(&request);
    let second = run(&request);
    assert_eq!(first, second);
    let mut shuffled = request.clone();
    shuffled.draft.claims.swap(0, 1);
    seal(&mut shuffled);
    let moved = run(&shuffled);
    let first_brief = brief_of(&first);
    let moved_brief = brief_of(&moved);
    assert_ne!(moved.input_digest, first.input_digest);
    assert_eq!(moved_brief.semantic_digest, first_brief.semantic_digest);
    assert_ne!(moved_brief.raw_digest, first_brief.raw_digest);
    let mut edited = request.clone();
    edited.draft.claims[0].statement = "Handle H mostly holds.".to_owned();
    seal(&mut edited);
    let edited_outcome = run(&edited);
    let changed = brief_of(&edited_outcome);
    assert_ne!(changed.semantic_digest, first_brief.semantic_digest);
    let mut left = CanonicalWriter::new();
    left.text("a", "1");
    left.integer("b", 2);
    left.flag("c", true);
    let mut right = CanonicalWriter::new();
    right.text("a", "1");
    right.integer("b", 2);
    right.flag("c", true);
    assert_eq!(left.finish(), right.finish());
}

// WORK_UNIT_CASE: 995/23
#[test]
fn malformed_redacted_and_nothing_invented() {
    let mut empty = base_request();
    empty.pack.question = String::new();
    assert!(matches!(
        synthesize(&empty),
        Err(SynthesisError::Malformed { .. })
    ));
    let mut sourceless = base_request();
    sourceless.pack.sources.clear();
    assert!(matches!(
        synthesize(&sourceless),
        Err(SynthesisError::Malformed { .. })
    ));
    let mut loud = base_request();
    loud.draft.question = "Q".repeat(8_000);
    seal(&mut loud);
    match synthesize(&loud) {
        Err(SynthesisError::ReferenceMismatch { want, got, .. }) => {
            assert!(want.len() <= 64 + "[redacted]".len());
            assert!(got.len() <= 64 + "[redacted]".len());
            assert!(got.contains("[redacted]"));
        }
        other => panic!("expected redacted mismatch, got {other:?}"),
    }
    let mut secret = base_request();
    secret.binding.requester_session = "sekrit-9z-token".to_owned();
    secret.draft.question = "Another question?".to_owned();
    seal(&mut secret);
    match synthesize(&secret) {
        Err(error) => assert!(!error.to_string().contains("sekrit-9z-token")),
        Ok(_) => panic!("expected a mismatch failure"),
    }
    let mut inventing = base_request();
    inventing.draft.probes[0].discriminates = vec!["minted-1".to_owned()];
    seal(&mut inventing);
    let inventing_outcome = run(&inventing);
    let brief = brief_of(&inventing_outcome);
    assert!(brief.probes.is_empty());
    assert_eq!(
        brief.probe_residue[0].reason,
        ProbeResidueReason::UnknownTarget
    );
    let request = base_request();
    let request_outcome = run(&request);
    let brief = brief_of(&request_outcome);
    let mut allowed: BTreeSet<&str> = BTreeSet::new();
    for card in &request.pack.sources {
        allowed.insert(card.handle.as_str());
    }
    for claim in &request.draft.claims {
        allowed.insert(claim.claim_id.as_str());
        for counter in &claim.counterclaims {
            allowed.insert(counter.counterclaim_id.as_str());
        }
    }
    for rival in &request.draft.rivals {
        allowed.insert(rival.rival_id.as_str());
    }
    for unknown in &request.draft.unknowns {
        allowed.insert(unknown.unknown_id.as_str());
    }
    for probe in &request.draft.probes {
        allowed.insert(probe.probe_id.as_str());
    }
    let mut inventoried = Vec::new();
    for row in &brief.claim_matrix {
        inventoried.extend(row.support.iter());
        inventoried.extend(row.counter_evidence.iter());
        inventoried.extend(row.citations.iter());
    }
    for rival in &brief.rivals {
        inventoried.extend(rival.evidence.iter());
    }
    inventoried.extend(brief.concilium.evidence_refs.iter());
    for probe in &brief.probes {
        inventoried.extend(probe.discriminates.iter());
    }
    for handle in inventoried {
        assert!(allowed.contains(handle.as_str()), "invented {handle}");
    }
}

// WORK_UNIT_CASE: 995/24
#[test]
fn public_consumer_and_portability_fixtures() {
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Complete),
        "candidate"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Partial),
        "partial"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Exhausted),
        "partial"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Abstained),
        "abstention"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Blocked),
        "blocked"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Unsupported),
        "unsupported"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Conflicted),
        "conflict"
    );
    assert_eq!(
        guest_parity_disposition(SynthesisDisposition::Unknown),
        "unsupported"
    );
    assert_eq!(
        synthesis_disposition_as_str(SynthesisDisposition::Exhausted),
        "exhausted"
    );
    assert_eq!(
        claim_disposition_as_str(ClaimDisposition::OutsideManifest),
        "outside-manifest"
    );
    assert_eq!(evidence_grade_as_str(EvidenceGrade::E0), "E0");
    assert_eq!(source_authority_rank(SourceAuthority::Unknown), 3);
    assert_eq!(omission_kind_rank(OmissionKind::OutputBytes), 6);
    assert!(is_digest(&sha256_hex(b"995")));
    assert!(!is_digest("short"));
    assert!(is_handle("src-a"));
    assert!(!is_handle("   "));
    assert!(is_text("Which handle holds?"));
    assert!(!is_text(""));
    assert_eq!(redact_value("short").as_str(), "short");
    assert!(redact_value(&"a".repeat(100)).ends_with("[redacted]"));
    let manifest = env!("CARGO_MANIFEST_DIR");
    let sources = [
        "src/lib.rs",
        "src/bounds.rs",
        "src/digest.rs",
        "src/model.rs",
        "src/synthesize.rs",
    ];
    let forbidden = [
        "std::time",
        "std::fs",
        "std::net",
        "std::thread",
        "std::process",
        "std::env",
        "std::os",
        "extern crate",
        "unimplemented!",
        "todo!",
        "panic!",
        ".unwrap()",
        ".expect(",
        "post_handler",
        "ModelClient",
        "ProviderClient",
        "serde",
        "tokio",
        "reqwest",
        "HashMap",
        "getrandom",
        "SystemTime",
        "Instant",
    ];
    let mut checked = 0;
    for source in sources {
        let path = format!("{manifest}/{source}");
        let text = std::fs::read_to_string(&path).expect("read source");
        if source == "src/lib.rs" {
            assert!(text.contains("forbid(unsafe_code)"));
        }
        for token in forbidden {
            assert!(!text.contains(token), "{source} contains {token}");
        }
        checked += 1;
    }
    assert_eq!(checked, 5);
    let cargo = std::fs::read_to_string(format!("{manifest}/Cargo.toml")).expect("read manifest");
    assert!(cargo.contains("name = \"eliot-dreamer-research-synthesis\""));
    assert!(!cargo.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "[dependencies]"
            || trimmed == "[dev-dependencies]"
            || trimmed.starts_with("[dependencies.")
    }));
    let outcome = run(&base_request());
    assert_eq!(outcome.disposition, SynthesisDisposition::Complete);
}
