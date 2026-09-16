//! Evidence-portfolio discipline suite (issue #700, cases 1-8, 11, 13, 14).
//!
//! Every case builds real inquiries, source records, coverage accounts and
//! manifests through the vetted constructors and asserts exact computed
//! outcomes. The golden record in `data/evidence_portfolio.json` mirrors the
//! canonical scenario; tests pin its semantic goldens and stability
//! properties.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_research_exchange_api::{DisclosureClass, SourceClass};
use eliot_researcher::evidence_portfolio::*;

const GOLDEN: &str = include_str!("data/evidence_portfolio.json");

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const EXPECTED_GRADE_ORDER: [&str; 4] = ["ORIENTING", "GROUNDED", "CORROBORATED", "SCIENCE_GRADE"];
const EXPECTED_DENOMINATOR_SIZE: usize = 4;

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        NonZeroU64::new(7).expect("sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn budgets() -> BudgetCaps {
    BudgetCaps {
        attempts: 8,
        sources: 8,
        bytes: 1_000_000,
        stu: 500,
        output: 64,
        cost: 100,
        work: 40,
        deadline_ms: 1_800_000_000_000,
    }
}

fn inquiry_params() -> FrozenInquiryParams {
    FrozenInquiryParams {
        schema: "research-inquiry/v1".to_owned(),
        protocol: "evidence-review/r3".to_owned(),
        policy: "policy-700".to_owned(),
        question: "which valve alloy survives the thermal envelope".to_owned(),
        objective: "select the flight alloy".to_owned(),
        output_contract: "research-evidence-bundle/v1".to_owned(),
        requester: "requester-700".to_owned(),
        task: "task-700".to_owned(),
        attempt: "attempt-1".to_owned(),
        scope: "propulsion thermal envelope".to_owned(),
        fence: fence(),
        privacy: "project-bound handling".to_owned(),
        disclosure: DisclosureClass::ProjectBound,
        roles: vec![
            RoleSlot {
                role: "primary".to_owned(),
                class: SourceClass::Paper,
                required: 2,
                authority_domain: "propulsion".to_owned(),
            },
            RoleSlot {
                role: "secondary".to_owned(),
                class: SourceClass::Documentation,
                required: 1,
                authority_domain: "propulsion".to_owned(),
            },
            RoleSlot {
                role: "negative".to_owned(),
                class: SourceClass::Report,
                required: 1,
                authority_domain: "safety".to_owned(),
            },
        ],
        routes: vec!["route-alpha".to_owned(), "route-beta".to_owned()],
        budgets: budgets(),
        stop_rule: "stop-on-exhaustion".to_owned(),
        partial_policy: "partial-with-omissions".to_owned(),
        operation_id: "op-inquiry-700".to_owned(),
        replay_id: "replay-inquiry-700".to_owned(),
    }
}

fn source_params(handle: &str) -> SourceRecordParams {
    SourceRecordParams {
        handle: handle.to_owned(),
        class: SourceClass::Paper,
        title: format!("title for {handle}"),
        locator: format!("snapshot::{handle}"),
        content_digest: DIGEST_A.to_owned(),
        operation_id: format!("op-{handle}"),
        receipt_handle: format!("rcpt-{handle}"),
        acquisition: SourceDisposition::Observed,
        published_ms: Some(1_700_000_000_000),
        observed_ms: Some(1_700_000_100_000),
        retrieved_ms: Some(1_700_000_200_000),
        freshness_boundary_ms: Some(1_800_000_000_000),
        transformed_from: None,
        transform_verified: false,
        grade: Some(2),
        authority_domains: BTreeSet::from(["propulsion".to_owned()]),
        lineage_root: Some(format!("root-{handle}")),
        disclosure: DisclosureClass::ProjectBound,
        content_flags: BTreeSet::new(),
        incentives_note: "independent lab, no sponsor".to_owned(),
        deception_risk: RiskState::Low,
        allowed_use: "evidence-only".to_owned(),
        allowed_effects: "none".to_owned(),
        verifier: "verifier-700".to_owned(),
        quarantine: None,
        counterevidence_of: BTreeSet::new(),
        cites: Vec::new(),
        evidence_spans: vec![EvidenceSpan {
            span_id: format!("span-{handle}"),
            anchor: "section-2".to_owned(),
            excerpt_digest: DIGEST_B.to_owned(),
        }],
        data_role: "primary".to_owned(),
    }
}

fn record(handle: &str) -> SourceRecord {
    SourceRecord::new(source_params(handle)).expect("source record")
}

fn manifest_for(portfolio: &EvidencePortfolio, inquiry: &FrozenInquiry) -> AuthorizedManifest {
    let mut sources = BTreeMap::new();
    for (handle, entry) in &portfolio.records {
        sources.insert(
            handle.clone(),
            (entry.content_digest.clone(), entry.transformed_from.clone()),
        );
    }
    let edges: BTreeSet<(String, String)> = portfolio
        .records
        .iter()
        .flat_map(|(handle, entry)| {
            entry
                .cites
                .iter()
                .map(move |edge| (handle.clone(), edge.clone()))
        })
        .collect();
    let allowlist: Vec<String> = portfolio.records.keys().cloned().collect();
    AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: inquiry.digest.clone(),
        denominator_digest: inquiry.denominator_digest(),
        sources,
        dependence_edges: edges,
        coverage_digest: portfolio.coverage.digest(),
        grade_limits: vec!["grade: weakest link applies".to_owned()],
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist,
        revoked: Vec::new(),
        disclosure: DisclosureClass::ProjectBound,
        expires_ms: 1_900_000_000_000,
        revision: 1,
    })
    .expect("manifest")
}

// WORK_UNIT_CASE: 700/1
#[test]
fn golden_canonical_four_grades_and_order() {
    assert_eq!(GRADE_ORDER, EXPECTED_GRADE_ORDER);
    assert_eq!(GRADE_ORDER.len(), 4);
    for (rank, name) in EXPECTED_GRADE_ORDER.iter().enumerate() {
        let rank = u8::try_from(rank).expect("rank");
        assert_eq!(grade_rank(name).expect("rank"), rank);
        assert_eq!(grade_name(rank).expect("name"), *name);
    }
    assert!(grade_rank("RELIABLE").is_err());
    assert!(grade_name(4).is_err());
    let all: Vec<Option<u8>> = vec![Some(0), Some(1), Some(2), Some(3)];
    assert_eq!(weakest_ceiling(&all).expect("ceiling"), Some(0));
    assert!(weakest_ceiling(&[]).is_err());
    assert!(GOLDEN.contains("ORIENTING"));
    assert!(GOLDEN.contains("SCIENCE_GRADE"));
}

// WORK_UNIT_CASE: 700/2
#[test]
fn weakest_source_ceiling_across_grades() {
    let mut tuned: Vec<SourceRecord> = Vec::new();
    for (index, grade) in [0u8, 1, 2, 3].iter().enumerate() {
        let mut params = source_params(&format!("grade-src-{index}"));
        params.grade = Some(*grade);
        tuned.push(SourceRecord::new(params).expect("graded source"));
    }
    let refs: Vec<&SourceRecord> = tuned.iter().collect();
    let decision = decide_grade(&refs, "propulsion", 1_700_000_300_000);
    assert_eq!(decision.ceiling, Some(0));
    assert!(decision.limits.is_empty());
    let single = decide_grade(&refs[3..], "propulsion", 1_700_000_300_000);
    assert_eq!(single.ceiling, Some(3));
    check_ceiling(3, 3).expect("equal ceiling holds");
    assert!(check_ceiling(3, 2).is_err());
    assert!(check_ceiling(2, 3).is_ok());
}

// WORK_UNIT_CASE: 700/3
#[test]
fn repetition_and_common_lineage_cannot_inflate() {
    let mut first = source_params("copy-a");
    first.lineage_root = Some("root-shared".to_owned());
    first.grade = Some(2);
    let mut second = source_params("copy-b");
    second.lineage_root = Some("root-shared".to_owned());
    second.grade = Some(2);
    let lone = source_params("lone-c");
    let records = BTreeMap::from([
        ("copy-a".to_owned(), SourceRecord::new(first).expect("a")),
        ("copy-b".to_owned(), SourceRecord::new(second).expect("b")),
        ("lone-c".to_owned(), SourceRecord::new(lone).expect("c")),
    ]);
    let table = LineageTable::build(&records);
    let (independent, unknown) = table.independent_support(&[
        "copy-a".to_owned(),
        "copy-b".to_owned(),
        "lone-c".to_owned(),
    ]);
    assert_eq!(independent, 2);
    assert_eq!(unknown, 0);
    let pair: Vec<&SourceRecord> = vec![&records["copy-a"], &records["copy-b"]];
    let repeated = decide_grade(&pair, "propulsion", 1_700_000_300_000);
    let solo = decide_grade(&[&records["copy-a"]], "propulsion", 1_700_000_300_000);
    assert_eq!(repeated.ceiling, solo.ceiling);
    assert_eq!(repeated.ceiling, Some(2));
    let unknown_root = SourceRecord::new({
        let mut params = source_params("mystery");
        params.lineage_root = None;
        params
    })
    .expect("unknown root preserved");
    let table = LineageTable::build(&BTreeMap::from([("mystery".to_owned(), unknown_root)]));
    let (independent, unknown) = table.independent_support(&["mystery".to_owned()]);
    assert_eq!(independent, 0);
    assert_eq!(unknown, 1);
}

// WORK_UNIT_CASE: 700/4
#[test]
fn source_outside_claim_authority_domain() {
    let mut params = source_params("foreign-src");
    params.authority_domains = BTreeSet::from(["avionics".to_owned()]);
    let foreign = SourceRecord::new(params).expect("foreign source");
    assert!(!foreign.covers_domain("propulsion"));
    let decision = decide_grade(&[&foreign], "propulsion", 1_700_000_300_000);
    assert_eq!(decision.ceiling, None);
    assert!(decision.limits.iter().any(|l| l.contains("outside domain")));
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let mut portfolio = EvidencePortfolio::open(&inquiry).expect("portfolio");
    portfolio
        .ingest(foreign, "primary#0")
        .expect("ingest foreign");
    let manifest = manifest_for(&portfolio, &inquiry);
    let claim = AuditedClaim {
        claim_id: "claim-domain".to_owned(),
        statement: "the alloy survives".to_owned(),
        material: true,
        domain: "propulsion".to_owned(),
        citations: vec!["foreign-src".to_owned()],
        precision: Vec::new(),
        counterclaim_ids: Vec::new(),
        unknown_refs: Vec::new(),
    };
    let verdict = audit_claim(&claim, &portfolio, &manifest, 1_700_000_300_000);
    assert_eq!(verdict.outcome, ClaimOutcome::Unsupported);
    assert!(
        verdict
            .residue
            .iter()
            .any(|r| r.contains("outside claim domain"))
    );
}

// WORK_UNIT_CASE: 700/5
#[test]
fn stale_partial_and_contested_sources_limit_grade() {
    let mut stale_params = source_params("stale-src");
    stale_params.grade = Some(3);
    stale_params.retrieved_ms = Some(1_850_000_000_000);
    let stale = SourceRecord::new(stale_params).expect("stale");
    assert!(stale.is_stale_at(1_860_000_000_000));
    let stale_decision = decide_grade(&[&stale], "propulsion", 1_860_000_000_000);
    assert_eq!(stale_decision.ceiling, Some(0));
    assert!(
        stale_decision
            .limits
            .iter()
            .any(|l| l.contains("ORIENTING"))
    );

    let mut partial_params = source_params("partial-src");
    partial_params.grade = Some(2);
    partial_params.acquisition = SourceDisposition::Partial;
    let partial = SourceRecord::new(partial_params).expect("partial");
    let partial_decision = decide_grade(&[&partial], "propulsion", 1_700_000_300_000);
    assert_eq!(partial_decision.ceiling, Some(1));

    let mut derived_params = source_params("derived-src");
    derived_params.grade = Some(3);
    derived_params.transformed_from = Some("raw-src".to_owned());
    derived_params.transform_verified = false;
    let derived = SourceRecord::new(derived_params).expect("derived");
    let derived_decision = decide_grade(&[&derived], "propulsion", 1_700_000_300_000);
    assert_eq!(derived_decision.ceiling, Some(1));

    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let mut portfolio = EvidencePortfolio::open(&inquiry).expect("portfolio");
    let mut rival_params = source_params("rival-src");
    rival_params.counterevidence_of = BTreeSet::from(["claim-contested".to_owned()]);
    let rival = SourceRecord::new(rival_params).expect("rival");
    portfolio
        .ingest(record("base-src"), "primary#0")
        .expect("ingest");
    portfolio.ingest(rival, "primary#1").expect("ingest rival");
    let manifest = manifest_for(&portfolio, &inquiry);
    let claim = AuditedClaim {
        claim_id: "claim-contested".to_owned(),
        statement: "the alloy survives".to_owned(),
        material: true,
        domain: "propulsion".to_owned(),
        citations: vec!["base-src".to_owned(), "rival-src".to_owned()],
        precision: Vec::new(),
        counterclaim_ids: vec!["rival-src".to_owned()],
        unknown_refs: Vec::new(),
    };
    let verdict = audit_claim(&claim, &portfolio, &manifest, 1_700_000_300_000);
    assert_eq!(verdict.outcome, ClaimOutcome::Contradicted);
    assert_eq!(verdict.counterevidence, vec!["rival-src".to_owned()]);
}

// WORK_UNIT_CASE: 700/6
#[test]
fn exact_complete_portfolio_denominator() {
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let members = inquiry.denominator_members();
    assert_eq!(members.len(), EXPECTED_DENOMINATOR_SIZE);
    assert!(members.contains("primary#0"));
    assert!(members.contains("primary#1"));
    assert!(members.contains("secondary#0"));
    assert!(members.contains("negative#0"));
    let first = inquiry.denominator_digest();
    assert_eq!(first.len(), 64);
    let mut shuffled = inquiry_params();
    shuffled.roles.reverse();
    shuffled.routes.reverse();
    let refrozen = FrozenInquiry::freeze(shuffled).expect("refrozen");
    assert_eq!(refrozen.denominator_digest(), first);
    assert_eq!(refrozen.digest, inquiry.digest);
    let mut vague = inquiry_params();
    vague.scope = "all".to_owned();
    assert!(FrozenInquiry::freeze(vague).is_err());
    let mut duplicate = inquiry_params();
    duplicate.roles.push(RoleSlot {
        role: "primary".to_owned(),
        class: SourceClass::Paper,
        required: 1,
        authority_domain: "propulsion".to_owned(),
    });
    assert!(FrozenInquiry::freeze(duplicate).is_err());
    let plan = plan_acquisition(&inquiry);
    assert_eq!(plan.len(), EXPECTED_DENOMINATOR_SIZE);
    assert_eq!(plan_acquisition(&inquiry), plan);
    for request in &plan {
        assert_eq!(request.inquiry_digest, inquiry.digest);
        assert_eq!(request.deadline_ms, inquiry.budgets.deadline_ms);
    }
    assert!(GOLDEN.contains("primary#0"));
    assert!(GOLDEN.contains("denominator_size"));
    assert!(GOLDEN.contains("evidence_portfolio"));
    assert!(GOLDEN.contains("work_unit_case"));
    assert!(GOLDEN.contains("propulsion thermal envelope"));
    assert!(GOLDEN.lines().count() > 40);
    let digest = sha256_hex(b"evidence-portfolio-700");
    assert_eq!(digest.len(), 64);
}

// WORK_UNIT_CASE: 700/7
#[test]
fn acquisition_dispositions_stay_distinct() {
    let wires: Vec<&str> = [
        SourceDisposition::Observed,
        SourceDisposition::Partial,
        SourceDisposition::Unavailable,
        SourceDisposition::Blocked,
        SourceDisposition::Stale,
        SourceDisposition::Malformed,
        SourceDisposition::Exhausted,
        SourceDisposition::Unknown,
    ]
    .iter()
    .copied()
    .map(SourceDisposition::wire_name)
    .collect();
    let unique: BTreeSet<&str> = wires.iter().copied().collect();
    assert_eq!(unique.len(), 8);
    assert!(SourceDisposition::Observed.may_support());
    assert!(SourceDisposition::Partial.may_support());
    assert!(!SourceDisposition::Exhausted.may_support());
    assert!(!SourceDisposition::Unknown.may_support());
    assert!(SourceDisposition::Observed.closes_member());
    assert!(!SourceDisposition::Partial.closes_member());
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let mut account = CoverageAccount::open(inquiry.denominator_members()).expect("account");
    account
        .record(
            "primary#0",
            SourceDisposition::Observed,
            Some("h-a".to_owned()),
        )
        .expect("observed");
    account
        .record("primary#1", SourceDisposition::Unavailable, None)
        .expect("unavailable");
    account
        .record("secondary#0", SourceDisposition::Blocked, None)
        .expect("blocked");
    account
        .record("negative#0", SourceDisposition::Exhausted, None)
        .expect("exhausted");
    account
        .note_frontier("budget stu exhausted at secondary")
        .expect("frontier");
    assert!(account.is_accounted());
    assert!(!account.all_closed());
    assert_eq!(account.digest().len(), 64);
}

// WORK_UNIT_CASE: 700/8
#[test]
fn absence_requires_complete_authoritative_lookup() {
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let mut proven = CoverageAccount::open(inquiry.denominator_members()).expect("account");
    for member in inquiry.denominator_members() {
        proven
            .record(
                &member,
                SourceDisposition::Observed,
                Some(format!("h-{member}")),
            )
            .expect("record");
    }
    assert_eq!(assess_absence(true, &proven, true), AbsenceVerdict::Proven);
    let mut gapped = CoverageAccount::open(inquiry.denominator_members()).expect("account");
    for member in inquiry.denominator_members() {
        let disposition = if member == "primary#0" {
            SourceDisposition::Unknown
        } else {
            SourceDisposition::Observed
        };
        gapped
            .record(&member, disposition, Some(format!("h-{member}")))
            .expect("record");
    }
    assert!(matches!(
        assess_absence(true, &gapped, true),
        AbsenceVerdict::Unproven { .. }
    ));
    let mut exhausted = CoverageAccount::open(inquiry.denominator_members()).expect("account");
    for member in inquiry.denominator_members() {
        exhausted
            .record(
                &member,
                SourceDisposition::Observed,
                Some(format!("h-{member}")),
            )
            .expect("record");
    }
    exhausted
        .note_frontier("route budget ended early")
        .expect("frontier");
    assert!(matches!(
        assess_absence(true, &exhausted, true),
        AbsenceVerdict::PartialExhaustion { .. }
    ));
    assert!(matches!(
        assess_absence(false, &proven, true),
        AbsenceVerdict::Unproven { .. }
    ));
    assert!(matches!(
        assess_absence(true, &proven, false),
        AbsenceVerdict::Unproven { .. }
    ));
}

// WORK_UNIT_CASE: 700/11
#[test]
fn malformed_circular_and_unresolved_citations() {
    let mut self_cite = source_params("self-src");
    self_cite.cites = vec!["self-src".to_owned()];
    assert!(SourceRecord::new(self_cite).is_err());
    let mut loop_a = source_params("loop-a");
    loop_a.cites = vec!["loop-b".to_owned()];
    let mut loop_b = source_params("loop-b");
    loop_b.cites = vec!["loop-a".to_owned()];
    let looping = BTreeMap::from([
        ("loop-a".to_owned(), SourceRecord::new(loop_a).expect("a")),
        ("loop-b".to_owned(), SourceRecord::new(loop_b).expect("b")),
    ]);
    assert!(matches!(
        check_citation_graph(&looping),
        Err(PortfolioError::CircularCitation { .. })
    ));
    let mut dangling = source_params("tip");
    dangling.cites = vec!["ghost".to_owned()];
    let open = BTreeMap::from([("tip".to_owned(), SourceRecord::new(dangling).expect("tip"))]);
    assert!(matches!(
        check_citation_graph(&open),
        Err(PortfolioError::UnresolvedRoot { .. })
    ));
    let mut chain = source_params("head");
    chain.cites = vec!["tail".to_owned()];
    let closed = BTreeMap::from([
        ("head".to_owned(), SourceRecord::new(chain).expect("head")),
        ("tail".to_owned(), record("tail")),
    ]);
    check_citation_graph(&closed).expect("acyclic graph holds");
}

// WORK_UNIT_CASE: 700/13
#[test]
fn unsupported_structured_precision_stays_typed_residue() {
    let exact = PrecisionAssertion {
        kind: PrecisionKind::Numeric,
        asserted: "42".to_owned(),
        supported: "42".to_owned(),
        basis: "measured count".to_owned(),
    };
    check_precision(&exact).expect("exact numeric holds");
    let interval = PrecisionAssertion {
        kind: PrecisionKind::Numeric,
        asserted: "42".to_owned(),
        supported: "40..44".to_owned(),
        basis: "calibrated interval".to_owned(),
    };
    check_precision(&interval).expect("interval holds");
    let over_precise = PrecisionAssertion {
        kind: PrecisionKind::Numeric,
        asserted: "42.00".to_owned(),
        supported: "42".to_owned(),
        basis: "whole-unit count".to_owned(),
    };
    let residue = check_precision(&over_precise).expect_err("over-precision fails");
    assert_eq!(residue.highest_supported, "42");
    assert!(residue.risk.contains("false quantification"));
    let outside = PrecisionAssertion {
        kind: PrecisionKind::Numeric,
        asserted: "45".to_owned(),
        supported: "40..44".to_owned(),
        basis: "calibrated interval".to_owned(),
    };
    assert!(check_precision(&outside).is_err());
    let date_hit = PrecisionAssertion {
        kind: PrecisionKind::Date,
        asserted: "1700000100000".to_owned(),
        supported: "1700000000000..1700000200000".to_owned(),
        basis: "capture window".to_owned(),
    };
    check_precision(&date_hit).expect("date inside window holds");
    let date_miss = PrecisionAssertion {
        kind: PrecisionKind::Date,
        asserted: "1700000900000".to_owned(),
        supported: "1700000000000..1700000200000".to_owned(),
        basis: "capture window".to_owned(),
    };
    assert!(check_precision(&date_miss).is_err());
    let version_hit = PrecisionAssertion {
        kind: PrecisionKind::Version,
        asserted: "r3".to_owned(),
        supported: "r3".to_owned(),
        basis: "frozen protocol".to_owned(),
    };
    check_precision(&version_hit).expect("exact version holds");
    let version_miss = PrecisionAssertion {
        kind: PrecisionKind::Version,
        asserted: "r4".to_owned(),
        supported: "r3".to_owned(),
        basis: "frozen protocol".to_owned(),
    };
    assert!(check_precision(&version_miss).is_err());
    let causal_hit = PrecisionAssertion {
        kind: PrecisionKind::Causal,
        asserted: "thermal-creep".to_owned(),
        supported: "thermal-creep|oxidation".to_owned(),
        basis: "failure analysis".to_owned(),
    };
    check_precision(&causal_hit).expect("evidenced mechanism holds");
    let causal_miss = PrecisionAssertion {
        kind: PrecisionKind::Causal,
        asserted: "resonance".to_owned(),
        supported: "thermal-creep|oxidation".to_owned(),
        basis: "failure analysis".to_owned(),
    };
    let residue = check_precision(&causal_miss).expect_err("inferred mechanism fails");
    assert_eq!(
        residue.required_probe,
        "name only evidenced mechanisms or declare correlation"
    );
}

// WORK_UNIT_CASE: 700/14
#[test]
fn hidden_counterevidence_and_unknowns_keep_accounting_open() {
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let mut portfolio = EvidencePortfolio::open(&inquiry).expect("portfolio");
    portfolio
        .ingest(record("base-src"), "primary#0")
        .expect("ingest");
    let manifest = manifest_for(&portfolio, &inquiry);
    let hidden_unknown = AuditedClaim {
        claim_id: "claim-hidden".to_owned(),
        statement: "the alloy survives".to_owned(),
        material: true,
        domain: "propulsion".to_owned(),
        citations: vec!["base-src".to_owned()],
        precision: Vec::new(),
        counterclaim_ids: Vec::new(),
        unknown_refs: vec!["unread-dossier-9".to_owned()],
    };
    let verdict = audit_claim(&hidden_unknown, &portfolio, &manifest, 1_700_000_300_000);
    assert_eq!(verdict.outcome, ClaimOutcome::IncompleteAccounting);
    assert_eq!(verdict.unknowns, vec!["unread-dossier-9".to_owned()]);
    assert_eq!(verdict.evidence_map, vec!["base-src".to_owned()]);
    let bare = AuditedClaim {
        claim_id: "claim-bare".to_owned(),
        statement: "the alloy survives".to_owned(),
        material: true,
        domain: "propulsion".to_owned(),
        citations: Vec::new(),
        precision: Vec::new(),
        counterclaim_ids: Vec::new(),
        unknown_refs: Vec::new(),
    };
    let verdict = audit_claim(&bare, &portfolio, &manifest, 1_700_000_300_000);
    assert_eq!(verdict.outcome, ClaimOutcome::IncompleteAccounting);
    let clean = AuditedClaim {
        claim_id: "claim-clean".to_owned(),
        statement: "the alloy survives".to_owned(),
        material: true,
        domain: "propulsion".to_owned(),
        citations: vec!["base-src".to_owned()],
        precision: Vec::new(),
        counterclaim_ids: Vec::new(),
        unknown_refs: Vec::new(),
    };
    let verdict = audit_claim(&clean, &portfolio, &manifest, 1_700_000_300_000);
    assert_eq!(verdict.outcome, ClaimOutcome::Supported);
    assert_eq!(verdict.grade_ceiling, Some(2));
    assert!(GOLDEN.contains("INCOMPLETE_ACCOUNTING"));
    assert!(GOLDEN.contains("SUPPORTED"));
    assert!(GOLDEN.contains("weakest_link"));
}
