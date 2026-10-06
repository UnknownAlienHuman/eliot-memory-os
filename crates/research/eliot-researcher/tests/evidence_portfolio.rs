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
use eliot_researcher::inquiry_governance::{
    CoverageGoal, EvidenceFreeze, EvidenceFreezeParams, EvidenceGrade, FreezeMemberReceipt,
    HypothesisPolicy, IndependenceBlindingPolicy, InquiryError, InquiryLane, InquiryOutputContract,
    InquiryProtocol, InquiryProtocolProfile, InquiryStopRule, ReopenCondition, StopRuleKind,
};
use eliot_researcher::{
    AdmittedExcerpt, AdmittedExcerptParams, ExcerptPosition, RetainedSourceRevision,
    RetainedSourceRevisionParams, audit_claim_with_excerpts,
};

const GOLDEN: &str = include_str!("data/evidence_portfolio.json");

#[test]
fn raw_source_derivation_requires_its_own_admitted_identity() {
    use eliot_researcher::source_admissibility::{admits_record_reference, record_references};

    let raw_source = "eliot://evidence/raw-parent";
    let mut params = source_params("derived-source");
    params.transformed_from = Some(raw_source.to_owned());
    params.transform_verified = true;
    let derived = SourceRecord::new(params).expect("vetted derived record");
    let references = record_references(&derived);
    let derivation = references
        .iter()
        .find(|reference| reference.reference == raw_source)
        .expect("derivation participates in both eligibility and diagnostic gates");
    assert_eq!(derivation.surface.wire_name(), "raw_source_derivation");

    let mut allowed = eliot_researcher::manifest(
        "derivation-run",
        fence(),
        vec![derived.handle.clone()],
        "root-revision-1",
        "propulsion",
        "project",
    )
    .expect("sealed reference manifest");
    allowed.validate().expect("valid run-bound manifest");
    assert!(!admits_record_reference(derivation, &allowed));
    allowed.url_handles.push(raw_source.to_owned());
    allowed = allowed.seal().expect("URL-only manifest");
    allowed.validate().expect("valid URL-only manifest");
    assert!(!admits_record_reference(derivation, &allowed));
    allowed.source_handles.push(raw_source.to_owned());
    allowed = allowed.seal().expect("admitted raw source identity");
    allowed
        .validate()
        .expect("valid raw source identity manifest");
    assert!(admits_record_reference(derivation, &allowed));
    allowed.stale_or_revoked_handles.push(raw_source.to_owned());
    allowed = allowed.seal().expect("revoked raw source identity");
    allowed.validate().expect("valid revoked manifest");
    assert!(!admits_record_reference(derivation, &allowed));

    let original = SourceRecord::new(source_params("original-source")).expect("raw record");
    assert!(
        record_references(&original)
            .iter()
            .all(|reference| reference.surface.wire_name() != "raw_source_derivation")
    );
}

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The exact retained bytes of every source record this suite builds.
///
/// `AuditedClaim.excerpts` is the field that makes I21.8's
/// `excerpt_supports_requirement` decidable for its occurrence half: without
/// the quoted bytes on this side of the boundary, cropped negation and
/// snippet-as-quote were unrepresentable rather than merely unchecked. A claim
/// audited here therefore offers the exact excerpt of the admitted revision
/// rather than no excerpt, and the occurrence check runs against the retained
/// original the governed source-admission/persistence owner committed.
///
/// This is deliberately a **single line with nothing before it**, and that is a
/// measured property rather than a convenience: the occurrence is anchored at
/// byte offset 0, so the governing leading window the cropped-negation arm
/// reads is empty, and a one-line quote has no further heading for the
/// stitching arm to find. A fixture that padded this with a preamble would be
/// asserting `NegationCropped` for reasons that have nothing to do with the
/// property each case is actually about.
const SOURCE_TEXT: &str = "the alloy survives the qualified thermal cycle";

/// The retained original for one admitted source handle, as the governed
/// source-admission/persistence owner would commit it.
///
/// Its `content_digest` is the digest of [`SOURCE_TEXT`], which is also what
/// [`source_params`] puts on the record, so the foreign-revision check compares
/// two independently produced values rather than a label with itself.
fn retained(handle: &str) -> RetainedSourceRevision {
    RetainedSourceRevision::retain(RetainedSourceRevisionParams {
        source_handle: handle.to_owned(),
        artifact_ref: format!("artifact::{handle}"),
        content_digest: sha256_hex(SOURCE_TEXT.as_bytes()),
        bytes: SOURCE_TEXT.as_bytes().to_vec(),
        snippet_regions: Vec::new(),
    })
    .expect("retained source revision")
}

/// The retained originals for exactly the handles a claim's excerpts name.
///
/// Keyed by the excerpt's own `source_handle`, so the audit resolves each
/// excerpt against the revision that admitted handle committed rather than
/// against whatever revision happened to be in the map.
fn retained_for(handles: &[&str]) -> BTreeMap<String, RetainedSourceRevision> {
    handles
        .iter()
        .map(|handle| ((*handle).to_owned(), retained(handle)))
        .collect()
}

/// The exact excerpt one admitted source handle offers, at the offset it was
/// measured at.
fn excerpt(handle: &str) -> AdmittedExcerpt {
    AdmittedExcerpt::offer(AdmittedExcerptParams {
        source_handle: handle.to_owned(),
        excerpt: SOURCE_TEXT.to_owned(),
        position: ExcerptPosition::ByteOffset { offset: 0 },
    })
    .expect("admitted excerpt")
}

/// Audits one claim whose excerpts are the retained originals named by
/// `handles`.
///
/// This is the entry point that actually compares quoted bytes with the
/// admitted original. The four-argument [`audit_claim`] deliberately has no
/// retained revision in hand, so every excerpt it audits is `NoRetainedRevision`
/// — a real finding, not a skip, but not a measurement either. A case whose
/// subject is source classification rather than excerpt occurrence would be
/// reporting that finding instead of the one it means to test.
fn audit_with_excerpts(
    claim: &AuditedClaim,
    portfolio: &EvidencePortfolio,
    binding: &AuditReferenceBinding,
    handles: &[&str],
) -> ClaimVerdict {
    audit_claim_with_excerpts(
        claim,
        portfolio,
        binding,
        1_700_000_300_000,
        &retained_for(handles),
    )
}

const EXPECTED_GRADE_ORDER: [&str; 4] = ["ORIENTING", "GROUNDED", "CORROBORATED", "SCIENCE_GRADE"];
const EXPECTED_DENOMINATOR_SIZE: usize = 4;

/// The manifest revision the absence fixture freezes and the evaluation names.
///
/// `AuthorizedManifest` keeps `revision` private and exposes no accessor for it,
/// so the fixture cannot read it back off the frozen value. It names the
/// revision it freezes here instead, in one place, and the join is still
/// enforced by the owner: `NoMatchEvaluationIssuer::issue_for` refuses a
/// manifest whose revision differs from the one the evaluation carries, so a
/// drifting constant fails the fixture instead of quietly passing it.
const ABSENCE_MANIFEST_REVISION: u64 = 1;

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
        // The admitted record's own content digest, which is the independent
        // expected value the foreign-revision check compares a retained
        // revision against. It is the digest of `SOURCE_TEXT`, so the record and
        // the retained original agree because both describe the same bytes, not
        // because the fixture reused one placeholder for both.
        content_digest: sha256_hex(SOURCE_TEXT.as_bytes()),
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
        provider_family: Some(format!("provider-{handle}")),
        evaluator_family: Some(format!("evaluator-{handle}")),
        assumptions: BTreeSet::from([format!("assumption-{handle}")]),
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

// Fail-closed fixture for the owner-bound absence preconditions: the two former
// caller-supplied booleans are no longer inputs, and the caller-authored
// `NoMatchEvaluation` that replaced them is gone with them. `Proven` now needs a
// real vetted record behind every closing member, an authorized manifest that
// commits those exact records, and an owner-issued per-member result whose
// identity is recomputed from the predicate and revisions actually in force.
// This helper supplies neither an evaluation nor a manifest, which is the state
// the ordinary Researcher route is in and is the fail-closed answer; the positive
// evidence is built by `proven_absence` below, which is the fixture work item 10
// of #2893.
fn preconditions(
    account: &CoverageAccount,
    evaluation: Option<NoMatchEvaluation>,
    frozen_scope_digest: &str,
) -> AbsencePreconditions {
    // Bare-preconditions helper carries no issuer context, so the admitted side
    // is `None`; the retained twin is the presented record itself, exactly what
    // the arrive-together doctrine threads on the production route.
    let retained_eval = evaluation.clone();
    AbsencePreconditions::derive(
        account,
        &BTreeMap::new(),
        None,
        1_700_000_300_000,
        frozen_scope_digest,
        PresentedEvaluation {
            evaluation,
            admitted_query: None,
            retained_evaluation: retained_eval.as_ref(),
        },
    )
    .expect("preconditions")
}

/// The instant every absence case in this suite is judged at.
///
/// It sits after the `retrieved_ms` of every record `source_params` builds
/// (1_700_000_200_000) and before that record's frozen freshness boundary
/// (1_800_000_000_000), so a record built from those parameters is current here
/// and an owner observation taken at or after the retrieval time can cover it.
const ASSESSMENT_MS: i64 = 1_700_000_300_000;

/// One real owner-issued evaluation over the exact closed members of `account`.
///
/// This is the positive evidence #2893's fixture work item 10 asks for, and every
/// commitment it hands to [`NoMatchEvaluationIssuer::new`] is an owner value this
/// suite already produced rather than a literal written to satisfy a validator:
///
/// * `scope_digest` and the `frozen_scope_digest` passed to
///   [`AbsencePreconditions::derive`] are the *same* string, so
///   `check_scope_binding` compares the issuer against itself rather than against
///   a caller-selected one. It is the digest of the frozen scope snapshot this
///   evaluation is bounded to, which is what the scope-binding check means;
/// * `denominator_digest` and `manifest_digest` are read off the very
///   [`AuthorizedManifest`] the evaluation is presented with, and
///   `manifest_revision` is the revision this fixture freezes for that same
///   manifest, so `check_manifest_binding` measures the issuer against that
///   manifest and refuses the pair if the two ever disagree;
/// * the per-member results are minted by `issue_for` itself, which joins each
///   closed member's handle, vetted record, currentness, manifest allowlist,
///   manifest record binding and observation order before a result exists, so
///   none of them is a member name copied out of the accounting.
///
/// The one thing no in-crate check can establish is that the predicate actually
/// ran: the issuer attests that as the evaluator owner's irreducible claim, which
/// is the residual trust boundary documented on [`NoMatchEvaluation`]. What this
/// fixture does establish is the part that was previously absent — that every
/// closing member resolves to a real vetted record under a manifest that commits
/// that exact record, and that the member list alone is no longer what carries
/// the negative.
fn issued_evaluation(
    account: &CoverageAccount,
    records: &BTreeMap<String, SourceRecord>,
    manifest: &AuthorizedManifest,
    frozen_scope_digest: &str,
) -> NoMatchEvaluation {
    let issuer = NoMatchEvaluationIssuer::new(
        NoMatchEvaluationIssuerParams {
            predicate_id: "no-match/absent-valley-alloy".to_owned(),
            predicate_revision: "r1".to_owned(),
            predicate_form: "exists(snapshot_bytes, alloy == member_alloy) == false".to_owned(),
            issuer_id: "evaluator-owner-700".to_owned(),
            evaluator_id: "no-match-evaluator-700".to_owned(),
            evaluator_revision: "evaluator-700.1".to_owned(),
            admission_receipt_id: "admission-700.1".to_owned(),
            fence: fence(),
            work_scope: "propulsion thermal envelope".to_owned(),
            scope_digest: frozen_scope_digest.to_owned(),
            scope_revision: "scope-700.1".to_owned(),
            denominator_digest: inquiry_denominator_digest(),
            manifest_digest: manifest.canonical_digest().expect("manifest commitment"),
            manifest_revision: ABSENCE_MANIFEST_REVISION,
            index_revision: "index-700.1".to_owned(),
            source_revision: "corpus-700.1".to_owned(),
            // At or after every record's retrieval time and at or before the
            // assessment instant, and the currentness bound at or after both, so the
            // observation window covers this assessment rather than merely parsing.
            observed_at_ms: 1_700_000_250_000,
            current_until_ms: 1_700_000_400_000,
            applicability: NoMatchApplicability::Current,
            // Grade 2 is the weakest grade `source_params` gives every record, so a
            // ceiling at that rank is checkable against the joined records rather
            // than an overclaim `check_ceiling` would refuse.
            proof_ceiling_grade: Some(2),
        },
        &admitted_query(),
    )
    .expect("owner issuer");
    issuer
        .issue_for(
            account,
            records,
            manifest,
            frozen_scope_digest,
            ASSESSMENT_MS,
        )
        .expect("owner-issued evaluation")
}

/// The same twenty owner commitments [`issued_evaluation`] holds, as a mutable value.
///
/// Each issuer-refusal case mutates exactly one field (scope, manifest revision, clock, identity)
/// and asserts the exact refusal; the unmutated value must issue exactly what
/// [`issued_evaluation`] issues, which the positive control in the foreign-scope issuer test pins.
/// This helper exists so those cases stay one link each instead of restating the commitment set.
fn issuer_params_for(
    manifest: &AuthorizedManifest,
    frozen_scope_digest: &str,
) -> NoMatchEvaluationIssuerParams {
    NoMatchEvaluationIssuerParams {
        predicate_id: "no-match/absent-valley-alloy".to_owned(),
        predicate_revision: "r1".to_owned(),
        predicate_form: "exists(snapshot_bytes, alloy == member_alloy) == false".to_owned(),
        issuer_id: "evaluator-owner-700".to_owned(),
        evaluator_id: "no-match-evaluator-700".to_owned(),
        evaluator_revision: "evaluator-700.1".to_owned(),
        admission_receipt_id: "admission-700.1".to_owned(),
        fence: fence(),
        work_scope: "propulsion thermal envelope".to_owned(),
        scope_digest: frozen_scope_digest.to_owned(),
        scope_revision: "scope-700.1".to_owned(),
        denominator_digest: inquiry_denominator_digest(),
        manifest_digest: manifest.canonical_digest().expect("manifest commitment"),
        manifest_revision: ABSENCE_MANIFEST_REVISION,
        index_revision: "index-700.1".to_owned(),
        source_revision: "corpus-700.1".to_owned(),
        observed_at_ms: 1_700_000_250_000,
        current_until_ms: 1_700_000_400_000,
        applicability: NoMatchApplicability::Current,
        proof_ceiling_grade: Some(2),
    }
}

/// The admitted query the suite's no-match records are bound to
/// (I21-09:17): the predicate identity and index revision the
/// frozen inquiry admitted, equal to the commitments
/// [`issuer_params_for`] holds.
fn admitted_query() -> AdmittedQueryCommitments {
    AdmittedQueryCommitments::new(
        "no-match/absent-valley-alloy".to_owned(),
        "index-700.1".to_owned(),
    )
    .expect("admitted query")
}

/// The denominator digest of the single frozen inquiry this suite shares.
///
/// Both the authorized manifest and the issuer name the same denominator, because
/// `check_manifest_binding` compares the issuer's held denominator against the
/// presented manifest's — the two are one concept, so they are read from one
/// value rather than spelled twice.
fn inquiry_denominator_digest() -> String {
    FrozenInquiry::freeze(inquiry_params())
        .expect("inquiry")
        .denominator_digest()
}

/// The real positive-absence case: one frozen authorized manifest committing one
/// real vetted record per closed member, and the owner-issued evaluation over
/// exactly those records.
///
/// Returns the account, the vetted record map, the manifest and the evaluation, so
/// the case can assert the positive verdict over them and then assert that the
/// *same* evidence stops proving anything once a single member's record is
/// withheld.
fn proven_absence() -> (
    CoverageAccount,
    BTreeMap<String, SourceRecord>,
    AuthorizedManifest,
    NoMatchEvaluation,
) {
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let members: Vec<String> = inquiry.denominator_members().into_iter().collect();
    let mut account = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    let mut records: BTreeMap<String, SourceRecord> = BTreeMap::new();
    for member in &members {
        // The handle is derived from the member so the accounting handle and the
        // record identity are bound to each other by construction; a synthetic
        // handle with no record behind it is exactly what the join now refuses
        // with `INCOMPATIBLE_SUBSTITUTED_RECORD` / `INCOMPATIBLE_MISSING_RECORD`.
        let handle = format!("src-{member}");
        let entry = record(&handle);
        account
            .record(member, entry.acquisition, Some(entry.handle.clone()))
            .expect("record");
        records.insert(entry.handle.clone(), entry);
    }
    // The manifest is frozen over exactly those records and the exact accounting
    // and denominator the issuer will name, through the same `freeze` call the
    // audit path uses at `audit_binding`.
    let allowlist: Vec<String> = records.keys().cloned().collect();
    let manifest = AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: inquiry.digest.clone(),
        denominator_digest: inquiry.denominator_digest(),
        sources: records
            .iter()
            .map(|(handle, entry)| {
                (
                    handle.clone(),
                    ManifestSource {
                        record_digest: entry.digest().expect("source record commitment"),
                        content_digest: entry.content_digest.clone(),
                        transformed_from: entry.transformed_from.clone(),
                    },
                )
            })
            .collect(),
        dependence_edges: BTreeSet::new(),
        coverage_digest: account.digest(),
        grade_limits: vec!["grade: weakest link applies".to_owned()],
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist,
        revoked: Vec::new(),
        disclosure: DisclosureClass::ProjectBound,
        expires_ms: 1_900_000_000_000,
        revision: ABSENCE_MANIFEST_REVISION,
    })
    .expect("authorized manifest");
    let evaluation =
        issued_evaluation(&account, &records, &manifest, &inquiry.denominator_digest());
    (account, records, manifest, evaluation)
}

fn manifest_for(portfolio: &EvidencePortfolio, inquiry: &FrozenInquiry) -> AuditReferenceBinding {
    let mut sources = BTreeMap::new();
    for (handle, entry) in &portfolio.records {
        sources.insert(
            handle.clone(),
            ManifestSource {
                record_digest: entry.digest().expect("source record commitment"),
                content_digest: entry.content_digest.clone(),
                transformed_from: entry.transformed_from.clone(),
            },
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
    let authorized = AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: inquiry.digest.clone(),
        denominator_digest: inquiry.denominator_digest(),
        sources,
        dependence_edges: edges,
        coverage_digest: portfolio.coverage.digest(),
        grade_limits: vec!["grade: weakest link applies".to_owned()],
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist: allowlist.clone(),
        revoked: Vec::new(),
        disclosure: DisclosureClass::ProjectBound,
        expires_ms: 1_900_000_000_000,
        revision: 1,
    })
    .expect("manifest");
    // The audit job's run-bound allowlist admits exactly the handles the
    // authorized manifest makes citable, under the inquiry's own State Fence, so
    // the two agree exactly as `AuditReferenceBinding::bind` requires.
    let run_manifest = eliot_researcher::manifest(
        format!("run-{}", inquiry.digest),
        inquiry.fence.clone(),
        allowlist,
        format!("root-{}", inquiry.digest),
        "evidence-portfolio-suite",
        "project-bound-suite",
    )
    .expect("run reference manifest");
    AuditReferenceBinding::bind(authorized, run_manifest, inquiry.fence.clone())
        .expect("audit reference binding")
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
        frozen_identities: Vec::new(),
        opposition_relations: Vec::new(),
        // The claim quotes the admitted revision it cites, so the excerpt
        // obligation is decided by the occurrence check rather than reported as
        // unsatisfied for want of a retained original. This case is about
        // authority-domain coverage, and leaving the excerpt unmeasured would
        // replace its finding with a stronger, unrelated one.
        excerpts: vec![excerpt("foreign-src")],
    };
    let verdict = audit_with_excerpts(&claim, &portfolio, &manifest, &["foreign-src"]);
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
        citations: vec!["base-src".to_owned()],
        precision: Vec::new(),
        counterclaim_ids: vec!["rival-src".to_owned()],
        unknown_refs: Vec::new(),
        frozen_identities: Vec::new(),
        opposition_relations: Vec::new(),
        excerpts: vec![excerpt("base-src")],
    };
    let verdict = audit_with_excerpts(&claim, &portfolio, &manifest, &["base-src"]);
    // The old fixture listed `rival-src` as a citation AND as a counterclaim and
    // expected CONTRADICTED. That is the defect #2874 closes: listing a handle
    // contests nothing. With no opposition relation supplied the honest class is
    // NOT_VERIFIABLE_IN_SCOPE, and the identity is still preserved.
    assert_eq!(verdict.outcome, ClaimOutcome::NotVerifiableInScope);
    assert_eq!(
        verdict.public_class(),
        PublicAuditClass::NotVerifiableInScope
    );
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
    let members: Vec<String> = inquiry.denominator_members().into_iter().collect();
    // The positive case first, because it is the one this item exists to make
    // reachable: real vetted records behind every closing member, a frozen
    // authorized manifest that commits exactly those records, and an evaluation
    // minted by the owner issuer over them. `Proven` is now reached, and it is
    // reached *over evidence* rather than over a member list.
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let proven = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(evaluation.clone()),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&evaluation),
        },
    )
    .expect("preconditions over real evidence");
    assert_eq!(
        assess_absence(&account, &proven),
        AbsenceVerdict::Proven,
        "real vetted records under a committed authorized manifest, with an \
         owner-issued per-member result, must prove the scoped absence"
    );
    // The evaluation is what carries the claim, so it is bound: it names every
    // closed member exactly once, it re-proves its own identity, and it carries
    // the proof ceiling the receipt revalidates against. That it names a member
    // only once, and only a member the accounting closed, is not asserted here
    // from the member list — `AbsencePreconditions::derive` recomputes every
    // result identity from the record's own commitments and refuses the record
    // otherwise, so the `Proven` above is itself the proof that each result is
    // the recomputed commitment of the exact record behind its member rather
    // than a name copied out of the accounting.
    let evaluated: Vec<String> = evaluation.evaluated_members();
    assert_eq!(
        evaluated, members,
        "one owner-issued result per closed member, in canonical member order"
    );
    for member in &members {
        let handle = format!("src-{member}");
        let entry = &records[&handle];
        assert_eq!(
            entry.handle, handle,
            "the accounting handle is the vetted record's own, not a stand-in"
        );
    }
    assert_eq!(
        evaluation.proof_ceiling_grade(),
        Some(2),
        "the issued record carries the ceiling the receipt revalidates against"
    );
    evaluation
        .verify_integrity()
        .expect("an issued evaluation re-proves its own identity");
    // The evaluation is bound to the exact scope snapshot the claim is scoped to.
    assert!(
        evaluation.covers_scope(&scope_digest),
        "the issued record is bounded to the same frozen scope snapshot the claim names"
    );
    // Withholding one member's record is the same evidence with one join unmet:
    // the negative is refused and the specific member and reason are retained.
    let withheld = members
        .iter()
        .find(|member| *member == "primary#0")
        .expect("member");
    let mut short = records.clone();
    short.remove(&format!("src-{withheld}"));
    let blocked = AbsencePreconditions::derive(
        &account,
        &short,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(evaluation.clone()),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&evaluation),
        },
    )
    .expect("preconditions over a withheld record");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &blocked) else {
        panic!("a withheld vetted record must not prove absence");
    };
    assert!(
        reason.contains(&format!("{withheld}=missing_vetted_record")),
        "the withheld member and its specific unmet join must be retained: {reason}"
    );
    // The same accounting with no records at all — the shape this case used to
    // assert as `Proven` — still cannot prove anything, and the member list alone
    // never carried the negative.
    let mut synthetic = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    for member in &members {
        synthetic
            .record(
                member,
                SourceDisposition::Observed,
                Some(format!("h-{member}")),
            )
            .expect("record");
    }
    // Corrected by #2893: the synthetic shape this case used to assert as
    // `Proven` — closed `Observed` members, an empty `SourceRecord` map and a
    // caller-authored member list — can no longer prove a predicate ran. Every
    // member is retained with the specific unmet join instead.
    let verdict = assess_absence(&synthetic, &preconditions(&synthetic, None, DIGEST_A));
    let AbsenceVerdict::Unproven { reason } = verdict else {
        panic!("a caller-authored member list over an empty record map must not prove absence");
    };
    for member in &members {
        assert!(
            reason.contains(&format!("{member}=missing_vetted_record")),
            "reason must retain member {member} and its specific unmet join: {reason}"
        );
    }
    let mut gapped = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    for member in &members {
        let disposition = if member == "primary#0" {
            SourceDisposition::Unknown
        } else {
            SourceDisposition::Observed
        };
        gapped
            .record(member, disposition, Some(format!("h-{member}")))
            .expect("record");
    }
    assert!(matches!(
        assess_absence(&gapped, &preconditions(&gapped, None, DIGEST_A)),
        AbsenceVerdict::Unproven { .. }
    ));
    let mut exhausted = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    for member in &members {
        exhausted
            .record(
                member,
                SourceDisposition::Observed,
                Some(format!("h-{member}")),
            )
            .expect("record");
    }
    exhausted
        .note_frontier("route budget ended early")
        .expect("frontier");
    assert!(matches!(
        assess_absence(&exhausted, &preconditions(&exhausted, None, DIGEST_A)),
        AbsenceVerdict::PartialExhaustion { .. }
    ));
    assert!(matches!(
        assess_absence(&gapped, &preconditions(&gapped, None, DIGEST_B)),
        AbsenceVerdict::Unproven { .. }
    ));
}

#[test]
fn absence_substituted_record_is_unproven() {
    // A substituted record is the same evidence with the handle/identity binding
    // broken: the accounting handle `src-primary#0` resolves to a vetted record
    // whose own handle is `src-intruder`. Completeness is proved on the frozen
    // scope (I21-06: `complete_scope` is the only basis on which a scoped absence
    // may be claimed), so a member closed against a record that is not itself that
    // member's record cannot support `Proven`.
    let (account, mut records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    records.insert("src-primary#0".to_owned(), record("src-intruder"));
    let retained_eval = evaluation.clone();
    let substituted = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(evaluation),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&retained_eval),
        },
    )
    .expect("preconditions over a substituted record");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &substituted) else {
        panic!("a substituted vetted record must not prove absence");
    };
    assert!(
        reason.contains("primary#0=record_handle_mismatch"),
        "the substituted member and its specific unmet join must be retained: {reason}"
    );
}

#[test]
fn absence_stale_record_is_unproven() {
    // A stale record is the same evidence with the currentness join unmet: the
    // accounting handle `src-primary#0` still resolves to a vetted record under
    // that exact handle, but its frozen freshness boundary now sits before the
    // assessment instant. Completeness is proved on the frozen scope (I21-06:
    // `complete_scope` is the only basis on which a scoped absence may be
    // claimed), so a member closed against a record that was already stale when
    // the claim was made cannot support `Proven`.
    let (account, mut records, _, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    // Same handle, same everything else, earlier boundary: the constructor puts no
    // constraint on the boundary and `is_stale_at` reports true because the
    // assessment instant is already past it.
    let mut params = source_params("src-primary#0");
    params.freshness_boundary_ms = Some(ASSESSMENT_MS - 1);
    let stale = SourceRecord::new(params).expect("stale record");
    records.insert("src-primary#0".to_owned(), stale);
    // No evaluation and no manifest, on purpose. The record now differs from the
    // one the issuer committed, so binding the evaluation would report the
    // earlier result-record mismatch rather than staleness; the handle, record and
    // currentness joins are the ones that hold or fail without a bound
    // evaluation, and currentness is the claim under test here.
    let stale_preconditions = AbsencePreconditions::derive(
        &account,
        &records,
        None,
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: None,
            admitted_query: None,
            retained_evaluation: None,
        },
    )
    .expect("preconditions over a stale record");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &stale_preconditions) else {
        panic!("a record past its frozen freshness boundary must not prove absence");
    };
    assert!(
        reason.contains("primary#0=record_stale_at_assessment"),
        "the stale member and its specific unmet join must be retained: {reason}"
    );
}

#[test]
fn absence_missing_handle_is_unproven() {
    // A closing member with no acquired handle is the same evidence with the
    // accounting-to-record join impossible: the member *is* closed as `Observed`,
    // so nothing of the denominator is left open, yet no handle exists that could
    // resolve that closure to a vetted record. Completeness is proved on the
    // frozen scope (I21-06: `complete_scope` is the only basis on which a scoped
    // absence may be claimed), so a member that cannot be joined to any record at
    // all cannot support `Proven`.
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let members: Vec<String> = inquiry.denominator_members().into_iter().collect();
    let (_, records, _, _) = proven_absence();
    let mut account = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    for member in &members {
        // Every member carries the same handle the vetted record map is keyed by,
        // except `primary#0`: it is closed with no handle at all, which is the
        // accounting this case is about.
        account
            .record(
                member,
                SourceDisposition::Observed,
                if member == "primary#0" {
                    None
                } else {
                    Some(format!("src-{member}"))
                },
            )
            .expect("record");
    }
    // No bound evaluation and no manifest, on purpose: the manifest
    // `proven_absence()` built commits that fixture's accounting and coverage
    // digest, not this one, and presenting it here would report an accounting
    // mismatch instead of the join under test. The handle join applies on its own
    // without an evaluation, and it is returned first for a member that closed
    // with no handle.
    let handle_less = AbsencePreconditions::derive(
        &account,
        &records,
        None,
        ASSESSMENT_MS,
        &inquiry_denominator_digest(),
        PresentedEvaluation {
            evaluation: None,
            admitted_query: None,
            retained_evaluation: None,
        },
    )
    .expect("preconditions over a missing handle");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &handle_less) else {
        panic!("a closing member with no acquired handle must not prove absence");
    };
    assert!(
        reason.contains("primary#0=missing_acquired_handle"),
        "the handle-less member and its specific unmet join must be retained: {reason}"
    );
}

#[test]
fn absence_foreign_scope_is_unproven() {
    // A foreign scope is the same positive evidence with the scope binding broken:
    // every closing member still resolves to its own vetted record, the manifest
    // still commits those exact records and the owner-issued evaluation still
    // carries a result for every member — but that evaluation was bounded to the
    // digest of the frozen scope snapshot this suite shares, while the claim is
    // scoped to `DIGEST_A`. Completeness is proved on the frozen scope (I21-06:
    // `complete_scope` is the only basis on which a scoped absence may be claimed),
    // so evidence bounded to a different snapshot cannot support `Proven` however
    // complete it is over its own.
    //
    // `AbsencePreconditions::derive` checks only the *shape* of the frozen scope
    // digest, and `DIGEST_A` is a well-formed 64-hex digest, so the preconditions
    // are derived rather than refused there; the binding of the evaluation to the
    // claimed scope is `assess_absence`'s own work at `foreign_evaluation_scope`
    // (`src/evidence_portfolio.rs`).
    let (account, records, manifest, evaluation) = proven_absence();
    let retained_eval = evaluation.clone();
    let foreign = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        DIGEST_A,
        PresentedEvaluation {
            evaluation: Some(evaluation),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&retained_eval),
        },
    )
    .expect("preconditions over a foreign scope");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &foreign) else {
        panic!("an evaluation bounded to a different frozen scope must not prove absence");
    };
    assert!(
        reason.contains(&format!("not to {DIGEST_A}")),
        "the scope the claim is scoped to must be retained: {reason}"
    );
}

#[test]
fn absence_issuer_blank_predicate_refused() {
    // The issuer's own predicate identity is one of the twenty commitments it
    // attests to, so a blank one is an evaluation over an arbitrary string
    // rather than over an identified predicate. Completeness is proved on the
    // frozen scope (I21-06: `complete_scope` is the only basis on which a scoped
    // absence may be claimed), and a claim whose predicate identity is blank
    // cannot be the predicate that completeness was proved for, so the issuer
    // refuses to exist rather than mint one. Only `predicate_id` is mutated here;
    // every other owner commitment is the value `issued_evaluation` holds, so the
    // refusal names this field alone.
    let (_, _, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_id = String::new();
    let err = NoMatchEvaluationIssuer::new(params, &admitted_query())
        .expect_err("a blank predicate identity must be refused");
    // `Blank` renders as `{field} must be non-blank`, so the display is what
    // names the exact field path the constructor refused.
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Blank { .. }),
        "a blank identity must be refused as `Blank`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.predicate_id"),
        "the refused field must be the predicate identity itself: {rendered}"
    );
}

#[test]
fn absence_issuer_blank_index_refused() {
    // The same refusal on the other identity this pair covers: the revision of
    // the source/index the predicate runs against. A blank index revision attests
    // to an evaluation over whatever the index happened to hold at claim time, so
    // the exact-negative claim it would back is not the one completeness was
    // proved for on the frozen scope (I21-06: `complete_scope` is the only basis
    // on which a scoped absence may be claimed). Only `index_revision` is
    // mutated, so this names its own field rather than the predicate identity
    // the sibling case refuses.
    let (_, _, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.index_revision = String::new();
    let err = NoMatchEvaluationIssuer::new(params, &admitted_query())
        .expect_err("a blank index identity must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Blank { .. }),
        "a blank identity must be refused as `Blank`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.index_revision"),
        "the refused field must be the index identity itself: {rendered}"
    );
}

/// A well-formed predicate the admitted query does not carry is a
/// different query, not a malformed one (issue #2893 W10/A2): every
/// shape validation passes, so the admitted binding is what refuses
/// the mint. Only `predicate_id` is mutated, so this names that
/// binding alone.
#[test]
fn absence_unadmitted_predicate_refused_at_issuance() {
    let (_, _, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_id = "unadmitted-arbitrary-predicate".to_owned();
    let err = NoMatchEvaluationIssuer::new(params, &admitted_query())
        .expect_err("a predicate the admitted query does not carry must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "an unadmitted predicate identity must be refused as `Conflict`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.predicate_id"),
        "the refused field must be the predicate identity binding itself: {rendered}"
    );
}

/// The same refusal on the other half of the admitted binding: a
/// well-formed but unadmitted index revision passes every shape
/// validation, so the admitted comparison is what refuses the mint.
/// Only `index_revision` is mutated, so this names that binding alone.
#[test]
fn absence_unadmitted_index_refused_at_issuance() {
    let (_, _, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.index_revision = "index-UNADMITTED.9".to_owned();
    let err = NoMatchEvaluationIssuer::new(params, &admitted_query())
        .expect_err("an index revision the admitted query does not carry must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "an unadmitted index revision must be refused as `Conflict`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.index_revision"),
        "the refused field must be the index revision binding itself: {rendered}"
    );
}

#[test]
fn absence_issuer_foreign_scope_refused() {
    // The issuer holds the frozen scope its evaluation is bounded to, so an
    // issuer asked to attest a scope it does not hold would mint a record whose
    // own `scope_digest` contradicts the completeness it claims. Completeness is
    // proved on the frozen scope (I21-06: `complete_scope` is the only basis on
    // which a scoped absence may be claimed), so the binding is the issuer's to
    // refuse at minting rather than the assessor's to discover on readback:
    // `issue_for` runs `check_scope_binding` before any other commitment, and
    // `DIGEST_A` is a well-formed digest, so this refusal names the scope binding
    // alone.
    //
    // The positive control first pins that the unmutated helper value issues
    // exactly what `issued_evaluation` issues, so the refusal below is caused by
    // the mutated scope alone.
    let (account, records, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let issuer = NoMatchEvaluationIssuer::new(
        issuer_params_for(&manifest, &scope_digest),
        &admitted_query(),
    )
    .expect("owner issuer");
    issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("positive control issues");

    let bad =
        NoMatchEvaluationIssuer::new(issuer_params_for(&manifest, DIGEST_A), &admitted_query())
            .expect("issuer holds another scope");
    let err = bad
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect_err("a foreign scope must be refused");
    // `Conflict` renders as `{field} conflicts with frozen content`, so the display
    // is what names the exact field path the issuer refused.
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a foreign frozen scope must be refused as `Conflict`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.scope_digest"),
        "the refused field must be the scope binding itself: {rendered}"
    );
}

/// The issuer holds the exact revision of the manifest it attests, so an issuer
/// asked to mint against a manifest it does not hold would produce a record whose
/// own commitments claim completeness on a revision of the sources it never
/// reviewed. Completeness is proved on the frozen scope and the exact frozen
/// source revision (I21-06: `complete_scope` is the only basis on which a scoped
/// absence may be claimed), so the revision binding is the issuer's to refuse at
/// minting rather than the assessor's to discover on readback.
///
/// The scope binding passes here, so the refusal is caused by the revision alone:
/// `issue_for` runs `check_manifest_binding` after `check_scope_binding`, and the
/// presented manifest still carries the digest, scope and denominator the issuer
/// holds - only its frozen `revision` is one the issuer did not take.
#[test]
fn absence_issuer_manifest_revision_refused() {
    let (account, records, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.manifest_revision = ABSENCE_MANIFEST_REVISION + 1;
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let err = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect_err("a manifest revision the issuer does not hold must be refused");
    // `Conflict` renders as `{field} conflicts with frozen content`, so the display
    // is what names the exact field path the issuer refused.
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "an unheld manifest revision must be refused as `Conflict`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.manifest_revision"),
        "the refused field must be the manifest revision binding itself: {rendered}"
    );
}

/// An accounting that never enumerated its whole denominator cannot back a
/// scoped absence claim.
///
/// Completeness is proved on the frozen scope, and `complete_scope` is the only
/// basis on which a scoped absence may be claimed (I21.6: `denominator_kind =
/// complete_scope` is the only basis on which a scoped absence may be claimed).
/// An account opened over the exact denominator members that records only some
/// of them still holds the rest open, so the enumeration this record would
/// claim never completed — the unrecorded member is not a disposition at all,
/// it is a missing step. The authorized manifest here commits that exact
/// accounting (`coverage_digest` is this account's own digest) and the issuer
/// holds the presented manifest and the frozen scope, so both bindings pass and
/// `check_enumeration` is what refuses, before any per-member join runs.
///
/// The refusal names the enumeration rather than a disposition: a member
/// recorded `Unknown` would be closed but non-closing and would take the later
/// per-member refusal path instead, so the two cases stay distinguishable.
#[test]
fn absence_issuer_open_enumeration_refused() {
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let members: Vec<String> = inquiry.denominator_members().into_iter().collect();
    let (_, records, _, _) = proven_absence();

    let mut account = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    for member in &members {
        // Skipping the `record` call is what leaves `primary#0` one of the
        // account's `open_members`: the accounting enumerated its denominator
        // only partially. A `Unknown` disposition would close the member and
        // take a different refusal path.
        if member == "primary#0" {
            continue;
        }
        account
            .record(
                member,
                SourceDisposition::Observed,
                Some(format!("src-{member}")),
            )
            .expect("record");
    }

    // The manifest is the same authorized manifest `proven_absence` freezes,
    // field for field, over the same records and denominator; only the
    // `coverage_digest` is this account's own, so the manifest commits the
    // partial accounting instead of the complete one.
    let allowlist: Vec<String> = records.keys().cloned().collect();
    let manifest = AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: inquiry.digest.clone(),
        denominator_digest: inquiry.denominator_digest(),
        sources: records
            .iter()
            .map(|(handle, entry)| {
                (
                    handle.clone(),
                    ManifestSource {
                        record_digest: entry.digest().expect("source record commitment"),
                        content_digest: entry.content_digest.clone(),
                        transformed_from: entry.transformed_from.clone(),
                    },
                )
            })
            .collect(),
        dependence_edges: BTreeSet::new(),
        coverage_digest: account.digest(),
        grade_limits: vec!["grade: weakest link applies".to_owned()],
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist,
        revoked: Vec::new(),
        disclosure: DisclosureClass::ProjectBound,
        expires_ms: 1_900_000_000_000,
        revision: ABSENCE_MANIFEST_REVISION,
    })
    .expect("authorized manifest");

    let scope_digest = inquiry_denominator_digest();
    let issuer = NoMatchEvaluationIssuer::new(
        issuer_params_for(&manifest, &scope_digest),
        &admitted_query(),
    )
    .expect("owner issuer");
    let err = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect_err("an unclosed enumeration must be refused");
    // `IncompleteDenominator` renders as `{field} is not an exact accounted
    // denominator`, so the display is what names the exact field path refused.
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::IncompleteDenominator { .. }),
        "an unclosed enumeration must be refused as `IncompleteDenominator`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.open_members"),
        "the refused field must be the unclosed enumeration itself: {rendered}"
    );
}

/// The owner issuer attests what it observed and only while its account remains
/// current, so it refuses an assessment instant its own window does not cover.
///
/// The scope, manifest and enumeration bindings all pass on this exact setup, so
/// the refusal is caused by the instant alone: `issue_for` runs
/// `check_observation_window` after `check_scope_binding`,
/// `check_manifest_binding` and `check_enumeration`. Both directions matter and
/// are distinct fields: an instant before the issuer observed anything cannot be
/// inside an observation it has not made yet, and an instant past its
/// currentness bound would assess a window that has already gone stale — either
/// one would let a scoped absence claim rest on completeness the issuer cannot
/// vouch for (I21-06: `complete_scope` is the only basis on which a scoped
/// absence may be claimed).
#[test]
fn absence_issuer_observation_window_refused() {
    let (account, records, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    // `issuer_params_for` holds `observed_at_ms = 1_700_000_250_000` and
    // `current_until_ms = 1_700_000_400_000`, so the two instants below sit just
    // outside either edge of that window.
    let issuer = NoMatchEvaluationIssuer::new(
        issuer_params_for(&manifest, &scope_digest),
        &admitted_query(),
    )
    .expect("owner issuer");

    // Too early: the issuer is asked to attest an observation taken before it
    // observed anything.
    let err = issuer
        .issue_for(
            &account,
            &records,
            &manifest,
            &scope_digest,
            1_700_000_200_000,
        )
        .expect_err("an instant before the observation must be refused");
    // `Conflict` renders as `{field} conflicts with frozen content`, so the
    // display is what names the exact field path the issuer refused.
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "an instant before the observation must be refused as `Conflict`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.observed_at_ms"),
        "the refused field must be the observation instant itself: {rendered}"
    );

    // Too late: the issuer is asked to attest inside a window that already
    // expired at minting time.
    let err = issuer
        .issue_for(
            &account,
            &records,
            &manifest,
            &scope_digest,
            1_700_000_500_000,
        )
        .expect_err("an instant past the currentness bound must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "an instant past the currentness bound must be refused as `Conflict`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.current_until_ms"),
        "the refused field must be the currentness bound itself: {rendered}"
    );
}

/// A vetted record rewritten after the owner issued its result no longer commits
/// that result, so the same evidence that proved absence over the original bytes
/// stops proving anything.
///
/// The handle, the accounting, the manifest and the evaluation are exactly
/// `proven_absence`'s; only the bytes behind one member differ, so the per-member
/// result the owner minted no longer names the record now standing behind that
/// member. `member_join_reason` compares the result's `record_digest` against the
/// joined record's own canonical digest before staleness and before the manifest
/// joins, so the retained reason is the digest mismatch itself (I21-06:
/// `complete_scope` is the only basis on which a scoped absence may be claimed).
#[test]
fn absence_changed_record_breaks_result_binding() {
    let (account, mut records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    // Any field change alters the record's canonical digest, so the result issued
    // over the original record no longer commits this one.
    let mut params = source_params("src-primary#0");
    params.title = "a changed title for src-primary#0".to_owned();
    let changed = SourceRecord::new(params).expect("changed record");
    records.insert("src-primary#0".to_owned(), changed);
    let retained_eval = evaluation.clone();
    let changed_binding = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(evaluation),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&retained_eval),
        },
    )
    .expect("preconditions over a changed record");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &changed_binding) else {
        panic!("a changed vetted record must not prove absence");
    };
    assert!(
        reason.contains("primary#0=result_record_digest_mismatch"),
        "the changed member and its specific unmet join must be retained: {reason}"
    );
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
        frozen_identities: Vec::new(),
        opposition_relations: Vec::new(),
        excerpts: vec![excerpt("base-src")],
    };
    let verdict = audit_with_excerpts(&hidden_unknown, &portfolio, &manifest, &["base-src"]);
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
        frozen_identities: Vec::new(),
        opposition_relations: Vec::new(),
        // No excerpt, because there is no admitted citation to quote one from.
        // An excerpt naming an unadmitted handle would be refused as fabricated
        // and would replace the "records no citations" finding this case is
        // about with a different one.
        excerpts: Vec::new(),
    };
    let verdict = audit_with_excerpts(&bare, &portfolio, &manifest, &[]);
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
        frozen_identities: Vec::new(),
        opposition_relations: Vec::new(),
        excerpts: vec![excerpt("base-src")],
    };
    // A claim with no frozen identity cannot be released as supported: there is
    // nothing to check its wording and revision against, so `MethodArtifact-
    // Alignment` fails by construction. The internal outcome stays
    // INCOMPLETE_ACCOUNTING rather than acquiring a new terminal class.
    let verdict = audit_with_excerpts(&clean, &portfolio, &manifest, &["base-src"]);
    assert_eq!(verdict.outcome, ClaimOutcome::IncompleteAccounting);
    assert_eq!(
        verdict.public_class(),
        PublicAuditClass::NotVerifiableInScope
    );
    assert!(!verdict.dimensions_complete());
    assert_eq!(verdict.grade_ceiling, Some(2));
    assert!(GOLDEN.contains("INCOMPLETE_ACCOUNTING"));
    assert!(GOLDEN.contains("SUPPORTED"));
    assert!(GOLDEN.contains("weakest_link"));
}

/// Two examined candidates the frozen denominator never declared.
fn examined_two() -> Vec<ObservedOutsideScope> {
    vec![
        ObservedOutsideScope {
            handle: "witness-a".to_owned(),
            disposition: SourceDisposition::Observed,
            content_digest: DIGEST_A.to_owned(),
            operation_id: "op-1".to_owned(),
            admitted_manifest_digest: DIGEST_A.to_owned(),
        },
        ObservedOutsideScope {
            handle: "witness-b".to_owned(),
            disposition: SourceDisposition::Observed,
            content_digest: DIGEST_A.to_owned(),
            operation_id: "op-2".to_owned(),
            admitted_manifest_digest: DIGEST_A.to_owned(),
        },
    ]
}

#[test]
fn open_verified_empty_refuses_unexamined() {
    assert!(matches!(
        CoverageAccount::open_verified_empty(&[]),
        Err(PortfolioError::IncompleteDenominator { .. })
    ));
    assert!(matches!(
        CoverageAccount::open(BTreeSet::new()),
        Err(PortfolioError::IncompleteDenominator { .. })
    ));
}

#[test]
fn open_verified_empty_retains_examined() {
    let account =
        CoverageAccount::open_verified_empty(&examined_two()).expect("verified empty account");
    assert_eq!(account.denominator_size(), 0);
    assert!(account.is_verified_empty());
    assert!(account.open_members().is_empty());
    assert_eq!(account.observed_outside_scope().len(), 2);
}

// Issue #1767 A5: the science grade binds evaluator linkage through the real
// requirement selector. Three records with distinct lineage roots, providers,
// ancestors and assumptions satisfy every axis only when their evaluators are
// distinct; one shared evaluator holds the EvaluatorFamily axis (and the whole
// profile) unmet. Grade scoping itself stays with `select_independence_requirement`
// (I21.2/I21.3): lower grades do not request the axis, so no linkage is
// demanded of them here.
fn evaluator_case_records(shared_evaluator: bool) -> BTreeMap<String, SourceRecord> {
    let mut records = BTreeMap::new();
    for handle in ["eval-a", "eval-b", "eval-c"] {
        let mut params = source_params(handle);
        params.transformed_from = Some(format!("parent-{handle}"));
        params.evaluator_family = Some(if shared_evaluator {
            "evaluator-shared".to_owned()
        } else {
            format!("evaluator-{handle}")
        });
        records.insert(
            handle.to_owned(),
            SourceRecord::new(params).expect("evaluator case record"),
        );
    }
    records
}

fn science_evaluator_profile(
    records: &BTreeMap<String, SourceRecord>,
) -> eliot_researcher::inquiry_governance::IndependenceProfile {
    use eliot_researcher::inquiry_governance::{EvidenceGrade, select_independence_requirement};

    let grade = EvidenceGrade::from_name("SCIENCE_GRADE").expect("science grade");
    let (dimensions, minimum) = select_independence_requirement(grade);
    assert!(
        dimensions.contains(
            &eliot_researcher::inquiry_governance::IndependenceDimension::EvaluatorFamily
        ),
        "the science grade must request the evaluator axis"
    );
    let eligible: Vec<String> = records.keys().cloned().collect();
    eliot_researcher::inquiry_governance::IndependenceProfile::derive(
        &eligible,
        records,
        &dimensions,
        minimum,
    )
}

#[test]
fn shared_evaluator_does_not_satisfy_science_requirement() {
    use eliot_researcher::inquiry_governance::IndependenceDimension;

    let records = evaluator_case_records(true);
    let profile = science_evaluator_profile(&records);
    assert!(
        !profile.meets_requirement,
        "one evaluator behind three records must not satisfy the science requirement"
    );
    let evaluator = profile
        .dimensions
        .iter()
        .find(|measurement| measurement.dimension == IndependenceDimension::EvaluatorFamily)
        .expect("evaluator axis is measured");
    assert!(
        !evaluator.meets_requirement,
        "the shared evaluator axis must stay unmet"
    );
    assert_eq!(
        evaluator.groups,
        vec!["evaluator-shared".to_owned()],
        "the shared evaluator collapses to exactly one family"
    );
}

#[test]
fn absence_issuer_nonblank_predicate_refused() {
    let (_, _, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_id = "no-match/absent-valley-alloy\u{7}".to_owned();
    let err = NoMatchEvaluationIssuer::new(params, &admitted_query())
        .expect_err("a control-bearing predicate identity must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::ControlCharacter { .. }),
        "a control-bearing identity must be refused as `ControlCharacter`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.predicate_id"),
        "the refused field must be the predicate identity itself: {rendered}"
    );
}

#[test]
fn absence_issuer_nonblank_index_refused() {
    let (_, _, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.index_revision = "index-700.1\u{7}".to_owned();
    let err = NoMatchEvaluationIssuer::new(params, &admitted_query())
        .expect_err("a control-bearing index revision must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::ControlCharacter { .. }),
        "a control-bearing revision must be refused as `ControlCharacter`, not as some other refusal: {rendered}"
    );
    assert!(
        rendered.contains("no_match_issuer.index_revision"),
        "the refused field must be the index revision itself: {rendered}"
    );
}

#[test]
fn absence_closed_denominator_missing_result_is_unproven() {
    let (_, mut records, _, evaluation) = proven_absence();
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let mut members: Vec<String> = inquiry.denominator_members().into_iter().collect();
    members.push("primary#extra".to_owned());
    let mut account = CoverageAccount::open(members.iter().cloned().collect()).expect("account");
    for member in &members {
        let handle = format!("src-{member}");
        if member == "primary#extra" {
            records.insert(handle.clone(), record(&handle));
        }
        account
            .record(member, SourceDisposition::Observed, Some(handle))
            .expect("record");
    }
    let allowlist: Vec<String> = records.keys().cloned().collect();
    let manifest = AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: inquiry.digest.clone(),
        denominator_digest: inquiry.denominator_digest(),
        sources: records
            .iter()
            .map(|(handle, entry)| {
                (
                    handle.clone(),
                    ManifestSource {
                        record_digest: entry.digest().expect("source record commitment"),
                        content_digest: entry.content_digest.clone(),
                        transformed_from: entry.transformed_from.clone(),
                    },
                )
            })
            .collect(),
        dependence_edges: BTreeSet::new(),
        coverage_digest: account.digest(),
        grade_limits: vec!["grade: weakest link applies".to_owned()],
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist,
        revoked: Vec::new(),
        disclosure: DisclosureClass::ProjectBound,
        expires_ms: 1_900_000_000_000,
        revision: ABSENCE_MANIFEST_REVISION,
    })
    .expect("authorized manifest");
    let scope_digest = inquiry_denominator_digest();
    let retained_eval = evaluation.clone();
    let preconditions = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(evaluation),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&retained_eval),
        },
    )
    .expect("preconditions over a closed denominator with a missing result");
    let AbsenceVerdict::Unproven { reason } = assess_absence(&account, &preconditions) else {
        panic!("a closed member with no owner-issued result must not prove absence");
    };
    assert!(
        reason.contains("primary#extra=no_predicate_result"),
        "the result-less member and its specific unmet join must be retained: {reason}"
    );
    assert!(
        reason.contains("5 closed member(s)"),
        "all five members must be closed (no open/unclosed arm may fire first): {reason}"
    );
}

#[test]
fn absence_replay_is_identical_under_one_identity() {
    let (account, records, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let issuer_a = NoMatchEvaluationIssuer::new(
        issuer_params_for(&manifest, &scope_digest),
        &admitted_query(),
    )
    .expect("owner issuer");
    let eval_a = issuer_a
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("first issuance");
    let issuer_b = NoMatchEvaluationIssuer::new(
        issuer_params_for(&manifest, &scope_digest),
        &admitted_query(),
    )
    .expect("owner issuer");
    let eval_b = issuer_b
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("replayed issuance");
    assert_eq!(
        eval_a.canonical_digest().expect("digest"),
        eval_b.canonical_digest().expect("digest"),
        "an exact replay under one admitted identity must be byte-identical"
    );
    assert_eq!(
        eval_a.canonical_bytes().expect("canonical bytes"),
        eval_b.canonical_bytes().expect("canonical bytes"),
        "an exact replay must preserve the actual canonical bytes"
    );
    eval_a
        .check_replay_consistency(&eval_b)
        .expect("an exact replay is consistent");
}

#[test]
fn absence_replay_conflicts_on_changed_predicate() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_form = "exists(snapshot_bytes, alloy == other_alloy) == false".to_owned();
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        changed.canonical_digest().expect("digest"),
        "the predicate bytes must be load-bearing in the record identity"
    );
    let err = evaluation
        .check_replay_consistency(&changed)
        .expect_err("same identity with a changed predicate must conflict");
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a changed predicate under one identity must conflict: {err}"
    );
    assert!(
        err.to_string()
            .contains("no_match_evaluation.predicate_form"),
        "the conflict must name the predicate bytes: {err}"
    );
}

#[test]
fn distinct_evaluators_satisfy_science_requirement() {
    let records = evaluator_case_records(false);
    let profile = science_evaluator_profile(&records);
    assert!(
        profile.meets_requirement,
        "distinct evaluators over distinct roots/providers/ancestors/assumptions satisfy science"
    );
}

#[test]
fn absence_replay_conflicts_on_changed_source_revision() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.source_revision = "corpus-700.2".to_owned();
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        changed.canonical_digest().expect("digest"),
        "the source revision must be load-bearing in the record identity"
    );
    let err = evaluation
        .check_replay_consistency(&changed)
        .expect_err("same identity with a changed source revision must conflict");
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a changed source revision under one identity must conflict: {err}"
    );
    assert!(
        err.to_string()
            .contains("no_match_evaluation.source_revision"),
        "the conflict must name the source revision: {err}"
    );
}

#[test]
fn absence_replay_conflicts_on_changed_evaluator() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.evaluator_id = "no-match-evaluator-701".to_owned();
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        changed.canonical_digest().expect("digest"),
        "the evaluator identity must be load-bearing in the record identity"
    );
    let err = evaluation
        .check_replay_consistency(&changed)
        .expect_err("same identity with a changed evaluator must conflict");
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a changed evaluator under one identity must conflict: {err}"
    );
    assert!(
        err.to_string().contains("no_match_evaluation.evaluator_id"),
        "the conflict must name the evaluator identity: {err}"
    );
}

#[test]
fn absence_replay_conflicts_on_changed_member_result() {
    let (account, mut records, _, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = source_params("src-primary#0");
    params.title = "a changed title for src-primary#0".to_owned();
    records.insert(
        "src-primary#0".to_owned(),
        SourceRecord::new(params).expect("changed record"),
    );
    let inquiry = FrozenInquiry::freeze(inquiry_params()).expect("inquiry");
    let allowlist: Vec<String> = records.keys().cloned().collect();
    let manifest = AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: inquiry.digest.clone(),
        denominator_digest: inquiry.denominator_digest(),
        sources: records
            .iter()
            .map(|(handle, entry)| {
                (
                    handle.clone(),
                    ManifestSource {
                        record_digest: entry.digest().expect("source record commitment"),
                        content_digest: entry.content_digest.clone(),
                        transformed_from: entry.transformed_from.clone(),
                    },
                )
            })
            .collect(),
        dependence_edges: BTreeSet::new(),
        coverage_digest: account.digest(),
        grade_limits: vec!["grade: weakest link applies".to_owned()],
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist,
        revoked: Vec::new(),
        disclosure: DisclosureClass::ProjectBound,
        expires_ms: 1_900_000_000_000,
        revision: ABSENCE_MANIFEST_REVISION,
    })
    .expect("authorized manifest");
    let issuer = NoMatchEvaluationIssuer::new(
        issuer_params_for(&manifest, &scope_digest),
        &admitted_query(),
    )
    .expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        changed.canonical_digest().expect("digest"),
        "the member result must be load-bearing in the record identity"
    );
    let err = evaluation
        .check_replay_consistency(&changed)
        .expect_err("same identity with a changed member result must conflict");
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a changed member result under one identity must conflict: {err}"
    );
    assert!(
        err.to_string().contains("no_match_evaluation.results"),
        "the conflict must name the member results: {err}"
    );
}

#[test]
fn absence_replay_conflicts_on_changed_work_scope() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.work_scope = "propulsion acoustic envelope".to_owned();
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        changed.canonical_digest().expect("digest"),
        "the work scope must be load-bearing in the record identity"
    );
    let err = evaluation
        .check_replay_consistency(&changed)
        .expect_err("same identity with a changed work scope must conflict");
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a changed work scope under one identity must conflict: {err}"
    );
    assert!(
        err.to_string()
            .contains("no_match_evaluation.canonical_body"),
        "the conflict must name the canonical body: {err}"
    );
}

#[test]
fn absence_replay_conflicts_on_changed_scope_revision() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.scope_revision = "scope-700.2".to_owned();
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        changed.canonical_digest().expect("digest"),
        "the scope revision must be load-bearing in the record identity"
    );
    let err = evaluation
        .check_replay_consistency(&changed)
        .expect_err("same identity with a changed scope revision must conflict");
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a changed scope revision under one identity must conflict: {err}"
    );
    assert!(
        err.to_string()
            .contains("no_match_evaluation.canonical_body"),
        "the conflict must name the canonical body: {err}"
    );
}

/// A well-formed evaluation under a different predicate identity is a
/// different claim, not a replay (issue #2893 W10/A2 round-2).
///
/// The admitted issuer holds `no-match/absent-valley-alloy`. An issuer
/// holding the well-formed but unadmitted `unadmitted-arbitrary-predicate`
/// still issues successfully over the same closed account, vetted records
/// and authorized manifest — issuance joins the presented evidence against
/// the issuer's own held commitments, and a different predicate is a
/// different admitted identity, not malformed text. Across the two records
/// `check_replay_consistency` is `Ok`: records under different identities
/// are different claims and nothing is compared.
#[test]
fn absence_foreign_predicate_is_a_different_claim() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_id = "unadmitted-arbitrary-predicate".to_owned();
    let foreign_issuer = NoMatchEvaluationIssuer::new(
        params,
        &AdmittedQueryCommitments::new(
            "unadmitted-arbitrary-predicate".to_owned(),
            "index-700.1".to_owned(),
        )
        .expect("foreign admitted"),
    )
    .expect("foreign issuer");
    let foreign = foreign_issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("well-formed foreign issuance still issues");
    assert_ne!(
        evaluation.canonical_digest().expect("digest"),
        foreign.canonical_digest().expect("digest"),
        "the predicate identity must be load-bearing in the record identity"
    );
    evaluation
        .check_replay_consistency(&foreign)
        .expect("different admitted identities are different claims, never a conflict");
}

/// Assessing a well-formed foreign-predicate evaluation pins the retained
/// gap (issue #2893 W10/A2 round-2).
///
/// The foreign record above is fully self-consistent: it was issued over
/// the real closed account, vetted records and authorized manifest, so every
/// join `AbsencePreconditions::derive` performs recomputes cleanly and the
/// verdict is `Proven`. That verdict proves only the record's own
/// consistency — this crate holds no predicate registry or admission ledger
/// against which the presented `predicate_id` could be bound to the
/// inquiry's admitted query (stated residual on `NoMatchEvaluation`; owner
/// route: the live evaluator composition, #1762). A caller that mints a
/// second well-formed issuer answers a different query and still closes.
/// This test pins that behavior so the gap stays visible instead of being
/// covered by a malformed-text shape check.
#[test]
fn absence_presented_without_retained_refused_on_consuming_path() {
    let (account, records, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_id = "unadmitted-arbitrary-predicate".to_owned();
    let foreign_admitted = AdmittedQueryCommitments::new(
        "unadmitted-arbitrary-predicate".to_owned(),
        "index-700.1".to_owned(),
    )
    .expect("foreign admitted");
    let foreign_issuer =
        NoMatchEvaluationIssuer::new(params, &foreign_admitted).expect("foreign issuer");
    let foreign = foreign_issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("well-formed foreign issuance still issues");
    // The admitted join passes (foreign admitted matches the presented
    // record), so the refusal below names the retained join alone.
    let err = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(foreign),
            admitted_query: Some(&foreign_admitted),
            retained_evaluation: None,
        },
    )
    .expect_err("a presented record with no retained record must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a presented-but-unretained record must be refused as `Conflict`: {rendered}"
    );
    assert!(
        rendered.contains("absence.presented_without_retained"),
        "the refusal must name the retained join itself: {rendered}"
    );
}

/// A presented record answering a query the admitted side does not carry
/// refuses on the consuming path even when a retained twin exists (issue
/// #2893 W10/A2-consume): the retained join passes (twin of the presented
/// record), so the refusal below names the admitted join alone.
#[test]
fn absence_unadmitted_presented_refused_on_consuming_path() {
    let (account, records, manifest, _) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.predicate_id = "unadmitted-arbitrary-predicate".to_owned();
    let foreign_admitted = AdmittedQueryCommitments::new(
        "unadmitted-arbitrary-predicate".to_owned(),
        "index-700.1".to_owned(),
    )
    .expect("foreign admitted");
    let foreign_issuer =
        NoMatchEvaluationIssuer::new(params, &foreign_admitted).expect("foreign issuer");
    let foreign = foreign_issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("well-formed foreign issuance still issues");
    let retained_foreign = foreign.clone();
    let err = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(foreign),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&retained_foreign),
        },
    )
    .expect_err("a presented record under an unadmitted query must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "an unadmitted presented record must be refused as `Conflict`: {rendered}"
    );
    assert!(
        rendered.contains("no_match_evaluation.predicate_id"),
        "the refusal must name the predicate identity binding itself: {rendered}"
    );
}

/// A presented record diverging from the retained record under one admitted
/// identity refuses on the consuming path (issue #2893 A5/W8-consume): the
/// admitted join passes (predicate and index unchanged), so the refusal below
/// names the replay join alone.
#[test]
fn absence_replay_conflict_refused_on_consuming_path() {
    let (account, records, manifest, evaluation) = proven_absence();
    let scope_digest = inquiry_denominator_digest();
    let mut params = issuer_params_for(&manifest, &scope_digest);
    params.work_scope = "propulsion acoustic envelope".to_owned();
    let issuer = NoMatchEvaluationIssuer::new(params, &admitted_query()).expect("owner issuer");
    let changed = issuer
        .issue_for(&account, &records, &manifest, &scope_digest, ASSESSMENT_MS)
        .expect("changed issuance still issues");
    let err = AbsencePreconditions::derive(
        &account,
        &records,
        Some(&manifest),
        ASSESSMENT_MS,
        &scope_digest,
        PresentedEvaluation {
            evaluation: Some(changed),
            admitted_query: Some(&admitted_query()),
            retained_evaluation: Some(&evaluation),
        },
    )
    .expect_err("a presented record diverging from the retained record must be refused");
    let rendered = err.to_string();
    assert!(
        matches!(err, PortfolioError::Conflict { .. }),
        "a same-identity divergence must be refused as `Conflict`: {rendered}"
    );
    assert!(
        rendered.contains("no_match_evaluation.canonical_body"),
        "the conflict must name the canonical body: {rendered}"
    );
}

// Issue #1765 W1/A4/A5: the freeze carries its admission/persistence receipts
// and owns its retained bytes. A freeze built by `EvidenceFreeze::freeze`
// round-trips through `retained_bytes`/`reload` against itself with its digest
// re-proved from the bytes; truncated bytes refuse as undecodable, and bytes
// of another freeze refuse as the wrong origin.
const FREEZE_DIGEST: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn freeze_profile() -> InquiryProtocolProfile {
    let grade = EvidenceGrade::from_name("CORROBORATED").expect("canonical grade");
    InquiryProtocolProfile {
        profile_id: "profile-fz-1".to_owned(),
        revision: 1,
        supersedes: None,
        inquiry_id: "freeze-inq-1".to_owned(),
        operation_id: "op-fz-1".to_owned(),
        exchange_id: "ex-fz-1".to_owned(),
        question: "which valve alloy survives the thermal envelope".to_owned(),
        intended_decision_or_artifact: "decide valve alloy".to_owned(),
        scope: "thermal envelope alloy review".to_owned(),
        requester_principal: "principal-fz".to_owned(),
        admitted_inquiry_digest: FREEZE_DIGEST.to_owned(),
        protocol: InquiryProtocol::EvidenceReview,
        selection_features_digest: FREEZE_DIGEST.to_owned(),
        evidence_grade: grade,
        lane: InquiryLane::Exploratory,
        coverage_goal: CoverageGoal::Exhaustive,
        admitted_coverage_goal: "exhaustive".to_owned(),
        admitted_coverage_goal_resolved: true,
        hypothesis_policy: HypothesisPolicy::FalsificationRequired,
        truth_surfaces_and_admissible_providers: vec!["surface-fz".to_owned()],
        admissible_source_classes: vec![SourceClass::Paper],
        reference_manifest_digest: FREEZE_DIGEST.to_owned(),
        admitted_denominator_digest: FREEZE_DIGEST.to_owned(),
        independence_and_blinding_policy: IndependenceBlindingPolicy::resolve(
            grade,
            InquiryLane::Exploratory,
            vec![],
            0,
            vec![],
            vec![],
            vec![],
            None,
        )
        .expect("exploratory policy"),
        independence_and_blinding_policy_digest: FREEZE_DIGEST.to_owned(),
        registration_binding_digest: FREEZE_DIGEST.to_owned(),
        fidelity_ceiling: "ceiling-fz".to_owned(),
        stop_rule: InquiryStopRule::resolve(
            8,
            1_800_000_000_000,
            StopRuleKind::BudgetOrDeadlineExhausted,
            "cancel-fz",
        )
        .expect("stop rule"),
        output_contract: InquiryOutputContract::resolve(
            "result-schema-fz",
            vec![ReopenCondition::NewEvidenceAvailable],
        )
        .expect("output contract"),
        disclosure_ceiling: DisclosureClass::ProjectBound,
        state_fence: fence(),
        change_reason: "initial".to_owned(),
        integrity_digest: FREEZE_DIGEST.to_owned(),
    }
}

fn freeze_receipt(handle: &str) -> FreezeMemberReceipt {
    FreezeMemberReceipt {
        source_handle: handle.to_owned(),
        admission_digest: FREEZE_DIGEST.to_owned(),
        content_digest: FREEZE_DIGEST.to_owned(),
        persistence_digest: FREEZE_DIGEST.to_owned(),
        retained_artifact_ref: format!("artifact:{handle}"),
    }
}

fn frozen(handle: &str, inquiry: &str) -> EvidenceFreeze {
    let profile = freeze_profile();
    EvidenceFreeze::freeze(
        EvidenceFreezeParams {
            inquiry_id: inquiry.to_owned(),
            portfolio_digest: FREEZE_DIGEST.to_owned(),
            manifest_digest: FREEZE_DIGEST.to_owned(),
            coverage_receipt_digest: FREEZE_DIGEST.to_owned(),
            evidence_set_id: "freeze-es-1".to_owned(),
            included_evidence_refs: vec![handle.to_owned()],
            member_receipts: vec![freeze_receipt(handle)],
            excluded_evidence: Vec::new(),
            unresolved_contradictions: Vec::new(),
            open_research_debts: Vec::new(),
            frozen_at_ms: 1_700_000_400_000,
            supersedes: None,
            supersede_reason: None,
            expected_revision: None,
        },
        &profile,
    )
    .expect("freeze")
}

#[test]
fn freeze_retained_bytes_reload_roundtrip() {
    let origin = frozen("frz-a", "freeze-inq-1");
    let bytes = origin.retained_bytes().expect("retained bytes");
    let reloaded = EvidenceFreeze::reload(&bytes, &origin).expect("reload");
    assert_eq!(
        reloaded, origin,
        "retained bytes reload to the freeze they were written from"
    );
    assert_eq!(
        reloaded.digest, origin.digest,
        "the digest is re-proved from the bytes, not trusted from outside"
    );
}

#[test]
fn freeze_reload_refuses_tampered_and_foreign() {
    let origin = frozen("frz-a", "freeze-inq-1");
    let bytes = origin.retained_bytes().expect("retained bytes");
    let cut = &bytes[..bytes.len() - 10];
    assert!(
        matches!(
            EvidenceFreeze::reload(cut, &origin),
            Err(InquiryError::FreezeStoreDecode { .. })
        ),
        "truncated bytes are not a freeze of the declared shape"
    );
    let other = frozen("frz-b", "freeze-inq-1");
    assert!(
        matches!(
            EvidenceFreeze::reload(&bytes, &other),
            Err(InquiryError::UnknownHandle { .. })
        ),
        "bytes of another freeze are not the origin they are read against"
    );
}
