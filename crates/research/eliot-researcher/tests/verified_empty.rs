//! Verified-empty enumeration-state wire spelling (issue #1767, W1/A2).
//!
//! A verified empty eligible scope is its own enumeration state, distinct
//! from an enumeration that never ran. The wire spelling is the contract
//! every later W1 slice binds against, so the four states must render
//! distinct wire names.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, DisclosureClass, SourceClass,
};
use eliot_researcher::evidence_portfolio::{
    AbsenceVerdict, CoverageAccount, EvidenceSpan, ObservedOutsideScope, PortfolioError, RiskState,
    SourceDisposition, SourceRecord, SourceRecordParams,
};
use eliot_researcher::inquiry_governance::{
    CoverageGoal, CoverageReceipt, CoverageReceiptParams, DenominatorKind, EnumerationState,
    EvidenceGrade, HypothesisPolicy, IndependenceBlindingPolicy, InquiryError, InquiryLane,
    InquiryOutputContract, InquiryProtocol, InquiryProtocolProfile, InquiryStopRule,
    ReopenCondition, SourcePortfolio, StopRuleKind, rederive_coverage_account_digest,
};
use eliot_researcher::source_admissibility::{
    SourceAdmissibilityRecord, SourceEligibility, SourceIndependence, SourceLimits,
};

#[test]
fn verified_empty_wire_spelling_is_distinct() {
    let wire_names = [
        EnumerationState::Uninitialised.wire_name(),
        EnumerationState::Incomplete.wire_name(),
        EnumerationState::Complete.wire_name(),
        EnumerationState::VerifiedEmpty.wire_name(),
    ];
    for (index, wire_name) in wire_names.iter().enumerate() {
        for other in wire_names.iter().skip(index + 1) {
            assert_ne!(wire_name, other, "wire names must be distinct");
        }
    }
    assert_eq!(
        EnumerationState::VerifiedEmpty.wire_name(),
        "verified_empty"
    );
    assert_ne!(
        format!("{}", EnumerationState::VerifiedEmpty),
        format!("{}", EnumerationState::Uninitialised)
    );
}

const DIGEST_VE: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// Two examined candidates the frozen denominator never declared (mirrors the
/// `examined_two` helper in `evidence_portfolio.rs`, which cannot be shared
/// across integration test targets).
fn examined_two() -> Vec<ObservedOutsideScope> {
    vec![
        ObservedOutsideScope {
            handle: "witness-a".to_owned(),
            disposition: SourceDisposition::Observed,
            content_digest: DIGEST_VE.to_owned(),
            operation_id: "op-1".to_owned(),
            admitted_manifest_digest: DIGEST_VE.to_owned(),
        },
        ObservedOutsideScope {
            handle: "witness-b".to_owned(),
            disposition: SourceDisposition::Observed,
            content_digest: DIGEST_VE.to_owned(),
            operation_id: "op-2".to_owned(),
            admitted_manifest_digest: DIGEST_VE.to_owned(),
        },
    ]
}

fn test_fence() -> StateFence {
    let lineage = match EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") {
        Ok(lineage) => lineage,
        Err(error) => panic!("test lineage must parse: {error:?}"),
    };
    let Some(sequence) = NonZeroU64::new(7) else {
        panic!("test sequence must be non-zero");
    };
    let epoch = match EpochId::new(lineage, sequence) {
        Ok(epoch) => epoch,
        Err(error) => panic!("test epoch must build: {error:?}"),
    };
    StateFence::new(epoch, ResourceGeneration::genesis())
}

/// Minimal profile for receipt-shape tests: `CoverageReceipt::compute` reads
/// only the inquiry identity, the two denominator digests and the hypothesis
/// policy, so every other field carries a plausible inert value. Falsification
/// policy keeps the counter-search status `NotRequired`.
fn receipt_profile() -> InquiryProtocolProfile {
    let grade = match EvidenceGrade::from_name("CORROBORATED") {
        Ok(grade) => grade,
        Err(error) => panic!("canonical grade must resolve: {error:?}"),
    };
    InquiryProtocolProfile {
        profile_id: "profile-ve-1".to_owned(),
        revision: 1,
        supersedes: None,
        inquiry_id: "inq-ve-1".to_owned(),
        operation_id: "op-ve-1".to_owned(),
        exchange_id: "ex-ve-1".to_owned(),
        question: "which valve alloy survives the thermal envelope".to_owned(),
        intended_decision_or_artifact: "decide valve alloy".to_owned(),
        scope: "thermal envelope alloy review".to_owned(),
        requester_principal: "principal-ve".to_owned(),
        admitted_inquiry_digest: DIGEST_VE.to_owned(),
        protocol: InquiryProtocol::EvidenceReview,
        selection_features_digest: DIGEST_VE.to_owned(),
        evidence_grade: grade,
        lane: InquiryLane::Exploratory,
        coverage_goal: CoverageGoal::Exhaustive,
        admitted_coverage_goal: "exhaustive".to_owned(),
        admitted_coverage_goal_resolved: true,
        hypothesis_policy: HypothesisPolicy::FalsificationRequired,
        truth_surfaces_and_admissible_providers: vec!["surface-ve".to_owned()],
        admissible_source_classes: vec![SourceClass::Paper],
        reference_manifest_digest: DIGEST_VE.to_owned(),
        admitted_denominator_digest: DIGEST_VE.to_owned(),
        independence_and_blinding_policy: match IndependenceBlindingPolicy::resolve(
            grade,
            InquiryLane::Exploratory,
            vec![],
            0,
            vec![],
            vec![],
            vec![],
            None,
        ) {
            Ok(policy) => policy,
            Err(error) => panic!("exploratory policy must resolve: {error:?}"),
        },
        independence_and_blinding_policy_digest: DIGEST_VE.to_owned(),
        registration_binding_digest: DIGEST_VE.to_owned(),
        fidelity_ceiling: "ceiling-ve".to_owned(),
        stop_rule: match InquiryStopRule::resolve(
            8,
            1_800_000_000_000,
            StopRuleKind::BudgetOrDeadlineExhausted,
            "cancel-ve",
        ) {
            Ok(rule) => rule,
            Err(error) => panic!("test stop rule must resolve: {error:?}"),
        },
        output_contract: match InquiryOutputContract::resolve(
            "result-schema-ve",
            vec![ReopenCondition::NewEvidenceAvailable],
        ) {
            Ok(contract) => contract,
            Err(error) => panic!("test output contract must resolve: {error:?}"),
        },
        disclosure_ceiling: DisclosureClass::ProjectBound,
        state_fence: test_fence(),
        change_reason: "initial".to_owned(),
        integrity_digest: DIGEST_VE.to_owned(),
    }
}

/// A verified-empty account receipts: the zero-member gate opens on run
/// evidence, the enumeration reads `VerifiedEmpty` (never vacuous `Complete`),
/// and the denominator stays `Unknown` — with no owner-issued record the
/// verdict cannot be `Proven`, so `complete_scope` is honestly unreachable
/// here; it waits the live evaluator composition (#1762).
#[test]
fn verified_empty_account_receipts_without_proof() {
    let account = match CoverageAccount::open_verified_empty(&examined_two()) {
        Ok(account) => account,
        Err(error) => panic!("examined scope must open verified empty: {error:?}"),
    };
    let profile = receipt_profile();
    let records: &[SourceAdmissibilityRecord] = &[];
    let receipt = match CoverageReceipt::compute(CoverageReceiptParams {
        profile: &profile,
        requested_scope: "which valve alloy survives the thermal envelope",
        frozen_scope_digest: DIGEST_VE,
        account: &account,
        records,
        absence_evidence: None,
        routes_used: vec![],
        provider_degradation: vec![],
        unknown_coverage: vec![],
        budget_limitation: None,
        assessment_time_ms: 1_800_000_000_000,
    }) {
        Ok(receipt) => receipt,
        Err(error) => panic!("verified empty scope must receipt: {error:?}"),
    };
    assert_eq!(receipt.enumeration_state, EnumerationState::VerifiedEmpty);
    assert_eq!(receipt.expected_members, 0);
    assert!(receipt.eligible_handles.is_empty());
    assert!(receipt.open_members.is_empty());
    assert_eq!(receipt.denominator_kind, DenominatorKind::Unknown);
    assert_ne!(
        receipt.absence_verdict,
        AbsenceVerdict::Proven,
        "no owner-issued record was presented, so nothing may prove the absence"
    );
}

// Issue #1767 W4: the citation relation closes inside the portfolio
// projection. A cycle or an edge to an unrecorded handle in the admitted set
// refuses assembly fail-closed; an acyclic graph assembles. Unknown lineage
// stays unknown through the independence axes, never counted as support.
fn w4_record(handle: &str, cites: Vec<String>) -> SourceRecord {
    SourceRecord::new(SourceRecordParams {
        handle: handle.to_owned(),
        class: SourceClass::Paper,
        title: format!("title {handle}"),
        locator: format!("snapshot::{handle}"),
        content_digest: DIGEST_VE.to_owned(),
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
        verifier: "verifier-w4".to_owned(),
        quarantine: None,
        counterevidence_of: BTreeSet::new(),
        cites,
        evidence_spans: vec![EvidenceSpan {
            span_id: format!("span-{handle}"),
            anchor: "section-2".to_owned(),
            excerpt_digest: DIGEST_VE.to_owned(),
        }],
        data_role: "primary".to_owned(),
    })
    .expect("w4 source record")
}

fn w4_admissible(
    profile: &InquiryProtocolProfile,
    record: SourceRecord,
) -> SourceAdmissibilityRecord {
    SourceAdmissibilityRecord {
        inquiry_id: profile.inquiry_id.clone(),
        evidence_set_id: "es-w4".to_owned(),
        profile_id: profile.profile_id.clone(),
        profile_revision: profile.revision,
        profile_digest: profile.integrity_digest.clone(),
        record,
        scope: "thermal envelope alloy review".to_owned(),
        eligibility: SourceEligibility::Eligible,
        taint: BTreeSet::new(),
        independence: SourceIndependence {
            lineage_root: None,
            shared_context_ancestor: None,
            shared_assumptions: Vec::new(),
            derived_from: None,
        },
        limits: SourceLimits {
            max_anchor_precision: AnchorPrecision::Section,
            allowed_uses: vec!["evidence-only".to_owned()],
            freshness_boundary_ms: Some(1_800_000_000_000),
            disclosure: DisclosureClass::ProjectBound,
            verifier: "verifier-w4".to_owned(),
        },
        reasons: Vec::new(),
        assessment_time_ms: 1_700_000_300_000,
        state_fence: test_fence(),
        candidate_only: true,
        governor_admission_required: true,
        digest: DIGEST_VE.to_owned(),
    }
}

#[test]
fn citation_cycle_refuses_portfolio_assembly() {
    let profile = receipt_profile();
    let records = vec![
        w4_admissible(&profile, w4_record("cyc-a", vec!["cyc-b".to_owned()])),
        w4_admissible(&profile, w4_record("cyc-b", vec!["cyc-a".to_owned()])),
    ];
    assert!(matches!(
        SourcePortfolio::assemble(&profile.inquiry_id, &profile, &records),
        Err(InquiryError::Portfolio(
            PortfolioError::CircularCitation { .. }
        ))
    ));
}

#[test]
fn citation_closure_holds_acyclic_assembly() {
    let profile = receipt_profile();
    let chained = vec![
        w4_admissible(&profile, w4_record("head", vec!["tail".to_owned()])),
        w4_admissible(&profile, w4_record("tail", Vec::new())),
    ];
    let portfolio =
        SourcePortfolio::assemble(&profile.inquiry_id, &profile, &chained).expect("acyclic graph");
    assert_eq!(portfolio.primary_sources.len(), 2);
    let dangling = vec![w4_admissible(
        &profile,
        w4_record("tip", vec!["ghost".to_owned()]),
    )];
    assert!(matches!(
        SourcePortfolio::assemble(&profile.inquiry_id, &profile, &dangling),
        Err(InquiryError::Portfolio(
            PortfolioError::UnresolvedRoot { .. }
        ))
    ));
}

// Issue #1767 W6: the carried receipt binds `account_digest`, and the digest
// is re-proved here from the retained manifest + admissibility — the same
// construction the live path runs. Same material re-proves the same digest
// (both denominator arms), and a substituted disposition moves it, so an
// account swapped after compute is observable instead of trusted.
fn w6_manifest(handles: Vec<String>) -> AllowedReferenceManifest {
    AllowedReferenceManifest {
        run_id: "run-w6".to_owned(),
        root_context_revision: "rev-w6".to_owned(),
        state_fence: test_fence(),
        source_handles: handles,
        evidence_handles: Vec::new(),
        artifact_handles: Vec::new(),
        url_handles: Vec::new(),
        tool_refs: Vec::new(),
        verifier_refs: Vec::new(),
        allowed_anchor_precision: AnchorPrecision::Section,
        scope_class: "scope-w6".to_owned(),
        disclosure: DisclosureClass::ProjectBound,
        retention_class: "retention-w6".to_owned(),
        stale_or_revoked_handles: Vec::new(),
        expansion_routes: Vec::new(),
        digest: DIGEST_VE.to_owned(),
    }
}

#[test]
fn coverage_account_digest_rederives_deterministically() {
    let profile = receipt_profile();
    let admissibility = vec![
        w4_admissible(&profile, w4_record("rd-a", Vec::new())),
        w4_admissible(&profile, w4_record("rd-b", Vec::new())),
    ];
    let manifest = w6_manifest(vec!["rd-a".to_owned(), "rd-b".to_owned()]);
    let first = rederive_coverage_account_digest(&manifest, &admissibility).expect("rederive");
    let second =
        rederive_coverage_account_digest(&manifest, &admissibility).expect("rederive again");
    assert_eq!(
        first, second,
        "same retained material re-proves the same digest"
    );
    let bare = w6_manifest(Vec::new());
    rederive_coverage_account_digest(&bare, &admissibility)
        .expect("empty manifest rebuilds over the examined run evidence");
}

#[test]
fn coverage_account_digest_observes_substitution() {
    let profile = receipt_profile();
    let base = vec![
        w4_admissible(&profile, w4_record("sub-a", Vec::new())),
        w4_admissible(&profile, w4_record("sub-b", Vec::new())),
    ];
    let manifest = w6_manifest(vec!["sub-a".to_owned(), "sub-b".to_owned()]);
    let intact = rederive_coverage_account_digest(&manifest, &base).expect("intact");
    let mut changed = base.clone();
    changed[0].record.acquisition = SourceDisposition::Partial;
    let altered = rederive_coverage_account_digest(&manifest, &changed).expect("altered");
    assert_ne!(
        intact, altered,
        "a substituted disposition must move the digest"
    );
}

// Issue #1767 W2: the norm-required source populations ride the receipt.
// represented = eligible with a visible disposition, omitted = eligible with
// none, cited = eligible handles another eligible record cites. Route
// staleness/skips and page cursors have no admitted input on this path, so no
// test synthesizes them.
fn w2_receipt() -> CoverageReceipt {
    use std::collections::BTreeSet;

    let profile = receipt_profile();
    let admissibility = vec![
        w4_admissible(&profile, w4_record("rep-a", vec!["rep-b".to_owned()])),
        w4_admissible(&profile, w4_record("rep-b", Vec::new())),
        w4_admissible(&profile, w4_record("om-c", Vec::new())),
    ];
    let mut account = CoverageAccount::open(
        ["rep-a", "rep-b", "om-c"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<String>>(),
    )
    .expect("w2 account");
    for record in &admissibility[..2] {
        account
            .observe(
                &record.record.handle,
                record.record.acquisition,
                &record.record.content_digest,
                &record.record.operation_id,
                DIGEST_VE,
            )
            .expect("w2 observe");
    }
    CoverageReceipt::compute(CoverageReceiptParams {
        profile: &profile,
        requested_scope: "which valve alloy survives the thermal envelope",
        frozen_scope_digest: DIGEST_VE,
        account: &account,
        records: &admissibility,
        absence_evidence: None,
        routes_used: Vec::new(),
        provider_degradation: Vec::new(),
        unknown_coverage: Vec::new(),
        budget_limitation: None,
        assessment_time_ms: 1_800_000_000_000,
    })
    .expect("w2 receipt")
}

#[test]
fn receipt_separates_represented_cited_and_omitted() {
    let receipt = w2_receipt();
    assert_eq!(
        receipt.eligible_handles,
        vec!["om-c".to_owned(), "rep-a".to_owned(), "rep-b".to_owned()],
        "all three admitted records are eligible"
    );
    assert_eq!(
        receipt.represented_handles,
        vec!["rep-a".to_owned(), "rep-b".to_owned()],
        "only observed eligible handles are represented"
    );
    assert_eq!(
        receipt.cited_handles,
        vec!["rep-b".to_owned()],
        "only the cited eligible handle is cited"
    );
    assert_eq!(
        receipt.omitted_handles,
        vec!["om-c".to_owned()],
        "the never-observed eligible handle is omitted"
    );
}
