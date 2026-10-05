//! Verified-empty enumeration-state wire spelling (issue #1767, W1/A2).
//!
//! A verified empty eligible scope is its own enumeration state, distinct
//! from an enumeration that never ran. The wire spelling is the contract
//! every later W1 slice binds against, so the four states must render
//! distinct wire names.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_research_exchange_api::{DisclosureClass, SourceClass};
use eliot_researcher::evidence_portfolio::{
    AbsenceVerdict, CoverageAccount, ObservedOutsideScope, SourceDisposition,
};
use eliot_researcher::inquiry_governance::{
    CoverageGoal, CoverageReceipt, CoverageReceiptParams, DenominatorKind, EnumerationState,
    EvidenceGrade, HypothesisPolicy, IndependenceBlindingPolicy, InquiryLane,
    InquiryOutputContract, InquiryProtocol, InquiryProtocolProfile, InquiryStopRule,
    ReopenCondition, StopRuleKind,
};
use eliot_researcher::source_admissibility::SourceAdmissibilityRecord;

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
