#![allow(clippy::expect_used)]

#[path = "support/grounding.rs"]
mod support;

use eliot_contracts::{ReceiptId, RequestId};
use eliot_dreamer_contracts::{
    AtomicityMode, ScreenBinding, ScreenState, TargetDenominator, grounding,
};
use support::*;

#[test]
fn full_handoff_round_trips_without_loss() {
    let input = draft();
    let manifest = manifest();
    let policy = policy();
    let ledger = ledger();
    let mut output = grounding::GroundedDreamDraft {
        schema_version: 2,
        job_id: input.job_id.clone(),
        task_id: task(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        draft_digest: input.draft_digest.clone(),
        manifest_digest: manifest.digest.clone(),
        policy_digest: policy.digest.clone(),
        input,
        manifest,
        policy,
        ledger,
        screen: None,
        output_digest: String::new(),
    };
    output.output_digest = output.computed_digest().expect("output digest");
    output.validate().expect("handoff validates");
    let wire = serde_json::to_string(&output).expect("encode");
    let decoded: grounding::GroundedDreamDraft = serde_json::from_str(&wire).expect("decode");
    assert_eq!(decoded, output);
    assert_eq!(
        decoded.input.claims[0].kind,
        grounding::ClaimKind::NumericQuantified
    );
}

#[test]
fn v1_shape_cannot_cross_decode_and_payload_kind_is_closed() {
    let mut claim = claim("claim-1");
    claim.kind = grounding::ClaimKind::Causal;
    assert!(claim.validate().is_err());
    let legacy = r#"{"statement":"old","source_handles":["x"]}"#;
    assert!(serde_json::from_str::<grounding::ModelDraft>(legacy).is_err());
}

#[test]
fn ledger_requires_exact_claim_denominator_reconciliation() {
    let mut value = ledger();
    value.expected_claim_ids.insert("claim-2".into());
    assert!(value.validate().is_err());
    value.unprocessed_claim_ids.insert("claim-2".into());
    value.unprocessed_reason = Some("algorithm frontier retained".into());
    value.ledger_digest = value.computed_digest().expect("ledger digest");
    value.validate().expect("explicit residue reconciles");
}

#[test]
fn manifest_is_a_revision_bound_firewall() {
    let mut value = manifest();
    assert!(value.contains(&artifact("evidence-1")));
    value
        .references
        .get_mut(&artifact("evidence-1"))
        .expect("ref")
        .stale = true;
    assert!(!value.contains(&artifact("evidence-1")));
    let wrong = eliot_dreamer_contracts::grounding::AuthorizedReference {
        handle: artifact("other"),
        source_lineage: None,
        support: None,
        provenance: None,
        content_digest: DIGEST.into(),
        source_revision: "revision-1".into(),
        authority_digest: DIGEST.into(),
        authority: eliot_evidence::EvidenceAuthority::SourceIdentity,
        freshness: eliot_evidence::EvidenceFreshness::ExactCommit,
        source_assurance: None,
        grade_ceiling: eliot_epistemic_contracts::EvidenceGrade::Grounded,
        assertability_ceiling: eliot_epistemic_contracts::PositionAssertability::QualifiedInference,
        privacy: eliot_epistemic_contracts::PrivacyHandling::Unrestricted,
        disclosure: eliot_epistemic_contracts::DisclosureClass::Open,
        origin: "grounding-test".into(),
        invalidated: false,
        revocation_reason: None,
        assertions: Vec::new(),
        stale: false,
    };
    value.references.insert(artifact("evidence-1"), wrong);
    assert!(value.validate().is_err());
}

#[test]
fn all_precision_kinds_are_explicit_and_policy_bounded() {
    let value = policy();
    assert_eq!(value.permitted_kinds.len(), 8);
    value.validate().expect("policy");
    let mut over = value.clone();
    over.max_claims = 0;
    assert!(over.validate().is_err());
}

#[test]
fn curation_screen_and_target_denominator_remain_bound() {
    let screen = ScreenBinding {
        request_id: RequestId::new("request-1").expect("request"),
        receipt_id: ReceiptId::new("receipt-1").expect("receipt"),
        screened_targets: vec!["target-1".into()],
        source_snapshot: "snapshot-1".into(),
        source_revision: "revision-1".into(),
        profile: "default".into(),
        task_id: "task-grounding".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: DIGEST.into(),
        item_digest: DIGEST.into(),
    };
    let target_mode = AtomicityMode::AllOrNothing;
    let target_members = vec!["target-1".into()];
    let target_digest = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&(&target_mode, &target_members, 1u32))
            .expect("target preimage"),
    );
    let binding = grounding::ScreenTargetBinding {
        screen,
        target_denominator: TargetDenominator {
            mode: target_mode,
            members: target_members,
            expected_total: 1,
        },
        target_digest,
    };
    binding.validate().expect("screen binding");
}
