//! Package fixtures for the epistemic Context provider contribution.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId,
    StateFence,
};
use eliot_epistemic_context_provider::{ContributionError, EpistemicContextContribution};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, CONTRACT_VERSION, ClaimId, CurrentEpistemicPosition,
    Currentness, PositionId, PositionRevision,
};
use eliot_receipts::WorkScopeId;

fn hex64() -> String {
    "0123456789abcdef".repeat(4)
}

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-epictx").expect("fixture scope")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(1).expect("non-zero"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn claim() -> ClaimId {
    ClaimId::new("claim-1").expect("fixture claim")
}

fn receipt() -> AdmittedReceipt {
    AdmittedReceipt::new(AdmittedReceiptParams {
        receipt_id: ReceiptId::new("rc-1").expect("fixture receipt"),
        payload_digest: hex64(),
        owner: SourceId::new("source-epi").expect("fixture source"),
        revision: "rev-1".to_owned(),
        scope: "scope-epi".to_owned(),
        fence: fence(),
        evidence_digest: hex64(),
        coverage_digest: hex64(),
        conflict_digest: hex64(),
        proof_digest: hex64(),
        position: PositionId::new("pos-1").expect("fixture position"),
        position_revision: PositionRevision::new(1).expect("fixture revision"),
    })
    .expect("fixture receipt")
}

fn position(currentness: Currentness) -> CurrentEpistemicPosition {
    // A superseded position must name its supersession links.
    let supersession = match currentness {
        Currentness::Current => BTreeSet::new(),
        Currentness::Superseded => {
            BTreeSet::from([
                ArtifactId::new("pos-2").expect("fixture supersession"),
            ])
        }
    };
    CurrentEpistemicPosition::new(receipt(), currentness, supersession, claim())
        .expect("fixture position")
}

#[test]
fn from_position_echoes_digest_and_claim() {
    let admitted = position(Currentness::Current);
    let contribution =
        EpistemicContextContribution::from_position(&admitted, scope(), fence())
            .expect("valid contribution");
    assert_eq!(contribution.position_digest, admitted.digest);
    assert_eq!(contribution.claim, admitted.claim);
    assert_eq!(
        contribution.provider.as_str(),
        eliot_epistemic_context_provider::PROVIDER_LABEL
    );
    assert_eq!(contribution.contract_version, CONTRACT_VERSION);
    contribution.validate().expect("contribution validates");
}

#[test]
fn superseded_position_contributes_nothing() {
    let admitted = position(Currentness::Superseded);
    let error = EpistemicContextContribution::from_position(&admitted, scope(), fence())
        .expect_err("superseded must fail");
    assert!(matches!(error, ContributionError::SupersededPosition));
}

#[test]
fn superseded_parts_contribute_nothing() {
    let error = EpistemicContextContribution::from_parts(
        hex64(),
        claim(),
        Currentness::Superseded,
        scope(),
        fence(),
    )
    .expect_err("superseded parts must fail");
    assert!(matches!(error, ContributionError::SupersededPosition));
}

#[test]
fn malformed_digest_is_rejected() {
    let error = EpistemicContextContribution::from_parts(
        "not-a-digest".to_owned(),
        claim(),
        Currentness::Current,
        scope(),
        fence(),
    )
    .expect_err("malformed digest must fail");
    assert!(matches!(error, ContributionError::InvalidField { .. }));
}

#[test]
fn uppercase_digest_is_rejected() {
    let error = EpistemicContextContribution::from_parts(
        "0123456789ABCDEF".repeat(4),
        claim(),
        Currentness::Current,
        scope(),
        fence(),
    )
    .expect_err("uppercase digest must fail");
    assert!(matches!(error, ContributionError::InvalidField { .. }));
}

#[test]
fn version_drift_is_rejected() {
    let mut contribution =
        EpistemicContextContribution::from_position(&position(Currentness::Current), scope(), fence())
            .expect("valid contribution");
    contribution.contract_version = ContractVersion::new(9, 9, 9);
    let error = contribution.validate().expect_err("drift must fail");
    assert!(matches!(error, ContributionError::VersionMismatch));
}

#[test]
fn oversized_scope_is_rejected() {
    let wide = "s".repeat(300);
    let error = EpistemicContextContribution::from_parts(
        hex64(),
        claim(),
        Currentness::Current,
        WorkScopeId::new(wide).expect("wide scope text"),
        fence(),
    )
    .expect_err("oversized scope must fail");
    assert!(matches!(error, ContributionError::InvalidField { .. }));
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "contract_version": {"major": 1, "minor": 2, "patch": 0},
        "provider": "smart.epistemic.context-provider",
        "position_digest": hex64(),
        "claim": "claim-1",
        "scope_id": "scope-epictx",
        "state_fence": {
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "support_score": 0.97
    });
    let error = serde_json::from_value::<EpistemicContextContribution>(json)
        .expect_err("unknown field must fail");
    assert!(error.to_string().contains("support_score"));
}

#[test]
fn contribution_roundtrips_over_the_wire() {
    let contribution =
        EpistemicContextContribution::from_position(&position(Currentness::Current), scope(), fence())
            .expect("valid contribution");
    let wire = serde_json::to_string(&contribution).expect("serialize contribution");
    let back: EpistemicContextContribution =
        serde_json::from_str(&wire).expect("deserialize contribution");
    assert_eq!(contribution, back);
}
