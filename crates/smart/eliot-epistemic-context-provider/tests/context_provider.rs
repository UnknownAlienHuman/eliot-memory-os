//! Package fixtures for the thin owner-contribution adapter.
//!
//! The adapter takes an admitted position or a whole owner contribution.
//! Every negative case derives from one valid adapted contribution by
//! tampering exactly one field. Pose acceptance with execution belongs to
//! package proof; these fixtures pin the adapter contract shape.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_context_contracts::ProviderId;
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
};
use eliot_epistemic_context_provider::{ContributionError, EpistemicContextContribution};
use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
    PositionId, PositionRevision, ProviderContribution,
};

fn hex64() -> String {
    "0123456789abcdef".repeat(4)
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
            BTreeSet::from([ArtifactId::new("pos-2").expect("fixture supersession")])
        }
    };
    CurrentEpistemicPosition::new(receipt(), currentness, supersession, claim())
        .expect("fixture position")
}

fn owner_contribution() -> ProviderContribution {
    ProviderContribution::contribute(&position(Currentness::Current))
        .expect("fixture owner contribution")
}

fn contribution() -> EpistemicContextContribution {
    EpistemicContextContribution::from_position(&position(Currentness::Current))
        .expect("fixture contribution")
}

#[test]
fn from_position_frames_the_owner_envelope() {
    let admitted = position(Currentness::Current);
    let made = EpistemicContextContribution::from_position(&admitted).expect("valid contribution");
    assert_eq!(made.contribution.position_digest, admitted.digest);
    assert_eq!(made.contribution.claim, admitted.claim);
    assert_eq!(made.contribution.scope, admitted.admission.scope);
    assert_eq!(made.contribution.fence, admitted.admission.fence);
    assert_eq!(
        made.provider.as_str(),
        eliot_epistemic_context_provider::PROVIDER_LABEL
    );
    made.validate().expect("contribution validates");
}

#[test]
fn from_contribution_attaches_the_provider() {
    let made = EpistemicContextContribution::from_contribution(owner_contribution())
        .expect("valid adaptation");
    assert_eq!(
        made.provider.as_str(),
        eliot_epistemic_context_provider::PROVIDER_LABEL
    );
    made.validate().expect("adapted contribution validates");
}

#[test]
fn superseded_position_contributes_nothing() {
    let admitted = position(Currentness::Superseded);
    let error =
        EpistemicContextContribution::from_position(&admitted).expect_err("superseded must fail");
    assert!(matches!(error, ContributionError::Upstream(_)));
}

#[test]
fn foreign_provider_identity_is_rejected() {
    let mut made = contribution();
    made.provider = ProviderId::new("other.provider").expect("foreign provider");
    let error = made.validate().expect_err("foreign provider must fail");
    assert!(matches!(error, ContributionError::InvalidField { .. }));
}

#[test]
fn tampered_owner_digest_is_rejected_upstream() {
    let mut made = contribution();
    made.contribution.position_digest = "not-a-digest".to_owned();
    let error = made.validate().expect_err("tampered digest must fail");
    assert!(matches!(error, ContributionError::Upstream(_)));
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "contribution": {
            "contract_version": {"major": 1, "minor": 2, "patch": 0},
            "view_kind": "CURRENT_EPISTEMIC_POSITION",
            "position_digest": hex64(),
            "claim": "claim-1",
            "currentness": "CURRENT",
            "scope": "scope-epi",
            "fence": {
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            },
            "source_revision": "rev-1",
            "coverage_digest": hex64(),
            "receipt_digest": hex64()
        },
        "provider": "smart.epistemic.context-provider",
        "support_score": 0.97
    });
    let error = serde_json::from_value::<EpistemicContextContribution>(json)
        .expect_err("unknown field must fail");
    assert!(error.to_string().contains("support_score"));
}

#[test]
fn contribution_roundtrips_over_the_wire() {
    let made = contribution();
    let wire = serde_json::to_string(&made).expect("serialize contribution");
    let back: EpistemicContextContribution =
        serde_json::from_str(&wire).expect("deserialize contribution");
    assert_eq!(made, back);
}
