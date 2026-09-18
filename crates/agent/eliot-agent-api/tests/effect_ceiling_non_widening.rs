use std::collections::BTreeSet;

use eliot_agent_api::{
    AttemptId, AuthorizedEffect, CONTRACT_VERSION, ContractError, EffectCeiling, EffectKind,
    ProposedEffect,
};

fn ceiling(scope_ref: &str, allowed: &[EffectKind], max_external_effects: u32) -> EffectCeiling {
    EffectCeiling {
        scope_ref: scope_ref.to_owned(),
        allowed: allowed.iter().copied().collect(),
        max_external_effects,
    }
}

fn canonical_digest() -> Result<eliot_agent_api::LowercaseSha256, serde_json::Error> {
    serde_json::from_value(serde_json::json!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ))
}

#[test]
fn child_effect_must_remain_within_parent_ceiling() {
    let parent = ceiling(
        "scope:root",
        &[EffectKind::Observe, EffectKind::ReadWorkspace],
        0,
    );
    let child = ceiling(
        "scope:root",
        &[
            EffectKind::Observe,
            EffectKind::ReadWorkspace,
            EffectKind::Network,
        ],
        0,
    );

    assert!(!child.allowed.is_subset(&parent.allowed));
    assert!(child.max_external_effects <= parent.max_external_effects);
}

#[test]
fn parent_scope_negative_reaches_the_parent_comparison() {
    let parent = ceiling("scope:root", &[EffectKind::Observe], 0);
    let child = ceiling("scope:root", &[EffectKind::Observe], 1);

    assert!(child.allowed.is_subset(&parent.allowed));
    assert!(child.max_external_effects > parent.max_external_effects);
}

#[test]
fn proposed_effect_cannot_cross_scope_or_effect_ceiling() -> Result<(), Box<dyn std::error::Error>>
{
    let parent = ceiling("scope:root", &[EffectKind::Observe], 0);
    let proposal = ProposedEffect {
        effect_id: "effect-1".to_owned(),
        attempt_id: AttemptId::new("attempt-1")?,
        kind: EffectKind::Network,
        scope_ref: parent.scope_ref.clone(),
        payload_digest: canonical_digest()?,
        rationale_ref: None,
    };

    assert_eq!(
        proposal.validate_against(&parent),
        Err(ContractError::InsufficientAuthority)
    );
    let wrong_scope = EffectCeiling {
        allowed: BTreeSet::from([EffectKind::Observe]),
        scope_ref: "scope:child".to_owned(),
        max_external_effects: 0,
    };
    assert_eq!(
        ProposedEffect {
            scope_ref: wrong_scope.scope_ref.clone(),
            kind: EffectKind::Observe,
            ..proposal
        }
        .validate_against(&parent),
        Err(ContractError::InsufficientAuthority)
    );
    Ok(())
}

#[test]
fn effect_payload_digest_rejects_noncanonical_placeholders() {
    // #228 v7: canonical 64-hex lowercase only; placeholders never upgrade.
    for legacy in [
        "sha256:payload",
        "payload-1",
        "",
        "abc",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        let wire = serde_json::json!({
            "effect_id": "effect-1",
            "attempt_id": "attempt-1",
            "kind": "observe",
            "scope_ref": "scope:root",
            "payload_digest": legacy,
            "rationale_ref": null,
        });
        assert!(
            serde_json::from_value::<ProposedEffect>(wire).is_err(),
            "legacy digest must be rejected: {legacy}"
        );
    }
}

#[test]
fn authorized_effect_rejects_string_and_unzoned_times() {
    // #228 v7: `ClockReading` objects only; bare/unzoned strings fail.
    for legacy_time in [
        "2026-08-14T00:00:00Z",
        "2026-08-14T00:00:00",
        "2026-08-14",
        "later",
        "",
    ] {
        let wire = serde_json::json!({
            "proposal": {
                "effect_id": "effect-1",
                "attempt_id": "attempt-1",
                "kind": "observe",
                "scope_ref": "scope:root",
                "payload_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "rationale_ref": null,
            },
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1,
            },
            "authorization_ref": "auth-1",
            "authorized_at": legacy_time,
            "expires_at": legacy_time,
        });
        assert!(
            serde_json::from_value::<AuthorizedEffect>(wire).is_err(),
            "string time must be rejected: {legacy_time}"
        );
    }
    // Structured readings deserialize.
    let wire = serde_json::json!({
        "proposal": {
            "effect_id": "effect-1",
            "attempt_id": "attempt-1",
            "kind": "observe",
            "scope_ref": "scope:root",
            "payload_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "rationale_ref": null,
        },
        "authority_epoch": {
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 1,
        },
        "authorization_ref": "auth-1",
        "authorized_at": {"valid_time_ms": 1000, "known_time_ms": 1001, "transaction_sequence": null, "monotonic_ns": null},
        "expires_at": {"valid_time_ms": 2000, "known_time_ms": 2001, "transaction_sequence": null, "monotonic_ns": null},
    });
    assert!(serde_json::from_value::<AuthorizedEffect>(wire).is_ok());
}

#[test]
fn v6_legacy_effect_wire_is_rejected_and_version_bumped() {
    // Loss-visible: v7 bump + typed fields reject v6 string wires.
    assert_eq!(CONTRACT_VERSION, "eliot-agent-api/v7");
    let v6 = serde_json::json!({
        "effect_id": "effect-1",
        "attempt_id": "attempt-1",
        "kind": "observe",
        "scope_ref": "scope:root",
        "payload_digest": "sha256:payload",
        "rationale_ref": null,
    });
    assert!(serde_json::from_value::<ProposedEffect>(v6).is_err());
}

#[test]
fn effect_receipt_stays_distinct_from_canonical_receipt_owner() {
    // Taxonomy: api `EffectReceipt` is agent-local; canonical
    // `ReceiptEnvelope` is owned by `eliot-receipts` (single owner via
    // `ProofCeiling` re-export). No local `ReceiptEnvelope` duplicate.
    let envelope_wire = serde_json::json!({
        "effect_id": "effect-1",
        "authorization_ref": "auth-1",
        "outcome": "committed",
        "observed_at": "2026-08-14T00:00:00Z",
        "artifact_refs": [],
    });
    assert!(serde_json::from_value::<eliot_agent_api::EffectReceipt>(envelope_wire).is_ok());
    // `ProofCeiling` is the shared receipt-ceiling owner, not a local copy.
    let ceiling = eliot_agent_api::ProofCeiling::Observation;
    assert_eq!(ceiling, eliot_agent_api::ProofCeiling::Observation);
}
