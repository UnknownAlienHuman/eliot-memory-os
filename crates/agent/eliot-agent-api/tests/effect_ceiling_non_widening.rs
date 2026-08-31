use std::collections::BTreeSet;

use eliot_agent_api::{AttemptId, ContractError, EffectCeiling, EffectKind, ProposedEffect};

fn ceiling(scope_ref: &str, allowed: &[EffectKind], max_external_effects: u32) -> EffectCeiling {
    EffectCeiling {
        scope_ref: scope_ref.to_owned(),
        allowed: allowed.iter().copied().collect(),
        max_external_effects,
    }
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
        payload_digest: "sha256:payload".to_owned(),
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
