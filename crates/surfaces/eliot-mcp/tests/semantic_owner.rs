#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use eliot_mcp::{
    CANONICAL_DEFINITION_VERSION, OperationalProjection, ToolMethodIdentity, canonical_registry,
    invalidation_on_profile_change, profile_version_changed, routing_decision,
    validate_operational_projection,
};

fn identity(name: &str) -> ToolMethodIdentity {
    ToolMethodIdentity {
        canonical_name: name.to_owned(),
        definition_version: CANONICAL_DEFINITION_VERSION.to_owned(),
    }
}

/// Acceptance 1: a provider rename retains retry/read-only/completion behavior
/// because routing consults the semantic profile rather than the name.
#[test]
fn rename_keeps_routing_behavior_from_profile() {
    let registry = canonical_registry().expect("canonical registry builds");
    let mut aliases = BTreeMap::new();
    aliases.insert("eliot.query".to_owned(), "eliot.query".to_owned());
    aliases.insert("vendor.renamed.query".to_owned(), "eliot.query".to_owned());

    let before = registry
        .resolve_via_provider_alias(&aliases, "eliot.query", CANONICAL_DEFINITION_VERSION)
        .expect("canonical alias resolves");
    let after = registry
        .resolve_via_provider_alias(
            &aliases,
            "vendor.renamed.query",
            CANONICAL_DEFINITION_VERSION,
        )
        .expect("renamed alias resolves to the same profile");

    assert_eq!(before.method, after.method);
    assert_eq!(routing_decision(before), routing_decision(after));
    assert!(routing_decision(after).read_only);
    assert!(routing_decision(after).retry_safe);
}

/// Acceptance 2: an effectful tool without a semantic profile is absent from
/// the Material surface and cannot be selected for mutation.
#[test]
fn missing_profile_is_absent_and_not_mutation_selectable() {
    let registry = canonical_registry().expect("canonical registry builds");
    let candidates = vec![identity("eliot.coordinate"), identity("vendor.effect")];
    let surface = registry.material_surface(&candidates);
    assert_eq!(surface.len(), 1);
    assert_eq!(surface[0].method.canonical_name, "eliot.coordinate");
    assert!(registry.mutation_selectable("eliot.coordinate", CANONICAL_DEFINITION_VERSION));
    assert!(!registry.mutation_selectable("vendor.effect", CANONICAL_DEFINITION_VERSION));
}

/// Acceptance 3: a semantic-version change invalidates dependents before reuse.
#[test]
fn profile_version_change_invalidates_dependents() {
    assert!(!profile_version_changed("1.0.0", "1.0.0"));
    assert!(profile_version_changed("1.0.0", "1.0.1"));
    assert!(invalidation_on_profile_change("1.0.0", "1.0.0").is_none());
    let invalidation =
        invalidation_on_profile_change("1.0.0", "1.0.1").expect("version change invalidates");
    assert!(invalidation.skills);
    assert!(invalidation.packets);
    assert!(invalidation.competence_evidence);
    assert!(invalidation.projections);
}

/// Single owner: one disagreeing MCP/WIT/EBP view fails against the profile.
#[test]
fn operational_projection_must_agree_with_single_owner() {
    let registry = canonical_registry().expect("canonical registry builds");
    let profile = registry
        .resolve("eliot.query", CANONICAL_DEFINITION_VERSION)
        .expect("query profile exists");
    let decision = routing_decision(profile);
    let agreeing = OperationalProjection {
        canonical_name: "eliot.query".to_owned(),
        claimed_retry_safe: decision.retry_safe,
        claimed_read_only: decision.read_only,
        claimed_completion_ceiling: decision.completion_ceiling,
    };
    validate_operational_projection(profile, &agreeing).expect("agreeing view passes");
    let disagreeing = OperationalProjection {
        claimed_retry_safe: !decision.retry_safe,
        ..agreeing
    };
    assert!(validate_operational_projection(profile, &disagreeing).is_err());
}
