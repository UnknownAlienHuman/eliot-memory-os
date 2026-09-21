#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use eliot_mcp::{
    CANONICAL_DEFINITION_VERSION, CANONICAL_TOOL_NAMES, OperationalProjection, StateInput,
    ToolMethodIdentity, ToolRequest, canonical_known_tools, canonical_registry,
    invalidation_on_profile_change, known_tool_profile, profile_version_changed,
    published_mcp_tool_surface, routing_decision, validate_operational_projection,
    validate_tool_request_owner,
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

/// Frozen v1 Skill lookup: one owner per canonical name at the pinned
/// definition version; unknown names have no owner and must not be invented.
#[test]
fn frozen_known_tool_lookup_serves_one_owner_per_method() {
    let registry = canonical_registry().expect("canonical registry builds");
    let tools = canonical_known_tools().expect("frozen enumeration builds");
    assert_eq!(tools.len(), CANONICAL_TOOL_NAMES.len());
    let mut names: Vec<&str> = tools
        .iter()
        .map(|profile| profile.method.canonical_name.as_str())
        .collect();
    names.sort_unstable();
    let mut expected: Vec<&str> = CANONICAL_TOOL_NAMES.to_vec();
    expected.sort_unstable();
    assert_eq!(names, expected);
    for profile in &tools {
        assert_eq!(
            profile.method.definition_version,
            CANONICAL_DEFINITION_VERSION
        );
        let resolved = registry
            .resolve(&profile.method.canonical_name, CANONICAL_DEFINITION_VERSION)
            .expect("enumerated tool resolves in the registry");
        assert_eq!(
            known_tool_profile(&profile.method.canonical_name).expect("frozen lookup resolves"),
            resolved.clone()
        );
    }
    assert!(known_tool_profile("vendor.effect").is_err());
}

/// Production join: a real contract request resolves to its owner, and the
/// published Material MCP surface is exactly the profiled catalogue.
#[test]
fn contract_request_and_transport_surface_join_to_the_owner() {
    let request = ToolRequest::State(StateInput {
        include: Vec::new(),
    });
    let profile = validate_tool_request_owner(&request).expect("state request has an owner");
    assert_eq!(profile.method.canonical_name, "eliot.state");
    assert!(routing_decision(&profile).read_only);

    let surface = published_mcp_tool_surface().expect("material surface builds");
    let names: Vec<&str> = surface
        .iter()
        .map(|descriptor| descriptor.name.as_str())
        .collect();
    assert_eq!(names, CANONICAL_TOOL_NAMES);
}

/// H-A adapter predicate: the production canonical registry value answers
/// exactly what the Skill-owned `CanonicalToolSource` port will delegate to
/// (`definition_version` binding + `resolve(...).is_ok()` membership at the
/// bound version). Proves the impl body against the real registry; the trait
/// `impl` itself applies verbatim once the Skill owner's trait merges.
#[test]
fn canonical_registry_value_answers_version_bound_skill_membership() {
    let registry = canonical_registry().expect("canonical registry builds");
    // The bound version the port reports is the frozen pinned version.
    assert_eq!(CANONICAL_DEFINITION_VERSION, "1.2.0");
    // Membership is exactly the registry's answer at the bound version.
    for name in CANONICAL_TOOL_NAMES {
        assert!(
            registry.resolve(name, CANONICAL_DEFINITION_VERSION).is_ok(),
            "profiled method must be known: {name}"
        );
    }
    assert!(
        registry
            .resolve("vendor.effect", CANONICAL_DEFINITION_VERSION)
            .is_err(),
        "unprofiled method must be absent, never synthesized"
    );
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
