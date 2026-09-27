//! Nextest serial sets derived from the declared test resource profiles.
//!
//! I2.22: two tests that claim the same exclusive resource, or the same
//! serial group, must not run concurrently. A nextest *test group* is the
//! mechanism that guarantees it: a group declared with `max-threads = 1` is
//! a logical mutex around exactly the tests its overrides select, and a test
//! that belongs to no group is unaffected by any group's limit. A partition
//! cannot express that, so this module derives serial sets, not partitions.
//!
//! Membership is the connected component of the bipartite
//! `test <-> declared identity` graph. A test that claims two exclusive
//! resources therefore lands in one serial set with both, and a set is named
//! after the smallest identity that binds it, so a set name changes only when
//! the declarations do. Every walk is over a `BTreeMap`, so the same
//! declarations always render the same bytes.
//!
//! This module owns no file: [`super::resources::NextestLanePlan`] renders
//! and validates the file, and the caller decides where it is written.

use std::collections::{BTreeMap, BTreeSet};

use super::resources::{ResourceError, ResourceKind, SchedulingDecision, TestResourceProfile};

/// The serial sets derived from a set of declared test profiles.
pub(super) struct ExclusivityPlan {
    /// Serial-set name to the exact, sorted member test names.
    pub sets: BTreeMap<String, Vec<String>>,
    /// Every declared identity to the serial set that holds it.
    pub group_of_identity: BTreeMap<String, String>,
}

/// The identity binding every test claiming this exclusive resource.
fn resource_identity(kind: ResourceKind, resource: &str) -> String {
    format!("{}:{resource}", kind.as_str())
}

/// The identity binding every test declaring this serial group. Spelled
/// apart from a resource identity so a serial group and a resource of the
/// same name stay two declarations.
fn serial_identity(group: &str) -> String {
    format!("serial:{group}")
}

/// The declared exclusivity identities of one test: one per exclusive
/// resource claim, plus the declared serial group.
pub(super) fn declared_identities(profile: &TestResourceProfile) -> Vec<String> {
    let mut identities: Vec<String> = profile
        .exclusive_resources
        .iter()
        .map(|claim| resource_identity(claim.kind, &claim.name))
        .collect();
    if !profile.serial_group.is_empty() {
        identities.push(serial_identity(&profile.serial_group));
    }
    identities
}

/// The exclusivity identities one recorded scheduling decision carries, read
/// from the leases it was allocated and the serial group it declared. A
/// decision that declared neither yields no identity, which is exactly the
/// unconstrained case.
pub(super) fn recorded_identities(decision: &SchedulingDecision) -> Vec<String> {
    let mut identities: Vec<String> = decision
        .leases
        .iter()
        .map(|lease| resource_identity(lease.kind, &lease.resource))
        .collect();
    if let Some(group) = &decision.serial_group {
        identities.push(serial_identity(group));
    }
    identities
}

/// Derives the serial sets over every declared test, keyed by nextest test
/// name.
///
/// Fails closed on an invalid declaration and on a test name no nextest
/// filterset can match, so an unrenderable test can never reach the rendered
/// file. A test that declares neither an exclusive resource nor a serial
/// group declares no identity and therefore joins no serial set.
pub(super) fn exclusivity_plan(
    declared: &BTreeMap<String, TestResourceProfile>,
) -> Result<ExclusivityPlan, ResourceError> {
    let mut tests_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut identities_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (test, profile) in declared {
        profile.validate()?;
        filterset_equality(test)?;
        let identities = declared_identities(profile);
        for identity in &identities {
            tests_of
                .entry(identity.clone())
                .or_default()
                .insert(test.clone());
        }
        identities_of.insert(test.clone(), identities);
    }

    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut sets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut group_of_identity: BTreeMap<String, String> = BTreeMap::new();
    // Roots are visited in ascending identity order, so the root that opens a
    // component is the smallest identity in it and names the serial set.
    for root in tests_of.keys() {
        if visited.contains(root) {
            continue;
        }
        let mut stack = vec![root.clone()];
        let mut component: Vec<String> = Vec::new();
        let mut members: BTreeSet<String> = BTreeSet::new();
        while let Some(identity) = stack.pop() {
            if !visited.insert(identity.clone()) {
                continue;
            }
            component.push(identity.clone());
            for test in &tests_of[&identity] {
                if !members.insert(test.clone()) {
                    continue;
                }
                stack.extend(identities_of[test].iter().cloned());
            }
        }
        for identity in component {
            group_of_identity.insert(identity, root.clone());
        }
        sets.insert(root.clone(), members.into_iter().collect());
    }
    Ok(ExclusivityPlan {
        sets,
        group_of_identity,
    })
}

/// Renders the deterministic `.config/nextest.toml` for these serial sets.
///
/// Each set becomes one `max-threads = 1` test group plus one override whose
/// filter is the union of exact-match filtersets over its members, so only
/// the declared members join the group and no other test is serialized with
/// them. Rendering fails closed on a member name no filterset can match.
pub(super) fn render_nextest_toml(
    sets: &BTreeMap<String, Vec<String>>,
) -> Result<String, ResourceError> {
    let mut out = String::new();
    out.push_str(
        "# Generated from the declared test resource profiles by\n\
         # eliot_testd_core::NextestLanePlan::render_nextest_toml. Do not edit\n\
         # by hand: NextestLanePlan::validate_nextest_toml fails closed when\n\
         # this file drifts from the declarations.\n",
    );
    if sets.is_empty() {
        return Ok(out);
    }
    out.push_str("\n[test-groups]\n");
    for name in sets.keys() {
        out.push_str(&format!("{} = {{ max-threads = 1 }}\n", toml_string(name)));
    }
    for (name, tests) in sets {
        let mut filter = String::new();
        for test in tests {
            if !filter.is_empty() {
                filter.push('|');
            }
            filter.push_str(&format!("test(={})", filterset_equality(test)?));
        }
        out.push_str(&format!(
            "\n[[profile.default.overrides]]\nfilter = {}\ntest-group = {}\n",
            toml_string(&filter),
            toml_string(name),
        ));
    }
    Ok(out)
}

/// The nextest equality matcher for one exact test name.
///
/// A bare matcher is a *contains* match, which would pull an undeclared test
/// into a serial set it never asked for; the `=` equality matcher selects
/// only the named test. Only the escape sequences the filterset DSL defines
/// are emitted, and any other control character is refused.
fn filterset_equality(test: &str) -> Result<String, ResourceError> {
    let mut out = String::with_capacity(test.len());
    for ch in test.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ')' => out.push_str("\\)"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                return Err(ResourceError::InvalidClaim {
                    field: "nextest test name",
                    reason: "must contain no control character the filterset DSL cannot escape",
                });
            }
            ch => out.push(ch),
        }
    }
    Ok(out)
}

/// A TOML basic string holding `text`. Declared names are already
/// control-free by `TestResourceProfile::validate` and by the matcher escape
/// above, so only the two structural characters need escaping.
fn toml_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
