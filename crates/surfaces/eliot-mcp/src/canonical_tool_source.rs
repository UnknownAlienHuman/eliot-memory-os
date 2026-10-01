//! Production H-A adapter: the canonical registry as a Skill-consumable
//! version-bound tool source. Delegates to the frozen v1 registry; mints no
//! second registry, infers no behavior from names.
use eliot_skill::CanonicalToolSource;

use crate::{CANONICAL_DEFINITION_VERSION, SemanticRegistry};

impl CanonicalToolSource for SemanticRegistry {
    fn definition_version(&self) -> &str {
        CANONICAL_DEFINITION_VERSION
    }

    fn knows_canonical_tool(&self, canonical_name: &str) -> bool {
        self.resolve(canonical_name, CANONICAL_DEFINITION_VERSION)
            .is_ok()
    }

    /// Live semantic-profile version for one canonical method (issue #1944
    /// A3).
    ///
    /// Resolves the profile from this registry on every call — the same live
    /// owner and the same `(canonical_name, CANONICAL_DEFINITION_VERSION)`
    /// key the dispatch path re-resolves per request in
    /// `validate_tool_request_owner` — and reports its `profile_version`, so
    /// the admitted-vs-live comparison in the refresh reconcile fires on a
    /// pure profile-version edit while the definition version stands still.
    /// Never a cached copy, never a literal: a profile-version move is
    /// visible on the next call. An unresolvable name reports no profile
    /// data (`None`); absence itself stays the membership port's decision.
    fn semantic_profile_version(&self, canonical_name: &str) -> Option<String> {
        self.resolve(canonical_name, CANONICAL_DEFINITION_VERSION)
            .ok()
            .map(|profile| profile.profile_version.clone())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{CANONICAL_TOOL_NAMES, canonical_registry};
    use eliot_skill::{KnownTools, ToolAliasTable, VersionBoundTools};

    #[test]
    fn registry_answers_the_version_bound_port_predicate() {
        let registry = canonical_registry().expect("canonical registry builds");
        assert_eq!(registry.definition_version(), CANONICAL_DEFINITION_VERSION);
        for name in CANONICAL_TOOL_NAMES {
            assert!(
                registry.knows_canonical_tool(name),
                "profiled method must be known: {name}"
            );
        }
        assert!(
            !registry.knows_canonical_tool("vendor.effect"),
            "unprofiled method must be absent, never synthesized"
        );
        assert!(
            !registry.knows_canonical_tool(""),
            "blank names are absent, never admitted"
        );
    }

    #[test]
    fn projection_carries_registry_membership_onto_the_skill_port() {
        let registry = canonical_registry().expect("canonical registry builds");
        let aliases = ToolAliasTable::new();
        let view = VersionBoundTools::new(&registry, &aliases);
        assert_eq!(view.definition_version(), CANONICAL_DEFINITION_VERSION);
        for name in CANONICAL_TOOL_NAMES {
            assert!(view.knows_tool(name), "projected view must know: {name}");
        }
        assert!(!view.knows_tool("eliot.memory_use"));
    }
}
