//! Skill-owned production consumer for the tool owner's canonical versioned
//! tool view.
//!
//! The tool owner's registry resolves `(canonical_name, definition_version)`
//! pairs and binds its own definition version (frozen `1944-skill-handoff.md`
//! v1: `known_tool_profile` / `canonical_known_tools` at `"1.2.0"`). The
//! catalogue boundary speaks the accepted name-only [`KnownTools`] port. This
//! module closes that gap without minting a second registry:
//!
//! - [`CanonicalToolSource`] is the neutral, object-safe port the tool owner
//!   implements for its registry. It carries the registry-bound definition
//!   version alongside exact membership, so the version dimension the frozen
//!   lookup requires is never dropped at the Skill boundary.
//! - [`ToolAliasTable`] is the Skill-owned provider→canonical alias map the
//!   frozen consumer rules require ("the Skill's own alias table"). A vendor
//!   rename resolves to the canonical name FIRST and only feeds the versioned
//!   lookup: the table carries no behavior, so an alias can never change
//!   routing, retry, or completion semantics.
//! - [`VersionBoundTools`] is the neutral projection of one source plus its
//!   alias table onto [`KnownTools`]. Membership is exactly the source's
//!   answer; a missing profile is absent, never synthesized.
//! - [`install_package_versioned`] gates installation on the Governor-admitted
//!   definition version before delegating to [`install_package`], which binds
//!   the presented materialization to its exact accepted candidate. The Skill
//!   never hardcodes the version literal: the source reports the version it
//!   binds, the composition states the version it admits, and any drift fails
//!   closed. A compiled test double reporting a stale version therefore cannot
//!   drive installation — this is what separates real provider availability
//!   from a compiled factory.
//! - [`readiness_available_for_package`] mirrors the sealed
//!   `validate_observations` rule
//!   (`crates/surfaces/eliot-skills/src/contract.rs`, `SkillPackage` private
//!   `validate_observations`) over the public [`ReadinessClaims`] shape: every
//!   required tool and capability needs an exact `(name, version)` observation
//!   marked [`Available`](eliot_skills::Availability::Available). The sealed
//!   materialization entry keeps enforcing the same rule at
//!   [`materialize`](eliot_skills::SkillPackage::materialize); this mirror
//!   applies it at the temporal delivery act (installed is not delivered), so
//!   the runtime driver refuses to issue a Hotset receipt for provider-
//!   unavailable material. Provider availability itself stays with the
//!   admission owner (Governor/host); this predicate only reads its claims.
//!
//! [`install_package`]: super::install_package

// The crate error carries the full store failure for typed recovery; every
// catalogue function returns it by value like the existing lifecycle API.
// Boxing it here would diverge from that contract, so the size lint is
// allowed for this module (same precedent as the Skill catalogue module).
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

use eliot_skills::{
    MaterializationPorts, MaterializationScope, MissingVerificationProvider,
    PortableSkillPackageCandidate, ReadinessClaims, SkillPackage,
};

use super::{SkillError, install_package};
use crate::{CatalogueInstallContext, KnownTools, MaterializationInputs, SkillCatalogue};

/// Skill-owned provider→canonical alias map.
///
/// Empty by default: names resolve to themselves until the Skill owner admits
/// an explicit rename. Resolution output feeds only the versioned tool lookup;
/// the table expresses no retry, read-only, or completion behavior, so an
/// alias entry can never alter routing decisions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ToolAliasTable {
    aliases: BTreeMap<String, String>,
}

impl ToolAliasTable {
    /// Creates an empty alias table (identity resolution).
    #[must_use]
    pub fn new() -> Self {
        Self {
            aliases: BTreeMap::new(),
        }
    }

    /// Admits one provider rename `provider_name → canonical_name`.
    ///
    /// Both sides must be non-blank; a name already mapped cannot be
    /// re-mapped, and a self-mapping is rejected as meaningless.
    pub fn insert(
        &mut self,
        provider_name: String,
        canonical_name: String,
    ) -> Result<(), SkillError> {
        crate::text(&provider_name, "tool_alias.provider_name")?;
        crate::text(&canonical_name, "tool_alias.canonical_name")?;
        if provider_name == canonical_name {
            return Err(SkillError::InvalidField {
                field: "tool_alias.provider_name",
                reason: "an alias must rename to a different canonical name",
            });
        }
        if self.aliases.contains_key(&provider_name) {
            return Err(SkillError::Duplicate {
                field: "tool_alias.provider_name",
            });
        }
        self.aliases.insert(provider_name, canonical_name);
        Ok(())
    }

    /// Resolves one provider name to its canonical method name, or returns
    /// the name itself when no rename is admitted.
    #[must_use]
    pub fn resolve<'a>(&'a self, provider_name: &'a str) -> &'a str {
        self.aliases
            .get(provider_name)
            .map_or(provider_name, String::as_str)
    }
}

/// Neutral port over the tool owner's canonical versioned registry.
///
/// Implemented by the tool owner for its registry (frozen v1:
/// `known_tool_profile(name).is_ok()` at the bound definition version).
/// Object-safe so the production source travels as `&dyn
/// CanonicalToolSource` into the installation boundary next to `&dyn
/// KnownTools`.
pub trait CanonicalToolSource {
    /// Definition version this source binds (the registry's own pinned
    /// version, never a caller-supplied value).
    fn definition_version(&self) -> &str;

    /// Exact membership at the bound version: `true` only when the registry
    /// resolves `(canonical_name, definition_version)`. No fallback, no
    /// substring match, no prose synthesis.
    fn knows_canonical_tool(&self, canonical_name: &str) -> bool;
}

/// Neutral projection of one canonical source plus its alias table onto the
/// accepted [`KnownTools`] port.
///
/// Holds only borrows: no registry copy, no name list, no version literal.
// The derived Debug would print the source trait object, which is not
// Debug; a manual impl is unnecessary — the projection is a thin boundary
// value, so Debug is simply not provided.
pub struct VersionBoundTools<'a> {
    source: &'a dyn CanonicalToolSource,
    aliases: &'a ToolAliasTable,
}

impl<'a> VersionBoundTools<'a> {
    /// Projects `source` through `aliases` onto [`KnownTools`].
    #[must_use]
    pub fn new(source: &'a dyn CanonicalToolSource, aliases: &'a ToolAliasTable) -> Self {
        Self { source, aliases }
    }

    /// Definition version the projected source binds, for admission gating.
    #[must_use]
    pub fn definition_version(&self) -> &str {
        self.source.definition_version()
    }
}

impl KnownTools for VersionBoundTools<'_> {
    fn knows_tool(&self, name: &str) -> bool {
        self.source.knows_canonical_tool(self.aliases.resolve(name))
    }
}

/// Cross-checks provider availability names against the live tool source.
///
/// The sealed observation mirror
/// ([`readiness_available_for_package`]) proves the provider marked every
/// required tool and capability available at its exact version, but the
/// claims themselves arrive from the injector lane. This predicate binds the
/// name dimension to current owner state: every available observation must
/// resolve through the caller-supplied tool-owner view (in production the
/// [`VersionBoundTools`] projection over the live canonical source), so a
/// claim for a tool the registry never admitted fails closed here instead
/// of flowing to receipt issuance. Availability truth itself — whether the
/// provider can actually execute — stays with the sealed G-16 ports and is
/// never inferred from membership; unknown or unavailable observations fail
/// in the mirror, never here.
pub fn readiness_names_known_to_source(
    readiness: &ReadinessClaims,
    tools: &dyn KnownTools,
) -> Result<(), SkillError> {
    use eliot_skills::Availability;

    fn known(
        tools: &dyn KnownTools,
        observations: &[eliot_skills::VersionedObservation],
    ) -> Result<(), SkillError> {
        for observation in observations {
            if !matches!(observation.availability, Availability::Available { .. }) {
                continue;
            }
            if !tools.knows_tool(&observation.name) {
                return Err(SkillError::InvalidField {
                    field: "readiness.observation.name",
                    reason: "an available observation names a tool the owner does not admit",
                });
            }
        }
        Ok(())
    }

    known(tools, &readiness.tools)?;
    known(tools, &readiness.capabilities)?;
    Ok(())
}

/// Mirrors the sealed observation rule at the delivery boundary.
///
/// Every tool and capability the package requires needs an exact `(name,
/// version)` observation in `readiness` marked available. Anything else —
/// missing, version-skewed, or provider-unavailable — fails closed, so the
/// runtime driver never issues a Hotset receipt for material the provider did
/// not admit. Host/profile equality and sealed verification stay with the
/// sealed [`materialize`](eliot_skills::SkillPackage::materialize) entry and
/// the admission owner; this predicate covers only the observation half.
pub fn readiness_available_for_package(
    package: &SkillPackage,
    readiness: &ReadinessClaims,
) -> Result<(), SkillError> {
    use eliot_skills::Availability;

    fn available(
        observations: &[eliot_skills::VersionedObservation],
        name: &str,
        version: &str,
    ) -> bool {
        observations.iter().any(|observation| {
            observation.name == name
                && observation.version == version
                && matches!(observation.availability, Availability::Available { .. })
        })
    }

    for requirement in &package.host.required_tools {
        if !available(&readiness.tools, &requirement.name, &requirement.version) {
            return Err(SkillError::InvalidField {
                field: "readiness.tools",
                reason: "a required tool is not provider-available at its exact version",
            });
        }
    }
    for requirement in &package.host.required_capabilities {
        if !available(
            &readiness.capabilities,
            &requirement.name,
            &requirement.version,
        ) {
            return Err(SkillError::InvalidField {
                field: "readiness.capabilities",
                reason: "a required capability is not provider-available at its exact version",
            });
        }
    }
    Ok(())
}

/// Runs the sealed materialization entry truthfully at the delivery boundary.
///
/// Calls the documented
/// [`materialize`](eliot_skills::SkillPackage::materialize) entry with the
/// real package, inputs, readiness, and scope, using the public
/// [`MissingVerificationProvider`](eliot_skills::MissingVerificationProvider)
/// for both sealed ports (no external crate can implement them: `mod sealed`
/// is private). The mapping keeps every sealed verdict honest:
///
/// - sealed-positive (`materialized_skill().is_some()`) → `Ok`. Unreachable
///   until the G-16 owner injects real ports, and honored when it happens: a
///   sealed positive remains the only path that can ever lift a Skill past
///   `Provisional`.
/// - sealed omission → `Err(InvalidField{field: "sealed.materialization"})`
///   with the owner's own reason code. The sealed owner's host/profile,
///   lifecycle-state, availability, observation, and receipt-binding verdicts
///   refuse delivery here with their own voice; nothing is reworded into a
///   local default.
/// - `Err(PlanGap)` from the ports (sealed verifier not injected) → `Ok`.
///   Verifier absence is integration state, not a package verdict: delivery
///   proceeds WITHOUT sealed verification on the validated-claim wire and the
///   entry stays `Provisional` (fresh installation never promotes past
///   provisional). Sealed-positive stays required for anything past
///   provisional.
/// - any other sealed error (binding/structural failure) → `Err(Surface)`
///   with the sealed message, like every other package-wire mismatch.
///
/// This never mints verification: with the missing-ports provider the only
/// `Ok` outcomes are a future sealed positive or the documented
/// verifier-absent provisional path.
pub fn sealed_materialization_check(
    package: &SkillPackage,
    inputs: &MaterializationInputs,
    readiness: &ReadinessClaims,
    scope: &MaterializationScope,
) -> Result<(), SkillError> {
    use eliot_skills::OmissionReason;

    let missing = MissingVerificationProvider;
    let ports = MaterializationPorts {
        readiness: &missing,
        g16: &missing,
    };
    match package.materialize(inputs, readiness, scope, &ports) {
        Ok(outcome) => match outcome.omission_reason() {
            None => Ok(()),
            Some(reason) => Err(SkillError::InvalidField {
                field: "sealed.materialization",
                reason: match reason {
                    OmissionReason::Conflict { .. } => "sealed owner omitted a conflicted package",
                    OmissionReason::Stale { .. } => "sealed owner omitted a stale package",
                    OmissionReason::Distractor { .. } => {
                        "sealed owner omitted a distractor package"
                    }
                    OmissionReason::Quarantined { .. } => {
                        "sealed owner omitted a quarantined package"
                    }
                    OmissionReason::PlanGap { .. } => "sealed owner reports a plan gap",
                    OmissionReason::UnsupportedHostProfile { .. } => {
                        "sealed owner reports an unsupported host/profile"
                    }
                },
            }),
        },
        Err(eliot_skills::SkillContractError::PlanGap { .. }) => Ok(()),
        Err(error) => Err(SkillError::Surface(error.to_string())),
    }
}
///
/// Installs one canonical package source under the versioned canonical view.
///
/// Fails closed unless the source binds exactly the definition version the
/// Governor composition admits (`admitted_definition_version` must be
/// non-blank: an empty admission never authorizes installation). A version
/// change on the tool-owner side therefore blocks installation until the
/// composition re-admits — the invalidation half of the frozen consumer rule
/// ("any profile-version edit invalidates dependents before Material reuse")
/// applied at the install boundary. On agreement, binds the presented
/// materialization to its exact accepted candidate and then projects and
/// inserts through [`install_package`] with the [`VersionBoundTools`]
/// projection, so install, delivery, and activation all share one versioned
/// membership.
pub fn install_package_versioned(
    catalogue: &mut SkillCatalogue,
    candidate: &PortableSkillPackageCandidate,
    package: &SkillPackage,
    inputs: &MaterializationInputs,
    context: &CatalogueInstallContext,
    source: &dyn CanonicalToolSource,
    aliases: &ToolAliasTable,
    admitted_definition_version: &str,
) -> Result<String, SkillError> {
    crate::text(
        admitted_definition_version,
        "tools.admitted_definition_version",
    )?;
    let bound = source.definition_version();
    crate::text(bound, "tools.definition_version")?;
    if bound != admitted_definition_version {
        return Err(SkillError::InvalidField {
            field: "tools.definition_version",
            reason: "the tool source binds a definition version the composition did not admit",
        });
    }
    let tools = VersionBoundTools::new(source, aliases);
    install_package(catalogue, candidate, package, inputs, context, &tools)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_skills::{
        AdvisoryRuleClaim, Availability, AvailabilityField, CapabilityVersion, ConflictState,
        DeliveryProjection, DependencyMaterial, DistractorState, FreshnessState, LifecycleProposal,
        QuarantineState, SkillBehavior, SkillCounters, SkillInteractionProjection, SkillState,
        ToolDefinitionMaterial, VersionedObservation, VersionedRequirement,
    };

    /// Boundary double implementing the OWNED port. It is test scaffolding,
    /// never a production provider claim: the version-drift proof below shows
    /// the installer refuses a double whose bound version the composition did
    /// not admit.
    struct ProofSource {
        version: String,
        known: Vec<String>,
    }

    impl CanonicalToolSource for ProofSource {
        fn definition_version(&self) -> &str {
            &self.version
        }

        fn knows_canonical_tool(&self, canonical_name: &str) -> bool {
            self.known.iter().any(|name| name == canonical_name)
        }
    }

    fn source(version: &str) -> ProofSource {
        ProofSource {
            version: version.to_owned(),
            known: vec!["eliot.state".to_owned(), "eliot.query".to_owned()],
        }
    }

    fn behavior() -> SkillBehavior {
        SkillBehavior {
            intent: "orient before acting".to_owned(),
            trigger: "when orientation is required load this skill".to_owned(),
            action: "run eliot.query".to_owned(),
            applies_when: vec!["the task needs orientation".to_owned()],
            where_not_apply: vec!["the host is unsupported".to_owned()],
            required_outputs: vec!["orientation".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            stop: "stop on stale material".to_owned(),
            escalation: "report PLAN_GAP".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
        }
    }

    fn inputs() -> MaterializationInputs {
        MaterializationInputs {
            canonical_source_bytes: b"canonical versioned fixture\n".to_vec(),
            contract_materialization: behavior(),
            dependencies: vec![DependencyMaterial {
                name: "eliot-evidence".to_owned(),
                version: "0.1.0".to_owned(),
                contract_digest: "e".repeat(64),
            }],
            tool_definitions: vec![ToolDefinitionMaterial {
                // Per-tool revisions are opaque to the version gate on
                // purpose: the admitted version binds the SOURCE, never the
                // package requirement rows.
                name: "eliot.state".to_owned(),
                version: "2.5.1".to_owned(),
                description: "orientation state".to_owned(),
                capabilities: vec![CapabilityVersion {
                    name: "eliot.query".to_owned(),
                    version: "7".to_owned(),
                }],
                actions: vec!["run eliot.query".to_owned()],
            }],
        }
    }

    fn rule() -> AdvisoryRuleClaim {
        let revision = eliot_contracts::Revision::new(1).expect("non-zero test revision");
        AdvisoryRuleClaim {
            rule_ref: eliot_rules::RuleRef::new("rule-versioned-1", revision)
                .expect("valid test rule ref"),
        }
    }

    fn fixture_package() -> (SkillPackage, MaterializationInputs) {
        // Behavior and host are the accepted candidate's own: the mapper
        // derives them from the definition and target below, so the binding
        // the versioned install path enforces holds by construction here.
        // The stamped install candidate comes from `fixture_candidate`.
        let candidate = crate::install::candidate_fixture::candidate_for(
            candidate_definition(),
            candidate_target(),
        );
        let material = inputs();
        let package = SkillPackage {
            registration: eliot_skills::RegistrationIdentity::new(
                "skill.versioned",
                "1.0.0",
                "Versioned skill",
            )
            .expect("valid test registration"),
            digests: eliot_skills::PackageDigests::derive(&material).expect("valid test inputs"),
            host: candidate.host.clone(),
            behavior: candidate.behavior.clone(),
            counters: SkillCounters::default(),
            state: SkillState {
                freshness: FreshnessState::Current,
                conflict: ConflictState::None,
                distractor: DistractorState::None,
                quarantine: QuarantineState::Clear,
            },
            lifecycle_proposal: LifecycleProposal::Keep,
            delivery: DeliveryProjection::default(),
            interaction: SkillInteractionProjection::default(),
            rule: rule(),
        };
        package
            .validate(&material)
            .expect("fixture package validates");
        (package, material)
    }

    /// Mirrors [`behavior`] as the accepted procedure definition the
    /// versioned-install fixtures bind against.
    fn candidate_definition() -> eliot_skills::ProcedureDefinition {
        eliot_skills::ProcedureDefinition {
            name: "orientation skill".to_owned(),
            purpose: "orient before acting".to_owned(),
            trigger: "when orientation is required load this skill".to_owned(),
            action: "run eliot.query".to_owned(),
            applies_when: vec!["the task needs orientation".to_owned()],
            where_not_apply: vec!["the host is unsupported".to_owned()],
            required_inputs: vec!["the exact task".to_owned()],
            ordered_steps: vec!["run eliot.query".to_owned()],
            expected_outputs: vec!["orientation".to_owned()],
            stop_conditions: vec!["stop on stale material".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            escalation: "report PLAN_GAP".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
            rollback_or_recovery: "restore the prior revision".to_owned(),
            required_tools: vec![VersionedRequirement {
                name: "eliot.state".to_owned(),
                version: "2.5.1".to_owned(),
            }],
            required_capabilities: vec![VersionedRequirement {
                name: "eliot.query".to_owned(),
                version: "7".to_owned(),
            }],
        }
    }

    fn candidate_target() -> eliot_skills::TargetProfile {
        eliot_skills::TargetProfile {
            target_id: "candidate-target".to_owned(),
            host: "codex".to_owned(),
            profile: "default".to_owned(),
            fingerprint: "2".repeat(64),
            available_tools: vec![VersionedRequirement {
                name: "eliot.state".to_owned(),
                version: "2.5.1".to_owned(),
            }],
            available_capabilities: vec![VersionedRequirement {
                name: "eliot.query".to_owned(),
                version: "7".to_owned(),
            }],
        }
    }

    fn fixture_candidate() -> eliot_skills::PortableSkillPackageCandidate {
        // The producer stamps the exact materialized digests: the versioned
        // install path never sees an unstamped candidate.
        let (package, material) = fixture_package();
        let raw = crate::install::candidate_fixture::candidate_for(
            candidate_definition(),
            candidate_target(),
        );
        crate::stamp_materialization_digests(&raw, &package, &material).expect("fixture stamps")
    }

    fn context() -> CatalogueInstallContext {
        CatalogueInstallContext {
            eligible_routes: vec!["route-1".to_owned()],
            eligible_profiles: vec!["profile-1".to_owned()],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            admitted_definition_version: "1.2.0".to_owned(),
            index_budget_tokens: 200,
            body_budget_tokens: 800,
            runtime_budget_tokens: 2000,
            index_tokens: 60,
            body_tokens: 400,
            runtime_tokens: 0,
            references: vec!["references/playbook.md".to_owned()],
            scripts: Vec::new(),
            assets: Vec::new(),
        }
    }

    fn available_readiness() -> ReadinessClaims {
        ReadinessClaims {
            host: "codex".to_owned(),
            profile: "default".to_owned(),
            provider: Availability::Available {
                field: AvailabilityField::Provider,
            },
            g16: Availability::Available {
                field: AvailabilityField::G16,
            },
            a06: Availability::Available {
                field: AvailabilityField::A06,
            },
            evidence: Availability::Available {
                field: AvailabilityField::Evidence,
            },
            tools: vec![VersionedObservation {
                name: "eliot.state".to_owned(),
                version: "2.5.1".to_owned(),
                availability: Availability::Available {
                    field: AvailabilityField::HostCapability,
                },
            }],
            capabilities: vec![VersionedObservation {
                name: "eliot.query".to_owned(),
                version: "7".to_owned(),
                availability: Availability::Available {
                    field: AvailabilityField::HostCapability,
                },
            }],
        }
    }

    #[test]
    fn alias_table_resolves_identity_by_default_and_admitted_renames() {
        let mut table = ToolAliasTable::new();
        assert_eq!(table.resolve("eliot.query"), "eliot.query");
        table
            .insert("vendor.renamed.query".to_owned(), "eliot.query".to_owned())
            .expect("admitted rename");
        assert_eq!(table.resolve("vendor.renamed.query"), "eliot.query");
        assert_eq!(table.resolve("eliot.query"), "eliot.query");
    }

    #[test]
    fn alias_table_rejects_blank_duplicate_and_self_mappings() {
        let mut table = ToolAliasTable::new();
        assert!(matches!(
            table.insert(String::new(), "eliot.query".to_owned()),
            Err(SkillError::InvalidField { .. })
        ));
        assert!(matches!(
            table.insert("vendor.query".to_owned(), "vendor.query".to_owned()),
            Err(SkillError::InvalidField { .. })
        ));
        table
            .insert("vendor.query".to_owned(), "eliot.query".to_owned())
            .expect("first mapping");
        assert!(matches!(
            table.insert("vendor.query".to_owned(), "eliot.state".to_owned()),
            Err(SkillError::Duplicate { .. })
        ));
    }

    #[test]
    fn versioned_install_passes_through_aliases_to_the_source() {
        let (package, material) = fixture_package();
        let candidate = fixture_candidate();
        let provider = source("1.2.0");
        let mut aliases = ToolAliasTable::new();
        aliases
            .insert("vendor.state".to_owned(), "eliot.state".to_owned())
            .expect("admitted rename");
        // The alias resolves before the lookup: the source only ever sees the
        // canonical name, so routing behavior cannot diverge per provider.
        let view = VersionBoundTools::new(&provider, &aliases);
        assert!(view.knows_tool("vendor.state"));
        assert!(view.knows_tool("eliot.query"));
        assert!(!view.knows_tool("eliot.finish"));
        assert_eq!(view.definition_version(), "1.2.0");

        let mut catalogue = SkillCatalogue::default();
        let installed = install_package_versioned(
            &mut catalogue,
            &candidate,
            &package,
            &material,
            &context(),
            &provider,
            &aliases,
            "1.2.0",
        )
        .expect("versioned install");
        assert_eq!(installed, "skill.versioned");
    }

    #[test]
    fn versioned_install_refuses_drifted_and_blank_admissions() {
        let (package, material) = fixture_package();
        let candidate = fixture_candidate();
        let stale = source("9.9.9");
        let aliases = ToolAliasTable::new();
        let mut catalogue = SkillCatalogue::default();
        let refused = install_package_versioned(
            &mut catalogue,
            &candidate,
            &package,
            &material,
            &context(),
            &stale,
            &aliases,
            "1.2.0",
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "tools.definition_version"
        ));
        assert!(catalogue.is_empty());

        let current = source("1.2.0");
        let blank = install_package_versioned(
            &mut catalogue,
            &candidate,
            &package,
            &material,
            &context(),
            &current,
            &aliases,
            "   ",
        );
        assert!(matches!(
            blank,
            Err(SkillError::InvalidField { field, .. })
                if field == "tools.admitted_definition_version"
        ));
        assert!(catalogue.is_empty());
    }

    #[test]
    fn versioned_install_refuses_tools_absent_from_the_source() {
        let (package, material) = fixture_package();
        let candidate = fixture_candidate();
        let empty = ProofSource {
            version: "1.2.0".to_owned(),
            known: Vec::new(),
        };
        let aliases = ToolAliasTable::new();
        let mut catalogue = SkillCatalogue::default();
        let refused = install_package_versioned(
            &mut catalogue,
            &candidate,
            &package,
            &material,
            &context(),
            &empty,
            &aliases,
            "1.2.0",
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "body.tool_refs"
        ));
        assert!(catalogue.is_empty());
    }

    #[test]
    fn readiness_mirror_requires_exact_available_observations() {
        let (package, _) = fixture_package();
        readiness_available_for_package(&package, &available_readiness())
            .expect("exact available observations cover the package");

        let mut skewed = available_readiness();
        skewed.tools[0].version = "2.5.2".to_owned();
        assert!(matches!(
            readiness_available_for_package(&package, &skewed),
            Err(SkillError::InvalidField { field, .. }) if field == "readiness.tools"
        ));

        let mut unavailable = available_readiness();
        unavailable.capabilities[0].availability = Availability::Unavailable {
            field: AvailabilityField::HostCapability,
            code: eliot_skills::UnavailableCode::HostCapabilityUnavailable,
            reason: "provider revoked the capability".to_owned(),
        };
        assert!(matches!(
            readiness_available_for_package(&package, &unavailable),
            Err(SkillError::InvalidField { field, .. })
                if field == "readiness.capabilities"
        ));
    }

    fn scope() -> MaterializationScope {
        use eliot_contracts::{EpochId, EpochLineageId, ProductId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;

        let fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("valid test lineage"),
                NonZeroU64::new(1).expect("nonzero test sequence"),
            )
            .expect("valid test epoch"),
            ResourceGeneration::new(1).expect("test generation"),
        );
        MaterializationScope {
            work_scope: eliot_receipts::WorkScopeBinding {
                scope_id: eliot_receipts::WorkScopeId::new("workscope-1")
                    .expect("valid test scope"),
                product_id: ProductId::new("test-product").expect("test product"),
                resource_generation: ResourceGeneration::new(1).expect("test generation"),
                state_fence: fence,
            },
            task: None,
        }
    }

    #[test]
    fn sealed_check_passes_provisional_when_the_verifier_is_absent() {
        // Current package, fully available readiness: the sealed entry runs
        // every owner gate, then the missing-ports provider reports PLAN_GAP.
        // Verifier absence is integration state, so the check passes WITHOUT
        // sealed verification; the entry stays provisional by construction.
        let (package, material) = fixture_package();
        sealed_materialization_check(&package, &material, &available_readiness(), &scope())
            .expect("verifier-absent provisional path");
    }

    #[test]
    fn sealed_check_refuses_sealed_omissions_with_the_owner_voice() {
        let (mut package, material) = fixture_package();
        package.state.freshness = FreshnessState::Stale {
            reason: "tool-def-2 moved".to_owned(),
        };
        package
            .validate(&material)
            .expect("stale package still validates");
        let refused =
            sealed_materialization_check(&package, &material, &available_readiness(), &scope());
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "sealed.materialization"
        ));

        let (package, material) = fixture_package();
        let mut foreign = available_readiness();
        foreign.host = "other-host".to_owned();
        let refused = sealed_materialization_check(&package, &material, &foreign, &scope());
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "sealed.materialization"
        ));
    }
}
