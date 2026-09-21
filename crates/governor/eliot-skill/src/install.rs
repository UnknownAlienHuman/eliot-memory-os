//! Governor-owned Skill catalogue installation: canonical package-source
//! projection into validated catalogue entries.
//!
//! This module is the production package-source → catalogue
//! installation/population caller. It projects an exact canonical
//! [`SkillPackage`](eliot_skills::SkillPackage) claim, re-validated against
//! its actual [`MaterializationInputs`](eliot_skills::MaterializationInputs),
//! into one [`SkillCatalogueEntry`] plus inserts it under the tool-owner
//! existence check. Every entry field derives either from the sealed package
//! source or from an explicit Governor-owned [`CatalogueInstallContext`]
//! parameter: nothing is defaulted, inferred, or bridged from a parallel
//! registry.
//!
//! Field map (package source → catalogue entry):
//!
//! ```text
//! registration.skill_id / .name      → index.skill_id / .name
//! behavior.trigger                   → index.trigger (when-to-load, I7.12)
//! context eligible routes/profiles   → index eligibility (admission owner)
//! registration.revision              → body.body_version (source revision)
//! behavior.action (exactly one)      → body.actions
//! behavior.where_not_apply           → body.where_not_apply
//! behavior.stop                      → body.stop_escalation
//! host.required tool + capability    → body.tool_refs (exact names, I7.12)
//!   names (tool-owner existence at insert/activation)
//! inputs.dependencies (exact material) → entry.dependencies (visible
//!   versions + contract digests, I7.13)
//! context host/profile versions      → entry.host_version / .profile_version
//! context runtime inventory+budgets  → entry.runtime (I7.12 cost split)
//! package.state                      → entry.status (Provisional install;
//!   Stale / Quarantined / Suppressed preserved, never upgraded)
//!
//! Interaction refs (`package.interaction`) are validated for consistency at
//! the package boundary (`SkillPackage::validate`) and stay with the Governor
//! lifecycle owner: rival/ordering/exclusion refs live on lifecycle views
//! (`SkillInteractionView`), not on catalogue entries, so they are checked
//! here but not stored here. A conflicted package still installs as
//! `Provisional`; the promotion depth check sees the rivals on its view.
//! ```
//!
//! Semantics honoured:
//!
//! - Immutable bodies: `body_digest` is recomputed canonically over the exact
//!   projected body. Any later mutation changes the digest, so Hotset receipts
//!   issued before a revision fail closed at activation (`IdentityMismatch`).
//!   Re-installing a revised package is an immutable-body revision: the entry
//!   is replaced wholesale and old receipts stop binding. Lifecycle revision
//!   history stays with the Governor lifecycle owner (`SkillRegistry`), never
//!   here.
//! - Approval: installation itself carries no package-string approval handle.
//!   Delivery approval stays where the catalogue boundary already enforces it:
//!   [`HotsetDeliveryReceipt::issue`](crate::HotsetDeliveryReceipt::issue)
//!   requires a non-blank `approval_ref`, and activation requires an applied
//!   receiver ack for that exact receipt. Callers that need an install-time
//!   approval record keep it in the Governor lifecycle review path.
//! - Dependency versions: the exact dependency set comes from
//!   [`MaterializationInputs`](eliot_skills::MaterializationInputs), the same
//!   actual material the package digests bind. A later observed change marks
//!   the entry stale through the existing
//!   [`note_dependency_change`](crate::SkillCatalogue::note_dependency_change)
//!   path and blocks use and delivery until re-admission.
//! - Counters and delivery flags (`SkillCounters`, `DeliveryProjection`) are
//!   lifecycle-owner evidence state, not catalogue install state, and are
//!   deliberately not projected: installed is not delivered, and delivery is
//!   not usefulness.
//!
//! Canonical-wire boundary (quoted exactly, not worked around): the sealed
//! positive materialization
//! ([`MaterializationOutcome::materialized_skill`](eliot_skills::MaterializationOutcome::materialized_skill))
//! is unobtainable outside the `eliot-skills` surface crate — its `sealed`
//! module is private (`crates/surfaces/eliot-skills/src/contract.rs`, `mod
//! sealed`), so no external crate can implement `ReadinessVerifierPort` or
//! `G16VerifierPort`, and the only public port is the always-`PLAN_GAP`
//! `MissingVerificationProvider`. The installer therefore consumes the
//! validated package claim plus its actual inputs through the public
//! [`SkillPackage::validate`](eliot_skills::SkillPackage::validate) binding,
//! which re-derives every package digest from those inputs. When the G-16
//! owner wires a callable sealed path, the same projection accepts the
//! materialized wrapper; the minimum contract needed is a sealed-issued
//! materialization receipt the installer can bind (proposed, not invented).
//!
//! The tool-owner existence check runs at insert (and again at delivery and
//! activation inside the catalogue boundary) over the caller-supplied
//! [`KnownTools`](crate::KnownTools) view. This crate mints no registry: an
//! unknown name fails closed here, never at first activation.

// The crate error carries the full store failure for typed recovery; every
// catalogue function returns it by value like the existing lifecycle API.
// Boxing it here would diverge from that contract, so the size lint is
// allowed for this module (same precedent as the Skill catalogue module).
#![allow(clippy::result_large_err)]

use eliot_skills::{
    ConflictState, DistractorState, FreshnessState, MaterializationInputs, QuarantineState,
    SkillPackage,
};

use super::{
    DependencyVersion, SkillBody, SkillCatalogue, SkillCatalogueEntry, SkillError, SkillIndexEntry,
    SkillRuntimeMetadata, SkillStatus,
};
use crate::KnownTools;
use serde::{Deserialize, Serialize};

/// Governor-owned installation parameters the sealed package does not carry.
///
/// The package binds identity, instruction, exact tools, dependencies, and
/// state. Everything else an entry requires — route/profile admission scope,
/// visible host/profile versions, the Governor-admitted Tool Definition
/// version, and the runtime inventory plus the I7.12 index/body/runtime token
/// budgets — is explicit Governor-owned install context, never inferred from
/// names or defaulted to empty success. The context crosses the Skill wire
/// as JSON, so field shapes stay wire-stable: new install parameters get new
/// optional fields, never silent repurposing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueInstallContext {
    /// Routes this installation admits the Skill for (at least one route or
    /// profile is required by entry validation).
    pub eligible_routes: Vec<String>,
    /// Profiles this installation admits the Skill for.
    pub eligible_profiles: Vec<String>,
    /// Visible host version pinned at install (I7.13).
    pub host_version: String,
    /// Visible profile version pinned at install (I7.13).
    pub profile_version: String,
    /// Tool Definition version the Governor admits for this installation.
    /// Recorded verbatim onto the catalogue entry so standing version
    /// checks compare the live canonical source against the version bound
    /// at install, never a re-stated claim.
    pub admitted_definition_version: String,
    /// Token budget for the index row (paid every session).
    pub index_budget_tokens: u32,
    /// Token budget for the activation body (paid on activation).
    pub body_budget_tokens: u32,
    /// Token budget for runtime assets (paid when read or executed).
    pub runtime_budget_tokens: u32,
    /// Measured index cost; must fit its budget.
    pub index_tokens: u32,
    /// Measured body cost; must fit its budget.
    pub body_tokens: u32,
    /// Measured runtime cost; must fit its budget.
    pub runtime_tokens: u32,
    /// Runtime reference inventory observed at install.
    pub references: Vec<String>,
    /// Runtime script inventory observed at install.
    pub scripts: Vec<String>,
    /// Runtime asset inventory observed at install.
    pub assets: Vec<String>,
}

impl CatalogueInstallContext {
    /// Validates the install context before projection. Entry validation
    /// remains the final gate; this fails fast with context-attributed fields.
    pub fn validate(&self) -> Result<(), SkillError> {
        crate::text(&self.host_version, "context.host_version")?;
        crate::text(&self.profile_version, "context.profile_version")?;
        crate::text(
            &self.admitted_definition_version,
            "context.admitted_definition_version",
        )?;
        if self.eligible_routes.is_empty() && self.eligible_profiles.is_empty() {
            return Err(SkillError::InvalidField {
                field: "context.eligibility",
                reason: "at least one eligible route or profile is required",
            });
        }
        for (budget, field) in [
            (self.index_budget_tokens, "context.index_budget_tokens"),
            (self.body_budget_tokens, "context.body_budget_tokens"),
            (self.runtime_budget_tokens, "context.runtime_budget_tokens"),
        ] {
            if budget == 0 {
                return Err(SkillError::InvalidField {
                    field,
                    reason: "budgets must be non-zero",
                });
            }
        }
        for (actual, budget, field) in [
            (
                self.index_tokens,
                self.index_budget_tokens,
                "context.index_tokens",
            ),
            (
                self.body_tokens,
                self.body_budget_tokens,
                "context.body_tokens",
            ),
            (
                self.runtime_tokens,
                self.runtime_budget_tokens,
                "context.runtime_tokens",
            ),
        ] {
            if actual > budget {
                return Err(SkillError::InvalidField {
                    field,
                    reason: "actual cost exceeds its budget",
                });
            }
        }
        Ok(())
    }
}

/// Projects one canonical package source into a validated catalogue entry.
///
/// Runs the public package↔inputs binding first
/// ([`SkillPackage::validate`](eliot_skills::SkillPackage::validate), which
/// re-derives every package digest from the actual inputs), then maps fields
/// per the module contract and runs entry validation last, so I7.13
/// structural checks gate installation exactly as they gate activation.
///
/// Package surface errors map to [`SkillError::Surface`]: a digest or binding
/// mismatch means the wire claim disagrees with its actual material, never a
/// catalogue logic failure.
pub fn project_package_to_entry(
    package: &SkillPackage,
    inputs: &MaterializationInputs,
    context: &CatalogueInstallContext,
) -> Result<SkillCatalogueEntry, SkillError> {
    package
        .validate(inputs)
        .map_err(|error| SkillError::Surface(error.to_string()))?;
    context.validate()?;

    let mut tool_refs: Vec<String> = Vec::with_capacity(
        package.host.required_tools.len() + package.host.required_capabilities.len(),
    );
    for requirement in &package.host.required_tools {
        if !tool_refs.iter().any(|known| known == &requirement.name) {
            tool_refs.push(requirement.name.clone());
        }
    }
    for requirement in &package.host.required_capabilities {
        if !tool_refs.iter().any(|known| known == &requirement.name) {
            tool_refs.push(requirement.name.clone());
        }
    }

    let mut dependencies = Vec::with_capacity(inputs.dependencies.len());
    for dependency in &inputs.dependencies {
        let version = DependencyVersion {
            name: dependency.name.clone(),
            version: dependency.version.clone(),
            contract_digest: dependency.contract_digest.clone(),
        };
        version.validate()?;
        dependencies.push(version);
    }

    let mut body = SkillBody {
        skill_id: package.registration.skill_id.clone(),
        body_version: package.registration.revision.clone(),
        body_digest: String::new(),
        actions: vec![package.behavior.action.clone()],
        where_not_apply: package.behavior.where_not_apply.clone(),
        stop_escalation: package.behavior.stop.clone(),
        tool_refs,
    };
    body.body_digest = body.expected_digest()?;

    let (status, stale_reason) = install_status(package);

    let entry = SkillCatalogueEntry {
        index: SkillIndexEntry {
            skill_id: package.registration.skill_id.clone(),
            name: package.registration.name.clone(),
            trigger: package.behavior.trigger.clone(),
            eligible_routes: context.eligible_routes.clone(),
            eligible_profiles: context.eligible_profiles.clone(),
        },
        body,
        runtime: SkillRuntimeMetadata {
            skill_id: package.registration.skill_id.clone(),
            body_version: package.registration.revision.clone(),
            references: context.references.clone(),
            scripts: context.scripts.clone(),
            assets: context.assets.clone(),
            index_budget_tokens: context.index_budget_tokens,
            body_budget_tokens: context.body_budget_tokens,
            runtime_budget_tokens: context.runtime_budget_tokens,
            index_tokens: context.index_tokens,
            body_tokens: context.body_tokens,
            runtime_tokens: context.runtime_tokens,
        },
        dependencies,
        host_version: context.host_version.clone(),
        profile_version: context.profile_version.clone(),
        admitted_definition_version: context.admitted_definition_version.clone(),
        status,
        stale_reason,
    };
    entry.validate()?;
    Ok(entry)
}

/// Maps package lifecycle state to the install status. Fresh installation is
/// always `Provisional`: I7.13 grants bounded single-route use without
/// independent transfer evidence, and promotion to `Current` runs through the
/// existing evidence path. Governed negative states are preserved verbatim and
/// never upgraded: quarantine wins over staleness, a distractor installs as
/// `Suppressed` (filtered out, blocked from use), and a conflicted package
/// installs as `Provisional` with its rival refs carried in interactions for
/// the promotion depth check to see.
fn install_status(package: &SkillPackage) -> (SkillStatus, Option<String>) {
    if let QuarantineState::Quarantined { reason } = &package.state.quarantine {
        return (SkillStatus::Quarantined, Some(reason.clone()));
    }
    if let FreshnessState::Stale { reason } = &package.state.freshness {
        return (SkillStatus::Stale, Some(reason.clone()));
    }
    if matches!(package.state.distractor, DistractorState::Distractor { .. }) {
        return (SkillStatus::Suppressed, None);
    }
    debug_assert!(matches!(
        package.state.conflict,
        ConflictState::None | ConflictState::Conflicted { .. }
    ));
    (SkillStatus::Provisional, None)
}

/// Installs one canonical package source into the catalogue: projects the
/// entry, runs the tool-owner existence check at insert, and returns the
/// installed Skill identity.
///
/// Re-installing a revised package replaces the entry wholesale
/// (immutable-body revision): the catalogue digest changes, so Hotset receipts
/// issued before the revision fail closed at activation instead of displaying
/// a stale body. Returns the `skill_id` the Governor owner binds to its
/// lifecycle `SkillRef.package_digest` (`package.digests.source_digest`).
pub fn install_package(
    catalogue: &mut SkillCatalogue,
    package: &SkillPackage,
    inputs: &MaterializationInputs,
    context: &CatalogueInstallContext,
    tools: &dyn KnownTools,
) -> Result<String, SkillError> {
    let entry = project_package_to_entry(package, inputs, context)?;
    let skill_id = entry.index.skill_id.clone();
    catalogue.insert(entry, tools)?;
    Ok(skill_id)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_skills::{
        AdvisoryRuleClaim, CapabilityVersion, DeliveryProjection, DependencyMaterial, HostLimits,
        HostProfile, LifecycleProposal, SkillBehavior, SkillCounters, SkillInteractionProjection,
        SkillState, ToolDefinitionMaterial, VersionedRequirement,
    };

    const BODY_DIGEST_SEED: &str = "package-fixture";

    struct FixtureTools;

    impl KnownTools for FixtureTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "cargo" || name == "rust-test"
        }
    }

    struct EmptyTools;

    impl KnownTools for EmptyTools {
        fn knows_tool(&self, _name: &str) -> bool {
            false
        }
    }

    fn behavior() -> SkillBehavior {
        SkillBehavior {
            intent: "verify one bounded Rust change".to_owned(),
            trigger: "when a bounded Rust verifier is required load this skill".to_owned(),
            action: "run cargo test".to_owned(),
            applies_when: vec!["the package is exact".to_owned()],
            where_not_apply: vec!["the host is unsupported".to_owned()],
            required_outputs: vec!["test result".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            stop: "stop on stale material".to_owned(),
            escalation: "report PLAN_GAP".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
        }
    }

    fn inputs() -> MaterializationInputs {
        MaterializationInputs {
            canonical_source_bytes: BODY_DIGEST_SEED.as_bytes().to_vec(),
            contract_materialization: behavior(),
            dependencies: vec![DependencyMaterial {
                name: "eliot-evidence".to_owned(),
                version: "0.1.0".to_owned(),
                contract_digest: "e".repeat(64),
            }],
            tool_definitions: vec![ToolDefinitionMaterial {
                name: "cargo".to_owned(),
                version: "1.89".to_owned(),
                description: "bounded Cargo verifier".to_owned(),
                capabilities: vec![CapabilityVersion {
                    name: "rust-test".to_owned(),
                    version: "1".to_owned(),
                }],
                actions: vec!["run cargo test".to_owned()],
            }],
        }
    }

    fn rule() -> AdvisoryRuleClaim {
        let revision = eliot_contracts::Revision::new(1).expect("non-zero test revision");
        AdvisoryRuleClaim {
            rule_ref: eliot_rules::RuleRef::new("rule-test-1", revision)
                .expect("valid test rule ref"),
        }
    }

    fn current_state() -> SkillState {
        SkillState {
            freshness: FreshnessState::Current,
            conflict: ConflictState::None,
            distractor: DistractorState::None,
            quarantine: QuarantineState::Clear,
        }
    }

    fn fixture_package() -> (SkillPackage, MaterializationInputs) {
        let material = inputs();
        let package = SkillPackage {
            registration: eliot_skills::RegistrationIdentity::new(
                "skill.demo",
                "1.0.0",
                "Demo skill",
            )
            .expect("valid test registration"),
            digests: eliot_skills::PackageDigests::derive(&material).expect("valid test inputs"),
            host: HostProfile {
                host: "codex".to_owned(),
                profile: "default".to_owned(),
                required_tools: vec![VersionedRequirement {
                    name: "cargo".to_owned(),
                    version: "1.89".to_owned(),
                }],
                required_capabilities: vec![VersionedRequirement {
                    name: "rust-test".to_owned(),
                    version: "1".to_owned(),
                }],
                limits: HostLimits {
                    max_description_chars: 500,
                    max_actions: 1,
                    max_expansion_handles: 2,
                },
            },
            behavior: behavior(),
            counters: SkillCounters::default(),
            state: current_state(),
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

    #[test]
    fn projection_maps_every_package_field_to_its_entry_slot() {
        let (package, material) = fixture_package();
        let entry =
            project_package_to_entry(&package, &material, &context()).expect("package projects");
        entry.validate().expect("projected entry validates");
        assert_eq!(entry.index.skill_id, "skill.demo");
        assert_eq!(entry.index.name, "Demo skill");
        assert_eq!(
            entry.index.trigger,
            "when a bounded Rust verifier is required load this skill"
        );
        assert_eq!(entry.body.body_version, "1.0.0");
        assert_eq!(entry.body.actions, vec!["run cargo test".to_owned()]);
        assert_eq!(
            entry.body.where_not_apply,
            vec!["the host is unsupported".to_owned()]
        );
        assert_eq!(entry.body.stop_escalation, "stop on stale material");
        assert_eq!(
            entry.body.tool_refs,
            vec!["cargo".to_owned(), "rust-test".to_owned()]
        );
        assert_eq!(
            entry.body.body_digest,
            entry.body.expected_digest().expect("digest")
        );
        assert_eq!(
            entry.dependencies,
            vec![DependencyVersion {
                name: "eliot-evidence".to_owned(),
                version: "0.1.0".to_owned(),
                contract_digest: "e".repeat(64),
            }]
        );
        assert_eq!(entry.host_version, "host-4.1.0");
        assert_eq!(entry.profile_version, "profile-2.0.0");
        assert_eq!(entry.status, SkillStatus::Provisional);
        assert_eq!(entry.stale_reason, None);
        assert!(entry.is_usable());
    }

    #[test]
    fn install_checks_tool_existence_and_returns_the_skill_identity() {
        let (package, material) = fixture_package();
        let mut catalogue = SkillCatalogue::default();
        let refused = install_package(&mut catalogue, &package, &material, &context(), &EmptyTools);
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "body.tool_refs"
        ));
        assert!(catalogue.is_empty());
        let installed = install_package(
            &mut catalogue,
            &package,
            &material,
            &context(),
            &FixtureTools,
        )
        .expect("install with known tools");
        assert_eq!(installed, "skill.demo");
        assert!(catalogue.is_usable("skill.demo"));
    }

    #[test]
    fn package_input_digest_mismatch_fails_closed_as_surface() {
        let (package, mut material) = fixture_package();
        material.dependencies[0].version = "9.9.9".to_owned();
        let refused = project_package_to_entry(&package, &material, &context());
        assert!(matches!(refused, Err(SkillError::Surface(_))));
    }

    #[test]
    fn governed_negative_states_install_without_upgrade() {
        let (mut package, material) = fixture_package();
        package.state.freshness = FreshnessState::Stale {
            reason: "tool-def moved".to_owned(),
        };
        let stale = project_package_to_entry(&package, &material, &context())
            .expect("stale package projects");
        assert_eq!(stale.status, SkillStatus::Stale);
        assert_eq!(stale.stale_reason.as_deref(), Some("tool-def moved"));
        assert!(!stale.is_usable());

        let (mut package, material) = fixture_package();
        package.state.quarantine = QuarantineState::Quarantined {
            reason: "governor hold".to_owned(),
        };
        let held = project_package_to_entry(&package, &material, &context())
            .expect("quarantined package projects");
        assert_eq!(held.status, SkillStatus::Quarantined);
        assert!(!held.is_usable());

        let (mut package, material) = fixture_package();
        package.state.distractor = DistractorState::Distractor {
            reason: "semantically filtered".to_owned(),
        };
        let filtered = project_package_to_entry(&package, &material, &context())
            .expect("distractor package projects");
        assert_eq!(filtered.status, SkillStatus::Suppressed);
        assert!(!filtered.is_usable());

        let (mut package, material) = fixture_package();
        package.state.conflict = ConflictState::Conflicted {
            references: vec!["skill.rival".to_owned()],
        };
        package.interaction.conflict_refs = vec!["skill.rival".to_owned()];
        let rival = project_package_to_entry(&package, &material, &context())
            .expect("conflicted package projects");
        assert_eq!(rival.status, SkillStatus::Provisional);
        assert_eq!(rival.stale_reason, None);
        assert!(rival.is_usable());
    }

    #[test]
    fn overlong_trigger_passes_package_but_fails_entry_validation() {
        let (mut package, mut material) = fixture_package();
        package.behavior.trigger =
            "when ".to_owned() + &"very detailed work ".repeat(10) + "arrives";
        material.contract_materialization = package.behavior.clone();
        package.digests =
            eliot_skills::PackageDigests::derive(&material).expect("re-derived digests");
        package
            .validate(&material)
            .expect("long trigger still fits the host description budget");
        let refused = project_package_to_entry(&package, &material, &context());
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "index.trigger"
        ));
    }

    #[test]
    fn install_then_promote_then_deliver_then_ack_then_display() {
        use crate::{
            HotsetAckDisposition, HotsetDeliveryAck, HotsetDeliveryReceipt, PromotionEvidence,
        };

        let (package, material) = fixture_package();
        let mut catalogue = SkillCatalogue::default();
        install_package(
            &mut catalogue,
            &package,
            &material,
            &context(),
            &FixtureTools,
        )
        .expect("install");
        catalogue
            .promote(
                "skill.demo",
                &PromotionEvidence {
                    independent_route_count: 1,
                    route_refs: vec!["route-1".to_owned()],
                    human_approval_ref: None,
                    is_shared_or_critical: false,
                },
            )
            .expect("evidence promotion to current");
        let receipt = HotsetDeliveryReceipt::issue(
            "hotset-install-1".to_owned(),
            &catalogue,
            vec!["skill.demo".to_owned()],
            &FixtureTools,
            "approval-commit-1".to_owned(),
        )
        .expect("delivery receipt");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        assert!(ack.confirms_applied(&receipt));
        let display = catalogue
            .activation_display("skill.demo", &receipt, &ack, &FixtureTools)
            .expect("activation display");
        display.validate().expect("display validates");
        let rendered = display.render();
        assert!(rendered.contains("when a bounded Rust verifier is required load this skill"));
        assert!(rendered.contains("1.0.0"));
        assert!(rendered.contains("budget index 60/200 body 400/800 runtime 0/2000"));
        assert!(rendered.contains("eliot-evidence@0.1.0"));
        assert!(rendered.contains(&receipt.receipt_digest));

        // Dependency drift after installation blocks redelivery and display.
        let mut drifted = material
            .dependencies
            .clone()
            .into_iter()
            .map(|item| DependencyVersion {
                name: item.name,
                version: item.version,
                contract_digest: item.contract_digest,
            })
            .collect::<Vec<_>>();
        drifted[0].version = "2.0.0".to_owned();
        assert!(
            catalogue
                .note_dependency_change(
                    "skill.demo",
                    drifted,
                    "eliot-evidence moved to 2.0.0".to_owned()
                )
                .expect("stale tracking")
        );
        assert!(!catalogue.is_usable("skill.demo"));
        let redelivery = HotsetDeliveryReceipt::issue(
            "hotset-install-2".to_owned(),
            &catalogue,
            vec!["skill.demo".to_owned()],
            &FixtureTools,
            "approval-commit-2".to_owned(),
        );
        assert!(matches!(
            redelivery,
            Err(SkillError::InvalidField { field, .. }) if field == "delivery.delivered_skill_ids"
        ));
    }

    #[test]
    fn context_rejects_empty_eligibility_zero_budgets_and_overruns() {
        let (package, material) = fixture_package();
        let mut bare = context();
        bare.eligible_routes.clear();
        bare.eligible_profiles.clear();
        assert!(matches!(
            project_package_to_entry(&package, &material, &bare),
            Err(SkillError::InvalidField { field, .. }) if field == "context.eligibility"
        ));
        let mut free = context();
        free.body_budget_tokens = 0;
        assert!(matches!(
            project_package_to_entry(&package, &material, &free),
            Err(SkillError::InvalidField { field, .. }) if field == "context.body_budget_tokens"
        ));
        let mut overrun = context();
        overrun.body_tokens = overrun.body_budget_tokens + 1;
        assert!(matches!(
            project_package_to_entry(&package, &material, &overrun),
            Err(SkillError::InvalidField { field, .. }) if field == "context.body_tokens"
        ));
    }
}
