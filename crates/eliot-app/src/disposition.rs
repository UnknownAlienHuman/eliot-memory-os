//! Legacy facade disposition inventory for issue #18.
//!
//! `eliot-governor` is a migration/regression facade, not a production
//! composition root. This module records the machine-readable inventory of
//! live callers that still terminate here, the disposition of each caller
//! (extract to its current owner, keep as a dated temporary fixture, or
//! remove), and the fail-closed startup guards that keep the facade from
//! gaining new ownership or new public surface and from re-entering the root
//! default build set.
//!
//! Every guard here is a detector over data baked at compile time with
//! `include_str!` from literal repository paths. The live side of every
//! comparison is read out of the real file, so a guard cannot be satisfied by
//! an assertion about the same hand-written list it is checking: changing the
//! real file is what makes the guard answer `Err`.
//!
//! Completeness boundary: [`CONSUMER_SURFACES`] is the declared class of
//! facade install/launch/advertisement surfaces, and
//! [`consumer_disposition_guard`] proves the inventory covers exactly that
//! class. Edges already migrated off the facade leave both tables and are
//! recorded in [`MIGRATED_CONSUMER_EDGES`] instead, guarded by
//! [`migrated_edge_guard`]. A legacy consumer that is *not* named there is outside the detector,
//! because `include_str!` needs a literal path and this crate has no hermetic
//! way to enumerate repository files at startup. Widening the class is a
//! one-line addition to that table, and the table is reviewable.

/// Where a live facade caller must go when the facade is retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Migrate the caller to the named current owner crate/binary.
    ExtractToCurrentOwner,
    /// Keep working only until the named expiry/removal condition holds.
    TemporaryFixture,
    /// Delete the caller or its legacy reference; nothing migrates.
    Remove,
}

impl Disposition {
    /// Recorded disposition word, used in guard failure text.
    const fn label(self) -> &'static str {
        match self {
            Self::ExtractToCurrentOwner => "extract_to_current_owner",
            Self::TemporaryFixture => "temporary_fixture",
            Self::Remove => "remove",
        }
    }
}

/// One live caller that still terminates at the `eliot-governor` facade.
///
/// `consumer` names the calling surface, never a bare command name.
/// `proof` is the repository path that proves the live call edge and is
/// always one of the baked [`CONSUMER_SURFACES`] paths.
/// `live_reference` is the exact text inside `proof` that proves the edge is
/// still live; the guard opens the baked proof and requires it.
/// `expiry` is the removal condition that retires this entry.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerEntry {
    /// Named calling surface, never a bare command name.
    pub consumer: &'static str,
    /// Repository path that proves the live call edge.
    pub proof: &'static str,
    /// Exact text inside `proof` that the guard verifies.
    pub live_reference: &'static str,
    /// The single disposition this retained path carries.
    pub disposition: Disposition,
    /// Removal condition; a [`Disposition::TemporaryFixture`] must date it.
    pub expiry: &'static str,
}

/// A declared facade install/launch/advertisement surface, baked from a
/// literal repository path at compile time.
pub struct ConsumerSurface {
    /// Repository-relative path that inventory entries must cite.
    pub path: &'static str,
    /// Exact text that proves this surface still reaches the facade.
    pub live_reference: &'static str,
    /// Baked file bytes, opened by the guards.
    pub body: &'static str,
}

const CODEX_PLUGIN_HOOKS: &str = include_str!("../../../plugin/eliot-governor/hooks/hooks.json");
const CODEX_PLUGIN_MCP: &str = include_str!("../../../plugin/eliot-governor/.mcp.json");
const CLAUDE_PLUGIN_HOOKS: &str =
    include_str!("../../../integrations/claude/eliot/hooks/hooks.json");
const CLAUDE_PLUGIN_MCP: &str = include_str!("../../../integrations/claude/eliot/.mcp.json");
const CLAUDE_DESKTOP_MCPB: &str =
    include_str!("../../../integrations/claude/claude-desktop/mcpb/manifest.json");
const CLAUDE_DESKTOP_README: &str =
    include_str!("../../../integrations/claude/claude-desktop/README.md");
const CLAUDE_DESKTOP_MCPB_README: &str =
    include_str!("../../../integrations/claude/claude-desktop/mcpb/README.md");
const OPENCODE_CONFIG: &str = include_str!("../../../integrations/opencode/opencode.json");
const OPENCODE_PLUGIN: &str = include_str!("../../../integrations/opencode/plugins/eliot.js");
const CODEX_MARKETPLACE: &str = include_str!("../../../integrations/codex/marketplace.json");
const CODEX_PLUGIN_METADATA: &str =
    include_str!("../../../plugin/eliot-governor/.codex-plugin/plugin.json");
const OPERATOR_CONTRACTS: &str =
    include_str!("../../../apps/Eliot.Operator/Protocol/OperatorContracts.cs");
const OPERATOR_INTENT: &str =
    include_str!("../../../apps/Eliot.Operator/Protocol/OperatorIntent.cs");
const OPERATOR_RESPONSE_BOUNDS: &str =
    include_str!("../../../apps/Eliot.Operator/Protocol/OperatorResponseBounds.cs");
const OPERATOR_README: &str = include_str!("../../../apps/Eliot.Operator/README.md");
const OPERATOR_TESTS: &str = include_str!("../../../tests/Eliot.Operator.Tests/Program.cs");
const WINDOWS_RELEASE_BUILD: &str =
    include_str!("../../../scripts/build-eliot-windows-x64-release.ps1");
const CLAUDE_DESKTOP_BUILD: &str =
    include_str!("../../../scripts/build-claude-desktop-extension.ps1");
const CREDENTIAL_RUNBOOK: &str =
    include_str!("../../../docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md");
const CLAUDE_DESKTOP_GUIDE: &str =
    include_str!("../../../docs/integrations/claude/CLAUDE_DESKTOP_MCPB.md");
const CLAUDE_CODE_PLUGIN_GUIDE: &str =
    include_str!("../../../docs/integrations/claude/CLAUDE_CODE_PLUGIN.md");
const CLAUDE_PLUGIN_README: &str = include_str!("../../../integrations/claude/eliot/README.md");
const OPENCODE_README: &str = include_str!("../../../integrations/opencode/README.md");
const WINDOWS_RELEASE_GUIDE: &str = include_str!("../../../docs/release/WINDOWS_X64_RELEASE.md");
const HOST_BUNDLE_MANIFEST: &str =
    include_str!("../../../integrations/agent-runtimes/host-bundle.manifest.json");
const CODEX_ROUTE_PROFILE: &str = include_str!("../../../integrations/codex/route-profile.json");
const CLAUDE_CONNECTOR_TEST: &str = include_str!("../../../scripts/test-claude-connector.ps1");
const MCP_REFERENCE_CLIENT: &str = include_str!("../../../scripts/eliot-mcp-reference-client.ps1");
const OPENCODE_PLUGIN_TEST: &str =
    include_str!("../../../integrations/opencode/tests/eliot-plugin.test.mjs");
const TRUSTED_CLI_LIVE_SIGNING_TEST: &str =
    include_str!("../../../tests/release-security/trusted-cli-live-signing-tests.ps1");

/// Every declared install/launch/advertisement surface of the legacy binary.
///
/// The guard requires exactly one inventory entry per surface and rejects an
/// inventory entry whose `proof` is not one of these paths, so the inventory
/// cannot silently fall behind the declared consumer set.
pub const CONSUMER_SURFACES: &[ConsumerSurface] = &[
    ConsumerSurface {
        path: "plugin/eliot-governor/hooks/hooks.json",
        live_reference: "${PLUGIN_ROOT}\\\\bin\\\\eliot-governor.exe",
        body: CODEX_PLUGIN_HOOKS,
    },
    ConsumerSurface {
        path: "integrations/claude/eliot/hooks/hooks.json",
        live_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
        body: CLAUDE_PLUGIN_HOOKS,
    },
    ConsumerSurface {
        path: "integrations/opencode/opencode.json",
        live_reference: "\"{env:ELIOT_GOVERNOR_EXE}\"",
        body: OPENCODE_CONFIG,
    },
    ConsumerSurface {
        path: "integrations/opencode/plugins/eliot.js",
        live_reference: "host-integrations/opencode/bin/eliot-governor.exe",
        body: OPENCODE_PLUGIN,
    },
    ConsumerSurface {
        path: "integrations/codex/marketplace.json",
        live_reference: "\"installation\": \"INSTALLED_BY_DEFAULT\"",
        body: CODEX_MARKETPLACE,
    },
    ConsumerSurface {
        path: "plugin/eliot-governor/.codex-plugin/plugin.json",
        live_reference: "\"name\": \"eliot-governor\"",
        body: CODEX_PLUGIN_METADATA,
    },
    ConsumerSurface {
        path: "scripts/build-eliot-windows-x64-release.ps1",
        live_reference: "integrations/codex/plugins/eliot-governor/bin/eliot-governor.exe",
        body: WINDOWS_RELEASE_BUILD,
    },
    ConsumerSurface {
        path: "scripts/build-claude-desktop-extension.ps1",
        live_reference: "server\\eliot-governor.exe",
        body: CLAUDE_DESKTOP_BUILD,
    },
    ConsumerSurface {
        path: "docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md",
        live_reference: "eliot-governor --config",
        body: CREDENTIAL_RUNBOOK,
    },
    ConsumerSurface {
        path: "docs/integrations/claude/CLAUDE_DESKTOP_MCPB.md",
        live_reference: "server/eliot-governor.exe mcp stdio",
        body: CLAUDE_DESKTOP_GUIDE,
    },
    ConsumerSurface {
        path: "docs/integrations/claude/CLAUDE_CODE_PLUGIN.md",
        live_reference: "${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe",
        body: CLAUDE_CODE_PLUGIN_GUIDE,
    },
    ConsumerSurface {
        path: "integrations/claude/eliot/README.md",
        live_reference: "eliot-governor host install --host claude",
        body: CLAUDE_PLUGIN_README,
    },
    ConsumerSurface {
        path: "integrations/opencode/README.md",
        live_reference: "eliot-governor host install --host opencode",
        body: OPENCODE_README,
    },
    ConsumerSurface {
        path: "docs/release/WINDOWS_X64_RELEASE.md",
        live_reference: "the Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`",
        body: WINDOWS_RELEASE_GUIDE,
    },
    ConsumerSurface {
        path: "integrations/agent-runtimes/host-bundle.manifest.json",
        live_reference: "\"destination_hint\": \"CODEX_HOME/plugins/eliot-governor\"",
        body: HOST_BUNDLE_MANIFEST,
    },
    ConsumerSurface {
        path: "integrations/codex/route-profile.json",
        live_reference: "\"path\": \"plugin/eliot-governor/.mcp.json\"",
        body: CODEX_ROUTE_PROFILE,
    },
    ConsumerSurface {
        path: "scripts/test-claude-connector.ps1",
        live_reference: "'release\\eliot-governor.exe'",
        body: CLAUDE_CONNECTOR_TEST,
    },
    ConsumerSurface {
        path: "integrations/claude/claude-desktop/README.md",
        live_reference: "cargo build --release -p eliot-app",
        body: CLAUDE_DESKTOP_README,
    },
    ConsumerSurface {
        path: "integrations/claude/claude-desktop/mcpb/README.md",
        live_reference: "`eliot-governor.exe`",
        body: CLAUDE_DESKTOP_MCPB_README,
    },
    ConsumerSurface {
        path: "apps/Eliot.Operator/Protocol/OperatorContracts.cs",
        live_reference: "crates/eliot-app/src/mcp_stdio/catalog.rs",
        body: OPERATOR_CONTRACTS,
    },
    ConsumerSurface {
        path: "apps/Eliot.Operator/Protocol/OperatorIntent.cs",
        live_reference: "crates/eliot-app/src/mcp_stdio.rs",
        body: OPERATOR_INTENT,
    },
    ConsumerSurface {
        path: "apps/Eliot.Operator/Protocol/OperatorResponseBounds.cs",
        live_reference: "crates/eliot-app/src/mcp_stdio/operator.rs",
        body: OPERATOR_RESPONSE_BOUNDS,
    },
    ConsumerSurface {
        path: "apps/Eliot.Operator/README.md",
        live_reference: "The `eliot_operator_*` tools are served by `crates/eliot-app`",
        body: OPERATOR_README,
    },
    ConsumerSurface {
        path: "tests/Eliot.Operator.Tests/Program.cs",
        live_reference: "crates/eliot-app/src/mcp_stdio/operator.rs",
        body: OPERATOR_TESTS,
    },
    ConsumerSurface {
        path: "scripts/eliot-mcp-reference-client.ps1",
        live_reference: "'codex_controller'",
        body: MCP_REFERENCE_CLIENT,
    },
    ConsumerSurface {
        path: "integrations/opencode/tests/eliot-plugin.test.mjs",
        live_reference: "process.env.ELIOT_GOVERNOR_EXE",
        body: OPENCODE_PLUGIN_TEST,
    },
    ConsumerSurface {
        path: "tests/release-security/trusted-cli-live-signing-tests.ps1",
        live_reference: "eliot-governor.exe",
        body: TRUSTED_CLI_LIVE_SIGNING_TEST,
    },
];

/// A token-bearing repository artifact whose exact path has been inspected
/// and whose semantic relationship to the Governor executable is classified.
/// These rows close the scanner denominator; `reference_only` rows do not
/// create a live executable consumer, while `live_consumer` rows stay in the
/// independently derived migration/equivalence proof denominator.
pub struct ClosedReferenceRole {
    /// Exact repository-relative path. No directory or extension rule applies.
    pub path: &'static str,
    /// Closed semantic role parsed by the release closure verifier.
    pub role: &'static str,
    /// Why the token is present and how retirement affects this exact artifact.
    pub basis: &'static str,
}

/// Exact non-surface references found by the tracked-token scan. Existing
/// `CONSUMER_SURFACES` and `MIGRATED_CONSUMER_EDGES` remain the independent
/// live/migrated owner declarations; any unlisted new reference remains
/// unknown. In particular, a path merely being documentation, a test, or a
/// script never grants it a role.
pub const CLOSED_REFERENCE_ROLES: &[ClosedReferenceRole] = &[
    // Current build and test entrypoints still consume the facade/package.
    ClosedReferenceRole {
        path: "Justfile",
        role: "live_consumer:build",
        basis: "sync-skills invokes cargo run -p eliot-app; retain explicit migration/equivalence proof",
    },
    ClosedReferenceRole {
        path: "scripts/run-isolated-tests.ps1",
        role: "live_consumer:test",
        basis: "the default TestPackage selects eliot-app for actual isolated test execution",
    },
    ClosedReferenceRole {
        path: "tests/release-security/trusted-cli-launch-tests.ps1",
        role: "live_consumer:test",
        basis: "launch contract fixture executes and verifies the selected release CLI identity",
    },
    ClosedReferenceRole {
        path: "Cargo.lock",
        role: "live_consumer:workspace_lock",
        basis: "locked workspace package identity used by Cargo resolution; keep in the current build proof denominator",
    },
    // Current Governor-config protocol, distinct from ELIOT_GOVERNOR_EXE.
    ClosedReferenceRole {
        path: "scripts/integration/IntegrationHarness.Runtime.psm1",
        role: "reference_only:current_configuration",
        basis: "ELIOT_GOVERNOR_CONFIG is a run-local protected config receipt, not an executable launch variable",
    },
    ClosedReferenceRole {
        path: "scripts/tests/IntegrationHarness.Runtime.Tests.ps1",
        role: "reference_only:current_configuration",
        basis: "fixtures exercise the current ELIOT_GOVERNOR_CONFIG receipt protocol and reject ambient values",
    },
    // Historical work units, migration maps, and decision records.
    ClosedReferenceRole {
        path: ".github/work-units/context-measurement-inventory.toml",
        role: "reference_only:historical_record",
        basis: "work-unit source inventory records package tokens for context accounting",
    },
    ClosedReferenceRole {
        path: ".github/work-units/context-measurement-owner-map.toml",
        role: "reference_only:historical_record",
        basis: "work-unit ownership map records the facade as a measured source boundary",
    },
    ClosedReferenceRole {
        path: "T11.md",
        role: "reference_only:historical_record",
        basis: "historical task record cites the legacy package as migration context",
    },
    ClosedReferenceRole {
        path: "T12.md",
        role: "reference_only:historical_record",
        basis: "historical task record cites the legacy package as migration context",
    },
    ClosedReferenceRole {
        path: "T9.md",
        role: "reference_only:historical_record",
        basis: "historical task record cites the legacy package as migration context",
    },
    ClosedReferenceRole {
        path: "docs/ADR/0001-phase-a-dependency-boundaries.md",
        role: "reference_only:decision_record",
        basis: "accepted dependency decision documents the former aggregate crate boundary",
    },
    ClosedReferenceRole {
        path: "docs/ADR/0004-l3-owned-user-mode-dogfood-runtime.md",
        role: "reference_only:decision_record",
        basis: "accepted runtime decision records historical facade/runtime separation",
    },
    ClosedReferenceRole {
        path: "docs/ADR/0005-l3-isolated-codex-clone.md",
        role: "reference_only:decision_record",
        basis: "accepted isolation decision records the legacy Codex clone context",
    },
    ClosedReferenceRole {
        path: "docs/ADR/0006-l7-lossless-opencode-jsonc-ownership.md",
        role: "reference_only:decision_record",
        basis: "accepted OpenCode decision records a former host integration reference",
    },
    ClosedReferenceRole {
        path: "docs/DEPENDENCY_POLICY.md",
        role: "reference_only:policy_history",
        basis: "dependency-policy narrative records legacy package identity, not an executable command",
    },
    ClosedReferenceRole {
        path: "docs/PROJECT_MAP.md",
        role: "reference_only:project_map",
        basis: "navigation map points to the facade owner path without invoking it",
    },
    ClosedReferenceRole {
        path: "docs/architecture/I02-01-primary-decision-crate-rich-process-sparse-owner-sparse.md",
        role: "reference_only:architecture_history",
        basis: "architecture evidence records an earlier package topology",
    },
    ClosedReferenceRole {
        path: "docs/architecture/I10-08-12-source-ownership-and-first-crate-extraction-wave.md",
        role: "reference_only:architecture_history",
        basis: "migration evidence records the original aggregate crate extraction path",
    },
    ClosedReferenceRole {
        path: "docs/architecture/I19-03-component-disposition.md",
        role: "reference_only:migration_policy",
        basis: "migration contract names the facade as a disposition target",
    },
    ClosedReferenceRole {
        path: "docs/architecture/ROUTES.md",
        role: "reference_only:navigation",
        basis: "documentation route index preserves a legacy source link",
    },
    ClosedReferenceRole {
        path: "docs/architecture/route-rules.toml",
        role: "reference_only:documentation_configuration",
        basis: "reader route examples mention the legacy path as repository content",
    },
    ClosedReferenceRole {
        path: "docs/integrations/claude/CLAUDE_INTEGRATION_SECURITY.md",
        role: "reference_only:security_guidance",
        basis: "security guidance describes the old launcher as a migration boundary",
    },
    ClosedReferenceRole {
        path: "docs/migration/1860-dispositions.md",
        role: "reference_only:migration_inventory",
        basis: "generated migration disposition records a package retirement row",
    },
    ClosedReferenceRole {
        path: "docs/migration/1860-impact-graph.md",
        role: "reference_only:migration_inventory",
        basis: "generated impact graph records the package node and edge set",
    },
    ClosedReferenceRole {
        path: "docs/operations/AGENT_DELIVERY_GUIDE.md",
        role: "live_consumer:build",
        basis: "the Windows release copies docs/operations verbatim and this operator guide tells recipients the Governor host route is current",
    },
    ClosedReferenceRole {
        path: "workstreams/T13.md",
        role: "reference_only:workstream_record",
        basis: "retirement workstream records the facade migration sequence",
    },
    ClosedReferenceRole {
        path: "workstreams/T7.md",
        role: "reference_only:workstream_record",
        basis: "retirement workstream records the facade migration sequence",
    },
    ClosedReferenceRole {
        path: "workstreams/configuration/assignments/1219-legacy-config-retirement.toml",
        role: "reference_only:workstream_record",
        basis: "configuration assignment records a retired config filename that shares the token",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/AGENTS.md",
        role: "reference_only:owner_instruction",
        basis: "owner instructions describe facade references as migration work",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/T1.md",
        role: "reference_only:workstream_record",
        basis: "workstream record cites the facade owner boundary",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/T2.md",
        role: "reference_only:workstream_record",
        basis: "workstream record cites the facade owner boundary",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/assignments/018-governor-ownership-boundary.toml",
        role: "reference_only:workstream_record",
        basis: "#18 assignment inventories the facade for migration and retirement",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/assignments/077-agent-bridge-host-request-port.toml",
        role: "reference_only:workstream_record",
        basis: "host-request assignment records the old MCP entrypoint as a replaced route",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/capability-cell-registry.contract.toml",
        role: "reference_only:owner_registry",
        basis: "capability registry records migration ownership, not an executable invocation",
    },
    ClosedReferenceRole {
        path: "workstreams/core-daemons/inventory.json",
        role: "reference_only:owner_registry",
        basis: "daemon inventory records the legacy facade as a migration boundary",
    },
    ClosedReferenceRole {
        path: "workstreams/github/assignments/1225-manual-workflow-reproducibility.toml",
        role: "reference_only:workstream_record",
        basis: "workflow assignment cites repository paths for reproducibility context",
    },
    ClosedReferenceRole {
        path: "workstreams/integration/assignments/1217-host-dispositions.toml",
        role: "reference_only:workstream_record",
        basis: "host disposition assignment tracks legacy integration references",
    },
    ClosedReferenceRole {
        path: "workstreams/integration/assignments/911-isolated-runtime-provider.toml",
        role: "reference_only:workstream_record",
        basis: "runtime-provider assignment cites facade history",
    },
    ClosedReferenceRole {
        path: "workstreams/integrations/assignments/1217-agent-host-integrations.toml",
        role: "reference_only:workstream_record",
        basis: "integration assignment records legacy host path identities",
    },
    ClosedReferenceRole {
        path: "workstreams/legacy/assignments/1189-legacy-core-retirement.toml",
        role: "reference_only:workstream_record",
        basis: "#1189 assignment is the retirement ledger for the aggregate crate",
    },
    ClosedReferenceRole {
        path: "workstreams/legacy/retirement-1189.toml",
        role: "reference_only:workstream_record",
        basis: "#1189 retirement ledger records source paths for deletion sequencing",
    },
    ClosedReferenceRole {
        path: "workstreams/regressions/assignments/007-claude-completion-reconciliation.toml",
        role: "reference_only:workstream_record",
        basis: "regression assignment cites a historical compatibility route",
    },
    ClosedReferenceRole {
        path: "workstreams/regressions/assignments/008-agent-context-attach.toml",
        role: "reference_only:workstream_record",
        basis: "regression assignment cites a historical compatibility route",
    },
    ClosedReferenceRole {
        path: "workstreams/regressions/assignments/009-antigravity-terminal-reduction.toml",
        role: "reference_only:workstream_record",
        basis: "regression assignment cites a historical compatibility route",
    },
    ClosedReferenceRole {
        path: "workstreams/release/assignments/1227-release-current-generation.toml",
        role: "reference_only:workstream_record",
        basis: "release assignment inventories the old bundle path as a removal condition",
    },
    ClosedReferenceRole {
        path: "workstreams/surfaces/assignments/1137-operator-winui-runtime.toml",
        role: "reference_only:workstream_record",
        basis: "surface assignment maps the legacy operator protocol to its owner",
    },
    // Generated code-navigation projections bind text, not runtime callers.
    ClosedReferenceRole {
        path: "docs/code-navigation/PACKAGE_DOCS_INDEX.md",
        role: "reference_only:generated_projection",
        basis: "generated package index links to the migration facade documentation",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/agent-bridge-core/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/agent-bridge-core/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/foundation.authority.epoch-identity/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/foundation.authority.epoch-identity/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/foundation.contracts.primitives/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/foundation.contracts.primitives/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.capability-admission/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.capability-admission/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.composition/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.composition/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.kernel-transport/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.kernel-transport/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.learning-closure/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.learning-closure/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.operator-replay/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.operator-replay/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.poll-contour/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.poll-contour/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.skill-catalogue/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.skill-catalogue/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.startup-binding/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.daemon.startup-binding/contract_kit.json",
        role: "reference_only:generated_projection",
        basis: "generated contract projection describes current daemon migration closure",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.admission/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.admission/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.classifier/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.classifier/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.journal_projection/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.journal_projection/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.plan_compilation/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor.observation.plan_compilation/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor_read/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/governor_read/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains migration package identity",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/index.json",
        role: "reference_only:generated_projection",
        basis: "generated capsule index records source package links",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/kernel-core/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/kernel-core/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/maintenance/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/maintenance/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/meta.improvement/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/meta.learning.activation_assessment/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/meta.learning.activation_assessment/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/observation-contracts/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/observation-contracts/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/operational-recovery-state/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/operational-recovery-state/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/runtime-contracts/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/runtime-contracts/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule records a migration source edge",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.context.candidates/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.context.candidates/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.context.contracts/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.context.contracts/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.context.reactive_delivery_plan/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.context.reactive_delivery_plan/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.cue.contracts/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.cue.contracts/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.cue.index/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.cue.index/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.dreamer.failure/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.dreamer.failure/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.epistemic.contracts/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.epistemic.contracts/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.epistemic.position/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.epistemic.position/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.learning.contracts/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.learning.contracts/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.learning.delta/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/smart.learning.delta/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/wasm-runtime/context_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated context capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/capsules/wasm-runtime/test_capsule.json",
        role: "reference_only:generated_projection",
        basis: "generated test capsule contains a source inventory token",
    },
    ClosedReferenceRole {
        path: "docs/code-navigation/logical-blocks.toml",
        role: "reference_only:generated_projection",
        basis: "generated source ownership projection includes a legacy symbol match",
    },
    // Exact audit, migration, test-data, and repository-control fixtures.
    ClosedReferenceRole {
        path: ".gitignore",
        role: "reference_only:repository_hygiene",
        basis: "ignore pattern prevents a local legacy data directory from entering Git",
    },
    ClosedReferenceRole {
        path: "scripts/audit-architecture-boundaries.py",
        role: "reference_only:audit_fixture",
        basis: "architecture audit scans names as static boundary evidence",
    },
    ClosedReferenceRole {
        path: "scripts/audit_cue_kind_retirement.py",
        role: "reference_only:audit_fixture",
        basis: "cue-kind retirement audit carries facade text only in its inventory corpus",
    },
    ClosedReferenceRole {
        path: "scripts/code_navigation_lib/common.py",
        role: "reference_only:navigation_configuration",
        basis: "skip-name set excludes local legacy data from generated navigation",
    },
    ClosedReferenceRole {
        path: "scripts/context_measurement_inventory.py",
        role: "reference_only:measurement_inventory",
        basis: "context measurement inventories source tokens without invoking the executable",
    },
    ClosedReferenceRole {
        path: "scripts/migration_inventory_1860.py",
        role: "reference_only:migration_inventory",
        basis: "migration inventory assigns the facade RETIRE disposition and records owners",
    },
    ClosedReferenceRole {
        path: "scripts/testdata/crate-reachability/crate_extraction_decisions.toml",
        role: "reference_only:audit_fixture",
        basis: "fixture exercises static crate reachability disposition parsing",
    },
    ClosedReferenceRole {
        path: "scripts/tests/test_cue_kind_retirement.py",
        role: "reference_only:audit_fixture",
        basis: "test exercises cue-kind inventory and retirement parsing",
    },
    ClosedReferenceRole {
        path: "scripts/verify-core-daemon-inventory.py",
        role: "reference_only:migration_verifier",
        basis: "verifier checks the facade registry and retirement status; it does not launch the command",
    },
    ClosedReferenceRole {
        path: "scripts/verify-github-workflows.py",
        role: "reference_only:audit_fixture",
        basis: "workflow verifier checks cache-key fixture strings containing the package token",
    },
    ClosedReferenceRole {
        path: "scripts/verify-legacy-config-retirement.py",
        role: "reference_only:migration_verifier",
        basis: "verifier's config filename and negative fixtures share the token; it does not launch the Governor",
    },
    ClosedReferenceRole {
        path: "scripts/work_unit_gate/doc_read_evidence.py",
        role: "reference_only:audit_fixture",
        basis: "documentation evidence schema cites a source path as data",
    },
    ClosedReferenceRole {
        path: "tests/cognitive/memory-curation/cases.json",
        role: "reference_only:test_data",
        basis: "cognitive fixture carries legacy source text as evaluation data",
    },
    ClosedReferenceRole {
        path: "tests/cognitive/memory-curation/curation-corpus.json",
        role: "reference_only:test_data",
        basis: "curation corpus stores a historical path mention as input data",
    },
    ClosedReferenceRole {
        path: "tests/release-security/build-sandbox-cache-tests.ps1",
        role: "reference_only:audit_fixture",
        basis: "sandbox cache test uses the name in a synthetic path fixture, not as an executable",
    },
    ClosedReferenceRole {
        path: "workspace/tools/eliot-runtime-compiler/src/lib.rs",
        role: "reference_only:migration_compiler_input",
        basis: "MIG-05 binds a migration cell to the facade path for analysis, not runtime invocation",
    },
    ClosedReferenceRole {
        path: "integrations/agent-skills/skill-pack.manifest.json",
        role: "live_consumer:build",
        basis: "eliot-skills validates derived_packages and SkillPackService::sync writes the declared plugin/eliot-governor/skills package",
    },
    ClosedReferenceRole {
        path: "plugin/eliot-antigravity-official/shared/ELIOT_TOOL_USAGE.md",
        role: "reference_only:skill_guidance",
        basis: "shared skill text mentions the old integration as migration guidance",
    },
];

/// Owner words the facade must never gain, per `crates/eliot-app/AGENTS.md`.
///
/// Compared against real facade data by [`assert_no_new_ownership`], never
/// tested for emptiness.
pub const FORBIDDEN_OWNER_SYMBOLS: &[&str] = &[
    "task",
    "WorkScope",
    "memory",
    "policy",
    "finish",
    "coordination",
    "scheduling",
    "Module",
    "Module Catalog",
    "storage",
    "store",
    "recovery",
    "provider",
    "agent",
    "runtime",
];

/// Baked-in workspace manifest used by [`default_members_guard`].
const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");

/// Baked-in facade manifest used by [`assert_no_new_ownership`].
const FACADE_MANIFEST: &str = include_str!("../Cargo.toml");

/// Baked-in facade entry point used by [`assert_no_new_ownership`].
const FACADE_MAIN: &str = include_str!("main.rs");

/// The facade's production dependency set at the issue #18 revision.
///
/// A frozen reference, not a live claim: the guard reads the real dependency
/// list out of [`FACADE_MANIFEST`] and fails on any difference in either
/// direction, so gaining a dependency cannot pass unnoticed.
const FROZEN_FACADE_DEPENDENCIES: &[&str] = &[
    "anyhow",
    "blake3",
    "clap",
    "eliot-agent-bridge-core",
    "eliot-engine",
    "eliot-runtime-contracts",
    "eliot-store",
    "eliot-types",
    "jsonc-parser",
    "serde",
    "serde_json",
    "sha2",
    "time",
    "tokio",
    "toml",
    "tracing",
    "tracing-subscriber",
    "uuid",
    "eliot-windows-ipc",
    "windows-service",
];

/// The facade's top-level `Command` variants at the issue #18 revision.
///
/// Frozen reference only. The live side is parsed out of the baked
/// [`FACADE_MAIN`] command tree, never hand-listed by the guard.
const FROZEN_FACADE_COMMANDS: &[&str] = &[
    "Dogfood",
    "Doctor",
    "DataRoot",
    "Backup",
    "Restore",
    "Export",
    "Import",
    "Blob",
    "Cutover",
    "Maintenance",
    "Incident",
    "Daemon",
    "Service",
    "Ipc",
    "Credentials",
    "Security",
    "Readiness",
    "StartupRecovery",
    "Db",
    "Writer",
    "Memory",
    "MemoryLifecycle",
    "Skill",
    "SkillCurator",
    "Graph",
    "Ul",
    "Codecortex",
    "ExternalReview",
    "Delegate",
    "DelegationCalibration",
    "Antigravity",
    "Eval",
    "Verify",
    "Metrics",
    "Trace",
    "Replay",
    "Sleep",
    "Dream",
    "Action",
    "Patch",
    "Work",
    "Worktree",
    "Blackboard",
    "Mailbox",
    "Recovery",
    "Legacy",
    "Collective",
    "Runtime",
    "Module",
    "Logs",
    "Adapter",
    "Verifier",
    "Hook",
    "Mcp",
    "Host",
    "ExternalAgent",
    "CognitiveField",
];

/// Facade dependencies that already carried a forbidden owner word at the
/// issue #18 revision.
///
/// Grandfathered legacy edges, tracked by their own dispositions. The
/// grandfather is per name, not per owner word, so a *new* `eliot-store-api`
/// is still refused even though `eliot-store` is grandfathered. The guard
/// requires this list to equal the owner names the baked manifest actually
/// produces, so it can neither grow to admit a new owner nor shrink to hide
/// one.
const PRE_ISSUE_18_DEPENDENCY_OWNER_NAMES: &[&str] = &[
    "eliot-agent-bridge-core",
    "eliot-runtime-contracts",
    "eliot-store",
];

/// Facade commands that already carried a forbidden owner word at the issue
/// #18 revision. Bounded and checked exactly like the dependency list.
const PRE_ISSUE_18_COMMAND_OWNER_NAMES: &[&str] = &[
    "ExternalAgent",
    "Memory",
    "MemoryLifecycle",
    "Module",
    "Recovery",
    "Runtime",
    "StartupRecovery",
];

/// Issue #18 inventory revision date.
///
/// A [`Disposition::TemporaryFixture`] whose dated removal condition is not
/// strictly later than this date has already outlived its own deadline, and
/// the guard says so instead of accepting the fixture as current.
const INVENTORY_REVISION: &str = "2026-09-25";

/// Live callers of the facade: plugin hooks, MCP registrations, host
/// integrations, install routes, staged release payloads, and operator
/// instructions. Every row cites a baked [`CONSUMER_SURFACES`] path.
pub fn current_consumer_inventory() -> &'static [ConsumerEntry] {
    &[
        ConsumerEntry {
            consumer: "Codex plugin lifecycle hooks",
            proof: "plugin/eliot-governor/hooks/hooks.json",
            live_reference: "${PLUGIN_ROOT}\\\\bin\\\\eliot-governor.exe",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when hooks route through bins/eliot-agent-bridge and crates/surfaces/* under #13",
        },
        ConsumerEntry {
            consumer: "Claude Code plugin lifecycle hooks",
            proof: "integrations/claude/eliot/hooks/hooks.json",
            live_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when hooks route through bins/eliot-agent-bridge and crates/surfaces/* under #13",
        },
        ConsumerEntry {
            consumer: "OpenCode MCP server registration",
            proof: "integrations/opencode/opencode.json",
            live_reference: "\"{env:ELIOT_GOVERNOR_EXE}\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the OpenCode MCP command resolves to bins/eliot-agent-bridge under #13",
        },
        ConsumerEntry {
            consumer: "Codex plugin install route",
            proof: "integrations/codex/marketplace.json",
            live_reference: "\"installation\": \"INSTALLED_BY_DEFAULT\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the default-installed Codex plugin is a current root plugin under #13",
        },
        ConsumerEntry {
            consumer: "Codex plugin identity manifest",
            proof: "plugin/eliot-governor/.codex-plugin/plugin.json",
            live_reference: "\"name\": \"eliot-governor\"",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove with the Codex Governor plugin subtree after accepted #18 consumer and retirement evidence under #1719",
        },
        ConsumerEntry {
            consumer: "OpenCode host integration",
            proof: "integrations/opencode/plugins/eliot.js",
            live_reference: "host-integrations/opencode/bin/eliot-governor.exe",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when OpenCode resolves its governor executable to a current root binary under #13",
        },
        ConsumerEntry {
            consumer: "Windows x64 release bundle staging",
            proof: "scripts/build-eliot-windows-x64-release.ps1",
            live_reference: "integrations/codex/plugins/eliot-governor/bin/eliot-governor.exe",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the release bundle no longer stages eliot-governor.exe at root or plugin bin",
        },
        ConsumerEntry {
            consumer: "Claude Desktop MCPB package staging",
            proof: "scripts/build-claude-desktop-extension.ps1",
            live_reference: "server\\eliot-governor.exe",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the packaged MCPB server is a current root binary under #11",
        },
        ConsumerEntry {
            consumer: "Operator credential runbook",
            proof: "docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md",
            live_reference: "eliot-governor --config",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the runbook targets bins/eliot under #11",
        },
        ConsumerEntry {
            consumer: "Claude Desktop operator guide",
            proof: "docs/integrations/claude/CLAUDE_DESKTOP_MCPB.md",
            live_reference: "server/eliot-governor.exe mcp stdio",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the guide targets the current root server binary under #11",
        },
        ConsumerEntry {
            consumer: "Claude Code operator guide",
            proof: "docs/integrations/claude/CLAUDE_CODE_PLUGIN.md",
            live_reference: "${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the guide documents the agent-bridge front door under #13",
        },
        ConsumerEntry {
            consumer: "Claude plugin operator README",
            proof: "integrations/claude/eliot/README.md",
            live_reference: "eliot-governor host install --host claude",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when installation is documented through bins/eliot under #11",
        },
        ConsumerEntry {
            consumer: "OpenCode operator README",
            proof: "integrations/opencode/README.md",
            live_reference: "eliot-governor host install --host opencode",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when installation is documented through bins/eliot under #11",
        },
        ConsumerEntry {
            consumer: "Windows x64 release retention record",
            proof: "docs/release/WINDOWS_X64_RELEASE.md",
            live_reference: "the Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the retained legacy entry points are deleted under #18",
        },
        ConsumerEntry {
            consumer: "Agent host-bundle Codex plugin staging",
            proof: "integrations/agent-runtimes/host-bundle.manifest.json",
            live_reference: "\"destination_hint\": \"CODEX_HOME/plugins/eliot-governor\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when host-bundle staging installs the current root plugin route under #13",
        },
        ConsumerEntry {
            consumer: "Codex route-profile plugin surfaces",
            proof: "integrations/codex/route-profile.json",
            live_reference: "\"path\": \"plugin/eliot-governor/.mcp.json\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the codex route profile names current-owner surfaces under #13",
        },
        ConsumerEntry {
            consumer: "Claude connector install-layout test",
            proof: "scripts/test-claude-connector.ps1",
            live_reference: "'release\\eliot-governor.exe'",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when connector tests target the current root server binary under #11",
        },
        ConsumerEntry {
            consumer: "Claude Desktop package build instructions",
            proof: "integrations/claude/claude-desktop/README.md",
            live_reference: "cargo build --release -p eliot-app",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the package instructions build and stage the current owner server under #11/#18",
        },
        ConsumerEntry {
            consumer: "Claude Desktop MCPB package instructions",
            proof: "integrations/claude/claude-desktop/mcpb/README.md",
            live_reference: "`eliot-governor.exe`",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the MCPB guide names only the current owner server under #11/#18",
        },
        ConsumerEntry {
            consumer: "Legacy UL cross-agent reference MCP client",
            proof: "scripts/eliot-mcp-reference-client.ps1",
            live_reference: "'codex_controller'",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove when the UL runner and codex_controller profile use the admitted current MCP owner under #18 and its owner track",
        },
        ConsumerEntry {
            consumer: "OpenCode legacy executable fallback fixture",
            proof: "integrations/opencode/tests/eliot-plugin.test.mjs",
            live_reference: "process.env.ELIOT_GOVERNOR_EXE",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove when the OpenCode integration no longer accepts the legacy executable fallback under #18",
        },
        ConsumerEntry {
            consumer: "Windows x64 live signing retained-Governor fixture",
            proof: "tests/release-security/trusted-cli-live-signing-tests.ps1",
            live_reference: "eliot-governor.exe",
            disposition: Disposition::TemporaryFixture,
            expiry: "update after #18 admits retirement so the signing fixture matches the selected bundle denominator",
        },
        ConsumerEntry {
            consumer: "Operator compatibility query contract",
            proof: "apps/Eliot.Operator/Protocol/OperatorContracts.cs",
            live_reference: "crates/eliot-app/src/mcp_stdio/catalog.rs",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when LegacyOperatorAdapter consumes the current query contract without the facade MCP catalog under #18",
        },
        ConsumerEntry {
            consumer: "Operator compatibility mutation contract",
            proof: "apps/Eliot.Operator/Protocol/OperatorIntent.cs",
            live_reference: "crates/eliot-app/src/mcp_stdio.rs",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when LegacyOperatorAdapter uses the current typed Operator-intent route without facade MCP dispatch under #18",
        },
        ConsumerEntry {
            consumer: "Operator compatibility response contract",
            proof: "apps/Eliot.Operator/Protocol/OperatorResponseBounds.cs",
            live_reference: "crates/eliot-app/src/mcp_stdio/operator.rs",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when Operator response bounds are verified against the current owner contract without facade emissions under #18",
        },
        ConsumerEntry {
            consumer: "Operator LegacyOperatorAdapter",
            proof: "apps/Eliot.Operator/README.md",
            live_reference: "The `eliot_operator_*` tools are served by `crates/eliot-app`",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the adapter is replaced by current ControlBoard/runtime-status reads and typed intent writes under #18",
        },
        ConsumerEntry {
            consumer: "Operator legacy-contract regression fixture",
            proof: "tests/Eliot.Operator.Tests/Program.cs",
            live_reference: "crates/eliot-app/src/mcp_stdio/operator.rs",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove after the Operator adapter test asserts the current owner contract and no longer references facade output under #18",
        },
    ]
}

/// One consumer edge migrated off the facade to its declared current owner
/// (issue #18 W11/W12/A9).
///
/// `proof` is the migrated file, baked above with `include_str!`.
/// `legacy_reference` is the retired legacy invocation and must be absent
/// from `proof`; `current_owner_reference` is the current-owner route text
/// and must be present. `evidence` records how the migration was performed.
pub struct MigratedConsumerEdge {
    /// Named calling surface, never a bare command name.
    pub consumer: &'static str,
    /// Migrated repository path that proves the current-owner edge.
    pub proof: &'static str,
    /// Retired legacy invocation text that must be gone from `proof`.
    pub legacy_reference: &'static str,
    /// Current-owner route text that must be present in `proof`.
    pub current_owner_reference: &'static str,
    /// Declared current owner binary/crate serving this edge.
    pub current_owner: &'static str,
    /// How the migration was performed.
    pub evidence: &'static str,
}

/// Consumer edges already migrated off the facade, with evidence.
///
/// A migrated file is no longer a [`CONSUMER_SURFACES`] surface and carries
/// no inventory entry: both tables prove liveness of the legacy binary, so a
/// migrated edge in either would fail its guard. [`migrated_edge_guard`]
/// proves instead that the legacy invocation stays gone and the
/// current-owner route stays live.
pub const MIGRATED_CONSUMER_EDGES: &[MigratedConsumerEdge] = &[
    MigratedConsumerEdge {
        consumer: "Codex plugin MCP server",
        proof: "plugin/eliot-governor/.mcp.json",
        legacy_reference: "\"command\": \"bin/eliot-governor.exe\"",
        current_owner_reference: "\"command\": \"bin/eliot-agent-bridge.exe\"",
        current_owner: "bins/eliot-agent-bridge (codex_controller MCP access edge; scope/capability admission in cli_contract)",
        evidence: "bridge argv mcp --profile codex_controller --transport stdio --client-declaration <installation-owned agent-bridge/client-declaration-v2.json>; profile/scope gate ported from crates/eliot-app/src/mcp_stdio.rs and reached by that argv; served on the admitted SPINE_FUNCTIONAL contour through the Kernel front door",
    },
    MigratedConsumerEdge {
        consumer: "Claude Desktop MCPB server entry point",
        proof: "integrations/claude/claude-desktop/mcpb/manifest.json",
        legacy_reference: "\"entry_point\": \"server/eliot-governor.exe\"",
        current_owner_reference: "\"entry_point\": \"server/eliot-agent-bridge.exe\"",
        current_owner: "bins/eliot-agent-bridge (SPINE_FUNCTIONAL contour)",
        evidence: "bridge argv mcp --profile SPINE_FUNCTIONAL --transport stdio --client-declaration <installation-owned agent-bridge/client-declaration-v2.json>; the admitted contour the delegated Claude/OpenCode host edges already use",
    },
    MigratedConsumerEdge {
        consumer: "Claude Code plugin MCP server",
        proof: "integrations/claude/eliot/.mcp.json",
        legacy_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
        current_owner_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-agent-bridge.exe\"",
        current_owner: "bins/eliot-agent-bridge (SPINE_FUNCTIONAL contour)",
        evidence: "bridge argv mcp --profile SPINE_FUNCTIONAL --transport stdio --client-declaration <installation-owned agent-bridge/client-declaration-v2.json>; the admitted contour the facade's unconditional Bridge redirect already serves for the claude host (crates/eliot-app/src/main.rs::delegate_host_mcp_to_agent_bridge); served through the Kernel front door with no Governor, Store, WAL, or writer construction",
    },
];

/// Baked bytes of a migrated edge proof.
fn migrated_proof_body(path: &str) -> Option<&'static str> {
    match path {
        "plugin/eliot-governor/.mcp.json" => Some(CODEX_PLUGIN_MCP),
        "integrations/claude/claude-desktop/mcpb/manifest.json" => Some(CLAUDE_DESKTOP_MCPB),
        "integrations/claude/eliot/.mcp.json" => Some(CLAUDE_PLUGIN_MCP),
        _ => None,
    }
}

/// Fail when a migrated edge regresses: the baked proof still names the
/// legacy invocation, no longer names the current-owner route, names an
/// unbaked proof, or the row is missing consumer, proof, references, owner,
/// or evidence.
pub fn migrated_edge_guard() -> Result<(), String> {
    if MIGRATED_CONSUMER_EDGES.is_empty() {
        return Err(
            "no migrated consumer edge is recorded; the migration guard is blind".to_owned(),
        );
    }
    for edge in MIGRATED_CONSUMER_EDGES {
        if edge.consumer.is_empty()
            || edge.proof.is_empty()
            || edge.legacy_reference.is_empty()
            || edge.current_owner_reference.is_empty()
            || edge.current_owner.is_empty()
            || edge.evidence.is_empty()
        {
            return Err(
                "migrated consumer edge is missing consumer, proof, references, owner, or evidence"
                    .to_owned(),
            );
        }
        let Some(body) = migrated_proof_body(edge.proof) else {
            return Err(format!(
                "migrated consumer edge proof {} is not a baked migrated file",
                edge.proof
            ));
        };
        if body.contains(edge.legacy_reference) {
            return Err(format!(
                "migrated consumer edge {} still names the legacy invocation {:?}",
                edge.proof, edge.legacy_reference
            ));
        }
        if !body.contains(edge.current_owner_reference) {
            return Err(format!(
                "migrated consumer edge {} no longer names its current-owner route {:?}; the migration regressed or the proof is wrong",
                edge.proof, edge.current_owner_reference
            ));
        }
    }
    Ok(())
}

/// Fail when a baked consumer surface no longer contains its recorded live
/// reference, when a baked surface that still reaches the legacy binary has
/// no inventory entry, when a retained path carries two dispositions, or when
/// an inventory proof is not one of the baked surfaces.
pub fn consumer_disposition_guard() -> Result<(), String> {
    if CONSUMER_SURFACES.is_empty() {
        return Err("no facade consumer surface is baked; the inventory guard is blind".to_owned());
    }
    for surface in CONSUMER_SURFACES {
        if !surface.body.contains(surface.live_reference) {
            return Err(format!(
                "baked facade consumer surface {} no longer contains its recorded live reference {:?}",
                surface.path, surface.live_reference
            ));
        }
        let recorded = inventory_entries_for(surface.path);
        let Some(entry) = recorded.first() else {
            return Err(format!(
                "baked facade consumer surface {} still reaches the legacy binary through {:?} but has no inventory entry",
                surface.path, surface.live_reference
            ));
        };
        if recorded.len() > 1 {
            return Err(format!(
                "retained path {} carries {} dispositions; exactly one disposition per retained path is required",
                surface.path,
                recorded.len()
            ));
        }
        if entry.live_reference != surface.live_reference {
            return Err(format!(
                "inventory entry for {} records live reference {:?} but the baked surface records {:?}",
                surface.path, entry.live_reference, surface.live_reference
            ));
        }
    }
    for entry in current_consumer_inventory() {
        if baked_surface(entry.proof).is_none() {
            return Err(format!(
                "inventory proof {} is not one of the baked facade consumer surfaces",
                entry.proof
            ));
        }
    }
    Ok(())
}

/// Fail when the inventory names no caller, when a recorded live reference is
/// missing, or when a recorded disposition contradicts the liveness its own
/// proof shows.
fn assert_inventory_entries_are_live() -> Result<(), String> {
    let inventory = current_consumer_inventory();
    if inventory.is_empty() {
        return Err("facade disposition inventory is empty".to_owned());
    }
    for entry in inventory {
        if entry.consumer.is_empty() || entry.proof.is_empty() || entry.expiry.is_empty() {
            return Err("facade inventory entry is missing consumer, proof, or expiry".to_owned());
        }
        if entry.live_reference.is_empty() {
            return Err(format!(
                "facade inventory entry {} records no live reference",
                entry.proof
            ));
        }
        let live = baked_surface(entry.proof)
            .is_some_and(|surface| surface.body.contains(entry.live_reference));
        if entry.disposition == Disposition::Remove && live {
            return Err(format!(
                "recorded removal of {} has not happened: the file still contains the legacy invocation {:?}",
                entry.proof, entry.live_reference
            ));
        }
        if entry.disposition != Disposition::Remove && !live {
            return Err(format!(
                "recorded {} for {} is not backed by its proof: {:?} is absent from that file, so the edge migrated or the proof is wrong",
                entry.disposition.label(),
                entry.proof,
                entry.live_reference
            ));
        }
    }
    Ok(())
}

/// Inventory rows citing `path`.
fn inventory_entries_for(path: &str) -> Vec<&'static ConsumerEntry> {
    current_consumer_inventory()
        .iter()
        .filter(|entry| entry.proof == path)
        .collect()
}

/// The baked surface recorded for `path`, if that surface is declared.
fn baked_surface(path: &str) -> Option<&'static ConsumerSurface> {
    CONSUMER_SURFACES
        .iter()
        .find(|surface| surface.path == path)
}

/// Fail when a [`Disposition::TemporaryFixture`] has no dated removal
/// condition, or when that condition is not strictly later than
/// [`INVENTORY_REVISION`], which means the fixture outlived its own deadline.
pub fn expiry_condition_guard() -> Result<(), String> {
    let Some(revision) = first_iso_date_digits(INVENTORY_REVISION) else {
        return Err("inventory revision constant is not an ISO date".to_owned());
    };
    for entry in current_consumer_inventory() {
        if entry.disposition != Disposition::TemporaryFixture {
            continue;
        }
        if !entry.expiry.to_ascii_lowercase().contains("remove") {
            return Err(format!(
                "temporary fixture {} records no removal condition in {:?}",
                entry.proof, entry.expiry
            ));
        }
        let Some(expiry_date) = first_iso_date_digits(entry.expiry) else {
            return Err(format!(
                "temporary fixture {} records no YYYY-MM-DD removal date in {:?}",
                entry.proof, entry.expiry
            ));
        };
        if expiry_date <= revision {
            return Err(format!(
                "temporary fixture {} expired on {}; record the removal or give it a condition later than {}",
                entry.proof,
                iso_date_text(expiry_date),
                INVENTORY_REVISION
            ));
        }
    }
    Ok(())
}

/// Digits of the first `YYYY-MM-DD` token in `text`.
fn first_iso_date_digits(text: &str) -> Option<[u8; 8]> {
    let bytes = text.as_bytes();
    for start in 0..bytes.len().saturating_sub(9) {
        let Some(window) = bytes.get(start..start + 10) else {
            break;
        };
        if let [
            year0,
            year1,
            year2,
            year3,
            b'-',
            month0,
            month1,
            b'-',
            day0,
            day1,
        ] = *window
        {
            let digits = [year0, year1, year2, year3, month0, month1, day0, day1];
            if digits.iter().all(u8::is_ascii_digit) {
                return Some(digits.map(|digit| digit - b'0'));
            }
        }
    }
    None
}

/// Readable `YYYY-MM-DD` form of eight date digits.
fn iso_date_text(digits: [u8; 8]) -> String {
    let text: String = digits
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    format!("{}-{}-{}", &text[0..4], &text[4..6], &text[6..8])
}

/// Fail when `FORBIDDEN_OWNER_SYMBOLS` is empty, when the grandfathered
/// pre-issue-18 owner names no longer describe the real facade, or when a
/// facade dependency or a facade command carries a forbidden owner word under
/// a name the facade did not already use at the issue #18 revision.
pub fn assert_no_new_ownership() -> Result<(), String> {
    if FORBIDDEN_OWNER_SYMBOLS.is_empty() {
        return Err("forbidden owner symbol list is empty; ownership guard is blind".to_owned());
    }
    let dependencies = facade_dependency_names()?;
    let commands = facade_command_variants()?;
    require_same_set(
        "pre-issue-18 facade dependency owner name",
        &owner_names_in(&dependencies),
        PRE_ISSUE_18_DEPENDENCY_OWNER_NAMES,
    )?;
    require_same_set(
        "pre-issue-18 facade command owner name",
        &owner_names_in(&commands),
        PRE_ISSUE_18_COMMAND_OWNER_NAMES,
    )?;
    for name in &dependencies {
        if let Some(word) = new_owner_word(name, PRE_ISSUE_18_DEPENDENCY_OWNER_NAMES) {
            return Err(format!(
                "facade dependency {name} is a new {word} owner; the facade must not gain task, memory, policy, finish, coordination, scheduling, Module, store, recovery, provider, agent, or runtime ownership"
            ));
        }
    }
    for name in &commands {
        if let Some(word) = new_owner_word(name, PRE_ISSUE_18_COMMAND_OWNER_NAMES) {
            return Err(format!(
                "facade command {name} is a new {word} owner; a new public command must not become a task, memory, policy, finish, coordination, scheduling, Module, store, recovery, provider, agent, or runtime owner"
            ));
        }
    }
    Ok(())
}

/// Fail when the facade's real dependency list or its real command tree
/// differs from the frozen issue #18 baseline, or when either carries a
/// forbidden owner word. This is what makes a new facade ownership edge (W10)
/// and a new public command (A10) detectable.
pub fn facade_surface_guard() -> Result<(), String> {
    require_same_set(
        "facade dependency",
        &facade_dependency_names()?,
        FROZEN_FACADE_DEPENDENCIES,
    )?;
    require_same_set(
        "facade command",
        &facade_command_variants()?,
        FROZEN_FACADE_COMMANDS,
    )?;
    assert_no_new_ownership()
}

/// Fail when `observed` and `baseline` are not the same set of names.
fn require_same_set(
    subject: &str,
    observed: &[&'static str],
    baseline: &[&'static str],
) -> Result<(), String> {
    for name in observed {
        if !baseline.contains(name) {
            return Err(format!(
                "{subject} {name} is not in the frozen issue #18 baseline; a new {subject} is new facade ownership or new public surface"
            ));
        }
    }
    for name in baseline {
        if !observed.contains(name) {
            return Err(format!(
                "frozen issue #18 baseline records {subject} {name}, which the facade no longer declares"
            ));
        }
    }
    Ok(())
}

/// The facade names that carry a forbidden owner word, deduplicated and in
/// observed order.
fn owner_names_in(names: &[&'static str]) -> Vec<&'static str> {
    let mut owners: Vec<&'static str> = Vec::new();
    for name in names {
        if carries_owner_word(name) && !owners.contains(name) {
            owners.push(name);
        }
    }
    owners
}

/// The first forbidden owner word `name` carries.
///
/// `pre_issue_18` grandfather is per name, so a new `eliot-store-api` is still
/// refused even though the pre-issue-18 `eliot-store` is grandfathered.
fn new_owner_word(name: &str, pre_issue_18: &[&'static str]) -> Option<&'static str> {
    if pre_issue_18.contains(&name) {
        return None;
    }
    FORBIDDEN_OWNER_SYMBOLS
        .iter()
        .copied()
        .find(|symbol| owner_word_present(name, symbol))
}

/// True when `name` carries at least one forbidden owner word.
fn carries_owner_word(name: &str) -> bool {
    FORBIDDEN_OWNER_SYMBOLS
        .iter()
        .any(|symbol| owner_word_present(name, symbol))
}

/// True when `symbol` is an owner word of `name`.
///
/// Both sides are split on separators and case humps, so `Restore` is not a
/// `store` owner while `MemoryLifecycle` is a `memory` owner and
/// `eliot-workscope` is a `WorkScope` owner. This keeps the forbidden list an
/// owner-word list instead of an accidental substring list.
fn owner_word_present(name: &str, symbol: &str) -> bool {
    let name_words = owner_words(name);
    let symbol_words = owner_words(symbol);
    if name_words.is_empty() || symbol_words.is_empty() {
        return false;
    }
    if contains_run(&name_words, &symbol_words) {
        return true;
    }
    let joined = symbol_words.concat();
    name_words.contains(&joined)
}

/// Lowercase comparable words of `text`, split on separators and case humps.
fn owner_words(text: &str) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    for (index, character) in characters.iter().enumerate() {
        if *character == '-' || *character == '_' || character.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        if starts_new_word(&characters, index) && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// True when `characters[index]` begins a new word.
fn starts_new_word(characters: &[char], index: usize) -> bool {
    if !characters[index].is_ascii_uppercase() {
        return false;
    }
    let previous = index
        .checked_sub(1)
        .and_then(|before| characters.get(before));
    let next = characters.get(index + 1);
    match previous {
        Some(last) if last.is_ascii_lowercase() || last.is_ascii_digit() => true,
        Some(last) if last.is_ascii_uppercase() => next.is_some_and(char::is_ascii_lowercase),
        _ => false,
    }
}

/// True when `words` occurs in `haystack` as one adjacent run.
fn contains_run(haystack: &[String], words: &[String]) -> bool {
    if words.is_empty() || words.len() > haystack.len() {
        return false;
    }
    haystack.windows(words.len()).any(|window| window == words)
}

/// Production dependency names read out of the baked facade manifest.
///
/// Dev-dependencies are deliberately excluded: a test-only edge is not facade
/// runtime ownership.
fn facade_dependency_names() -> Result<Vec<&'static str>, String> {
    const SECTIONS: [&str; 2] = ["[dependencies]", "[target.'cfg(windows)'.dependencies]"];
    let mut names: Vec<&'static str> = Vec::new();
    for section in SECTIONS {
        let start = FACADE_MANIFEST
            .find(section)
            .ok_or_else(|| format!("facade Cargo.toml has no {section} section"))?;
        let body = manifest_section_body(&FACADE_MANIFEST[start + section.len()..])?;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((declared, _)) = line.split_once('=') else {
                return Err(format!(
                    "facade Cargo.toml dependency line is not `name = value`: {line}"
                ));
            };
            // Cargo accepts both `name = value` and the dotted `name.workspace`.
            let name = declared.split('.').next().unwrap_or_default().trim();
            if name.is_empty()
                || !name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
            {
                return Err(format!(
                    "facade Cargo.toml dependency does not declare a bare name: {line}"
                ));
            }
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if names.is_empty() {
        return Err(
            "facade Cargo.toml declares no dependency; ownership guard is blind".to_owned(),
        );
    }
    Ok(names)
}

/// Text of the dependency section that follows `rest`, exclusive of the next
/// section header. Fails closed when the manifest is malformed.
fn manifest_section_body(rest: &'static str) -> Result<&'static str, String> {
    let open = rest.find("\n[").ok_or_else(|| {
        "facade Cargo.toml dependency section is malformed; no section follows".to_owned()
    })?;
    Ok(&rest[..=open])
}

/// Top-level `enum Command` variants read out of the baked facade entry
/// point, in declaration order.
fn facade_command_variants() -> Result<Vec<&'static str>, String> {
    const HEADER: &str = "enum Command {";
    let start = FACADE_MAIN.find(HEADER).ok_or_else(|| {
        "facade main.rs declares no `enum Command`; surface guard is blind".to_owned()
    })?;
    let body = &FACADE_MAIN[start + HEADER.len()..];
    let close = body.find("\n}").ok_or_else(|| {
        "facade main.rs `enum Command` is not closed; surface guard is blind".to_owned()
    })?;
    let mut variants: Vec<&'static str> = Vec::new();
    for line in body[..close].lines() {
        if !is_variant_level_line(line) || is_variant_continuation(line) {
            continue;
        }
        let Some(name) = command_variant_name(line) else {
            return Err(format!(
                "facade main.rs `enum Command` declares a variant this guard cannot name, so the surface guard would be blind to it: {}",
                line.trim()
            ));
        };
        if variants.contains(&name) {
            return Err(format!(
                "facade main.rs `enum Command` declares {name} twice"
            ));
        }
        variants.push(name);
    }
    if variants.is_empty() {
        return Err(
            "facade main.rs `enum Command` declares no variant; surface guard is blind".to_owned(),
        );
    }
    Ok(variants)
}

/// True when `line` sits at exactly the variant level of `enum Command`.
fn is_variant_level_line(line: &str) -> bool {
    match line.strip_prefix("    ") {
        Some(rest) => !rest.is_empty() && !rest.starts_with(' '),
        None => false,
    }
}

/// True when `line` continues a variant instead of declaring one.
fn is_variant_continuation(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with('}') || trimmed.starts_with('#') || trimmed.starts_with("//")
}

/// The `Command` variant name a source line declares, if it declares one.
fn command_variant_name(line: &'static str) -> Option<&'static str> {
    let rest = line.strip_prefix("    ")?;
    if !rest.starts_with(|character: char| character.is_ascii_uppercase()) {
        return None;
    }
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

/// Fail when `crates/eliot-app` is back in the root `default-members` set.
/// The facade must stay out of the default build; absence of the section
/// also fails closed.
pub fn default_members_guard() -> Result<(), String> {
    let marker = "default-members";
    let start = WORKSPACE_MANIFEST
        .find(marker)
        .ok_or_else(|| "root Cargo.toml has no default-members section".to_owned())?;
    let rest = &WORKSPACE_MANIFEST[start + marker.len()..];
    let open = rest
        .find('[')
        .ok_or_else(|| "root Cargo.toml default-members section is malformed".to_owned())?;
    let after = &rest[open..];
    let close = after
        .find(']')
        .ok_or_else(|| "root Cargo.toml default-members section is malformed".to_owned())?;
    let members = &after[..close];
    if members.contains("eliot-app") {
        return Err(
            "crates/eliot-app must not be in root default-members; facade is not a production root"
                .to_owned(),
        );
    }
    Ok(())
}

/// Run every facade disposition guard before command dispatch. Any failure
/// aborts startup; the caller converts `Err` into a non-zero exit.
pub fn run_facade_disposition_guards() -> Result<(), String> {
    default_members_guard()?;
    consumer_disposition_guard()?;
    assert_inventory_entries_are_live()?;
    migrated_edge_guard()?;
    expiry_condition_guard()?;
    facade_surface_guard()?;
    crate::cell_declaration_registry::cell_declaration_guard()?;
    Ok(())
}
