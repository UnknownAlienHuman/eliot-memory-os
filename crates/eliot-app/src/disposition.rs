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
//! class. A legacy consumer that is *not* named there is outside the detector,
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
const OPENCODE_CONFIG: &str = include_str!("../../../integrations/opencode/opencode.json");
const OPENCODE_PLUGIN: &str = include_str!("../../../integrations/opencode/plugins/eliot.js");
const CODEX_MARKETPLACE: &str = include_str!("../../../integrations/codex/marketplace.json");
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
        path: "plugin/eliot-governor/.mcp.json",
        live_reference: "\"command\": \"bin/eliot-governor.exe\"",
        body: CODEX_PLUGIN_MCP,
    },
    ConsumerSurface {
        path: "integrations/claude/eliot/hooks/hooks.json",
        live_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
        body: CLAUDE_PLUGIN_HOOKS,
    },
    ConsumerSurface {
        path: "integrations/claude/eliot/.mcp.json",
        live_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
        body: CLAUDE_PLUGIN_MCP,
    },
    ConsumerSurface {
        path: "integrations/claude/claude-desktop/mcpb/manifest.json",
        live_reference: "\"entry_point\": \"server/eliot-governor.exe\"",
        body: CLAUDE_DESKTOP_MCPB,
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
        live_reference: "The Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`",
        body: WINDOWS_RELEASE_GUIDE,
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
            consumer: "Codex plugin MCP server",
            proof: "plugin/eliot-governor/.mcp.json",
            live_reference: "\"command\": \"bin/eliot-governor.exe\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the eliot MCP server is served by bins/eliot-agent-bridge under #13",
        },
        ConsumerEntry {
            consumer: "Claude Code plugin lifecycle hooks",
            proof: "integrations/claude/eliot/hooks/hooks.json",
            live_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when hooks route through bins/eliot-agent-bridge and crates/surfaces/* under #13",
        },
        ConsumerEntry {
            consumer: "Claude Code plugin MCP server",
            proof: "integrations/claude/eliot/.mcp.json",
            live_reference: "\"command\": \"${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the MCP server is served by bins/eliot-agent-bridge under #13",
        },
        ConsumerEntry {
            consumer: "Claude Desktop MCPB server entry point",
            proof: "integrations/claude/claude-desktop/mcpb/manifest.json",
            live_reference: "\"entry_point\": \"server/eliot-governor.exe\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the packaged server entry point is a current root binary under #11",
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
            live_reference: "The Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove by 2026-12-31, when the retained legacy entry points are deleted under #18",
        },
    ]
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
    expiry_condition_guard()?;
    facade_surface_guard()?;
    Ok(())
}
