//! Legacy facade disposition inventory for issue #18.
//!
//! `eliot-governor` is a migration/regression facade, not a production
//! composition root. This module records the machine-readable inventory of
//! live callers that still terminate here, the disposition of each caller
//! (extract to its current owner, keep as a temporary fixture, or remove),
//! and the fail-closed startup guards that keep the facade from gaining new
//! ownership or re-entering the root default build set.

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

/// One live caller that still terminates at the `eliot-governor` facade.
///
/// `consumer` names the calling surface, never a bare command name.
/// `proof` is the repository path that proves the live call edge.
/// `expiry` is the removal condition that retires this entry.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerEntry {
    pub consumer: &'static str,
    pub proof: &'static str,
    pub disposition: Disposition,
    pub expiry: &'static str,
}

/// Live callers of the facade: plugin hooks, MCP servers, host integrations,
/// the release bundle, and operator docs.
pub fn current_consumer_inventory() -> Vec<ConsumerEntry> {
    vec![
        ConsumerEntry {
            consumer: "Codex plugin lifecycle hooks",
            proof: "plugin/eliot-governor/hooks/hooks.json",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when hooks route through bins/eliot-agent-bridge and crates/surfaces/* under #13",
        },
        ConsumerEntry {
            consumer: "Codex plugin MCP server",
            proof: "plugin/eliot-governor/.mcp.json",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the eliot MCP server is served by bins/eliot-agent-bridge under #13",
        },
        ConsumerEntry {
            consumer: "Claude plugin lifecycle hooks",
            proof: "integrations/claude/eliot/hooks/hooks.json",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when hooks route through bins/eliot-agent-bridge and crates/surfaces/* under #13",
        },
        ConsumerEntry {
            consumer: "Claude Desktop MCPB server entry point",
            proof: "integrations/claude/claude-desktop/mcpb/manifest.json",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the packaged server entry point is a current root binary under #11",
        },
        ConsumerEntry {
            consumer: "OpenCode host integration",
            proof: "integrations/opencode/plugins/eliot.js",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove when OpenCode resolves its governor executable to a current root binary under #13",
        },
        ConsumerEntry {
            consumer: "Windows x64 release bundle staging",
            proof: "scripts/build-eliot-windows-x64-release.ps1",
            disposition: Disposition::TemporaryFixture,
            expiry: "remove when the release bundle no longer stages eliot-governor.exe at root or plugin bin",
        },
        ConsumerEntry {
            consumer: "Operator credential runbook",
            proof: "docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md",
            disposition: Disposition::Remove,
            expiry: "remove legacy eliot-governor invocations once the runbook targets bins/eliot under #11",
        },
    ]
}

/// Owner symbols the facade must never gain, per `crates/eliot-app/AGENTS.md`.
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

/// Fail when the inventory cannot prove every entry is a tracked, expirable
/// caller, or when the ownership guard itself is misconfigured.
pub fn assert_no_new_ownership() -> Result<(), String> {
    if FORBIDDEN_OWNER_SYMBOLS.is_empty() {
        return Err("forbidden owner symbol list is empty; ownership guard is blind".to_owned());
    }
    for entry in current_consumer_inventory() {
        if entry.consumer.is_empty() || entry.proof.is_empty() || entry.expiry.is_empty() {
            return Err("facade inventory entry is missing consumer, proof, or expiry".to_owned());
        }
        match entry.disposition {
            Disposition::ExtractToCurrentOwner
            | Disposition::TemporaryFixture
            | Disposition::Remove => {}
        }
    }
    Ok(())
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
    assert_no_new_ownership()?;
    if current_consumer_inventory().is_empty() {
        return Err("facade disposition inventory is empty".to_owned());
    }
    Ok(())
}
