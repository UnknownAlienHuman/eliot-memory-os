import io

ROOT = r'C:\Development\Rust\projects\eliot-swarm\MC-18'
p = ROOT + r'\crates\eliot-app\src\disposition.rs'
t = io.open(p, encoding='utf-8').read()
assert '\r' not in t

s1 = '''    ConsumerSurface {
        path: "plugin/eliot-governor/.mcp.json",
        live_reference: "\\"command\\": \\"bin/eliot-governor.exe\\"",
        body: CODEX_PLUGIN_MCP,
    },
'''
assert t.count(s1) == 1, 'surface codex'
t = t.replace(s1, '')

s2 = '''    ConsumerSurface {
        path: "integrations/claude/claude-desktop/mcpb/manifest.json",
        live_reference: "\\"entry_point\\": \\"server/eliot-governor.exe\\"",
        body: CLAUDE_DESKTOP_MCPB,
    },
'''
assert t.count(s2) == 1, 'surface mcpb'
t = t.replace(s2, '')

i1 = '''        ConsumerEntry {
            consumer: "Codex plugin MCP server",
            proof: "plugin/eliot-governor/.mcp.json",
            live_reference: "\\"command\\": \\"bin/eliot-governor.exe\\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the Codex MCP server is served by the eliot-mcp track entry point (codex_controller has no Bridge contour and is refused at the facade gate per crates/eliot-app/src/main.rs; bins/eliot-agent-bridge under #13 is not the owner)",
        },
'''
assert t.count(i1) == 1, 'inventory codex'
t = t.replace(i1, '')

i2 = '''        ConsumerEntry {
            consumer: "Claude Desktop MCPB server entry point",
            proof: "integrations/claude/claude-desktop/mcpb/manifest.json",
            live_reference: "\\"entry_point\\": \\"server/eliot-governor.exe\\"",
            disposition: Disposition::ExtractToCurrentOwner,
            expiry: "remove when the packaged server entry point is a current root binary under #11",
        },
'''
assert t.count(i2) == 1, 'inventory mcpb'
t = t.replace(i2, '')

anchor = '''/// Fail when a baked consumer surface no longer contains its recorded live
/// reference, when a baked surface that still reaches the legacy binary has
/// no inventory entry, when a retained path carries two dispositions, or when
/// an inventory proof is not one of the baked surfaces.
pub fn consumer_disposition_guard() -> Result<(), String> {'''

table = '''/// One consumer edge migrated off the facade to its declared current owner
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
        legacy_reference: "\\"command\\": \\"bin/eliot-governor.exe\\"",
        current_owner_reference: "\\"command\\": \\"bin/eliot-agent-bridge.exe\\"",
        current_owner: "bins/eliot-agent-bridge (codex_controller MCP access edge; scope/capability admission in cli_contract)",
        evidence: "bridge argv mcp --profile codex_controller --transport stdio --client-declaration <installation-owned agent-bridge/client-declaration-v2.json>; profile/scope gate ported from crates/eliot-app/src/mcp_stdio.rs and reached by that argv; served on the admitted SPINE_FUNCTIONAL contour through the Kernel front door",
    },
    MigratedConsumerEdge {
        consumer: "Claude Desktop MCPB server entry point",
        proof: "integrations/claude/claude-desktop/mcpb/manifest.json",
        legacy_reference: "\\"entry_point\\": \\"server/eliot-governor.exe\\"",
        current_owner_reference: "\\"entry_point\\": \\"server/eliot-agent-bridge.exe\\"",
        current_owner: "bins/eliot-agent-bridge (SPINE_FUNCTIONAL contour)",
        evidence: "bridge argv mcp --profile SPINE_FUNCTIONAL --transport stdio --client-declaration <installation-owned agent-bridge/client-declaration-v2.json>; the admitted contour the delegated Claude/OpenCode host edges already use",
    },
];

/// Baked bytes of a migrated edge proof.
fn migrated_proof_body(path: &str) -> Option<&'static str> {
    match path {
        "plugin/eliot-governor/.mcp.json" => Some(CODEX_PLUGIN_MCP),
        "integrations/claude/claude-desktop/mcpb/manifest.json" => Some(CLAUDE_DESKTOP_MCPB),
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
pub fn consumer_disposition_guard() -> Result<(), String> {'''

assert t.count(anchor) == 1, 'guard anchor'
t = t.replace(anchor, table)

run = '''    default_members_guard()?;
    consumer_disposition_guard()?;
    assert_inventory_entries_are_live()?;
'''
assert t.count(run) == 1, 'runner anchor'
t = t.replace(run, '''    default_members_guard()?;
    consumer_disposition_guard()?;
    assert_inventory_entries_are_live()?;
    migrated_edge_guard()?;
''')

doc = '''//! [`consumer_disposition_guard`] proves the inventory covers exactly that
//! class. A legacy consumer that is *not* named there is outside the detector,'''
assert t.count(doc) == 1, 'doc anchor'
t = t.replace(doc, '''//! [`consumer_disposition_guard`] proves the inventory covers exactly that
//! class. Edges already migrated off the facade leave both tables and are
//! recorded in [`MIGRATED_CONSUMER_EDGES`] instead, guarded by
//! [`migrated_edge_guard`]. A legacy consumer that is *not* named there is outside the detector,''')

io.open(p, 'w', encoding='utf-8', newline='').write(t)
print('disposition patched OK')
