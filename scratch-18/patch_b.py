import io, json

ROOT = r'C:\Development\Rust\projects\eliot-swarm\MC-18'

codex = {
    "mcpServers": {
        "eliot": {
            "type": "stdio",
            "command": "bin/eliot-agent-bridge.exe",
            "cwd": ".",
            "args": [
                "mcp",
                "--profile",
                "codex_controller",
                "--transport",
                "stdio",
                "--client-declaration",
                "${PLUGIN_ROOT}/bin/agent-bridge/client-declaration-v2.json"
            ],
            "enabled": True,
            "required": False
        }
    }
}
p1 = ROOT + r'\plugin\eliot-governor\.mcp.json'
io.open(p1, 'w', encoding='utf-8', newline='').write(json.dumps(codex, indent=2) + '\n')

p2 = ROOT + r'\integrations\claude\claude-desktop\mcpb\manifest.json'
m = json.loads(io.open(p2, encoding='utf-8').read())
assert m['server']['entry_point'] == 'server/eliot-governor.exe', 'precondition legacy entry'
m['description'] = 'Exposes bins/eliot-agent-bridge to Claude Desktop as the local MCP server. Not the production Governor.'
m['long_description'] = (
    'Current-owner server entry point (issue #18): launches '
    'server/eliot-agent-bridge.exe with the documented bridge MCP argv '
    '(mcp --profile SPINE_FUNCTIONAL --transport stdio --client-declaration '
    '<installation-owned agent-bridge/client-declaration-v2.json>), serving the '
    'admitted SPINE_FUNCTIONAL contour through the Kernel front door. The bridge '
    'constructs no Governor, Store, WAL, or writer objects; the client declaration '
    'is installation-owned and re-validated by the bridge (digest plus live Kernel '
    'challenge) before serving. Tools and prompts ship generated. '
    'Claude identity never grants a permanent role.'
)
del m['_legacy_compatibility']
m['server']['entry_point'] = 'server/eliot-agent-bridge.exe'
m['server']['mcp_config']['command'] = '${__dirname}/server/eliot-agent-bridge.exe'
m['server']['mcp_config']['args'] = [
    'mcp',
    '--profile',
    'SPINE_FUNCTIONAL',
    '--transport',
    'stdio',
    '--client-declaration',
    '${__dirname}/server/agent-bridge/client-declaration-v2.json'
]
io.open(p2, 'w', encoding='utf-8', newline='').write(json.dumps(m, indent=2) + '\n')
print('manifests migrated OK')
