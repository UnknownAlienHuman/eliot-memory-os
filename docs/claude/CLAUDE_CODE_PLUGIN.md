# Claude Code plugin

Claude Code uses the native plugin in `integrations/claude/eliot`. The package
contains four generated ELIOT skills, deterministic hooks, and one MCP server:

```text
${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe mcp stdio --host claude --instance default
```

The plugin does not require the Governor to be on `PATH`. Generated skill copies
must remain byte-identical to `integrations/agent-skills`; `host skill-lint`
enforces that invariant.

## Build, install, and validate

```powershell
cargo build --release --package eliot-app --bin eliot-governor
.\target\release\eliot-governor.exe host install --host claude
.\target\release\eliot-governor.exe host doctor --host claude
claude plugin validate "$env:USERPROFILE\.claude\skills\eliot"
claude mcp list
```

Installation owns only the ELIOT plugin directory and does not inspect provider
credentials or rewrite unrelated Claude settings.

## Authority boundary

Hooks provide compact lifecycle observations and may request or deny work early.
They cannot create a task role, lease, verification run, completion proof, or
canonical memory claim. The compact Claude access profile exposes governed tools
and prompts but omits raw database, credential, shell, patch, provider, and
unconditional completion authority.
