# Claude Desktop MCPB

Claude Desktop uses the MCPB extension source under
`integrations/claude/claude-desktop`. It is separate from the Claude Code plugin
and contains one embedded native stdio facade:

```text
server/eliot-governor.exe mcp stdio --host claude-desktop --instance default
```

The package contains no database password, provider credential, runtime token, or
canonical store. Runtime authentication is resolved from the current ELIOT-owned
per-user publication when the facade starts.

## Build and validate

```powershell
cargo build --release --package eliot-app --bin eliot-governor
.\scripts\build-claude-desktop-extension.ps1
npx --yes @anthropic-ai/mcpb validate .\integrations\claude\claude-desktop\mcpb\manifest.json
.\target\release\eliot-governor.exe host doctor --host claude-desktop
```

Installation must use Claude Desktop's official extension review UI. Do not edit
`claude_desktop_config.json` manually. The Governor writes an install receipt only
after the installed manifest and embedded executable hash match the package.

## Runtime contract

The Desktop facade uses the compact Claude profile. Host identity grants no task
role. Candidate writes remain candidate-only, are idempotent, and require current
project/task scope plus provenance and freshness bounds. Runtime/auth generation
rotation requires reconnection; stale authority is rejected.
