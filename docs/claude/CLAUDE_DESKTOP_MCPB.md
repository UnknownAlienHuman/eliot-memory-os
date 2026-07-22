# Claude Desktop MCPB

Claude Desktop uses the MCPB source under
`integrations/claude/claude-desktop/mcpb`. Its embedded native server runs:

```text
server/eliot-governor.exe mcp stdio --host claude-desktop --instance default
```

The package contains no database, password, provider credential, runtime token,
project data, or Claude Code hooks. It connects to the same Governor authority as
the Code plugin.

## Build and validate

```powershell
cargo build --release --package eliot-app --bin eliot-governor
.\scripts\build-claude-desktop-extension.ps1
```

The script derives the Cargo target directory, generates tools and prompts from
the exact bundled Governor catalog, validates and packs with the MCPB CLI version
pinned in `tool-versions.json`, and writes the package and compatibility receipts
under `%LOCALAPPDATA%\Eliot\packages\claude`.

Installation and activation use Claude Desktop's official extension lifecycle:

```powershell
& $governor host install --host claude-desktop
& $governor host activate --host claude --surface desktop
& $governor host doctor --host claude
```

Do not edit `claude_desktop_config.json`. Desktop mode must stand down the Code
plugin before a Desktop-hosted Claude Code session starts. Desktop has MCP tools,
prompts, and server instructions only; it must never be reported as having hook
enforcement.
