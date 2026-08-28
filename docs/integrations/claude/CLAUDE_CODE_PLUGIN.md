# Claude integration architecture

Claude is one logical host family with two generated package surfaces:

- `claude_code_plugin`: official Claude Code plugin with MCP, four skills, and
  semantic lifecycle hooks;
- `claude_desktop_mcpb`: Desktop MCPB with MCP tools, prompts, and instructions,
  but no Claude Code hook capability.

The tracked source of truth is `integrations/claude`. The Governor catalog is the
only tool/prompt metadata authority. Generated plugin artifacts and MCPB packages
live under `%LOCALAPPDATA%\Eliot\packages`, outside the OneDrive repository.

## Claude Code package

`integrations/claude/eliot` has the standard plugin structure:

```text
.claude-plugin/plugin.json
.mcp.json
hooks/hooks.json
skills/
README.md
```

`host install --host claude` stages a deterministic local marketplace, embeds
the exact running `eliot-governor.exe`, and invokes the official non-interactive
`claude plugin marketplace` and `claude plugin install/enable` lifecycle. It does
not copy a plugin into `~/.claude/skills` or edit Claude's internal plugin data.
The official plugin id is `eliot@eliot-local`.

The generated plugin version combines the independent source manifest version,
source bundle hash, and Governor hash. The install receipt records source commit,
artifact hash, installed path/version, Governor SHA-256, and Claude version.

```powershell
$target = cargo metadata --format-version 1 --no-deps |
  ConvertFrom-Json | Select-Object -ExpandProperty target_directory
$governor = Join-Path $target 'release\eliot-governor.exe'

& $governor host install --host claude
& $governor host activate --host claude --surface code
& $governor host doctor --host claude
claude plugin list --json
```

Strict validation is run against the `installPath` returned by
`claude plugin list --json`, never against the retired direct-skills path.

## Exactly one active surface

Code mode enables `eliot@eliot-local` and requires the Desktop MCPB to be
inactive. Desktop mode disables the Code plugin and enables the MCPB through
Claude Desktop's owned lifecycle. The family doctor reports both surfaces,
active count, selected surface, installed hashes, and any duplicate roots or
dual-active conflict. A surface change requires a Claude reload/new session.

## Hook semantics

Eight events are intentionally split by whether they can decide anything:

| Event | Handler | Effect |
|---|---|---|
| `SessionStart` | `hook session-start` | synchronous compact context |
| `PreToolUse` | `hook pre-tool-use` | synchronous governed allow/deny |
| `PreCompact` | `hook pre-compact` | synchronous preservation gate |
| `Stop` | `hook stop` | synchronous FinishGate decision |
| `PostToolUseFailure` | `host event` | asynchronous observation |
| `SubagentStart` | `hook subagent-start` | asynchronous observation |
| `SubagentStop` | `hook subagent-stop` | asynchronous observation |
| `SessionEnd` | `host event` | asynchronous observation |

`PreToolUse` is filtered to `Bash|Edit|Write|NotebookEdit`. Hooks defer when the
session is not attached to an ELIOT task, so unrelated Claude projects are never
blocked. Hooks may enrich or deny early, but cannot create leases, proof, task
roles, completion, or canonical memory claims.

## Validation

`scripts/test-claude-connector.ps1` verifies the selected single surface,
official inventory, strict plugin validation, four skills, eight hooks, MCP
connection, Governor hash parity, catalog parity, and focused protocol tests.
`scripts/build-claude-desktop-extension.ps1` validates and packs with the exact
MCPB CLI version pinned in `tool-versions.json`.
