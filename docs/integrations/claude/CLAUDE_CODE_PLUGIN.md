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

## Front-door selection (issue #1719, OSP1 step 1')

Claude Code is the one host that moves off the legacy Governor MCP entry
behind an explicit flag; OpenCode, Claude Desktop, and the Codex plugin keep
their `eliot-governor` entries while the flag is absent. Once
`ELIOT_CLAUDE_FRONT_DOOR=agent-bridge` selects the new stack, every legacy
entrypoint (`daemon run`, `service run`, `hook`, `mcp stdio`) on every host
refuses with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the canonical-route
receipt (gating owned by #1858); the flagged Claude MCP edge is served by
the staged bridge instead, and the flag being absent preserves the legacy
path on all hosts.

- Tracked host config `integrations/claude/eliot/.mcp.json` keeps the legacy
  default byte-identical: one `eliot` server,
  `${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe` with
  `mcp stdio --host claude --instance default`. Hooks in `hooks/hooks.json`
  stay on the Governor binary as well.
- Bundle provisioning: `scripts/build-eliot-windows-x64-release.ps1
  -ClaudeCodeFrontDoor legacy|agent-bridge` (default `legacy`). `legacy`
  stages today's set unchanged; `agent-bridge` additionally builds
  `bins/eliot-agent-bridge` and stages `eliot-agent-bridge.exe` at the
  bundle root, recorded in `PlanOnly` (`claude_code_front_door`),
  `RELEASE.json`, and `STAGED_PAYLOAD_MANIFEST.json`, and enforced by
  bundle verification. A flagged command therefore always exists wherever
  the bundle stages it.
- Operator launch flag: `ELIOT_CLAUDE_FRONT_DOOR=agent-bridge` selects the
  new path at launch; unset (or any other value) means legacy. The flag is
  consumed by entrypoint gating (owned by #1858) and Claude MCP bridge
  delegation (owned by #2562 with the #1858/#77 track), not by this plugin
  tree.
- Full retirement of the legacy Governor entry (Work option 1) or re-home
  of the Codex entry point (Work option 2) does not land in this slice:
  both remain BLOCKED-BY #18 (legacy-deletion owner), and the Codex
  re-home additionally awaits the eliot-mcp behavior track per canon.
- New path argv: `eliot-agent-bridge mcp --profile SPINE_FUNCTIONAL
  --transport stdio --client-declaration <installation-absolute
  path>/agent-bridge/client-declaration-v2.json`. The leading `mcp` token is
  the explicit checked MCP entrypoint contract owned by #2562: it selects
  the MCP JSON-RPC front door, while the tokenless argv keeps serving the
  private `op` stdio clients unchanged. The declaration file is
  installation-owned (absolute path, file name
  `client-declaration-v2.json`, parent directory `agent-bridge`, enforced by
  `bins/eliot-agent-bridge/src/cli_contract.rs`); the bundle and this
  plugin never invent it.

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
