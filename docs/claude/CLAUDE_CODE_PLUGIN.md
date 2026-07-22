# Claude Code plugin

Claude Code uses the native plugin in `integrations/claude/eliot`. The package
contains four generated ELIOT skills, deterministic hooks, and one MCP server:

```text
${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe mcp stdio --host claude --instance default
```

The plugin does not require the Governor to be on `PATH`. The skill copies are
generated: `just sync-skills` writes them from `integrations/agent-skills`, and
`host skill-lint` fails the build if anyone edits one by hand.

## Build, install, and validate

Cargo output is redirected outside OneDrive, so the binary is not under
`.\target`; take the path from `cargo`.

```powershell
cargo build --release --package eliot-app --bin eliot-governor
$governor = cargo metadata --format-version 1 --no-deps |
  ConvertFrom-Json | ForEach-Object { Join-Path $_.target_directory 'release\eliot-governor.exe' }
& $governor host install --host claude
& $governor host doctor --host claude
claude plugin validate "$env:USERPROFILE\.claude\skills\eliot"
```

Installation owns only the ELIOT plugin directory and does not inspect provider
credentials or rewrite unrelated Claude settings.

## Hooks

Eight events, split by whether they can decide anything.

| Event | Handler | Blocks | Runs |
| --- | --- | --- | --- |
| `SessionStart` | `hook session-start` | no | sync — its context must reach the first model request |
| `PreToolUse` | `hook pre-tool-use` | yes | sync |
| `PreCompact` | `hook pre-compact` | yes | sync |
| `Stop` | `hook stop` | yes | sync |
| `PostToolUseFailure` | `host event` | no | async |
| `SubagentStart` | `hook subagent-start` | no | async |
| `SubagentStop` | `hook subagent-stop` | no | async |
| `SessionEnd` | `host event` | no | async |

Enforcement goes through `hook <event>` rather than the generic `host event`
path, because each event has its own decision schema and the generic path emits
one shape for all of them. This matters concretely: the finish gate blocks with
a top-level `{"decision": "block"}`, which is what `Stop` reads. `TaskCompleted`
blocks on exit code 2 or `{"continue": false}` instead, so the same handler
declared there would emit valid JSON that Claude Code ignores for that event.

`PreToolUse` is filtered to `Bash|Edit|Write|NotebookEdit`. The plugin is
installed at user scope and therefore fires in every Claude session on the
machine, so both gates defer when `ELIOT_TASK_ID` does not attach the session to
an ELIOT task — an unrelated project is never blocked.

## Authority boundary

Hooks provide compact lifecycle observations and may deny work early. They
cannot create a task role, lease, verification run, completion proof, or
canonical memory claim. The compact Claude access profile exposes governed tools
and prompts but omits raw database, credential, shell, patch, provider, and
unconditional completion authority.
