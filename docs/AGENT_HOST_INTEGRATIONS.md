# Agent host integrations

## Common contract

ELIOT is one host-independent Memory OS and Governor. Codex, Antigravity,
OpenCode, Claude Code, and Claude Desktop are replaceable clients of the same
runtime, task state, receipts, and canonical store boundary. A host name selects
transport and capabilities; it never grants a task role, truth authority, or
completion authority.

Every live MCP session registers an `AgentSessionHostBinding`. Current task-role
and controller leases come from `eliot_host_session_status`; historical receipts
and host labels are not role evidence.

The portable skill pack contains exactly four skills:

- `eliot-work`
- `eliot-remember`
- `eliot-recover`
- `eliot-finish`

Canonical skill bodies live in `integrations/agent-skills`. Generated host copies
must remain byte-identical.

## Host surfaces

| Host | Product integration | Installation authority |
|---|---|---|
| Codex | Native ELIOT plugin with one MCP server, four canonical skills, and bounded lifecycle hooks | Codex plugin lifecycle and MCP configuration |
| Antigravity | Official ELIOT plugin plus a governed MCP registration | Antigravity plugin directory and GUI MCP config |
| OpenCode | Additive JSONC configuration, lifecycle plugin, four skills | Governor ownership manifest |
| Claude Code | Official local-marketplace plugin with MCP, hooks, and four skills | `claude plugin` lifecycle |
| Claude Desktop | MCPB extension with an embedded native stdio facade; no hooks | Claude Desktop extension UI/registry |

Claude is one host family with two package surfaces. In a Claude Code session
hosted by Desktop, exactly one surface may be active: `code` or `desktop`.

## Resolve the release binary

Cargo output is intentionally outside OneDrive. Commands below assume:

```powershell
cargo build --release --package eliot-app --bin eliot-governor
$target = cargo metadata --format-version 1 --no-deps |
  ConvertFrom-Json | Select-Object -ExpandProperty target_directory
$governor = Join-Path $target 'release\eliot-governor.exe'
```

## Inspect, install, and activate

```powershell
& $governor daemon health --instance default
& $governor host inspect --host opencode
& $governor host doctor --host opencode
& $governor host install --host opencode

& $governor antigravity plugin install-official --admin-confirm
& $governor antigravity mcp register --admin-confirm
& $governor antigravity doctor

& $governor host install --host claude
& $governor host activate --host claude --surface code
& $governor host doctor --host claude

# Optional Desktop package; activate only when Code mode is intentionally stood down.
& $governor host install --host claude-desktop
& $governor host activate --host claude --surface desktop
```

Installers modify only ELIOT-owned surfaces and preserve unrelated providers,
models, permissions, MCP entries, instructions, plugins, settings, and provider
authentication. Switching surfaces is idempotent and reports whether Claude must
reload or start a new session.

## Managed work and result authority

Render or launch supervised work only with an explicit model and bounded prompt:

```powershell
& $governor host render --host opencode --mode supervised --model <model>
& $governor host launch --host opencode --mode supervised --model <model> --prompt '<bounded work>'
```

Managed launch reuses a ready default Governor or starts the same ELIOT release
as a hidden per-user process. Readiness requires an authenticated named-pipe
handshake. Runtime evidence belongs under the per-user ELIOT runtime root.

Registering a host session gives no role. Delegated results remain candidate
evidence until the controller records a disposition; disposition never bypasses
verification or FinishGate. Unknown provider outcomes must be reconciled by
session ID, idempotency key, and broker state before retry.

## Understanding Layer v1.4 certification

Codex has a native ELIOT plugin. The package exposes one governed MCP server,
the four canonical skills, and bounded lifecycle hooks; it is not a prose-only
integration.

Antigravity's official package is consumed by the default agent through its
skills, rules, and governed GUI MCP registration. A custom `eliot-agent`,
`--agent eliot-agent`, a duplicate legacy CLI MCP config, or a blank replacement
profile is neither required nor accepted as readiness evidence.

The Claude Code and Antigravity packages were exercised in blind reciprocal run
`ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486`. The run completed exactly
eight provider calls, both directions passed, and no provider outcome was
unknown. Canonical receipts prove provider-owned candidate submission, exact
handle retrieval, influence acknowledgement, clean memory-free controls, and
unchanged truth revision for observability-only writes.
