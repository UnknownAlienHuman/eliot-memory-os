# Agent host integrations

## Common contract

ELIOT is one host-independent Memory OS and Governor. Codex, Antigravity,
OpenCode, Claude Code, and Claude Desktop are replaceable clients of the same
runtime, task state, receipts, and canonical store boundary. A host name selects
transport and capabilities; it never grants a task role, truth authority, or
completion authority.

Every live MCP session registers an `AgentSessionHostBinding`. The authoritative
role source is `eliot_host_session_status`, which returns only current task-role
and controller leases for that session. Historical receipts and host labels are
not role evidence.

The portable skill pack contains exactly four skills:

- `eliot-task-cycle`
- `eliot-understanding`
- `eliot-delegation`
- `eliot-verify-finish`

Canonical skill bodies live in `integrations/agent-skills`. OpenCode and Claude
copies must remain byte-identical.

## Host surfaces

| Host | Product integration | Authority notes |
|---|---|---|
| Codex | project MCP and repository instructions | controller-capable only through current leases |
| Antigravity | official plugin, agent, rules, skill, governed MCP | host identity is never a permanent auditor role |
| OpenCode | additive JSONC configuration, lifecycle plugin, four skills | preserves unrelated user configuration |
| Claude Code | self-contained plugin, hooks, four skills, compact MCP | provider authentication remains Claude-owned |
| Claude Desktop | MCPB extension with embedded native stdio facade | no database credentials or host-derived role |

## Inspect and launch

```powershell
.\target\release\eliot-governor.exe daemon health --instance default
.\target\release\eliot-governor.exe host inspect --host opencode
.\target\release\eliot-governor.exe host doctor --host opencode
.\target\release\eliot-governor.exe host inspect --host claude
.\target\release\eliot-governor.exe host doctor --host claude
.\target\release\eliot-governor.exe host skill-lint
```

Render or launch supervised work only with an explicit model and bounded prompt:

```powershell
.\target\release\eliot-governor.exe host render --host opencode --mode supervised --model <model>
.\target\release\eliot-governor.exe host launch --host opencode --mode supervised --model <model> --prompt '<bounded work>'
```

Managed launch reuses a ready default Governor or starts the same ELIOT release as
a hidden per-user process. Readiness requires an authenticated named-pipe
handshake. Runtime evidence belongs under the per-user ELIOT runtime root, not in
the repository.

## Installation and rollback

Installers own only named ELIOT surfaces and must preserve unrelated providers,
models, permissions, MCP entries, instructions, plugins, and settings.

```powershell
.\target\release\eliot-governor.exe host install --host opencode --dry-run
.\target\release\eliot-governor.exe host install --host opencode
.\target\release\eliot-governor.exe host uninstall --host opencode --dry-run
.\target\release\eliot-governor.exe host uninstall --host opencode

.\target\release\eliot-governor.exe host install --host claude
.\target\release\eliot-governor.exe host uninstall --host claude

.\target\release\eliot-governor.exe host install --host claude-desktop
.\target\release\eliot-governor.exe host doctor --host claude-desktop
.\target\release\eliot-governor.exe host uninstall --host claude-desktop
```

Provider credentials and auth files are never read or modified. Rollback is
ownership-manifest bounded and refuses an ELIOT-owned entry that changed after
installation.

## Dynamic roles and results

Registering a host session gives no role. Role and controller leases are scoped to
one task and a bounded lifetime. Delegated results remain candidate evidence until
the controller records a disposition; disposition does not bypass verification or
FinishGate.

Unknown provider outcomes must be reconciled by session ID, idempotency key, and
broker state before retry. Never blindly redispatch an operation whose result may
already have been accepted.
