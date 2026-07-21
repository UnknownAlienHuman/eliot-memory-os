# ADR 0004: Owned user-mode dogfood runtime

## Status

Accepted for Phase L3 dogfood.

## Context

The daemon and SurrealDB server can outlive the command that starts them. A
plain background launch does not prove that a later stop request still targets
the same processes, and a repository-local runtime would place credentials and
IPC authentication material inside a synchronized source tree.

## Decision

`eliot-governor dogfood` requires an explicit absolute root below the current
user's `LOCALAPPDATA` or `TEMP`. It rejects lexical OneDrive, common sync, and
`.git` paths without querying Known Folder or sync configuration. `init`
restricts that root to the current Windows SID and `LocalSystem`, generates a
persistent RocksDB configuration there, and emits an isolated Codex MCP config
with the real-provider kill switch enabled.

`start` records every owned child as a `(role, PID, canonical executable)`
tuple. `status`, `doctor`, and `stop` re-resolve PID-to-executable identity.
`stop` first requests cooperative daemon shutdown, then stops only the recorded
SurrealDB PID after identity verification. It never kills by process name.
Runtime state remains under the selected root so a clean stop/start preserves
canonical records.

The distributable plugin uses the current direct `.mcp.json` server map and a
bundled `bin/eliot-governor.exe` staged by `install-local.ps1`. Plugin hooks
resolve that binary from `PLUGIN_ROOT`; the live L3 run uses a generated
project-scoped config and does not install, trust, or enable the plugin
globally.

## Consequences

- Operators can remove one owned root after a clean stop.
- A recycled or tampered PID is rejected rather than terminated.
- Secrets and the per-start IPC token never enter the repository.
- The user must explicitly initialize each persistent dogfood root.
- Plugin packaging and live project-scoped configuration remain separate
  validation surfaces.
