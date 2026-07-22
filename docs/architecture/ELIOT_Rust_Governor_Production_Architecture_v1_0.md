# ELIOT Rust Governor
## Current implementation architecture

**Status:** maintained description of the implementation that exists now.  
**Primary platform:** native Windows.  
**Canonical source:** `UnknownAlienHuman/eliot-memory-os`, branch `main`.  
**Product license:** MIT.  

Source files, Cargo manifests and lockfile, migrations, generated Cargo metadata,
diagnostics, and tests are current truth. This document describes them; it does
not override them. The canonical master is the product vision. The Understanding
Layer document is future design.

## 1. Runtime topology

```text
Codex / Antigravity / OpenCode / Claude
                 |
          host MCP facade
                 |
      authenticated Windows IPC
                 |
         eliot-governor.exe
        /        |         \
 policy engine  receipts   adapters
        \        |         /
        governed store boundary
                 |
      external SurrealDB process
                 |
      operator-owned local data root
```

The Governor is the only normal application write authority. It turns typed
requests into governed transitions and receipts. SurrealDB is a separate runtime
reached through the repository's WebSocket/RPC transport; no SurrealDB Rust SDK
or embedded database is linked into the Governor. `redb` is the local control
WAL, not a second semantic memory database. Large artifacts use the bounded blob
store.

The normal runtime, database, reports, packages, and build cache are outside the
OneDrive source tree. The database remains a separately installed and separately
licensed runtime.

## 2. Workspace boundaries

The Rust workspace has five crates:

| Crate | Responsibility |
|---|---|
| `eliot-types` | Shared configuration, IDs, schemas, and wire contracts |
| `eliot-engine` | Governance, memory lifecycle, task, verification, delegation, provider, and host policy |
| `eliot-store` | SurrealDB supervision/RPC, migrations, WAL, blobs, backup/restore, and store receipts |
| `eliot-windows-ipc` | Authenticated named-pipe protocol and Windows process boundary |
| `eliot-app` | CLI, daemon, MCP facade, host packages, managed invocation, and operator commands |

`apps/Eliot.Operator` is a replaceable Windows operator UI over governed
protocols. It has no private truth or bypass around engine authority.

The application layer is divided by stable responsibility. MCP catalog,
dispatch, evaluation, experiment, replay, and verification logic are separate
modules. Host runtime separates Claude packaging, integration install state, and
managed launch. Provider budget recording is isolated from historical campaign
code. No obsolete milestone command module is part of the product CLI.

## 3. Authority and truth

- Current files, compiler diagnostics, live service state, and exact external
  sources outrank memory.
- Memory records are evidence with scope, provenance, freshness, lifecycle, and
  contradiction state. They are never ambient instructions.
- Host identity is transport metadata, not a permanent controller, auditor,
  verifier, or worker role.
- Work and controller authority come from bounded task-scoped leases.
- Provider output and delegated output are candidate evidence until disposition.
- Verification and FinishGate are the only path to a completion claim.
- Unknown provider outcomes are reconciled before retry; idempotency prevents a
  blind duplicate dispatch.

## 4. Storage and credential boundary

The production credential authority on Windows is Windows Credential Manager,
credential id `surreal-runtime/default`. Omitted `credential_provider` resolves
to Windows Credential Manager. The legacy password-file provider is explicit,
migration-gated compatibility only.

Secret values are transient. They are not placed in logs, traces, errors,
receipts, reports, memory, or Git. Rotation evidence records authority and
verification facts rather than secret-derived hashes.

The Surreal executable is resolved and identity-bound before use. The supervisor
sanitizes the child environment and records the exact process identity it owns.

## 5. SurrealDB ownership lifecycle

The supervisor distinguishes two cases:

1. It starts a SurrealDB process for this runtime and owns that exact child.
2. It connects to an already-compatible process and does not own it.

Graceful daemon shutdown stops new work, drains Governor clients and store
leases, releases store handles, validates the recorded child identity, stops only
the owned child, verifies exit, and removes matching owner state. It never kills
an arbitrary `surreal.exe` by name or by an unverified stale PID.

A pre-existing server is left running. Crash recovery reconnects when identity
and endpoint remain valid; stale ownership metadata alone never authorizes a
kill. Restart tests preserve canonical data across the stop/start boundary.

## 6. IPC and protocol

Local control uses current-user authenticated Windows named pipes with runtime
and auth generations. Sessions cannot reuse stale authority after rotation. The
handshake replay window is a bounded deterministic FIFO: recent duplicate nonces
are rejected, old entries turn over, fresh clients keep connecting beyond the
capacity, and a new auth generation resets the window.

MCP is a typed facade, not direct database access. The catalog in
`mcp_stdio/catalog.rs` is reused by live `tools/list`, prompts, surface parity
tests, and generated MCPB metadata. Package manifests never hand-copy a second
tool catalog.

## 7. Host integrations

### Codex

Codex uses MCP plus shared and project-specific skills/instructions. ELIOT does
not claim or ship a Codex plugin. Global shared skills live in the shared MCP
workspace; project truth remains in this repository.

### Antigravity

Antigravity uses its official plugin schema/lifecycle and an ELIOT MCP entry in
the GUI configuration. Doctor requires the installed official plugin surfaces,
schema validity, visible ELIOT agent/rules/skill, and an existing executable in
the live MCP registration. Old generated pseudo-plugin/skill bundles are not a
supported product surface.

### OpenCode

OpenCode installation is additive JSONC plus a bounded lifecycle plugin and the
four portable skills. Uninstall is ownership-manifest bounded and preserves
unrelated provider and user configuration.

### Claude

Claude is one host family with two explicit surfaces:

- `claude_code_plugin`: official local-marketplace plugin with one MCP server,
  four skills, and semantic hooks;
- `claude_desktop_mcpb`: MCPB with generated tools/prompts and no hooks.

Exactly one surface is active in overlapping sessions. The family doctor detects
dual activation, duplicate plugin roots, missing install sources, drift from the
selected surface, and installed binary/package hashes. Claude provider auth stays
Claude-owned.

Generated plugin and MCPB artifacts live under
`%LOCALAPPDATA%\Eliot\packages`. Claude Code installation uses the official
`claude plugin` lifecycle. Desktop installation uses Claude Desktop's extension
review/registry lifecycle.

## 8. Hooks and gates

Observation hooks are asynchronous when their result cannot affect the event.
Gates are synchronous only when the host consumes their decision schema.
`PreToolUse`, `PreCompact`, and `Stop` use event-specific governed responses;
`SessionStart` supplies compact context. Unattached sessions defer instead of
blocking unrelated projects. Hooks cannot mint role, lease, memory truth,
verification, or completion authority.

## 9. Build, packages, and release

The repository pins Rust 1.96.1 and declares an MSRV of 1.89. Developer Cargo
output is directed to `%LOCALAPPDATA%\Eliot\build\eliot-memory-os-target`.
Generated Claude packages go to `%LOCALAPPDATA%\Eliot\packages`. An explicit
release command may stage an attested unsigned bundle under `dist/`; normal
development packaging does not.

The Windows release contains the Governor, required Operator publish output,
portable configuration, integrations, migrations, and current runbooks. It is
source-commit bound, secret-scanned, and hash inventoried. Public distribution
still requires signing and a separate review of any third-party runtime
redistribution.

## 10. Verification contract

The inner loop is `just quick`. Real completion uses the smallest relevant
targeted tests followed by `just verify`. Provider-free Windows CI runs metadata,
formatting, workspace check, and workspace tests. Live paid-provider evaluation
is intentionally outside the deterministic gate.

Completion reports distinguish repository proof from machine-local integration
and runtime smoke. A config edit is not proof of a live registration; doctors,
host-owned inventories, authenticated IPC, process identity, and exact readback
provide that evidence.

## 11. Current limits and future design

ELIOT is pre-alpha. The canonical master describes mechanisms beyond the current
implementation. The Understanding Layer specification defines deeper cue-based
project understanding, concept artifacts, behavioral/causal graphs, bounded
context injection, and prediction calibration. Those mechanisms become current
only when source, schema, diagnostics, tests, and runtime proof say so.
