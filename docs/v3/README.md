# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-27 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is greenfield. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its legacy runtime is donor-only.

## Reading order

1. [Architecture draft.18](ARCHITECTURE.md) — product purpose, authority, Base, schema/backup invariants.
2. [Implementation draft.39](IMPLEMENTATION.md) — runtime, migration 0001, fixed queries, Windows/process, backup/rollback and implementation order.
3. [Cognition draft.22](COGNITION.md) — reconstruction, retrieval, learning, backup authority and revision algorithms.
4. [Inference Contract 0.17](INFERENCE-CONTRACT.md) — sole normative Memory↔controller V2 boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, decisions, gaps and queue.
6. [Audit](AUDIT.md) — root causes, rejected machinery and evidence limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for requirements and donors.

Architecture 18, Implementation 39, Cognition 22, Contract 0.17 and this README describe one synchronized design. `ANALYSIS-REGISTRY.md` is the only active work ledger. Git history preserves chronology; do not create another report, task catalogue, gate database or errata authority.

None of these documents proves implemented runtime behavior.

## Selected construction

One Rust codebase provides supervisor, daemon and transient relay modes. One active external SurrealDB child owns persistence; one isolated disposable candidate may exist during restore.

- **Daemon:** application operations, Store Editor, replay/jobs, controller-mutation owner, backup-set owner, restore file leases, retrieval/context and public control.
- **Supervisor:** executable/root/process identity, Store root/Owner credentials, migrations, candidate process/root, credential rotation and final cutover.
- **Controller V2:** one-shot caller authentication, profiles, provider execution/readback, global `WriteId` receipts and private temporary inference copies.
- **Host/controller:** user task/action execution and acceptance.

Base starts without inference, vectors, converter or Research.

## Connected completion

```text
real caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Types, fixtures, receipts, reports, branches and compilation alone are intermediate evidence.

## Store baseline and migration 0001

```text
SurrealDB 3.3.4
external RocksDB
sync=every
query-only authenticated WebSocket
STRICT database
six SCHEMAFULL tables
```

Application IDs crossing JSON are canonical bounded strings; native Surreal record IDs remain internal. Every fixed query has an explicit projection and DTO. There is no generic `Value`, raw SurrealQL or `SELECT *` persistence boundary.

Migration assets form one ordered UTF-8/LF bundle. SHA-256 is computed outside the assets; the migration never contains its own digest literal. The runner binds generation and bundle digest to fixed metadata params and verifies exact `INFO FOR DB/TABLE` definitions before daemon admission.

Base lexical retrieval uses `blank,class` + `lowercase` and separate FULLTEXT indexes for observation excerpts and Memory text. Exact and unique indexes remain separate index kinds.

## Capture and context

First host profile captures SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact and SessionEnd.

One immutable `CaptureCommand` exists before IPC:

```text
same command → daemon capture → Store readback → committed
no established ownership → exact durable spool → staged
staged command → daemon replay → Store readback → pending removed
```

`stage_required` is private quiesce flow control. SessionStart/UserPromptSubmit return actual packet content. Prepared, emitted, action-associated and used remain separate facts.

## Backup authority

Backup ID is `b_` plus 32 lowercase hex characters from 128 OS-random bits.

The daemon does not create an empty final directory. It writes canonical `fence.json` inside a private same-parent temp directory, flushes file+directory, atomically no-replace renames the directory to the final ID, flushes the parent and reopens the final fence. Pre-rename temp is non-pinning cleanup debt; post-rename sync/readback uncertainty is publication-unknown and pins conservatively.

Daemon owns both controller-mutation and backup-set owners:

```text
close/drain controller mutation
→ backup-set transition
→ publish/read back final fence
→ reopen mutation admission
```

Self-contained `abort.json` and `retire.json` remain terminal after content files are removed. Restore holds no-follow handles with delete sharing denied through candidate verification and final terminal-state recheck. Retirement and cleanup wait.

Supervisor owns candidate process/root and final cutover. Daemon/channel loss forces candidate kill/reap/discard before another daemon or cutover.

## Controller boundary

Current authority:

```text
eliot-swarm-controller@613ea6b5ff6389c7629a988e271477ee45c9d2c1
```

Controller issue #200 now requires three separate facts:

```text
allocated binding revision
selected current pointer
native effect / command state
```

Candidate admission never moves pointer. Launch/resume publish target pointer only with dispatch/generation transition; first observe/control/detach move pointer only after their exact effect. Allocator is monotonic and independent of pointer/history pruning. PR #201 remains fixture-only.

Contract 0.17 uses stable `memory_inference` client ID, current token version, precommitted global `WriteId`, one provider attempt, exact result copy, fixed retention inventory and dependency-aware cleanup. Issue #199 remains blocked on #200 and V2 L0/L1.

## Implementation order

0. **Slice 0:** Windows/process/IPC/Surreal/Store, migration 0001/query corpus, external-ID state, staged backup publication, backup-set owner/lease/candidate custody, rollback/erasure/rotation/shutdown.
1. **Base Slice 1:** event → Store/spool → replay → restart → exact open.
2. **Base Slice 2:** qualified Claude relay, continuation, lexical retrieval, actual packet emission, notes/corrections/commitments and maintenance.
3. **Controller #200 + V2 L0/L1.**
4. **Inference P1a:** stable caller, calls/copies/runner, cut/retention, backup integration and one result changing later context.
5. **P1b/later:** rotation, embeddings, views, documents, Research and more hosts.

Production code first. Run `cargo fmt --check` and minimum changed-package Clippy after coherent increments. Broad campaigns follow connected product.

## Evidence limits

Source/design evidence is not runtime qualification. PR #5325 still lacks genuine final-tree documentation evidence and independent approval; the last completed gate also reported SurrealDB provisioner failure. No fabricated evidence block is accepted.