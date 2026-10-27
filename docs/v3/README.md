# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-27 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is greenfield. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its legacy runtime is donor-only.

## Reading order

1. [Architecture draft.19](ARCHITECTURE.md) — product purpose, authority, Base, schema/backup invariants.
2. [Implementation draft.42](IMPLEMENTATION.md) — runtime, exact SurrealDB 3.3.4 migration/query boundary, Windows/process, backup/rollback and sequence.
3. [Cognition draft.23](COGNITION.md) — reconstruction, retrieval, learning, backup authority and failure algorithms.
4. [Inference Contract 0.18](INFERENCE-CONTRACT.md) — sole normative Memory↔controller V2 boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, decisions, gaps and queue.
6. [Audit](AUDIT.md) — root causes, rejected machinery and evidence limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for requirements and donors.

Architecture 19, Implementation 42, Cognition 23, Contract 0.18 and this README describe one synchronized design. `ANALYSIS-REGISTRY.md` is the only active work ledger. Git history preserves chronology; do not create another report, task catalogue, gate database or errata authority.

None of these documents proves implemented runtime behavior.

## Construction and authority

One Rust codebase provides supervisor, daemon and transient relay modes. One active SurrealDB child owns persistence; one isolated disposable candidate may exist during restore.

- **Daemon:** application operations, Store Editor, replay/jobs, controller-mutation owner, backup-set owner, bounded restore leases, retrieval/context and public control.
- **Supervisor:** executable/root/process identity, Store root/Owner credentials, migrations, candidate process/root, credential rotation and final cutover.
- **Controller V2:** one-shot caller authentication, profiles, provider execution/readback, global `WriteId` receipts and private temporary copies.
- **Host/controller:** user task/action execution and acceptance.

Base starts without inference, vectors, converters or Research.

## Connected completion

```text
real caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Types, fixtures, receipts, reports, branches and compilation alone are intermediate evidence.

## Store and schema baseline

First qualification target:

```text
SurrealDB 3.3.4
external RocksDB
sync=every
query-only authenticated WebSocket
STRICT database
six SCHEMAFULL tables
```

Application IDs crossing JSON are canonical bounded strings; native Surreal record IDs remain internal. Base IDs are generated from 128 OS-random bits, retained before retryable writes and never treated as time order. Derived unique keys are domain-separated SHA-256 over length-prefixed components. Every fixed query has an explicit projection and DTO; direct work reconstruction uses explicit indexed workspace/task/actor/session fields rather than parsing `binding_json`.

Migration bundle identity includes format version, runner protocol, exact wrapper template, ordered UTF-8/LF DDL assets and expected catalog template. Bound generation/digest values remain outside the preimage. Schema admission uses plain `INFO FOR DB` / `INFO FOR TABLE` maps, sorted by owned keys and compared as exact pinned-version canonical `DEFINE` strings. `INFO ... STRUCTURE` is not an admission API.

Exact tag source/tests establish:

- `DEFINE FIELD` clause/type grammar and canonical rendering;
- `READONLY` permits initial assignment and same-value replay but rejects changed value;
- row-local ASSERT evaluation after type coercion;
- UNIQUE tuple skipping when any component is `NONE` or `NULL`;
- persisted PARAM rollback and cancelled index-overwrite preservation;
- numbered FTS score, zero-score matches and representative indexed iteration;
- plain INFO maps of canonical DEFINE strings.

They do **not** prove the complete V3 migration wrapper, bound metadata over the production WebSocket client, all DDL rollback points, concurrent uniqueness, every reader plan, Windows/RocksDB durability or DTO correctness. Those remain Slice 0.

V3 uses `NONE` as the sole conditional-key absence state; `NULL` is not written to optional unique-key fields. `READONLY` guards later changed values but never generates or owns application identity. Migration 0001 row assertions are defense in depth; byte digests, replay identity, sequence allocation and cross-row invariants remain application/transaction owned.

Scored FTS uses numbered match references:

```text
WHERE search_text @0@ $query
SELECT ..., search::score(0) AS score
ORDER BY score DESC, canonical_id ASC
LIMIT $hard_limit
```

A zero score remains a match. Lexical retrieval is one bounded top-K statement snapshot per call, not a durable cursor across corpus changes.

## Capture and context

First host profile captures SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact and SessionEnd.

```text
same immutable command → daemon capture → Store readback → committed
no established ownership → exact durable spool → staged
staged command → daemon replay → Store readback → pending removed
```

`stage_required` is private quiesce flow control. SessionStart/UserPromptSubmit return actual packet content. Prepared, emitted, action-associated and used remain separate facts.

## Backup authority

Backup ID is `b_` plus 32 lowercase hex characters from 128 OS-random bits.

Daemon writes canonical `fence.json` inside a private same-parent temp directory, flushes file+directory, atomically no-replace renames the directory to the final ID, flushes the parent and reopens the final fence. The final directory never appears empty. Pre-rename temp is non-pinning cleanup debt; post-rename uncertainty pins conservatively after reconciliation.

Daemon owns controller-mutation and backup-set owners:

```text
close/drain controller mutation
→ backup-set transition
→ publish/read back final fence
→ reopen mutation admission
```

Self-contained abort/retire tombstones remain terminal after content cleanup.

Restore first admits finite part-count/per-part/total-byte/path limits. It keeps a logical lease plus final-directory/parts-directory/fence/manifest handles with read sharing only, then opens, verifies, copies and closes one part at a time. V3 never holds an unbounded handle set. Final terminal/manifest identity is rechecked before cutover.

Supervisor owns candidate process/root and final cutover. Daemon/channel loss forces candidate kill/reap/discard before another daemon or cutover.

## Controller boundary

Current controller authority:

```text
eliot-swarm-controller@613ea6b5ff6389c7629a988e271477ee45c9d2c1
```

Issue #200 separates allocated revision, selected pointer and effect state. Candidate admission never moves pointer; launch/resume publish target pointer with dispatch; attach/detach move it only after exact effect. Allocator is monotonic and independent of pointer/history pruning. PR #201 remains fixture-only.

Contract 0.18 uses stable `memory_inference` client ID, current token version, precommitted global `WriteId`, one provider attempt, exact result copy, fixed retention inventory and dependency-aware cleanup. Issue #199 remains blocked on #200 and V2 L0/L1.

## Implementation order

0. **Slice 0:** exact DDL grammar, wrapper-bound metadata/full rollback/catalog, unique concurrency, fixed query DTO/EXPLAIN, then Windows/process/IPC/Surreal/Store, external-ID state, staged backup publication, bounded restore lease, rollback/erasure/rotation/shutdown.
1. **Base Slice 1:** event → Store/spool → replay → restart → exact open.
2. **Base Slice 2:** qualified Claude relay, indexed continuation, lexical top-K retrieval, actual context emission, notes/corrections/commitments and maintenance.
3. **Controller #200 + V2 L0/L1.**
4. **Inference P1a:** stable caller, calls/copies/runner, cut/retention, backup integration and one result changing later context.
5. **P1b/later:** rotation, embeddings, views, documents, Research and more hosts.

Production code first. Run `cargo fmt --check` and minimum changed-package Clippy after coherent increments. Broad campaigns follow connected product.

## Evidence limits

Source/design evidence is not runtime qualification. PR #5325 still lacks genuine final-tree documentation evidence and independent approval; the last completed gate also reported SurrealDB provisioner failure. No fabricated evidence block is accepted.