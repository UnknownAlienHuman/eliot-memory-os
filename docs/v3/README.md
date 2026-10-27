# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-27 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is greenfield. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its existing V1 runtime is donor-only.

## Reading order

1. [Architecture draft.17](ARCHITECTURE.md) — product purpose, authority, Base, extensions and invariants.
2. [Implementation draft.38](IMPLEMENTATION.md) — runtime, Store, Windows/process, durability, backup/rollback and implementation order.
3. [Cognition draft.21](COGNITION.md) — reconstruction, retrieval, learning, terminal backup authority, restore leases and revision algorithms.
4. [Inference Contract 0.16](INFERENCE-CONTRACT.md) — sole normative Memory↔controller V2 boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, decisions, gaps and queue.
6. [Audit](AUDIT.md) — root causes, rejected machinery and evidence limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for requirements and donors.

Architecture 17, Implementation 38, Cognition 21, Contract 0.16 and this README describe one synchronized design. `ANALYSIS-REGISTRY.md` is the only active work ledger. Git history preserves chronology; do not create another report, task catalogue, gate database or errata authority.

None of these documents proves implemented runtime behavior.

## Selected construction and authority

One local Rust package/codebase provides supervisor, daemon and transient relay modes. One active external SurrealDB child owns persistence; one isolated disposable candidate may exist during restore.

- **Daemon:** application operations, Editor-authenticated Store mutations, replay/jobs, backup cuts, context/retrieval and public control.
- **Supervisor/installer:** executable/root/process identity, root/Owner credentials, migrations, Store lifecycle, backup-set owner, restore leases, credential rotation and cutover.
- **Controller V2:** one-shot caller authentication, model profiles, provider execution/readback, global `WriteId` receipts and private temporary inference copies.
- **Host/controller:** user task/action execution and acceptance.

Root/Owner material never enters daemon. Inherited supervisor channel carries closed typed maintenance intent/result—never arbitrary SQL, argv, endpoint, path or secret. Request/acknowledgement is not completion; process, credential, Store, installation-record and selection readback own result.

Base captures real events, preserves notes/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. It starts without inference, vectors, converter or Research. Extensions reuse same records/jobs/revisions/context; there is no second Lite/Full memory engine.

## Connected completion criterion

```text
real caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Types, ports, fixtures, receipts, reports, branches and compilation alone are intermediate evidence.

## Store and local durability baseline

First qualification target:

```text
SurrealDB 3.3.4
external RocksDB
sync=every
query-only authenticated WebSocket client
STRICT database
six SCHEMAFULL application tables
```

Store admission requires exact executable/root identity, owned child/listener/peer, upstream readiness, Editor authentication, healthy one-owner socket, query-only denial matrix, schema verification and typed write/read/delete through production client.

Immutable publication:

```text
create-new same-directory temp
→ full write + file flush
→ no-replace MoveFileExW WRITE_THROUGH
→ parent-directory flush
→ exact reopen/readback
```

Mutable `installation.toml` and `controller-write-id.state` are separate expected-state replacements with exact old/new/unknown reconciliation. External-WriteId state and installation-scoped backup records live outside rollback Store roots.

## Host capture, spool and context

First host: bounded Claude Code relay for:

```text
SessionStart
UserPromptSubmit
PostToolUse
PostToolUseFailure
Stop
SubagentStop
PostCompact
SessionEnd
```

One immutable `CaptureCommand` exists before IPC.

```text
same command → daemon capture → matching Store readback → committed
stage_required/unavailable/uncertain → exact durable pending file → staged
staged command → daemon replay → Store readback → pending removed
```

Public results:

- `committed` — Store readback matched;
- `staged` — exact pending command durable;
- `unknown` — neither ownership established;
- `rejected` — deterministic pre-ownership failure.

`stage_required` is private quiesce flow control, never rejection. `SessionStart`/`UserPromptSubmit` return actual packet content. “Event spooled” is status. Packet prepared, emitted, action-associated and actually used remain distinct.

## Exact open

One exact handle/locator plus optional bounded range. Never rerun search/conversion/Research/inference for historical handle. Result states requested/resolved identity, range/digest, revision/representation, limits/gaps, relation descriptors, cursor and exact missing/forbidden/erased/damaged/unsupported disposition.

Historical handle never falls forward. Fixed caps need continuation.

## Backup, rollback, terminal state and erasure

Surreal HTTP export/import and startup import are not application backup owners.

Backup uses a brief exact spool/controller cut:

```text
stop Store/replay and controller mutations
→ disposition every call/cancel/release/retention WriteId
→ capture exact spool/controller cut
→ allocate non-reused random backup ID
→ publish rollback-safe canonical plan fence
→ relay continues post-cut staging
→ copy exact immutable cut entries and typed Store pages
```

It publishes canonical typed pages over six tables, selected-root blobs, deletion notices, cut pending/failed spool and sanitized config. Final manifest owns completion.

One in-process backup-set owner owns backup-ID allocation, installation-record scans, terminal transitions, restore leases and physical cleanup. It is not another service or database.

Controlled records:

```text
backups/<random-id>/
  fence.json?
  parts/...
  manifest.json?
  abort.json?
  retire.json?
```

`abort.json` and `retire.json` are self-contained immutable terminal tombstones after exact prerequisites. They bind backup/plan/fence identity and deterministic terminal operation; retirement also binds manifest digest. Once durable, later deletion of fence, manifest or parts does not undo terminal state. Malformed/both-terminal/mismatched sets fail closed.

Derived state is terminal-first:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no manifest/terminal            -> preparing/publication-unknown
other ambiguity                           -> unresolved/fail closed
```

Published non-retired backups and unresolved provisional fences pin dependent-call release and controller post-cut retention. Terminal generations do not pin; surviving content remains cleanup debt.

Restore is exact rollback, not invented merge. It requires a backup-set read lease with retained no-follow handles through candidate verification and final pre-cutover terminal-state recheck. Retirement, abort and cleanup wait on that lease. Crash discards candidate and releases lease. Healthy current Store first gets safety backup; previous root remains until retirement. Current deletion notices dominate backup content; current post-cut spool merges by exact command bytes/disposition.

Deletion fence prevents reintroduction but is not physical-erasure proof. Previous root/candidate/backup containing erased scope is deleted wholly or erasure remains incomplete. Off-machine copies are external.

## Current controller V2 authority

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

This is still specification target. `docs/roadmap.md` is its sole status tracker; L0.1–L1.11 remain unchecked.

Controller issue #200 blocks foundation correctness. Current binding allocation conflates selected pointer and next immutable revision. Draft PR #201 repairs fixtures but not allocator/schema semantics. Issue #199 owns later Memory extension and remains blocked on #200 and V2 L0/L1.

## One-shot inference Contract 0.16

Stable principal:

```text
principal_kind = memory_inference
client_id      = memory:<random-stable-installation-id>
token_version  = current physical credential version
```

No owner, Agent, automation, plugin or no-token fallback.

Every caller mutation uses global canonical ULID `WriteId` persisted before send. Live call identity:

```text
WriteId globally unique
+ client_id
+ method
+ canonical semantic payload
```

Same identity returns original/current call; mismatch is `id_conflict`; valid absent ID may first-admit only during normal live operation. No separate Operation ID/submission ledger.

Memory owns one locked atomic external-WriteId generator outside rollback roots. One controller-mutation owner serializes call admission, cancel, release and retention advance.

Minimal controller state:

```text
write_receipts
memory_inference_clients
inference_calls
private inference_input/result files
```

Registration owns:

```text
last_admission_seq
retain_after_seq
```

`retain_after_seq` is guaranteed post-cut completeness cut. `inference.list(after, through)` has fixed membership and returns `history_gap` whenever `after < retain_after_seq`.

### Backup cut dispositions

Before backup high-water, Memory closes/drains the controller-mutation owner.

Every created call ID becomes:

```text
admitted
retired_not_admitted
admission_unknown
```

Every created cancel/release/retention ID becomes:

```text
effect_observed
retired_not_sent
mutation_unknown
```

Old backup never first-admits an absent call or auxiliary ID. After restore, current auxiliary need is recomputed; any new effect gets a fresh WriteId only after post-cut inventory.

Every admitted in-cut call is:

```text
controller_closed
  backup is fully self-contained

controller_dependent
  backup still needs controller state/result/copy/readback
```

### Canonical plan and terminal records

Before writing any backup part, Memory computes `backup_plan_digest` over a closed immutable plan excluding its own digest, publication state and later page/part/manifest digests. It publishes installation-scoped `fence.json`; final manifest repeats the plan digest plus actual inventories.

Backup IDs are random 128-bit installation-local values allocated by create-new publication and never reused.

Self-contained terminal markers make cleanup closed under its own rules:

- abort only after exact no-manifest/no-writer/no-lease and partial-content cleanup;
- retire only for exact published backup with no restore lease;
- marker remains terminal after content-bearing files are removed;
- both markers or contradictory surviving files are integrity failure.

Store maintenance rows mirror status only. After rollback they are reconciled before job claims; stale future-timeline rows cannot create terminal records, clear pins or send release/retention.

### Cleanup and retention authority

With valid caller:

```text
queued call: optional inference.cancel
then inference.release(...), subject to current controlled backup set
```

Controller-owner `inference.erase` is local break-glass. Memory has no owner credential, cannot submit it and records `owner_action_required` until non-content owner readback.

Required retention cut is the minimum high-water among published non-retired restorable backups and unresolved preparing/publication-unknown fences. A restored pending retention row is never blindly sent; current desired cut is recomputed from installation records and controller readback.

After rollback:

- `controller_closed` jobs restore from backup facts even when controller row is pruned;
- `controller_dependent` jobs require exact call/copy;
- retired call/auxiliary IDs stay retired;
- one fixed post-cut interval is inventoried;
- out-of-target results are not adopted;
- current cancel/release/retention effects are recomputed;
- unavailable caller produces owner-action-required debt;
- history gap, call/auxiliary unknown, terminal-record ambiguity, missing dependent copy or unavailable identity keeps inference disabled;
- Base remains usable.

Controller-local install/rotate publishes raw token only into admitted create-new/no-reparse restrictive-ACL private destination. Memory never receives controller owner authority.

## Preserved goals, minimal mechanisms

| Goal | V3 minimum | Rejected default machinery |
|---|---|---|
| Resume | Stable work address + observations + direct reconstruction | Universal state/checkpoint platform |
| Source/provenance | Observation + exact blob/range + handles | Truth/evidence promotion service |
| Correction | Current revision + history + grounds | Global truth score/ladder |
| Avoid repeats | Scoped negative memory/method revision | Failure-fingerprint platform |
| Context | Direct current-work + lexical + optional vectors + bounded packet | Context service/packet database |
| Learning | Finite Memory job + exact recipe + one-shot call + later consumer | Permanent Dreamer/Task lifecycle |
| Optional capability | Internal connected vertical increment | Crate/process/manifest per noun |
| Privacy | Disclosure + actual send-owner check + finite copy cleanup | General Governor/approval platform |
| Recovery | One Store + spool + supervisor + typed backup/exact rollback | Recovery DB/global identity graph |
| Authority | Daemon application owner + narrow privileged boundary | Public supervisor API |
| Development | One issue/branch/integrator + terminal overlap disposition | Work-unit DB/agent scheduler |

## Implementation order

0. **Memory Slice 0:** exact Windows executable/root/process/IPC/Surreal/Store/file/WriteId-state/backup-set owner/terminal records/restore lease/rollback/erasure/rotation/shutdown qualification.
1. **Base Slice 1:** event → Store/spool → replay → restart → exact open.
2. **Base Slice 2:** qualified Claude relay, continuation, lexical retrieval, actual context emission, notes/corrections/commitments and Base maintenance.
3. **Controller #200 + V2 L0/L1:** repair specification/validator, then implement fresh foundation; never extend V1.
4. **Inference P1a:** stable principal, WriteId state, mutation owner, backup-set owner, cut dispositions, canonical plan, installation fence/self-contained terminal records, restore lease, calls/private copies, text runner, release+retention, high-water/list/tombstones, owner break-glass and one result changing later context.
5. **Inference P1b:** rotation, stale-session fence and delayed credential retirement.
6. Independent embeddings, views, documents, Research and additional hosts.
7. Advanced curation only after Base paths work.

Production code first. Run `cargo fmt --check` and minimum changed-package Clippy after coherent increments. Broad deterministic/live/platform/load campaigns follow connected product.

## Evidence limits

Source/design evidence is not runtime qualification. No Windows Store, host capture, controller V2 foundation or inference runtime is implemented by these documents.

Memory PR #5325 currently lacks genuine machine-generated documentation evidence and independent approval; latest completed run also reported SurrealDB provisioner failure. No fabricated evidence block is accepted.

Full release ZIP and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` remain unavailable as readable source material. Donor conclusions apply only to exact paths/revisions recorded in registry.