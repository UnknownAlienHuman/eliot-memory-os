# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-26 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is a greenfield implementation. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its existing V1 runtime is donor-only.

## Reading order

1. [Architecture draft.12](ARCHITECTURE.md) — product purpose, authority, Base, extensions and invariants.
2. [Implementation draft.33](IMPLEMENTATION.md) — runtime, Store, Windows/process, durability, backup/rollback and implementation order.
3. [Cognition draft.16](COGNITION.md) — reconstruction, retrieval, learning, backup admission closure and revision algorithms.
4. [Inference Contract 0.11](INFERENCE-CONTRACT.md) — sole normative Memory↔controller V2 boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, current decisions, exact gaps and queue.
6. [Audit](AUDIT.md) — root causes, rejected machinery and evidence limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements and donors.

Architecture 12, Implementation 33, Cognition 16, Contract 0.11 and this README describe one synchronized design. `ANALYSIS-REGISTRY.md` is the only active work ledger. Git history preserves chronology; do not create another report, task catalogue, gate database or errata authority.

None of these documents proves implemented runtime behavior.

## Selected construction and authority

One local Rust package/codebase provides supervisor, daemon and transient relay modes. One active external SurrealDB child owns persistence; one isolated disposable candidate may exist during restore.

- **Daemon:** application operations, Editor-authenticated Store mutations, replay/jobs, backup cuts, context/retrieval and public control.
- **Supervisor/installer:** executable/root/process identity, root/Owner credentials, migrations, Store lifecycle, credential rotation and installation cutover.
- **Controller V2:** one-shot caller authentication, model profiles, provider execution/readback, global `WriteId` receipts and private temporary inference copies.
- **Host/controller:** user task/action execution and acceptance.

Root/Owner material never enters the daemon. The inherited supervisor channel carries only closed typed maintenance intent/result—never arbitrary SQL, argv, endpoint, path or secret. A request/acknowledgement is not completion; exact process, credential, Store and selection readback own the result.

Base captures real events, preserves notes/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. It starts without inference, vectors, converter or Research. Extensions reuse the same records/jobs/revisions/context; there is no second Lite/Full memory engine.

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

Store admission requires exact executable/root identity, owned child/listener/peer, upstream readiness, Editor authentication, healthy one-owner socket, query-only denial matrix, schema verification and typed write/read/delete through the production client.

Immutable publication:

```text
create-new same-directory temp
→ full write + file flush
→ no-replace MoveFileExW WRITE_THROUGH
→ parent-directory flush
→ exact reopen/readback
```

Mutable `installation.toml` and `controller-write-id.state` are separate expected-state replacements with exact old/new/unknown reconciliation. External-WriteId state lives outside rollback Store roots.

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
- `staged` — exact pending command is durable;
- `unknown` — neither ownership established;
- `rejected` — deterministic pre-ownership failure.

`stage_required` is private quiesce flow control, never rejection. `SessionStart`/`UserPromptSubmit` return actual packet content. “Event spooled” is status. Packet prepared, emitted, action-associated and actually used remain distinct.

## Exact open

One exact handle/locator plus optional bounded range. Never rerun search/conversion/Research/inference for a historical handle. Result states requested/resolved identity, range/digest, revision/representation, material limits/gaps, relation descriptors, cursor and exact missing/forbidden/erased/damaged/unsupported disposition.

Historical handle never falls forward. Fixed caps need continuation.

## Backup, rollback and erasure

Surreal HTTP export/import and startup import are not application backup owners.

Backup uses a brief exact spool cut:

```text
stop Store mutations/replay
→ reconcile active replay
→ hold publication lock only for inventory/generation cut
→ release lock
→ relay continues post-cut staging
→ copy exact immutable cut entries
```

It publishes canonical typed pages over six tables, selected-root blobs, deletion notices, cut pending/failed spool and sanitized config. Manifest owns completion.

Restore is exact rollback to one backup cut, not an invented merge of later Store rows. Healthy current Store first gets safety backup; previous root remains until retirement. Current deletion notices dominate backup content; current post-cut spool merges by exact command bytes/disposition.

Deletion fence prevents reintroduction but is not physical-erasure proof. A previous root/candidate/backup containing erased scope is deleted wholly or erasure remains incomplete. Off-machine copies are external.

## Current controller V2 authority

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

This is still a specification target. `docs/roadmap.md` is its sole status tracker; L0.1–L1.11 remain unchecked.

Controller issue #200 blocks foundation correctness. Current binding allocation conflates selected pointer and next immutable revision. Draft PR #201 repairs fixtures but not allocator/schema semantics. Controller issue #199 owns the later Memory extension and remains blocked on #200 and V2 L0/L1.

## One-shot inference Contract 0.11

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

Same identity returns original/current call; mismatch is `id_conflict`; valid absent ID may first-admit only during normal live operation. There is no separate Operation ID/submission ledger.

Memory owns one locked atomic external-WriteId generator outside rollback Store roots. Cancel, release and retention advance also receive durable pre-send IDs.

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

`retain_after_seq` is guaranteed completeness cut. `inference.list(after, through)` has fixed membership and returns `history_gap` whenever `after < retain_after_seq`.

### Backup admission closure

Before backup high-water is read, Memory pauses/drains one controller-dispatch owner and classifies every created call ID:

```text
admitted                exact call and admission_seq exist
retired_not_admitted    exact healthy absence; ID can never be sent later
admission_unknown       continuity incomplete
```

A controller-continuous backup contains admitted calls only. An old backup never first-admits an absent ID. A retired local intent may create a fresh successor only after post-cut inventory.

### Cleanup authority

With a valid caller:

```text
queued call: optional inference.cancel
then inference.release(abandon_for_erasure)
```

Controller-owner `inference.erase` is local break-glass. Memory has no owner credential, cannot submit it and records `owner_action_required` until non-content owner readback is observed.

### Retention and erasure tombstones

Erasing content for a call above `retain_after_seq` leaves bounded text-free membership tombstone until cut advancement. Deleting even tombstone requires prior retirement of every controlled backup pinning the interval. Otherwise erasure remains incomplete rather than silently breaking restore inventory.

After rollback:

- admitted in-cut jobs use same calls/IDs;
- missing admitted call is `history_gap/damaged`, never first admission;
- retired-not-admitted IDs stay retired;
- one fixed post-cut interval is inventoried by admission sequence;
- out-of-target results are not adopted;
- valid caller uses cancel/release-abandon;
- unavailable caller produces owner-action-required debt;
- history gap or unavailable identity keeps inference disabled;
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

0. **Memory Slice 0:** exact Windows executable/root/process/IPC/Surreal/Store/file/WriteId-state/backup/rollback/erasure/rotation/shutdown qualification.
1. **Base Slice 1:** event → Store/spool → replay → restart → exact open.
2. **Base Slice 2:** qualified Claude relay, continuation, lexical retrieval, actual context emission, notes/corrections/commitments and Base maintenance.
3. **Controller #200 + V2 L0/L1:** repair specification/validator, then implement fresh foundation; never extend V1.
4. **Inference P1a:** stable principal, rollback-safe WriteId state, single dispatch owner, admission-cut classification, calls/private copies, text runner, caller cleanup, high-water/list/retention/tombstones, owner break-glass boundary and one result changing later context.
5. **Inference P1b:** rotation, stale-session fence and delayed credential retirement.
6. Independent embeddings, views, documents, Research and additional hosts.
7. Advanced curation only after Base paths work.

Production code first. Run `cargo fmt --check` and minimum changed-package Clippy after coherent increments. Broad deterministic/live/platform/load campaigns follow connected product.

## Evidence limits

Source/design evidence is not runtime qualification. No Windows Store, host capture, controller V2 foundation or inference runtime is implemented by these documents.

Memory PR #5325 currently lacks genuine machine-generated documentation evidence and independent approval; the latest completed run also reported SurrealDB provisioner failure. No fabricated evidence block is accepted.

Full release ZIP and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` remain unavailable as readable source material. Donor conclusions apply only to exact paths/revisions recorded in the registry.