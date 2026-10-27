# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-26 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is a greenfield implementation. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its existing V1 runtime is a donor and must not receive new Memory functionality.

## Reading order

1. [Architecture draft.10](ARCHITECTURE.md) — product purpose, authority owners, Base, extensions and invariants.
2. [Implementation draft.31](IMPLEMENTATION.md) — runtime, Store, Windows/process, durability, backup/restore and implementation sequence.
3. [Cognition draft.14](COGNITION.md) — current-work reconstruction, retrieval, learning and revision algorithms.
4. [Inference Contract 0.10](INFERENCE-CONTRACT.md) — sole normative Memory↔controller V2 boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — checked evidence, decisions, remaining gaps and exact queue.
6. [Audit](AUDIT.md) — root causes, rejected machinery and evidence limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements and donors.

`ANALYSIS-REGISTRY.md` is the only active work ledger. Git history preserves chronology. Do not create another V3 report, task catalogue, gate database or errata authority.

### Current synchronization state

Contract 0.10 and the registry use the current controller authority and corrected retention/WriteId design. Architecture 10, Implementation 31 and Cognition 14 still contain a few Contract 0.9 names (`c8c0ee1`, `earliest_retained_seq` and missing installation WriteId-state/auxiliary mutation fields). Registry R-024 is therefore `PARTIAL`; those existing owner documents must be updated in place before coding inference. Base/Store design is unaffected and remains independently implementable.

## Product construction

One local Rust package/codebase provides:

```text
eliot supervisor
eliot daemon
eliot relay ...
```

One active external SurrealDB child owns persistence; one isolated disposable candidate may exist during restore qualification. Ordinary modules provide boundaries. A new process/crate/table exists only for a real independent owner, deployment, failure or stored-state boundary.

Authority:

- daemon — application operations, Editor-authenticated Store mutations, replay/jobs, backup cut, context/retrieval and public control;
- supervisor/installer — executable/root/process identity, root/Owner credentials, migrations, Store lifecycle, credential rotation and installation cutover;
- controller V2 — one-shot caller authentication, model profiles, physical provider execution/readback and private temporary inference copies;
- host/controller — user task/action execution and acceptance.

Base works without controller inference, vectors, converter or Research. It captures real events, retains exact sources, supports notes/corrections/commitments, reconstructs current work, supplies lexical/exact context and reopens exact sources after restart.

## Connected completion criterion

A capability is present only when this path exists:

```text
real caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Types, ports, fixtures, receipts, issue count, branches, reports and compilation alone are intermediate evidence.

## Store and local durability baseline

Selected first qualification target:

```text
SurrealDB 3.3.4
external RocksDB
sync=every
query-only authenticated WebSocket client
STRICT database
six SCHEMAFULL application tables
```

The current Rust SDK is not baseline: its exact version raises MSRV/license/dependency questions and does not justify linking the engine when a bounded remote client suffices.

Store admission requires the conjunction of:

```text
exact executable/root identity
→ owned child/listener/established peer
→ upstream readiness
→ Editor Basic authentication
→ healthy one-owner socket
→ query-only denial matrix
→ schema generation/definition verification
→ typed production-client write/read/delete
```

A path, PID, port, HTTP status, WebSocket 101 or clean process exit is not admission or durability proof.

Immutable local publication:

```text
create-new same-directory temp
→ full write + file flush
→ no-replace MoveFileExW WRITE_THROUGH
→ parent-directory flush
→ exact reopen/readback
```

Mutable `installation.toml` is a separate supervisor-only expected-generation replacement with exact old/new/unknown reconciliation. It is not implemented through the immutable primitive.

## Host capture, spool and context

First host profile: bounded Claude Code relay for:

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

One immutable `CaptureCommand` is built before IPC. Native/command identity identifies occurrence; content digest verifies bytes and never merges separate occurrences.

Public capture outcomes:

- `committed` — Store readback matched;
- `staged` — exact command is durably present in pending spool;
- `unknown` — neither ownership can be established;
- `rejected` — deterministic failure before ownership transfer.

Private `stage_required` during backup/shutdown/erasure means “relay must durably stage”, not rejection.

`SessionStart`/`UserPromptSubmit` return actual rendered context. “Event spooled” is status, not context. Packet prepared/emitted/action-associated/actually-used remain distinct.

## Backup, rollback and erasure

Surreal HTTP export/import and startup import are not application backup owners.

Memory backup:

1. stops Store mutations and new replay;
2. reconciles active replay and Store-write unknowns;
3. holds the cross-process spool publication lock only for one exact inventory/generation cut;
4. releases it so relay continues post-cut staging;
5. writes canonical typed pages for six tables plus selected-root blobs, deletion notices, cut pending/failed spool and sanitized config;
6. publishes a manifest with exact counts/digests/gaps.

Restore is exact rollback to one backup cut, not an invented merge of later Store rows. A healthy current Store first receives a safety backup; previous root remains until explicit retirement. Current deletion notices dominate backup content. Current post-cut spool merges by exact command bytes/disposition; failed never becomes pending.

Deletion fence prevents reintroduction but is not physical-erasure proof. Controlled previous roots/candidates/backups containing erased scope must be wholly deleted or erasure remains incomplete. Off-machine copies are outside initial controlled scope.

## Current controller V2 authority

Inspected authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

This is a specification target. `docs/roadmap.md` is its sole status tracker and all L0.1–L1.11 items remain unchecked.

Controller issue #200 is an active foundation blocker. Current binding allocation conflates current pointer with next immutable revision. In addition to failed observe→control, cancelled initial launch, cancelled queued resume and failed/unknown first observe attach can reuse/collide with already allocated revisions. PR #201 repairs validator fixtures only; it does not close allocator/schema semantics.

Controller issue #199 owns the later scoped Memory one-shot extension and remains blocked on V2 L0/L1 plus #200.

## One-shot inference Contract 0.10

One stable principal per Memory installation:

```text
principal_kind = memory_inference
client_id = memory:<random-stable-installation-id>
token_version = monotonic credential version
```

No owner, Agent, automation, plugin or no-token fallback.

Every controller mutation uses a global canonical ULID `WriteId` persisted before send. Call identity:

```text
WriteId
+ client_id
+ method
+ canonical semantic payload
```

Same identity returns the original/current call; mismatch is `id_conflict`; valid absent ID is first admission. There is no separate Operation ID or submission ledger.

Memory keeps one locked atomic external-WriteId generator state outside rollback Store roots. Rollback does not restore/reuse old generator state. Cancel, release and retention advance also receive durable pre-send WriteIds.

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

`retain_after_seq` is the guaranteed restore-completeness cut. `earliest_retained_seq` may be diagnostic but is not a guarantee. `inference.list(after, through)` has stable membership and returns `history_gap` whenever `after < retain_after_seq`, even if some rows still happen to exist.

Memory advances retention only after durable readback of its controlled backup-set change. The required cut is the minimum controller high-water among every locally retained restorable backup for the exact controller/client identity.

After rollback:

- in-cut jobs use their same WriteIds;
- post-cut calls are inventoried through one fixed high-water;
- out-of-target results are not adopted as cognition;
- each call is terminal/released or explicitly abandoned/erased through a durable cleanup record;
- new controller inference remains disabled until inventory is complete;
- Base remains available.

## Preserved goals, minimal mechanisms

| Goal | V3 minimum | Rejected default machinery |
|---|---|---|
| Resume work | Stable work address + retained observations | Universal Understanding State/checkpoint platform |
| Preserve source | Observation + exact blob/range + handles | Truth/Evidence registry and promotion ladder |
| Correct memory | Current revision + history + grounds | Global truth score/correction subsystem |
| Avoid repeated failure | Scoped negative memory or method revision | FailureFingerprint/quarantine platform |
| Deliver context | Direct current-work + lexical + optional vectors + bounded packet | Context service/packet database |
| Learn | Finite Memory job + exact recipe + one-shot call + later consumer | Permanent Dreamer/Task lifecycle |
| Optional capability | Internal connected vertical increment | Crate/process/manifest per noun |
| Privacy | Disclosure + actual send-owner check + finite copy cleanup | General Governor/approval platform |
| Recovery | One Store + spool + supervisor + typed backup/exact rollback | Recovery DB/global identity graph |
| Development | One issue/branch/integrator + terminal overlap disposition | Work-unit DB/agent scheduler |

## Implementation order

0. **Memory Slice 0:** exact Windows executable/root/process/IPC/Surreal/Store/file/backup/rollback/erasure/rotation/shutdown qualification.
1. **Base Slice 1:** real event → Store or spool → replay → restart → exact open.
2. **Base Slice 2:** qualified Claude relay, continuation, lexical retrieval, actual packet emission, notes/corrections/commitments and Base maintenance.
3. **Controller V2 L0/L1 + issue #200:** build the new foundation; do not extend V1.
4. **Inference P1a:** stable Memory principal, external WriteId state, receipts/calls/private copies, text runner, get/read/cancel/release/high-water/list/retention, one episode result changing later context.
5. **Inference P1b:** token rotation, stale-session fence and delayed credential retirement.
6. Independent embeddings, project views, documents, Research and additional hosts.
7. Advanced curation only after Base paths work.

Production code first. Run `cargo fmt --check` and minimum relevant changed-package Clippy after coherent increments. Broad deterministic/live/platform/load campaigns follow the connected product.

## Current open work

The active queue is in [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md). Immediate work:

1. synchronize Architecture/Implementation/Cognition and root entry points with Contract 0.10;
2. close controller #200 without hiding the pointer-absent/cancelled-candidate cases;
3. keep issue #199 blocked until V2 L0/L1 exists;
4. implement/qualify Memory Slice 0 and useful Base independently of controller inference.

## Evidence limits

Source/design evidence is not runtime qualification. No Windows Store, host capture, controller V2 foundation or inference runtime is implemented by these documents.

Memory PR #5325 currently fails before MergeCompile because machine-readable documentation evidence is absent; the same run also reports SurrealDB provisioner input failure. No fabricated evidence block is accepted.

Full release ZIP and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` remain unavailable as readable source material. Donor conclusions apply only to exact paths/revisions recorded in the registry.