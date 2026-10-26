# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-26 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is a greenfield implementation. The current `eliot-swarm-controller` V2 is also a fresh build; its V1 runtime is a donor and must not receive new Memory functionality.

## Reading order

1. [Architecture draft.10](ARCHITECTURE.md) — product purpose, authority owners, Base, extensions and invariants.
2. [Implementation draft.31](IMPLEMENTATION.md) — runtime, Store, Windows/process, durability, backup/restore and implementation sequence.
3. [Cognition draft.14](COGNITION.md) — current-work reconstruction, retrieval, learning and revision algorithms.
4. [Inference Contract 0.9](INFERENCE-CONTRACT.md) — sole normative Memory↔controller V2 boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — current decisions, gaps, source coverage and queue.
6. [Audit conclusion](AUDIT.md) and [requirements/source map](AUDIT-MAP.md) — historical evidence and stable source dispositions.

Architecture 10, Implementation 31, Cognition 14 and Contract 0.9 describe one product at increasing depth. None is implemented product code. `ANALYSIS-REGISTRY.md` is the only active work ledger; do not create another readiness report, donor dump or errata authority.

## Current authority

| Scope | Authority | State |
|---|---|---|
| Memory product/ownership | Architecture draft.10 | design only |
| Memory runtime/Store | Implementation draft.31 | design only |
| Cognitive algorithms | Cognition draft.14 | design only |
| Memory↔controller inference | Contract 0.9 | design only |
| Controller inspected baseline | `eliot-swarm-controller@c8c0ee122c98a01be86bc5296a22a389662a1c89`, merged PR #197 | V2 specification; L0/L1 runtime not built |

The old controller V1 `swarm-client`, Manager/Operator roles, generic Operation/artifact model, invented protocol-v2 hello and reconcile-or-admit path are donor history only. Current implementation target is controller V2 local JSON-RPC, SQLite WAL and canonical external ULID `WriteId` receipts.

## Product result

Eliot is useful only when accumulated experience changes the next decision:

```text
real source occurrence
→ durable observation/source bytes
→ current-work reconstruction
→ exact/lexical context and source handles
→ later action/outcome
→ revised claim/method/continuation
→ changed later context
```

Completion is:

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery
```

A type, receipt, fixture, report, issue, serializer or passing shape test is not product behavior by itself.

## Selected construction

One local Rust package/codebase provides supervisor, daemon and transient relay modes. One private inherited supervisor↔daemon channel carries only closed privileged intents. One private SurrealDB child owns application persistence. Optional capabilities are internal vertical increments or narrow outbound adapters.

Authority:

- **Daemon:** Memory operations, Editor-authenticated writes, replay/jobs, quiesce facts and public control.
- **Supervisor/installer:** executable/data-root identity, root/Owner credentials, migrations, Store lifecycle, installation selection and cutover.
- **Relay:** bounded host translation and durable staging when daemon ownership is unavailable.
- **Controller V2:** Memory caller authentication, inference configuration, provider invocation/readback, `WriteId` idempotency and temporary inference copies.
- **Host/controller:** external task/agent execution and user acceptance.

Memory may reference external work, but does not become a task manager, swarm controller, permission engine or research platform.

## Useful Base first

Base works without controller inference, vectors, document conversion, project graph or Research credentials. It provides:

- one real host capture path;
- exact retained source bytes and occurrence identity;
- notes, corrections and commitments with history;
- exact and lexical retrieval;
- current-work reconstruction;
- actual context emission through a supported host boundary;
- exact source opening;
- restart, spool, local backup/exact rollback and controlled erasure;
- direct status/control.

The first learning extension is one connected loop:

```text
retained episode
→ exact processing recipe
→ one controller V2 call with precommitted WriteId
→ typed create/revise/no-change/partial/error result
→ ordinary Memory revision
→ changed later context
→ exact release/cleanup state
```

Vectors, documents, project views, Research, additional hosts and richer cognition remain independent increments.

## Windows and Store baseline

Before an owned child runs, supervisor retains and verifies executable plus selected-root identity, creates the child suspended, compares the actual image, assigns Windows Job custody and resumes only after agreement.

First Store qualification target remains SurrealDB 3.3.4 with external RocksDB, `sync=every`, `--no-defaults`, sanitized environment, dynamic loopback listener and exact listener/peer ownership. Root/Owner are supervisor-only; daemon uses Editor.

One task owns each authenticated WebSocket and permits one exact in-flight request. Timeout, cancellation ambiguity, wrong/late response, close or protocol fault poisons the socket. Possible mutation send becomes `OUTCOME_UNKNOWN` and is reconciled by application identity.

JSON uses explicit bounded DTOs and fixed queries—no generic `Value`, `SELECT *` or broad CRUD surface. A path, PID, port, ready status, WebSocket 101, acknowledgement or clean process exit is not ownership/durability proof.

## Capture, spool and context

Relay builds one complete bounded `CaptureCommand` before IPC. Native/command identity identifies occurrence; digest verifies bytes.

```text
same command → daemon capture → matching Store readback → committed
no safe daemon ownership → exact durable spool publication → staged
staged command → daemon replays same operation → Store readback → remove pending body
```

Public outcomes are `committed | staged | unknown | rejected`. There is no successful `forwarded` without Store readback and no `staged` before file plus parent-directory durability/readback.

Context is useful only when rendered bytes cross the host contract. Keep distinct:

```text
prepared
emitted
action-associated when observable
used/influential: usually unknown
```

“Event spooled” or a local packet file is status, not context delivery.

### Brief backup spool cut

Backup must not hold the cross-process spool publication lock while paging Store rows or copying backup bytes:

1. stop new Store mutations/replay and reconcile active replay;
2. lock only long enough to capture or rotate one exact bounded spool inventory/generation cut;
3. release the lock;
4. relay continues post-cut staging separately;
5. backup copies exact immutable entries named by the cut;
6. missing/mismatched cut entry fails backup.

This is the selected R-127 correction; the exact Win32 primitive and crash qualification remain Slice 0 work.

## Controller V2 one-shot inference

Memory uses a dedicated principal:

```text
principal = memory_inference
client_id = memory:<stable-memory-installation-id>
token_version = positive monotonic credential version
```

It is not owner, Agent, project automation or script custody. Missing/invalid token never falls back to owner.

Memory durably creates the canonical ULID `WriteId` and exact request bytes/digest before first send. Call identity is:

```text
(client_id, WriteId, method, canonical semantic payload)
```

Lost reply, restart or restore repeats the same ID and exact bytes:

```text
same identity → original/current call
same ID, changed payload → id_conflict
valid absent ID → first admission only
expired/future ID → explicit refusal
```

There is no separately discovered Operation ID and no Memory submission ledger.

Controller reuses V2 `write_receipts` and adds only:

```text
memory_inference_clients
inference_calls
```

Prompts/results live in private call-owned files, not generic controller artifacts or receipts. One bounded runner performs at most one provider attempt. A possible send without exact readback becomes `unknown`, never automatic retry.

Exact surface, profile/disclosure rules, range reads, cleanup, retention and token rotation are in Contract 0.9.

## Backup, exact rollback and controller continuity

Memory backup is an application-owned typed cut over six tables, selected-root blobs, deletion notices, exact spool cut, sanitized configuration and controller inference cut. Manifest owns completeness. Surreal export/import and startup import are not selected.

Restore is exact rollback, not invented merge:

- healthy current Store first gets a safety backup;
- disaster mode records uninventoried current Memory state;
- previous root remains until explicit retirement;
- only deletion continuity and exact spool continuity merge automatically;
- post-backup Store rows/config/jobs are not copied silently.

Before backup, Memory stops new controller-backed admissions, persists every created `WriteId` and records exact per-client controller `admission_seq` high-water plus earliest retained sequence.

After restore:

- in-cut jobs reconcile using the same WriteIds;
- calls admitted after the backup cut are listed by admission sequence;
- post-cut results are not adopted into restored cognition without exact lost job/source mapping;
- each out-of-target call must be terminal/released or explicitly abandoned/erased;
- a pruned interval returns `history_gap`, never false empty;
- all new controller-backed inference remains disabled until inventory is complete and dispositioned.

If controller identity, credential or inventory is unavailable, Base may resume but inference remains disabled with `external_work_inventory_unavailable`. A new caller or reset controller does not silently clear the debt.

## Erasure and credential rules

A deletion fence prevents reintroduction; it does not prove physical deletion. Controlled scope includes current/previous/candidate roots, pending/failed spool, blobs, local backups and controller input/result copies. Initial Base deletes an entire offline generation containing erased scope or reports incomplete erasure.

Store password update alone does not revoke authenticated WebSocket sessions. Completion closes sockets, restarts Store and requires fresh daemon admission.

Controller client rotation preserves stable `client_id`, increments `token_version`, invalidates stale transports and retains previous credential file until later explicit retirement. Raw tokens, routing key and provider secrets never enter Memory backup or controller receipts/logs.

## Implementation order

### Slice 0

- exact Windows executable/root identities and ACLs;
- suspended launch, Job containment and inherited supervisor channel;
- relay named pipe and mutual attestation;
- Surreal binary/profile/listener/peer/bootstrap/roles/socket owner;
- migrations, strict schema, fixed DTOs, conflicts and applied-before-fsync unknown readback;
- immutable publication and mutable selection;
- capture/spool/replay barrier;
- brief spool cut, application backup/exact rollback and physical erasure;
- Store credential revocation and bounded shutdown.

### Base Slice 1

Supervisor/daemon/Store composition, capture/blob/spool/replay/status/restart/exact open.

### Base Slice 2

Qualified Claude relay, continuation, actual packet emission, lexical retrieval, notes/corrections/commitments, backup/rollback/erase.

### Controller dependency

Controller V2 must first implement its own L0/L1 foundation. Do not patch the legacy runtime to unblock Memory.

### P1a

Dedicated Memory principal, `client.identity`, `WriteId` receipts, profiles/disclosure, private copies, `inference_calls` runner, get/range-read/cancel/release/high-water/list, non-disclosing owner erase, one Memory adapter and one later context consumer.

### P1b

Same owner `WriteId`, deterministic token re-derivation, stale transport reaping, pending/current/previous credential selection and delayed retirement.

Embeddings, HTTPS and richer provider readback come later.

## Verification order and proof ceiling

During implementation:

```text
write connected production code first
→ cargo fmt --check
→ minimum relevant package build/Clippy
→ continue vertical path
```

Broad tests, live harness campaigns, fault injection, platform matrix and load/retention qualification start after the connected product exists.

Current proof ceiling:

- current owner documents are synchronized on 10/31/14/0.9;
- selected source and donor paths were inspected;
- current controller V2 specification and PR #197 were read;
- no Memory V3 runtime, controller inference extension, Windows Store run, backup round-trip, host capture or learning loop exists yet.

## Frozen non-goals

Do not:

- implement Memory inference in controller V1;
- create another Task/Attempt/workflow/proof platform;
- authenticate Memory through owner/Agent/automation/no-token fallback;
- retry uncertain provider execution with a new `WriteId`;
- place content-bearing prompts/results in generic artifacts/receipts/logs;
- hold spool publication lock during long backup work;
- infer empty controller inventory from a retention gap;
- merge post-backup Store rows without retained change log/conflict policy;
- claim physical erasure while any controlled copy remains;
- silently fall back provider/model/destination/Store version/engine;
- treat documentation or CI shape as completed product behavior.
