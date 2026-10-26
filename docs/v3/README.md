# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-26 · normative design, not implemented code.**

V1/V2 Memory implementations are donors. V3 is a greenfield implementation. The current controller is also being rebuilt as V2; its retired V1 runtime is a donor, not the target of Memory integration.

## Reading order

1. [Architecture](ARCHITECTURE.md) — product purpose, authority owners, Base, extensions and non-goals.
2. [Implementation](IMPLEMENTATION.md) — Memory runtime, Store, Windows/process, durability, backup/restore and implementation sequence.
3. [Cognition](COGNITION.md) — current-work reconstruction, retrieval, learning and revision algorithms.
4. [One-shot inference contract](INFERENCE-CONTRACT.md) — sole normative Memory↔controller boundary.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — current decisions, gaps, source coverage and queue.
6. [Audit conclusion](AUDIT.md) and [requirements/source map](AUDIT-MAP.md) — historical evidence and stable source dispositions.

`ANALYSIS-REGISTRY.md` is the only active work ledger. Do not create another readiness report, donor inventory or errata authority.

## Current authority and synchronization status

| Scope | Current authority | Status |
|---|---|---|
| Memory product/ownership | Architecture draft.9 | Design only |
| Memory runtime/Store | Implementation draft.30 | Design only |
| Cognitive algorithms | Cognition draft.13 | Design only |
| Memory↔controller inference | Contract 0.9 | Current cross-repository boundary |
| Controller inspected baseline | `eliot-swarm-controller@c8c0ee122c98a01be86bc5296a22a389662a1c89` / merged PR #197 | V2 specification; L0/L1 runtime not built |

Contract 0.9 replaces the previous V1-specific controller target. Older passages in Architecture/Implementation/Cognition that name `swarm-client`, Manager/Operator roles, protocol-v2 hello, `credential_id`, generic Operation/artifact rows or reconcile-or-admit are **superseded for the controller boundary** and must be replaced before implementation starts. The registry records this as R-024 `PARTIAL`; it is not hidden as synchronized.

## Product result

Eliot is useful when accumulated experience changes the next decision:

```text
real source occurrence
→ durable observation/source bytes
→ current-work reconstruction
→ exact/lexical context and source handles
→ later action/outcome
→ revised claim/method/continuation
→ changed later context
```

A type, receipt, fixture, report, issue or serializer is not product behavior by itself. Completion is:

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery
```

## Selected construction

One local Rust package/codebase provides:

- supervisor mode;
- daemon mode;
- transient relay mode;
- ordinary internal modules;
- one private inherited supervisor↔daemon channel;
- one private SurrealDB application Store;
- optional outbound adapters only when enabled.

A new process is justified only by a real external runtime or failure boundary. A new crate/table/registry is justified only by a current caller and independent owned state.

### Authority owners

- **Memory daemon:** application operations, capture/replay/jobs, Editor-authenticated Store writes, quiesce facts and public control.
- **Supervisor/installer:** executable/data-root identity, root/Owner credentials, migrations, Store lifecycle, installation selection, cutover and privileged maintenance.
- **Relay:** bounded host event translation and durable staging when daemon ownership is unavailable.
- **Controller V2:** caller authentication, inference configuration, provider invocation/readback, `WriteId` idempotency and temporary controller copies.
- **Host/controller:** external agent/task execution and user acceptance.

Memory may reference external tasks/results, but does not become a task manager, swarm controller, permission engine or research platform.

## Useful Base before model features

Base works without controller inference, vectors, document conversion, project graph or Research credentials. It must provide:

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
→ one controller V2 inference call
→ typed create/revise/no-change/partial/error result
→ ordinary Memory revision
→ changed later context
→ controller copies released or explicit cleanup debt
```

Vectors, documents, project views, Research and richer cognition remain independent increments.

## Process and Store baseline

Before an owned child runs, supervisor retains and verifies executable plus selected-root identity, creates the child suspended, compares the actual image, assigns Windows Job custody and resumes only after agreement.

First Store qualification target remains SurrealDB 3.3.4 with external RocksDB, canonical selected-root URL, `sync=every`, `--no-defaults`, sanitized environment, dynamic loopback listener and exact listener/peer ownership. Root/Owner remain supervisor-only; daemon uses Editor.

One task owns each authenticated WebSocket, permits one exact in-flight request and poisons the socket after timeout/cancellation ambiguity, wrong/late response or protocol fault. JSON uses explicit DTOs and fixed bounded queries—no generic `Value`, `SELECT *` or broad CRUD surface.

A path, PID, port, HTTP status, WebSocket 101, clean process exit or acknowledgement is not ownership/durability proof.

## Capture, spool and context

The relay builds one complete bounded `CaptureCommand` before IPC. Native/command identity identifies the occurrence; digest verifies bytes.

```text
same command → daemon capture → matching Store readback → committed
no safe daemon ownership → exact durable spool publication → staged
staged command → daemon replays same operation → Store readback → remove pending body
```

Public outcomes are `committed | staged | unknown | rejected`. There is no successful `forwarded` state without Store readback and no `staged` state before file plus parent-directory durability/readback.

### Backup spool cut correction

Backup must **not** hold the cross-process spool publication lock while paging Store rows or copying backup bytes. The selected contract is:

1. daemon stops new Store mutations/replay and reconciles the active replay item;
2. acquire the publication lock only long enough to capture/rotate one exact bounded spool inventory/generation cut;
3. release the lock;
4. relay continues publishing post-cut entries separately;
5. backup copies only the immutable identities/digests recorded in the cut;
6. missing/mismatched cut entry fails the backup instead of being silently omitted.

The exact Windows file primitive and crash cases remain Slice 0 implementation work (R-127).

Context is useful only when rendered bytes cross the host contract. Keep distinct:

```text
prepared
emitted
associated with a later action when observable
used/influential: usually unknown
```

“Event spooled” or a local packet file is status, not context delivery.

## Controller V2 one-shot inference

The current controller authority uses local JSON-RPC, SQLite WAL and canonical external ULID `WriteId` receipts. Existing V1 `swarm-client`/Operation code is selected for deletion and must not receive new Memory functionality.

Memory uses a dedicated controller principal:

```text
principal = memory_inference
client_id = memory:<stable-memory-installation-id>
token_version = positive monotonic credential version
```

It is not owner, Agent, project automation or script custody. Missing/invalid token never falls back to owner.

Before first send, Memory persists the exact `WriteId` and request bytes/digest. Call identity is:

```text
(client_id, WriteId, method, canonical semantic payload)
```

Lost reply/restart/restore repeats the same ID and exact bytes:

```text
same identity -> original call/current state
same ID, changed payload -> id_conflict
valid absent ID -> first admission only
expired/future ID -> explicit refusal
```

There is no unknown separately discovered Operation ID and no Memory submission ledger.

Controller reuses `write_receipts` and adds only:

```text
memory_inference_clients
inference_calls
```

Prompts/results live in private call-owned controlled files, not generic controller artifacts/receipts. One bounded runner performs at most one provider attempt. Possible send without exact readback becomes `unknown`, never automatic retry.

Exact surface, profile/disclosure rules, range reads, cleanup and rotation are in [Contract 0.9](INFERENCE-CONTRACT.md).

## Backup, rollback and controller continuity

Memory backup is an application-owned typed cut over six tables, selected-root blobs, deletion notices, exact spool cut and sanitized configuration. Manifest owns completeness. Surreal export/import and startup import are not selected.

Restore is exact rollback, not invented merge:

- healthy current Store first gets a safety backup;
- disaster mode records uninventoried current Memory state;
- previous root remains until explicit retirement;
- only deletion continuity and exact spool continuity are merged automatically;
- post-backup Store rows/config/jobs are not copied silently.

### Controller external-work denominator

Before backup, Memory stops new inference admissions, persists every created WriteId and records the exact per-client controller `admission_seq` high-water plus earliest retained sequence.

After restore:

- in-cut jobs reconcile with the same WriteIds;
- calls admitted after the backup cut are listed by admission sequence;
- their results are not adopted into restored cognition without the lost exact job/source mapping;
- every out-of-target call must be terminal/released or explicitly abandoned/erased;
- a pruned interval returns `history_gap`, never false empty;
- all new controller-backed inference remains disabled until the inventory is complete and dispositioned.

If controller identity/credential/inventory is unavailable, Base may resume but inference remains disabled with `external_work_inventory_unavailable`. A new caller or reset controller does not silently clear the debt.

## Erasure and credential rules

A deletion fence prevents reintroduction; it does not prove physical deletion. Controlled scope includes current/previous/candidate roots, pending/failed spool, blobs, local backups and controller input/result copies. Initial Base deletes an entire offline generation containing erased scope or reports incomplete erasure.

Store password update alone does not revoke authenticated WebSocket sessions. Completion closes privileged/runtime sockets and restarts Store before daemon re-admission.

Controller client rotation preserves stable `client_id`, increments `token_version`, invalidates stale transports and retains previous credential file until later explicit retirement. Raw tokens/provider secrets never enter Memory backup or controller SQLite/receipts/logs.

## Implementation order

### Slice 0 — qualify hard boundaries

- exact Windows executable/root identities and ACLs;
- supervisor↔daemon inherited channel and relay named pipe;
- Surreal binary/profile/listener/peer/bootstrap/roles/socket owner;
- migrations, strict schema, conflicts and applied-before-fsync unknown readback;
- immutable publication vs mutable selection;
- brief spool cut, application backup/exact rollback and physical erasure;
- Store credential revocation and bounded shutdown.

### Base Slice 1

Supervisor/daemon/Store composition, capture/blob/spool/replay/status/restart/exact open.

### Base Slice 2

Qualified Claude relay, continuation, actual packet emission, lexical retrieval, notes/corrections/commitments, backup/rollback/erase.

### Controller V2 dependency

Controller must first implement its own V2 L0/L1 foundation. Do not patch the legacy runtime to unblock Memory.

### P1a — connected text inference

Dedicated Memory principal, `client.identity`, `WriteId` receipts, profiles/disclosure, private copies, `inference_calls` runner, get/range-read/cancel/release/high-water/list, non-disclosing owner erase, one Memory adapter and one later context consumer.

### P1b — token rotation

Same owner WriteId, deterministic token re-derivation, stale transport reaping, pending/current/previous selection and delayed retirement.

Embeddings, HTTPS and richer provider readback come later.

## Verification order and proof ceiling

During implementation:

```text
write connected production code first
→ cargo fmt --check
→ minimum relevant package build/Clippy
→ continue vertical path
```

The complete test/live/platform/load campaign starts only after the connected product exists. Documentation, source review, schema execution, Clippy and fixtures do not establish runtime correctness.

Current proof ceiling:

- architecture/design decisions are recorded;
- selected donor/source paths were inspected;
- controller V2 current specification and PR #197 were read;
- no Memory V3 runtime, controller inference extension, Windows Store run, backup round-trip, host capture or learning loop exists yet.

## Frozen non-goals

Do not:

- implement against controller V1;
- create another Task/Attempt/workflow/proof platform;
- authenticate Memory through owner/Agent/automation/no-token fallback;
- retry uncertain provider execution with a new WriteId;
- place content-bearing prompts/results in generic artifacts/receipts/logs;
- hold spool publication lock during long backup work;
- infer empty controller inventory from a retention gap;
- merge post-backup Store rows without a retained change log/conflict policy;
- claim physical erasure while any controlled copy remains;
- silently fall back provider/model/destination/Store version/engine;
- treat documentation/CI shape as completed product behavior.
