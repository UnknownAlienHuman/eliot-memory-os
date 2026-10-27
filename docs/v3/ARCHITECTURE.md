# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.19 · 2026-10-27 · normative design for the greenfield rewrite.**

V1/V2 Memory implementations are donors. V3 is a new implementation. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its legacy runtime is donor-only.

This document owns product purpose, authority and invariants. [Implementation](IMPLEMENTATION.md) owns runtime, Store and maintenance. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.18](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only active work ledger.

## 0. External dependency

Controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
```

Its V2 roadmap remains unimplemented. Issue #200 must separate monotonic binding allocation, selected pointer and native effect before L0/L1. Issue #199 implements Memory inference only after that foundation. Base does not wait.

## 1. Purpose and completion

Eliot makes accumulated experience useful at the next decision:

```text
observe exact source
→ reconstruct current work
→ supply applicable context
→ observe action/result
→ revise memory or method
→ use the revision later
```

Product value is visible when Eliot restores work without inventing state, prevents known failures from silently returning, exposes constraints/exceptions/unknowns before action, learns from outcomes, preserves source/history and remains useful without optional inference.

A mechanism enters V3 only after its real caller, owner, durable result or typed unknown and consumer are named.

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Types, ports, fixtures, receipts, reports and compilation are not product behavior by themselves.

## 2. Ownership

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance | Human and host/controller |
| Agent/task/tool execution | Host/controller |
| Host event translation and context emission | Narrow relay/adapter |
| Observations, revisions, retrieval, context, outcomes and finite jobs | Memory daemon |
| Store mutations, replay and quiesce evidence | Memory daemon |
| Controller-mutation serialization, backup IDs/records, dependency snapshots, bounded restore leases and backup cleanup | Daemon backup-set owner |
| Executable/root identity, Store root/Owner credentials, migrations, candidate process/root and cutover | Supervisor/installer |
| Interpretation, consolidation and method improvement | Memory learning handlers |
| One-shot authentication, profiles, provider execution/readback, receipts and temporary inference copies | Controller V2 |
| Persistence/indexes/transactions | Private SurrealDB Store |

Public control reaches the daemon. Privileged root/Owner/process/cutover effects cross one inherited typed channel. Supervisor independently resolves approved resources; it never accepts arbitrary SQL, argv, endpoint, path or secret from daemon. Daemon never receives root or Owner credentials.

Memory links external work but is not another task manager, permission engine, swarm controller or acceptance authority.

### 2.1 Dreamer is a role

Dreamer means model-assisted interpretation for one finite Memory job. It is not a permanent process, provider, scheduler, special database or canonical writer.

### 2.2 One-shot inference is not Agent orchestration

Memory uses one dedicated `memory_inference` principal and precommitted global `WriteId`s. It creates no controller Agent, binding, turn, command, Goal, automation, Task or review lifecycle.

### 2.3 Stable caller, credential and effects are distinct

```text
client_id = memory:<stable-random-installation-id>
token_version = current credential version
call identity = WriteId + client_id + method + canonical payload
```

Client ID survives rollback and rotation. Token version authenticates but does not own calls. Memory owns one monotonic WriteId state outside rollback roots. Unknown old effects are read back or retained unknown; a new ID is never recovery.

### 2.4 Profiles and disclosure belong to the send owner

Controller owns versioned connection/profile, provider credential reference, actual destination, model and finite limits. Memory chooses a profile name and reduces input to `local_only | external_allowed`. Controller checks actual destination before provider I/O. No silent fallback exists.

## 3. Product shape

Initial product is one Rust codebase/executable with supervisor, daemon and transient relay modes; one private inherited channel; one active external SurrealDB child; at most one disposable restore candidate; installation-scoped external-ID and backup authority outside rollback roots; and optional outbound clients constructed only when enabled.

A new process, crate, table or registry requires independently owned state, dependency, deployment or failure boundary.

### 3.1 Layers, not process tiers

1. domain values and pure transformations;
2. application operations;
3. external I/O adapters;
4. surfaces/runtime composition.

Internal calls use typed Rust values. Serialization belongs only at Store/process/network boundaries.

### 3.2 Useful Base and additive capabilities

Base works without inference, vectors, converters or Research. It provides real host capture, exact source/occurrence identity, notes/corrections/commitments, exact and lexical retrieval, addressed current work, actual context emission, exact source opening, restart/spool, local backup/rollback/erasure and direct control.

First learning closes one loop from retained episode through one controller call to a Memory revision consumed by later context and dependency-aware cleanup.

Vectors, views, documents, Research and additional hosts are independent increments sharing the same records/jobs/revisions/context.

### 3.3 First host is narrow

Initial Claude events:

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

Claude JSON is adapter input, not Memory domain state. Prompt/session boundaries emit actual context. Final messages are retained directly. Compact summary is derived representation. Enforcement hooks are outside Base.

## 4. Identity and memory invariants

- Work identity is project/workspace plus actual task or actor/session; path/branch/commit are environment.
- Occurrence identity is native event identity or relay command ID; digest verifies bytes and does not merge occurrences.
- Accepted source is preserved before interpretation; excerpts and normalized fields are projections.
- Source, representation and claim have distinct identities.
- Current revision and history never substitute for each other.
- Origin, reuse scope and disclosure are independent.
- Grounds groups encode conjunction/alternatives; navigation is not evidence; cycles add no support.
- Support, retrieval exposure and advisory influence are separate.
- Exact `open` requires one handle and reports exact identity/revision/range/digest/gaps/relations/continuation. Historical handles never fall forward.
- Reduce exposure, withdraw influence, supersede/refute, retire backup and physically erase are different operations.

Deletion notices, membership tombstones and backup terminal markers prevent false reintroduction/inventory/restore claims but are not physical deletion proof.

## 5. Retrieval, context and learning

Address current work before similarity search. Candidate arms are direct/address/exact/lexical/vector/grounds/relation/method and are unioned before final selection.

Lexical retrieval is one bounded top-K Store snapshot per call. BM25 score depends on the current corpus; V3 does not expose a durable page cursor across calls. Equal scores use canonical-ID tie-break. Score ranks candidates only; it does not establish truth/support/applicability.

A decision packet contains current goal/progress, exact corrections, open commitments, applicable methods with exceptions, relevant episodes, dissent/unknowns and source handles. Exact values and qualifications travel together.

Prepared, emitted, action-associated, used and successful are separate facts.

A project view is a versioned answer over examined scope. Failed refresh leaves prior qualified view and exact source access available.

No-change is valid only after completed cognitive work on supplied input. Rejection, no result, malformed output, truncation, omitted coverage or unknown execution is not no-change. Cleanup is separate from cognitive result.

## 6. Store and schema authority

Initial Store target is SurrealDB 3.3.4, external RocksDB and explicit `sync=every`. Base owns six `SCHEMAFULL` tables plus immutable blobs:

```text
stream
observation
memory
memory_history
link
job
```

Application identity crossing JSON is a canonical bounded string; Surreal record IDs remain internal. Queries are fixed, bound and explicitly projected. No generic `Value`, `SELECT *` or raw SurrealQL boundary exists.

Migration bundle identity includes a format version, runner protocol, exact transactional wrapper template, ordered UTF-8/LF DDL assets and expected-catalog template. Bound generation/digest values are outside the preimage, avoiding self-reference.

Schema admission uses plain `INFO FOR DB` and `INFO FOR TABLE` maps. `STRUCTURE` is forbidden as unstable internal output. The client sorts parsed owned map keys and compares exact pinned-version server-canonical `DEFINE` strings, not raw JSON byte order. Roles/credentials are admitted separately.

Base full-text queries use numbered match references when score is requested and separate FULLTEXT indexes over observation excerpts and Memory text.

## 7. Backup authority

### 7.1 Concrete owners and lock order

Daemon owns controller-mutation and backup-set owners. Supervisor owns candidate process/root and final cutover.

```text
close/drain controller mutation
→ enter backup-set transition
→ publish/read back final fence authority
→ leave transition
→ reopen mutation admission
```

No release/retention can cross a newly visible fence. Terminal transitions remove pins, so stale pre-terminal reads are conservative.

### 7.2 Atomic first visibility

Backup ID is `b_` plus 32 lowercase hexadecimal characters from 128 OS-random bits. Daemon writes canonical fence inside a private same-parent temp directory, flushes file+directory, no-replace renames the directory to final ID, flushes parent and reopens final directory/fence no-follow.

Final directory never appears empty. Pre-rename temp is non-pinning cleanup debt. Post-rename sync/readback uncertainty is publication-unknown and pins after reconciliation.

### 7.3 Terminal records

Self-contained `abort.json` and `retire.json` remain terminal after content cleanup and prevent backup-ID reuse. Abort is pre-publication only; retire is published-backup only; both/malformed/mismatched combinations fail closed. Terminalization is not erasure.

### 7.4 Bounded restore lease

Daemon lease holds a logical lease plus final-directory/fence/manifest handles opened no-follow with read sharing only. Before candidate work, manifest part count, per-part bytes, total bytes and canonical unique paths must satisfy finite limits.

Parts are streamed one at a time: open one no-follow read handle with write/delete sharing denied, verify path/identity/length/digest, copy+verify into candidate, close, then continue. V3 never retains an unbounded handle set.

The logical owner blocks daemon retirement/cleanup. A final terminal/manifest identity recheck occurs immediately before cutover. Daemon/channel loss forces supervisor to kill/reap/discard candidate before another daemon or cutover. A scan without a held lease is not restore authority.

### 7.5 Controller dependencies

Backup cut dispositions every call/cancel/release/retention ID. Every admitted call is `controller_closed` or `controller_dependent`. Published non-retired backups and unresolved fences pin dependent copies and post-cut retention. Store maintenance rows are status mirrors only.

Restore is exact rollback, not invented merge. Closed jobs restore from backup facts; dependent jobs require exact call/copy; post-cut calls are inventoried over one fixed interval and never adopted as restored cognition. Base remains usable when inference continuity is unavailable.

## 8. Reliability, privacy and control

Persist adjacent states separately: committed/staged/unknown capture; prepared/emitted context; complete/paged/missing/damaged reads; inference prepared/admitted/sending/settled/unknown/abandoned; closed/dependent controller state; backup staging/preparing/publication-unknown/published/aborted/retired; release/retention pins; restore lease/limit/candidate state; physical cleanup and owner-action debt.

Acknowledgement is not completion. Provider body is not decoded proposal. Backup plan digest is not manifest digest. Rename without parent durability/readback is not publication. Terminal marker is not erasure.

Secrets remain with their owners. Controller owns provider credentials/token issuance; supervisor owns Store root/Owner references; daemon receives Store Editor and current Memory caller credential reference only.

Direct control provides status/open/configure/pause/cancel/correct/withdraw/erase/backup/restore/rotate/retire/shutdown. Status derives from actual process, Store, schema catalog, spool, controller and installation-record readback.

## 9. Non-goals

V3 does not add without demonstrated need:

- public supervisor API or generic admin bus;
- arbitrary SQL/path/argv/secret over inherited IPC;
- another task manager, workflow engine, semantic DB or provider stack;
- controller Agent/Goal/automation/script/MCP for one-shot inference;
- permanent Dreamer process;
- truth/skill/outcome/packet registries;
- general Governor/approval/proof platform;
- service/crate/manifest per noun;
- controller backup-pin service or second mutation ledger;
- generic Surreal protocol/value reimplementation;
- rollback-derived external IDs or backup IDs;
- empty final backup-directory reservation;
- unbounded restore part handles;
- unstable `INFO ... STRUCTURE` as schema API;
- durable lexical cursor without a retained corpus snapshot;
- first admission of old absent calls from backup;
- Memory impersonation of controller-owner erase.

## 10. Product evidence and order

Base evidence:

```text
real host event
→ Store ownership or durable stage
→ replay when staged
→ restart
→ continuation/context or retrieval
→ exact source open
```

Backup evidence:

```text
final directory first visible with exact fence
→ finite manifest limits admitted
→ every external ID has cut disposition
→ plan/parts/manifest exact
→ parts streamed with bounded handles
→ final lease recheck precedes cutover
→ crash cannot cut over stale candidate
→ terminal state survives cleanup
```

Implementation order:

1. Memory Slice 0 physical/Store/schema/backup qualification;
2. useful Base capture/replay/open;
3. first qualified host/context path;
4. controller #200 plus V2 L0/L1;
5. Contract 0.18 text-inference P1a;
6. credential rotation P1b;
7. independent vectors/views/documents/Research/hosts;
8. advanced curation after connected Base.

Production code comes first. Run formatting and minimum changed-package Clippy after coherent increments. Broad qualification follows connected product.