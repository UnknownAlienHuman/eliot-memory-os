# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.20 · 2026-10-28 · design for the greenfield rewrite, not implemented behavior.**

V1/V2 Memory implementations are donors. This document owns purpose, responsibility
and invariants. [Implementation](IMPLEMENTATION.md) owns runtime, Store, maintenance
and build order; [Cognition](COGNITION.md) owns algorithms; the
[Inference contract](INFERENCE-CONTRACT.md) owns the proposed external call boundary.
[ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only work ledger.

## 0. External dependency

Controller foundation and Memory inference are different capabilities. The inspected
controller has an implemented foundation but lacks the Memory principal and inference
handlers; exact source and adaptation requirements are maintained in
[Inference §0](INFERENCE-CONTRACT.md#0-authority-and-prerequisites).

Base has no controller dependency. Model-assisted learning requires the scoped inference
extension, not another implementation of controller L0/L1 or an Agent-binding programme.
Never route around missing inference through owner credentials, Agent tasks or legacy V1.

## 1. Purpose and completion

Eliot makes accumulated experience useful at the next decision:

```text
preserve exact observation
→ reconstruct current work
→ supply applicable context
→ observe action/result
→ revise memory or method
→ use the revision later
```

Value means restored work without invented state, remembered failures and exceptions,
explicit unknowns, learning from outcomes and preserved source/history. Optional
inference must not be necessary for ordinary capture, retrieval or context.

Add a mechanism only for a named caller, owner, durable result or typed unknown and
actual consumer. Completion includes restart/readback where persistence matters.
A type, port, fixture, receipt, report, branch or passing compile alone is intermediate.

## 2. Ownership

| Responsibility | Owner |
|---|---|
| Goals, permissions and acceptance | Human and host/controller |
| Agent/task/tool execution | Host/controller |
| Event translation and actual context emission | Narrow host relay |
| Observations, revisions, retrieval, context, outcomes and finite jobs | Memory daemon |
| Store mutations, replay and quiesce | Memory daemon |
| External-call serialization and backup dependency checks | Daemon controller-mutation owner |
| Backup records, transitions, bounded restore leases and cleanup | Daemon backup-set owner |
| Executable/root identity, Store root/Owner credentials, migration, candidate and cutover | Supervisor/installer |
| Interpretation, consolidation and method improvement | Memory learning handlers |
| Scoped one-shot call, provider execution/readback and private inference copies | Controller extension |
| Persistence, indexes and transactions | Private SurrealDB Store |

Public control reaches the daemon. Privileged process/root/Owner/cutover effects cross
one inherited typed channel. Supervisor independently resolves approved resources;
it does not accept arbitrary SQL, argv, endpoint, path or secret from the daemon.
Daemon never receives root or Owner credentials.

Dreamer is a role performed for one finite semantic job, not a permanent process,
provider stack, scheduler, special database or canonical writer. A controller call is
not an Agent/session/Goal lifecycle. Memory links external work but does not own it.

Stable client identity, credential version and call identity remain separate. Rotation
or rollback cannot authorize a second uncertain effect. The send owner controls actual
profile/destination/credentials; a profile name is not permission for silent fallback.
Detailed identities and readback belong to the inference contract, not a second model here.

## 3. Product shape

One Rust codebase/executable provides supervisor, daemon and transient relay modes.
One active external SurrealDB child owns persistence. At most one isolated disposable
candidate exists during restore. External-ID and backup authority live outside rollback
Store roots. Optional outbound adapters are constructed only when enabled.

Layers are domain values/pure transformations → application operations → I/O adapters
→ surfaces/runtime composition. Internal calls use typed Rust values; serialization
belongs at Store/process/network boundaries.

A process, crate, table or registry needs an independently owned state, dependency,
deployment or failure boundary. The target topology is not an instruction to scaffold
all future capability owners before the first caller exists.

### 3.1 Useful Base

Base captures real host events; preserves source/occurrence identity; supports notes,
corrections and commitments; reconstructs addressed work; performs exact and lexical
retrieval; emits actual context; opens exact sources; survives restart/spooling; and
provides local backup, rollback, erasure and direct control. It needs no inference,
vectors, converters or Research. These are Base completion requirements, not all
prerequisites for starting the first capture/open increment.

### 3.2 Additive learning

The first learning loop turns a retained episode and exact processing method into one
controller call, then a Memory revision consumed by later context. Cleanup and backup
continuity are part of enabling that call, not claims inferred from a returned model body.
Vectors, views, documents, Research and other hosts reuse the same records/jobs/revisions.

### 3.3 First host is narrow

The first Claude profile selects SessionStart, UserPromptSubmit, PostToolUse,
PostToolUseFailure, Stop, SubagentStop, PostCompact and SessionEnd. Verify the installed
host contract before enabling each event. Host JSON is adapter input, not domain state.
Session/prompt boundaries emit actual context; final messages are retained directly;
compact summaries are derived representations. Enforcement hooks are outside Base.

## 4. Identity and memory invariants

- Work address is project/workspace plus actual task or actor/session; path/branch/commit
  are environment, not task identity. Late results retain issue-time binding.
- Occurrence identity is native event identity or relay command ID. Digest verifies
  bytes; it does not merge distinct occurrences with equal content.
- Preserve accepted source before interpretation. Source, representation and claim
  have distinct identities; excerpts/normalization cannot replace original bytes.
- Current revision and history never substitute for each other. Exact historical
  opening cannot fall forward, rerun inference or resurrect erased content.
- Origin, reuse scope and disclosure are independent. Grounds groups express required
  conjunctions and alternatives; navigation and cycles do not establish support.
- Support, retrieval exposure and advisory influence are separate. Reducing exposure,
  withdrawing influence, superseding/refuting, retiring backup and erasing bytes differ.

Deletion notices, membership tombstones and terminal backup records prevent false
reintroduction/inventory/restore claims; none is physical deletion proof.

## 5. Retrieval, context and learning

Address current work before similarity search. Union independently bounded direct,
address, exact-cue, lexical, optional vector, grounds/relation and method candidates
before final selection. Apply scope before arm limits.

Lexical ranking uses one bounded statement snapshot, not a durable BM25 cursor across
corpus changes. Score orders candidates but proves neither truth nor applicability.

A packet preserves current goal/progress, exact corrections, open commitments,
applicable methods with exceptions, relevant episodes, dissent/unknowns and exact
source handles. Negation, version and contraindications travel with the value.
Prepared, emitted, action-associated, used and successful are different facts.

A project view is a versioned answer over examined scope. Failed refresh leaves the
previous qualified view and exact source access available. No-change requires completed
cognitive work on supplied input; rejection, missing/malformed/truncated output or
unknown execution is not no-change. Cleanup is separate from cognitive outcome.

## 6. Store and schema authority

The selected initial target is external SurrealDB 3.3.4/RocksDB with explicit
`sync=every`, six `SCHEMAFULL` tables (`stream`, `observation`, `memory`,
`memory_history`, `link`, `job`) and immutable blobs. These are design selections,
not a claim of a running or qualified Store.

Application IDs crossing JSON are bounded canonical strings; native record IDs stay
internal. Queries are fixed, bound, explicitly projected and decoded through DTOs.
There is no user-supplied SQL, generic CRUD or `SELECT *` application boundary.

[Implementation §4–6](IMPLEMENTATION.md#4-migration-0001-and-schema-authority) owns IDs,
field invariants, indexes, schema-bundle identity, catalog comparison, queries and
transactions. Source/upstream-test evidence cannot qualify the complete Eliot wrapper.
Do not copy these internal details into the controller protocol.

## 7. Backup authority

The daemon owns backup records and dependency decisions; supervisor owns candidate
process/root and cutover. Installation records outside rollback roots outrank restored
Store maintenance mirrors.

Required invariants: a final backup first appears with its fence; ambiguous publication
pins conservatively; terminal records survive content cleanup; restore validates finite
limits and retains a bounded lease; parts are verified one at a time; final recheck
precedes cutover; daemon/channel loss discards a candidate before restart/cutover.
Restore is exact rollback, never an invented merge with future cognition. Current
deletion notices dominate backup content.

[Implementation §8](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle) is the sole owner
of physical publication, plan/terminal codecs, lease/custody and rollback procedures.
The [inference contract](INFERENCE-CONTRACT.md#8-memory-backup-interaction) adds the
external-effect cut and release/retention rules only when controller calls exist.
Base backups must not contact a controller that Base does not use.

## 8. Reliability, privacy and control

Persist adjacent states separately: committed/staged/unknown capture; prepared/emitted
context; complete/paged/missing/damaged reads; admitted/sending/settled/unknown calls;
backup publication/terminal state; lease/candidate state; physical cleanup and owner debt.
Acknowledgement is not completion; a body is not a decoded proposal; a terminal marker
is not erasure; loss after possible effect is not proof of rollback.

Secrets stay with their owners. Controller owns provider/caller credential issuance;
supervisor owns Store root/Owner references; daemon receives Editor and its scoped
Memory caller credential reference only. Restrictive OS access is not a portable
encrypted-backup guarantee or hostile-same-user sandbox.

Control supports status/open/configure/pause/cancel/correct/withdraw/erase/backup/restore/
rotate/retire/shutdown as their owners are implemented. Status uses actual readback;
unavailable features remain explicit rather than empty successful handlers.

## 9. Non-goals

No second task manager, permission/acceptance engine, semantic DB, provider stack,
permanent Dreamer, generic admin bus or proof platform. No crate/manifest per noun,
truth/skill/packet registry, controller backup service, second mutation ledger or
compatibility executor. Do not copy a dependency's lifecycle machinery to obtain one
model call. Reuse an existing owner before creating a new one.

## 10. Product evidence and order

Build the connected increments in
[Implementation §11](IMPLEMENTATION.md#11-implementation-sequence); it alone owns their
order. Start with capture → durable Store/spool → replay/restart → exact open, then host
context and Base maintenance. Complete the inference boundary before enabling learning.
A complete backup/crash/load campaign is not a condition for writing the first path.

Preserve safety checks at the boundary that needs them: no unverified credentials sent,
no false durable capture, no unleased restore/cutover, no uncertain external effect retried.
Production code first, formatting and minimum changed-package Clippy after coherent
increments. Broad qualification follows the assembled product; unexecuted behavior
remains unqualified.
