# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.25 · 2026-11-06 · design for the greenfield rewrite, not implemented behavior.**

V1/V2 Memory implementations are donors. This document owns purpose, responsibility
and invariants. [Implementation](IMPLEMENTATION.md) owns runtime, Store, maintenance
and build order; [Cognition](COGNITION.md) owns algorithms; the
[Inference contract](INFERENCE-CONTRACT.md) owns the proposed external call boundary.
[ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only work ledger.

## 0. External dependency

Base works locally without a controller. Only model-assisted jobs depend on the scoped
[Memory inference extension](INFERENCE-CONTRACT.md#0-authority-and-prerequisites).

## 1. Purpose and completion

Eliot reconstructs the smallest useful model of the work: **goal/criterion, how the
relevant part works, current state, attempts/results, uncertainty and next step**.
The agent should recover why a decision follows, what would change it and where to
check it. Retain concrete objects, critical values and conditions; links expose supporting detail.

| Agent problem | Required behavior |
|---|---|
| Context lost after compaction, restart or handoff | Rebuild the current goal, decisions, attempts and next step from retained sources. |
| Context fills with repeated or unrelated material | Keep a small active view; inject useful changes at the next decision boundary and open detail on demand. |
| The agent does not know what to recall | A touched artifact, error, result or changed premise activates prepared knowledge and relevant counterexamples. |
| A familiar failure recurs | Supply its conditions, attempted repair and what would justify a different next attempt. |
| Old knowledge survives a code/API/goal change | Requalify the affected model and advice; expose the current fact and unresolved conflict. |
| Experience accumulates without improving work | Revise the knowledge or processing method actually consumed by later decisions. |

Committed capture preserves events as [observations](IMPLEMENTATION.md#72-capture-command-commit-and-replay).
Direct edits and Dreamer publish [memory revisions](IMPLEMENTATION.md#74-direct-revision-and-lost-replies).
Base assembles prepared knowledge, current observations and exact links into
[decision context](COGNITION.md#6-retrieval-and-context), without inference. The agent
reasons, the host acts, and captured outcomes inform later revisions.
[Exact open](IMPLEMENTATION.md#73-exact-open-and-byte-ranges) supplies supporting detail.

Agent-authored revisions remain useful without Dreamer. Explanations and predicted
consequences remain attributed hypotheses until supported; missing understanding stays
a named question. Measure correct continuation and avoided repeated mistakes against total
preparation/read/use cost, not recall or compressed word count alone.

Completion connects a caller, existing owner, result/unknown and actual consumer,
including restart/readback for persistent effects. [Cognition §2](COGNITION.md#2-current-work-reconstruction)
defines the working model; [the research map](AUDIT-MAP.md#5-из-исследований-в-реализацию)
records its evidence and limits.

## 2. Ownership

| Responsibility | Owner |
|---|---|
| Goals, permissions and acceptance | Human and host/controller |
| Agent/task/tool execution | Host/controller |
| Event translation and actual context emission | Narrow host relay |
| Memory, retrieval/context, finite learning jobs, mutations/replay and backup dependency/record operations | One Memory daemon; ordinary modules own these operations |
| Executable/root identity, Store root/Owner credentials, migration, candidate and cutover | Supervisor/installer |
| Scoped one-shot call, provider execution/readback and private inference copies | Controller extension |
| Persistence, indexes and transactions | Private SurrealDB Store |

Public control reaches the daemon. Privileged process/root/Owner/cutover effects cross
one inherited typed channel. Supervisor independently resolves approved resources;
it does not accept arbitrary SQL, argv, endpoint, path or secret from the daemon.
Daemon never receives root or Owner credentials.

Dreamer is the semantic role of finite jobs in the existing daemon: prepare/revise useful
knowledge and answer agent research turns. Dialogue is linked requests/results, not a
permanent process, separate chat store or canonical writer. A controller call is not an
Agent/session/Goal lifecycle. Memory links external work but does not own it.

The [inference contract](INFERENCE-CONTRACT.md) owns client/credential/call identity,
destination and uncertain-effect readback; rotation/rollback never authorizes a duplicate call.

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

Dreamer prepares changed work and reusable mechanisms/procedures for a real consumer;
an agent can also ask a question or follow-up without a failed lookup. Outcomes/tests/
corrections revise knowledge, retrieval cues or the processing recipe. External
self-learning requires later context/jobs to consume that revision
([Cognition §12](COGNITION.md#12-consolidation-disagreement-and-improvement)).
Calls include cleanup and backup continuity. Local Research needs no web acquisition;
optional acquisition/vectors/documents reuse existing owners and records.

### 3.3 First host is narrow

The first Claude relay captures host events and supplies context at start/resume/compact,
user prompts and supported tool-result boundaries. One batch update is preferred to
duplicate per-tool injections. Final messages are retained directly; compaction summaries
are derived. [Cognition §6.5.1](COGNITION.md#651-first-claude-output-boundary) owns the exact mapping.
Additional hosts translate the same operations; their event names do not alter domain state.
Memory failure withholds unavailable context and leaves host execution available.

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

Start with addressed work and the current event's exact artifact/error cues. Follow known
decision dependencies and failed attempts, even when their wording differs from the query.
Expand lexical/relations/methods and optional vectors for a remaining question. Scope before
limits and select from the union; rank is neither truth nor applicability.

A new or uncertain context gets a self-contained work model; an ongoing context gets
useful changes and necessary premises. Preserve mechanisms/attempts, corrections,
commitments, exceptions and unresolved evidence that change the action, expected
consequence or verification. Show meaningful qualifications and exact source handles;
keep internal defaults, backend inventories and diagnostic bookkeeping out of the prompt.

[Cognition §6](COGNITION.md#6-retrieval-and-context) owns selection and packing,
[§6.2.1](COGNITION.md#621-proactive-attention-without-repeated-context) repeat suppression,
and [§6.5](COGNITION.md#65-handoff) handoff. Validate sources before output; optional
telemetry failure cannot withhold valid context. Prepared, emitted, used and successful
remain distinct observations.

Missing evidence, low similarity or an optional backend failure affects only the dependent
claims; independent useful context and exact open remain available. A pending/failed refresh
leaves applicable prior knowledge plus newer evidence visible with preparation limits.
Changed premises requalify affected advice; only completed cognitive work can yield
`no_change` ([§9.2](COGNITION.md#92-result-and-cognitive-states)).

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

[Implementation §11](IMPLEMENTATION.md#11-implementation-sequence) owns the connected
increments and their observable exits. The first capture/open path does not wait for
backup/crash/load qualification; model-assisted learning waits for its inference boundary.

Preserve safety checks at the boundary that needs them: no unverified credentials sent,
no false durable capture, no unleased restore/cutover, no uncertain external effect retried.
Production code first, formatting and minimum changed-package Clippy after coherent
increments. Broad qualification follows the assembled product; unexecuted behavior
remains unqualified.
