# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.18 · 2026-10-27 · normative design for the greenfield rewrite.**

V1/V2 Memory implementations are donors. V3 is a new implementation, not a compatibility migration. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its legacy runtime is donor-only and must not receive new Memory functionality.

This document owns product purpose, authority and invariants. [Implementation](IMPLEMENTATION.md) owns concrete runtime, Store and maintenance. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.17](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only active work ledger.

## 0. Current external dependency

Inspected controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

It selects a fresh local JSON-RPC + SQLite WAL V2 with global external ULID `WriteId` receipts. Its roadmap is the sole implementation tracker; L0.1–L1.11 remain unchecked.

Memory inference prerequisites:

1. controller issue #200 separates binding revision allocation, selected pointer and native effect;
2. controller V2 L0/L1 exists before scoped Memory extension issue #199.

Useful Base does not wait for those prerequisites.

## 1. Product purpose and completion

Eliot makes accumulated experience useful at the next decision:

```text
observe what happened
→ preserve exact source
→ reconstruct current work
→ supply applicable context
→ a person or external agent acts
→ observe the result
→ revise memory or method
→ use that revision later
```

Product value is visible when Eliot:

- restores interrupted work without inventing state;
- prevents known failed approaches from silently returning;
- exposes material constraints, exceptions, counterexamples and unknowns before action;
- turns observed outcomes into later changes in guidance;
- keeps original sources openable and corrections reversible;
- remains useful when inference, vectors or specialist tools are unavailable.

A mechanism enters V3 only after its real caller, owner, durable result or typed unknown and consumer are named. A type, port, fixture, report, issue, receipt or passing serializer is not product behavior by itself.

The unit of completion is one connected edge:

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Correct a harmful default at its owner instead of adding another registry, ceremony or exception layer.

## 2. Ownership and authority

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance of external work | Human and host/controller |
| Agent sessions, tools, task execution and orchestration | Host/controller |
| Host event translation and supported context emission | Narrow host adapter/relay |
| Observations, revisions, retrieval, context, outcomes and finite Memory jobs | Memory daemon/application operations |
| Application Store mutations, replay/jobs, backup cut and quiesce evidence | Memory daemon |
| Controller-mutation serialization, backup IDs, installation backup records, restore file leases and backup cleanup | Memory daemon backup-set owner |
| Executable/root identity, root/Owner credentials, migrations, Store lifecycle, disposable restore candidate and final cutover | Memory supervisor/installer |
| Interpretation, consolidation and method improvement | Memory learning handlers |
| One-shot caller authentication, profiles, provider invocation/readback, `WriteId` receipts and temporary inference copies | Controller V2 |
| Application persistence, indexes and transactions | SurrealDB through one private Memory Store |
| Code/document/source translation | Narrow configured adapters/tools |
| External research execution and large corpora | Eliot Research or another configured research system |

Public control reaches the daemon. A privileged effect—root/Owner use, migration, DB-user rotation, SurrealDB process action or installation cutover—crosses one inherited supervisor channel as a closed typed intent. The supervisor independently resolves approved resources and secret references. It never accepts arbitrary SQL, argv, endpoint, path or secret from the daemon. The daemon never receives root or Owner credentials.

Memory may link an external task, action and result, but it does **not** become another task manager, permission engine, swarm controller, acceptance authority or research platform.

### 2.1 Dreamer is a role, not a process

Dreamer means model-assisted interpretation for one finite Memory job. It is not a permanent daemon, provider, scheduler, special database or second canonical writer.

A learning handler freezes finite input and an exact processing-method revision, builds one exact request, invokes the controller outside a Store transaction, verifies and copies a result when present, decodes a purpose-specific response and publishes ordinary Memory revisions.

### 2.2 One-shot inference is not Agent orchestration

```text
exact input + profile + disclosure + finite limits + precommitted WriteId
→ complete | partial | failed | unknown
→ exact visible body when present + bounded observed facts
```

Memory uses one dedicated `memory_inference` principal. It does not create controller Agent, generation, binding, turn, command, Goal, automation run/action, workspace, native session, Task, Attempt, review or acceptance objects.

### 2.3 Stable caller, rotating credential and external IDs are distinct

One Memory installation owns one stable caller:

```text
client_id = memory:<random-stable-installation-id>
```

`token_version` authenticates current physical credential. It never owns or renames calls. `client_id` survives Memory restart, Store-root cutover, rollback and token rotation.

Memory owns one monotonic global-ULID generator state outside rollback Store roots. It advances that state durably, stores every exact mutation `WriteId` in the owning job/maintenance record and only then sends.

This applies to call, cancel, release and retention advance. A new ID is never recovery from an unknown old effect.

### 2.4 Profiles and disclosure belong at the send owner

Controller owns versioned `InferenceConnection` and `InferenceProfile`: endpoint/transport, private provider credential reference, actual destination, requested model, automatic-use permission and finite limits.

Memory chooses a profile name and reduces supplied material to:

```text
local_only
external_allowed
```

Derived content cannot widen the strictest contributing source it still reveals. Controller resolves actual destination and checks disclosure before provider I/O. A loopback gateway forwarding to cloud is external. No silent fallback exists.

## 3. Product shape

Initial product is:

- one Rust package/codebase;
- one executable with supervisor, daemon and transient relay modes;
- one private inherited supervisor↔daemon channel;
- one private application Store and one active SurrealDB child;
- at most one isolated disposable restore candidate;
- installation-scoped external-ID and backup authority outside rollback Store roots;
- ordinary internal modules;
- optional outbound clients constructed only when enabled.

A new process, crate, table or registry is justified only by independently owned state, dependency, deployment or failure boundary. A noun in prose is not an instruction to create a service.

### 3.1 Four responsibility layers, not four process tiers

1. domain values and pure transformations;
2. application operations;
3. external I/O adapters;
4. surfaces and runtime composition.

Internal calls use typed Rust values. Serialization belongs at actual Store/process/network boundaries. Add a trait only for a real interchangeable I/O boundary.

### 3.2 Useful Base, then additive capabilities

Base works without controller inference, vectors, converters, project graph or Research credentials. It provides:

- real host capture and durable spool recovery;
- exact source bytes and occurrence identity;
- notes, corrections and commitments with history;
- exact and lexical retrieval;
- addressed current-work reconstruction;
- actual context delivery at a supported host boundary;
- exact source opening;
- restart, local backup, exact rollback and controlled erasure;
- direct status and control.

First learning extension closes one loop:

```text
retained episode
→ exact processing recipe
→ one controller call
→ typed create/revise/no-change/partial/error
→ ordinary Memory revision
→ changed later context
→ controller copies released or explicit cleanup debt
```

Vectors, project views, documents, Research and additional hosts are independent increments. They reuse the same records, finite jobs, revisions, context and maintenance paths.

### 3.3 First host is a narrow relay

The initial Claude Code profile supports:

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

Claude JSON is adapter input, not the Memory domain model. `SessionStart` and `UserPromptSubmit` are context boundaries. `Stop`/`SubagentStop` retain host-supplied final responses. `PostCompact` is derived representation, not replacement source truth.

`PreToolUse`, permission and finish enforcement are outside Base. Negative memory is advisory by default.

## 4. Identity and memory invariants

### 4.1 Work identity is not environment state

Project/workspace plus actual host task identity—or narrow actor/session fallback—addresses continuing work. Path, branch, commit, resource version and time describe environment.

Branch switch does not erase a goal. A result from checkout B does not establish checkout A. Fork/transfer retains explicit relations. Late results keep issue-time binding.

### 4.2 Occurrence identity is not content equality

Use the strongest native event key plus bound host/session/task/resource scope. When absent, the relay command ID is occurrence and replay key. Digest verifies bytes; it does not merge equal occurrences.

### 4.3 Preserve accepted source before interpretation

Capture exclusions/redactions run before ownership transfer and remain explicit. Accepted material is retained exactly within its declared bound, inline or as an immutable blob. Extracted text, normalized fields and excerpts are projections.

### 4.4 Source, representation and claim are distinct

Observation records what a source supplied, not universal truth. Claims, methods, explanations, predictions and project views are derived knowledge with exact source/revision handles.

Rename, copy, conversion and export preserve separate identities plus relations. Similarity or equal bytes do not prove continuity or independent support.

### 4.5 Current revision and history are distinct

Corrections create revisions. Historical evidence remains exact-openable. Incompatible alternatives may coexist. Removing a successor does not resurrect its predecessor.

### 4.6 Origin, reuse and disclosure are distinct

Every item retains origin. Reuse scope says where it may be considered. Disclosure says where supplied content may travel. Reuse never widens disclosure or proves applicability to another workspace/version/task.

### 4.7 Grounds are explicit enough to revise

Links in one required group are conjunctive; different groups are alternatives; ungrouped support is advisory; navigation has no evidential Boolean meaning. Citation count is not proof. Cycles supply no independent support.

### 4.8 Support, exposure and influence are distinct

Existence, support, retrieval exposure and advisory influence answer different questions. Retrieval frequency does not verify truth. Known contradiction accompanies affected guidance rather than collapsing into one score.

### 4.9 Exact `open` is not broad retrieval

`open` requires one nonempty exact handle/locator and optional bounded range. It reports requested/resolved identity, revision/representation, returned range/digest, current/history state, capture gaps, qualifications, relation descriptors, expansion handles and continuation.

Historical handles never fall forward. Empty selector never means broad project read. Fixed truncation without continuation is an explicit incomplete gap.

### 4.10 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Retrieve less while permitted history remains |
| Withdraw influence | Stop guidance in the stated situation |
| Supersede/refute | Publish a scoped replacement or contradiction |
| Retire backup | Make one published generation permanently non-restorable; does not delete content |
| Erase controlled scope | Delete controlled source/derivatives/spool/backups/controller copies while retaining only required anti-reintroduction/inventory/terminal tombstones |

A deletion notice, membership tombstone or backup terminal marker is not physical deletion proof. Provider-held copies/effects and exported off-machine backups are external boundaries.

## 5. Context, understanding and learning

Address current work before similarity search. A decision packet includes only material that can change the next action: current goal/progress, exact corrections, open commitments, applicable methods with exceptions, relevant episodes, dissent/unknowns and source handles.

Exact values and qualifications travel together. Prefer a complete qualified unit or explicit omission/handle over a misleading fragment. Useful recall must not depend solely on an agent remembering to ask.

A project view is a versioned answer to one useful question over examined scope. Exact structure comes from sources/tools; semantic explanation may use a learning handler. Failed refresh leaves the prior qualified view and direct source access available.

No-change is valid only after cognitive work completes on supplied input. Rejection, no result, malformed output, truncation, omitted coverage or unresolved execution is not no-change. Cleanup outcome remains separate from cognitive outcome.

Recursive improvement diagnoses the failed connected edge—capture, source selection, Store/spool, controller admission/execution/readback, backup authority, decoding, publication, retrieval, delivery, use or applicability—and corrects that edge instead of multiplying lessons or global scores.

## 6. Store and schema authority

The initial Store target is SurrealDB 3.3.4 with external RocksDB and explicit `sync=every`. Base owns six `SCHEMAFULL` tables plus immutable blobs:

```text
stream
observation
memory
memory_history
link
job
```

Application identity crossing JSON is a bounded canonical string. Surreal native record IDs remain internal. Every fixed query has an explicit projection and typed DTO; no generic `Value`, `SELECT *`, raw SurrealQL or implicit special-type round trip is exposed.

Migration authority is one ordered UTF-8/LF asset bundle. Its SHA-256 is computed outside the assets; the migration does not contain its own digest literal. The runner binds generation and digest into one fixed transactional metadata wrapper, then verifies exact pinned-version `INFO FOR DB/TABLE` definitions before daemon admission.

Base lexical retrieval uses a neutral analyzer (`blank,class` plus `lowercase`) and separate FULLTEXT indexes for observation excerpts and Memory search text. Exact/unique indexes remain separate index kinds.

## 7. Backup-set authority and restore

### 7.1 Concrete owners and lock order

The daemon owns both the controller-mutation owner and the backup-set owner. The supervisor owns candidate Store process/root and final installation cutover.

A new backup fence follows one order:

```text
close and drain controller-mutation admission
→ acquire backup-set transition
→ publish and read back final fence authority
→ release transition
→ reopen controller-mutation admission
```

This prevents a release or retention advance from passing a stale “no fence” observation. Abort/retire only remove pins, so a stale pre-terminal snapshot is conservative.

### 7.2 Atomic first visibility

A backup ID is `b_` plus 32 lowercase hexadecimal characters from 128 OS-random bits. The daemon builds canonical `fence.json` inside a private same-parent temporary directory, flushes file and directory, atomically renames the directory without replacement to `backups/<id>`, flushes the parent and reopens the final directory/fence no-follow.

The final backup directory first becomes visible with its authoritative fence already inside it.

- collision: discard temp, generate another ID and recompute the plan before any part;
- crash before final rename: temp staging is non-restorable/non-pinning cleanup debt;
- rename may have committed but parent sync/readback failed: publication is unknown and reconciliation pins conservatively;
- once a final fence or terminal marker exists, the ID is never reused.

### 7.3 Terminal records

`abort.json` and `retire.json` are self-contained immutable terminal tombstones after exact prerequisites. Abort applies only before a valid manifest. Retire applies only to an exact published backup. Both are mutually exclusive and remain authoritative after content-bearing files are removed.

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other malformed/mismatch/ambiguity      -> unresolved/fail closed
```

Terminalization is not physical erasure.

### 7.4 Restore lease and crash custody

Restore is admitted only through the daemon backup-set owner. The lease retains no-follow handles to the final directory, fence, manifest and required parts with delete sharing denied, and remains held through candidate verification and the final terminal-state check before cutover.

Retirement, abort and cleanup wait for the lease. The supervisor receives only closed backup identity/digest and cutover intents, never an arbitrary path.

If daemon or inherited channel is lost while a candidate exists, the supervisor kills, reaps and discards the candidate before starting another daemon or permitting cutover. Supervisor loss is contained by the process-family Job. Restart reconstructs backup authority from installation records before ordinary jobs.

### 7.5 Controller dependencies

Before backup high-water, one controller-mutation owner is drained and every call/cancel/release/retention ID receives an exact cut disposition. Every admitted in-cut call is `controller_closed` or `controller_dependent`.

Published non-retired backups and unresolved provisional fences pin dependent controller copies and post-cut retention. Terminal generations do not pin, but surviving content remains cleanup debt. Store maintenance rows mirror status only and cannot recreate installation state after rollback.

Restore is exact rollback, not invented merge. `controller_closed` jobs restore from backup facts. `controller_dependent` jobs require exact call/copy. Post-cut calls are inventoried over one fixed interval and are never adopted as restored cognition. Base remains usable when inference continuity is unavailable.

## 8. Reliability, privacy and direct control

Persist enough state to distinguish adjacent lifecycle states: committed/staged/unknown capture; prepared/emitted context; complete/paged/missing/damaged reads; inference prepared/admitted/sending/settled/unknown/abandoned; controller-closed/dependent; backup staging/preparing/publication-unknown/published/aborted/retired; release/retention pins; physical cleanup debt; owner-action-required debt; privileged maintenance requested/quiesced/executing/selection-unknown/completed.

Acknowledgement is not completion. Heartbeat is not progress. Provider body is not a decoded proposal. Backup plan digest is not manifest digest. Rename without parent durability/readback is not publication. Terminal marker is not erasure.

Secrets stay with their owner. Controller owns provider credentials and Memory caller token issuance. Supervisor owns Store root/Owner references. Daemon receives Store Editor and current Memory controller credential reference only. Backups retain non-secret identities, not reusable secrets.

Direct control provides status/open/configure/pause/cancel/correct/withdraw/erase/backup/restore/rotate/retire/shutdown. Status derives from actual process, Store, spool, controller and installation-record readback.

## 9. Explicit non-goals

V3 does not add without demonstrated need:

- public supervisor API or generic administration bus;
- arbitrary SQL/path/argv/secret over the inherited channel;
- another task manager, workflow engine, semantic DB or provider stack;
- controller Agent/Goal/automation/script/MCP for one-shot inference;
- permanent Dreamer process;
- truth/skill/outcome/packet registries;
- a general Governor/approval/proof platform;
- actor/crate/service/manifest per concept;
- a controller backup-pin service or second mutation ledger;
- runtime plugin/WASM/hot-generation machinery;
- model judges, silent fallback or arbitrary provider extras;
- generic Surreal JSON/CBOR protocol reimplementation;
- rollback-derived external IDs or backup IDs;
- first admission of absent old calls from backup;
- release past a retained/provisional dependency;
- retention advance past retained/provisional high-water;
- rollback-local Store rows as backup authority;
- empty final backup directories as reserved authority;
- deleting files as retirement;
- Memory impersonation of controller-owner erase.

## 10. Product evidence and order

Base evidence:

```text
real host event
→ committed Store observation or durable stage
→ replay when staged
→ restart
→ actual continuation/context or explicit retrieval
→ exact source open
```

Inference evidence:

```text
stable caller + precommitted WriteId
→ one admitted call / at most one provider attempt
→ exact result or typed no-result/unknown
→ decoded publication
→ later context consumer
→ rollback-safe final fence visibility
→ terminal and restore-lease reconciliation
→ dependency-aware release/retention
```

Implementation order:

1. Memory Slice 0 physical/Store/schema/backup qualification;
2. useful Base capture/replay/open;
3. first qualified host/context path;
4. controller #200 plus V2 L0/L1;
5. Contract 0.17 text-inference P1a;
6. credential rotation P1b;
7. independent vectors/views/documents/Research/hosts;
8. advanced curation after connected Base.

Production code comes first. Run formatting and minimum changed-package Clippy after coherent code increments. Broad qualification follows connected product.