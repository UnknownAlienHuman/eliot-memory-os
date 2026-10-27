# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.17 · 2026-10-27 · normative design for the greenfield rewrite.**

V1/V2 Memory implementations are donors. V3 is a new implementation, not a compatibility migration. Current `eliot-swarm-controller` V2 is also a fresh implementation target; its existing V1 runtime is donor-only and must not receive new Memory functionality.

This document owns product purpose, authority and invariants. [Implementation](IMPLEMENTATION.md) owns concrete runtime, Store and maintenance paths. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.16](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only active work ledger.

## 0. Current external dependency

Inspected controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

It selects fresh local JSON-RPC + SQLite WAL V2 with global external ULID `WriteId` receipts. Its roadmap is the sole implementation tracker and every L0.1–L1.11 item remains unchecked.

Memory inference prerequisites:

1. controller issue #200 repairs binding-revision allocation/schema authority;
2. controller V2 L0/L1 exists before scoped Memory extension issue #199.

Base Memory does not wait for those prerequisites.

## 1. Product purpose

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
- remains useful when controller inference, vectors or specialist tools are unavailable.

A mechanism enters V3 only after its real caller, owner, retained result or typed unknown and consumer are named. A type, port, receipt, fixture, report, issue or passing serializer is not product behavior by itself.

The unit of completion is one connected edge:

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery where relevant
```

Correct a harmful default at its owner instead of adding another exception, registry or receipt layer.

## 2. Ownership and authority

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance of external work | Human and host/controller |
| Agent sessions, tools, task execution and orchestration | Host/controller |
| Host event translation and supported context emission | Narrow host adapter/relay |
| Observations, semantic revisions, retrieval, context, outcomes and finite Memory jobs | Memory daemon/application operations |
| Application Store mutations, replay/jobs, backup cut and quiesce evidence | Memory daemon |
| Installation selection, root/Owner credentials, migrations, Store lifecycle, backup-set owner, terminal records, restore leases and cutover | Memory supervisor/installer |
| Interpretation, consolidation and method improvement | Memory learning handlers |
| One-shot caller authentication, profiles, provider invocation/readback, `WriteId` receipts and temporary inference copies | Controller V2 |
| Application persistence, indexes and transactions | SurrealDB through one private Memory Store |
| Code/document/source translation | Narrow configured adapters/tools |
| External research execution and large corpora | Eliot Research or another configured research system |

Public control reaches the daemon. A privileged effect—root/Owner use, migration, DB-user rotation, SurrealDB process action or installation cutover—crosses one private inherited supervisor channel as a closed typed intent. Supervisor independently resolves approved resources and secret references. It never accepts arbitrary SQL, argv, endpoint, path or secret from daemon. Daemon never receives root or Owner credentials.

Memory may link an external task, action and result, but it does **not** become another task manager, acceptance authority, permission engine, swarm controller or research platform.

### 2.1 Dreamer is a role, not a process

**Dreamer** means model-assisted interpretation for one finite Memory job. It is not a permanent daemon, provider, special database, scheduler or second canonical writer.

A learning handler freezes finite input and exact processing-method revision, builds exact request, calls configured controller boundary outside Store transaction, verifies/copies result when present, decodes one purpose-specific response and publishes ordinary Memory revisions.

### 2.2 One-shot inference is not Agent orchestration

```text
exact input + profile + disclosure + finite limits + precommitted WriteId
→ complete | partial | failed | unknown
→ exact visible body when present + bounded observed facts
```

Memory uses dedicated controller V2 `memory_inference` principal and Contract 0.16 methods. It does not create controller Agent, binding, turn, command, Goal, automation run/action, workspace, native session, Task, Attempt, review or acceptance object.

Richer software-agent work may use controller Agents when it genuinely needs tools or continuation. One bounded memory extraction must not expand into a workflow engine.

### 2.3 Stable caller, rotating credential and external identities are distinct

One Memory installation owns one stable caller:

```text
client_id = memory:<random-stable-installation-id>
```

`token_version` authenticates current physical credential. It never owns or renames calls. `client_id` survives Memory restart, Store-root cutover, exact rollback and token rotation. Changing it is unsupported principal migration.

Memory owns one monotonic global-ULID generator state outside rollback Store roots. It durably advances generator, persists each exact mutation `WriteId` in owning job/maintenance record, and only then sends.

This applies to:

```text
inference.text / inference.embed
inference.cancel
inference.release
inference.retention.advance
```

Live call identity:

```text
WriteId globally unique
+ client_id
+ method
+ canonical semantic payload
```

Lost live reply or restart repeats same ID and bytes. Matching identity returns current/original call; mismatch conflicts; valid absent ID may first-admit during normal live operation.

A controlled backup is stricter. Before high-water read, one Memory controller-mutation owner is closed/drained and every created call ID becomes exactly one of:

```text
admitted
retired_not_admitted
admission_unknown
```

Every created cancel, release and retention-advance ID becomes:

```text
effect_observed
retired_not_sent
mutation_unknown
```

An old backup never first-admits an absent call or auxiliary ID. After restore, any still-needed auxiliary effect is recomputed from current call, controlled-backup-set and controller-cut facts and receives a fresh WriteId only after post-cut inventory. There is no separately discovered Operation ID or Memory submission ledger.

Backup identity is independent again: one fixed-width random 128-bit installation-local ID allocated by create-new publication. It is never derived from rollback Store state or wall clock alone and is never reused after an abort or retirement tombstone.

### 2.4 Profiles and disclosure belong at the send owner

Controller owns versioned `InferenceConnection` and `InferenceProfile`: endpoint/transport, private provider credential reference, actual destination, requested model, automatic-use permission and finite limits.

Memory chooses profile name and reduces supplied material to:

```text
local_only
external_allowed
```

Derived content cannot widen the strictest source it still reveals. Controller resolves actual destination and checks disclosure before provider I/O. Loopback gateway forwarding to cloud is external. Memory cannot construct arbitrary endpoints, headers, extras, retries or fallback ladders.

Unavailable profile/capacity or disclosure mismatch is operational failure/waiting, not cognitive `no_change` and not processed coverage.

### 2.5 Cleanup authority, backup terminal state and restore leases are distinct

One call creates at most two private controller files:

```text
inference_input
inference_result
```

Controller performs at most one provider attempt. Possible-send loss becomes retained `unknown`, never automatic redispatch.

Normal caller cleanup uses:

```text
inference.release(memory_copy_verified)
inference.release(terminal_without_result)
inference.release(abandon_for_erasure)
```

A queued call may first receive caller `inference.cancel`. `abandon_for_erasure` fences future dispatch, settlement and publication before controlled-copy deletion.

Each admitted in-cut backup job is classified:

```text
controller_closed
  backup already contains every exact terminal Memory fact/body it needs,
  no future controller settlement/publication is possible,
  and no controller copy/cleanup/readback remains required

controller_dependent
  backup still needs controller status, present/future result bytes,
  or unresolved cleanup/readback
```

One in-process backup-set owner—not another service, database or durable workflow—owns:

- non-reused backup-ID allocation;
- installation-record scanning and exact derived state;
- provisional and terminal transitions;
- restore read leases;
- physical backup cleanup.

Before any backup part, Memory closes/drains the controller-mutation owner, captures the exact spool/controller cut, computes a canonical plan digest and durably publishes installation-scoped create-new `fence.json` outside rollback Store roots. The digest excludes itself, publication state and later page/part/manifest digests. Final manifest repeats the plan digest and actual inventories.

`abort.json` and `retire.json` are self-contained immutable terminal tombstones after their prerequisites are proven. Each binds backup ID, plan and observed fence identity, deterministic terminal operation identity and a closed reason; retirement also binds observed manifest digest. After durable marker readback, later deletion of fence, manifest or parts does not undo terminal state. Both markers together, malformed records or surviving files that contradict their recorded digests fail closed.

Controlled-set state is derived terminal-first:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication-unknown
other mismatch/ambiguity                -> unresolved/fail closed
```

Published non-retired backups and unresolved provisional fences pin release and post-cut retention. Retired and aborted generations do not pin, but any surviving content is physical-cleanup debt.

Restore requires more than a scan. The backup-set owner grants an exact read lease and retains no-follow handles to the chosen fence, manifest and parts. Retirement, abort and cleanup wait until candidate verification and final pre-cutover terminal-state recheck complete. Crash releases the lease and the disposable candidate is abandoned.

Store maintenance rows are status mirrors only. After rollback they are reconciled against installation records before job claims; stale future-timeline mirrors cannot create terminal records, clear pins or send release/retention.

Controller-owner `inference.erase` is local break-glass for missing/disabled caller or emergency. Memory has no owner credential, cannot submit it and cannot report it complete before non-content owner readback.

Controller registration owns:

```text
last_admission_seq
retain_after_seq
```

`retain_after_seq` guarantees post-cut membership above the cut. It is monotonic and is **not lowered** to pin in-cut dependencies; those remain protected because required calls/copies stay unreleased. Retained backups and unresolved provisional fences constrain how far the cut may advance. A restored pending retention intent is never blindly replayed; current target is recomputed from installation records and controller readback.

Erasing content above cut leaves bounded text-free tombstone until cut advances beyond its sequence. If even tombstone must disappear, all controlled backups pinning interval retire and cut advances first; otherwise erasure remains incomplete.

## 3. Product shape

Initial product is:

- one Rust package/codebase;
- one executable with supervisor, daemon and transient relay modes;
- one private inherited supervisor↔daemon channel;
- one private application Store and one active SurrealDB child;
- at most one isolated restore candidate;
- installation-scoped WriteId state and backup records outside rollback Store roots;
- one in-process controller-mutation owner and one in-process backup-set owner;
- ordinary internal modules;
- optional outbound clients only when enabled.

A new process, crate, table or registry is justified only by real independently owned state, dependency, deployment or failure boundary. An owner task around live OS handles/mutual exclusion is not a new public service. A noun in documentation is not instruction to build a service.

### 3.1 Four responsibility layers, not four process tiers

1. domain values and pure transformations;
2. application operations;
3. external I/O adapters;
4. surfaces/runtime composition.

Internal calls use typed Rust values. Serialization belongs at actual Store/process/network boundaries. Add a trait only for a real interchangeable I/O boundary.

### 3.2 Useful Base, then additive capabilities

**Base** works without controller inference, vector encoder, document converter, project graph or Research credentials. It provides:

- capture from one real host;
- exact retained source bytes and occurrence identity;
- notes, corrections and commitments with history;
- exact and lexical retrieval;
- addressed current-work reconstruction;
- actual context delivery at supported host boundary;
- exact source opening;
- restart, spool, local backup/exact rollback and controlled erasure;
- direct status and control.

First learning extension closes one loop:

```text
retained episode
→ exact processing recipe
→ one controller V2 inference call
→ typed create/revise/no-change/partial/error
→ ordinary Memory revision
→ changed later context
→ controller copies released or explicit cleanup debt
```

Vectors, project views, documents, Research and additional hosts are independent increments. They reuse same records, finite jobs, revision publication, context and maintenance paths. There is no separate Lite/Full memory engine.

### 3.3 First host is a narrow relay

First profile is one Claude Code hook relay with finite event set:

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

Claude JSON is adapter input, not Memory domain model. `SessionStart` and `UserPromptSubmit` are context boundaries. `Stop`/`SubagentStop` retain host-supplied final responses. `PostCompact` is derived representation, not replacement truth.

`PreToolUse`, permission and finish enforcement are outside Base. Negative memory is advisory by default. Any later guard is explicit and opt-in.

### 3.4 Direct capture and spool share one operation

Relay builds one immutable bounded `CaptureCommand` before IPC. Direct delivery and replay use same command ID/bytes.

```text
command
→ daemon capture
→ matching Store readback
→ committed

no established daemon ownership
→ durable pending publication
→ staged
→ daemon replays same capture
→ Store readback
→ pending body removed
```

No successful `forwarded` state without Store readback and no `staged` before file plus parent-directory durability/exact reopen.

Spool is transport-recovery queue, not another memory database. One daemon replayer owns it. Corrupt/permanently rejected entries move to bounded failed quarantine; successful replay removes content-bearing pending entry.

### 3.5 Context handoff is a real host effect

A packet is useful only when rendered bytes cross supported host boundary. “Event spooled” is status, not context. Local file or packet ID is not delivery.

Retain packet bytes/digest, budget, gaps and exact included revisions as ordinary observation/blob/link data. Keep distinct:

```text
prepared
emitted
associated with later action when observable
actually used/influential: usually unknown
```

## 4. Identity and memory invariants

### 4.1 Work identity is not environment state

Project/workspace plus actual host task identity—or narrow actor/session fallback—addresses continuing work. Path, branch, commit, resource version and time describe environment.

Branch switch does not erase goal. Result from checkout B does not establish checkout A. Fork/transfer retain explicit relations. Late results keep issue-time binding. Unknown association limits claims but does not block source preservation.

### 4.2 Occurrence identity is not content equality

Use strongest native event key plus bound host/session/task/resource scope. When absent, relay command ID is occurrence/replay key. Digest verifies bytes; it does not merge equal events or become logical source ID by default.

### 4.3 Preserve accepted source before interpretation

Capture exclusions/redactions run before ownership transfer and remain explicit. Accepted material is retained exactly within declared bound, inline or immutable blob. Extracted text, normalized fields and excerpts are projections.

Missing models, vectors or specialist tools cannot destroy source or prevent exact readback.

### 4.4 Source, representation and claim are distinct

Observation records what source supplied, not universal truth. Claims, methods, explanations, predictions and project views are derived knowledge with exact source/revision handles.

Rename, copy, conversion and export preserve separate identities plus relations. Equal bytes or similarity do not prove continuity or independent support.

### 4.5 Current revision and history are distinct

Corrections create revisions. Historical evidence remains openable. Incompatible alternatives may coexist. Removing successor does not restore predecessor automatically. Occurrence time, stated validity, receipt time and editorial time answer different questions.

### 4.6 Origin, reuse and disclosure are distinct

Every item retains origin. Reuse scope says where method may be considered. Disclosure says where supplied content may travel. Reuse never widens disclosure or proves applicability to another workspace/version/task.

### 4.7 Grounds are explicit enough to revise

Conclusion may depend on all links in one required group, one of several alternative groups, advisory support, or navigation with no evidential meaning. Citation count is not Boolean logic. Cycles supply no independent support.

Targeted source change triggers bounded reconsideration, not whole-graph proof before ordinary recall.

### 4.8 Support, exposure and influence are distinct

Existence, support, retrieval exposure and advisory influence answer different questions. Frequent retrieval does not verify truth. Rarity does not refute. Known contradiction travels with affected guidance rather than collapsing into one score.

### 4.9 Exact `open` is not broad retrieval

`open` requires one nonempty exact handle/locator and optional bounded range. It reports requested/resolved identity, representation/revision, returned range/digest, current/history state, capture gaps, material qualifications, relation descriptors, expansion handles and cursor.

Historical handle never falls forward. Current handle does not resurrect history. Empty selector never means broad project read. Fixed truncation without continuation is explicit incomplete gap.

### 4.10 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | retrieve less while permitted history remains |
| Withdraw influence | stop guidance in stated situation |
| Supersede/refute | publish scoped replacement/contradiction |
| Abort backup candidate | prove a never-published candidate terminal after exact absence/cleanup |
| Retire backup | make one published generation permanently non-restorable through terminal tombstone; does not delete its content |
| Erase controlled scope | delete controlled source/derivatives/spool/backups/controller copies and retain only required anti-reintroduction/inventory/terminal tombstones |

Deletion fence, membership tombstone or backup terminal marker prevents false reintroduction/inventory/restore claims but is not physical deletion proof. Provider-held copies/effects and exported off-machine backups remain external boundaries.

## 5. Current work and decision context

Address current work before similarity search. Open direct continuation, merge relevant later observations, then retrieve related experience.

A decision packet contains only material that can change next action:

- goal and criteria;
- plan/progress/open commitments;
- exact constraints and corrections;
- applicable or conditional methods plus exceptions;
- relevant prior episodes;
- dissent, unknowns and missing checks;
- source handles.

Exact values and qualifications travel together. Prefer concise qualified units or explicit omission/handle over misleading fragments. Useful recall must not depend solely on agent remembering to ask: first host uses `SessionStart` and `UserPromptSubmit`.

Advice and enforcement remain separate.

## 6. Understanding

A project view is revisable answer to one useful question over examined scope: purpose, boundaries, responsibilities, consumers, rationale, failed approaches or intended-versus-observed discrepancy.

Exact structure comes from sources/tools; semantic explanation may use learning handler. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is incremental. First contact returns available exact facts; bounded orientation creates useful views; changes refresh affected views only; failed refresh leaves prior qualified view and direct source open available.

No compulsory pyramid, onboarding ceremony or separate self-model registry is selected.

## 7. Learning and self-improvement

### 7.1 One Memory job owns semantic loop

```text
frozen sources + exact recipe + disclosure + precommitted WriteId
→ controller first admission or exact live replay
→ one bounded provider attempt
→ exact result copy when present
→ purpose-specific decode
→ atomic Memory publication or valid no-change
→ later consumer
→ caller-authorized cleanup when no controlled backup dependency remains
```

Store conflict replays retained result, not model call. Ambiguous provider outcome stays unknown. New WriteId is not recovery.

### 7.2 No-change, partial and cleanup

No-change is valid only after cognitive work completes on supplied input. Profile rejection, no result, malformed output, truncation, omitted input or unresolved execution is not no-change.

Useful partial output retains exact coverage. Cleanup outcome is separate from cognitive outcome: useful learning may remain cleanup-incomplete, and failed request may clean up successfully without knowledge.

### 7.3 Outcome attribution

Where correlation exists, retain exact method revision offered/used and observed criterion outcome. Otherwise preserve episode without invented attribution. Distinguish offered, handed off, action observed, adherence unknown/inferred and comparative benefit supported/unknown.

One attributable attempt/criterion contributes once. Replayed hooks/summaries are not independent successes.

### 7.4 Recursive improvement

Diagnose failed connected edge—capture, source selection, controller admission/execution/readback/retention/backup dependency/publication/terminal state/restore lease/cleanup, decoding, publication, retrieval, delivery, use or applicability—and correct that edge. Do not multiply duplicate lessons or add global intelligence score.

## 8. Backup, rollback and external-work continuity

Application backup uses brief spool publication cut, canonical typed Store pages, exact selected-root blobs, deletion notices, cut pending/failed spool and sanitized config. Manifest owns completion.

Before controller high-water, Memory closes/drains one controller-mutation owner and classifies every call and auxiliary mutation ID. Only admitted calls belong to controller-continuous external-work set; absent old call or auxiliary IDs are permanently retired, not later sent from backup.

Every admitted in-cut call is `controller_closed` or `controller_dependent`. After the exact spool/controller cut, Memory obtains a fresh random backup ID, computes a canonical immutable plan digest and publishes `backups/<id>/fence.json` outside rollback Store roots before any backup part. Final manifest repeats the plan digest and actual inventories; no self-referential manifest digest exists.

The backup-set owner derives authority from installation records. Self-contained `abort.json` and `retire.json` remain terminal after content cleanup. Store maintenance rows mirror status only and are reconciled before job claims after rollback.

A published non-retired backup or unresolved fence pins dependent-call release. `preparing` and `publication_unknown` also pin post-cut retention at recorded high-water. Terminal generations do not pin; remaining files are cleanup debt.

Restore is exact rollback, not invented merge. It acquires an exact backup read lease. Retirement, abort and cleanup wait until candidate verification and final pre-cutover terminal-state recheck complete. Retired or aborted backups are rejected. Crash discards the candidate and releases the lease.

`controller_closed` jobs restore from backup facts even when controller row pruned. `controller_dependent` jobs require exact call/copy. Retired call or auxiliary IDs never send again. Current cancel/release/retention needs are recomputed after post-cut inventory from current controller and installation facts.

Post-cut calls are inventoried through fixed `(backup_high_water, inventory_high_water]`. Results are not adopted. Valid caller uses recomputed cancel/release-abandon after controlled-set checks; unavailable caller creates owner-action-required debt.

`history_gap`, caller/controller unavailability, call or auxiliary unknown, publication/terminal unknown, missing dependent copy or identity reset keeps inference disabled. Base remains available. External-WriteId generator and installation-scoped backup authority are not rolled back.

## 9. Reliability, privacy and direct control

Persist enough state to distinguish adjacent lifecycle states: accepted/staged/committed/unknown capture; prepared/emitted context; exact-read complete/paged/missing/damaged; inference prepared/admitted/retired-not-admitted/sending/settled/unknown/abandoned; auxiliary effect-observed/retired-not-sent/unknown; controller-closed/dependent; result copied/decoded/published; per-copy cleanup; backup preparing/publication-unknown/published/aborted/retired; restore lease; release and retention fences; mirror-current/superseded; physical-cleanup debt; owner-action-required debt; privileged maintenance requested/quiesced/executing/selection-unknown/completed.

Acknowledgement is not completion. Heartbeat is not progress. Provider body is not decoded proposal. Published memory is not external success. Backup plan digest is not final manifest digest. Backup scan is not a restore lease. Store mirror is not installation authority. Terminal marker is not content erasure. File deletion is not terminal-state creation.

Secrets stay with owner:

- controller owns provider credentials and Memory caller token issuance;
- Memory supervisor owns Store root/Owner references;
- daemon receives only Store Editor and current Memory controller credential reference;
- Memory jobs/backups retain non-secret call identities only.

Direct control provides status/open/configure/pause/cancel/correct/withdraw/erase/backup/restore/rotate/retire/shutdown. Status derives from actual Store/process/spool/controller/installation-record readback facts.

## 10. Explicit non-goals

Without demonstrated consumer and owner decision, V3 does not add:

- public supervisor API or generic administration bus;
- arbitrary SQL/path/argv/secret over inherited channel;
- second task manager, workflow engine, semantic DB or provider stack;
- controller Agent/Goal/automation/script/MCP for one-shot inference;
- permanent Dreamer process;
- truth/skill/outcome/packet registry;
- general Governor/approval/proof platform;
- actor/crate/service/manifest per concept;
- a controller backup-pin service/table when installation records + ordinary status are sufficient;
- runtime plugin/WASM/hot-generation machinery;
- model judges, silent fallback or arbitrary provider extras;
- generated inventories as permanent authorities;
- generic JSON/CBOR vendor-protocol reimplementation;
- content hash as occurrence identity;
- aggregate cleanup hiding retained copies;
- backup rollback presented as current-state merge;
- observed earliest controller row presented as retention guarantee;
- rollbackable/reusable external-WriteId generator;
- first admission of an absent old call, cancel, release or retention ID from backup;
- release of a call pinned by retained or provisional backup dependency;
- retention advance past a retained or preparing/publication-unknown backup high-water;
- precommitted final-manifest digest inside Store data being backed up;
- rollback-local Store row as backup-set authority;
- terminal marker whose validity forever depends on content files cleanup may delete;
- restore without an exact read lease or cleanup/retirement of a leased backup;
- backup ID derived from rollback state or reused after terminal marker;
- restored Store mirror creating terminal records or clearing pins;
- deleting manifest/fence/parts as retirement;
- using pre-publication abort marker as published-backup retirement;
- clearing publication/terminal unknown without exact installation-file reconciliation;
- lowering monotonic retain cut to pin old dependency;
- Memory impersonation of controller-owner erase;
- deletion of pinned inventory membership without tombstone/cut advance.

## 11. Product evidence and implementation order

Base minimum evidence:

```text
real host event
→ committed Store observation or durable staged command
→ replay when staged
→ restart
→ actual continuation/context or explicit retrieval
→ exact source open
```

Inference minimum evidence:

```text
stable caller + precommitted WriteId
→ one admitted call / at most one provider attempt
→ exact result copy or typed no-result/unknown
→ decoded publication
→ later context consumer
→ rollback-safe installation plan fence
→ self-contained terminal state when backup leaves restorable set
→ restore lease through candidate verification/cutover recheck
→ cut disposition for every caller mutation ID
→ dependency-aware release and retention
→ restart/rollback reconciliation
```

Implementation order:

1. Memory Slice 0 physical/Store/backup-set qualification;
2. useful Base capture/replay/open;
3. first qualified host/context path;
4. controller #200 plus V2 L0/L1;
5. Contract 0.16 text-inference P1a;
6. credential rotation P1b;
7. independent vectors/views/documents/Research/hosts;
8. advanced curation after connected Base.

Production code comes first. Run formatting and minimum changed-package Clippy after coherent code increments. Broad qualification follows connected product.