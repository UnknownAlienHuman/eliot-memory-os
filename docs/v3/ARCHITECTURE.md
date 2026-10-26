# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.10 · 2026-10-26 · normative design for the greenfield rewrite.**

V1/V2 Memory implementations are donors. V3 is a new implementation, not a compatibility migration. The current `eliot-swarm-controller` V2 is also a fresh build; its V1 runtime is a donor and must not receive new Memory functionality.

This document defines product purpose, ownership and invariants. [Implementation](IMPLEMENTATION.md) defines the runtime, Store and maintenance paths. [Cognition](COGNITION.md) defines algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) is the sole normative Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only active work ledger.

## 1. Product purpose

Eliot makes accumulated experience useful at the next decision:

```text
observe what happened
→ preserve exact source
→ reconstruct current work
→ supply applicable context
→ a person or external agent acts
→ observe result
→ revise memory or method
→ use that revision later
```

A searchable archive is necessary but insufficient. Product value is visible when Eliot:

- restores interrupted work without inventing state;
- prevents known failed approaches from silently returning;
- exposes relevant constraints, counterexamples and unknowns before action;
- turns observed outcomes into later changes in guidance;
- keeps original sources openable and corrections reversible;
- remains useful when optional models, vectors or specialist tools are unavailable.

A mechanism enters V3 only after its real caller, owner, retained result or typed unknown and consumer are named. A type, port, receipt, fixture, report, issue, serializer or passing shape check is not product behavior by itself.

The unit of completion is:

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery
```

Correct a repeatedly harmful default at its owner instead of adding an exception layer.

## 2. Ownership and boundaries

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance of external work | Human and host/controller |
| Agent sessions, tools, task execution and swarm orchestration | Host/controller |
| Host event translation and host-supported context emission | Narrow host adapter/relay |
| Observations, revisions, retrieval, context, source links, outcomes and finite Memory jobs | Memory daemon/application operations |
| Application Store mutations, replay/jobs, backup cut and quiesce evidence | Memory daemon |
| Installation selection, root/Owner credentials, migrations, DB-user rotation, Store lifecycle and restore cutover | Supervisor/installer outside daemon failure domain |
| Interpretation, consolidation and method improvement | Memory learning handlers |
| One-shot caller authentication, profiles, provider invocation/readback, `WriteId` receipts and temporary inference copies | `eliot-swarm-controller` V2 |
| Persistence, indexes and transactions | SurrealDB through one private Memory Store |
| Code/document/source translation | Narrow configured adapters/tools |
| External research execution and large corpora | Eliot Research or another configured research system |
| Detection and containment of daemon/process-family failure | Supervisor |

Public `control` reaches the daemon first. A privileged effect—root/Owner use, migration, user rotation, SurrealDB process action or installation cutover—crosses one private inherited supervisor channel as a closed typed intent. Supervisor independently resolves approved resources and secret references; it never accepts arbitrary SQL, argv, endpoint, path or secret from that channel. Daemon never receives root or Owner credentials.

Memory may link an external task/action/result, but it does **not** become another task manager, acceptance authority, permission engine, swarm controller or research platform.

A host adapter translates native events and emits context through a real host boundary. It does not invent memory semantics, claim Store ownership before readback or replace source bytes with a lossy status record.

### 2.1 Dreamer is a role, not a process

**Dreamer** means model-assisted interpretation for one finite Memory job. It is not a permanent daemon, model vendor, special database, separate scheduler or second canonical writer.

A learning handler freezes finite input plus one processing-method revision, builds an exact request, calls the configured controller boundary outside the Store transaction, verifies and copies the exact result when present, decodes a purpose-specific response and publishes ordinary Memory revisions. Deterministic reducers and embeddings do not become Dreamer jobs merely because they compute.

### 2.2 One-shot inference is not agent orchestration

The semantic operation is:

```text
exact input + profile + disclosure + finite limits + precommitted WriteId
→ complete | partial | failed | unknown
→ exact body when present + requested/observed execution facts
```

Memory uses the dedicated controller V2 `memory_inference` principal and narrow JSON-RPC methods from Contract 0.9. It does not create a controller Agent, generation, turn, command, Goal, automation run/action, workspace, native harness session, Task, Requirement, Attempt, review or acceptance object.

Richer software-agent work may use controller Agents when it genuinely needs tools, continuation or orchestration. One memory extraction must not expand into a workflow engine.

### 2.3 Caller identity and `WriteId` are separate

One Memory installation owns one stable non-secret controller caller:

```text
client_id = memory:<stable-installation-id>
```

A positive `token_version` authenticates the current physical credential; it never owns or renames calls. `client_id` survives Memory restart, Store-root cutover, exact rollback and token rotation. Changing it is unsupported principal migration.

Memory commits the canonical ULID `WriteId` and exact request bytes/digest before first send. Call identity is:

```text
(client_id, WriteId, method, canonical semantic payload)
```

Lost reply, restart or restore repeats the same ID and exact bytes. The same identity returns the original call/current state; changed payload conflicts; a valid absent ID creates the first admission. There is no separately discovered Operation ID and no Memory submission ledger.

### 2.4 Connection/profile and disclosure have different owners

Controller configuration owns:

```text
InferenceConnection
  adapter/transport version
  canonical endpoint
  private provider credential reference
  actual_destination = local | external

InferenceProfile
  connection reference/digest
  requested model
  automatic-use permission
  finite input/output/time/concurrency/batch limits
  supported response formats
```

A loopback gateway forwarding to cloud is `external`. Memory selects a profile name only; it does not receive provider secrets or construct arbitrary headers, endpoints, extras or fallback ladders.

Memory reduces supplied material to:

```text
local_only
external_allowed
```

Derived content cannot widen the strictest source it still reveals. Controller resolves actual destination and checks disclosure at admission. Protected content is not silently removed to make an external route pass.

Unavailable profile, connection, capacity or disclosure mismatch is operational waiting/rejection/failure, not cognitive no-change and not processed coverage.

### 2.5 Controlled request/result copies have finite lifetime

One call creates at most two private controller copies:

```text
inference_input
inference_result
```

They are call-owned private files, not generic controller artifacts or receipts. Controller stages exact input before provider I/O, performs at most one provider attempt, retains exact visible result when present and exposes bounded exact-caller range reads.

Successful path:

1. Memory reads result ranges;
2. verifies length and digest;
3. durably copies the body into its job/blob;
4. calls `inference.release(memory_copy_verified)`.

Terminal no-result uses `terminal_without_result`. Erasure of unresolved work uses `abandon_for_erasure`, which fences future dispatch, settlement and publication before controlled-copy deletion. Cleanup tracks input and result independently; an aggregate `released` state cannot hide a remaining or mismatched copy.

Controller owner may erase exact calls using non-content provenance but cannot read result bytes, adopt caller ownership or fabricate a Memory result. Provider-side execution, retention and billing remain external facts.

### 2.6 User intent and factual reports remain distinct

The user owns goals and preferences, not infallibility about external facts. Preserve intent changes as intent. Preserve factual assertions with source, conditions and counterevidence. Generated continuation, learned method or retrieved suggestion cannot silently replace the user's goal, relax criteria or grant execution authority.

## 3. Product shape

The initial product supports several configured projects concurrently. Project-local state remains scoped; explicitly reusable methods may be considered across selected projects.

The initial product is:

- one Rust package/codebase;
- one executable with supervisor, daemon and transient relay modes;
- one private inherited supervisor↔daemon channel with no public endpoint;
- one private SurrealDB application Store;
- one Store server child;
- ordinary internal modules;
- optional outbound clients only when enabled.

A new process is justified only by a real external runtime or failure boundary. A new crate, table or registry is justified only by an actual dependency, deployment or independently owned-state boundary. A noun is not an instruction to create a service.

One stored mutable state has one application mutation owner. Dashboards, packets, scores, maps and status reports are views unless they own independent state.

### 3.1 Layers remain; pass-through machinery does not

Keep four responsibility layers:

1. **domain and pure transformations** — values, comparison, reduction and packing over supplied inputs;
2. **application operations** — capture, revision, retrieval, learning and control;
3. **external I/O** — Store, host, controller inference, document and Research adapters;
4. **surfaces/runtime** — CLI, hooks, process startup and composition.

These are dependency boundaries, not four processes or a compulsory `interface → facade → service → repository` chain. Internal calls use typed Rust values. Serialization belongs only at actual storage, process or network boundaries. Add a trait only where a real interchangeable I/O boundary exists.

An extension is a vertical capability across the layers it actually uses. It adds a real writer/handler and consumer to existing operations; it does not build a miniature platform with its own scheduler, database, context compiler and supervisor.

### 3.2 Useful Base, then additive capabilities

**Base** works without controller inference, vector encoder, document converter, project graph or Research credentials. It provides:

- capture from one real host;
- exact retained source bytes and occurrence identity;
- notes, corrections and commitments with history;
- exact and lexical retrieval;
- addressed current-work reconstruction;
- actual context emission through a supported host boundary;
- exact source opening;
- restart, spool, local backup/exact rollback and controlled erasure;
- direct status and control.

The first learning extension closes one connected loop:

```text
retained episode
→ exact processing recipe
→ one controller V2 inference call
→ typed create/revise/no-change/partial/error result
→ ordinary Memory revision
→ changed later context
→ controller copies released or explicit cleanup debt
```

A terminal no-result call may close cleanup without fabricating cognitive no-change.

Vectors, project understanding, documents, Research, more hosts and richer cognition are independent increments. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. There is no second Lite/Full memory engine.

Optional means optional in construction, startup and execution. A failed or disabled extension cannot disable capture, exact reads or source opening. Disabling a producer stops new work without deleting readable retained knowledge.

### 3.3 First host profile is a narrow relay

The first host profile is one Claude Code hook relay because it exposes real lifecycle, user-prompt, tool-result and final-response boundaries. Claude-specific JSON remains adapter input; it does not become the Memory domain model.

Initial event set:

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

`SessionStart` and `UserPromptSubmit` are decision-time context boundaries. `Stop` and `SubagentStop` retain the host-supplied final response when available. `PostCompact` is a derived representation, not replacement source truth.

`PreToolUse`, permission and finish enforcement are outside Base. Negative memory is advisory by default. A later host guard is explicit, narrow and opt-in.

The installed host version and emitted payloads must be qualified during implementation. Public documentation is design input, not proof of the installed runtime.

### 3.4 Capture and spool share one ownership operation

The relay builds one complete bounded `CaptureCommand` before IPC. Direct delivery and replay use the same command and idempotency identity.

```text
exact CaptureCommand
→ daemon capture
→ Store identity/digest readback
→ committed

no safe daemon ownership
→ exact durable publication to pending spool
→ staged
→ daemon replays the same capture operation
→ Store readback
→ pending body removed
```

There is no successful `forwarded` state without Store readback and no `staged` state before file plus parent-directory durability and exact reopen.

The spool is a transport-recovery queue, not a second memory database. The daemon is the sole replayer. Corrupt or permanently rejected entries move to a failed area with bounded non-content diagnostics; successful replay removes the content-bearing pending file.

Durable publication means create-new same-directory temporary regular file, complete write, file flush, no-replace rename, parent-directory flush and exact reopen. A direct write to the final path is not a durable queue contract.

Capture remains useful when context or optional learning fails. Context failure does not roll back committed source.

### 3.5 Backup uses a brief spool cut, not a long publication lock

Backup must not hold the cross-process spool publication lock while paging Store rows or copying backup bytes. The selected contract is:

1. daemon stops new Store mutations and replay, then reconciles the active replay item;
2. acquire the publication lock only long enough to capture or rotate one exact bounded spool inventory/generation cut;
3. release the lock;
4. relay continues publishing post-cut entries separately;
5. backup copies only the immutable identities and digests recorded in the cut;
6. a missing or mismatched cut entry fails the backup instead of being silently omitted.

This preserves capture availability during a long backup while keeping the backup denominator exact.

### 3.6 Context handoff is a real host effect

A context packet is useful only when rendered bytes cross a supported host boundary. “Event spooled” is status, not context. A local file or packet ID is not delivery.

The packet is retained as ordinary observation/blob/link data: rendered digest, budget, gaps and exact included revisions. Keep distinct:

```text
prepared
emitted through the host contract
associated with a later action when observable
actually used or influential: usually unknown
```

Failure to emit leaves explicit retrieval and source opening available. The host receives a specific gap rather than fabricated empty success.

### 3.7 Privileged lifecycle is one inherited boundary

Supervisor and daemon are different failure and authority domains, so they use one real internal boundary. Supervisor creates it before daemon launch and passes only exact handles to the child. It is not a named public endpoint, plugin protocol or general administration API.

Closed frames include:

```text
store_descriptor / daemon_ready
maintenance_request / maintenance_result
quiesce / quiesced / resume
shutdown_ready / shutdown_complete
```

One operation ID correlates each finite exchange. Daemon may name an already retained backup, credential or configuration identity; it cannot submit raw SQL, executable arguments, endpoint, arbitrary path or secret. Supervisor reopens and validates the referenced object itself.

Daemon owns application admission and produces quiesce facts: replay stopped, active replay reconciled, Store writes settled or unknown, socket closure and exact spool/deletion/controller cuts. Supervisor owns privileged execution and installation selection. Neither side reports completion from acknowledgement alone; result comes from Store, credential, process or selection readback.

Channel loss is fail-closed. Before cutover, a lost daemon abandons the candidate. After possible selection replacement, startup reads actual selection before another action.

Immutable blobs, spool entries, deletion notices and backup generations are no-replace publications. Mutable installation selection is supervisor-only expected-generation replacement with parent-directory durability, exact readback and explicit unknown reconciliation. Previous root remains until deliberate retirement.

## 4. Identity and memory invariants

### 4.1 Project, workspace, work identity and environment are different

A project is a configured work scope; it need not be Git. A workspace identifies one working instance. A task or actor/session address identifies continuing work. Path, branch, commit, resource version and time describe changing environment.

Therefore:

- branch switch does not erase goal or commitment;
- a result from checkout B does not establish checkout A’s condition;
- fork and explicit transfer retain relations instead of renaming work;
- late result keeps the binding captured when issued;
- unknown association limits claims but does not block source preservation.

There is no universal workspace generation whose mismatch disables an entire project.

### 4.2 Occurrence identity and content equality are different

A real occurrence is identified by the strongest native event identity plus bound host/session/task/resource scope. When the host supplies no unique key, relay command ID is occurrence and replay key.

A digest verifies bytes. It does not merge two occurrences merely because their text is equal and is not a logical source ID unless the object is explicitly content-addressed.

Replay of one command returns its prior result. Different occurrence with identical bytes remains a different observation.

### 4.3 Preserve accepted source before interpretation

Capture exclusions run before ownership transfer. Accepted content is retained exactly within its declared bound, inline or as immutable blob. Extracted text, normalized fields and excerpts are projections, not replacement source truth.

A generic key-name sanitizer cannot silently remove URLs, endpoints, paths, final messages or source locators. Secret exclusions/redactions are explicit, narrow and recorded as capture limitations. Host truncation or omission remains visible.

Missing model, vector, project view or external service cannot destroy captured source or prevent exact readback.

### 4.4 Source, representation and claim are different

An observation records what a source supplied, not that every statement is true. Claim, explanation, method, prediction and project view are derived knowledge.

Derived knowledge retains exact source handles/revisions. Retrieval does not strengthen support. Model-generated IDs are not evidence. Exact names, versions, values, negations, limitations and counterexamples travel with useful summaries.

Source object, version and transformed representation have different identities. Rename, copy, conversion, crop and export retain explicit relations. Similarity or equal bytes do not prove identity, continuity or independent support.

### 4.5 Current value and history are different

Corrections create revisions. Historical evidence remains openable after current applicability changes. Incompatible alternatives may coexist. Removing a successor does not automatically restore its predecessor.

Occurrence time, stated validity, receipt time and editorial revision time answer different questions. Late import or new summary is not a fresh world observation.

### 4.6 Origin, reuse scope and disclosure are different

Every item retains origin. Reusable methods separately state where they may be considered. Reuse never erases origin, conditions, counterexamples or disclosure limits.

Permission to consider a method elsewhere does not prove workspace, task or version conditions and does not authorize sending supporting source to a model.

A generalized method may be `external_allowed` while a supporting episode remains `local_only` only when generalized content no longer contains or reveals protected material.

### 4.7 Grounds are explicit enough to revise

A conclusion may depend on all members of one required group, one of several alternative groups, advisory support, or navigation links with no evidential meaning.

Eliot does not infer Boolean meaning from citation count. Unknown composition remains unknown. A material source change triggers targeted reconsideration, not whole-graph proof before every read. Cycles supply no independent support.

### 4.8 Support, exposure and influence are separate

Existence, support, retrieval exposure and advisory influence answer different questions. A frequently retrieved item is not thereby verified. An archived observation is not false. An untested hypothesis can be useful conditionally. Known refutation accompanies affected guidance rather than becoming a universal score.

### 4.9 Exact open is not broad retrieval

`open` requires one nonempty exact handle or source locator and optional bounded range. Search/context may suggest handles; only `open` resolves one.

Resolution preserves identity:

- current semantic handle → current revision or explicit absent/withdrawn/erased;
- version handle → exact historical revision or explicit missing/damaged, never current fallback;
- observation/source handle → retained accepted body/blob and actual locator;
- representation handle → exact transformation and relation to original, never silent reconversion.

Every exact read states requested/resolved identity, returned range/digest, current/history state, capture gaps, conditions/limitations, relation descriptors, expansion handles and next cursor where more material exists.

Empty exact selector never means broad project read. A fixed cap without continuation is incomplete coverage. Cursor binds exact object, revision, representation and options; units are explicit.

Opening one claim/method need not load every neighbor body, but it cannot hide material grounds, contradictions, replacements, exceptions or outcomes. Return bounded revision-aware relation descriptors and expansion handles.

### 4.10 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop guidance in a stated situation |
| Supersede/refute | Publish scoped replacement or contradiction |
| Erase scope | Remove controlled source/derivatives, staged data, controlled backups and every created controller inference copy |

Already delivered provider copies/effects are an external boundary. Restore cannot silently revive a known deletion. Erasure of unresolved inference requires explicit abandonment and cannot prove provider-side non-execution or deletion.

## 5. Current work and decision context

Current work is addressed before similarity search.

When the host supplies a usable task/session identity, Eliot opens the continuation directly, merges relevant later observations and only then retrieves related experience. A branch/workspace alone does not distinguish every concurrent task. A cancelled or superseded direction does not become current because it is semantically similar.

A decision packet contains only material that can change the next action:

- current goal and criteria;
- current plan, progress and open commitments;
- exact constraints and corrections;
- applicable or conditional methods;
- relevant prior episodes and exceptions;
- dissent, uncertainty and missing checks;
- source handles.

Exact values and qualifications travel together. A high-ranked method cannot crowd out its own exception. Prefer one concise qualified unit or explicit omission plus expansion handle over a misleading fragment.

Useful recall must not depend solely on an agent remembering to ask. The first Claude host uses `SessionStart` and `UserPromptSubmit` as delivery boundaries. A host without push hooks may pull at its next supported boundary.

Prepared context is not handoff; handoff is not use; use is not success. Do not wake a stopped agent merely for bookkeeping. Advice and enforcement are separate; negative memory is advisory by default.

## 6. Understanding

A project view is a reconstructible, revisable answer to a useful question over an examined scope: purpose, boundaries, responsibilities, consumers, rationale, failed approaches or intended-versus-observed discrepancy.

Exact structure comes from sources/tools. Semantic explanation may use a learning handler. Intended behavior, observed implementation and inferred explanation stay distinct.

Understanding is incremental: exact facts immediately; bounded orientation job; affected-view refresh only; complete-set claim invalidated by a new consumer; failed refresh leaves prior qualified view plus direct source access. It is not a compulsory pyramid, onboarding ceremony or self-model registry.

## 7. Learning and self-improvement

Learning changes external memory, methods, context construction and selected configurable strategies; it does not require model-weight training.

Once purpose/profile are configured, Eliot may interpret selected episodes, publish provisional lessons and revise methods through the ordinary write path. Reversible suggestions do not require votes or promotion ceremonies. They cannot change permissions, user goals or external acceptance.

### 7.1 One Memory job owns the semantic loop

```text
frozen sources + recipe + disclosure + saved WriteId/request
→ authenticated controller V2 call
→ private input + inference_calls row
→ at most one provider attempt
→ private result when present
→ Memory range read + digest/length verification + durable copy
→ purpose decoder
→ atomic publication or valid no-change
→ later consumer
→ release/cleanup
```

Terminal no-result produces no cognitive body or no-change, but may close cleanup. Store conflict replays retained result, not provider call. Ambiguous provider effect remains unknown. A new `WriteId` is not recovery.

Controller owns authentication, configuration, provider execution/readback and temporary copies; it does not own Memory job, source coverage, decoding or publication.

### 7.2 Model-independent cognitive contract

Processing method and result schema define the cognitive operation. Profile selects versioned adapter/connection/model; interface compatibility does not guarantee equal quality.

Retain profile/connection/adapter digests, actual destination, requested/observed model, finish/limits/usage/cost when supplied and unknown fields as unknown. Cleanup states remain separate from cognitive result.

A text job consumes the exact processing-method revision. Embeddings consume the selected profile. Deterministic reducers need neither. A proposal changes behavior only when a real consumer reads it.

### 7.3 Outcome attribution

Retain exact method revision offered or used where correlatable. Otherwise preserve the episode without invented attribution. Distinguish offered, handed off, action observed, adherence inferred or unknown, outcome observed and comparative benefit supported or unknown.

One attributable attempt/criterion contributes once. Replay or summary is not independent success. Missing correlation limits evaluation but not capture or provisional learning.

### 7.4 No-change, partial and cleanup

No-change is valid only for cognitive work completed on supplied input. Unavailable/disallowed profile, admission rejection, provider failure, no result, malformed output, truncation, unresolved execution or omitted input are not successful no-change.

Useful partial output may retain exact coverage. Cleanup outcome is separate: a failed request may clean successfully without learning; a useful result may remain cleanup-incomplete while Memory safely uses a verified copy.

### 7.5 Recursive improvement

Diagnose the failed connected edge: capture, selection, admission, provider execution, readback, cleanup, decode, publication, retrieval, delivery, use, applicability or method quality. Correct that edge instead of multiplying lessons or adding a global intelligence score.

Within repeatable work, Propose–Probe–Compose is optional. Baseline/no-change remains valid. A candidate is not automatically better. Irreversible effects are not repeated merely for comparison.

## 8. Disagreement, prediction, research and commitments

Disagreement belongs to question, scope and time. Preserve alternatives and grounds, then identify the cheapest useful distinguishing observation. A panel or vote is not default. Unresolved disagreement need not block unrelated work; a provisional choice records rationale and reconsideration trigger.

A prediction states the expected observation before action, conditions and available check. Static dependency, co-change and causal explanation are not interchangeable.

Research begins with available memory and exact local sources. External acquisition addresses a concrete remaining gap. Eliot Research owns execution/corpora; Memory stores compact findings, alternatives, coverage and exact handles. Failed request, uninformative completion and useful partial answer are distinct outcomes.

Commitments and problems are retained state, not notifications. Showing, acknowledging or passing a due date does not resolve them. Resolution follows a matching observed event or explicit owner change.

## 9. Reliability, backup/restore, privacy and control

Persist enough to distinguish capture rejected/staged/committed/unknown; context prepared/emitted/action-associated/use unknown; exact read complete/paged/missing/forbidden/erased/damaged; inference waiting/admitted/queued/sending/unknown/result copied/decoded/applied; per-copy cleanup; privileged maintenance/quiesce/cutover/selection state.

Acknowledgement is not completion. Heartbeat is not progress. Provider body is not a decoded proposal. Proposal is not published memory. Published memory is not external success. Cleanup success is not cognitive success.

External I/O never runs inside a Store transaction. Unknown effects reconcile through saved identity and native readback, never a new request ID.

### 9.1 Backup and exact rollback

Backup is an application-owned coherent typed cut. It records six tables, selected-root blobs, deletion notices, sanitized config, exact spool cut and controller inference cut. Manifest owns completeness. Surreal export/import and startup import are not selected.

Backup locks spool publication only for the short inventory/generation cut. Long table reads and file copies occur after lock release while post-cut relay staging continues separately.

Restore is exact rollback, not merge of later Store rows. A healthy current Store first gets a safety backup. Previous root stays until explicit retirement. Only deletion continuity and exact spool continuity auto-merge.

Before backup, Memory stops new inference admissions, persists every `WriteId` and records controller per-client `high_water` plus `earliest_retained_seq`. Restore reconciles in-cut jobs by the same WriteIds and inventories calls after the cut. Out-of-target results are not adopted without the lost exact job/source mapping. A retention gap is `history_gap`, never empty. All new inference stays disabled until inventory is complete and dispositioned; Base may resume independently.

If controller identity, caller credential or inventory is unavailable, restore records `external_work_inventory_unavailable`, keeps inference disabled and does not claim complete rollback or erasure.

### 9.2 Privacy and erasure

Secrets stay in their owner: controller owns provider/client derivation secret; supervisor owns root/Owner references; daemon gets Editor plus non-secret descriptors. Raw tokens and provider secrets never enter Memory Store/backup or controller receipts/logs.

Physical erasure traverses Memory source/derivatives/spool/backups and controller call copies. A late result cannot reintroduce erased material through an abandoned call. Complete erasure is not reported while a controlled copy remains or mismatches. Provider-side deletion requires an actual provider guarantee.

### 9.3 Direct control

Daemon external surface provides status/inbox, inspect/open, configure, pause/resume/cancel, correct/withdraw/erase, backup/restore and shutdown. It reports operation ID immediately and delegates only closed privileged effects to supervisor.

Status exposes ownership, spool/context/open gaps, profile/destination issues, unknown inference, post-restore inventory/history gap, maintenance/quiesce/cutover state and exact per-copy cleanup debt.

## 10. Explicit non-goals

V3 does not add without demonstrated consumer and owner decision:

- public supervisor API or generic administration bus;
- arbitrary commands, paths, SQL or secrets over privileged channel;
- second task/workflow engine inside Memory;
- duplicated provider/credential/router stack;
- controller V1 `swarm-client`, Manager/Operator or Operation/artifact surface;
- Agent, Goal, automation or script route for one-shot inference;
- old Governor/portfolio/capability platform;
- permanent Dreamer process/model loop;
- second semantic/vector database;
- truth/skill/outcome/packet registry;
- universal policy/approval/proof platform;
- route-classifier model or silent fallback;
- arbitrary provider fields;
- internal broker/event bus;
- actor/crate/contract/service per concept;
- per-helper lifecycle/proof/promotion manifests;
- runtime plugins, WASM or hot-generation machinery;
- global workspace fences before capture/read;
- full-graph verification before recall;
- mandatory model judge;
- success-shaped stubs or generated inventories;
- aggregate cleanup hiding a remaining copy;
- content hash as occurrence identity;
- empty exact selector as broad read;
- fixed relation truncation presented as complete;
- service-status text presented as context.

## 11. Product evidence

A capability exists only with:

```text
real input
→ owning operation
→ retained result or typed unknown
→ actual consumer
→ observable effect
→ restart/readback where relevant
```

Minimum Base evidence:

```text
real host event in session A
→ committed observation or durable staged command
→ replay when staged
→ restart
→ exact continuation/context in session B
→ actual host emission or explicit retrieval
→ exact source open with revision/range/digest
```

Minimum learning evidence:

```text
retained episode
→ saved request + precommitted WriteId
→ one controller provider attempt/result-or-unknown
→ verified Memory copy and typed decode
→ atomic revision/no-change/partial
→ changed later context
→ exact release/cleanup state
→ restart readback
```

Minimum restore evidence includes the brief spool cut, candidate qualification, selection replacement/readback, daemon re-admission, same-WriteId in-cut reconciliation, post-cut controller inventory or explicit history gap and no new inference until continuity is dispositioned.
