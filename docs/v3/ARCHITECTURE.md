# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.8 · 2026-10-24 · normative design for the greenfield rewrite.**

V1 and V2 are donors. V3 is a new implementation, not a compatibility migration.

This document defines product purpose, ownership and invariants. [Implementation](IMPLEMENTATION.md) defines the Memory runtime, data and connected operations. [Cognition](COGNITION.md) defines algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) is the sole normative Memory↔controller boundary. [AUDIT](AUDIT.md) explains rejected machinery and source limits. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the only active analysis ledger.

## 1. Product purpose

Eliot makes accumulated experience useful at the next decision.

```text
observe what happened
→ preserve the source
→ reconstruct current work
→ supply applicable context
→ a person or external agent acts
→ observe the result
→ revise memory or method
→ use that revision later
```

A searchable archive is necessary but insufficient. Product value is visible when Eliot:

- restores interrupted work without inventing state;
- prevents known failed approaches from silently returning;
- exposes relevant constraints, counterexamples and unknowns before a decision;
- turns observed outcomes into later changes in guidance;
- keeps original sources openable and corrections reversible;
- remains useful when optional models, vectors or specialist tools are unavailable.

A mechanism enters V3 only after its real caller, owner, retained result and consumer are named. A type, port, receipt, fixture, report, issue or passing serializer is not product behavior by itself.

The unit of completion is a connected edge:

```text
shipped caller
→ owning operation
→ durable result or typed unknown
→ actual consumer/readback
→ restart/recovery
```

More metadata, stages, checks, processes or interfaces are not benefits by themselves. Correct a repeatedly harmful default at its owner instead of adding an exception layer.

## 2. Ownership and boundaries

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance of external work | Human and host/controller |
| Agent sessions, tools, task execution and swarm orchestration | Host/controller |
| Host event translation and host-supported context emission | Narrow host adapter/relay |
| Observations, revisions, retrieval, context, source links, outcomes and finite memory jobs | Eliot Memory OS |
| Interpretation, consolidation and method improvement | Eliot learning handlers |
| Provider credentials, configured connections, physical model invocation and provider readback | `eliot-swarm-controller` |
| Persistence, native indexes and transactions | SurrealDB through one private Memory Store |
| Code/document/source translation | Narrow adapters and configured specialist tools |
| External research execution and large research corpora | Eliot Research or another configured research system |
| Detection of daemon/process-family failure | Supervisor outside the daemon failure domain |

Eliot may link an external task, attempt, action and result, but it does **not** become another task manager, acceptance authority, permission engine, swarm controller or research platform.

A host adapter translates native events and emits context through a real host boundary. It does not invent memory semantics, claim Store ownership before readback or replace source bytes with a lossy status record.

The controller may execute one model request for Eliot, but it does **not** own Eliot's memory job, episode coverage, processing recipe, disclosure reduction, decoding, publication or retry decision. Eliot does not copy controller Tasks, Attempts, workspaces, reviews or provider internals merely to obtain one completion.

### 2.1 Dreamer is a role, not a mandatory process

**Dreamer** means model-assisted interpretation for a concrete finite Eliot job. It is not a permanent daemon, model vendor, special database, separate scheduler or second canonical writer.

A learning handler freezes finite input and one exact processing-method revision, builds an exact request, calls the configured controller inference boundary outside the Store transaction, retains the verified result when one exists, decodes a purpose-specific response and publishes ordinary memory revisions. Deterministic reducers and embeddings do not become Dreamer jobs merely because they use computation.

### 2.2 One-shot inference is not agent orchestration

The first learning extension needs this semantic operation:

```text
exact input + selected profile + disclosure + finite limits + stable request key
→ complete | partial | failed | unknown
→ exact returned body when present + requested/observed execution facts
```

Memory calls narrow controller operations through the existing authenticated local IPC client:

```text
inference.text
inference.embed
inference.release
operation.get
operation.cancel
artifact.get
artifact.read
```

These operations do not require a controller Task, Requirement, Attempt, binding, workspace, native agent session, review, submission or acceptance lifecycle.

Richer software-agent work continues to use controller Tasks and native sessions when it genuinely needs tools, continuation or orchestration. One memory extraction must not expand into a generic workflow engine inside Memory OS.

### 2.3 Connection and profile are different owners

Controller configuration owns two small static records.

`InferenceConnection` owns:

- transport and endpoint;
- private credential reference;
- non-secret connection identity;
- declared `actual_destination = local | external`.

`actual_destination` describes where supplied content ultimately goes. A loopback gateway that forwards to a cloud provider is `external`.

`InferenceProfile` owns:

- one closed, versioned adapter ID;
- one connection reference;
- requested model;
- automatic-use permission;
- finite input, output, timeout and concurrency limits;
- supported response formats.

The resolved profile inherits `actual_destination` from its connection. Controller computes immutable non-secret connection/profile digests and freezes the resolved snapshot on admission. Reconfiguration affects a new explicit request; it cannot mutate an admitted Operation.

Memory selects only a profile name. It does not receive provider secrets or construct arbitrary headers, query parameters, provider extras or fallback ladders.

There is no implicit fallback. An unavailable connection, profile, provider, model or capacity returns a specific waiting, rejection, failure or unknown state. Controller cannot silently switch provider, model, account, destination, retention or billing semantics.

### 2.4 Disclosure is checked at the actual send boundary

Memory reduces material actually supplied to one value:

```text
local_only
external_allowed
```

Project configuration supplies the default; a source may be stricter. Derived content cannot widen the strictest source it still contains or reveals. Mixed input uses the strictest contributing class. Reuse scope does not widen disclosure.

`local_only` requires a connection whose `actual_destination` is `local`. Protected material is not silently omitted to make an external profile pass. The job waits or fails with a specific profile/disclosure gap; it is not successful no-change and does not mark input processed.

These checks belong to controller admission after it resolves the actual connection/profile. Memory must not infer destination from a loopback address or stale duplicate configuration. This boundary does not justify a general Governor, route classifier, approval ceremony, capability registry, portfolio planner or per-call proof package.

### 2.5 Controlled request and result copies have finite lifetime

One inference Operation creates at most two controller-owned content artifacts:

```text
inference_input
inference_result
```

Exact input is staged before provider I/O without copying raw content into generic Operation JSON. Exact visible result, when one exists, is retained long enough for readback after disconnect or restart.

Successful result path:

1. Memory reads the result in bounded ranges;
2. verifies length and digest;
3. durably copies it into its existing job/blob;
4. calls `inference.release(memory_copy_verified)`.

Other cleanup paths remain first-class:

- rejected, failed or queued-cancelled terminal Operation without result uses `terminal_without_result` to remove retained input;
- unresolved work selected for physical erase uses explicit `abandon_for_erasure`, which fences future controller dispatch, settlement and publication before cleanup.

Controller tracks input and result cleanup independently. One removed file cannot hide another retained, mismatched or unknown copy. Aggregate `released` is valid only when every created controller content artifact is removed or verified already absent.

Release failure does not invalidate a verified Memory copy, but remains visible and prevents complete erasure. `abandon_for_erasure` cannot prove that provider execution, storage or billing did not occur. Provider-held copies/effects are an external boundary; controller-managed files are not.

### 2.6 User intent and factual reports remain distinct

The user owns goals and preferences, not infallibility about external facts. Preserve an explicit change of intent as such. Preserve a factual assertion with its source, conditions and possible counterevidence. A generated continuation, learned method or retrieved suggestion cannot silently replace the user's goal, relax its criteria or grant execution authority.

## 3. Product shape

The initial product supports several configured projects concurrently. Project-local state remains scoped; explicitly reusable methods may be considered across the owner's selected projects.

The initial product is:

- one Rust package and one codebase;
- one executable with supervisor, daemon and transient relay modes;
- one private application Store;
- one SurrealDB server child;
- ordinary internal modules;
- optional outbound clients constructed only when enabled.

A new process is justified only by a real external runtime or failure boundary. A new crate is justified only by an actual dependency, deployment or independently changing boundary. A noun in the design is not an instruction to create a registry, protocol, actor, state machine or service.

One stored mutable state has one application mutation owner. This does not mean one permitted author, one interpretation or one source. Dashboards, packets, scores, maps and status reports are views unless they own independent state.

### 3.1 Layers remain; pass-through machinery does not

Keep four responsibility layers:

1. **domain and pure transformations** — values, comparison, reduction and packing over supplied inputs;
2. **application operations** — capture, revision, retrieval, learning and control;
3. **external I/O** — Store, host, controller inference, document and Research adapters;
4. **surfaces/runtime** — CLI, hooks/MCP, process startup and composition.

These are dependency boundaries, not four processes or a compulsory `interface → facade → service → repository` chain. Internal calls use typed Rust values. Serialization belongs at actual storage, process or network boundaries. Add a trait only where a real interchangeable I/O boundary exists.

An extension is a vertical capability across the layers it actually uses. It adds a real writer/handler and consumer to existing operations; it does not build a miniature platform with its own scheduler, database, context compiler and supervisor.

### 3.2 Useful Base, then additive capabilities

**Base** works without controller, model, vector encoder, document converter, project graph or Research credentials. It provides:

- capture from one real host;
- explicit notes, corrections and commitments with history;
- exact and lexical retrieval;
- addressed current-work reconstruction from saved state and available events;
- bounded context delivery and exact source opening;
- restart, spool, backup/restore and erase for retained Base data;
- direct status and control.

Base is a useful limited product, not a claim of automatic learning.

The first learning extension closes one connected loop:

```text
retained episode
→ exact processing recipe
→ one admitted inference Operation
→ retained typed create/revise/no-change result
→ ordinary memory revision
→ changed later context
→ controller input/result copies released or exact cleanup gap reported
```

A terminal no-result Operation still closes its cleanup edge without fabricating cognitive no-change.

Vectors, project understanding, documents, Research, more hosts and richer cognition are independent increments. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. There is no separate Lite database, Full memory engine or compulsory all-module installation.

Optional means optional in construction, startup and execution. A failed or disabled extension cannot disable capture, exact reads or source opening. Disabling a producer stops new work without deleting readable retained knowledge. Re-enabling it does not require a full-corpus rebuild before ordinary use.

### 3.3 First host profile is a narrow relay, not a plugin platform

The first integrated host profile is one Claude Code hook relay because it exposes real lifecycle, user-prompt, tool-result and final-response boundaries. Claude-specific JSON remains an adapter input. It does not become the Memory domain model or force every host to imitate Claude.

The initial Base event set is intentionally finite:

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

`SessionStart` and `UserPromptSubmit` are also supported decision-time context boundaries. `Stop` and `SubagentStop` retain the host-supplied final response directly when available. `PostCompact` is a derived representation, not replacement source truth.

`PreToolUse`, permission and stop enforcement are not Base memory requirements. Negative memory is advisory by default. A later host guard is explicit, narrow and opt-in; V3 does not carry forward a general lease, finish or compaction gate merely because a historical plugin exposed one.

The installed host version and actual emitted payloads must be qualified during implementation. Current public documentation is a design input, not proof of an installed runtime.

### 3.4 Direct capture and spool share one ownership operation

The relay builds one complete bounded `CaptureCommand` before any daemon call. Direct delivery and replay use that same command and same idempotency identity.

```text
exact CaptureCommand
→ daemon capture
→ Store identity/digest readback
→ committed

unknown/unavailable daemon result
→ atomic durable publication to pending spool
→ staged
→ daemon replays same capture operation
→ Store readback
→ pending body removed
```

There is no successful `forwarded` state without Store ownership/readback. There is no `staged` state before the exact command is durably published.

The spool is a transport-recovery queue, not a second memory database. The daemon is its sole replayer. Corrupt or permanently rejected entries move to a failed area with bounded non-content diagnostics; they do not retry forever. Successful replay removes the content-bearing pending file instead of maintaining a second committed archive.

Durable publication means same-directory temporary regular file, complete write, file synchronization, atomic rename and parent-directory synchronization. A direct write to the final path is not a durable queue contract.

Capture remains useful when context or optional learning fails. Context failure does not roll back a committed source event.

### 3.5 Context handoff is a real host effect

A context packet is useful only when rendered content crosses a supported host boundary. A message such as “event spooled” is status, not context. A local file or generated packet is not delivery.

The packet is retained through ordinary V3 data rather than a PacketStore: an application observation/blob records packet identity, rendered digest, budget, gaps and exact included revisions; ordinary links record inclusion and observed handoff.

Keep these states distinct:

```text
prepared
emitted through the host contract
associated with a later action when observable
actually used or influential: usually unknown unless separately observed
```

Failure to emit a packet leaves explicit retrieval and source opening available. The host receives a specific gap rather than fabricated empty success.

## 4. Identity and memory invariants

### 4.1 Project, workspace, work identity and environment are different

A project is a configured scope of work; it need not be a Git repository. A workspace identifies one working instance. A task or actor/session address identifies continuing work. Path, branch, commit, resource version and time describe changing environment.

Therefore:

- switching branch does not erase a continuing goal or commitment;
- a result from checkout B does not establish checkout A's condition;
- fork and explicit transfer retain relations rather than silently renaming work;
- a late result keeps the binding captured when issued;
- unknown association limits claims about a resource but does not block preservation of input.

There is no universal workspace generation whose mismatch disables the whole project.

### 4.2 Occurrence identity and content equality are different

A real occurrence is identified by the strongest native event identity available, plus its bound host/session/task/resource scope. When the host supplies no unique event key, the relay-generated command ID is the occurrence key and replay idempotency key.

A content digest verifies bytes. It does not merge two real occurrences merely because their text is equal and does not become a logical source ID unless the object is explicitly content-addressed.

An identical replay of one command returns its prior result. A different occurrence with identical bytes remains a different observation.

### 4.3 Preserve accepted source before interpretation

Capture exclusions run before ownership transfer. Material accepted for capture is retained exactly within its declared bound, either inline or as an immutable blob. Extracted text, fields and search excerpts are projections, not replacement source truth.

A generic key-name sanitizer cannot silently remove URLs, endpoints, paths, final messages or other source locators from accepted source data. Secret exclusions and redactions are explicit, narrow and recorded as capture limitations. Host-side truncation or omitted fields remain visible as gaps.

Missing models, embeddings, project views or external services cannot destroy captured source or prevent exact readback.

### 4.4 Source, representation and claim are different

An observation records what a source supplied, not that every statement inside it is true. A claim, explanation, method, prediction or project view is derived knowledge.

Derived knowledge retains exact source handles and revisions. Retrieval does not strengthen support. Model-generated IDs are not evidence. Exact names, versions, values, negations, limitations and counterexamples travel with a useful summary.

A source object, version and transformed representation have different identities. Rename, copy, conversion, crop and export retain explicit relations. Similarity or equal bytes do not prove identity, continuity or independent support.

### 4.5 Current value and history are different

Corrections create revisions. Historical evidence remains openable after current applicability changes. Incompatible alternatives may coexist. Removing a successor does not automatically restore its predecessor.

Occurrence time, stated validity, receipt time and editorial revision time answer different questions. A late import or new summary is not a fresh world observation.

### 4.6 Origin, reuse scope and disclosure are different

Every item retains origin. Reusable methods separately state where they may be considered: origin project, selected projects or the local owner's projects.

Reuse never erases origin, material conditions, counterexamples or disclosure limits. Permission to consider a method elsewhere does not prove workspace/task/version conditions and does not authorize sending its sources to a model.

A generalized method may be `external_allowed` while a supporting episode remains `local_only` only when the generalized content no longer contains or reveals protected material. Otherwise the stricter disclosure remains.

### 4.7 Grounds are explicit enough to revise

A conclusion may depend on all members of one required group, one of several alternative groups, advisory support, or navigation links carrying no evidential meaning.

Eliot does not infer Boolean meaning from citation count. Unknown composition remains unknown. A material source change triggers targeted reconsideration, not whole-graph proof before every read. Cycles supply no independent support.

### 4.8 Support, exposure and influence are separate

Existence, support, retrieval exposure and advisory influence answer different questions. A frequently retrieved item is not thereby verified. An archived observation is not false. An untested hypothesis can be useful conditionally. Known refutation accompanies affected guidance rather than becoming a generic score.

These distinctions live on ordinary records and links. They do not require a truth registry, universal confidence score or promotion ladder before capture.

### 4.9 Exact open is not broad retrieval

`open` requires one nonempty exact handle or source locator and an optional bounded range. Search/context may suggest handles; only `open` resolves one.

Exact handles preserve requested identity:

- a current semantic handle resolves current revision or explicit absent/withdrawn/erased state;
- a version handle resolves exactly that historical revision or explicit missing/damaged state;
- an observation/source handle resolves the retained body/blob representation and actual locator;
- a transformed representation handle resolves that representation and its relation to the original, never a silent reconversion or newer substitute.

Every exact read states the requested and resolved identity, returned byte/item range and digest, current/history state, capture gaps, material conditions and limitations, relation descriptors, expansion handles and next cursor where more retained material exists.

An empty exact selector never means “return a broad project read.” Broad navigation is a separate bounded query with its own scope, denominator and cursor.

Opening one claim or method does not have to expand every source body, but it cannot hide the existence of material grounds, contradictions, replacements, exceptions or outcomes merely because the caller did not already know both endpoints. Return bounded revision-aware relation descriptors and expansion handles. Neighbor bodies are subsequent exact reads.

A fixed relation cap without continuation is incomplete coverage, not complete exact read. `requested`, `returned`, `missing` and `forbidden` dispositions are derived from actual reads. `truncated=true` requires a valid continuation for the omitted readable part or an explicit non-pageable gap.

Ranges/cursors bind to the exact object, revision, representation and read options. A cursor cannot be replayed against another object or changed current revision. Limits state their unit: rows, bytes, decoded elements or rendered text.

### 4.10 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop guidance in the stated situation |
| Supersede/refute | Publish a scoped replacement or contradiction |
| Erase scope | Remove controlled source/derivatives, staged data, controlled backups and every created controller inference copy |

Already delivered provider copies/effects are an external boundary. Restore cannot silently revive a known deletion. Erasure of an unresolved Operation requires explicit abandonment and cannot be reported as proof of provider-side deletion or non-execution.

## 5. Current work and decision context

Current work is addressed before similarity search.

When the host supplies a usable task/session identity, Eliot opens the continuation directly, merges relevant later observations and then retrieves related experience. A branch or workspace alone does not distinguish every concurrent task. A cancelled or superseded direction does not become current because it is semantically similar.

A decision packet contains only material that can change the next action:

- current goal and criteria;
- current plan, progress and open commitments;
- exact constraints and corrections;
- applicable or conditional methods;
- relevant prior episodes and exceptions;
- dissent, uncertainty and missing checks;
- source handles.

Exact values and qualifications travel together. A high-ranked method cannot crowd out its own exception. Prefer a concise qualified unit or specific omission with an expansion handle over a misleading fragment. Empty sections add no filler.

Eliot supports reactive context at a real host boundary, explicit retrieval/open and optional model-assisted orientation for a concrete question.

Useful recall must not depend solely on an agent remembering to ask. The first Claude host uses `SessionStart` and `UserPromptSubmit` as direct delivery boundaries. A host without push hooks may pull at its next supported boundary.

Prepared context is not handoff; handoff is not use; use is not success. Do not wake a stopped agent merely for bookkeeping.

Advice and enforcement are separate. Negative memory is advisory by default. A host-enforced rule is explicit, narrow and opt-in.

## 6. Understanding

A project view is a reconstructible, revisable answer to a useful question over an examined scope: purpose, boundaries, responsibilities, consumers, rationale, failed approaches or intended-versus-observed discrepancy.

Exact structure comes from sources and tools. Semantic explanation may use a learning handler. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is incremental:

- first contact returns exact available facts immediately;
- a bounded orientation job creates useful views;
- source changes refresh affected views only;
- a new consumer can invalidate a complete-set claim without changing old cited files;
- failed refresh leaves the prior qualified view and direct source access available.

Understanding is not a compulsory pyramid, onboarding ceremony or placeholder card. The same source/view mechanism applies to Eliot itself. A summary or health check cannot certify architecture implementation; no separate self-model registry is needed.

## 7. Learning and self-improvement

Initial learning changes external memory, methods, context construction and selected configurable strategies. It does not require model-weight training.

Once a learning purpose and permitted profile are configured, Eliot may automatically interpret selected episodes, publish provisional lessons and revise methods through the ordinary write path. Reversible improvements do not require a vote, promotion ceremony or experiment before every useful suggestion. They cannot change permissions, user goals or external task acceptance.

### 7.1 One Memory job owns the semantic loop

Successful result path:

```text
frozen sources + exact recipe revision + disclosure
→ saved exact Memory request
→ direct authenticated controller IPC
→ controller inference_input + one inference Operation
→ frozen InferenceConnection / InferenceProfile behavior
→ controller inference_result
→ Memory range read + length/digest verification + durable copy
→ purpose-specific decoder
→ atomic publication or valid no-change
→ later consumer
→ inference.release(memory_copy_verified)
```

Terminal no-result path:

```text
rejection / failed attempt without result / queued cancellation
→ no cognitive body and no no-change
→ inference.release(terminal_without_result)
→ retained input copy removed or exact cleanup gap
```

Erasure of unresolved work:

```text
queued / sending / unknown Operation selected for erase
→ inference.release(abandon_for_erasure)
→ controller fences future dispatch/settlement/publication
→ controlled copies removed when exact
→ provider effect/copy remains external unknown
```

Controller owns configured connection, adapter execution, Operation identity/readback and temporary artifacts. It does not claim, complete or mutate the Memory job.

Store conflicts replay the retained result, not the model call. An ambiguous external outcome remains unknown until native readback resolves it or the owner explicitly abandons it. A new request ID is not recovery.

### 7.2 Model-independent cognitive contract

The processing method and result schema define the cognitive operation. A profile selects one versioned adapter, connection and requested model. Interface compatibility does not guarantee equal quality.

Retain:

- profile and connection digests plus adapter ID;
- `actual_destination`;
- requested/observed model and provider facts;
- observed finish, limits, usage and cost when supplied;
- unknown fields as unknown, not zero or inferred;
- input/result cleanup states independently.

A text job consumes the exact processing-method revision. Embeddings consume the selected profile. Deterministic reducers need neither. A stored proposal changes behavior only when a real consumer reads it.

### 7.3 Outcome attribution

Where an external action can be correlated, retain the exact method revision offered or used. Otherwise preserve the episode without invented attribution. Distinguish offered, handed off, action observed, adherence inferred or unknown, outcome observed and comparative benefit supported or unknown.

One attributable attempt/criterion contributes once. Replayed hooks and summaries are not independent successes. Missing correlation limits evaluation; it does not block capture, retrieval or provisional learning.

### 7.4 No-change, partial and cleanup

No-change is valid only for cognitive work completed on supplied input. It is not a mandatory explanation after every event.

Unavailable/disallowed profile, admission rejection, provider failure, no result, malformed output, missing fields, truncation, unresolved execution and partial processing are not successful no-change. Useful partial output may be retained with exact coverage; it cannot mark omitted input processed.

Cleanup outcome is separate from cognitive outcome. A failed/no-result request may complete cleanup successfully without producing learning. A useful result may remain cleanup-incomplete while Memory safely uses a verified local copy.

### 7.5 Recursive improvement

Self-improvement diagnoses the failed connected edge: capture, source selection, admission, controller execution, result readback, cleanup, decoding, publication, retrieval, delivery, use, applicability or method quality. Correct that edge instead of multiplying duplicate lessons or adding a global intelligence score.

Within repeatable work, Eliot may use Propose–Probe–Compose. Across tasks, it retains lessons. Baseline/no-change remains valid. A selected candidate is not automatically better. Irreversible effects are not repeated merely for comparison.

## 8. Disagreement, prediction, research and commitments

Disagreement belongs to a question, scope and time. Preserve rivals and grounds, then identify the cheapest useful distinguishing observation. One source lookup, agent or human decision may be enough. A panel or vote is not required.

Unresolved disagreement does not block unrelated work. A provisional choice records rationale and a reconsideration trigger.

A prediction states the expected observation before action, conditions and available check. Static dependency, co-change and causal explanation are not interchangeable.

Research begins with available memory and exact local sources. External acquisition is for a concrete remaining gap. Eliot Research owns execution and corpora; Memory stores compact findings, alternatives, coverage and exact handles.

A failed source request, completed but uninformative research and useful partial answer are different outcomes. Repeating uncertainty does not justify an endless research loop.

Commitments and problems are retained state, not notifications. Showing or acknowledging one does not resolve it; a passed due date does not complete it. Resolution follows a matching observed event or explicit owner change. Notifications do not create another task manager.

## 9. Reliability, privacy and direct control

Persist enough information to distinguish:

- source command not accepted, rejected, staged, committed or unknown;
- context prepared, emitted, action-associated or use unknown;
- exact read complete, paged, missing, forbidden, erased or damaged;
- inference not requested, waiting, requested but not admitted, queued or sending;
- external outcome unknown;
- result retained by controller or copied into Memory;
- decoded or applied;
- terminal without result;
- input cleanup state and result cleanup state;
- aggregate cleanup pending, incomplete or released;
- abandoned for erasure;
- provider-side effect/copy external unknown;
- partial, failed, cancelled or erased.

Acknowledgement is not completion. Heartbeat is not progress. Prepared context is not handoff. Provider body is not a decoded proposal. Proposal is not published memory. Published memory is not proof of external success. Cleanup success is not cognitive success; cognitive success is not cleanup success.

Primary capture and reads remain available when optional routes fail. External I/O never runs inside a Store transaction. Unknown outcomes reconcile through saved identity and native readback, not a new request ID.

Secrets remain in controller. Memory stores profile name, frozen non-secret execution identity, Operation/result references and observed facts. Missing usage, cost or account identity remains unknown.

Physical erasure traverses Memory inputs/results, pending spool, controlled backups and each controller content artifact. A late result cannot reintroduce erased material through an abandoned Operation. Do not report complete erasure while a controlled copy remains or mismatches; do not report provider-side deletion unless the provider actually guarantees it.

Direct control provides status/inbox, inspect/open, configure, pause/resume/cancel, correct/withdraw/erase, backup/restore and shutdown. It reports capture ownership, spool backlog/failures, context handoff gaps, exact-read gaps, profile/connection unavailability, destination mismatch, unknown inference outcome, abandonment and exact per-copy cleanup gaps.

## 10. Explicit non-goals

V3 does not add these without a demonstrated consumer and owner decision:

- a second task manager or workflow engine inside Memory;
- a duplicated provider/credential/router stack;
- controller Task/Attempt for one-shot inference;
- agent workspace/session route types as inference configuration;
- the old Governor route/capability/fingerprint/portfolio platform;
- a permanent Dreamer process or model loop;
- a second semantic/vector database;
- a truth/skill registry, outcome store or packet database;
- a universal policy/approval/proof platform;
- a route-classifier model or silent fallback;
- arbitrary provider fields under unspecified compatibility;
- a broker/event bus for internal calls;
- an actor/crate/contract/service per concept;
- per-helper lifecycle/proof/promotion manifests;
- runtime Rust plugins, WASM packaging or hot-generation machinery;
- global project/workspace fences before ordinary capture/read;
- full-graph verification before useful recall;
- a mandatory model judge;
- success-shaped stubs;
- generated inventories as permanent authorities;
- an aggregate cleanup flag that hides which controlled copy remains;
- a successful `forwarded` capture result without Store readback;
- content hash as occurrence identity;
- empty exact selector as a broad-read shortcut;
- fixed relation truncation presented as complete exact open;
- service-status text presented as memory context.

## 11. Product evidence

A capability is present only when a real path exists:

```text
real input
→ owning operation
→ retained result or typed unknown
→ actual consumer
→ observable product effect
→ restart/readback where relevant
```

For Base, minimum evidence is:

```text
real host event in session A
→ committed observation or durable staged command
→ daemon replay when staged
→ service restart
→ exact continuation/context in session B
→ actual host emission or explicit retrieval
→ exact source open with revision/range/digest
```

A local spool file without replay is not Base capture. A rendered packet without host emission is not context delivery. An exact-read response with hidden truncation or missing relation descriptors is not complete open.

For first learning, minimum evidence is one retained episode, exact recipe/disclosure, one frozen connection/profile behavior, one controller Operation, exact result read/Memory copy when result exists, decoded publication or valid no-change, later context reading the resulting revision, and exact cleanup disposition showing input/result removed or an explicit per-copy gap.

For terminal no-result, minimum evidence is an exact operational failure/cancellation, no fabricated cognitive result, and successful input cleanup or explicit gap.

A stored type, fixture, receipt, generated report, serializer or leaf compilation alone is not evidence.