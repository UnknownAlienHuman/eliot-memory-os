# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.7 · 2026-10-24 · normative design for the greenfield rewrite.**

V1 and V2 are donors. V3 is a new implementation, not a compatibility migration.

This document defines product purpose, ownership and invariants. [Implementation](IMPLEMENTATION.md) defines the Memory runtime, data and connected operations. [Cognition](COGNITION.md) defines algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) is the sole normative Memory↔controller boundary. [AUDIT](AUDIT.md) explains rejected machinery and source limits. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the active analysis ledger.

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
| Observations, revisions, retrieval, context, source links, outcomes and finite memory jobs | Eliot Memory OS |
| Interpretation, consolidation and method improvement | Eliot learning handlers |
| Provider credentials, configured connections, physical model invocation and provider readback | `eliot-swarm-controller` |
| Persistence, native indexes and transactions | SurrealDB through one private Memory Store |
| Code/document/source translation | Narrow adapters and configured specialist tools |
| External research execution and large research corpora | Eliot Research or another configured research system |
| Detection of daemon/process-family failure | Supervisor outside the daemon failure domain |

Eliot may link an external task, attempt, action and result, but it does **not** become another task manager, acceptance authority, permission engine, swarm controller or research platform.

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

Project configuration supplies default; a source may be stricter. Derived content cannot widen the strictest source it still contains or reveals. Mixed input uses strictest contributing class. Reuse scope does not widen disclosure.

`local_only` requires a connection whose `actual_destination` is `local`. Protected material is not silently omitted to make an external profile pass. Job waits or fails with specific profile/disclosure gap; it is not successful no-change and does not mark input processed.

These checks belong to controller admission after it resolves actual connection/profile. Memory must not infer destination from loopback address or stale duplicate config. This boundary does not justify general Governor, route classifier, approval ceremony, capability registry, portfolio planner or per-call proof package.

### 2.5 Controlled request and result copies have finite lifetime

One inference Operation creates at most two controller-owned content artifacts:

```text
inference_input
inference_result
```

Exact input is staged before provider I/O without copying raw content into generic Operation JSON. Exact visible result, when one exists, is retained long enough for readback after disconnect or restart.

Successful result path:

1. Memory reads result in bounded ranges;
2. verifies length/digest;
3. durably copies it into existing job/blob;
4. calls `inference.release(memory_copy_verified)`.

Other cleanup paths remain first-class:

- rejected, failed or queued-cancelled terminal Operation without result uses `terminal_without_result` to remove retained input;
- unresolved work selected for physical erase uses explicit `abandon_for_erasure`, which fences future controller dispatch/settlement/publication before cleanup.

Controller tracks input and result cleanup independently. One removed file cannot hide another retained, mismatched or unknown copy. Aggregate `released` is valid only when every created controller content artifact is removed or verified already absent.

Release failure does not invalidate a verified Memory copy, but remains visible and prevents complete erasure. `abandon_for_erasure` cannot prove that provider execution, storage or billing did not occur. Provider-held copies/effects are an external boundary; controller-managed files are not.

### 2.6 User intent and factual reports remain distinct

The user owns goals and preferences, not infallibility about external facts. Preserve explicit change of intent as such. Preserve factual assertion with source, conditions and possible counterevidence. Generated continuation, learned method or retrieved suggestion cannot silently replace user goal, relax criteria or grant execution authority.

## 3. Product shape

The initial product supports several configured projects concurrently. Project-local state remains scoped; explicitly reusable methods may be considered across the owner's selected projects.

The initial product is:

- one Rust package and one codebase;
- one executable with supervisor, daemon and transient relay modes;
- one private application Store;
- one SurrealDB server child;
- ordinary internal modules;
- optional outbound clients constructed only when enabled.

A new process is justified only by real external runtime or failure boundary. A new crate is justified only by actual dependency, deployment or independently changing boundary. A noun in design is not instruction to create registry, protocol, actor, state machine or service.

One stored mutable state has one application mutation owner. This does not mean one permitted author, one interpretation or one source. Dashboards, packets, scores, maps and status reports are views unless they own independent state.

### 3.1 Layers remain; pass-through machinery does not

Keep four responsibility layers:

1. **domain and pure transformations** — values, comparison, reduction and packing over supplied inputs;
2. **application operations** — capture, revision, retrieval, learning and control;
3. **external I/O** — Store, host, controller inference, document and Research adapters;
4. **surfaces/runtime** — CLI, MCP/hooks, process startup and composition.

These are dependency boundaries, not four processes or compulsory `interface → facade → service → repository` chain. Internal calls use typed Rust values. Serialization belongs at actual storage, process or network boundaries. Add trait only where real interchangeable I/O boundary exists.

An extension is a vertical capability across layers it actually uses. It adds real writer/handler and consumer to existing operations; it does not build miniature platform with scheduler, database, context compiler and supervisor.

### 3.2 Useful Base, then additive capabilities

**Base** works without controller, model, vector encoder, document converter, project graph or Research credentials. It provides:

- capture from one real host;
- explicit notes, corrections and commitments with history;
- exact and lexical retrieval;
- addressed current-work reconstruction from saved state and available events;
- bounded context delivery and exact source opening;
- restart, spool, backup/restore and erase for retained Base data;
- direct status and control.

Base is useful limited product, not claim of automatic learning.

First learning extension closes one connected loop:

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

Vectors, project understanding, documents, Research, more hosts and richer cognition are independent increments. They reuse same records, finite jobs, revision publication, context assembly and maintenance path. There is no separate Lite database, Full memory engine or compulsory all-module installation.

Optional means optional in construction, startup and execution. Failed/disabled extension cannot disable capture, exact reads or source opening. Disabling producer stops new work without deleting readable retained knowledge. Re-enabling does not require full-corpus rebuild before ordinary use.

## 4. Identity and memory invariants

### 4.1 Project, workspace, work identity and environment are different

A project is configured scope of work; it need not be Git repository. Workspace identifies one working instance. Task or actor/session address identifies continuing work. Path, branch, commit, resource version and time describe changing environment.

Therefore:

- switching branch does not erase continuing goal/commitment;
- result from checkout B does not establish checkout A's condition;
- fork and explicit transfer retain relations rather than silently renaming work;
- late result keeps binding captured when issued;
- unknown association limits claims about resource but does not block preserving input.

There is no universal workspace generation whose mismatch disables whole project.

### 4.2 Preserve before interpretation

Permitted source events are stored before model interpretation. Missing models, embeddings, maps or external services cannot destroy original or prevent direct readback.

Replay is deduplicated by source identity, not text equality. Distinct occurrences remain distinct even when text matches. Several IDs, summaries or representations of one event do not create independent corroboration.

### 4.3 Source, representation and claim are different

Observation records what source supplied, not that every statement is true. Claim, explanation, method, prediction or project view is derived knowledge.

Derived knowledge retains exact source handles/revisions. Retrieval does not strengthen support. Model-generated IDs are not evidence. Exact names, versions, values, negations, limitations and counterexamples travel with useful summary.

Source object, version and transformed representation have different identities. Rename, copy, conversion, crop and export retain explicit relations. Similarity/equal bytes do not prove identity, continuity or independent support.

### 4.4 Current value and history are different

Corrections create revisions. Historical evidence remains openable after current applicability changes. Incompatible alternatives may coexist. Removing successor does not automatically restore predecessor.

Occurrence time, stated validity, receipt time and editorial revision time answer different questions. Late import/new summary is not fresh world observation.

### 4.5 Origin, reuse scope and disclosure are different

Every item retains origin. Reusable methods separately state where they may be considered: origin project, selected projects or local owner's projects.

Reuse never erases origin, material conditions, counterexamples or disclosure limits. Permission to consider method elsewhere does not prove workspace/task/version conditions and does not authorize sending sources to model.

Generalized method may be `external_allowed` while supporting episode remains `local_only` only when generalized content no longer contains/reveals protected material. Otherwise stricter disclosure remains.

### 4.6 Grounds are explicit enough to revise

A conclusion may depend on all members of required group, one of alternative groups, advisory support, or navigation links carrying no evidential meaning.

Eliot does not infer Boolean meaning from citation count. Unknown composition remains unknown. Material source change triggers targeted reconsideration, not whole-graph proof before every read. Cycles supply no independent support.

### 4.7 Support, exposure and influence are separate

Existence, support, retrieval exposure and advisory influence answer different questions. Frequently retrieved item is not thereby verified. Archived observation is not false. Untested hypothesis can be useful conditionally. Known refutation accompanies affected guidance rather than becoming generic score.

These distinctions live on ordinary records/links. They do not require truth registry, universal confidence score or promotion ladder before capture.

### 4.8 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop guidance in stated situation |
| Supersede/refute | Publish scoped replacement or contradiction |
| Erase scope | Remove controlled source/derivatives, staged data, controlled backups and every created controller inference copy |

Already delivered provider copies/effects are external boundary. Restore cannot silently revive known deletion. Erasure of unresolved Operation requires explicit abandonment and cannot be reported as proof of provider-side deletion/non-execution.

## 5. Current work and decision context

Current work is addressed before similarity search.

When host supplies usable task/session identity, Eliot opens continuation directly, merges relevant later observations and then retrieves related experience. Branch/workspace alone does not distinguish every concurrent task. Cancelled/superseded direction does not become current because semantically similar.

Decision packet contains only material that can change next action:

- current goal and criteria;
- current plan, progress and open commitments;
- exact constraints/corrections;
- applicable/conditional methods;
- relevant prior episodes/exceptions;
- dissent, uncertainty and missing checks;
- source handles.

Exact values and qualifications travel together. High-ranked method cannot crowd out its own exception. Prefer concise qualified unit or specific omission with expansion handle over misleading fragment. Empty sections add no filler.

Eliot supports reactive context at real host boundary, explicit retrieval/open and optional model-assisted orientation for concrete question.

Useful recall must not depend solely on agent remembering to ask. Prepared context is not handoff; handoff is not use; use is not success. Host without push hooks can pull at next supported boundary. Do not wake stopped agent for bookkeeping.

Advice and enforcement are separate. Negative memory is advisory by default. Host-enforced rule is explicit, narrow and opt-in.

## 6. Understanding

A project view is reconstructible, revisable answer to useful question over examined scope: purpose, boundaries, responsibilities, consumers, rationale, failed approaches or intended-versus-observed discrepancy.

Exact structure comes from sources/tools. Semantic explanation may use learning handler. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is incremental:

- first contact returns exact facts immediately;
- bounded orientation job creates useful views;
- source changes refresh affected views only;
- new consumer can invalidate complete-set claim without changing old cited files;
- failed refresh leaves prior qualified view and direct source access.

Understanding is not compulsory pyramid, onboarding ceremony or placeholder card. Same source/view mechanism applies to Eliot itself. Summary/health check cannot certify architecture implementation; no separate self-model registry needed.

## 7. Learning and self-improvement

Initial learning changes external memory, methods, context construction and selected configurable strategies. It does not require model-weight training.

Once learning purpose and permitted profile are configured, Eliot may automatically interpret selected episodes, publish provisional lessons and revise methods through ordinary write path. Reversible improvements do not require vote, promotion ceremony or experiment before every suggestion. They cannot change permissions, user goals or external task acceptance.

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

Erasure of unresolved path:

```text
queued / sending / unknown Operation selected for erase
→ inference.release(abandon_for_erasure)
→ controller fences future dispatch/settlement/publication
→ controlled copies removed when exact
→ provider effect/copy remains external unknown
```

Controller owns configured connection, adapter execution, Operation identity/readback and temporary artifacts. It does not claim, complete or mutate Memory job.

Store conflicts replay retained result, not model call. Ambiguous external outcome remains unknown until native readback resolves or owner explicitly abandons it. New request ID is not recovery.

### 7.2 Model-independent cognitive contract

Processing method and result schema define cognitive operation. Profile selects versioned adapter, connection and requested model. Interface compatibility does not guarantee equal quality.

Retain:

- profile and connection digests plus adapter ID;
- `actual_destination`;
- requested/observed model/provider facts;
- observed finish, limits, usage/cost when supplied;
- unknown fields as unknown, not zero/inferred;
- input/result cleanup states independently.

Text job consumes exact processing-method revision. Embeddings consume selected profile. Deterministic reducers need neither. Stored proposal changes behavior only when real consumer reads it.

### 7.3 Outcome attribution

Where external action can be correlated, retain exact method revision offered/used. Otherwise preserve episode without invented attribution. Distinguish offered, handed off, action observed, adherence inferred/unknown, outcome observed and comparative benefit supported/unknown.

One attributable attempt/criterion contributes once. Replayed hooks/summaries are not independent successes. Missing correlation limits evaluation; it does not block capture, retrieval or provisional learning.

### 7.4 No-change, partial and cleanup

No-change is valid only for cognitive work completed on supplied input. It is not mandatory explanation after every event.

Unavailable/disallowed profile, admission rejection, provider failure, no result, malformed output, missing fields, truncation, unresolved execution and partial processing are not successful no-change. Useful partial output may be retained with exact coverage; it cannot mark omitted input processed.

Cleanup outcome is separate from cognitive outcome. A failed/no-result request may complete cleanup successfully without producing learning. A useful result may remain cleanup-incomplete while Memory safely uses verified local copy.

### 7.5 Recursive improvement

Self-improvement diagnoses failed connected edge: capture, source selection, admission, controller execution, result readback, cleanup, decoding, publication, retrieval, delivery, use, applicability or method quality. Correct that edge instead of multiplying duplicate lessons or adding global intelligence score.

Within repeatable work, Eliot may use Propose–Probe–Compose. Across tasks, it retains lessons. Baseline/no-change remains valid. Selected candidate is not automatically better. Irreversible effects are not repeated merely for comparison.

## 8. Disagreement, prediction, research and commitments

Disagreement belongs to question, scope and time. Preserve rivals/grounds, then identify cheapest useful distinguishing observation. One source lookup, agent or human decision may be enough. Panel/vote not required.

Unresolved disagreement does not block unrelated work. Provisional choice records rationale and reconsideration trigger.

Prediction states expected observation before action, conditions and available check. Static dependency, co-change and causal explanation are not interchangeable.

Research begins with available memory and exact local sources. External acquisition is for concrete remaining gap. Eliot Research owns execution/corpora; Memory stores compact findings, alternatives, coverage and exact handles.

Failed source request, completed but uninformative research and useful partial answer differ. Repeating uncertainty does not justify endless research loop.

Commitments/problems are retained state, not notifications. Showing/acknowledging does not resolve; passed due date does not complete. Resolution follows matching observed event or explicit owner change. Notifications do not create task manager.

## 9. Reliability, privacy and direct control

Persist enough information to distinguish:

- not requested;
- waiting for configured profile;
- requested but not admitted;
- queued/sending;
- external outcome unknown;
- result retained by controller;
- result copied into Memory;
- decoded/applied;
- terminal without result;
- input cleanup state;
- result cleanup state;
- aggregate cleanup pending/incomplete/released;
- abandoned for erasure;
- provider-side effect/copy external unknown;
- partial, failed, cancelled or erased.

Acknowledgement is not completion. Heartbeat is not progress. Prepared context is not handoff. Provider body is not decoded proposal. Proposal is not published memory. Published memory is not proof of external success. Cleanup success is not cognitive success; cognitive success is not cleanup success.

Primary capture/reads remain available when optional routes fail. External I/O never runs inside Store transaction. Unknown outcomes reconcile through saved identity/native readback, not new request ID.

Secrets remain in controller. Memory stores profile name, frozen non-secret execution identity, Operation/result refs and observed facts. Missing usage, cost or account identity remains unknown.

Physical erasure traverses Memory inputs/results, spool, controlled backups and each controller content artifact. Late result cannot reintroduce erased material through abandoned Operation. Do not report complete erasure while controlled copy remains or mismatches; do not report provider-side deletion unless provider actually guarantees it.

Direct control provides status/inbox, inspect/open, configure, pause/resume/cancel, correct/withdraw/erase, backup/restore and shutdown. It reports profile/connection unavailable, destination mismatch, automatic denial, limits, unknown outcome, abandonment and exact per-copy cleanup gaps.

## 10. Explicit non-goals

V3 does not add these without demonstrated consumer and owner decision:

- second task manager/workflow engine inside Memory;
- duplicated provider/credential/router stack;
- controller Task/Attempt for one-shot inference;
- agent workspace/session route types as inference config;
- old Governor route/capability/fingerprint/portfolio platform;
- permanent Dreamer process/model loop;
- second semantic/vector DB;
- truth/skill registry, outcome store or packet DB;
- universal policy/approval/proof platform;
- route-classifier model or silent fallback;
- arbitrary provider fields under unspecified compatibility;
- broker/event bus for internal calls;
- actor/crate/contract/service per concept;
- per-helper lifecycle/proof/promotion manifests;
- runtime Rust plugins, WASM packaging or hot-generation;
- global project/workspace fences before capture/read;
- full-graph verification before recall;
- mandatory model judge;
- success-shaped stubs;
- generated inventories as permanent authorities;
- aggregate cleanup flag that hides which controlled content copy remains.

## 11. Product evidence

A capability is present only when real path exists:

```text
real input
→ owning operation
→ retained result or typed unknown
→ actual consumer
→ observable product effect
→ restart/readback where relevant
```

For Base: source knowledge captured in session A, service restart, relevant retrieval/delivery in session B and exact source opening.

For first learning: retained episode, exact recipe/disclosure, one frozen connection/profile behavior, one controller Operation, exact result read/Memory copy when result exists, decoded publication or valid no-change, later context reading resulting revision, and exact cleanup disposition showing input/result removed or explicit per-copy gap.

For terminal no-result: exact operational failure/cancellation, no fabricated cognitive result, and successful input cleanup or explicit gap.

Stored type, fixture, receipt, generated report, serializer or leaf compilation alone is not evidence.
