# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.6 · 2026-10-24 · normative design for the greenfield rewrite.**

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

A learning handler freezes finite input and one exact processing-method revision, builds an exact request, calls the configured controller inference boundary outside the Store transaction, retains the verified result, decodes a purpose-specific response and publishes ordinary memory revisions. Deterministic reducers and embeddings do not become Dreamer jobs merely because they use computation.

### 2.2 One-shot inference is not agent orchestration

The first learning extension needs this semantic operation:

```text
exact input + selected profile + disclosure + finite limits + stable request key
→ complete | partial | failed | unknown
→ exact returned body + requested/observed execution facts
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

The resolved profile inherits `actual_destination` from its connection. Controller computes an immutable digest over non-secret behavior-changing fields and freezes the resolved snapshot on admission. Reconfiguration affects a new explicit request; it cannot mutate an admitted Operation.

Memory selects only a profile name. It does not receive provider secrets or construct arbitrary headers, query parameters, provider extras or fallback ladders.

There is no implicit fallback. An unavailable connection, profile, provider, model or capacity returns a specific waiting, rejection, failure or unknown state. Controller cannot silently switch provider, model, account, destination, retention or billing semantics.

### 2.4 Disclosure is checked at the actual send boundary

Memory reduces the material actually supplied to one value:

```text
local_only
external_allowed
```

Project configuration supplies the default; a source may be stricter. Derived content cannot widen the strictest source it still contains or reveals. Mixed input uses the strictest contributing class. Reuse scope does not widen disclosure.

`local_only` requires a connection whose `actual_destination` is `local`. Protected material is not silently omitted to make an external profile pass. The job waits or fails with a specific profile/disclosure gap; it is not successful no-change and does not mark input processed.

These are deterministic checks at the controller's actual provider-send boundary. They do not justify a general Governor, route classifier, approval ceremony, capability registry, portfolio planner or per-call proof package.

### 2.5 Controlled request and result copies have finite lifetime

One inference Operation creates at most two controller-owned content artifacts:

```text
inference_input
inference_result
```

The exact input is staged before provider I/O without copying raw content into generic Operation JSON. The exact visible result is retained long enough for readback after disconnect or restart.

Memory reads the result in bounded ranges, verifies length and digest, and durably copies it into its existing job/blob before decoding. It then calls idempotent `inference.release`, which removes **both** controller-owned content artifacts when present and retains only bounded text-free deduplication/status facts.

Until release completes, the input/result artifacts are controlled duplicate content. Release failure does not invalidate a verified Memory copy, but it remains visible and prevents a claim of complete erasure. Provider-held copies are an external boundary; controller-managed files are not.

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
4. **surfaces/runtime** — CLI, MCP/hooks, process startup and composition.

These are dependency boundaries, not four processes or a compulsory `interface → facade → service → repository` chain. Internal calls use typed Rust values. Serialization belongs at actual storage, process or network boundaries. Add a trait only where a real interchangeable I/O boundary exists.

An extension is a vertical capability across the layers it actually uses. It adds a real writer/handler and real consumer to existing operations; it does not build a miniature platform with its own scheduler, database, context compiler and supervisor.

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
→ controller input/result copies released
```

Vectors, project understanding, documents, Research, more hosts and richer cognition are independent increments. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. There is no separate Lite database, Full memory engine or compulsory all-module installation.

Optional means optional in construction, startup and execution. A failed or disabled extension cannot disable capture, exact reads or source opening. Disabling a producer stops new work without deleting readable retained knowledge. Re-enabling it does not require a full-corpus rebuild before ordinary use.

## 4. Identity and memory invariants

### 4.1 Project, workspace, work identity and environment are different

A project is a configured scope of work; it need not be a Git repository. A workspace identifies one working instance. A task or actor/session address identifies continuing work. Path, branch, commit, resource version and time describe changing environment.

Therefore:

- switching branch does not erase a continuing goal or commitment;
- a result from checkout B does not establish checkout A's current condition;
- fork and explicit transfer retain relations rather than silently renaming work;
- a late result keeps the binding captured when it was issued;
- unknown association limits claims about that resource but does not block preservation of the input.

There is no universal workspace generation whose mismatch disables the whole project.

### 4.2 Preserve before interpretation

Permitted source events are stored before model interpretation. Missing models, embeddings, maps or external services cannot destroy the original or prevent direct readback.

Replay is deduplicated by source identity, not text equality. Distinct real occurrences remain distinct even when their text matches. Several IDs, summaries or representations of one event do not create independent corroboration.

### 4.3 Source, representation and claim are different

An observation records what a source supplied, not that every statement inside it is true. A claim, explanation, method, prediction or project view is derived knowledge.

Derived knowledge retains exact source handles and revisions. Retrieval does not strengthen support. Model-generated IDs are not source evidence. Exact names, versions, values, negations, limitations and counterexamples travel with a useful summary.

A source object, its version and a transformed representation have different identities. Rename, copy, conversion, crop and export retain explicit relations. Similarity or equal bytes alone do not prove identity, continuity or independent support.

### 4.4 Current value and history are different

Corrections create revisions. Historical evidence remains openable after current applicability changes. Incompatible alternatives may coexist. Removing a successor does not automatically restore its predecessor as current.

Occurrence time, stated validity, receipt time and editorial revision time answer different questions. A late import or newly written summary does not become a fresh observation of the world.

### 4.5 Origin, reuse scope and disclosure are different

Every item retains where it came from. Reusable methods separately state where they may be considered:

- origin project only;
- selected projects;
- the local owner's projects.

Reuse never erases origin, material conditions, counterexamples or disclosure limits. Permission to consider a method elsewhere does not prove its workspace-, task- or version-specific conditions and does not authorize sending its sources to a model.

A generalized method may be `external_allowed` while a supporting episode remains `local_only` only when the generalized content no longer contains or reveals protected material. Otherwise the stricter disclosure remains.

### 4.6 Grounds are explicit enough to revise

A conclusion may depend on:

- all members of one required grounds group;
- one of several alternative groups;
- advisory supporting material;
- navigation links that carry no evidential meaning.

Eliot does not infer Boolean meaning from citation count. Unknown composition remains unknown. A material source change triggers targeted reconsideration of affected conclusions, not a whole-graph proof before every read. Cycles supply no independent support.

### 4.7 Support, exposure and influence are separate

Existence, evidential support, retrieval exposure and advisory influence answer different questions. A frequently retrieved item is not thereby verified. An archived observation is not thereby false. An untested hypothesis can be useful when shown conditionally. Known refutation accompanies affected guidance rather than being replaced by a generic score.

These distinctions live on ordinary records and links. They do not require a truth registry, universal confidence score or promotion ladder before capture.

### 4.8 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop guidance in the stated situation |
| Supersede/refute | Publish a scoped replacement or contradiction |
| Erase scope | Remove controlled source and derivatives, including staged data, controlled backups and controller inference input/result copies |

Already delivered provider copies are an external boundary. Restore cannot silently revive a known current deletion.

## 5. Current work and decision context

Current work is addressed before similarity search.

When the host supplies a usable task/session identity, Eliot opens that continuation directly, merges relevant later observations and then retrieves related experience. A branch or workspace alone does not distinguish every concurrent task. A cancelled or superseded direction does not become current because it is semantically similar.

A decision packet contains only material that can change the next action:

- current goal and known criteria;
- current plan, progress and open commitments;
- exact constraints and explicit corrections;
- applicable or conditional methods;
- relevant prior episodes and material exceptions;
- dissent, uncertainty and missing checks;
- source handles for expansion.

Exact values and qualifications travel together. A high-ranked method cannot crowd out its own exception. Prefer a concise qualified unit or a specific omission with an expansion handle over a misleading fragment. Empty sections add no filler.

Eliot supports:

- reactive context at a real host boundary;
- explicit retrieval/open;
- optional model-assisted orientation for a concrete question.

Useful recall must not depend solely on an agent remembering to ask. Prepared context is not handoff; handoff is not use; use is not success. A host without push hooks can pull at its next supported boundary. Do not wake a stopped agent merely for bookkeeping.

Advice and enforcement are separate. Negative memory is advisory by default. A host-enforced rule is explicit, narrow and opt-in.

## 6. Understanding

A project view is a reconstructible, revisable answer to one useful question over an examined scope: purpose, boundaries, responsibilities, consumers, rationale, failed approaches or discrepancy between intended and observed behavior.

Exact structure comes from actual sources and tools. Semantic explanation may use a learning handler. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is incremental:

- first contact returns available exact facts immediately;
- a bounded orientation job creates useful views;
- source changes refresh affected views only;
- a new consumer can invalidate a complete-set claim without changing old cited files;
- failed refresh leaves the prior qualified view and direct source access available.

Understanding is not a compulsory pyramid, onboarding ceremony or placeholder card. The same source/view mechanism applies to Eliot itself. A summary or health check cannot certify that architecture is implemented; no separate self-model registry is needed.

## 7. Learning and self-improvement

Initial learning changes external memory, methods, context construction and selected configurable strategies. It does not require model-weight training.

Once a learning purpose and permitted profile are configured, Eliot may automatically interpret selected episodes, publish provisional lessons and revise connected methods through its ordinary write path. Reversible improvements do not require a vote, promotion ceremony or experiment before every suggestion. They cannot change permissions, user goals or external task acceptance.

### 7.1 One Memory job owns the semantic loop

```text
frozen sources + exact recipe revision + disclosure
→ saved exact Memory request
→ direct authenticated controller IPC
→ controller inference_input + one inference Operation
→ frozen InferenceConnection / InferenceProfile behavior
→ controller inference_result or typed failure/unknown
→ Memory range read + length/digest verification + durable copy
→ purpose-specific decoder
→ atomic publication or valid no-change
→ later consumer
→ inference.release for controller input/result copies
```

The controller owns only configured connection, adapter execution, Operation identity/readback and temporary controlled artifacts. It does not claim, complete or mutate the Memory job.

Store conflicts replay the retained result, not the model call. A request with ambiguous external outcome remains unknown until native readback resolves it or the Memory owner chooses a new explicit attempt. A new request ID is not recovery.

### 7.2 Model-independent cognitive contract

The processing method and result schema define the cognitive operation. A profile selects a versioned adapter, connection and requested model. Interface compatibility does not guarantee equal quality.

Retain with the result:

- profile digest and adapter ID;
- non-secret connection identity and `actual_destination`;
- requested and observed model/provider facts;
- observed finish, limits, usage and cost when supplied;
- unknown fields as unknown rather than zero or inferred.

A text job consumes its exact processing-method revision. Embeddings consume a selected embedding profile. Deterministic reducers need neither. A stored proposal changes behavior only when a real consumer reads it.

### 7.3 Outcome attribution

Where an external action can actually be correlated, retain the exact method revision offered or used. Otherwise preserve the episode without invented attribution. Distinguish:

- offered;
- handed off;
- action observed;
- adherence inferred or unknown;
- outcome observed;
- comparative benefit supported or unknown.

One attributable attempt/criterion contributes once. Replayed hooks and summaries are not independent successes. Missing correlation limits evaluation; it does not block capture, retrieval or provisional learning.

### 7.4 No-change and partial results

No-change is valid only for work actually completed on the supplied input. It is not a mandatory explanation after every event.

Unavailable/disallowed profile, admission rejection, provider failure, malformed output, missing fields, truncation, unresolved external execution and partial processing are not successful no-change. Useful partial output may be retained with exact coverage; it cannot mark omitted input processed.

### 7.5 Recursive improvement

Self-improvement diagnoses the failed connected edge: capture, source selection, disclosure/profile admission, controller execution, result readback/release, decoding, publication, retrieval, delivery, use, applicability or method quality. Correct that edge instead of multiplying duplicate lessons or adding a global intelligence score.

Within repeatable work, Eliot may use Propose–Probe–Compose. Across tasks, it retains lessons about how to improve. Baseline/no-change remains valid. A selected candidate is not automatically better. Irreversible external effects are not repeated merely to obtain a comparison.

## 8. Disagreement, prediction, research and commitments

Disagreement belongs to a question, scope and time. Preserve rival explanations and their grounds, then identify the cheapest useful observation that can distinguish them. One source lookup, one agent or a human decision may be enough. A panel or vote is not required.

Unresolved disagreement does not block unrelated work. A provisional choice records why it was chosen and what would cause reconsideration.

A prediction states expected observation before an action, its conditions and the available check. Static dependency, co-change and causal explanation are not interchangeable.

Research begins with available memory and exact local sources. External acquisition is used for a concrete remaining gap. Eliot Research owns research execution and large corpora; Eliot stores compact findings, alternatives, coverage and exact source handles needed later.

A failed source request, completed but uninformative research and useful partial answer are different outcomes. Repeating the same uncertainty does not justify an endless research loop.

Commitments and unresolved problems are retained state, not notifications. Showing or acknowledging one does not resolve it, and a passed due date does not complete it. Resolution follows a matching observed event or explicit owner change. Optional notifications do not create another task manager.

## 9. Reliability, privacy and direct control

Persist enough information to distinguish:

- not requested;
- waiting for an allowed/configured profile;
- requested but not admitted;
- queued or sending;
- external outcome unknown;
- controller result retained;
- result copied into Memory;
- decoded;
- applied to memory;
- controller cleanup pending, incomplete or released;
- partial, failed, cancelled or erased.

Acknowledgement is not completion. Heartbeat is not progress. Prepared context is not handoff. A provider body is not a decoded proposal. A proposal is not published memory. Published memory is not proof of external success.

Primary capture and reads remain available when optional routes fail. External I/O never runs inside a Store transaction. Unknown external outcomes are reconciled through saved request identity and native readback where supported; they are not repaired by issuing a new request ID.

Secrets remain in the controller credential system. Memory stores only profile names, frozen non-secret execution identity, Operation/result references and observed facts. Missing usage, cost or account identity remains unknown.

Physical erasure traverses Memory inputs/results, spool, controlled backups and both controller inference content artifacts. A late result cannot reintroduce erased material. Do not report complete erasure while controlled duplicate content remains.

Direct control provides status/inbox, inspect/open, configure, pause/resume/cancel, correct/withdraw/erase, backup/restore and graceful shutdown. It reports profile/connection unavailable, destination mismatch, automatic-use denial, limits, unknown outcome and cleanup gaps directly.

## 10. Explicit non-goals

V3 does not add these without a demonstrated consumer and owner decision:

- a second task manager or workflow engine inside Memory OS;
- a provider/credential/router stack duplicated inside Memory OS;
- controller Task/Attempt for ordinary one-shot inference;
- reuse of agent workspace/session route types as inference configuration;
- the old Governor route/capability/fingerprint/portfolio platform;
- a permanent Dreamer process or model loop;
- a second semantic/vector database;
- a truth registry, skill registry, outcome store or packet database;
- a universal policy/approval/proof platform;
- a route-classifier model or silent fallback ladder;
- arbitrary provider headers/body fields under an unspecified compatibility claim;
- a broker or event bus for internal function calls;
- one actor, crate, contract package or service per concept;
- mandatory per-helper lifecycle/proof/promotion manifests;
- runtime Rust plugins, WASM packaging or hot-generation machinery;
- global project/workspace fences before ordinary capture/read;
- full-graph verification before useful recall;
- a mandatory model judge for every model result;
- success-shaped stubs for unavailable capabilities;
- generated repository inventories as permanent work authorities.

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

For Base, the minimum observation is: source knowledge captured in session A, service restart, relevant retrieval/delivery in session B, and exact source opening.

For first learning, the minimum observation is: one retained episode, exact recipe and disclosure, one allowed frozen connection/profile behavior, one controller Operation, exact result read and Memory copy, one decoded publication or valid no-change, a later context that reads the resulting revision, and release or explicit cleanup gap for both controller input/result artifacts.

A stored type, fixture, receipt, generated report, passing serializer or leaf compilation alone is not that evidence.
