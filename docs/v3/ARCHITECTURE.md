# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.4 · 2026-10-24 · normative design for the greenfield rewrite.**

V1 and V2 are donors. V3 is a new implementation, not a compatibility migration. This document defines the product purpose, ownership and invariants. [Implementation](IMPLEMENTATION.md) defines the concrete runtime, data and integration design. [Cognition](COGNITION.md) defines the algorithms. [AUDIT](AUDIT.md) explains the rejected machinery and source limits. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) tracks what has and has not been checked.

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

A searchable archive is necessary but insufficient. A stored object, graph, summary, receipt or passing shape test does not demonstrate memory. Product value is visible when Eliot:

- restores work after interruption without inventing state;
- prevents repeated mistakes and abandoned approaches from silently returning;
- exposes relevant constraints, counterexamples and unknowns before a decision;
- turns observed outcomes into a later change in guidance;
- keeps original sources openable and corrections reversible;
- remains useful when optional models, vectors or specialist tools are unavailable.

A mechanism must serve one of those outcomes. More metadata, stages, checks, processes or interfaces are not benefits by themselves. When a default repeatedly blocks useful work, correct that default at its owner instead of building another exception layer around it.

## 2. Ownership and boundaries

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance of external work | Human and host/controller |
| Agent sessions, tools, task execution and swarm orchestration | Host/controller |
| Observations, revisions, retrieval, context, source links, outcomes and finite memory jobs | Eliot Memory OS |
| Interpretation, consolidation and method improvement | Eliot learning handlers; the model call is supplied through a narrow inference adapter |
| Provider/model selection, credentials and model execution | `eliot-swarm-controller` through a one-shot inference route in the initial integrated profile |
| Persistence, native indexes and transactions | SurrealDB through one private Store |
| Code/document/source translation | Narrow adapters and configured specialist tools |
| External research execution and large research corpora | Eliot Research or another configured research system |
| Detection of daemon/process-family failure | Supervisor outside the daemon failure domain |

Eliot may link an external task, attempt, action and result, but it does **not** become another task manager, acceptance authority, permission engine, swarm controller or research platform.

The controller may execute a model request for Eliot, but it does **not** own Eliot's memory job, episode coverage, recipe revision, publication or retry decision. Conversely, Eliot does not copy controller Tasks, Attempts, workspaces, review state or provider internals merely to obtain one completion.

### 2.1 Dreamer is a role, not a mandatory process

**Dreamer** means model-assisted interpretation performed for a concrete Eliot job. It is not a permanent daemon, model vendor, special database, separate scheduler or second canonical writer.

A learning handler prepares one finite request, invokes the configured inference adapter outside the Store transaction, retains the exact result, decodes a purpose-specific response and publishes ordinary memory revisions. Different models can perform that role. Deterministic work and embeddings do not become Dreamer jobs merely because they use computation.

### 2.2 One-shot inference is not agent orchestration

The first learning extension needs this semantic operation:

```text
exact prompt + route profile + output limits + stable request key
→ complete | partial | unknown | failed
→ exact returned body and observed model metadata
```

The initial integrated adapter calls a narrow `inference.text` operation in `eliot-swarm-controller`. That operation reuses controller credentials, route selection, request deduplication and durable result artifacts, but it does not require a controller Task, requirement list, Attempt, native workspace, review or acceptance lifecycle.

Richer agent work can still use controller Tasks and native sessions when the work actually needs tools, continuation or orchestration. The one-shot inference boundary must not be widened into a generic workflow engine inside Memory OS.

### 2.3 User intent and factual reports remain distinct

The user owns goals and preferences, not infallibility about external facts. Preserve an explicit change of intent as such. Preserve a factual assertion with its source, conditions and possible counterevidence. A generated continuation, learned method or retrieved suggestion cannot silently replace the user's goal, relax its criteria or grant execution authority.

## 3. Product shape

The initial product supports several configured projects concurrently. Project-local state remains scoped; explicitly reusable methods may be considered across the owner's selected projects.

The initial product is:

- one Rust codebase;
- one demand-start local service;
- one private application Store;
- one SurrealDB server child;
- one small supervisor mode of the same executable;
- transient host relays/adapters;
- ordinary internal modules;
- optional outbound clients constructed only when their capability is enabled.

A new process is justified only by a real external runtime or failure boundary. A new crate is justified only by an actual dependency, deployment or change boundary. A noun in the design is not an instruction to create a registry, protocol, actor, state machine or service.

One stored mutable state has one application mutation owner. This does not mean one permitted author, one interpretation or one source. Dashboards, packets, scores, maps and status reports are views unless they genuinely own independent state.

### 3.1 Layers remain; pass-through machinery does not

Keep four responsibility layers:

1. **domain and pure transformations** — values, comparison, reduction and packing over supplied inputs;
2. **application operations** — capture, revision, retrieval, learning and control;
3. **external I/O** — Store, host, inference, embedding, document and research adapters;
4. **surfaces/runtime** — CLI, MCP/hooks, process startup and composition.

These are dependency boundaries, not four processes or a compulsory `interface → facade → service → repository` chain. Internal calls use typed Rust values. Serialization belongs at actual storage, process or network boundaries. Add a trait only where a real interchangeable I/O boundary exists.

An extension is a vertical capability across the layers it actually uses. It adds a real writer/handler and a real consumer to existing operations; it does not build a miniature platform with its own scheduler, database, context compiler and supervisor.

### 3.2 A useful Base, then additive capabilities

**Base** works without model, vector encoder, document converter, project graph or Research credentials. It provides:

- capture from one real host;
- explicit notes, corrections and commitments with history;
- exact and lexical retrieval;
- addressed current-work reconstruction from saved state and available events;
- bounded context delivery and exact source opening;
- restart, spool, backup/restore and erase for the data it stores;
- direct status and control.

Base is a useful limited product, not a claim of automatic learning.

The first learning extension closes one connected loop:

```text
retained episode
→ exact processing recipe
→ one inference request
→ typed create/revise/no-change result
→ ordinary memory revision
→ changed later context
```

Vectors, project understanding, documents, Research, more hosts and richer cognition are independent increments. They reuse the same records, Store, finite jobs, context assembly and maintenance path. There is no separate Lite database, Full memory engine or compulsory all-module installation.

Optional means optional in construction, startup and execution. A failed or disabled extension cannot disable capture, exact reads or source opening. Disabling a producer stops new work without deleting readable retained knowledge. Re-enabling it does not require a full-corpus rebuild before ordinary use.

### 3.3 Project, workspace and current state

A project is a configured scope of work; it need not be a Git repository. A workspace identifies one working instance. Path, branch, commit and resource versions describe changing state rather than stable task identity.

Keep stable work identity separate from environmental observations:

- switching branch does not erase a continuing goal or commitment;
- a result from checkout B does not establish checkout A's current condition;
- a moved, forked or transferred task retains its actual association and source history;
- a late result keeps the binding captured when it was issued;
- unknown association limits the claim about that resource, not permission to preserve the input.

Change propagation follows actual dependencies and conditions. There is no universal workspace generation whose mismatch disables the whole project. General methods may transfer under recorded conditions; instance-bound facts remain attributed to their workspace/task.

## 4. Memory model invariants

### 4.1 Preserve before interpretation

Permitted source events are stored before model interpretation. Missing models, embeddings, project maps or external services cannot destroy the original or prevent direct readback.

Replay is deduplicated by source identity, not text equality. Distinct real occurrences remain distinct even when their text matches. Several IDs, summaries or representations of one event do not create independent corroboration.

### 4.2 Source, claim and representation are different

An observation records what a source supplied, not that every statement inside it is true. A claim, explanation, method, prediction or project view is derived knowledge.

Derived knowledge retains exact source handles and revisions. Retrieval of a claim does not strengthen its support. Model-generated IDs are not source evidence. Exact names, versions, values, negations, limitations and counterexamples travel with a useful summary.

A source object, its version and a transformed representation are different identities. Rename, copy, conversion, crop and export retain explicit relations. Similarity or equal bytes alone do not prove object identity, continuity or independent support.

### 4.3 Current value and history are different

Corrections create revisions. Historical evidence remains openable after current applicability changes. Incompatible alternatives may coexist. Removing a successor does not automatically restore its predecessor as current.

Occurrence time, stated validity, receipt time and editorial revision time answer different questions. A late import or newly written summary does not become a fresh observation of the world.

### 4.4 Origin and reuse scope are different

Every item retains where it came from. Reusable methods separately state where they may be considered:

- origin project only;
- selected projects;
- the local owner's projects.

Reuse never erases origin, material conditions, counterexamples or disclosure limits. Permission to consider a method in a project does not prove its workspace-, task- or version-specific conditions hold there.

### 4.5 Grounds are explicit enough to revise

A conclusion may depend on:

- all members of one required grounds group;
- one of several alternative groups;
- supporting material that is useful but not required;
- navigation links that carry no evidential meaning.

Eliot does not infer Boolean meaning from citation count. Unknown composition remains unknown. A material source change triggers targeted reconsideration of affected conclusions, not a whole-graph proof before every read.

### 4.6 Support, accessibility and influence are separate

Existence, evidential support, retrieval exposure and advisory influence answer different questions. A frequently retrieved item is not thereby verified. An archived observation is not thereby false. An untested hypothesis can be useful when presented conditionally. Known refutation accompanies affected guidance rather than being replaced with a generic low score.

These distinctions live on ordinary records and links. They do not require a universal truth score, promotion ladder or classification ceremony before capture.

### 4.7 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop guidance in the stated situation |
| Supersede/refute | Publish a scoped replacement or contradiction |
| Erase scope | Remove controlled source and derivatives, including staged data and controlled backups |

Already delivered host/provider copies are an external boundary. Restore cannot silently revive a known current deletion.

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

Eliot supports three uses of the same memory:

- reactive context at a real host boundary;
- explicit retrieval/open;
- optional model-assisted orientation for a concrete question.

Useful recall must not depend solely on an agent remembering to ask. A host without push hooks can pull at its next supported boundary. Do not wake a stopped agent merely for bookkeeping or claim context was delivered when no supported boundary occurred.

Advice and enforcement are separate. Negative memory is advisory by default. A host-enforced rule is explicit, narrow and opt-in.

## 6. Understanding

Eliot maintains reconstructible, revisable views from project purpose to subsystems, resources and observed effects.

Exact structure comes from actual sources and tools. Semantic explanation may use a learning handler. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is incremental:

- first contact returns available exact facts immediately;
- a bounded orientation job creates useful purpose/area views;
- source changes refresh affected views only;
- a new consumer can invalidate a complete-set claim without changing old cited files;
- failed refresh leaves the prior qualified view and direct source access available.

Understanding is not a compulsory pyramid, onboarding ceremony or placeholder card. The same source/view mechanism applies to Eliot itself: intended design, actual code, current runtime and learned incidents remain separate inputs. A summary or health check cannot certify that the architecture is implemented; no separate self-model registry is needed.

## 7. Learning and self-improvement

Initial learning changes external memory, methods, context construction and selected configurable strategies. It does not require model-weight training.

Once a learning purpose and route are configured, Eliot may automatically interpret selected episodes, publish provisional lessons and revise connected methods through its ordinary write path. Ordinary reversible improvements do not require a human vote, promotion ceremony or experiment before every useful suggestion. They preserve sources, qualifications and history; they cannot change permissions, user goals or external task acceptance.

### 7.1 One Memory job owns the loop

The semantic owner is one Eliot job:

```text
frozen sources + exact recipe revision
→ saved inference request
→ configured inference adapter
→ retained raw result
→ purpose-specific decoder
→ atomic publication
→ next reader
```

The inference adapter owns only external execution and readback. It does not claim, complete or mutate the Memory job. Store conflicts replay the retained result, not the model call. A request with ambiguous external outcome remains unknown until provider/controller readback resolves it or the owner chooses a new explicit attempt.

### 7.2 Model-independent Dreamer

The processing recipe and result contract define the cognitive operation. The configured route may use a cloud model, local model or harness-backed provider. Interface compatibility does not guarantee equal quality; route/model identity and observed limits are retained with the result.

A text-interpretation job consumes its exact recipe revision. Embeddings consume an encoder profile. Deterministic reducers need neither. A stored proposal changes behavior only when a real consumer reads it.

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

Provider failure, malformed output, missing fields, truncation, unresolved external execution and partial processing are not successful no-change. Useful partial output may be retained as partial with exact coverage; it cannot mark omitted input processed.

### 7.5 Recursive improvement

Self-improvement diagnoses the failed step: capture, interpretation, retrieval, delivery, use, applicability or method quality. Correct that step instead of multiplying duplicate lessons or adding a global intelligence score.

Within repeatable work, Eliot may use Propose–Probe–Compose. Across tasks, it retains lessons about how to improve. Baseline/no-change remains valid. A selected candidate is not automatically better. Irreversible external effects are not repeated merely to obtain a comparison.

## 8. Disagreement, prediction and research

Disagreement belongs to a question, scope and time. Preserve rival explanations and their grounds, then identify the cheapest useful observation that can distinguish them. One source lookup, one agent or a human decision may be enough. A panel or vote is not required.

Unresolved disagreement does not block unrelated work. A provisional choice records why it was chosen and what would cause reconsideration.

A prediction states the expected observation before an action, its conditions and the available check. Static dependency, co-change and causal explanation are not interchangeable.

Commitments and unresolved problems are retained state, not notifications. Showing or acknowledging one does not resolve it, and a passed due date does not complete it. Resolution follows a matching observed event or explicit owner change. Optional notifications do not create another task manager.

Research begins with available memory and exact local sources. External acquisition is used for a concrete remaining gap. Eliot Research owns research execution and large corpora; Eliot stores compact findings, alternatives, coverage and source handles needed later.

A failed source request, completed but uninformative research and a useful partial answer are different outcomes. Repeating the same uncertainty does not justify an endless research loop. Ask for clarification only when the answer can materially change the task or owner decision.

## 9. Reliability, privacy and direct control

Persist enough information to distinguish:

- not requested;
- requested but not admitted;
- admitted/running;
- completed with retained result;
- partial;
- failed;
- unknown outcome;
- applied to memory;
- cancelled or erased.

Acknowledgement is not completion. Heartbeat is not progress. Prepared context is not handoff. A model response is not a published lesson. A published lesson is not proof of external success.

Primary capture and reads stay available when optional routes fail. External I/O never runs inside a Store transaction. Unknown external outcomes are reconciled through saved request identity and native readback where supported; they are not repaired by issuing a new request ID and hoping the first call did nothing.

Secrets remain in the owning credential system. Stored prompts/results obey configured privacy and disclosure. A source handle identifies content; it does not grant access. Direct control provides status/inbox, inspect/open, configure, pause/resume/cancel, correct/withdraw/erase, backup/restore and graceful shutdown.

## 10. Explicit non-goals

V3 does not add these without a demonstrated second consumer and owner decision:

- a second task manager or workflow engine inside Memory OS;
- a provider stack duplicated inside Memory OS when controller owns the configured routes;
- a permanent Dreamer process or model loop;
- a second semantic/vector database;
- a truth registry, skill registry, outcome store or packet database;
- a universal policy/approval/proof platform;
- a broker or event bus for internal function calls;
- one actor, crate, contract package or service per concept;
- runtime Rust plugins, WASM packaging or hot-generation machinery;
- global project/workspace fences before ordinary capture/read;
- full-graph verification before useful recall;
- a mandatory model judge for every model result;
- success-shaped stubs for unavailable capabilities.

## 11. Product evidence

A capability is present only when a real path exists:

```text
real input
→ owning operation
→ retained result
→ actual consumer
→ observable product effect
```

For Base, the minimum product observation is: source knowledge captured in session A, service restart, relevant retrieval/delivery in session B, and exact source opening.

For first learning, the minimum observation is: one retained episode, one exact recipe and inference request, one retained/decoded result, one published lesson or valid no-change, and a later context that reads the resulting revision. A stored type, fixture, receipt, generated report or passing serializer alone is not that evidence.
