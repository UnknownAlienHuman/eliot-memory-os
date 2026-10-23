# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft.3 · 2026-10-23 · normative design for the greenfield rewrite.**

V1 and V2 are donors. V3 is a new implementation, not a compatibility migration. This document defines **why the product exists, what it owns, and which invariants must survive implementation**. [Implementation](IMPLEMENTATION.md) defines the concrete process, data and integration design. [Cognition](COGNITION.md) defines the algorithms. The [audit conclusion](AUDIT.md) records the evidence, rejected mechanisms and known limits.

## 1. Product purpose

Eliot makes accumulated experience useful at the next decision.

It preserves what actually happened, reconstructs current work, retrieves applicable knowledge, exposes contradictions and unknowns, and improves subsequent work from observed outcomes. This serves people and agents working with code, documents and other supported sources; it is not a code-only archive.

```text
observe
→ preserve
→ reconstruct the current situation
→ supply useful context
→ a person or external agent acts
→ observe the result
→ revise memory or method
→ use that revision in later work
```

A searchable archive is necessary but insufficient. A large graph, a generated summary, a stored receipt or a successful serialization does not demonstrate understanding. Product value is visible when Eliot reduces repeated mistakes, lowers reconstruction cost, preserves continuity, and supplies relevant knowledge before a consequential decision.

A mechanism must serve this purpose. When a chosen default repeatedly prevents useful work, correct that default at its owner rather than add an exception service around it. Preserve source accuracy, actual access controls and the user's intent; do not turn architectural terminology or an unmeasured quality score into a new permission to read or learn. More metadata, checks or stages are not benefits in themselves.

## 2. Ownership and boundaries

| Responsibility | Owner |
|---|---|
| User goal, permissions and acceptance of external work | Human and host/controller |
| Agent sessions, tools, task execution and swarm orchestration | Host/controller |
| Observations, semantic revisions, retrieval, context, source links and outcome memory | Eliot |
| Interpretation, consolidation, procedure extraction and improvement proposals | Dreamer through controller |
| Model/provider execution and retries | Controller |
| Persistence, native search indexes and transactions | SurrealDB through one private Store |
| Code/document/source translation | Narrow adapters and existing specialist tools |
| External research acquisition and large research corpora | Eliot Research or another configured research system |
| Detecting failure of Eliot's process family | A supervisor outside the daemon failure domain |

Eliot may link a task, attempt, method and result. It does **not** become a second task manager, acceptance authority, permission engine, model runtime, research platform or swarm controller. Stored or retrieved text does not create execution authority, and a memory check does not prove whole-task completion.

The user owns goals and preferences, not infallibility about external facts. Preserve an explicit change of intent as such; preserve a factual report with its source and possible counterevidence. Generated continuation and learned advice cannot silently replace the goal or relax its criteria.

Controller-to-memory context and memory-to-controller inference are separate integrations. One does not imply the other. Dreamer can use any suitable configured text route; its cognitive role is not tied to a particular provider or embedding model.

## 3. Product shape

The initial product supports several configured projects concurrently. Project-local work remains scoped; explicitly reusable methods may be considered across the owner's projects.

The initial product is:

- one Rust codebase;
- one demand-start local service;
- one application Store;
- one SurrealDB server child;
- one small supervisor mode of the same executable;
- transient host relays/adapters;
- ordinary internal modules, not one process or crate per concept.

A new process is justified only by a real external runtime or failure boundary. A new crate is justified only by an actual dependency, deployment or change boundary. A noun in the design is not an instruction to create a registry, protocol, lifecycle or state machine.

One stored mutable state has one application mutation owner, not one permitted author or one mandatory interpretation. Dashboards, packets, scores, maps and status reports are views unless they genuinely own independent state.

### 3.1 Layers remain; mandatory machinery does not

Separate the domain model and pure transformations, application operations, external I/O, and host/user surfaces. Pure reasoning over supplied values does not import the database SDK, model provider or host protocol. Application operations own the useful transaction or workflow; adapters translate actual external inputs and results. Surfaces invoke those same operations instead of owning another implementation.

These are dependency and responsibility boundaries, not four processes or a compulsory chain of pass-through calls. A small function does not need its own contract package, port, actor, service and manifest. Use narrow public module interfaces and private internals; share a type directly when no representation change is needed. Introduce a trait when an actual substitutable boundary benefits from it, not once per noun.

An extension is a vertical capability across the layers it actually uses. It may supply a search arm, a source reader, an interpretation job or a host adapter. It reuses existing storage, context assembly and finite work rather than constructing its own miniature platform. Calls between application modules use their public functions and an acyclic dependency direction; independent modules need not communicate through a broker or catalogue.

### 3.2 A usable Base, then additive capabilities

Ship a lightweight Base that captures real events, preserves and corrects explicit knowledge, retrieves exact/lexical material, delivers useful context to one host, and reopens its sources after restart. It has real local lifecycle and data controls. It does not require a model, vector encoder, project graph, document converter or Research connection.

Base is a useful limited product, not the claim that self-learning is complete. The first learning extension closes the episode → actual model result → lesson → later context loop. Further retrieval, understanding, source and meta-learning capabilities extend the same product and data, not a second Lite implementation. The complete target in this document remains; unavailable depth is described honestly rather than replaced with a successful stub.

Optional capabilities are optional in construction, startup and execution, not merely hidden in the UI. Their absence or failure cannot make primary capture/read depend on them. Disabling a producer stops its new work without deleting already retained readable knowledge. Enabling it does not demand a full-corpus rebuild before ordinary use. An explicit request for a missing capability returns that fact, not a fabricated empty success.

Keep one current data model and shared application operations across configurations. Extra depth must not silently change an earlier record's meaning or make it unreadable without the module that produced it. Changing an extension can require a real schema migration, but not a permanent parallel generation or compatibility framework for the discarded V1/V2 runtimes.

### 3.3 Project, working instance and current state

A project is a configured scope of work, not necessarily a Git repository. A directory, document set, service, remote resource or ad hoc task can supply the same memory operations. A workspace identifies a particular working instance; its location, branch and resource versions describe changing state. Neither a matching folder name nor shared Git history makes two instances the same task.

Keep stable work identity separate from observations of its changing environment. A branch switch does not erase a continuing task's goal and commitments; a result from another checkout does not establish the current checkout's condition. A move, fork or transfer retains its actual association and historical sources instead of silently relabelling old events. Unknown association limits the claim about that resource, not permission to capture input or use unrelated knowledge.

Change propagation follows the resources and conditions a view actually depends on. There is no universal workspace generation whose mismatch disables the whole project. General methods may transfer under their recorded conditions; instance-bound facts remain attributed to that instance. This needs ordinary bindings, source references and applicability checks, not a second scope authority or discovery-lease system.

## 4. Memory model invariants

### 4.1 Preserve before interpretation

Permitted source events are stored before model interpretation. Missing models, embeddings or project maps cannot destroy the original or prevent direct readback.

Replay is deduplicated by source identity, not by text equality. Distinct real occurrences remain distinct even when their text is identical. Distinct IDs, repeated reports or several representations do not by themselves establish independent corroboration.

### 4.2 Source and derivation are different

An observation records what a source supplied, not that every assertion inside it is true. A claim, explanation, method, prediction or project view is derived knowledge.

Derived knowledge retains addressable source handles and the source revisions it used. A model-generated ID is not source content. Retrieval of a claim does not increase its evidential support. Keep the actual qualification, negation and counterexample with a useful summary; expanding a source must not silently fetch a newer substitute.

Resource identity, source version and derived representation are distinct. A renamed file may preserve continuity; a crop, conversion or export produces another representation. Similarity or equal bytes alone do not establish that two objects or occurrences are identical. Retain the actual relation and its uncertainty without rewriting old locators.

### 4.3 Current value and history are different

Historical evidence remains available after current applicability changes. A procedure can retain valid historical evidence while its exact repair is no longer applicable. Source unavailability limits disclosure or checking; it is not automatically refutation of retained knowledge.

Corrections create revisions. Incompatible alternatives may coexist. Removing a successor does not automatically restore its predecessor as current. Occurrence, stated validity, receipt and editorial revision times answer different questions; a late import or fresh summary does not make old evidence a new observation of the world.

### 4.4 Origin and reuse scope are different

Every item retains where it came from. Reusable methods separately state where they may be considered:

- the originating project;
- selected projects;
- the local owner's projects.

Cross-project reuse never erases origin, conditions, counterexamples or disclosure limits. Permission to consider an item in a project is not evidence that its workspace-, task- or version-specific conditions hold there.

### 4.5 Grounds are explicit enough to revise

A conclusion may depend on:

- all members of one grounds group;
- one of several alternative grounds groups;
- supporting material that is useful but not required;
- navigation links that carry no evidential meaning.

Eliot does not infer AND/OR semantics from the number of citations. Unknown composition remains unknown. A material change or a concrete question can trigger targeted reconsideration; incomplete grounds do not require a fresh proof before every read or invalidate all other memory.

### 4.6 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop a conclusion or method from guiding the stated situation |
| Supersede/refute | Publish a reasoned replacement or contradiction |
| Erase scope | Remove controlled source and derivatives, including staged input and controlled backups |

Already delivered host/provider copies are an external boundary. Restore cannot silently revive a known current deletion.

### 4.7 Support, accessibility and influence remain separate

Existence, evidential support, retrieval exposure and advisory influence answer different questions. A frequently retrieved item is not thereby verified; an archived observation is not thereby false; an untested hypothesis can be useful when presented conditionally. Known refutation accompanies the affected advice rather than being replaced by a generic low score.

Represent these distinctions on ordinary records and their source relations. They do not require a universal truth score, status-promotion ladder or full classification before capture. Direct inspection may expose permitted withdrawn history without reinstating it as current guidance.

## 5. Current work and decision context

Current work is addressed before similarity search.

When the host supplies a usable continuation identity, Eliot opens that state directly, merges later observed events, and then retrieves related experience. A workspace or Git branch alone does not distinguish every concurrent task. A cancelled or superseded plan does not become current merely because it is semantically similar.

A useful context packet selects material relevant to the present decision:

- current goal and known criteria;
- current plan, progress, open commitments and relevant recent results;
- exact constraints and applicable or explicitly conditional methods;
- relevant prior episodes and material exceptions;
- dissent, uncertainty and missing checks;
- source handles for expansion.

Exact values and qualifications travel together. A high-ranked claim does not crowd out its own material exception. Unknown utility is not proof that a potentially important item is useless. Prefer a concise qualified unit or a specific omission with an expansion handle over a misleading fragment. Empty sections add no filler.

Preserve three uses of the same memory: reactive context from observed host/source contact, explicit retrieval, and an optional Dreamer orientation for a concrete question. Useful recall must not depend solely on an agent remembering to ask for it. A host without push hooks retains pull and delivery at its next supported boundary; do not pretend an earlier intervention occurred or wake an agent merely for bookkeeping.

Context must reach the model at a boundary where it can still affect the decision. Advice and enforcement are separate. Negative memory is advisory by default; a specific host-enforced rule is explicit and opt-in.

Normal retrieval uses independent exact and lexical candidates, compatible vectors and relevant relation expansion. Vector retrieval is required in the complete product, but vector unavailability is a degraded route rather than an empty memory bank. Automatic context remains cheap; deliberate deeper retrieval uses the same assembly path with an explicit wait budget.

## 6. Understanding

Eliot maintains reconstructible, revisable views from project purpose to subsystems, resources and observed effects.

Exact structure comes from actual sources and tools. Semantic explanation may use Dreamer. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is built incrementally:

- first contact returns available exact facts immediately;
- a bounded orientation job creates useful purpose/area views;
- source changes refresh affected views;
- new consumers can invalidate a complete-set claim even when old cited files did not change;
- failed refresh leaves the previous qualified view and direct source access available.

Understanding is not a compulsory pyramid, complete onboarding ceremony or placeholder card with no explanation. The same source/view mechanism applies to Eliot itself: its intended design, actual implementation, current operation and learned incidents are distinct inputs. A summary or successful health check cannot certify that the architecture is implemented; no separate self-model registry is needed.

## 7. Learning and self-improvement

Initial learning changes external memory, methods, context construction and selected configurable strategies. It does not require model-weight training.

Once the relevant operation is configured, Eliot can automatically interpret selected episodes, publish provisional lessons and revise connected methods through its ordinary write path. Ordinary reversible memory improvements do not require a human vote, a separate promotion ceremony or an experiment before every useful suggestion. They preserve sources, qualifications and recoverable history; they do not change permissions, user goals or external task acceptance. Coalesced finite work replaces a model call after every event.

A useful provisional method may enter a later eligible context automatically. Applicability and demonstrated broad effectiveness are separate questions.

Where an attempt can actually be correlated, retain the exact method revision offered or used. Otherwise preserve the episode without invented attribution. Eliot distinguishes:

- offered;
- delivered;
- action observed;
- adherence inferred or unknown;
- outcome observed;
- comparative benefit supported or unknown.

One attributable attempt/criterion contributes once. Replayed hooks and summaries of the same episode are not independent successes. Missing correlation limits evaluation; it does not require agent writeback forms or block capture, retrieval or provisional learning.

A method revision changes behavior only when a real consumer reads it. A text-interpretation job selects and consumes its exact recipe; an encoder uses its profile and deterministic work needs no prompt. New method revisions affect later work, not the frozen input of an already running request. Writing a proposal for a different algorithm does not change that algorithm's code.

Self-improvement diagnoses the failed step: capture, interpretation, retrieval, delivery, use, applicability or method quality. It corrects that step instead of multiplying duplicate lessons or adding a global intelligence score. No-change is a valid result of work actually performed, not a mandatory justification collected after every external action.

Within a task, Eliot may use Propose–Probe–Compose when repetition is appropriate. Across tasks, it retains lessons about how to improve. Baseline/no-change remains valid. A selected candidate is not automatically better. Irreversible external actions are not repeated merely to obtain a comparison.

## 8. Disagreement, prediction and research

Disagreement belongs to a question, scope and time. Eliot preserves rival explanations and their grounds, then identifies the cheapest useful observation that can distinguish them. One source lookup, one agent or a human decision may be enough. A panel or vote is not required.

Unresolved disagreement does not block unrelated work. A provisional choice records why it was chosen and what would cause reconsideration. An unknown should identify the affected question and useful next observation, not force every local correction back through a complete review of the goal.

A prediction states the expected observation before the action, its conditions and the available check. Static dependency, co-change and causal explanation are not interchangeable.

Commitments and unresolved problems are retained state, not notifications. Showing or acknowledging one does not resolve it, and a passed due date does not complete it. Resolution follows a relevant observed event or an explicit owner change. The same scoped context and inspectable inbox expose these records; optional notifications do not create another task manager or a blanket blocker. An expired predictive warning may stop being shown without closing a separate commitment.

Research begins with available memory and exact local sources. External acquisition is used for a concrete remaining gap. Eliot Research owns research execution and large corpora; Eliot stores compact findings, alternatives, coverage and source handles needed later.

A failed source request, completed but uninformative research, and a useful partial answer are different outcomes. Repeating the same uncertainty is not a reason for an endless research loop. Ask for clarification when it can materially resolve the task or an owner decision, not to complete an internal record's optional fields.

## 9. Reliability, privacy and direct control

Persist a primary change and its necessary follow-up intent together. Reconcile uncertain writes by stable identity. A worker restart does not authorize duplicate provider work or external effects.

Hashes identify actual payloads, cache inputs and backup bytes. They do not create authority or prove understanding.

The initial local profile uses project selection, capture exclusions, retention settings and allowed model routes. It does not require a general organization/principal/grant graph or per-record authorization certificates.

Eliot is not a sandbox against unrestricted code running as the same OS user. Use OS permissions, database credentials and the host's real execution controls; state the limit instead of hiding it behind extra metadata.

The owner can directly inspect, configure, pause, cancel, correct, withdraw, erase, back up and restore memory. Optional notifications and diagnostics do not become prerequisites for those operations. An unavailable optional capability or incomplete assessment affects the dependent operation, not a universal permission to continue. Uncertain external effects remain explicit rather than being replayed blindly.

## 10. Explicit non-goals

V3 does not include by default:

- backward compatibility with the V1/V2 runtime;
- Kernel/Host generations, hot replacement or migration facades;
- a second semantic database or mirrored search store;
- a universal workflow engine or query language;
- a skill registry separate from ordinary versioned memory;
- a truth registry, ontology manager or policy engine;
- a mandatory model call for every event, read or tool action;
- a proof factory, signed read receipt or comprehension certificate;
- automatic acceptance of external tasks;
- a second research runtime or swarm;
- success-shaped stubs used to satisfy tests.

A mature dependency or native database feature is preferred over a custom substitute when it actually serves the selected path. These exclusions reject redundant machinery, not the useful capability it was supposed to provide.

## 11. Development rule

Build connected product paths, not layers of unused types.

Each capability must identify:

1. the real input;
2. the operation that runs;
3. the state or content saved;
4. the next real consumer;
5. the failure visible to the user.

Implement the usable Base first, with minimum relevant build/Clippy checks during coding. Once it runs, test that Base before adding further depth. Then implement and test each connected extension against the same product paths, keeping Base usable without it. Testing does not wait for the entire future cognitive system, and tests do not justify speculative infrastructure or production stubs. Module-local tests may substitute an external dependency; they do not establish that the real integration works.
