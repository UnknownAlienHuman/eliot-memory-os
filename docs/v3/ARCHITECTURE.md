# Eliot Memory OS V3 — Architecture

**Revision 1.0-draft · 2026-10-22 · normative design for the greenfield rewrite.**

V1 and V2 are donors. V3 is a new implementation, not a compatibility migration. This document defines **why the product exists, what it owns, and which invariants must survive implementation**. [Implementation](IMPLEMENTATION.md) defines the concrete process, data and integration design. [Cognition](COGNITION.md) defines the algorithms. The [audit conclusion](AUDIT.md) records the evidence, rejected mechanisms and known limits.

## 1. Product purpose

Eliot makes accumulated experience useful at the next decision.

It preserves what actually happened, reconstructs current work, retrieves applicable knowledge, exposes contradictions and unknowns, and improves subsequent work from observed outcomes.

```text
observe
→ preserve
→ reconstruct the current situation
→ supply useful context
→ an external agent acts
→ observe the result
→ revise memory or method
→ use that revision in later work
```

A searchable archive is necessary but insufficient. A large graph, a generated summary, a stored receipt or a successful serialization does not demonstrate understanding. Product value is visible when Eliot reduces repeated mistakes, lowers reconstruction cost, preserves continuity, and supplies relevant knowledge before a consequential decision.

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

Controller-to-memory context and memory-to-controller inference are separate integrations. One does not imply the other.

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

The implementation may contain modules named `store`, `memory`, `context`, `learning`, `jobs`, `adapters` and `control`. These are code ownership boundaries, not mandated services.

A new process is justified only by a real external runtime or failure boundary. A new crate is justified only by an actual dependency, deployment or change boundary. A noun in the design is not an instruction to create a registry, protocol, lifecycle or state machine.

One mutable fact has one writer. Dashboards, packets, scores, maps and status reports are views unless they genuinely own independent state.

## 4. Memory model invariants

### 4.1 Preserve before interpretation

Permitted source events are stored before model interpretation. Missing models, embeddings or project maps cannot destroy the original or prevent direct readback.

Replay is deduplicated by source identity, not by text equality. Independent identical events remain independent evidence.

### 4.2 Source and derivation are different

An observation records what a source supplied. A claim, explanation, method, prediction or project view is derived knowledge.

Derived knowledge retains addressable source handles and the source revisions it used. A model-generated ID is not source content. Retrieval of a claim does not increase its evidential support.

### 4.3 Current value and history are different

Historical evidence remains available after current applicability changes. A procedure can retain valid historical evidence while its exact repair is no longer applicable.

Corrections create revisions. Incompatible alternatives may coexist. Removing a successor does not automatically restore its predecessor as current.

### 4.4 Origin and reuse scope are different

Every item retains where it came from. Reusable methods separately state where they may be considered:

- the originating project;
- selected projects;
- the local owner's projects.

Cross-project reuse never erases origin, conditions, counterexamples or disclosure limits.

### 4.5 Grounds are explicit enough to revise

A conclusion may depend on:

- all members of one grounds group;
- one of several alternative grounds groups;
- supporting material that is useful but not required;
- navigation links that carry no evidential meaning.

Eliot does not infer AND/OR semantics from the number of citations. When the composition is unknown, the conclusion is reconsidered rather than automatically preserved or withdrawn.

### 4.6 Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Show less often while permitted history remains |
| Withdraw influence | Stop a conclusion or method from guiding the stated situation |
| Supersede/refute | Publish a reasoned replacement or contradiction |
| Erase scope | Remove controlled source and derivatives, including staged input and controlled backups |

Already delivered host/provider copies are an external boundary. Restore cannot silently revive a known current deletion.

## 5. Current work and decision context

Current work is addressed before similarity search.

When the host supplies a task, session, branch, workspace or continuation identifier, Eliot opens that state directly, merges later observed events, and then retrieves related experience. A cancelled or superseded plan does not become current merely because it is semantically similar.

A useful context packet contains only material that can change the present decision:

- current goal and known criteria;
- current plan, progress, open commitments and relevant recent results;
- exact constraints and applicable methods;
- relevant prior episodes and material exceptions;
- dissent, uncertainty and missing checks;
- source handles for expansion.

Exact values and qualifications travel together. Handles provide progressive disclosure. Empty sections add no filler.

Context must reach the model at a boundary where it can still affect the decision. Advice and enforcement are separate. Negative memory is advisory by default; a specific host-enforced rule is explicit and opt-in.

Normal retrieval uses independent exact and lexical candidates, compatible vectors and relevant relation expansion. Vector retrieval is required in the complete product, but vector unavailability is a degraded route rather than an empty memory bank.

## 6. Understanding

Eliot maintains reconstructible, revisable views from project purpose to subsystems, resources and observed effects.

Exact structure comes from actual sources and tools. Semantic explanation may use Dreamer. Intended behavior, observed implementation and inferred explanation remain distinguishable.

Project understanding is built incrementally:

- first contact returns available exact facts immediately;
- a bounded orientation job creates useful purpose/area views;
- source changes refresh affected views;
- new consumers can invalidate a complete-set claim even when old cited files did not change;
- failed refresh leaves the previous qualified view and direct source access available.

Understanding is not a compulsory pyramid, complete onboarding ceremony or placeholder card with no explanation.

## 7. Learning and self-improvement

Initial learning changes external memory, methods, context construction and selected configurable strategies. It does not require model-weight training.

A useful provisional method may enter a later eligible context automatically. Applicability and demonstrated broad effectiveness are separate questions.

Each subsequent attempt refers to the exact method revision it received. Eliot distinguishes:

- offered;
- delivered;
- action observed;
- adherence inferred or unknown;
- outcome observed;
- comparative benefit supported or unknown.

One real outcome contributes once. Replayed hooks, several steps in one attempt and summaries of the same episode are not independent successes.

A method revision changes behavior only when a real consumer reads it. A job selects a method ID and revision; the request builder opens and inserts that exact method. A new revision applies to later jobs unless an explicit safe restart is chosen.

Self-improvement diagnoses the failed step: capture, retrieval, delivery, use, applicability or method quality. It corrects that step instead of multiplying duplicate lessons or adding a global intelligence score.

Within a task, Eliot may use Propose–Probe–Compose when repetition is appropriate. Across tasks, it retains lessons about how to improve. Baseline/no-change remains valid. A selected candidate is not automatically better. Irreversible external actions are not repeated merely to obtain a comparison.

## 8. Disagreement, prediction and research

Disagreement belongs to a question, scope and time. Eliot preserves rival explanations and their grounds, then identifies the cheapest useful observation that can distinguish them. One source lookup, one agent or a human decision may be enough. A panel or vote is not required.

Unresolved disagreement does not block unrelated work. A provisional choice records why it was chosen and what would cause reconsideration.

A prediction states the expected observation before the action, its conditions and the available check. Static dependency, co-change and causal explanation are not interchangeable.

Research begins with available memory and exact local sources. External acquisition is used for a concrete remaining gap. Eliot Research owns research execution and large corpora; Eliot stores compact findings, alternatives, coverage and source handles needed later.

A failed source request, completed but uninformative research, and a useful partial answer are different outcomes. Repeating the same uncertainty is not a reason for an endless research loop.

## 9. Reliability, privacy and direct control

Persist a primary change and its necessary follow-up intent together. Reconcile uncertain writes by stable identity. A worker restart does not authorize duplicate provider work or external effects.

Hashes identify actual payloads, cache inputs and backup bytes. They do not create authority or prove understanding.

The initial local profile uses project selection, capture exclusions, retention settings and allowed model routes. It does not require a general organization/principal/grant graph or per-record authorization certificates.

Eliot is not a sandbox against unrestricted code running as the same OS user. Use OS permissions, database credentials and the host's real execution controls; state the limit instead of hiding it behind extra metadata.

The owner can directly inspect, configure, pause, cancel, correct, withdraw, erase, back up and restore memory. Optional notifications and diagnostics do not become prerequisites for those operations.

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

A mature dependency or native database feature is preferred over a custom substitute when it actually serves the selected path.

## 11. Development rule

Build connected product paths, not layers of unused types.

Each capability must identify:

1. the real input;
2. the operation that runs;
3. the state or content saved;
4. the next real consumer;
5. the failure visible to the user.

Implementation follows the owner's sequence: product code first, minimum relevant checks/Clippy, broader tests after the connected product exists. A test later exercises the same production path; it must not create a second implementation inside the product.
