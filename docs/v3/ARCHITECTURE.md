# Eliot Memory OS V3 — Architecture

**Revision 0.2 · 2026-10-19 · design proposal, not an implemented product.**

V1 and V2 are donors. V3 is designed and then written from scratch. This manifesto preserves the original Smart Memory OS purpose; [Implementation](IMPLEMENTATION.md) owns mechanisms, and the [consolidated audit](AUDIT.md) owns evidence and alternatives. Technical proposals below are not represented as separately approved owner decisions.

The design inputs are a local-first Rust product, demand-start operation, a supervised SurrealDB child, full vector capability, external `eliot-swarm-controller` model routing, and no second swarm inside memory. Those choices do not require carrying over V2's process graph, compatibility layers, or development bureaucracy.

## 1. Purpose

Eliot makes accumulated experience useful for the next decision. It preserves observations, reconstructs a situation, explains relevant relationships, exposes contradictions and unknowns, prevents repetition of applicable known failures, and improves subsequent work through observable outcomes.

The complete loop is:

**observe → preserve → reconstruct useful context → external agent acts → observe the outcome → revise memory or method → evaluate the next comparable attempt.**

A searchable archive is useful but is not the complete Smart Memory OS. Neither a large knowledge graph nor a model-generated reflection proves understanding or learning. Progress means less repeated error, better continuation, relevant knowledge available at the correct decision boundary, and an acceptable total cost.

Original basis: [V1 Canonical Master](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md), [V1 Understanding Layer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md). The [audit requirement matrix](AUDIT.md#3-the-34-preserved-requirements) keeps all 34 requirements visible.

## 2. Product boundary

| Responsibility | Owner |
|---|---|
| Ultimate goal, authority, acceptance of externally executed work | Human and external host/controller |
| Executing tools, managing agent sessions, scheduling a swarm | External host/controller |
| Observations, memory revisions, provenance, retrieval, context and outcome memory | Eliot |
| Interpretation, consolidation, concepts, procedures, proposed improvements | Dreamer: a replaceable model-work role, not another authority |
| Model/provider selection and execution, including embeddings | External controller through an explicit execution capability |
| Primary persistence, transactions and search indexes | SurrealDB, used by one private application storage boundary |
| Source acquisition and host lifecycle translation | Narrow adapters with declared coverage |
| Detecting failure of a memory process | Observation outside that process's failure domain |

Eliot remembers the relationship between a host task, an attempt, delivered context, an action, and an outcome. It does not create a competing task truth or accept a host task merely because one verification command passed.

Two integrations are distinct: the controller asks Eliot for context; Eliot asks the controller to execute model work. Neither direction is assumed implemented because the other has a document or a method name. Background memory maintenance does not require inventing a coding task. Model and embedding capabilities are enabled independently as their real routes work.

## 3. Lightweight modularity

Begin with one memory service and ordinary internal modules. A module exists because it owns a coherent transformation or state boundary, not because an architectural noun needs a crate. Pure computations remain functions. Long-running work uses bounded jobs. External runtimes remain external.

Use one primary memory store and one owner for each mutable fact. A context packet, dashboard, learned-policy score, or project map is a projection unless it has a genuinely independent lifecycle. Do not persist several competing versions of the same operational state.

The application starts on demand. An independent supervisor may live only while the memory service is active; a separate observer adds a real process and its cost must be counted. It is not a second memory writer. No permanent system service, automatic scheduled wake, or hot replacement of arbitrary code is required by default.

The update path is controlled restart and recovery. Optional computation may fail without taking down unrelated work. A Rust module is not a memory-protection boundary: process abort, resource exhaustion, blocking native code and task errors are different failures. Use process isolation where its benefit is concrete, not for every cognitive function.

Replaceability means a clear module boundary and recoverable data. It does not mean building every future database, harness or plugin protocol in advance.

## 4. Memory preserves distinctions

### Preserve before interpretation

Accept admissible observations before semantic classification. Unknown meaning is a valid state. Missing models, an incomplete ontology, or a failed consolidation must not destroy the source or block deterministic readback.

Preservation still obeys storage and privacy policy. It is not permission to collect prohibited secrets. Acknowledgements identify what actually happened: committed to primary storage, durably staged for later intake, outcome unknown, or rejected. Repeated delivery is deduplicated by source-event identity, not merely by equal text.

### History is not current applicability

Keep an immutable observation of a failure at revision X even when the project moves to revision Y. A historical source supports what happened then; a live dependency establishes whether a view or recommendation applies now. Treating every old source as invalid whenever HEAD changes would erase the experience the system is intended to accumulate.

A procedure therefore carries historical evidence **and** current preconditions. Changing unrelated code does not revoke its history. Changing a relevant API or tool profile requires reconsidering applicability. Refuting or withdrawing an actual source requires reconsidering its conclusions. Privacy restrictions continue through all actual content lineage, whether historical or live. For model-generated text, the supplied source material bounds disclosure; the model cannot declassify its output by omitting a citation.

### Knowledge is revisable

Distinguish observations, claims, hypotheses, decisions, procedures, unknowns and conflicts. Keep support, search availability and permitted influence separate. Retrieval frequency, confidence, similarity and the number of paraphrases do not make a claim true.

A correction creates a new revision and a reason. Multiple citations do not automatically mean independent support; multiple premises are not automatically interchangeable. Do not remove a citation from old synthesized text and declare that text safe or independently justified.

### Forgetting has different meanings

| Operation | Preserved distinction |
|---|---|
| Reduce availability | Less ordinary exposure; history may remain available on demand |
| Refute, supersede or revoke influence | A conclusion no longer guides work under the stated conditions; retain permitted history |
| Erase a defined privacy scope | Remove controlled data and derivatives; account for staged input, backups and external copies |

Compression cannot silently discard the only exception, counterexample, failed attempt or open commitment. A restored copy must not revive a current deletion or restriction. Bytes already delivered outside Eliot have a separate retention boundary; a database flag cannot recall them.

## 5. Context at the actual decision boundary

Normal retrieval does not wait for generative inference. Use exact cues and lexical retrieval, compatible embeddings and bounded relation expansion. Vector capability is part of the full product; its outage is a visible degraded mode, not the absence of all memory. Scope and permitted influence constrain candidate selection and final disclosure.

A packet contains the material that can change this decision: goal and criteria, current state, applicable constraints, experience, relevant relationships, counterevidence, unknowns and the next useful verification. Empty sections need no filler. Exact values and exceptions survive as complete semantic units. Omitted material has revalidated expansion handles.

There are two different delivery mechanisms:

- **Advisory context:** reaches a model request before the model chooses the decision it can affect.
- **Action enforcement:** an already authorized host gate can stop a particular pending action.

A hook executing before a tool is not proof that the model reads its text before that tool. The adapter must declare the real timing. Semantic similarity is advisory; an exact applicable rule may restrict an action only under existing policy. Do not block every tool to manufacture an opportunity for context injection.

Previously delivered context may remain in a host transcript. Refresh on continuation and show superseded guidance; do not claim remote erasure or guaranteed removal of the model's prior context. A critical action can require a fresh host-side check where the host actually supports it.

## 6. Understanding, attention and disagreement

Maintain a reconstructible map from project purpose to subsystems, concepts, resources and observable effects. Structure and exact references come from available source tools. Meaning, analogies and proposed causal explanations may require a model. The output distinguishes those two kinds of evidence and marks missing coverage.

Update only affected views. A missed watcher event is repaired by source reconciliation, not by trusting an old summary indefinitely. Non-Git projects remain valid projects; lack of a revision anchor reduces a claim of freshness rather than inventing a commit.

A useful prediction names an observable consequence, the conditions and where it will be checked. Compare it with a subsequent result. Static dependency, co-change and causal evidence remain different relationships. Unknown comparison is not failure or confirmation.

Negative memory records the trigger, failed action, conditions and grounds for reopening. A false prohibition is itself useful experience. Successes contribute procedures too; a memory composed only of prohibitions would become an obstacle rather than an assistant.

When explanations conflict, preserve dissent and shared sources, identify what would discriminate between them, and propose a next observation. This preserves the cognitive purpose of Concilium without a voting system or an embedded swarm.

Attention is unresolved state that matters to work: a contradiction, missing support, commitment, dangerous recurrence or missed observation. Notification delivery and acknowledgement are not resolution.

## 7. Self-learning must reach a consumer

Initial self-learning changes external memory, procedures and permitted context methods, not model weights. Dreamer may use any configured model that supports the chosen task; protocol compatibility does not promise equal quality.

A candidate names a concrete change, trigger, evidence, scope, exceptions and withdrawal condition. A low-risk advisory can enter the next eligible context automatically under existing policy. Do not trap every candidate behind a manual approval or an unimplemented evaluation platform.

Retain the subsequent attempt and the exact procedure revision offered. Distinguish found, delivered, observed action, adherence, outcome and comparative benefit. A citation, overlapping filename or agent self-report is not causal evidence.

One underlying outcome contributes once to a given evaluation. Retry, duplicate hooks, several steps of one episode and restating an induction example are not new independent successes. A corrected outcome replaces the current assessment instead of permanently increasing a counter.

Broader reuse requires applicable subsequent cases, negative cases and an independent evaluation against a fixed baseline. Data used to invent a rule cannot simultaneously prove its out-of-sample value. Success on one profile is not an automatic claim about every repository or model. When data are sparse, useful local adaptation can remain explicitly provisional.

Improvements to retrieval, context assembly, prediction and verification are evaluated as separate changes. The candidate cannot weaken its own evaluator, alter the user's goal, increase authority, silently change privacy or publish itself to a broader audience. Safety constraints and explicit user requirements are not withheld for a memory experiment.

## 8. Dreamer and research

Dreamer performs bounded consolidation, interpretation, contradiction analysis, project orientation, procedure extraction and improvement work. It reuses the same job machinery and storage path. It does not need a dedicated always-on intelligence service or a new memory layer for each operation.

The model proposes data. Eliot validates input membership, target scope, current revision, permitted transformation and current job ownership before applying it. A model may propose a subject or relationship; it cannot authorize a cross-subject merge or select a foreign write target. Unsupported output is a job failure, not loss of the original observations.

Research acquisition can come from an external provider. The output names its examined scope, sources, counterevidence and gaps. No result in a sample or top-k search is not proof of universal absence. Exploration may change its question openly; confirmation uses fixed criteria.

[Hy-Memory](https://github.com/Tencent-Hunyuan/Hy-Memory/tree/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a) is a mechanism donor, not V3's mandatory runtime. Its learned writer weights, training signals and application code are different artifacts. Eliot should borrow useful organization and feedback mechanisms without copying the entire hierarchy or claiming that ordinary source citations reproduce supervised reward attribution.

## 9. Reliability and control without a second operating system

Persist a write and its required follow-up intent together. Reconcile an unknown response using the same identity. A local worker claim is distinct from an external model request: worker recovery is not permission to buy the same inference again.

A cancelled, expired or replaced worker cannot publish. External cancellation is best-effort unless the executor guarantees more. Account for late results and unknown cost separately from permission to use their content.

During maintenance, separate pausing admission from holding a lock. Do not wait for workers while holding the resource they need to finish. Prefer a clearly bounded conservative backup procedure over an unsupported promise of an instantaneous snapshot. Recovery must not blindly replay external effects from an older backup.

People can inspect active work, reasons for delay, recent changes, provenance and missing observations; pause or cancel; select routes and budgets; correct or erase defined memory. The same application functions serve CLI and any later panel. A separate control-plane platform is unnecessary.

The initial local-user profile is not a security boundary against an arbitrary process running with the same unrestricted OS identity. Agent tool restrictions and database credentials must match the actual deployment. A CLI label saying “human only” or a Job Object does not establish such isolation.

## 10. Economy and development

Count the total supported system: Eliot, required controller work, adapters, database operation, scripts, builds, memory, latency and model attempts. Moving complexity into SQL or another repository does not eliminate its cost. A claimed 50-fold reduction requires a comparable implemented boundary.

Add a mechanism because it completes a user path or removes a specific failure. No crate-per-concept, generic query language, second semantic store, duplicate scheduler, permanent compatibility facade, proof-factory or mandatory approval of every ordinary helper.

Finish the documentation stage before rewriting the product. Then build connected vertical paths with the owner's order: product code and minimum relevant checks/Clippy; tests after the product is built. Future behavioral scenarios are requirements for truthful product acceptance, not a demand to create test infrastructure now.

All 29 original A15 scenarios remain in the [audit scenario matrix](AUDIT.md#12-all-29-original-scenarios). A first partial slice does not silently remove the remaining cognitive, privacy, supervision or control requirements.
