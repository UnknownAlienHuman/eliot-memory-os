# Eliot Memory OS V3 — Architecture

**Revision 0.6 · 2026-10-19 · documentation-stage design, not a working product.**

V1 and V2 are donors. V3 is a new implementation, not a compatibility migration. This manifesto defines purpose and boundaries; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) define mechanisms. The [consolidated audit](AUDIT.md) holds sources and rejected alternatives; the [audit map](AUDIT-MAP.md) tracks unfinished reading, not runtime permissions.

The design inputs remain local-first Rust, demand-start operation, a SurrealDB server child, full vector capability, model and embedding routes through `eliot-swarm-controller`, and no second swarm inside memory. Old donor ADRs and release ceremonies do not acquire authority over V3 merely by remaining in Git.

## 1. Purpose

Eliot makes accumulated experience useful for the next decision. It preserves observations, reconstructs a situation, connects project purpose to implementation, exposes contradictions and unknowns, helps avoid applicable known failures, and improves subsequent work from observed outcomes.

**Observe → preserve → reconstruct useful context → external agent acts → observe the result → revise memory or method → use the revision in subsequent work.**

A searchable archive is useful but not the complete Smart Memory OS. A large graph, reflection paragraph or successful serialization does not demonstrate understanding. The useful outcomes are less repeated error, cheaper reconstruction, better continuation and relevant knowledge at the actual decision boundary.

The original basis is the [V1 Canonical Master](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md) and [Understanding Layer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md). All [34 requirements](AUDIT.md#3-the-34-preserved-requirements) and [29 original scenarios](AUDIT.md#12-all-29-original-scenarios) remain visible; a first slice does not erase them.

## 2. Product boundary

| Responsibility | Owner |
|---|---|
| User goal, execution permissions and acceptance of external work | Human and external host/controller |
| Tools, agent sessions and swarm scheduling | External host/controller |
| Observations, semantic revisions, source links, retrieval, context and outcome memory | Eliot |
| Interpretation, consolidation, concepts, procedures and improvement proposals | Dreamer, using any suitable configured model |
| Provider/model execution and embeddings | Controller through its actual supported routes |
| Persistence, search indexes and transactions | SurrealDB through one private application Store |
| Host/source translation | Narrow adapters |
| Detecting failure of the memory process | Observation outside that process's failure domain |

Eliot links a task, attempt, context, action and outcome without creating a competing task manager. An external task is not accepted because one memory check or command returned success.

Controller-to-memory context and memory-to-controller inference are different integrations. A document for one does not implement the other. Background memory work does not need a fake coding goal. Real synthesis tasks may use the controller's existing execution model when appropriate.

## 3. Lightweight modularity

Begin with one memory service and ordinary internal modules. Pure transformations are functions; finite background work uses the existing job mechanism. A noun in an architecture is not an instruction to create a crate, process, registry or protocol.

One mutable fact has one writer. Packets, dashboards, aggregate scores and current-state maps are views unless an independent lifecycle is genuinely required. No second semantic database or mirrored workflow state is introduced for convenience.

Start on demand. Reuse an existing supervisor only when it actually covers the memory process; otherwise a small supervisor can live with the standalone application. Count that process honestly. No permanent Windows service, automatic OS wake or hot replacement of arbitrary code is required by default.

Restart and recovery are the upgrade path. A Rust module is not a memory-protection boundary: task error, process abort, resource exhaustion and blocking native code need different handling. Isolate external runtimes where the failure cost warrants it, not every cognitive operation.

Replaceability means a coherent boundary and recoverable data. It does not require implementing every hypothetical future backend or reproducing V2's migration facades.

## 4. Memory preserves distinctions

### Preserve before interpretation

Capture permitted observations before semantic classification. Missing models and unknown meaning cannot destroy the original or prevent deterministic readback. Source-event identity deduplicates replay; identical text from independent events remains distinct.

Report the actual preservation result: primary commit, durable staging, unknown result or rejection. Restrict secrets and retention at capture, not through a proof certificate added after disclosure.

### History is not current applicability

An error observed at revision X remains historical evidence after the project reaches Y. Only relevant current preconditions govern whether a concrete recommendation still applies. An unrelated HEAD change must not erase accumulated experience.

Keep historical evidence, live requirements and disclosure restrictions distinct. A procedure can retain its old evidence while a removed API makes its exact repair inapplicable. A refuted premise causes reconsideration, not silent deletion of an inconvenient citation from unchanged synthesized text.

### Knowledge is revisable

Observations, claims, hypotheses, intended behavior, observed behavior, procedures and unknowns are not interchangeable. Retrieval frequency, confidence, cosine similarity and paraphrase count do not establish truth.

A correction records a new revision and its reason. Preserve incompatible alternatives and independent occurrences. Several citations need not be independent; several premises need not be alternatives. Removing a successor does not automatically make its predecessor current again.

### Forgetting is not one operation

| Operation | Meaning |
|---|---|
| Reduce exposure | Less ordinary attention; permitted history can remain available |
| Refute, supersede or withdraw influence | A conclusion no longer guides the stated situation |
| Erase a defined scope | Remove controlled content and derivatives; account for staged input and backups |

Compression must preserve material exceptions, counterexamples and open commitments. A restored old copy cannot silently revive known current deletions. Already delivered host/provider copies are an explicit boundary, not something a local flag can recall.

## 5. Context at the actual decision boundary

Normal retrieval does not wait for generative inference. Use independent exact and lexical candidates, compatible vectors and relevant relation expansion. Vectors are part of the full product; their outage is a degraded route, not an empty memory bank.

A packet contains what can change this decision: goal and criteria, current state, applicable constraints, relevant experience, dissent, missing information and a useful next check. Empty sections need no filler. Exact values and exceptions travel as meaningful units; additional material is available through handles.

Advisory context must reach the model before the decision it can affect. An authorized host gate is a different mechanism that can stop a pending action. A hook running before a tool does not prove that the model reads its text before that tool. Do not block every call to manufacture another model turn.

Similarity can suggest a relevant warning; it does not authorize a prohibition. Negative memory should help work, not become an expanding policy engine. A legitimate diagnostic probe can have an expected negative result without becoming a forbidden action.

Previously delivered material may persist in a transcript. Refresh current applicability on continuation; do not claim that memory withdrawal erased the model's prior context.

## 6. Understanding, attention and disagreement

Maintain reconstructible views from project purpose to subsystems, resources and observable effects. Exact structure comes from source tools; semantic explanation and analogy may require a model. Keep those origins distinguishable.

Update affected views, not the whole world after every edit. A list of cited files does not establish that no new consumer appeared elsewhere: set-valued views retain their examined scope. Non-Git projects and incomplete source coverage remain useful with explicit limits.

A prediction names the expected observation before the action, its conditions and how it can be checked. Static dependency, co-change and causal explanation are different relationships. An unavailable comparison proves neither success nor failure.

Preserve successful methods as well as negative experience. A false warning is itself feedback. When explanations conflict, retain their evidence and differences and identify a discriminating observation; this preserves Concilium's cognitive purpose without a voting platform.

An unresolved commitment or contradiction is state, not a notification. Delivery and acknowledgement do not resolve it.

## 7. Automatic learning and learning how to improve

Initial self-learning changes external memory, procedures and permitted context methods, not model weights. Dreamer is model-independent; interface compatibility does not guarantee equal quality.

A useful low-risk advisory may enter a subsequent eligible context automatically. Reuse in another permitted situation may also be provisional when its conditions are checked and its limits are shown. Do not require a separate approval, experiment or universal promotion certificate before every such use. Applicability, permission to use and demonstrated effectiveness are different questions.

Record the subsequent attempt and exact method revision. Separate delivery, observed action, adherence, outcome and comparative benefit. One outcome contributes once; duplicate hooks, several steps of one attempt and repeated summaries are not independent successes. A corrected outcome replaces its contribution.

Claims of broad improvement require independent comparable evidence, including failures and material profile changes. Evidence used to invent a method does not prove its out-of-sample benefit. Missing evidence permits a labelled hypothesis, not a fabricated success score.

Two recursive loops use these same records. Within a task, propose a concrete change, probe its effect where repetition is appropriate, and compose or keep the current method. Across tasks, retain what the comparison taught about **how to improve**, so future proposals and checks can become better. This borrows the mechanism of [Harness2](https://github.com/google-research/harness2/tree/1cfe254e8d25b15f37048c3730134686abe60335), not its benchmark runtime or fixed rollout quota.

An improvement can be rejected or add no knowledge. The user goal, permissions and acceptance criteria are not editable variables of the same comparison. A chosen output is not automatically better, and the latest task-specific harness is not blindly inherited by the next task.

## 8. Dreamer and research

Dreamer performs interpretation, consolidation, contradiction analysis, project orientation, procedure extraction and improvement through the existing job and storage paths. It is not an always-on second authority or one service per cognitive operation.

Models propose content and relationships. Application code checks a small concrete contract: valid result shape, actual input/target membership, relevant source/target revisions and current job. It does not issue semantic-comprehension certificates. Physical erasure, goal changes and new execution permissions are not implied by a model response.

Research can use external Search/Research providers. Record the examined scope, sources, contrary evidence and gaps. Exploration may revise its question openly. An empty sample or top-k result is not universal absence.

[Hy-Memory](https://github.com/Tencent-Hunyuan/Hy-Memory/tree/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a) supplies useful memory mechanisms; its writer weights, application paths and training evaluation are distinct artifacts. Borrowing one does not qualify the others.

## 9. Necessary reliability, not an enterprise policy platform

Persist a change and its necessary follow-up intent together. Reconcile unknown writes by stable identity. A local worker restart does not authorize a duplicate external inference or tool effect. Stale workers cannot publish, and best-effort cancellation does not mean an external effect never happened.

Keep straightforward local configuration: selected projects, capture/retention preferences and allowed model routes. Preserve source links for correction and deletion. No principal/grant graph, per-record authorization certificate, signed proposal or hashed proof of reading is required for this local profile.

Hashes are useful for identifying actual payloads, caching and backup integrity. They do not create authority or prove understanding. Do not rehash ordinary in-process values across invented trust boundaries. Use standard implementations, OS access controls and the controller's actual execution permissions.

The application is not a sandbox against an unrestricted process under the same OS account. That limitation must be stated, not disguised by additional identity fields. Do not expose database credentials to model context or send local-only data to a remote route.

Control remains direct: inspect, pause, cancel, configure, correct and erase defined memory. During maintenance, never wait for a worker while holding the lock it needs. Prefer a concrete conservative backup to an unsupported instantaneous-snapshot promise. A small CLI/inbox and existing state views are sufficient initially.

## 10. Economy and development

Count the entire required system: Eliot, controller work, adapters, database operation, scripts, builds, process memory, latency and model attempts. Moving complexity into SQL or another repository does not remove its cost. A fifty-fold reduction is a hypothesis until measured at a comparable functional boundary.

Add a mechanism to complete a user path or remove a named failure. Do not create a crate per concept, a second scheduler, a universal query language, permanent compatibility facades, a proof factory or mandatory approval of ordinary helpers. Prefer a mature dependency to a custom substitute unless its actual cost is worse; old donor restrictions are evidence, not vetoes.

Finish documentation before the rewrite. Then build connected paths using the owner's sequence: product code, minimum relevant checks/Clippy, tests after the product is built. Future behavioral cases are acceptance expectations, not a demand to construct a test bureaucracy now.
