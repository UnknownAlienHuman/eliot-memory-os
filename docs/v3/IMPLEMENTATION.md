# Eliot Memory OS V3 — Implementation

**Revision 0.3 · 2026-10-19 · technical proposal; no V3 runtime has been implemented or qualified.**

[Architecture](ARCHITECTURE.md) defines purpose and preserved properties. [Audit](AUDIT.md) records findings, source pins and rejected alternatives. This document owns runtime and integration mechanisms; [Cognition](COGNITION.md) expands the cognitive transformations inside these same modules. Names below are application concepts, not claims about existing controller RPCs or ready-to-run SurrealQL. Revision 0.3 audits Memory OS `da441352`; the controller source boundary `96a0d5a` is retained from 0.2, not newly qualified.

## 1. Initial delivery

### 1.1 Runtime and module shape

Use one Rust package initially, with executable modes and ordinary modules. Split a crate only for a demonstrated dependency, trust, deployment or change-cost boundary. The same executable can provide CLI, MCP/hook relay, supervisor and daemon modes; these modes do not each require their own package.

| Module | Owns | Does not own |
|---|---|---|
| `store` | Schema, parameterized queries, atomic writes, operation readback | A general query language or a second database service |
| `memory` | Capture, revisions, source lineage, allowed state transitions | Provider execution or task acceptance |
| `context` | Retrieval, applicability, packet assembly and progressive reveal | Another semantic store |
| `learning` | Procedures, outcome interpretation and evaluation projections | A parallel attempt/overlay scheduler |
| `jobs` | Durable memory-processing intent, claims and result application | Provider-side execution state |
| `adapters` | Actual host/source/controller interfaces | Invented capabilities or arbitrary model SQL |
| `control` | Settings, maintenance, health/status and recovery decisions | A replacement for OS process primitives |

The selected database is a SurrealDB server child of `eliotd`. One private `Store` module performs application writes. Use native lexical/vector indexes, relations and transactions; no redb/SQLite semantic mirror, storage bridge process, universal operation catalogue or compatibility facade.

The first deployment is local Windows. The proposed full observed profile has three owned processes while active: a small demand-start supervisor, `eliotd`, and its SurrealDB child. CLI/host relay processes are transient; the external controller and its model runtimes are additional dependencies. This is one memory writer, not a claim of one total process. The smaller launcher-only profile lacks continuous hang detection and is reported as such. Detailed custody is in §9.

### 1.2 Demand-start and dependency availability

A host/CLI invocation starts the supervisor and daemon through one OS single-instance boundary per data directory. Readiness covers storage and required local operations, not every optional model route. During a model outage, capture and permitted exact/lexical reads continue; vectors remain a full-product capability with a visible degraded state when unavailable.

Before idle exit, stop admission of new external work, settle short mutations, preserve pending jobs and stop the child database. The supervisor recognizes intentional shutdown and exits. There is no SCM installation or background wake registration by default. Scheduled work runs while active or at the next demand start; report overdue work honestly. An explicitly enabled OS wake may start the application later, but does not become a second scheduler or quietly change this default.

### 1.3 Database client decision and error boundary

Keep the client private to `Store`. The retained [Phase A ADR](../ADR/0001-phase-a-dependency-boundaries.md) excluded the SDK because of its then-current dependency/release-gate graph. The supplied Claude proposal later used `Surreal<Any>`. Neither establishes that the dependency issue persists or that a specific current SDK/server pair works.

Do not silently revoke that constraint or implement both clients. O4 must record one choice: retain a narrow official WebSocket JSON-RPC transport, or explicitly replace the historical restriction with a pinned network-only SDK whose dependency cost is acceptable. Prefer reuse over recreating connection, authentication and decoding machinery, but do not present this preference as an approved SDK migration. Embedded database engines are unnecessary in the production client.

The earlier audit identified server 3.3.4, dated 2026-10-13, as a V3 candidate. It is not an installed-version claim, and the exact client/server build is still unqualified. Record the selected server, client and schema versions together; avoid a moving `latest` target in implementation. These implementation choices do not modify the retained V2 dependency graph or ADR in this documentation change.

For either client, transport success is not mutation success. Check all statement results, required bindings, decoded types and expected cardinality; a conditional single-row transition must affect exactly the intended row. The SDK documentation specifically exposes per-statement errors and notes that an unbound parameter becomes `NONE` rather than necessarily raising an error. A private fixed query plus a small typed parameter object is enough; do not build a query validator language. [Query documentation](https://surrealdb.com/docs/reference/rust/methods/query).

## 2. Minimal data and ownership

### 2.1 Record families

| Family | Retained facts | Writer |
|---|---|---|
| `observation` | Source event identity, original admissible material or blob handle, origin, scope, timestamps and coverage | `memory.capture` |
| `memory` | Immutable revisions of claims, decisions, procedures, unknowns, failures and project views; support, availability and influence | `memory.apply` |
| `link` | Typed references between exact revisions; evidence, live requirement, contradiction, replacement or structural relation | The same memory transaction |
| `attempt` | External task/attempt identity, applicable context revisions, prediction, available action/outcome observations | `record_outcome` |
| `job` | One durable intention to transform memory; inputs/profile, claim, deadline, execution reference and result | `jobs` through `Store` |
| `operation` | Local mutation identity, input fingerprint, result and minimum retry/correction explanation | The corresponding transaction |

These are logical families, not a fixed table count. Context deliveries and outcome contributions can be child records of an attempt; notifications can use jobs. Do not persist a new state machine for each view.

Preserve semantic revisions as actual application records, not merely as overwritten rows whose earlier values might exist in engine history. A material correction points to its predecessor; replacement does not destroy a distinct physical occurrence.

For large permitted inputs, persist immutable blob bytes first and publish their reference transactionally; later garbage-collect unreferenced blobs. If only a prefix/tail or external source handle was captured, record that limit. Truncating the extractor's prompt is not the same as deleting the original error or exception. Backups and erasure cover blobs as well as database rows.

### 2.2 Identity, scope and status

Derive the local user and permitted project/workspace from the connection and host binding. A model cannot set an authoritative owner or expand scope. Branch, file/symbol, task and tool profile are applicability dimensions where necessary, not separate authorities.

Keep source-event identity separate from content equality. A replay uses the same `(source, event_id, source_revision)` or an adapter-assigned stable delivery ID. Equal text from independent events remains independently identifiable; distinct IDs for copies of one event do not make independent evidence.

For time, distinguish when an event occurred, when it was received, and a claim's validity interval. Each interval boundary can be known, unknown or unbounded. Unknown is not INSERT time. Historical queries must not manufacture certainty from absent dates.

| Dimension | Proposed values | Meaning |
|---|---|---|
| Support | observed, hypothesis, supported, conflicted, refuted, unknown | Evidential interpretation, with its basis |
| Availability | active, on_demand, archived | Ordinary selection versus explicit reveal |
| Influence | use, warn, handle, none, quarantined | Allowed presentation/action influence |

A useful hypothesis may be delivered with its hypothesis label. `influence != none` is not a valid allowlist: it also admits quarantined or handle-only content. Restricted metadata and hidden ranking features require the same policy attention as displayed text.

The first profile assumes cooperative adapters and the host's actual tool restrictions. An agent with unrestricted shell/filesystem access under the same OS account can potentially invoke administrative CLI modes or access that user's files. “Human CLI only” is not a hard sandbox. Stronger isolation requires an actual host/OS access boundary, not an extra `principal` string. Do not expose database credentials to the model or arbitrary adapters.

Current-state grouping preserves subject/aspect, perspective and source context as defined in [Cognition §§2–3](COGNITION.md#2-small-claim-identity-not-a-fixed-world-ontology). Intended behavior, observed behavior and a proposed explanation are not interchangeable values. An ambiguous semantic key does not block raw capture.

### 2.3 Historical evidence, live requirements and privacy lineage

Use the existing link structure with explicit meanings:

| Link meaning | Example | What changes invalidate it |
|---|---|---|
| Historical evidence | This error occurred in attempt A on source revision X | Retraction, loss of evidential support, or policy/erasure affecting the source; a later unrelated HEAD does not erase the event |
| Live requirement | This current API map or actionable instruction requires the present signature to match revision X | Change of the relevant anchor/profile, not every repository edit |
| Supporting evidence | Another source favors the conclusion | Reconsider strength/justification; it is not automatically an alternative sufficient proof |
| Contradiction/replacement | New evidence disputes or replaces a prior conclusion | Keep both histories and the reason for the transition |

Batch or episode membership is navigation, not evidence or a live requirement. Store one batch reference rather than a Cartesian set of all-to-all support links. Explicit evidence may select a subset; an allowed citation ID still does not prove that the interpretation is true.

A procedure may use immutable evidence from X while its applicability is checked against Y. For instance, the lesson to inspect an API consumer can survive a source update while an exact instruction to call a removed symbol cannot.

For a derived revision, list required live anchors separately from historical evidence. Validate the selected candidate's relevant dependency subgraph, with memoization within the request. Unresolved cycles or exhausted validity checks produce a visible stale/unknown item, not a positive `use` decision. Background refresh continues affected work. No whole-corpus traversal is required on every read, and no bounded pass may silently declare unvisited descendants valid.

If a derivation requires several premises, all remain required. Independent alternative justifications must be identified explicitly; several citations are not an automatic OR. After losing an actual premise, review or regenerate the conclusion before publishing a new revision. Do not preserve the old text merely by deleting its inconvenient citation.

**Policy lineage is separate from live freshness.** Every actual content source, historical or current, contributes its permitted read/disclosure purposes. For a model transformation, conservatively include all source material supplied to that invocation, not only the citations the model chooses to return. A derivative may not have broader effective permissions than that input lineage allows; a broader derivative is regenerated from an appropriately restricted input set. Recheck policy before model dispatch, publication and reveal. Removing a private source link without regenerating the content does not declassify the content.

Serialize eligibility-changing transitions and derivative publication through a short per-workspace application write boundary. Validation and commit must be ordered against those transitions; a snapshot over different rows alone is insufficient. A future multi-writer profile needs a database conflict mechanism, not a claim that this local rule already scales to it.

Before handing bytes to a transport, revalidate current policy and required live anchors at that boundary. Do not hold a database transaction while waiting for the provider. A handoff already admitted may finish after a restriction is acknowledged; cancellation is best-effort. Eliot-owned queued payloads must recheck when actually sent. A controlled boundary cannot recall bytes already in a host transcript or external provider.

## 3. Host interface and experience intake

### 3.1 Small application surface

| Operation | Input supplied or bound by adapter | Result |
|---|---|---|
| `attach` | Workspace and real host capabilities | Binding, settings and explicit missing capabilities |
| `capture` | Event ID, source revision and admissible material | ID plus committed / staged / unknown / rejected |
| `context` | Current task/goal reference, decision cue, budget | Useful packet, handles, warnings and gaps |
| `open` | Handle and requested revision | Revalidated content or unavailable / stale / denied |
| `record_outcome` | Attempt, criterion, available action/result evidence | Stored outcome and eligible next learning work |
| `dream` | Question or selected memory-processing goal | Job handle and eventual candidates/result |
| `control` | Status, pause/cancel, configuration, correction or erasure | Applied transition or its concrete unavailable/busy state |

CLI/MCP/hook adapters reuse these functions. Do not make an agent administer leases, fill proof profiles, query several readiness registries or repeatedly attach before every tool. Keep the model-visible surface small; internal helpers need not each become MCP tools.

For an ambiguous project, preserve admissible input in a narrow session scope rather than guessing a foreign project ID. Non-Git projects use available directory/source anchors. Setup may inspect bounded metadata for an unknown executable; it must not run it, including `--version`, or grant it secrets merely to complete setup.

### 3.2 Capture and correction

Validate storage permission, size and basic envelope shape; do not require semantic classification. In one transaction, reconcile operation identity and input bytes, store the observation, insert necessary deferred work and retain the operation result. A repeated ID with different bytes is a conflict. Return `committed` only when the transaction is confirmed.

An error code, an explicit user decision, exact edit reference or verifier result can be recorded deterministically. A model supplies interpretation later. Correcting an observation preserves its original source identity and the amendment; it is not another independent outcome.

### 3.3 Durable deferred intake

Use one small **file spool for input delivery only** when the database is unavailable or mutations are paused. It is not searchable semantic memory and does not hold a second job scheduler.

Initial candidate layout: one bounded event file per stable delivery ID, grouped into an active directory and sealed directories. Create a complete temporary file outside the rotatable active directory, persist it, then atomically publish it into the currently selected active directory under an opaque safe filename using the selected Windows primitive. A short per-data-directory ingress mutex orders publication and directory rotation; concurrent hook processes never append interleaved JSON into the same text line. Existing same-ID bytes are a replay; different bytes are a conflict. Exact Windows durability/rename semantics remain an implementation qualification, not an assumed `flush()` guarantee.

A `staged` acknowledgement follows durable publication. Partial temporary files are not acknowledged input. Enforce limits by bytes and item size; full disk/spool produces an explicit rejection. Recover all sealed directories and the active directory; a crash during rotation must not hide a sealed batch. Delete a spool file only after a confirmed primary commit or an authoritative erasure decision.

Replay calls the normal capture transaction with the same identity and current retention rules. A lost commit response is reconciled by operation/source identity before any new insertion. Same-ID database and spool copies are safe duplicates, not two observations or two model jobs. Previously staged content does not become confirmed knowledge just because it exists on disk.

Erasure and backup use this spool through the single ordering procedure in §10. They are not redefined here. In particular, backup does not wait for a replay worker while holding its ingress lock, and erasure need not trust a stale cached tombstone set.

### 3.4 First host: native Claude Code integration

**Proposal:** implement native Claude Code command hooks plus MCP first, independently of whether a controller's Claude SDK adapter exposes the same hooks. Discover and record the installed version and actual enabled events; documentation availability is not installed qualification.

Use SessionStart and UserPromptSubmit for bounded orientation at the next planning boundary; PostToolUse/Failure for capture; continuation/compaction events for refresh; and a separate deterministic PreToolUse policy check only where a configured rule actually needs enforcement. The official hook reference states that tool-hook `additionalContext` is read on the **next model request**, not as a new model decision before the pending tool. Do not describe this advisory channel as prevention of that call. [Hook timing](https://code.claude.com/docs/en/hooks#add-context-for-claude).

Advisory timeout returns no additional advice and records degraded delivery. Mandatory enforcement follows its explicitly configured failure policy; absence of memory advice must not grant permission. Do not use generic string similarity to block shell execution. An exact permitted rule includes its relevant arguments/resource/profile and reason for reopening.

Capture hook identities and immutable source references where available. If events arrive out of order, keep their linkage; do not pair a result to the latest request by timestamp. For missing IDs, the adapter creates stable delivery identity and states its correlation limit. A process crash before the hook ran is not observed capture.

On resume or host/model change, reconstruct current goals, abandoned plans, unresolved commitments and live applicability; retain historical failures. Previously inserted host text may persist, so a fresh packet distinguishes withdrawn advice instead of claiming to erase it. Reset the delivery cache for the new context incarnation. Do not suppress a changed procedure forever because an older revision was delivered earlier in the session.

Do not force a lesson on every Stop, make every Stop restart the conversation, or require an agent to call `finish` just to end a session. “No supported lesson” is valid. Model-visible source text is data, not a privileged instruction channel.

### 3.5 Host capability limits

Separate capabilities for capture, advisory insertion timing, pending-action denial, outcome observation, transcript refresh and cancellation. A search-only host remains useful but does not demonstrate proactive closed-loop behavior. Other hosts get their own adapters; similar field names are not proof of equivalent timing, persistence or cancellation.

The initial controller SDK bridge has its own bounded metadata/result path. Reusing it requires checking that path, not assuming that all native Claude Code hooks pass through it. Hostless maintenance has no agent action stream; its completion is the memory transformation, not an invented host-task outcome.

## 4. Retrieval and context assembly

### 4.1 Query path

Derive permitted scope and live situation. Retrieve exact constraints and negative guidance independently of relevance top-k; then exact identifiers, BM25, compatible vectors and limited neighboring source/relation expansion. Merge rankings without merging distinct events, contradictory claims or different revisions merely because their texts are similar.

Apply allowed scope and presentation channels within each candidate arm and again before reveal. If the ANN plan cannot enforce the required restriction, use exact similarity inside the authorized set or another demonstrated query plan; global top-k followed by filtering is not equivalent. Do not use quarantined or private edges as hidden ranking boosts into an otherwise allowed result.

Validate policy lineage and **required live** anchors as specified in §2.3. Historical evidence can be shown as history. Compose complete semantic units and give a reason for material exclusion or uncertainty. Store only the IDs/revisions, method revision and outcome linkage needed for explanation; temporary full ranking traces need not become another permanent registry.

After candidate retrieval, use [scoped current-value resolution](COGNITION.md#3-resolve-current-state-independently-of-relevance-ranking) rather than selecting truth by ranking. Enumerate relevant permitted alternatives by group key; missing group coverage remains explicit. [Procedure applicability](COGNITION.md#61-three-valued-matching) is applicable, inapplicable or unknown, not a similarity threshold disguised as certainty.

### 4.2 Channels and token economy

| Channel | Eligibility |
|---|---|
| Main context | Authorized, eligible availability, permitted `use`, applicable live requirements; support shown |
| Warning | Authorized `warn` or an applicable rule; no silent truth/authority promotion |
| Expansion handle | Permitted metadata for omitted detail; access rechecked when opened |
| Operator review | Explicit separate request for quarantined/archived material |

Reserve room for the current goal, criteria, material constraints and exceptions. If they do not fit, return a visible incomplete decision packet with handles rather than silently dropping them. Do not pad every response with all architectural sections.

Track delivery per `(binding/context incarnation, memory revision, trigger purpose)`, not forever per memory ID. Re-deliver a changed or critically applicable item when necessary. Observe re-opened handles and repeated reconstruction work: a tiny initial packet that forces repeated full reads may cost more overall.

### 4.3 Embeddings and indexes

The embedding profile is independent of the text-generation/Dreamer model. It includes producer/model revision, dimension, document/query input modes or prefixes, preprocessing and normalization where required. Each vector also binds to exact content revision. Changing the Dreamer model alone does not require rebuilding all embeddings.

Never mix spaces merely because dimensions match. An actual embedding-profile change builds a separate derived index while compatible old queries can continue; switch only after declared coverage is sufficient. Old pending work cannot write into the new profile. A local/cached query vector is usable only under the exact compatible profile and current disclosure rules.

Validate batched results before storage: every requested item is accounted for once, IDs/order are unambiguous, values are finite, dimension/profile match and content revision is still valid. A partial batch is explicitly partial; do not zip a shorter array onto inputs, substitute zero vectors or mark the whole batch complete. Retry only missing eligible work.

A remote query embedding is a model call with cost and latency. The normal context deadline need not wait for it; offer a bounded enhanced request or state lexical-only degradation. Exact vector scan is acceptable for a small authorized corpus. HNSW and rank fusion are query choices, not permission/freshness checks. Index plans and version-specific prefilter behavior require later measurement on the selected server.

## 5. One background-work queue

### 5.1 Intent, claim and external execution are different

A memory job stores its purpose, exact inputs/profile, deduplication key, policy/budget, due/deadline, current state and claim, optional external execution reference and final application result. Fields without a consumer are not added.

| Identity | Lifetime | Must not be confused with |
|---|---|---|
| `job_id` / input-profile key | One memory-processing intention | Every wake or transport retry |
| Claim token | One local worker's current right to publish | Provider request identity |
| External request/execution reference | One dispatched inference or embedding batch | A new local worker after restart |
| Memory operation identity | One conditional application of a result | Proof of one provider charge |

The queue has pending, running, waiting, completed, failed and cancelled states with reasons. Views may show timeout/stale-input without adding another scheduler. Missing text generation does not stall an unrelated embedding or deterministic job.

### 5.2 Claim and application

```text
short transaction:
  choose eligible pending work, or reclaim an expired local claim
  enforce input/profile, deadline, capacity and retry policy
  conditionally change the same job row to running with a new claim token
commit

inspect retained external execution before doing any paid work
perform bounded computation outside the transaction

short transaction under the relevant memory write boundary:
  revalidate policy, required live anchors and target revisions
  require the current running job, matching unexpired claim and deadline
  apply admissible output and mark this job complete together
  zero matched rows or a transaction conflict means no publication
commit
```

Heartbeat extends only the current unexpired claim within the deadline. An expired worker cannot publish even before another worker reclaims. Cancellation and completion contend on the same job row. Record a rejected late application outside the rolled-back result transaction; do not lose the explanation with the rejected write.

Use database time for lease predicates. A timeout on waiting does not establish that an external execution stopped. Pure local work can be recomputed; external work follows §5.3. Batches are finite: new observations create or update the next pending batch, not continually reset an already running batch.

### 5.3 Recovery without duplicate paid requests

Persist a stable external request identity and immutable request fingerprint **before dispatch**. If the transport loses acknowledgement, retain an unknown outcome and query the same controller identity. A reclaimed local job first loads that reference; it does not generate a new provider request merely because its claim token changed.

Only the controller owns provider-attempt selection/retries. Eliot may poll or request cancellation of that execution; it must not independently race another provider retry. When no durable readback or idempotent submission is available, the route declares that limitation. A bounded explicitly allowed new inference may cost again and is recorded as a new external execution, not an invisible replay. Uncertain potentially effectful harness work is not blindly repeated.

Result application is idempotent even when external execution was not exactly once. Account for known late usage or uncertainty independently of whether the content may still be applied. Cancelled or stale work cannot replenish its budget by pretending its unreported cost was zero.

### 5.4 Enqueue and wakeup

Initial choice: insert required jobs in the same transaction as the corresponding memory change. Poll durable due rows with bounded concurrency; a notification only accelerates wakeup. There is no need for both an event-driven scheduler and a competing changefeed scheduler.

A synchronous database event that inserts a row is an alternative enqueue mechanism, not a complete job engine. Changefeeds are retained change logs, not an infinite durable queue. Imports require explicit reconciliation of derived jobs/indexes; do not depend on import replaying table events. [Events](https://surrealdb.com/docs/reference/query-language/statements/define/event), [export/import behavior](https://surrealdb.com/docs/reference/cli/db/commands/export).

Fairness is simple: reserve bounded service for foreground capture/control, limit each expensive class, and avoid a backlog of re-embedding starving outcome capture. Do not introduce a second capacity ledger mirroring the job table.

## 6. Dreamer interface through the controller

### 6.1 Actual source boundary

At controller `96a0d5a6632cfbd541e804d7969d3e76e716bf6a`, [the integration document](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/96a0d5a6632cfbd541e804d7969d3e76e716bf6a/docs/eliot-memory-os-integration.md) describes a requested **controller-to-Eliot context packet**, marked not implemented. It is not a specification of an Eliot-to-controller generation or embedding API. A generic Operation lifecycle also does not establish semantic inference completion.

The examined paths do not establish a qualified Memory OS inference bridge. This is a bounded finding, not a claim that every controller file has been searched and no usable primitive exists. Reuse its ordinary execution infrastructure where it fits; do not rename Goal acceptance into a model result or duplicate its scheduler.

### 6.2 Small proposed execution contract

Expose two independently advertised capabilities through the controller: text/structured generation and embeddings. Exact public method names and the first implemented route remain O2; this proposal does not order source changes in the controller repository.

| Request | Required meaning |
|---|---|
| Stable request ID and fingerprint | Same request can be reconciled after lost acknowledgement |
| Memory job reference and optional external task reference | Maintenance does not require a fake coding task |
| Purpose/output contract | Extraction, synthesis, procedure or embedding; schema/profile revision |
| Authorized excerpts/item IDs and relevant revisions | Bound what the executor actually receives |
| Route constraints, disclosure purpose, deadline and limits | No hidden provider/region/cost expansion |

A terminal result includes the matching identity, output or explicit partial/failure state, requested and observed model/profile where available, usage or unknown usage, execution-attempt information and a durable readback limit. A controller transport acknowledgement, a native accepted input, an execution result and a task acceptance remain different facts.

A real synthesis task may use the controller's Task/Attempt machinery if required by that harness. What is forbidden is inventing coding goals or redundant task truth solely to satisfy a transport schema. Prefer the smallest existing execution path compatible with the actual effect.

For text-only maintenance, the executor gets no unnecessary workspace mutation tools. If a harness cannot disable such tools, it must not be presented as equivalent to a pure inference endpoint; select an appropriate constrained route or expose the limitation. Credentials remain with the controller; memory content and a `budget` field do not constrain an independently privileged remote executor by themselves.

### 6.3 Validation and model independence

Dreamer may propose create, revise, relation, procedure and influence changes. The application validates schema/size, candidate-set membership, scope and target revision, actual source lineage, permitted operation and current job claim. New IDs are assigned by the application. Subject resolution is a proposal requiring applicable evidence, not a prompt prohibition that prevents classification or an unchecked foreign-target write.

Physical source erasure, goal/permission changes and changing acceptance criteria are not ordinary Dreamer operations. Interdependent proposals are applied atomically; independent valid proposals may survive a partial batch when that is explicitly represented. An empty valid result means no proposal. Invalid JSON, unavailable provider, withdrawn source and exhausted deadline remain different outcomes.

Every supported model uses this same memory boundary. Prompts and output adapters may differ. Compare extraction/reconciliation quality per model, rather than assuming that an OpenAI-compatible endpoint recreates Hunyuan's learned weights.

### 6.4 Cost and capability qualification

Reserve a conservative permitted budget before dispatch and reconcile known usage later; uncertainty consumes the reservation until resolved under policy. Record model fallback only within existing disclosure and cost constraints. Strict ceilings require control of the actual executor/key or provider configuration, not just an advisory number in JSON.

Qualification is capability-specific: an observed text route need not wait for an unrelated embedding route; deterministic work need not wait for either. Before claiming a route works, observe a real request, output/error handling, identity/readback, declared cancellation behavior and usage/uncertainty. No such live qualification occurred in this documentation pass.

## 7. Learning that reaches the next attempt

### 7.1 One data model, not a learning platform

A procedure is a memory revision with trigger, local preconditions, a specific proposed behavior, historical evidence, exceptions, expected observation and withdrawal condition. Its application/evaluation links live with ordinary attempts. Aggregate counters are projections of those links, not a second authoritative LearningState database.

An attempt names the external task when present, exact procedure/context revisions, the observed action, result criterion/profile and unresolved signals. No hidden model reasoning is needed. A final task reward is not automatically attributed to every record in the packet.

### 7.2 Concrete first automatic loop

1. Capture an API compatibility failure and its exact source/consumer anchors, or a successful nontrivial method with evidence.
2. Produce a local procedure, for example: inspect the definition and one affected consumer before the next comparable API edit. Retain its historical failure/success evidence and applicability conditions.
3. If the proposal is a low-risk advisory within established policy, make it eligible automatically. It does not wait for a manual approval of every record.
4. At the next planning boundary, `context` selects that procedure revision. The adapter records delivery timing, not an invented claim that the agent followed it.
5. Link available action/result observations from the next attempt. An unsupported host outcome channel remains unknown.
6. Narrow, retain or withdraw the advisory based on actual new evidence; keep the original attempt and counterexample. A successful historical lesson may remain useful after unrelated code changes.

A procedure cannot execute a retrieved command by itself, disable a verifier, change permission or force the model to follow it. A feedback-only host can support provisional learning, but does not establish observed behavioral benefit.

For the first API-change loop, [Cognition §6](COGNITION.md#6-applicability-before-automatic-learning) defines the applicability check and a proposed criterion: recurrence of the identified compatibility failure under the relevant API/consumer and verifier profile. An unrelated failure is not automatically evidence against every delivered procedure.

### 7.3 Evidence accounting

Use one current contribution for `(procedure_revision, attempt_id, criterion/evaluator_revision)`. Redelivered feedback is idempotent. Amending a result replaces that contribution with an explicit revision; it does not increment permanent success again. Several traces from one attempt, repeated exports and copies of the same evidence are not independent trials.

Keep these observations separate: offered; delivered at a relevant boundary; action observed; adherence consistent with the procedure; result; comparative benefit. Adherence is not proof of causality. Model self-report and cue overlap are evidence of a different, weaker kind. Missing feedback is neither a success nor a failed action.

Induction examples can explain why a procedure was proposed. They cannot prove that the already-existing procedure caused their past successes. Do not put them into a causal “with procedure” cohort retroactively. Heuristic priors or similarity scores may rank provisional candidates; display them as heuristics, not measured improvement.

Infrastructure failures stay visible in the operational denominator and cost. For a quality comparison, report which cases were excluded and why; do not quietly discard valid task failures or convert timeouts into neutral successes.

### 7.4 Local use and wider transfer

| Transition | Rule |
|---|---|
| Proposed → local advisory | Grounded, narrow, reversible memory change within current policy; actual context consumer exists |
| Local → reusable in declared scope | Subsequent applicable cases and independent comparison against fixed criteria, including negative cases |
| Local/reusable → narrowed or disabled | Counterexample, adverse outcome, missing live applicability or no useful benefit under the declared criterion |

There is no universal “two successes means general truth” threshold. For the first route, retain a provisional local rule and collect distinct future attempts; broader claims require a predeclared comparison appropriate to that task family. Do not add a general statistics service to implement this. A small deterministic reducer over attempt records can compute counts, paired differences and uncertainty.

Compare no added memory, raw/exact-lexical memory and the candidate method on comparable tasks, profile and budgets. Hold out cases from induction/optimization. Where live A/B is permitted, change only the advisory being evaluated; never withhold explicit user requirements, necessary safety checks or known enforced constraints. Read-only shadow comparison can assess selection, not claim a changed real-world outcome.

A new model/tool/retrieval profile starts a new applicability evaluation; it does not copy an old confidence score. Procedures, retrieval recipes, compression strategies and predictors can all improve through the same bounded mechanism, without giving a candidate control of its own judge or global policy.

## 8. Project understanding, causality, and research

[Cognition §4](COGNITION.md#4-project-understanding-as-a-small-set-of-revisable-views) owns the construction and refresh algorithm: small purpose/map/area views, exact source structure, separately labelled inferred meaning, selection-membership tracking and finite target-keyed jobs. A new consumer can invalidate a complete-set claim without changing any old citation. Positive source references alone are insufficient.

Use the host's tools, ripgrep or one appropriate LSP/SCIP/structural adapter, not competing embedded code-graph stacks. Exact capture/readback starts before full semantic onboarding. A repository-wide HEAD movement prompts affected-scope reconciliation; it does not erase historical observations. One running finite build and one coalesced pending successor use the queue in §5, not a new cognitive scheduler.

Keep exact intermediate edits when the host exposes them. Final `git diff` does not recreate reverted or lost intermediate attempts. Reveal related events, source neighborhoods and diff history on demand instead of stuffing them into every prompt.

Static dependency, co-change, analogy and causal hypothesis are distinct link meanings. A prediction is recorded before the relevant action with expected effect, conditions and observable criterion. Results can be hit, miss, partial or unknown. Correlated files alone do not establish an intervention result.

A research job records question, examined scope, source revisions and read portions, findings, counterevidence and gaps. External Search/Research may supply acquisition; Eliot handles memory and interpretation. Exploration can change its question explicitly. Confirmation keeps criteria separate from the generator. No universal science-workflow engine is required.

Apply the same map to Eliot itself. A mismatch between contract and code becomes a grounded discrepancy and a proposed correction; the system cannot redefine the requirement silently to make itself successful.

## 9. Control, watchdog, and honest completion

### 9.1 Independent Windows supervision

**Proposed profile:** the launcher starts `eliot supervise` on demand. That small process owns the daemon process handle and a Job Object covering the daemon/database family. Assign the daemon before it can start unowned children; use non-inherited ownership handles and disallow unintended breakaway. Closing the sole controlling handle with the selected kill-on-close policy handles supervisor death. Never kill by executable name or reuse an unverified PID as ownership. [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The supervisor observes exit and an independent request/response health probe. A fresh challenge must be answered by the relevant live service path; a file mtime or isolated heartbeat thread is not proof that work can proceed. Health distinguishes serving, database-degraded and controlled maintenance. Maintenance has a deadline/progress signal and does not disable hang detection forever.

On a confirmed owned-process failure, stop the owned family and restart within configured intensity limits. Intentional idle shutdown does not restart. Repeated failure leaves a clear unavailable state and local diagnostic/notification rather than a storm. Native launch, nesting, custody and hang behavior require real Windows verification; this document does not claim it occurred.

This observer does not contain memory, job or provider state and does not outlive the active service by default. Its own failure is discovered by the next launcher and by the owned-family termination behavior; do not build an infinite chain of watchers.

### 9.2 Cognitive monitoring and operator surface

Compare available host events, workspace changes and reported task progress. A heartbeat is not progress; a file change is not task completion. Missing signals reduce the declared coverage. Try a bounded resynchronization, retain the gap, then notify when it needs attention.

The first operator surface is CLI status/inbox/control backed by the same functions; a later compact panel is a projection. A read-only database browser can inspect permitted data without becoming another writer. Display pending jobs, reasons, active profile, cost/unknown cost, source lineage and unresolved commitments, not dozens of proof states.

Notification delivery can use an ordinary job. Acknowledgement is receipt, not resolution. Deduplicate by the underlying problem and material changes, not each retry. A broken notification channel leaves the issue visible locally; do not pretend that an undelivered message reached the human.

Doctor may perform configured bounded mechanical repairs: restart an owned worker, retry eligible work, reconcile an index. It does not rewrite facts, delete user material or weaken policy to make a check pass.

### 9.3 Completion and safe control

`record_outcome` stores facts and claims; it does not accept a controller Task. A completion projection shows each declared criterion, relevant revision, available evidence and gaps. One verifier proves only what it checks. Passing local checks cannot erase a known failing product path.

A command found in a repository or memory is not automatically authorized for execution. A configured verifier is tied to its approved command and workspace policy. Missing verification remains unknown. Goal revision, cancellation, recipient acknowledgement and memory usefulness remain different facts without requiring separate services.

## 10. Deletion, backup, and restore

### 10.1 Restriction journal and erasure scope

Use a minimal current restriction journal outside rollback-prone backup images. It contains opaque source/delivery identities or explicitly defined scope selectors, sequence and operation identity, not deleted text or deterministic hashes of low-entropy secrets. It is operational retention state, not a second semantic database.

The short ingress/retention ordering boundary is shared with spool publication. Before acknowledging withdrawal, durably append the restriction, prevent future matching replay/disclosure, and invalidate current application eligibility. Replay and serving must reconcile the current journal before use after a crash. Primary deletion, derivative regeneration/removal, indexes, blob/cache cleanup and controlled backup retirement can then progress in bounded work. Expose `withdrawn; purge pending` separately from completed physical erasure.

Deleting a source applies through **all content lineage**, not just live dependency links. An independently supported claim may be regenerated from permitted evidence, but its old private synthesis is not made public by unlinking the source. External host/provider copies are a named boundary; cancellation is not erasure.

A finite ID-based restriction prevents resurrection of the identified material from controlled copies. It does not recognize the same sentence newly submitted under an unrelated identity. When source identity cannot support safe replay, disable that source's retained replay pending a fresh authorized import rather than claim magical content recognition.

### 10.2 Conservative backup with an explicit cutoff

Choose a quiesced logical export first. Do not promise a short snapshot lock before establishing an actual snapshot API for every component.

1. Enter maintenance by pausing new primary mutations and external dispatch. Let already-running short transactions settle **without holding the mutex they need**. Status and backup cancellation remain responsive.
2. Briefly take the ingress boundary, seal the current spool directory and create a fresh active directory. Retain the sealed batch identity and the current restriction sequence as the backup cutoff. Capture accepted afterward belongs to the new active batch, outside this backup.
3. Keep primary mutations quiesced for the whole database export. Export the database, referenced immutable blobs, sealed staged input and the restriction prefix into a temporary backup directory. Including an already committed event also in the sealed spool is safe because restore deduplicates its identity; compulsory draining of the spool is unnecessary.
4. Verify the selected export completed, required components are present and durable, then publish a small completed-backup manifest containing cutoff, component identities/checksums and schema/application versions. A partial directory is not a restore point. Unpause ordinary work afterward.

Do not acknowledge a conflicting erase/cancel/configuration transition as applied during the quiesced export. Either cancel the backup and perform the requested transition, or return a clear busy/pending result without an applied acknowledgement. New ordinary observations may be durably staged subject to the same storage limits and current policy.

The backup guarantees recovery through its declared cutoff, not through the eventual wall-clock end of a long export. A copy of open database-engine files is not this procedure. The conservative pause can later be replaced only by a verified consistent snapshot contract. [Official backup boundary](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery).

### 10.3 Restore and old external jobs

Restore into a fresh directory with ordinary retrieval and external dispatch disabled. Import the database and blobs, replay the included staged inputs through current restrictions, reconcile application revisions and derived indexes/jobs, then perform required sanity checks before switching the active data root.

Apply the **current** restriction journal, not just the copy inside the backup. Keeping a journal outside a restore image prevents ordinary rollback, but does not prove freshness after the entire device and journal were lost or rolled back together. Without a trustworthy current restriction history, the restore remains quarantined; do not serve old memory as compliant. A separately preserved current journal or a deliberate fresh selective import is required. This is an explicit limit, not another checksum certificate.

Treat restored external executions as requiring reconciliation. A job pending in the backup may have executed after its cutoff. Pure derived work can be recomputed; a model/harness request must be read back through its retained identity before a new dispatch. Restoring a job table is not authorization to repeat old external effects.

Logical exports do not substitute for application-level immutable semantic revisions. Check statement/import failures and essential records rather than trusting only an exit code. Reconcile job/index requirements explicitly after bulk import; historical V2 statuses do not become current V3 truth. V1/V2 data import is a separate selected-data operation, not an obligation to support every old runtime format.

### 10.4 Schema upgrades

Keep a schema version and one supported application/server range. Structural upgrades pause dependent dispatch, use a completed pre-upgrade backup, and record a resumable or explicitly failed transition. An old binary must not open a newer schema by ignoring fields. Restore follows the same current restriction policy. No live generation/canary/compatibility plane is required for this restart-based path.

## 11. Work sequence

### Documentation now

The current revision integrates the contracts instead of appending another competing paragraph. Preserve the 34 requirements and 29 A15 scenarios in the audit. Resolve remaining concrete interface/version questions in §13 without treating every unqualified runtime observation as a new architecture subsystem.

### Implementation after documentation

Build a connected path: demand start → capture/read → context at a real host boundary → actual controller-backed model work → validated local procedure → next attempt/outcome. Include minimal independent health, control and truthful degraded states rather than postponing them behind a large framework.

Then complete remaining project understanding, wider procedure transfer, privacy/restore and additional host/source adapters. A partial slice is not the full product. Do not first reproduce Kernel/Host/ORS, every possible schema, 43 donor runtimes or hundreds of inventory-derived issues.

Owner's development order remains product code, minimum relevant checks/Clippy, tests after the product is built. The next section is a future behavioral acceptance map, not tests executed now or a new test-first gate.

## 12. End-to-end scenarios for the future product

| ID | Situation | Required observable result |
|---|---|---|
| S1 | Unknown note type; model absent; duplicate delivery | Preserve one observation and exact read without invented classification |
| S2 | Resume/compaction or non-Git project | Reconstruct the declared goal, alternatives, commitments and next step; show missing anchors |
| S3 | Familiar resource before an action | Advisory reaches a relevant model decision; a pending tool is constrained only by a real authorized gate |
| S4 | Contradiction, false synthesis or poisoning | Preserve history/dissent; withdraw actual affected influence and review remaining justification |
| S5 | Missed file-change event | Refresh current views; keep valid historical observations and unrelated lessons |
| S6 | Prediction before an edit | Compare the named effect under matching conditions; correlation is not causality |
| S7 | Similar error in different conditions | Exact rule obeys applicability; similarity warns; false positives can be narrowed |
| S8 | Procedure from success/failure | Next attempt is linked; delivery, action, outcome and comparative benefit are distinct |
| S9 | Wider transfer causes harm | Retain counterexample and narrow/withdraw transfer without rewriting old results |
| S10 | Different model, malformed result or foreign target | Reject invalid transformations; original memory and independent routes continue |
| S11 | Partial research or missing provider | Scope and gaps remain explicit; empty top-k is not universal absence |
| S12 | Database outage, lost reply or expired worker | Durable states remain distinct; same identities reconcile; old claim cannot publish |
| S13 | Service hangs | Independent observer detects the owned failure and applies bounded recovery |
| S14 | Forget, erase, restore old copy | Availability, influence and physical purge differ; current restrictions precede serving |
| S15 | Partial completion or missing verifier | Report criteria and unknowns; no whole-task PASS from one local check |
| S16 | Large audit and dissent | Preserve unique coverage, lineage, alternatives and a discriminating next observation |
| S17 | False enforcement warning | Challenge/narrow only the false trigger, retaining the true safety boundary |
| S18 | Optional failure, queue pressure, repeated repair | Keep eligible control/read/capture; expose refusal and stop ineffective retry storms |
| S19 | Workspace changes without reports; missed notification; unknown executable | Surface gaps; acknowledgement is not resolution; do not execute an untrusted probe |
| S20 | Host/model/tool profile changes | Recheck applicability and capabilities without erasing historical experience |
| S21 | Worker restarts after external acceptance | Read back the same external request; do not buy a second inference because its local claim changed |
| S22 | Feedback replay or outcome correction | One current contribution per attempt/criterion; no artificial increase in independent support |
| S23 | Embedding response is reordered, short or incompatible | Validate item identity/profile/dimension; no silent vector misassignment or zero-vector success |
| S24 | Backup interrupted; capture continues | Incomplete backup rejected; accepted post-cutoff input remains in the new spool segment |
| S25 | Old backup contains pending external job or stale restriction history | Reconcile execution; keep restore isolated when current restrictions cannot be established |
| S26 | Session replays previously injected advice | Fresh applicability is shown; no promise that a DB revoke erased an external transcript |

The [audit](AUDIT.md#12-all-29-original-scenarios) retains every original A15 case; S21–S26 are additional failure walkthroughs, not claims of executed tests. [Cognition §8](COGNITION.md#8-implementation-placement-and-future-walkthroughs) adds fourteen cognitive walkthroughs without introducing another test platform.

## 13. Open decisions for the next documentation stage

| ID | Concrete proposal now | Remaining decision/evidence |
|---|---|---|
| O1 | Native Claude Code hooks plus MCP first; advisory timing distinct from action enforcement | Pin installed version/event fields and demonstrate capture, continuation, denied-tool and outcome correlation |
| O2 | Two independently available generation/embedding capabilities through existing controller execution; maintenance task optional | Select exact existing/new methods and first route; agree durable readback/retention/cancel and constraints with controller owner |
| O3 | Bounded event-file spool, current restriction journal, quiesced export with finite cutoff | Select Windows persistence/rename APIs, concrete limits and current-journal recovery path; qualify failure handling |
| O4 | One private Store, one client, explicit statement/cardinality checks and restart upgrades | Resolve historical no-SDK restriction versus later SDK proposal; pin actual compatible versions and concrete schema/queries |
| O5 | Three-valued applicability, automatic narrow advisory and API-compatibility recurrence criterion; unique outcome contributions | Pin the actual API/consumer and evaluator profile, collect comparable cases and select an appropriate promotion threshold; no universal confidence formula |
| O6 | Same-binary demand-start supervisor, owned process family, independent probe, CLI inbox | Qualify Windows custody/hang/idle behavior and configured notification channel; scheduled wake remains opt-in |

These remaining checks do not reopen the entire architecture or require a separate daemon, registry, approval ceremony or issue factory for every row. Documentation acceptance and runtime qualification are different stages.
