# Eliot Memory OS V3 — Implementation

**Revision:** 0.1, 2026-10-18. **Status:** technical proposal; V3 code has not been written, and queries/runtime have not been verified. [Architecture](ARCHITECTURE.md) defines the properties to preserve; [Audit](AUDIT.md) records the rationale and limits of the evidence.

This document proposes a sufficiently concrete design for further documentation review. Method and field names are interface proposals, not claims about an existing API. Pseudocode specifies transactional conditions; it is not ready-to-run SurrealQL.

## 1. Initial delivery

Start with one Rust package containing a library and executable; this is an initial shape, not a permanent limit. The executable provides service and CLI modes. Its ordinary modules are `memory`, `context`, `learning`, `jobs`, `adapters`, and `control`; split crates only when there is a demonstrated need.

The primary database is a separate SurrealDB server, supervised as a child process of demand-started `eliotd`. A private `Store` module owns parameterized SurrealQL over the official WebSocket JSON-RPC interface as the initial implementation candidate; the Rust SDK remains an open alternative pending the documentation decision. Application-facing public types do not expose database-specific types. Do not add a generic query AST, universal operation catalogue, or separate store daemon. Keeping the bridge thin does not grant a model or host arbitrary SQL access. SurrealDB is the selected full-featured store, including vector search; vectors are part of the product, not an optional future tier.

The researched current stable SurrealDB line is 3.3, patch 3.3.4 dated 2026-10-13. This is a **candidate for a new V3 installation**, not Eliot's installed version or verified compatibility. Before implementation, pin actual server/client-interface versions and verify required operations; do not automatically carry over V2's 3.1/3.2 line. [Official releases](https://surrealdb.com/releases).

The first target profile is local Windows operation, matching the original project. It assumes local IPC authenticated against the OS user, a protected data directory, and separate connection settings. Networked multi-tenant deployment is not enabled by a switch without implementing authentication, isolation, and operations.

Model and embedding work goes through `eliot-swarm-controller`, the sole provider/model routing boundary. Eliot does not call provider APIs directly. The target contract allows cloud, local, and harness-mediated routes chosen by the user, including embedding routes; their current support must be checked individually. A concrete controller client/adapter is a required working capability, not a placeholder facade: a route is reported unavailable until an end-to-end request, response, usage/unknown-cost, error, and cancellation contract works. Heavy Python/model runtimes or tools with different trust levels remain outside the Eliot process. Eliot does not load arbitrary plugins with primary database rights.

`eliotd` starts on demand; a CLI/host entry point starts it before serving an operation. Use a normal OS single-instance mechanism per data directory, not a new authority-epoch framework. Before an intentional idle exit, persist unfinished work, drain active mutations and stop the database child cleanly. The observer distinguishes intentional idle shutdown from a crash.

Future scheduled jobs require a wake source while the daemon is stopped. The first Windows profile should register the next due wake with the OS; that timer only starts Eliot, while the database job remains the work owner. Without a supported wake source, report execution as deferred until the next host invocation and do not promise scheduled delivery. Startup, shutdown, timer and hang behavior are part of O6.

## 2. Minimal data and ownership

### 2.1 Record families

| Family | Content and meaning | Mutation owner |
|---|---|---|
| `observation` | Source event, origin, subject, scope, bytes/blob reference, receive time, source event ID/revision, use constraints | `memory.capture` |
| `memory` | Versioned conclusion, hypothesis, decision, procedure, negative experience, or project view; support, status, scope, influence | `memory.apply` |
| `link` | Typed relation among records/revisions: support, depends_on, contradicts, supersedes, occurrence_of, structural, co_change, causal_hypothesis | Same transactional memory path |
| `attempt` | Host task/attempt, delivered context, prediction, action, observed outcome, next adaptation | `memory.record_outcome`; external task lifecycle stays with host |
| `job` | Deferred work: input IDs/revisions, policy, executor, deadline, attempt, cancellation, result | `jobs` through `Store` |
| `operation` | Mutation idempotency, short result explanation, revisions, minimum trace for diagnosis/retry | Transaction for the corresponding operation |

These are logical families, not a requirement for exactly six tables. A notification can be a `job` of type `notify`; embedding preparation can be another job type. Procedures and concepts are usually `memory` variants rather than new services. Not every diagnostic line becomes a durable cognitive object.

Large source files and attachments may live as blobs with checksums and reference-based access. For two-phase persistence, materialize the blob durably first, then publish its reference in a transaction; clean up unused blobs later. A durable success must never reference bytes that have not been saved. Deletion and backup cover both storage locations.

### 2.2 Shared fields and their meaning

`id`, `revision`, `owner_id`, `scope`, `source_refs`, `created_at`, and `content` are shared fields where applicable. An ID grants no authority. Derive `owner_id` and permitted scope from the authenticated connection and workspace binding; never accept them from model text.

Scope contains only necessary dimensions: user/organization, project/workspace, and, when needed, branch, resource, and task. Project-wide memory does not inherit permission for neighboring projects. Branch history and the current checkout are distinct; transferring experience between them is a new application in the target scope.

For an event, record `observed_at` and receipt time. For a claim, `valid_from` and `valid_to` may be unknown; unknown is not replaced with INSERT time. Represent each boundary as one of `known(timestamp)`, `unknown`, or `unbounded`. A historical query that depends on an unknown boundary returns uncertainty, not a positive match. Queries may distinguish “when it applied” from “when it became known.” These fields and revisions suffice for v0.1; no universal temporal engine is proposed.

Support, availability, and influence are independent:

| Dimension | Proposed values | What it controls |
|---|---|---|
| `support` | observed, hypothesis, supported, conflicted, refuted, unknown | How a conclusion is grounded; a strong status requires a source and a testable property |
| `availability` | active, on_demand, archived | Whether it participates in ordinary search or is separately revealed |
| `influence` | use, warn, handle, none, quarantined | Which presentation channel is permitted and whether content may guide action |

`use` does not mean “true”: a hypothesis may be useful if presented as a hypothesis. `quarantined` content is excluded from ordinary content and hidden ranking features; operator review is a separate authorized request. `handle` permits only an authorized description and reference; that description must not reveal restricted content.

### 2.3 Support, revision, and dependency

A `depends_on` link means that this derived revision requires a specific source revision. `support` means evidence in favor of a claim and does not by itself assert logical sufficiency. Multiple support links are not automatically interpreted as AND or OR. Where sufficiency matters, make it explicit in the specific derivation type or a small list of justifications.

A source change immediately makes dependent revisions ineligible for ordinary influence, even if background graph traversal is incomplete. Before context delivery or opening a handle, check dependency validity transitively to current source revisions. If a bounded traversal cannot establish validity, fail closed: do not deliver the old projection as `use`; mark it stale/unavailable until rechecked. A background job completes invalidation and may rebuild projections. Batch limits bound one pass, not correctness. This does not require a full ATMS or enumerate every support combination.

If independent support remains, recompute or review the justification and derived text before publishing a new revision. Deleting an old support link does not make its old synthesis verified.

A derived record's effective read/use policy is no broader than the intersection of the policies and permitted purposes of its actual source revisions. Compute and persist that effective policy before sending derived content to a model, before saving/publishing a derivative, and again before `open` or context delivery. If policy intersection cannot be determined, do not disclose or publish into a broader scope. Removing a private link without regenerating the text does not make the text public.

The first profile has one application writer per data directory. Within `Store`, serialize eligibility-changing source/policy transitions with validation and publication of derivatives. Use a workspace write critical section around those transactions; a multi-writer deployment would additionally need a database conflict guard touched by both paths. Snapshot reads alone do not prevent a concurrent revocation of a different row. Direct external database mutation is outside this profile and requires reconciliation before normal service resumes.

Order outbound disclosure against those same transitions. Immediately before handing a context response or ModelJob payload to its transport, enter the workspace gate, check the current source/policy revisions, and admit that bounded handoff. A payload still in an Eliot-owned queue must pass this check when dispatched; an earlier check is not permission to send later. Revocation acknowledgement prevents subsequent handoff admissions. A handoff already admitted to the transport is in flight and may complete after acknowledgement; its cancellation is best-effort. Do not hold a database transaction while waiting for a network response. The gate covers validation and initiation of the bounded handoff, not the remote model's execution. Disclosure to the external controller is already a disclosure; Eliot cannot promise that a controller or provider will erase or stop using bytes it has received. The controller contract must separately state cancellation/retention behavior for its queued jobs.

Freshness refers to declared observed source revisions, not an impossible atomic snapshot of every external filesystem and provider. Before a dependent material action, the host rechecks critical live anchors where its contract requires that. Revocation stops subsequent disclosures at the controlled boundary; it cannot recall bytes already sent to a provider. A pure dependency cycle or an unresolved dependency makes the derived view unknown/stale, not implicitly valid.

## 3. Host interface and experience intake

### 3.1 Operations

| Operation | Minimum input | Result |
|---|---|---|
| `attach` | Authenticated connection, workspace, host capabilities | Binding, settings, visible capture/push/action-control limits |
| `capture` | Event with origin/event ID and raw data or source handle | Durable ID and committed / staged / unknown / rejected |
| `context` | Goal or task reference, situation/resource, permitted budget | Context packet, reveal handles, warnings, gaps, receipt |
| `open` | Authorized handle and, if needed, revision | Revalidated current reveal or stale / unavailable / denied |
| `record_outcome` | Task/attempt, action, prediction reference, artifacts, observation | Stored outcome, support level, next learning job |
| `dream` | Background-work goal or selected experience group | Job ID/status, then candidates/result |
| `control` | Pause, cancel, settings, correction/withdrawal, or deletion | Applied change or reason it is unavailable |

Transport endpoints may differ; MCP and CLI call the same application functions. An ordinary agent needs a compact handshake: attach/bootstrap to establish workspace and task binding; capture/observe; request/push context at relevant cues; report action/outcome; inspect status. It must not manually fill lease, receipt, classifier, or proof-profile registries. Host-bound metadata is populated automatically. A host that cannot emit cues, receive context, or report outcomes declares those capabilities unsupported; Eliot must not imply it observed or changed that work.

`attach` must not invent an unknown project ID. Recover an unambiguous binding from the authenticated workspace. If ambiguous, preserve an admissible observation in the narrow current-session scope and ask only for the necessary clarification. Binding to a task does not authorize rewriting its goal.

Bootstrap may use an authorized directory or source manifest without Git; record available anchors and unknown coverage rather than inventing a repository revision. If a setup adapter encounters an executable that the host has not authorized, it may read bounded static metadata such as path, size, digest, file format, and available signature/provenance information. It must not run that file, including a `--version` probe, load it as a library, or give it secrets. Metadata is evidence for an operator decision, not an automatic trust grant. The first supported setup adapter and its actual metadata API are part of O1.

### 3.2 Transactional capture

1. Validate connection, storage permission, size, and basic shape. Do not put prohibited secrets in raw logs or debug output.
2. Normalize origin IDs without collapsing distinct physical events. For redelivery use `(owner, source, event_id, source_revision)`; if a source has no ID, the host creates a stable delivery ID. Use content hashes for similarity/byte reconciliation, not universal event identity.
3. In one transaction, check operation ID and input digest; persist the observation, required jobs, and operation result. Same identity with different bytes is a conflict, not a silent overwrite.
4. Return `committed` only after confirmed commit. Classification and embeddings run later.

Explicit errors, user decisions, exact diff references, and tool results can be captured deterministically. A model adds semantic interpretation; it does not authorize the source record to exist.

### 3.3 Database outage and unknown commit

When offline intake is enabled, a small append-only spool stores only input envelopes and delivery identity. A write is acknowledged as `staged` after fsync or the selected OS's equivalent reliable persistence. It is not primary memory and does not enter ordinary context as confirmed knowledge. Full spool or disk failure returns an explicit error.

After recovery, replay uses the same IDs. The same input creates neither a second observation nor a second paid job. Clear spool entries only after the primary transaction is confirmed. Document its format, disk limit, and access protection during implementation; V2's entire ORS is not required.

**Deletion, replay and backup ordering (required):** A durable deletion tombstone covers the observation ID, its derived records and queued or staged intake identities. Under one local intake/erase ordering gate, erase first prevents new admission of matching identities, durably records the tombstone, then deletes primary records, edges, embeddings and pending jobs. Spool replay checks the tombstone before any insertion and again at the primary transaction boundary; a concurrent replay must not commit after deletion. Do not acknowledge deletion while any earlier staged envelope can reappear. Keep the minimal tombstone information outside an older restore image (or reapply a separately durable deletion journal), and reject restore if that journal is missing or inconsistent. Never restore directly over the live database.

A backup first pauses intake/replay at the same ordering gate, drains and reconciles all acknowledged staged envelopes, and only then snapshots the database and deletion journal at a consistent boundary. If drain or durable reconciliation fails, backup fails explicitly; it must not silently omit acknowledged observations. Release the gate after the snapshot boundary, not after the whole export. An interrupted backup is not a valid restore point. These operations use one short coordinator and the existing store/spool, not another recovery service or second semantic database.

If the commit response is lost, query by the same operation ID. While the result is unknown, do not treat the write as either accepted or safely absent. The database path provides idempotent reconciliation; external effects depend on the external API's capabilities.

### 3.4 Continuation and host replacement

After compaction or a host/model change, rebuild context from durable goals as declared by their owner, decisions, active commitments, rival explanations, failed attempts, and explicitly abandoned plans. An obsolete summary must not reactivate a cancelled goal or rejected plan. Recheck the new host binding, authority, available cues/actions, context limits, and procedure/profile applicability. Do not copy a previous model's confidence or capability declaration to the new model. A context budget overrun causes selective reveal, task decomposition by the external task owner, or an allowed route change; it is not permission to drop a material exception silently. O1 must show this against a real host continuation path.

## 4. Retrieval and context assembly

### 4.1 Query path

1. Derive permitted scope from binding and query; load active constraints and exact negative rules.
2. Retrieve candidates by exact references/resources, BM25, and vector retrieval. Vector search is a supported product path, not a later optional tier; a temporary route/index failure may fall back to BM25/exact and must be visible.
3. Merge ranked lists, remove duplicate representations, and preserve distinct physical events and conflicting evidence.
4. Expand links and neighboring source chunks within bounds, preserving scope and permissions at every hop.
5. Immediately before composing the response, check influence, transitive dependencies, freshness, and effective privacy policy; assemble whole useful items within budget.
6. Write a short receipt: recipe revision, used IDs/revisions, warnings, material exclusions, incomplete coverage, and cost. A full list of intermediate candidates may be a temporary diagnostic trace, not a required permanent record.

BM25 source paths already exist in V2; V3 can reuse that experience. Establish an executed lexical baseline before claiming an improvement over it; this documentation audit did not run the V2 retrieval path. [V2 SQL](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/load_memory_search_fts_candidates.surql).

### 4.2 Explicit admission channels

| Response channel | Condition |
|---|---|
| Main context | Authorized read, active/on_demand when requested, `influence=use`, current dependencies; support is shown |
| Warnings | Authorized record with `influence=warn` or an applicable negative rule |
| Reveal references | Authorized metadata only for `influence=handle` or eligible omitted material |
| Operator review | Separate authorized request for quarantined/archived material; its content is not mixed into agent context |

The filter `influence != none` is insufficient. Apply scope in the candidate query before top-k, then check it again before reveal. If the chosen ANN plan cannot enforce the required candidate restriction, use exact vector search inside the authorized set or another demonstrably bounded route. A broad search followed by late filtering is not equivalent.

### 4.3 Embeddings and indexes

Bind every embedding to `(model/profile, dimension, preprocessing_revision, content_revision)`. Never mix incompatible spaces even if dimensions match. A model change creates a new generation of the derived index; populate it in the background while the previous profile serves compatible queries until cutover. If no compatible query embedding is available, retain BM25/exact retrieval and report the degraded route.

Remote query embedding is a network model call with latency and cost, even though it does not generate text. The default context path need not wait for it: use a local/cached option, a separate bounded enhanced request, or disclose degraded quality. HyDE and generative reranking are costly enhancement paths.

For a small authorized corpus, exact vector scan may suffice. Add HNSW only when measurements justify it. RRF combines rankings but does not replace freshness, support, or negative-experience checks. Tune top-k, `ef`, weights, and token budgets by profile rather than treating them as universal laws.

SurrealDB 3.3 documents prefiltering for indexed conditions and the need to create/rebuild corresponding indexes on that version. Before 3.3.1, duplicate-vector handling had defects; fixing new inserts does not repair an already damaged index. Background compaction does not make written content invisible: documentation says unmerged updates remain readable, possibly at higher cost. For V3 these are query-plan/version questions, not proven performance. [Migration 3.2→3.3](https://surrealdb.com/docs/build/migrating/from-old-surrealdb-versions/32-to-33), [DEFINE INDEX](https://surrealdb.com/docs/reference/query-language/statements/define/indexes), [INFO](https://surrealdb.com/docs/reference/query-language/statements/info).

## 5. One background-work queue

### 5.1 Minimum job semantics

A job has `job_id`, unique `job_key`, type, input IDs/revisions, scope, rule revision, available model route, budget, `not_before`, deadline, state, attempt number, current `claim_token`, lease expiry, and result reference. The schema may combine fields; every retained field must have a consumer.

Working states: pending → running → completed; on error, bounded retry or failed; separately cancelled and waiting_for_dependency. Stale input causes input regeneration or a terminal reason, not blind retry. System failures and unusable model responses are distinct.

### 5.2 Claim and completion

```text
transaction:
  select a pending job whose not_before has arrived, or a running job with expired lease
  require remaining deadline, retry budget, and available required dependencies
  transition an overdue job to terminal timeout instead of starting paid work
  conditionally update the same revision and state:
    running, new claim_token, attempt + 1, lease_until
  if the conditional update fails: no claim
commit

perform bounded work outside the transaction

transaction:
  verify required input revisions and current access scope
  conditionally update the same job row to completed only if:
    job_id, running state, and current claim_token match; not cancelled
    database time at this transition is before lease_until and deadline
  if no row matches: abort the result transaction
  apply the admissible result in this same transaction
commit
```

A claim transaction conflict means retry selection, not two owners. Heartbeat extends only its own unexpired claim within the deadline. Completion and cancellation/reclaim contend on the same job row; a transaction conflict rolls back the entire result and requires revalidation. An expired lease fails the final conditional transition even if nobody has reclaimed it. A timeout/cancellation transition also invalidates the claim token. An old worker may finish computation but cannot publish its result; preserve the rejection reason separately from the aborted result transaction. Use database time for these predicates and short transactions, not a worker's local clock as commit authority. Cancellation of a wait does not prove that an external action physically stopped.

`job_key` binds the processing goal to input revision/profile; repeated wakeups do not create paid duplicates. A batch of observations may produce one consolidation job rather than one LLM call per row. A new observation must not continually reset a bounded batch already in progress.

### 5.3 Events, changefeeds, and outbox

The initial option is an explicit job INSERT in the same application transaction as the memory change. A periodic worker selects durable rows; a notification/event may accelerate wakeup, but losing it does not lose work.

A synchronous `DEFINE EVENT` that only adds an outbox row can also provide atomic enqueue. It is a valid alternative, not a free job engine. Async events provide atomic enqueue but permit duplicate delivery. A changefeed is a change log within its retention window; LIVE SELECT alone does not provide catch-up. Cancellation, deduplication, late results, policy, and operation outcome remain Eliot contracts. [Events](https://surrealdb.com/docs/reference/query-language/statements/define/event), [Changefeeds](https://surrealdb.com/docs/learn/querying/real-time/changefeeds).

SurrealDB does not run table events during bulk import. After import/restore, reconcile required jobs and indexes. This reconciliation concerns derived data and does not require a second scheduler.

## 6. Dreamer interface through the controller

### 6.1 Request and response contract

| `ModelJob` input | Purpose |
|---|---|
| Job/attempt ID, deadline, limits | Correlate cost, retry, and result |
| Purpose and output-schema revision | Distinguish consolidation, conflict, procedure, project synthesis, and research |
| Authorized source IDs/revisions and excerpts | Prevent citation of an unread source |
| Scope, permitted-disclosure policy, selected route | Check before transmission and before save |
| Job context and known candidates | Perform the work without inventing external control material |

Eliot submits the immutable, bounded `ModelJob` envelope to `eliot-swarm-controller`; it includes job/attempt identity, deadline, purpose/schema revision, source manifest and excerpts, scope/disclosure policy, selected route, output limits, and budget ceiling. The controller operation must accept a request ID for idempotent submission, expose a durable job/result handle, and return a terminal status (`completed`, `partial`, `unavailable`, `timeout`, `cancelled`, or `failed`) with structured output when present, source references, requested/actual model and endpoint class, usage when supplied, number of network attempts, and typed error. Cancellation is best-effort and distinct from terminal completion. Missing usage remains unknown and is charged conservatively against the reserved budget. A declared provider name does not prove the actual model; opaque gateways are marked as such. This request/response/result contract must be implemented end to end against the controller before claiming the route works.

The first working route must be an end-to-end controller route, not a direct provider API in Eliot and not a stub/facade. The same boundary is intended to support cloud, local, and harness-mediated models and embedding routes as their adapters implement the contract. Switching models does not change the primary-memory format. Until the actual controller integration is implemented and verified, report the route as unavailable; capture and recall continue. Do not claim that an existing controller surface already provides a generic memory-job/model-result API.

At controller commit `513f9698c268753dc6f2a6c0cf4d9a53f7f5e472`, the integration document explicitly says runtime integration is not implemented. Its task-scoped Goal does not start a model. The proposed `ModelJob` and embedding contract is therefore new boundary work, not a renamed Goal call. [Controller integration](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/513f9698c268753dc6f2a6c0cf4d9a53f7f5e472/docs/eliot-memory-os-integration.md), [Goal contract](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/513f9698c268753dc6f2a6c0cf4d9a53f7f5e472/crates/swarm-kernel-host/src/goals/mod.rs#L1-L78).

Local and remote routes differ in privacy. Eliot filters the payload before sending it and checks effective source-policy intersection and purpose. An untrusted remote executor with its own credentials cannot be technically constrained by a `budget` field. The guarantee is limited to Eliot-controlled submission, agreed external limits, and visible unknowns. Strict ceilings require a controlled transport/key/process or provider-side configuration.

### 6.2 Applying results

The model proposes `create`, `revise`, `link`, `propose_procedure`, or `propose_influence_change`. Physical deletion of source data and changes to authority are not model operations.

Before commit, the application checks:

- the output parses under the current schema and stays within limits;
- every referenced ID belongs to the authorized input/candidate set or is a new server-assigned ID;
- owner/workspace and current target revision match;
- used sources remain available, unrevoked, and at suitable revisions;
- the operation is allowed for this type, does not raise support without evidence, and does not broaden effective disclosure or purpose;
- the job claim remains valid.

Prompt-level ID checking is not execution validation. Protection is required in both the result validator and conditional UPDATE/DELETE at the storage boundary. Failure of one candidate may leave independent candidates usable; interdependent candidates are applied atomically or rejected as a group.

An empty valid result means “no proposal.” Invalid JSON, timeout, and withdrawn source are not equivalent to that result. After bounded retries, source observations remain available; never retry forever without changed conditions.

### 6.3 Budget and isolation

Before a request, reserve an upper estimate of permitted cost/tokens. After the response, record actual data and uncertainty. On timeout, do not zero unknown cost and thereby let retries bypass the limit. If a provider lacks an idempotent request ID, record that retrying may cost again even when Eliot's result commit is idempotent.

The controller's owning route obtains provider credentials from the selected OS secret store or other explicitly configured protected source; Eliot holds only its controller connection credential where needed. Do not store provider credentials in memory, prompts, or receipts. Logs retain safe route identifiers and costs. Model changes or fallback are allowed only within the user's existing policy.

## 7. Learning that reaches the next attempt

### 7.1 What is retained

A learning candidate is an ordinary memory revision with trigger/scope, a specific proposed change, source attempt references, rationale, constraints/counterexamples, expiry/rollback condition, application status, and evaluation. It may describe a context recipe, search order, procedure, or recommendation to an external harness.

A linked attempt records what was expected, what happened, the context/procedure revision available, observed action, unknowns, and the next step to change. Model access and hidden chain-of-thought are unnecessary.

### 7.2 Lifecycle

| Transition | Basis and effect |
|---|---|
| observation/outcome → proposed | A deterministic error or Dreamer proposes a specific grounded adaptation |
| proposed → local | Automatically apply only an advisory context hint/procedure within existing policy and scope; no new authority or verifier weakening |
| local → reusable | Compare with baseline, independently evaluate on applicable data, and observe later use; explicitly bound transfer scope |
| local/reusable → narrowed/disabled | Harm, counterexample, stale support, incorrect trigger, or no benefit; create a new revision and reason |

Automatic narrowing of a candidate's scope is data-only; it cannot silently change permissions. Broad reuse is automatic only when declared independent acceptance criteria are met—there is no per-candidate human approval gate. Reversible here means the memory revision can be withdrawn; it does not imply an already-taken host action can be undone.

Bind an evaluated improvement to the relevant model, host, retrieval recipe, source/tool profile, and evaluator revisions. A material stack change makes that evidence stale for the new profile; re-evaluate before claiming transferable benefit. A plausible but wrong merge/procedure must be withdrawable while original observations, dissent, and relevant evaluation history remain available. Local evaluator scores do not override a failed end-to-end outcome. Experimental changes run in an isolated comparison or an explicitly permitted reversible local scope before broader adoption; this does not require live code replacement.

A behavior change needs a consumer: context selects the applicable procedure/hint, host receives the specific permitted delta, then `record_outcome` links the next attempt. If the host cannot apply the delta, retain the candidate as `delivery_unsupported`; do not call it applied.

A deterministic procedure is data: preconditions, steps, scope, expected result, verification method, examples, and exceptions. It does not execute arbitrary code from memory. Automation may use only capabilities already authorized by the host.

### 7.3 What counts as evidence

Distinguish delivery, observed action change, adherence, outcome, and causal benefit. Without action observation, do not substitute cue overlap or “it helped” feedback. Retain feedback as useful but weaker evidence.

Compare a candidate on the same source tasks and constraints; evaluate results separately from the generator. Data available to Dreamer during optimization is not holdout. Do not silently change the evaluator with the candidate. Keep valid unsuccessful attempts in the denominator; report infrastructure failures separately rather than turning them into success.

Evaluate benefit by result correctness, repeated errors, preserved constraints, transfer, cost, and latency. Include positive and negative cases. One success supports a local hypothesis; statistical claims require sufficient comparable data. Select formulas and thresholds by task during implementation; do not use a universal “self-learning=PASS” score.

### 7.4 Concrete example

After a failed API change, retain the diff, documentation revision, and incompatibility error. Eliot links the failure to the exact contract and proposes a local procedure: before the next similar edit, open the definition and check one known consumer. Context delivers the advisory before the next change. The host reports observed action and outcome. If the rule is unnecessary for another API family, narrow its scope; if it prevents the error, retain it under the confirmed conditions.

This example needs an observation, procedure, context delivery, attempt, and next outcome. It does not need a separate LearningStateView daemon, HarnessOverlay store, or another scheduler. Without an observed next action, the learning loop is not closed.

## 8. Project understanding, causality, and research

On attach or source revision change, an adapter supplies file structure, manifests, symbols/references when available, and diffs. Build a small project map from these. Connect LSP/SCIP/tree-sitter or an external code graph only for a task requiring exact extraction; do not build the same relations under five competing owners.

Each project view records its source revision and the dependencies actually used. A watcher accelerates refresh; periodic reconciliation against current source head detects missed events. Unsupported languages or incomplete indexes are visible in coverage; no search result does not prove that a symbol or effect is absent.

Static dependency, co-change, and causal inference use different `link.kind` values. A model may propose a causal hypothesis and testable prediction. Confirmation by a particular experiment is bound to its conditions; it does not become a universal law of the system.

For coding traces, retain sequential changes, including failed and reverted ones when the host observes them. A final git diff cannot recover lost intermediate attempts. Reveal neighboring chunks and timelines on demand rather than duplicating them in every context packet.

A research job retains its question, scope boundary, versioned sources, portions actually read, findings, and links to supporting/counterevidence. `complete_for_scope`, `partial`, `inconclusive`, and `unavailable` remain distinct. For confirmatory work, fix criteria and scope before evaluation; exploratory work may change its question while retaining that change history.

A search API or donor pipeline may perform part of the work, but Eliot does not accept its result as verified truth. Do not build a universal science workflow engine or make V2's full research registry mandatory at this stage.

The same source-grounded map may describe Eliot itself. If observed code or behavior contradicts its declared contract, retain the discrepancy, bound claims of support, and propose a code repair or an explicit documentation correction for the responsible owner. Automatically rewriting the requirement to match a failing implementation is not learning.

## 9. Control, watchdog, and honest completion

The operator surface calls the same control/job/memory functions as the CLI. It shows current jobs, delays/reasons, model/cost, significant memory changes, source lineage, capture status, and limits of host observability. It supports pause/resume/cancel, route/profile changes, correction/withdrawal, and deletion requests. The initial surface may be CLI plus a compact panel; responsibilities do not depend on UI framework.

Notifications are durable jobs with event-based deduplication, importance, expiry, and delivery state. A missing delivery channel is visible and is not treated as successful delivery. Acknowledgement means receipt only; it does not resolve the underlying issue or task. Keep notification delivery, recipient acknowledgement, task completion, approval resolution, and outcome helpfulness as separate states. Do not flood the operator with every internal retry.

An independent observer uses a supported OS mechanism for process exit/restart and a separate responsiveness check. It must not depend on the queue or loop it observes. Internal metrics show task progress but do not prove availability after a hang. Define the health probe and notification route during the first supported profile; until then the full watchdog capability is incomplete.

Workspace progress and agent/task progress are different. Compare observed workspace events with agent-reported task progress, surface missed updates or unresolved attention, and attempt bounded resynchronization. When a signal is unavailable, reduce the claimed observability rather than inventing it. Report the exact workspace/project delta, active task state, evidence and unresolved blockers separately; activity counts or notification acknowledgements are not progress or resolution.

Diagnostic/Doctor first gathers state and proposes a bounded recovery action. Automatic restart is allowed under configured policy. Deletion, goal changes, and broad external effects are not harmless repairs.

On restart, establish the current policy, job claims, and operation outcomes before allowing dependent new dispatches. A database or host process surviving `eliotd` does not retain authority to commit an old result. If recovery repeatedly fails, stop repeating the same repair, record the unresolved hypothesis and budget, and escalate through the configured channel. Continue unaffected read/control paths only when their prerequisites are valid.

`record_outcome` does not close a host task by itself. The completion view compares declared criteria with applicable results at the required revision and identifies missing/unknown items. Running one verifier helps only for the property it checks. The external host confirms its own completion; Eliot records that claim separately from its independent support level.

## 10. Deletion, backup, and restore

Deletion first stops permitted influence, then covers selected source bytes, derived revisions, embeddings, blobs, and caches. If physical deletion cannot happen immediately, show its actual state. Access revocation takes effect immediately on reads, independently of background cleanup.

A backup contains consistent data and revisions; indexes can be rebuilt. A deletion/revocation journal used on restore cannot roll back with the same old snapshot: retain a current sequence separately or use another mechanism that prevents restored memory from being published before reconciliation. This is open technical decision O3 for the chosen delivery, not a completed guarantee.

Restore first runs outside active retrieval, applies current restrictions and deletions, reconciles jobs and input revisions, then switches service. State backup cleanup, retention periods, and the scope of external provider copies separately. A hash of a low-entropy secret in a tombstone may leak it; deletion identifiers must not reproducibly reveal deleted content.

V1/V2 import is a separate future operation over selected data. Historical verified status is not current truth. V3 need not support every old record type or live V2 runtime migration. No user data is imported or deleted at this documentation stage.

For V3's own upgrades, keep an explicit schema version and supported application/database version range. Start serving only after checking compatibility. A migration requiring structural data changes runs with ordinary dispatch paused, a consistent pre-upgrade backup, and an explicit completion marker; an interrupted upgrade remains unavailable for dependent work until resumed or restored under the same current deletion policy. Never open a newer schema with an older binary by silently ignoring fields. Choose the concrete migration steps and backup/rollback procedure in O4; this minimum restart-based upgrade path does not recreate V2's live release-generation system.

## 11. Work sequence

### Documentation now

1. Consolidated audit, source-requirement matrix, Architecture, and concrete workflows are this revision.
2. Resolve open contracts O1–O6; walk through input, response, failure, and recovery examples on paper; refine disputed mechanisms.
3. Stabilize the agreed documentation revision and first deliverable boundary. This draft does not automatically start implementation.

### Implementation after documentation

Build a vertical product first: attach/capture → durable read/context → real model job through the controller → apply bounded output → next attempt and outcome. Then add missing project understanding, procedure transfer, supervision, UI, privacy/restore, and specialized sources. Label partial stages honestly; functions retained in Architecture remain in V3 scope.

Do not first rewrite Kernel/Host/ORS/Instrument Plane, generate all types, or distribute hundreds of donor leaf issues. One implementation task should complete a useful path or fix a specific observed failure of that path.

Owner's development order: product code, minimum relevant checks/Clippy; tests after the product is built. Scenarios below describe future behavioral evaluation, not a current test-first gate. Claims of working reliability, privacy, or learning still require corresponding evidence before presenting the product as complete.

## 12. End-to-end scenarios for the future product

| ID | Situation | Observable result |
|---|---|---|
| S1 | Unknown note format, model disabled, duplicate delivery | Observation stored once with provenance; exact read available; no invented classification |
| S2 | Agent resumes after session loss/compaction, including a project without Git | Declared goal, rival explanations, decisions, open commitments, and next step recovered from available anchors; abandoned plans stay inactive; gaps are visible |
| S3 | A familiar resource appears before an action | Relevant rule/experience arrives in time; irrelevant and restricted material has no influence |
| S4 | A new source contradicts an old conclusion, a plausible synthesis proves wrong, or poisoning is discovered | Conflict and original observations remain; affected influence stops transitively; remaining independent support and derived text are reconsidered before reuse |
| S5 | A file changes and watcher misses the event | Reconciliation marks project view stale; exact read remains available; refresh touches required dependencies |
| S6 | A side-effect prediction is recorded before an edit | Afterwards hit/miss/partial/unknown is recorded against the observation; co-change is not causal proof |
| S7 | A known error recurs in a similar but different situation | Exact rule acts within its scope; similarity warns; new conditions permit review of a false restriction |
| S8 | Success/failure produces a procedure | Next comparable attempt changes; delivery/action/outcome remain distinct; no host feedback means no claimed benefit |
| S9 | A local procedure transfers to another project and causes harm | Counterexample and scope are considered; transfer is narrowed/reversed; prior evaluation history remains |
| S10 | Dreamer changes model and receives malformed output, foreign ID, old revision, or injected instructions in sources/tool metadata | Primary memory remains available; invalid operation is rejected; source instructions remain data without new authority; route, cost, and reason are visible |
| S11 | Research source is unavailable or only part of corpus was reviewed | Report bounds coverage and links claims to read portions; absence from top-k is not treated as absolute absence |
| S12 | Database stops after intake, commit response is lost, a lease expires, or a worker restarts | Committed/staged/unknown remain distinct; same operation IDs prevent duplicate writes; an expired/replaced claim cannot publish, even before reclaim; reconcile before dependent dispatch resumes |
| S13 | Service hangs and internal diagnostics do not respond | Independent observer detects it and performs authorized recovery/notification; unfinished work is not called successful |
| S14 | Forgetting, privacy deletion, and restoration of an old copy | Availability/withdrawal/deletion differ; current restrictions apply before restored data is served; uncontrolled copies are identified |
| S15 | User cancels or asks “done?” with partial results, an unavailable verifier, or local checks passing while the product fails | Clear control and honest criteria status; unknown stays unknown; the failed end-to-end result prevents a whole-task success claim |
| S16 | Large audit is only partly in scope and assessors disagree | Preserve scope, unique coverage, source lineage, partial findings, alternative explanations, and dissent; synthesis proposes a discriminating observation instead of averaging disagreement |
| S17 | A guard flags a harmless but similar case as unsafe | Preserve the known dangerous case, show the harmless case as a false-positive challenge, and narrow the trigger only if evidence supports it; do not weaken the true safety boundary |
| S18 | An optional capability fails, queues fill, or repeated repair fails | Unaffected capture/read/control continue where safe; refusal and bounded retries are visible; stop repeating failed repairs, reconsider the hypothesis, and escalate without a restart storm |
| S19 | Workspace changes without agent reporting, a notification is missed, or setup finds an untrusted executable | Show the observation gap and resynchronize; keep unresolved attention separate from acknowledgement; inspect executable metadata without executing it or granting secrets |
| S20 | A different host/model/tool stack takes over, or a learned method no longer fits the available context | Preserve durable goal/experience; recheck binding, capabilities, profile, and evaluation applicability; stale confidence does not transfer; reveal/decompose/change route within policy |

Memory quality comparison includes a no-consolidation baseline, exact/BM25, and the selected enhanced route under comparable budget. Metrics include outcome quality, repeated errors, missed constraints, useful-retrieval precision, latency, context size, cost, recovery, and false prohibitions. Measure results on V3; line counts are not a substitute.

## 13. Open decisions for the next documentation stage

| ID | Decision | Initial proposal and questions to resolve |
|---|---|---|
| O1 | First real host and its capabilities | Select one local adapter; document capture/push/outcome/identity/cancel against a real API. Other hosts get an honest degraded profile. |
| O2 | First Dreamer/controller route | Agree the real `eliot-swarm-controller` request/response contract for model and embedding jobs, including JSON/errors/usage/cancel and verifiable privacy/budget limits. Do not use a direct provider call or stub as the first working route. |
| O3 | Durable intake and restore protection | Specify fsync/spool limit and a current deletion history outside a rollback-prone snapshot; handle write failure and unavailable key. |
| O4 | Exact SurrealDB interface/schema | Pin compatible versions and decide the thin parameterized SurrealQL/WebSocket JSON-RPC implementation versus official SDK; specify conditional claim, transaction retries, scoped queries, revisions, and the restart-based schema upgrade/rollback procedure in §10. Add HNSW where needed by the full vector product and measurement. |
| O5 | Local automatic learning and transfer | Define allowed deltas, first trigger/consumer, negative cases, evaluator, and local → reusable criteria. Local automation is advisory only; broad reuse follows independent criteria, not per-candidate approval. |
| O6 | Independent observation and operator surface | Specify Windows service/health probe/notification route, hang detection separate from exit, recovery settings, and minimum UI. |

O1–O6 are bounded architecture questions. They do not authorize reintroducing all of V2 or require a separate subsystem for every row.
