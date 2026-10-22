# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft · 2026-10-22 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into processes, data, operations and integration paths. [Cognition](COGNITION.md) defines the algorithms used by those paths. The [audit conclusion](AUDIT.md) explains why the rejected V1/V2 machinery is not reproduced.

No schema, controller method or host adapter described here is claimed implemented until the product code exists.

## 1. Runtime and first use

### 1.1 Process family

The initial Windows profile uses one executable with modes:

```text
eliot supervisor     persistent owner of the local process family
eliot daemon         memory service
eliot relay ...      transient host/CLI relay
```

The supervisor owns:

- `eliot daemon`;
- one SurrealDB server child;
- their Windows Job Object;
- restart intensity and planned shutdown.

The daemon does not supervise itself. Hosts and controller do not also own this process family in the initial profile.

### 1.2 Data directory and configuration

Use the platform local application-data directory, for example:

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  db\
  blobs\
  spool\
  backups\
  logs\
```

`config.toml` contains only practical local settings:

- data directory;
- selected projects/workspaces;
- capture exclusions and retention;
- controller endpoint/routes;
- embedding profile;
- idle timeout;
- optional host adapters;
- optional external research and source tools;
- several concurrently selected projects and any explicitly allowed cross-project reuse scopes.

It is not a policy database or a generated registry.

### 1.3 Demand start

A relay or host adapter:

1. connects to the local endpoint;
2. if absent, acquires the launch mutex and starts `eliot supervisor`;
3. waits for daemon readiness;
4. performs the requested operation.

The supervisor starts SurrealDB, waits for its concrete readiness, then starts the daemon. Planned idle shutdown stops new external dispatch, settles short mutations, leaves pending work in the database, stops daemon and database, and exits.

Primary capture and exact/lexical reads become available as soon as Store is ready. They do not wait for embeddings, Dreamer, project orientation or a graph.

## 2. Code structure

Start with one Rust package and ordinary modules:

| Module | Owns |
|---|---|
| `store` | SurrealDB schema, queries, transactions and readback |
| `memory` | observations, semantic revisions, sources and correction |
| `context` | current-work recovery, retrieval, applicability and rendering |
| `learning` | procedures, improvement lessons and outcome reduction |
| `jobs` | finite background work and claims |
| `adapters` | host, controller, source and research boundaries |
| `control` | configuration, status, maintenance, backup and restore |

Pure transformations remain functions. A module does not automatically get a trait, service, registry or crate.

The external boundaries are:

- SurrealDB;
- host events/MCP;
- controller text execution and embeddings;
- optional source tools;
- optional Eliot Research.

## 3. Application surface

All host surfaces call the same application functions.

| Operation | Result |
|---|---|
| `attach(workspace, session)` | bound project/session and actual capabilities |
| `capture(event)` | committed, staged, unknown or rejected |
| `context(decision_frame, budget)` | useful packet plus expansion handles and gaps |
| `open(handle)` | exact current/historical item or source segment |
| `record_outcome(report)` | captured observed result or explicitly sourced report |
| `dream(request)` | finite interpretation/research/improvement job |
| `control(command)` | status, configure, pause/cancel, correct, erase, backup or restore |

`record_outcome` reuses capture. It does not create an execution-proof subsystem.

## 4. Physical data model

The initial schema uses six primary tables plus filesystem blobs.

### 4.1 `stream`

Identifies a source/session/agent stream.

Key fields:

- `id`;
- `project`;
- `source_kind`;
- `source_native_id`;
- `workspace`;
- `last_ingest_seq`.

Unique identity: `(project, source_kind, source_native_id)`.

### 4.2 `observation`

Preserves an actual source event or explicitly sourced report.

Key fields:

- `id`;
- `project`;
- `stream`;
- `event_key`;
- `ingest_seq`;
- `occurred_at`;
- `received_at`;
- `kind`;
- `body` or `blob_ref`;
- searchable excerpt;
- available task/session/branch/call/parent references;
- source locator and revision;
- capture limit if content was partial.

Unique identity: `(project, stream, event_key)`.

An observed tool result and an agent's report about a result are different observations.

### 4.3 `memory`

Holds the current editorial revision of a semantic item.

Key fields:

- `id`;
- `origin_project`;
- `reuse_scope`;
- `revision`;
- `kind`;
- `content`;
- `search_text`;
- exact cues and advisory aliases;
- `subject`, `aspect`, `perspective`;
- applicability conditions and exceptions;
- validity interval;
- exposure/influence state;
- created/updated times;
- optional active embedding profile/vector/revision.

`origin_project` never changes. `reuse_scope` may be project-local, selected projects or local-owner-wide.

### 4.4 `memory_history`

Stores previous semantic revisions.

Unique identity: `(item, revision)`.

A version handle is `(item_id, revision)`. `open` returns that exact version. It never substitutes the latest historical row for a missing current item.

### 4.5 `link`

Stores typed, revision-aware relations.

Key fields:

- source item/observation and source revision;
- target item/observation and target revision;
- relation kind;
- optional `grounds_group`;
- source locator;
- note/qualification.

Relation kinds include:

- evidence;
- live requirement;
- contradiction;
- replacement;
- episode membership/order;
- outcome of;
- used method;
- navigation/related.

For compound grounds:

- links in one non-null `grounds_group` are required together;
- different groups are alternatives;
- ungrouped evidence is supportive unless the item explicitly names it as required.

This is sufficient for addressable revision. It is not a general theorem prover.

### 4.6 `job`

Stores finite background work.

Key fields:

- `id`;
- `project`;
- `purpose`;
- `target_key`;
- `state`;
- finite input observation IDs/ranges;
- input memory IDs/revisions;
- selected method ID/revision;
- current claim and expiry;
- due time/attempt;
- controller execution reference;
- result refs and processed input;
- error or no-change result.

At most one job runs for a `(purpose, target_key)`. New events coalesce into one pending successor; they never mutate the running job's input.

### 4.7 Blobs and source locators

Large source bytes live under `blobs/`; database rows keep an opaque reference and digest.

Supported source locators are concrete:

- code: repository/worktree, revision, path, lines or symbol;
- document/PDF: URI/file, revision, page and element/span;
- spreadsheet: file, revision, sheet and range;
- image: file/revision and region;
- transcript/media: stream/session, event/turn or time range;
- web/research: URL, retrieval time and quoted/span locator.

A generic payload alone does not mean a source type is supported.

## 5. Store and transaction operations

Store is private application code using the official network Rust SDK and one reusable WebSocket connection to the SurrealDB child. Fixed parameterized query files are preferred to a generic query builder.

### 5.1 `capture_event`

Inside one short transaction:

1. resolve/create the stream;
2. read the event key;
3. if the same input already exists, return it without duplicate work;
4. if the key exists with different input, record a conflict/correction path;
5. advance local ingestion sequence;
6. insert the observation;
7. create or extend necessary pending jobs;
8. commit.

Semantic classification, embeddings and source parsing do not run inside this transaction.

When Store is unavailable, write one complete bounded spool file under the stable event identity. Staged input is not confirmed semantic memory. Replay calls `capture_event` with the same key.

### 5.2 `claim_due_job`

Conditionally claim a due job and freeze its finite inputs.

The worker reads the named method revision and input/source material after the claim. It does not expand the input to every record now visible.

Independent targets proceed independently. There is no project-wide head-of-line barrier.

### 5.3 `apply_job_result`

Prepare model/source results outside the transaction.

Inside one transaction:

1. verify the current job claim;
2. verify each addressed current memory revision;
3. archive replaced revisions;
4. update/create addressed memory items;
5. insert revision-aware links/grounds;
6. record the actual result or explicit no-change;
7. finish the job for exactly its supplied input;
8. create any genuinely necessary successor work;
9. commit.

A zero-row conditional update fails the transaction. Do not use `UPSERT` when an existing item was required.

A lost commit acknowledgement is resolved by reading the same job/result identity before repeating external work.

### 5.4 `find_context`

Run independent retrieval arms:

- direct handles and exact identifiers;
- current-work address;
- full-text search;
- compatible vector search;
- scoped claim-group alternatives;
- relevant typed relations;
- project-local and eligible reusable methods.

Union candidates before applicability and final packing. Page broad enumeration. A per-page limit is not total corpus capacity.

### 5.5 `open_handle`

Open:

- current or historical memory revision;
- observation;
- source segment/blob;
- view and its examined scope;
- job/result status.

Missing content is reported as missing. Do not generate a plausible substitute.

## 6. Host capture and delivery

### 6.1 First adapter: Claude Code

Use supported host events rather than inferred execution proofs.

Initial mapping:

| Host boundary | Eliot action |
|---|---|
| Session start / prompt boundary | attach and request orientation/current context |
| Tool success | capture call identity, input reference and actual result |
| Tool failure | capture call identity and actual error |
| Batch/turn boundary when supported | request context informed by recent results |
| Resume/compaction boundary | refresh current work and changed advice |
| Explicit user correction | capture and publish/update a memory item directly when sufficiently structured |

The adapter records what the host supplies. It does not invent a task ID, verifier, successful step or project. Subagent events remain in their native child/parent streams and are not flattened into a fictitious single sequence.

The adapter tags Eliot-injected context. When later conversation is captured, exact injected blocks are excluded as new source evidence while genuinely new user/agent actions and results remain. Previously delivered advice is not counted as independent confirmation merely because it reappears in the transcript.

Capture returns without waiting for Dreamer. A wakeup only makes interpretation due.

### 6.2 Other hosts

Each adapter maps native events into the same `capture`, `context`, `open` and `control` operations.

Do not create a universal plugin framework before a second real adapter proves the common boundary. Host-specific lifecycle traps remain in that adapter.

### 6.3 Delivery semantics

Build the packet before optional diagnostics.

Distinguish:

- packet prepared;
- handed to the host;
- observed by the host if such feedback exists;
- applied by the agent, usually unknown unless later evidence supports it.

Do not mark delivered before handoff. Logging failure cannot erase a known primary result.

Repeat suppression is a small cache keyed by context incarnation and material revision. New corrections or newly available orientation may be offered again.

## 7. Current work and context

### 7.1 Decision frame

A decision frame carries available:

- project/workspace;
- task/session/branch IDs;
- current user goal and criteria;
- selected resources;
- tool/model profile;
- context incarnation;
- token budget.

Unknown fields remain unknown.

### 7.2 Continuation before similarity

Context construction:

1. directly open current task/session/branch continuation;
2. merge later observations not represented by that continuation;
3. retrieve exact constraints and corrections;
4. retrieve applicable methods and episodes;
5. resolve current claim groups and dissent;
6. add optional project view and relation expansion;
7. pack the decision.

A cancelled plan or old continuation does not regain authority by similarity.

A continuation is an ordinary versioned memory item containing:

- active goal;
- current plan;
- completed work;
- rejected/abandoned approaches;
- open commitments;
- last relevant results;
- next useful step;
- source handles and coverage.

It does not replace the original events.

### 7.3 Packing

Pack semantic units, not isolated rows:

- claim with material exception;
- failure with repair/result;
- method with conditions;
- dissent with its distinguishing check.

Candidate examination and final packet size are different budgets. If early candidates are inapplicable, inspect later candidates within the request work limit.

Render useful content, not only record IDs and scores. Details remain available through `open`.

## 8. Retrieval and project understanding

### 8.1 Search

Primary full-text and exact queries operate on `memory` and selected observation fields. Vector search is an additional arm.

Embedding identity includes encoder, preprocessing and content revision. A failed or pending vector leaves exact/lexical retrieval available.

Background embedding work is batched and limited so foreground query capacity remains.

### 8.2 Relations and episodes

Expand only relations that supply missing information: order, consumer, cause, repair, outcome or exception.

An intermediate node need not repeat query words. Use relation type, direction, scope and work budget; do not scan all links or encode every visited node again.

A short lesson may expand to its source episode: relevant preceding action, result, repair and check. Episode order comes from stream/call/result links, not timestamp proximity across unrelated work.

### 8.3 Project structure

Use configured existing tools rather than an embedded parser platform.

Initial code-structure adapter: `codebase-memory-mcp` when configured. Request compact architecture/package/entry-point structure and open exact sources as needed.

Fallbacks such as manifests, ripgrep and direct source reads provide partial structure with explicit limits. They do not claim a complete call graph.

Project views are ordinary versioned memory items:

- purpose and boundaries;
- subsystem/area explanations;
- recurring question answers;
- examined scope and source revisions;
- known gaps.

Source additions, removals, renamed resources and new consumers refresh affected views through ordinary jobs. A failed refresh leaves the prior qualified view usable.

### 8.4 Documents and other sources

Use external converters when useful; do not embed another memory runtime.

Docling is the initial document/PDF converter candidate. The adapter preserves the original file/revision and maps converted elements back to pages/spans.

Spreadsheets, images and transcripts use their concrete locators. Unsupported detail remains accessible as original bytes/handle and is not silently treated as indexed.

## 9. Dreamer and controller

### 9.1 Text execution

Dreamer is a job purpose, not a separate service.

Initial controller mapping uses the supported text-execution path:

1. prepare/open an executor/session as required;
2. dispatch a finite synthesis task containing the saved input handles and selected method revision;
3. retain the controller execution reference;
4. read the actual completed output and usage;
5. persist the useful result before releasing temporary executor state.

Input admission is not completed inference.

Do not rely on a later-message API unless its result reader supports that origin. Fix such a gap in the controller adapter, not by scraping logs inside Memory OS.

### 9.2 Request content

A Dreamer request includes:

- concrete question/purpose;
- finite source observations/segments;
- current relevant methods/items;
- exact selected method ID/revision when improving behavior;
- output contract: create, update, keep/no-change, or report uncertainty;
- source handles and disclosure route.

The model may propose memory revisions and links. Application code checks parseability, addressed membership, current revisions and job claim. It does not certify truth. Route fallback never silently expands disclosure or budget beyond configuration.

### 9.3 Embeddings

Controller needs a batch vector operation:

```text
encoder profile + [(item_id, text_revision, text)]
→ per-item vector or per-item error
```

This is controller model infrastructure, not an agent task. Until implemented, V3 remains useful through exact/full-text retrieval.

Applying a vector updates derived fields for the matching content/profile. It does not create a semantic revision or trigger another learning episode.

### 9.4 Research

The required Research adapter contract is:

```text
question + scope + source constraints + budget
→ status + report + source handles + examined coverage + gaps
```

Eliot Research owns acquisition and large corpora. Eliot stores the compact findings/alternatives needed later and links to the underlying sources.

This contract is a required implementation target, not a claim of an existing endpoint.

## 10. Learning

### 10.1 Episode input

Host events are grouped using actual session/task/call/result relationships. Chunking a large log for search does not define a task boundary.

Coalesce wakeups, not observations. A running interpretation job sees a finite saved range; later events remain for the pending successor.

### 10.2 Interpret or keep

A normal Dreamer job receives:

- the relevant episode slice;
- explicit user feedback/corrections;
- a small set of related current lessons;
- the selected method revision used to interpret or improve.

It may:

- create a provisional lesson;
- update a named lesson;
- create/update a project view;
- identify contradiction/unknown;
- keep/no-change.

Parse failure or provider failure is not no-change.

A direct explicit correction may publish without a model call.

### 10.3 Method consumer

Every method-affecting job stores `method_id` and `method_revision`.

The request builder opens that exact text and includes it in the actual controller request. The job result records which revision was used.

A new revision affects new jobs. Existing running work continues with its selected revision unless explicitly restarted.

A method without a real consumer is stored knowledge, not implemented self-improvement.

### 10.4 Applicability and transfer

Applicability is three-valued:

- applicable;
- inapplicable;
- unknown/conditional.

Similarity finds candidates; it does not prove conditions. Negation, version and observed execution results must not be reduced to word overlap.

Cross-project retrieval considers:

1. current project items;
2. reusable methods whose `reuse_scope` includes the current project.

Origin and source restrictions remain visible. Transfer may be provisional; broad effectiveness requires later comparable outcomes.

### 10.5 Outcome feedback

Outcome records distinguish:

- method offered/delivered;
- action observed;
- method followed or unknown;
- criterion coverage;
- result;
- competing failures/cost;
- comparative benefit or unknown.

One attempt/criterion contributes once. Corrections replace the current contribution with history.

A missing diagnostic is success only if the relevant check actually covered the target.

### 10.6 Recursive improvement

Use the same jobs, methods and outcomes for:

- task-local Propose–Probe–Compose;
- cross-task lessons about how to improve.

Baseline/no-change remains eligible. Repeatable local calculations and copies are preferred probes. Do not repeat irreversible external actions merely to compare candidates.

### 10.7 Self-diagnosis

When a useful result fails, identify the first failed step:

- event not captured;
- lesson not produced;
- lesson not retrieved;
- context not delivered;
- advice not used;
- advice inapplicable;
- advice used and harmful.

Correct that step. A failed repair blocks unsupported repetition of that repair, not all diagnosis under the same configuration.

## 11. Disagreement, anticipation and research use

### 11.1 Disagreement

Represent rival explanations as ordinary claims with grounds and counterevidence.

Select the cheapest useful discriminating observation. Additional agents are optional controller tools. A vote or number of agents is not evidence.

Unresolved alternatives remain available; unrelated work continues.

### 11.2 Anticipation

A conditional anticipation is a method or claim describing:

- trigger situation;
- expected future observation/risk;
- material conditions;
- useful check/action;
- expiry/reconsideration condition.

It enters ordinary context when relevant. Expiry of the warning does not fabricate an outcome.

### 11.3 Research use

Research findings preserve:

- the question;
- sources examined;
- report/findings;
- alternatives;
- coverage/gaps;
- source handles;
- method/version used.

A source acquisition failure and completed but uninformative research are different. Repeated no-change on unchanged inputs does not automatically rerun.

## 12. Deletion, backup and restore

### 12.1 Deletion

Publish withdrawal before acknowledging it. Remove controlled current/history rows, links, vectors, blobs, staged input and controlled backup copies as required.

Keep the minimum replay/deletion information outside rollback-prone copies. Do not retain deleted text in that record.

### 12.2 Backup

1. pause primary mutations and new external dispatch;
2. let short transactions finish;
3. seal the current spool batch and open a new one;
4. export primary DB state and referenced blobs into a temporary directory;
5. include the sealed input cutoff and known deletion information;
6. verify required components;
7. publish the completed-backup marker;
8. resume.

New input remains in the new spool batch. An interrupted copy is not a restore point.

### 12.3 Restore

Restore into a fresh directory. Apply known current deletions, import primary data/blobs and make primary reads available before embeddings and views finish rebuilding.

If current deletion history was lost, the owner may explicitly restore the selected copy with the limitation reported. Do not quarantine all intact data behind an impossible proof.

Old external jobs do not restart automatically. Reconcile execution references before any repeated provider/tool effect.

## 13. Control and observability

Direct controls:

- status;
- inspect/open;
- pause/resume jobs;
- cancel owned work;
- configure routes/projects/retention;
- correct/withdraw/erase;
- backup/restore;
- graceful shutdown.

Status is derived from actual process, Store, jobs and recent results. Heartbeat is not progress; acknowledgement is not resolution; prepared context is not delivery.

Optional notification failure does not block status or control.

## 14. Implementation sequence

Build vertical slices in this order.

### Slice 1 — Store and local lifecycle

- supervisor, daemon and SurrealDB child;
- configuration/data directories;
- capture event;
- exact open/read after restart;
- spool when Store is unavailable;
- direct status/shutdown.

### Slice 2 — Host capture and context

- first Claude adapter;
- actual tool result/error capture;
- current-work continuation;
- full-text/exact context;
- `open` expansion;
- advice delivered at a real model boundary.

### Slice 3 — Dreamer and lessons

- actual controller text execution;
- finite episode job;
- create/update/keep;
- method revision consumed by the next job;
- outcome capture and correction.

### Slice 4 — Understanding and transfer

- codebase-memory-mcp adapter;
- affected project views;
- origin/reuse scope;
- cross-project method retrieval;
- disagreement and anticipation.

### Slice 5 — Vectors, documents and research

- controller batch embeddings;
- Docling/source locators;
- Research request/result adapter;
- hybrid retrieval and richer sources.

### Slice 6 — Recovery and advanced improvement

- backup/restore/erase;
- recursive improvement;
- targeted self-diagnosis;
- additional host/source adapters.

For each slice, implement the real production path first. Run minimum relevant build/Clippy checks. Add broader tests after the connected behavior exists. Do not create success-shaped stubs, fixtures in the production branch or unused framework code to satisfy a planned test.
