# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.19 · 2026-10-24 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, data and connected operations. [Cognition](COGNITION.md) defines algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) is the sole normative Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) records checked evidence, decisions and open gaps.

Nothing here is implemented merely because it is specified. The complete target is not a prerequisite for useful Base. Build the connected production slices in §14. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 1. Runtime and first use

### 1.1 Process family

The initial Windows profile uses one executable with modes:

```text
eliot supervisor     owns the local process family
eliot daemon         serves Memory operations
eliot relay ...      transient host/CLI adapter
```

The supervisor owns:

- `eliot daemon`;
- one SurrealDB server child;
- their Windows Job Object;
- restart intensity and planned shutdown.

The daemon does not supervise itself. Hosts and `eliot-swarm-controller` do not own this process family. Provider/model processes remain controller/provider concerns.

### 1.2 Data root and configuration

Use one stable installation root, for example:

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  data\
    db\
    blobs\
  spool\
  deletions\
  backups\
  logs\
```

`config.toml` contains practical local settings:

- selected data directory;
- configured projects/workspaces;
- capture exclusions and retention;
- host adapters;
- controller IPC/data root and private inference-client credential path;
- selected text/embedding profile names;
- project/source disclosure defaults;
- idle timeout and automatic-work mode;
- optional document/Research tools;
- explicitly allowed cross-project reuse scopes.

It is not a generated policy database, route registry or module catalogue.

Provider connections, provider credentials, adapter IDs and `actual_destination` declarations stay with `eliot-swarm-controller`. Memory stores only selected profile names and frozen non-secret execution identity returned by controller.

### 1.3 Demand start and shutdown

The supervisor holds a named mutex for the stable installation root throughout startup, operation and shutdown. A relay connects first; if no endpoint answers, it starts a supervisor candidate and waits. Only the candidate owning the mutex starts children. An existing owner with an unready daemon is not permission to launch another database.

Create SurrealDB and daemon children suspended, assign them to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resume them. If assignment fails, terminate the still-suspended child. Start and verify the configured database connection before reporting Store ready. Do not kill unrelated processes by name or port.

Restarting a failed daemon does not restart a healthy database. If the supervisor dies, owned children terminate with the Job Object; the next demand start opens existing data.

Before normal idle shutdown:

1. stop new external dispatch;
2. allow one finite drain interval for already eligible work;
3. persist collected results and progress;
4. stop daemon and database;
5. wait for exit and release the mutex.

Pending data, a completed background job or an internal poll cannot renew the interval indefinitely. Explicit shutdown does not start a final Dreamer cycle. Unknown controller/provider outcomes remain reconcilable after restart; shutdown does not authorize another request ID.

Primary capture and exact/lexical reads become available as soon as Store is ready. They do not wait for controller inference, embeddings, project orientation or a graph.

## 2. Code structure

### 2.1 Start with one Rust package

Use one library package plus a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries. Split a crate only when an actual dependency, deployment or independently changing boundary requires it.

| Module | Owns | Does not own |
|---|---|---|
| `model` | Small values crossing real internal boundaries | Vendor SDKs, runtime, universal contract catalogue |
| `store` | Schema/migrations, fixed queries, atomic writes, exact reads and blobs | Interpretation, host protocol, model selection |
| `memory` | Semantic item operations, revisions, history, grounds and source links | Raw host/provider I/O |
| `context` | Decision-frame retrieval, applicability, relation expansion and packing | Second Store or model scheduler |
| `learning` | Purpose-specific input selection, request builders, disclosure reduction, decoders, reducers and publication proposals | Job claims, provider retries or credentials |
| `vectors` | Vector-space identity, result mapping and vector candidate arm | Provider transport or second vector database |
| `jobs` | Due selection, claim/reclaim, finite handler dispatch, reconciliation and result application | Semantic algorithms duplicated from handlers |
| `adapters::host` | Native host event normalization and context delivery | Task ownership or memory policy |
| `adapters::controller` | Authenticated controller IPC, `inference.text`, `inference.embed`, Operation/artifact readback, queued cancel and `inference.release` | Memory job state, publication, provider credentials or route planning |
| `adapters::source` | Document, structure and Research translation | Another memory service |
| `control` | Status/inbox, configuration, maintenance and owner commands | General policy engine |
| `runtime` | Composition, process/task lifetime and shutdown | Cognitive algorithms or global mutable service locator |

Dependency direction:

```text
model + pure transformations          -> no I/O imports
store + outbound adapters             -> model and external dependencies
application operations                -> model, Store API and narrow clients
host / CLI / MCP surfaces             -> application operations
runtime composition                   -> concrete constructors and startup/shutdown
```

Keep IPC, HTTP, SQL and module internals private. Internal calls share typed Rust values; serialize only at storage, process or network boundaries. Add a trait at a real interchangeable I/O boundary, not for every table or function.

### 2.2 Base and additive capabilities

**Base** provides capture, explicit notes/corrections/commitments, exact and lexical retrieval, addressed current work, bounded context/open, restart/spool and maintenance for retained Base data. It starts without controller, model, encoder, converter or Research credentials.

| Capability | Additional dependency | Existing consumer |
|---|---|---|
| First learning | Base observations, one controller inference client, one processing recipe | Ordinary `memory`, `context` and `open` |
| Vector retrieval | Base text revisions and controller embedding profile | Additional candidate arm in `context` |
| Project understanding | Base source access and configured structure tool; inference only for explanation | Versioned project views |
| Documents | Base blobs/jobs and configured converter | Search excerpts and exact source `open` |
| Research | Configured Research client | Findings/report/source handles in ordinary memory |
| Richer cognition | Relevant claims/methods/outcomes and text inference where needed | Same jobs, revisions and context |
| Another host | That host's actual events and delivery boundary | Same application operations |

These increments are not a compulsory chain. Vectors do not require Dreamer. Documents do not require Research. Another host does not create another memory engine.

### 2.3 Integration is ordinary code

A new capability adds only what its connected path needs:

1. a narrow external client when necessary;
2. one application handler or foreground operation;
3. Store fields/indexes introduced by its first real writer;
4. its real reader/consumer;
5. maintenance for the retained data it adds.

It does not automatically add a process, manifest family, event bus, scheduler, database, context compiler, plugin platform or generated inventory.

Finite expensive work uses the existing `job` runner. A long-lived task exists only when it must retain an actual resource or continuously receive input. Runtime plugin discovery, dynamic Rust ABI, WASM packaging and hot-generation machinery are not selected.

### 2.4 Optional means optional

Construct an optional client only when configured. Do not probe every remote service on daemon startup. A capability failure stays inside that capability; Base remains available.

Disabling a capability stops new dispatch for its purposes. Pending work waits rather than being repeatedly claimed and failed. Already admitted controller Operations retain exact request/result identity until reconciled, cancelled where still queued, released or erased. Re-enabling may continue selected pending work or a finite backfill; ordinary reads do not wait for it.

Use Cargo features only when omitting a heavy optional dependency materially reduces the build or package. Do not add a negative `lite` feature that changes record meaning.

## 3. Application surface and work binding

All host surfaces call the same application operations:

| Operation | Result |
|---|---|
| `attach(workspace, session)` | Project/workspace binding, continuation address, gaps and actual capabilities |
| `capture(event)` | `committed`, `staged`, `unknown` or `rejected` |
| `context(frame, budget, retrieval=local)` | Packet ID, rendered text, exact revisions, handles and gaps |
| `open(handle, read_context, range?)` | Exact item/source or bounded page and continuation |
| `record_outcome(report)` | Captured observed result or explicitly sourced report |
| `dream(request)` | Finite interpretation/research/improvement job when its handler is configured |
| `control(command)` | Status/inbox, configure, pause/cancel, correct, withdraw/erase, backup/restore or shutdown |

`record_outcome` reuses capture. An unavailable capability fails specifically; it does not return successful empty output.

### 3.1 Bind work without a scope platform

Configuration owns stable project/workspace IDs and their current roots or resource selectors. A project may be a repository, directory, document set, service or ad hoc work.

Resolve binding per request/event, not through one mutable `session.current_project`. A tool reading another root keeps that resource binding while remaining linked to the originating task. Late events and spool replay use their captured binding, not today's current directory.

Continuation addresses use project/workspace plus the actual host task identity, or the narrowest actor/session fallback. Branch, HEAD and path are observed state, not task identity. Fork and explicit transfer create explicit relations; they do not silently rename or merge interleaved work.

Missing association remains a gap. Capture under an ad hoc/session scope rather than mixing candidate projects or blocking all input until a complete survey exists.

## 4. Physical data model

Use six primary tables plus filesystem blobs. Add fields and indexes with their first real writer and reader; do not implement six speculative subsystems before Base capture.

### 4.1 `stream`

Identifies one native source/session/agent stream.

Key fields:

- `id`, `project`, `source_kind`, `source_native_id`;
- optional origin workspace;
- `last_ingest_seq`.

Unique identity: `(project, source_kind, source_native_id)`.

Stream sequence orders intake only within that stream. It is not a project clock or learning cursor.

### 4.2 `observation`

Preserves an actual source event, explicitly sourced report or directly observed Eliot application event.

Key fields:

- `id`, `project`, `stream`, `event_key`, `ingest_seq`;
- occurrence and receipt times with preserved uncertainty;
- `kind`, body or `blob_ref`, bounded searchable excerpt;
- disclosure class: `local_only | external_allowed`;
- captured workspace/task/session/call/parent/resource/version facts;
- continuation and packet references when present;
- source locator and capture limit;
- exact correction outcome/version handles for structured correction.

Unique identity: `(project, stream, event_key)`.

A tool result, agent report about it, prepared packet and observed handoff are distinct observations. Replays compare source content, not receipt time.

### 4.3 `memory`

Holds the current editorial revision of a semantic item.

Key fields:

- `id`, `origin_project`, `reuse_scope`, `revision`, `kind`;
- for methods: `method_role = advice | processing` and implemented `processing_purpose`;
- optional exact `address_kind` and `address_key`;
- `content`, `search_text`, exact cues and advisory aliases;
- disclosure class and source-derived limitations;
- subject/aspect/perspective;
- material applicability conditions/exceptions and optional typed selectors;
- validity interval;
- support limitations separately from retrieval exposure and advisory influence;
- optional commitment state;
- optional vector, effective space and encoded representation identity;
- created/updated times.

One complete exact address has at most one current item. An unaddressed note needs no address. Source project is not reuse audience, and reuse scope does not widen disclosure.

### 4.4 `memory_history`

Stores previous semantic revisions.

Unique identity: `(item, revision)`.

A version handle is `(item_id, revision)`. Exact historical read never falls back to the latest revision. Current read never resurrects a historical row after deletion.

### 4.5 `link`

Stores typed, revision-aware relations.

Key fields:

- source item/observation and source revision;
- target item/observation and target revision;
- relation kind;
- optional grounds group;
- source locator and qualification.

Kinds include evidence, live requirement, contradiction, replacement, episode membership/order, resource continuity/derivation, outcome-of, used-method, packet inclusion/handoff and navigation.

For grounds, links in one non-null group are required together; different groups are alternatives; ungrouped support is advisory. Group meaning is local to one conclusion revision.

### 4.6 `job`

Stores finite background work.

Key fields:

- `id`, `project`, `purpose`, `target_key`, `state`;
- explicit/automatic origin and source cause;
- first queued/due time, attempt number, retry or waiting reason;
- frozen observation IDs/segments or per-stream ranges;
- input memory IDs/revisions;
- selected processing method ID/revision;
- claim owner and expiry;
- configured execution limits;
- reduced disclosure class;
- selected controller profile name;
- exact saved request or blob reference, byte length and digest;
- controller Operation ID and stable client request ID;
- frozen profile digest, adapter ID, non-secret connection identity and `actual_destination`;
- controller result artifact reference, length and digest;
- retained Memory raw result/blob and requested/observed metadata;
- `controller_copy_state = not_created | retained | cleanup_pending | cleanup_incomplete | released`;
- decoded proposal/no-change/partial/failure state;
- applied result handles, covered input and remaining/unavailable portions.

One `(project, purpose, target_key)` has at most one active job and one coalesced pending successor. Active includes waiting for or reconciling an admitted external request. Completed history does not occupy the slot.

### 4.7 Blobs and locators

Large source bytes, prompts and results live under `blobs/`; rows keep opaque references and digests. Save bytes before committing a row that refers to them. Cleanup may remove unreferenced temporary files later; a committed row must never point to bytes that were never saved.

Locators are format-specific and claim only supplied precision:

- code: workspace, captured source identity/version, path and line/symbol range;
- document/PDF: captured source, saved conversion identity and element/page/region when available;
- spreadsheet: source/version, sheet and range;
- image: source/version and region;
- transcript/media: stream/session and event/turn/time range;
- web/research: captured representation/revision and passage range;
- service/runtime: configured environment, actual run/instance identity and observation time.

Dirty/untracked code is cited by retained bytes or retained range, not by HEAD alone. Similarity may suggest continuity but does not rewrite old locators.

## 5. Store operations and transaction rules

Store is private application code using the official SurrealDB SDK and fixed parameterized queries. Network, controller, document and Research calls never run inside a database transaction.

Use native keys/indexes for identity. A preceding existence query alone does not prevent concurrent duplicates. Dependent writes use one explicit transaction; zero-row conditional updates abort rather than return an error-shaped success.

Retry database conflicts with the same saved input. A stale semantic revision is different: do not silently replace the expected revision and overwrite a concurrent change. For uncertain commit, read by owning observation/job identity before repeating.

### 5.1 `capture_event`

In one short transaction:

1. resolve or create stream by unique native identity;
2. read the event key;
3. return the saved result for an identical replay;
4. reject or record mismatch if the same identity names different source content;
5. advance stream intake sequence and insert observation;
6. coalesce only implemented, enabled and necessary follow-up work;
7. commit.

Capture does not call a model. Packet/status/read/claim-renewal/release/embedding-completion events do not automatically become new experience. A structured correction uses §5.3.

If Store is unavailable, durably publish a complete spool command under the same source identity. Report `staged` only after bytes are saved. Replay uses the same operation and deletes the spool entry only after primary readback.

### 5.2 `claim_due_job`

Select only work whose handler is present, enabled and eligible for configured automatic mode. Waiting for idle time, a configured profile, disclosure-compatible destination or resume is not a failed attempt.

In one short transaction:

1. select a due target fairly;
2. move its pending row into the active slot;
3. freeze finite inputs;
4. set claim/expiry;
5. resolve and freeze exact processing-method revision when required;
6. reduce actual selected input to one disclosure class;
7. select the configured profile name without resolving connection secrets;
8. commit.

The handler builds and saves exact request bytes/digest before controller I/O. Reclaim never rebuilds a different request for an already admitted Operation.

### 5.3 `publish_memory_revision`

For explicit correction or accepted proposal, one transaction:

1. re-read expected current revision;
2. reject stale expected revision;
3. copy old current row into `memory_history`;
4. write new current revision;
5. insert revision-specific source/grounds/replacement links;
6. settle the owning command/job result;
7. coalesce only affected follow-up work;
8. commit.

IDs for proposal-created items are allocated once and retained with decoded job result so a Store retry cannot create another item.

### 5.4 `retain_external_result` and `apply_job_result`

Controller polling/artifact reading occurs outside Store transactions.

After exact result bytes are read and verified, one short transaction stores:

- controller Operation/result identity;
- exact Memory blob reference, length and digest;
- requested/observed execution metadata;
- external status and limits;
- current controller-copy state.

Decoding occurs from the retained Memory blob. Applying a valid proposal uses one transaction with expected revisions, new history/current rows, links, coverage and job disposition. A Store conflict reuses the saved decoded proposal and never repeats inference.

Controller release occurs outside the publication transaction after Memory has a verified durable copy. Its success/failure updates only cleanup state; it does not roll back a valid Memory publication.

### 5.5 Exact reads and coherent hydration

Read current item, exact revision, grounds, source handles, conditions, exceptions and controller/job status through bounded Store operations. A packet records the exact revisions actually rendered.

Do not mix a current item with links from another revision. If the required coherent set cannot be read under one transaction/snapshot, use revision checks and retry the read rather than silently combining states.

### 5.6 Bounded reads

All large reads page by real byte/row limits. A row limit is not a byte limit. Preserve UTF-8 boundaries and continuation handles. Long JSON, one-line logs and converted documents must not force unbounded allocation.

## 6. Host capture and context delivery

### 6.1 Capture

A host adapter normalizes native events but retains native identity, event ordering, task/session/call/result relations, occurrence time, body limits and source locator. It does not invent missing task identity or semantic success.

Capture path:

```text
native event
→ bounded normalization
→ capture_event
→ committed or durable spool
→ optional finite follow-up job
```

Final assistant text, tool result and host lifecycle events remain distinct. Capture exclusions apply before durable publication.

### 6.2 Context delivery

At a real supported host boundary:

1. resolve exact continuation address;
2. load current work and explicit constraints;
3. generate independent retrieval candidates;
4. resolve current revisions/applicability and material exceptions;
5. pack within actual budget;
6. persist packet identity and exact included revisions;
7. render through the host boundary.

Distinguish:

- packet prepared;
- packet handed off to host;
- packet associated with a later action;
- content actually used, when observable.

Absence of host correlation does not block retrieval or capture. Do not claim delivery merely because packet text was written to a local file.

## 7. Retrieval, context and source opening

### 7.1 Decision frame

A decision frame contains project/workspace/task or actor/session address, observed resource versions, focused question, exact cues, known constraints and requested budget.

Address current work before search. A branch/path alone does not select among interleaved tasks.

### 7.2 Candidate arms

Generate bounded candidates independently from:

- direct IDs/handles;
- exact current-work address;
- exact cues;
- full-text/lexical search;
- compatible vector space when enabled;
- current alternatives/grounds;
- typed relations;
- project-local and eligible reusable methods.

Union before final selection. A lexical candidate does not require a vector score. Workspace/task selectors apply before per-arm limits.

### 7.3 Ranking and applicability

Rank relevance separately from evidential support. Scores are relative ordering, not calibrated truth probability.

Applicability is `applicable | inapplicable | conditional/unknown`. Exact typed conditions may decide simple cases. Natural-language uncertainty remains conditional. Token overlap does not prove a condition.

Material exception/counterevidence is loaded with its claim or method even if it would not rank independently.

### 7.4 Packing

Pack semantic units, not arbitrary chunks:

- current work;
- exact constraints/corrections;
- applicable or conditional methods;
- relevant prior episode;
- dissent, unknowns and next checks;
- source handles.

If a unit cannot fit, return a faithful qualified reduction plus expansion handle or omit the whole unit with a stated gap. Never drop negation, version or contraindication.

Packet-local grouping reduces repetition but does not merge stored identities or create evidence.

### 7.5 `open`

`open` resolves an exact item/revision, observation, blob, converted representation, report section or source range. It does not rerun search, conversion, research or inference merely to satisfy a historical handle.

Return metadata/excerpt first and selected bounded ranges next. A missing retained representation is a specific durability gap, not permission to substitute a newer source.

## 8. Project views, documents and affected grounds

### 8.1 Project views

A project view is a versioned answer to one useful question over an examined scope. First contact returns available exact facts immediately. A finite job may add semantic explanation.

A view records examined workspace/resource revisions, answer, source handles and gaps. Membership-affecting changes qualify or dirty the view. Refresh affected views only; retain prior qualified view and direct source access while refresh is unavailable.

### 8.2 Documents

Document path:

```text
captured original bytes
→ finite converter job
→ retained structured representation + status/errors
→ searchable source excerpts
→ exact open of the saved representation
```

Do not reconvert on read or silently substitute a newer file. Preserve available element/page/layout precision; do not fabricate cell or region coordinates. Partial conversion remains useful with explicit coverage. Keep referenced assets before deleting converter temporaries.

### 8.3 Reconsider affected grounds

A correction, refutation, relevant live-condition change or erasure records its actual scope and coalesces a follow-up job in the primary mutation. Use reverse grounding indexes to page affected conclusion revisions. Load each conclusion's complete groups; do not walk navigation links as evidence or rebuild every project view.

Known qualification reaches context before replacement explanation is ready. Model work may help interpret an unresolved relation, but no model call is needed to find declared affected links or a broken required group. Cycles supply no independent support. Keep traversal finite and resumable in the existing job.

## 9. Controller inference, embeddings and Research

### 9.1 One Memory-side controller client

[INFERENCE-CONTRACT](INFERENCE-CONTRACT.md) owns the cross-repository method, authority, artifact, replay, provider-adapter and release details. Memory uses one narrow authenticated client over the pinned controller IPC implementation:

```rust
trait ControllerInferenceClient {
    async fn text(&self, request: TextRequest) -> OperationRef;
    async fn embed(&self, request: EmbeddingRequest) -> OperationRef;
    async fn get(&self, operation: OperationRef) -> OperationReceipt;
    async fn read_result(&self, artifact: ArtifactRef, range: ByteRange) -> Bytes;
    async fn cancel_queued(&self, operation: OperationRef) -> CancelResult;
    async fn release(&self, request: ReleaseRequest) -> ReleaseResult;
}
```

The concrete adapter reuses the exact-revision `swarm-client` dependency. It does not copy IPC framing/authentication, use MCP or spawn one CLI process per request.

The public controller methods are:

```text
inference.text
inference.embed
inference.release
operation.get
operation.cancel
artifact.get
artifact.read
```

The controller route is not a controller Task/Attempt and does not own Memory job state, recipe, source coverage, decoding or publication.

### 9.2 Connection, profile and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile` configuration.

A connection owns transport, private credential reference, non-secret identity and `actual_destination = local | external`. A loopback endpoint may still have an external destination.

A profile selects one closed versioned adapter ID, one connection, requested model, `allow_automatic`, finite input/output/time/concurrency limits and supported response formats. The resolved profile inherits destination from the connection. Controller freezes a canonical non-secret digest on admission.

Memory selects a profile name and reduces actual supplied content to:

```text
local_only | external_allowed
```

Reduction is deterministic:

- project configuration supplies a default;
- a source may be stricter;
- a derived item remains as strict as content it still contains or reveals;
- mixed input uses the strictest contributing class;
- reuse scope does not widen disclosure;
- `local_only` requires `actual_destination=local`.

Do not omit protected material to make an external destination pass. If required material and selected profile are incompatible, the job waits or fails with a disclosure/profile gap. It is not no-change and does not mark input processed.

Automatic execution requires both Memory automatic mode and profile `allow_automatic=true`. Missing usage, cost or account identity remains unknown. No silent fallback is allowed.

### 9.3 Exact request, readback and release lifecycle

Before controller I/O, save on the existing Memory job:

- stable client request ID;
- selected profile name;
- reduced disclosure and explicit/automatic origin;
- exact prompt/input bytes or immutable blob reference, length and digest;
- finite requested limits/format;
- selected recipe/source revisions.

Call controller outside the Store transaction.

Connected lifecycle:

```text
saved Memory request
→ authenticated inference.text/embed
→ controller validates and stages private inference_input
→ controller Operation with frozen connection/profile behavior
→ provider attempt or typed rejection/unknown
→ immutable inference_result when a body exists
→ Memory operation.get + bounded artifact.read
→ Memory verifies length/digest and stores exact result bytes
→ decode/map and apply through ordinary Store operations
→ inference.release removes controller inference_input and inference_result
→ Memory records released or cleanup gap
```

Controller deduplicates by exact caller, stable request ID, method and canonical bounded request identity. Input digest/length participates; raw content is not stored in generic Operation JSON.

If the admission reply is lost, repeat the identical request to the same controller as the same client. Once Operation ID exists, use `operation.get` and artifact readback. Connection loss after possible send remains `unknown` unless native readback resolves it. A new request ID is not recovery.

`complete` or usable `partial` requires exact artifact readback. Memory verifies length/digest and stores its own copy before decoding or release. Malformed cognitive output is still retained as exact transport output and is not successful no-change.

`inference.release` is idempotent and covers both controller-owned content artifacts. Cleanup failure is visible but does not invalidate a verified Memory copy. Release is independent of cognitive success: after Memory has durable exact bytes, malformed/failed decoding does not justify indefinite controller retention.

Cancellation applies only while controller Operation is still queued. Once provider I/O may have begun, local cancellation cannot prove non-execution and content needed for reconciliation is retained until release is permitted.

### 9.4 Embeddings

`inference.embed` uses the same Operation, controlled-copy, exact-readback and release lifecycle.

Canonical result contains:

```text
effective vector space
+ role: query | document
+ one vector or error per input_key
+ observed model/usage/limits when supplied
```

Controller owns provider-specific serialization, credentials and model invocation. Memory maps each result to exact item/revision/representation. Missing, duplicate or unresolvable positions are errors, not zero vectors or shifted assignment.

Coalesce compatible inputs within actual bounds. Preserve successful items and leave unresolved items explicit. Applying vectors updates derived fields only. Content revision invalidates the old vector in the primary mutation; text remains lexically usable.

One initial vector space is enough. Changing to an incompatible space pauses only vector dispatch/query, rebuilds derived vectors in finite pages and leaves Base reads available.

After the canonical embedding result is durably copied and mapped, call `inference.release` for that Operation as well.

### 9.5 Research

Use the existing Eliot Research application boundary, not a new executor or corpus.

Separate:

1. search without synthesis;
2. start requested research;
3. read run status and retained artifact identity;
4. read actual report sections;
5. open cited evidence.

Save exact request/profile/idempotency key before submission. Replay recovers the same run when supported; it does not unconditionally start another investigation. Metadata does not count as report text. Interrupted reading resumes from retained section/source refs.

Current Research gaps remain: align the MCP request decoder with the current selected method/model request and open saved citations from retained source representation rather than active search-index readiness. Large report sections need bounded reading in Research's existing reader, not a replacement model answer.

## 10. Learning and autonomous curation

### 10.1 Episode input and coverage

Group events through actual session/task/call/result/parent relations. An episode may use several streams without flattening native order or waiting for every child.

A job freezes membership and exact observation segments/per-stream bounds. Distinguish:

- selected source material;
- text actually supplied to controller inference;
- successfully processed coverage.

An unexpanded handle, trimmed body or omitted segment is not covered. Complete no-change covers only supplied input and purpose. Deferred material goes to pending successor. There is no global processed bit.

### 10.2 Interpret, correct or keep

A normal learning job receives relevant episode input, explicit feedback, a small set of related items and exact processing-method revision. It may create a provisional claim/method, revise a named item/view, identify conflict/unknown or keep/no-change.

A direct structured correction uses §5.3 without inference.

### 10.3 Processing-method consumer

Ship real default recipe text only for implemented text purposes. First enablement for a project saves the needed default as an ordinary processing method at a stable purpose address. Do not seed future purposes.

When claiming a text job, freeze method ID/revision with inputs. Request builder opens that exact body. Reclaimed work retains the same method and saved request. Software update does not overwrite a learned or user-edited method with bundled default.

Textual improvement changes the addressed processing method through ordinary revision. Later jobs consume the new revision; running work keeps frozen input. A method with no real consumer is stored knowledge, not implemented self-improvement.

### 10.4 Outcome feedback

Retain source events in observations. Reduce attributable feedback into ordinary versioned outcome items addressed by exact method revision, actual attempt/execution and criterion/checked target.

A tool result and agent report about it may both be saved but are one attempt. A packet proves offered context, not adherence. Unknown method/attempt association remains unknown rather than crediting every shown method.

Consumers:

- `context` loads relevant limitations/counterexamples with selected advice;
- `learning` may revise addressed method when new feedback can change a later decision.

### 10.5 Automatic timing without another scheduler

Keep capability enablement separate from `automatic = off | idle | background`.

| Setting | Behavior |
|---|---|
| Capability disabled | No new explicit/automatic work from producer; retained content remains readable; admitted controller Operations remain reconcilable |
| Enabled, automatic off | Explicit `dream` works; no automatic inference or reminders to re-enable it |
| Enabled, automatic idle | Coalesced work may run after foreground quiet and during finite drain |
| Enabled, automatic background | Same runner progresses under configured capacity while capture/control/context retain priority |

A selected profile may independently refuse automatic use. Explicit work remains available if otherwise permitted; automatic jobs wait with a specific reason.

New relevant input coalesces one pending target and preserves first queued time. A quiet delay batches nearby events; maximum age makes it due but does not override disabled, destination/disclosure incompatibility or idle-only mode. Claim one finite slice; leave remainder pending.

During foreground return, stop starting new idle work. Already admitted work may finish or remain unknown; do not cancel and repurchase on every keystroke. A stopped process resumes pending jobs at next use. Optional unattended windows are external OS/host invocations of the same finite maintenance operation, not another scheduler inside Eliot.

Curation output must reach ordinary context/open/method consumers. An unread maintenance report is not product result.

## 11. Consolidation, disagreement and commitments

### 11.1 Consolidation without destructive identity merge

Distinguish:

- source-event replay;
- packet-local grouping;
- same-item revision;
- new synthesis from several episodes;
- correction or split of erroneous synthesis.

A broader pattern normally creates a separate provisional claim or method linked to exact sources. It does not delete or union source identities. A false merge narrows or splits derived item while original episodes and historical handles remain.

### 11.2 Disagreement and anticipation

Represent rival explanations as ordinary claims with grounds and counterevidence. Select the cheapest useful discriminating observation; voting is not evidence.

A prediction records trigger, expected observation, material conditions, useful check/action and reconsideration/expiry condition. Expiry does not fabricate outcome or close commitment.

### 11.3 Commitments

Commitments are ordinary scoped memory items with state, recipient/owner, optional due time and source. Context and inbox read them outside similarity ranking.

Showing, acknowledging or passing a due date does not resolve a commitment. Resolution follows a matching observed result or explicit owner change. Notifications are optional and do not create another task manager.

### 11.4 Self-diagnosis

Ask which connected step failed:

- capture;
- source selection or disclosure reduction;
- profile/destination admission;
- controller execution;
- result retention/readback/release;
- decoding;
- publication;
- retrieval/applicability;
- host delivery;
- use/correlation;
- method quality.

Correct the supported failing step. Do not create recursive diagnosis jobs from routine accounting or every no-change.

## 12. Deletion, backup and restore

### 12.1 Withdrawal and erasure

Withdrawal stops guidance; it does not claim physical deletion.

For erasure, record exact selected scope/command ID as a small text-free durable notice before removal. Cancel affected pending work, request queued controller cancellation where applicable, settle local writers and prevent late controller/Research results or spool replay from reintroducing erased content.

Page through actual references and remove controlled observations, memory/current/history, conversion assets, source excerpts, packet copies, job input/output blobs, staged files and content-bearing links in scope. Remove or replace controlled backups containing the data.

For each affected inference Operation:

1. preserve enough identity to prevent replay/reintroduction;
2. call `inference.release` when terminal or owner-authorized abandonment permits cleanup;
3. verify release covers controller `inference_input` and `inference_result` when present;
4. retain cleanup gap when either controlled copy cannot be confirmed removed.

Already delivered provider copies are an external boundary. A controller artifact is controlled integration data, not external merely because it is in another local service. Do not report complete erase while it remains.

### 12.2 Backup

Use native logical database export plus referenced immutable blobs and finite selected spool entries. Include schema, all six tables, explicit history/links, methods/continuations/outcomes, retained model/Research results and non-secret configuration metadata.

Remote/controller handles alone do not back up their bytes. Search indexes are rebuildable; exact sources and paid model output are not.

Pause new mutations/dispatch, drain short transactions, freeze backup set, export through Store-owned maintenance transport, copy referenced blobs, write manifest/checksums/counts and publish completion only after all bytes succeed. Failure leaves live data intact.

### 12.3 Restore

Restore into a fresh candidate directory/database. Native import can partially apply; retry only into another empty candidate. Verify actual current/history/blob reads, apply current deletion notices and hold unfinished external jobs for reconciliation rather than redispatch.

Switch selected data directory through one durable installation configuration update under the same mutex. Keep prior data until explicit retirement. Current credentials and controller profiles are not overwritten by backup settings. Primary reads become available before optional vectors, views or learning refresh.

## 13. Control and observability

Direct controls:

- status and scoped inbox;
- inspect/open;
- pause/resume jobs;
- cancel owned queued work;
- configure projects, host adapters, disclosure defaults and selected profile names;
- correct/withdraw/erase;
- backup/restore;
- graceful shutdown.

Status is derived from actual process, configuration, jobs and retained external results. Show distinctly:

- disabled;
- waiting for automatic mode;
- profile or connection unavailable;
- destination/disclosure mismatch;
- automatic use denied;
- requested but not admitted;
- queued/sending;
- outcome unknown;
- controller result retained;
- result copied into Memory;
- decoded;
- applied;
- cleanup pending, incomplete or released;
- partial, failed, cancelled or erased.

Do not equate:

- request receipt with external admission;
- admission with completion;
- completion with retained bytes;
- retained bytes with decoded proposal;
- decoded proposal with published memory;
- published memory with external task success;
- Memory copy with release of controller input/result copies.

Missing usage/cost/account identity is unknown, not zero. Optional notification failure does not block status or control.

## 14. Implementation sequence

Write connected production code first. Run minimum relevant build/Clippy after a coherent code increment. Do not construct a large speculative test framework or force production behavior around placeholder tests. Full automated testing follows connected product implementation; the scenarios below define what the later suite must exercise.

Before each slice:

- name one integrator and exact product edge;
- reject missing configuration, stale base and duplicate owner before expensive setup;
- do not open overlapping sibling work without a terminal disposition;
- count merged product behavior and closed blockers, not generated artifacts.

### Slice 1 — Store and local lifecycle

Implement supervisor/daemon/SurrealDB ownership, configuration, capture, exact read after restart, spool, direct status/shutdown and shared revision/history path used by explicit notes/corrections.

Observable path:

```text
real event → committed observation → restart → exact open
```

### Slice 2 — Useful Base

Connect first host capture, continuation lookup/raw bounded tail, exact/full-text retrieval, explicit notes/corrections/commitments, context delivery, source open, pause/stop and Base backup/restore/erase.

Base runs with controller/model/vector/document/Research capabilities disabled.

Observable path:

```text
session A captures result or explicit lesson
→ process restart
→ relevant session B receives it
→ exact source opens
```

### Slice 3 — Controller one-shot inference owner

In `eliot-swarm-controller`, implement [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md):

- narrow `inference_client` authority and exact allowlist;
- static `InferenceConnection` and `InferenceProfile` configuration;
- canonical non-secret profile digest and `actual_destination`;
- `inference.text`, `inference.embed` and `inference.release`;
- controlled `inference_input` and `inference_result` artifacts;
- exact dedup, queued cancellation and unknown-outcome behavior;
- one Operation-backed runner;
- closed loopback text adapter first, embeddings second;
- durable public result readback;
- idempotent cleanup of both controller content copies;
- no Task/Attempt/workspace/review/ScriptRun semantics.

This is adjacent-repository production work, not a Memory-side provider stack.

### Slice 4 — First connected learning

In Memory, pin/reuse controller `swarm-client`; add one controller client, one `episode_learning` handler, disclosure reduction, exact retained request/result, digest verification, decoder, publication and release tracking.

Observable path:

```text
episode + exact recipe + disclosure
→ one controller inference Operation
→ retained and verified Memory copy
→ create/revise/no-change
→ later context consumes revision
→ controller inference_input/result released or exact cleanup gap reported
```

Exercise unknown outcome, malformed/partial output and controller restart without calling inference twice. Keep Base working with learning disabled.

### Slice 5 — Independent capability increments

Add vector retrieval, project views, documents, Research and additional hosts according to actual prerequisites. Each increment connects output to an existing reader and extends maintenance for retained data. Do not make each earlier extension a prerequisite.

### Slice 6 — Advanced improvement

Add cross-episode curation, recursive improvement, targeted diagnosis, richer disagreement/anticipation and broader integrations only after base paths work. Reuse the same jobs, revisions and context; do not create a second cognitive runtime.

### Final verification phase

After product implementation is connected, build the automated suite around the real operations above, then add concurrency, restart, erasure and optional-capability failure. Substituted provider responses verify local mapping only and do not qualify a live provider route.

Inspect actual latency, I/O, calls, retained bytes, dependencies and code size before claiming optimization. Line count is a diagnostic, not a quota or permission to compress responsibilities into an unreadable monolith.
