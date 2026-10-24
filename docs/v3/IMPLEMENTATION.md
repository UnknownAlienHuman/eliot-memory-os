# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.18 · 2026-10-24 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into runtime, modules, data and connected operations. [Cognition](COGNITION.md) defines the algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) defines the narrow Memory↔controller model boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) records checked evidence, decisions and open gaps.

Nothing here is implemented merely because it is specified. The complete target is not a prerequisite for useful Base. Build connected production slices in §14; do not construct scaffolding for later capabilities before their first real writer and consumer exist.

## 1. Runtime and first use

### 1.1 Process family

The initial Windows profile uses one executable with modes:

```text
eliot supervisor     owns the local process family
eliot daemon         serves memory operations
eliot relay ...      transient host/CLI adapter
```

The supervisor owns:

- `eliot daemon`;
- one SurrealDB server child;
- their Windows Job Object;
- restart intensity and planned shutdown.

The daemon does not supervise itself. Hosts and `eliot-swarm-controller` do not own this process family. Model/provider processes remain controller/provider concerns.

### 1.2 Data root

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
- controller endpoint and inference/embedding profile names;
- project/source disclosure defaults;
- idle timeout and automatic-work mode;
- optional document/Research tools;
- explicitly allowed cross-project reuse scopes.

It is not a generated policy database, route registry or module catalogue. Provider credentials and secret connection material stay with their owner, initially `eliot-swarm-controller`. Memory stores profile names, frozen non-secret profile identity returned by controller and external operation/result references.

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

Pending data, a completed background job or an internal poll cannot renew the interval indefinitely. Explicit shutdown does not start a final DreamCycle. Unknown external attempts remain reconcilable after restart; shutdown does not authorize a second model call.

Primary capture and exact/lexical reads become available as soon as Store is ready. They do not wait for inference, embeddings, project orientation or a graph.

## 2. Code structure

### 2.1 Start with one Rust package

Use one library package plus a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries. Split a crate only when an actual dependency, deployment or change boundary requires it.

| Module | Owns | Does not own |
|---|---|---|
| `model` | Small values crossing real module boundaries | Vendor SDKs, runtime, a universal contract catalogue |
| `store` | Schema/migrations, fixed queries, atomic writes, exact reads and blobs | Interpretation, host protocol, model selection |
| `memory` | Semantic item operations, revisions and source links | Raw provider or host I/O |
| `context` | Decision-frame retrieval, applicability, relation expansion and packing | A second Store or model scheduler |
| `learning` | Purpose-specific request builders, disclosure reduction, decoders, reducers and publication proposals | Job claims, provider retries or direct external I/O |
| `jobs` | Due selection, claim/reclaim, finite handler dispatch, reconciliation and result application | Semantic algorithms duplicated from handlers |
| `adapters::host` | Native host event normalization and context delivery | Task ownership or memory policy |
| `adapters::inference` | `TextInferenceClient` over controller `inference.text` and result release/readback | Memory job state, publication, provider credentials or route planning |
| `adapters::embedding` | `EmbeddingClient` over controller `inference.embed` | Semantic revisions or a second vector database |
| `adapters::source` | Document, structure and Research translation | Another memory service |
| `control` | Status/inbox, configuration, maintenance and owner commands | A general policy engine |
| `runtime` | Composition, process/task lifetime and shutdown | Cognitive algorithms or a global mutable service locator |

Dependency direction:

```text
model + pure transformations          -> no I/O imports
store + outbound adapters             -> model and their external dependencies
application operations                -> model, Store API and required narrow clients
host / CLI / MCP surfaces             -> application operations
runtime composition                   -> concrete constructors and startup/shutdown
```

Keep SDK connections, SQL helpers and module internals private. Internal calls share typed Rust values; serialize only at storage, process or network boundaries. Add a trait at a real interchangeable I/O boundary, not for every table or function.

### 2.2 Base and additive capabilities

**Base** provides capture, explicit notes/corrections/commitments, exact and lexical retrieval, addressed current work, bounded context/open, restart/spool and maintenance for retained Base data. It starts without controller, model, encoder, converter or Research credentials.

| Capability | Additional dependency | Existing consumer |
|---|---|---|
| First learning | Base observations, one `TextInferenceClient`, one recipe | Ordinary `memory`, `context` and `open` |
| Vector retrieval | Base text revisions and one `EmbeddingClient` | Additional candidate arm in `context` |
| Project understanding | Base source access and configured structure tool; inference only for explanations | Versioned project views |
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

It does not automatically add a process, manifest family, event bus, scheduler, database, context compiler or plugin platform.

Finite expensive work uses the existing `job` runner. A long-lived task exists only when it must retain an actual resource or continuously receive input. Runtime plugin discovery, dynamic Rust ABI, WASM packaging and hot-generation machinery are not selected.

### 2.4 Optional means optional

Construct an optional client only when configured. Do not probe every remote service on daemon startup. A capability failure stays inside that capability; Base remains available.

Disabling a capability stops new dispatch for its purposes. Pending work waits rather than being repeatedly claimed and failed. Already dispatched work retains exact request/result identity until reconciled, cancelled or erased. Re-enabling can continue selected pending work or a finite backfill; ordinary reads do not wait for it.

A runtime switch does not remove compiled dependencies. Use Cargo features only when omitting a heavy optional dependency materially reduces the build or package. Do not add a negative `lite` feature that changes record meaning.

## 3. Application surface and work binding

All host surfaces call the same application operations:

| Operation | Result |
|---|---|
| `attach(workspace, session)` | Project/workspace binding, continuation key, gaps and actual capabilities |
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

A tool result, an agent report about it, a prepared packet and an observed handoff are distinct observations. Replays compare source content, not receipt time.

### 4.3 `memory`

Holds the current editorial revision of a semantic item.

Key fields:

- `id`, `origin_project`, `reuse_scope`, `revision`, `kind`;
- for methods: `method_role = advice | processing` and implemented `processing_purpose`;
- optional exact `address_kind` and `address_key`;
- `content`, `search_text`, exact cues and advisory aliases;
- disclosure class and source-derived disclosure limitations;
- subject/aspect/perspective;
- material applicability conditions/exceptions and optional typed selectors;
- validity interval;
- support limitations separately from retrieval exposure and advisory influence;
- optional commitment state;
- optional embedding vector, effective space and encoded representation identity;
- created/updated times.

One complete exact address has at most one current item. An unaddressed note needs no address. A source project is not a reuse audience, and reuse scope does not widen disclosure.

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
- first queued/due time, retry and waiting/error reason;
- frozen observation IDs/segments or per-stream ranges;
- input memory IDs/revisions;
- selected processing method ID/revision;
- claim and expiry;
- configured execution limits;
- reduced disclosure class;
- selected inference/embedding profile name;
- exact saved external request or blob reference and digest;
- external operation/request/result references;
- frozen non-secret profile identity returned by controller;
- retained raw result/status/body blob and observed metadata;
- controller result-release state;
- applied result handles, covered input, remaining/unavailable portions;
- explicit no-change, partial, unknown or failure disposition.

One `(project, purpose, target_key)` has at most one active job and one coalesced pending successor. Active includes waiting for or reconciling a dispatched external request. Completed history does not occupy the slot.

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

Store is private application code using the official SurrealDB SDK and fixed parameterized queries. Network, model, document and Research calls never run inside a database transaction.

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

Capture does not call a model. Packet/status/read/claim-renewal/result-release/embedding-completion events do not automatically become new experience. A structured correction uses the atomic path in §5.3.

If Store is unavailable, durably publish a complete spool command under the same source identity. Report `staged` only after bytes are saved. Replay uses the same operation and deletes the spool entry only after primary readback.

### 5.2 `claim_due_job`

Select only work whose handler is present, enabled and eligible for configured automatic mode. Waiting for idle time, a permitted inference profile, disclosure-compatible route or resume is not a failed attempt.

In one short transaction:

1. select a due target fairly;
2. move its pending row into the active slot;
3. freeze finite inputs;
4. set claim/expiry;
5. resolve and freeze exact processing method revision when required;
6. reduce actual selected input to one disclosure class;
7. select the configured profile name, without resolving provider secrets;
8. commit.

The worker reads inputs and invokes external clients outside the transaction. Reclaiming an expired worker claim keeps the same job, frozen input, saved request and external references. It first reads saved/local/remote result state; expiry is not permission to buy another model call.

Automatic work additionally requires both Memory automatic mode and `allow_automatic` in the selected controller profile. Neither setting silently enables the other.

### 5.3 `publish_revision`

All semantic mutation uses one internal function within the caller-owned transaction. Inputs are create/update target, expected revision, complete new semantic fields, actual source handles and revision-aware links/grounds.

The function:

1. checks addressed expected revision;
2. archives the prior current revision;
3. creates or updates the item;
4. replaces current-revision links with the explicitly supplied set;
5. records scoped replacement/withdrawal when requested;
6. returns the exact new version handle.

A direct structured correction saves its observation, applies the edit and saves the mutation result in the same transaction. Replay returns the original result even if later edits exist. A stale first application is retained as an unapplied correction; it does not overwrite newer work.

### 5.4 `apply_job_result`

Persist exact external result bytes/status/limits on the job before parsing or publication releases temporary output. Verify result digest/length against controller receipt before decode. An erasure-cancelled job cannot reintroduce deleted data.

For one dependent semantic publication, one transaction:

1. return existing applied result on replay;
2. verify current claim and expected target revisions;
3. publish changes through `publish_revision`;
4. save exact handles/no-change and actual input coverage;
5. finish the job and release its active slot;
6. retain or create any necessary successor;
7. commit.

A database conflict reuses the retained proposal. A genuine target change records the proposal as not applied and coalesces explicit reconciliation; it does not silently call the model again.

Independent embedding results may be applied in bounded groups. One stale item does not discard valid vectors for other inputs. Embedding completion changes derived fields only and creates no semantic revision.

Controller result release is a separate idempotent cleanup step after Memory has durably stored and verified the exact body. Cleanup failure does not undo a published lesson, but remains visible and blocks a claim of complete erasure for that controlled duplicate.

### 5.5 `find_context`

Run available candidate arms independently:

- direct handles and exact IDs;
- exact continuation address;
- exact cues;
- full-text search;
- compatible vector search when enabled and available;
- scoped alternatives and typed relations;
- local and eligible reusable advice methods.

Apply project/workspace/task eligibility before each arm's limit. Do not retrieve global top-k and discard other projects afterward. Internal processing recipes are selected by job purpose, not injected as task advice.

Union version handles, then load bounded metadata/previews, applicability, material exceptions and only selected bodies/ranges. `LIMIT` on rows does not limit body bytes. Do not hold a Store transaction across query embedding or host handoff.

Return packet ID, rendered content, exact item/method revisions, source handles and gaps. Recording attribution failure does not suppress useful context.

### 5.6 `open_handle`

Open current/historical memory, observation, source segment/blob, bounded stream/episode page, project view, job/result status or recorded context packet.

The requested immutable version remains constant across pages. Missing content is missing; do not substitute a newer URL, file or revision. Default reads are bounded. Return actual range, retained total when known, next continuation and capture completeness. Byte, character, line, page and cell coordinates are not interchangeable.

Exact source opening does not depend on search-index readiness and never buys another OCR, model or source execution.

## 6. Host capture and delivery

### 6.1 First adapter: Claude Code

Use a command hook calling `eliot relay`, not a model-based hook.

| Native event | Eliot action |
|---|---|
| `SessionStart`, `UserPromptSubmit` | Attach and request current orientation |
| `SubagentStart` | Address child by actual session/agent ID and offer initial child context |
| `PostToolUse`, `PostToolUseFailure` | Capture exact call input and structured result/error under `tool_use_id` |
| `PostToolBatch` when available | Relate model-visible representations to the same calls and request one packet at the next model boundary |
| `Stop`, `SubagentStop`, `StopFailure` | Capture supplied closing text/error and make relevant background work due; do not wake the agent for bookkeeping |
| `PostCompact` when available | Record the host-produced view, not independent evidence of every underlying event |

Preserve native session, agent, prompt, tool and transcript identities when supplied. Role names are not instance IDs. Keep structured tool result and model-visible batch representation distinct. Missing or empty final text is not replaced with an older transcript tail.

The relay synchronously commits or durably stages the event, then exits. It does not wait for learning, transcript synthesis or whole-service readiness. Ordinary memory hooks do not block tools or emit permission decisions.

### 6.2 Delivery

Build context before optional diagnostics. Distinguish packet preparation, local write/handoff, observed host acceptance and later use.

For Claude, output only valid event-specific JSON on stdout; diagnostics stay elsewhere. Fit essential claims and exceptions within the host's actual string limit and expose detail through `open`. A host-generated overflow file preview is not proof the complete packet reached the model.

Use one selected boundary for a full packet, not duplicate full packets at every hook. Initial child orientation may use `SubagentStart`; later advice waits for a real supported boundary. Background learning remains stored if no next boundary occurs.

Record exact rendered revisions and recipient. Without native evidence, offered context is not confirmed adherence. Do not demand an extra agent acknowledgement form to manufacture correlation.

## 7. Current work, retrieval and packing

### 7.1 Decision frame

A decision frame contains available:

- project/workspace and exact continuation key;
- native task/session identity;
- branch/HEAD/resource conditions separately;
- current user request, goal and criteria;
- explicit retrieval question and typed cues;
- relevant decision/historical time;
- tool/model profile;
- context incarnation;
- output and input/read/work budgets.

Unknown fields remain unknown. Generated summaries cannot replace sourced goals.

### 7.2 Continuation before similarity

Context construction order:

1. open addressed continuation;
2. read bounded relevant observations outside its recorded per-stream coverage;
3. apply explicit constraints, corrections and open commitments;
4. retrieve applicable methods and episodes;
5. resolve alternatives and material dissent;
6. add optional project view/relation expansion;
7. pack the decision.

A continuation is an ordinary versioned memory item recording goal, plan, completed work, abandoned approaches, open commitments, last results, next step, represented streams/segments and gaps. It never replaces original observations.

For a large unsummarized tail, freeze an upper sequence per relevant stream, read a finite metadata/excerpt page across streams, union exact linked call/results and indexed hits, then open selected ranges within aggregate budget. Old exact corrections/commitments use addressed reads rather than newest-N arrival. Read cursors are not learning coverage.

### 7.3 Search

Base uses native exact/full-text search. Preserve typed exact cues for paths, symbols, commands, versions and error codes.

Use one focused natural-language query from explicit question, current request, goal or error, not the entire transcript. A broad OR candidate arm improves recall; applicability and packing remove noise. Exact technical identity does not depend on token conjunction.

The full-text index covers the indexed field, not the entire blob behind it. Long text may produce addressable source segments through finite deterministic processing. Until then, empty excerpt search does not prove absence from unindexed bytes.

The vector arm adds candidates to the same pipeline. Automatic host context never waits for cold encoder/network work. Explicit semantic retrieval may obtain one query vector within its request budget; failure returns useful local results plus a missing-arm gap.

### 7.4 Packing

Build whole decision units:

1. addressed current work and explicit corrections outside semantic ranking;
2. selected claim/method plus material conditions, counterexamples and replacement links;
3. relevant episode action/result/repair/check;
4. source handles and specific gaps.

Pack within actual rendered budget. Prefer current corrections and decision-changing limitations over optional background. Do not drop negation, version or exception to make a recommendation fit. If a unit cannot fit faithfully, return a qualified short form plus handle or omit the whole unit with a stated gap.

Candidate examination, bytes read and rendered packet size are separate budgets.

## 8. Sources and project understanding

### 8.1 Project views

Use configured structure tools and direct source reads, not an embedded parser platform. Views retain question, examined scope/revisions, answer, source handles and gaps. Refresh only affected views; serve the prior qualified view while refresh fails or is pending.

The same mechanism reads Eliot's Architecture, implementation and observed runtime as distinct sources. No self-model service or conformance database is added.

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

A correction, refutation, relevant live-condition change or erasure records its actual scope and coalesces a follow-up job in the primary mutation. Use reverse grounding indexes to page affected conclusion revisions. Load each conclusion's own complete groups; do not walk navigation links as evidence or rebuild every project view.

Known qualification reaches context before a replacement explanation is ready. Model work may help interpret an unresolved relation, but no model call is needed to find declared affected links or a broken required group. Cycles supply no independent support. Keep traversal finite and resumable in the existing job.

## 9. External inference, embeddings and Research

### 9.1 Normative inference boundary

The shared cross-repository contract is [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md). Memory exposes these narrow internal client traits:

```rust
trait TextInferenceClient {
    async fn infer(&self, request: TextRequest) -> TextResult;
    async fn release_result(&self, operation: ExternalOperationRef) -> ReleaseResult;
}

trait EmbeddingClient {
    async fn embed(&self, request: EmbeddingRequest) -> EmbeddingResult;
}
```

The initial adapters call controller:

```text
inference.text
inference.embed
inference.result.release
operation.get
artifact.get
artifact.read
```

The controller route is not a controller Task/Attempt and does not own Memory job state, recipe, source coverage, decoding or publication.

### 9.2 Inference profile and disclosure

Controller configuration owns a small static `InferenceProfile`. Memory references it by name; controller freezes the non-secret snapshot identity at admission.

The profile contains only:

- adapter/connection reference and requested model;
- locality: `local | external`;
- `allow_automatic`;
- finite input/output/time/concurrency limits;
- supported response formats;
- explicit fallback policy, initially none.

Memory reduces the actual supplied content to:

```text
local_only | external_allowed
```

Reduction is deterministic:

- project configuration supplies a default;
- a source may be stricter;
- a derived item remains as strict as content it still contains or reveals;
- mixed input uses the strictest contributing class;
- reuse scope does not widen disclosure;
- `local_only` requires a local profile.

Do not silently omit protected material to make an external profile pass. If required material and selected profile are incompatible, the job waits or fails with a disclosure/profile gap. It is not no-change and does not mark input processed.

Automatic execution requires both Memory automatic mode and profile `allow_automatic = true`. Missing usage or cost remains unknown, never zero. No silent switch of provider, model, account, locality, retention or billing path is allowed.

### 9.3 Request, result and release lifecycle

Before external I/O, save on the existing job:

- stable request key/client request ID;
- selected profile name;
- reduced disclosure and explicit/automatic origin;
- exact prompt/input bytes or immutable blob reference and digest;
- finite requested limits/format;
- selected recipe/source revisions.

Call controller outside the Store transaction.

Deduplication key is:

```text
authenticated caller + client_request_id + canonical method parameters
```

An exact replay returns the original Operation/admission state. Different parameters under the same ID are rejected.

If admission reply is lost, repeat the identical request to the same controller as the same client. Once Operation ID exists, use `operation.get` and artifact readback. A connection or timeout after bytes may have been sent remains `unknown` unless native idempotency/readback resolves it. A new request ID is not recovery.

For `complete` or usable `partial`:

1. read exact artifact ranges;
2. verify byte length and digest from public receipt;
3. save exact body in Memory blob/job;
4. decode and publish through §5.4;
5. call idempotent `inference.result.release`;
6. retain cleanup status.

Controller release removes operation-owned content/staging only after Memory durable-copy acknowledgement and retains a bounded text-free receipt. Release failure is visible but does not invalidate already verified Memory bytes.

Cancellation stops waiting or a not-yet-admitted attempt when possible. It does not prove a provider call did not occur and does not erase a completed result. Erasure must include Memory copies and any still-controlled controller duplicate.

### 9.4 Embeddings

`inference.embed` returns:

```text
effective vector space
+ role: query | document
+ one vector or error per input_key
+ observed usage/limits
```

Controller owns provider-specific splitting, credentials and model invocation. Memory maps each result to exact item/revision/representation. Missing, duplicate or unresolvable positions are errors, not zero vectors or shifted assignment.

Coalesce compatible inputs, respect actual token/byte/count limits, preserve successful sub-batches and retry only unresolved items under the same unknown-outcome rules. Applying a vector updates derived fields only. A content revision invalidates old vector in the primary mutation; text remains lexically usable.

One initial vector space is enough. Changing to an incompatible space pauses only vector dispatch/query, rebuilds derived vectors in finite pages and leaves Base reads available.

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
- text actually supplied to inference;
- successfully processed coverage.

An unexpanded handle, trimmed body or omitted segment is not covered. Complete no-change covers only the supplied input and purpose. Deferred material goes to pending successor. There is no global processed bit.

### 10.2 Interpret, correct or keep

A normal learning job receives relevant episode input, explicit feedback, a small set of related items and the exact processing recipe. It may create a provisional claim/method, revise a named item/view, identify conflict/unknown or keep/no-change.

A direct structured correction uses §5.3 without inference.

### 10.3 Processing method consumer

Ship real default recipe text for each implemented text purpose as application assets. First enablement for a project saves the needed default as an ordinary processing method at a stable purpose address. Do not seed future or unimplemented purposes.

When claiming a text job, freeze selected method ID/revision with inputs. The request builder opens that exact body. Reclaimed work retains the same method and saved request. Software update does not overwrite a learned or user-edited method with bundled default.

Textual improvement changes the addressed processing method through ordinary revision. Later jobs consume the new revision; running work keeps frozen input. A method with no real consumer is stored knowledge, not implemented self-improvement.

### 10.4 Outcome feedback

Retain source events in observations. Reduce attributable feedback into ordinary versioned outcome items addressed by exact method revision, actual attempt/execution and criterion/checked target.

A tool result and agent report about it may both be saved but are one attempt. A packet proves offered context, not adherence. Unknown method/attempt association remains unknown rather than crediting every method shown.

Two consumers:

- `context` loads relevant limitations/counterexamples with selected advice;
- `learning` may revise the addressed method when new feedback can change the next decision.

### 10.5 Automatic timing without another scheduler

Keep capability enablement separate from `automatic = off | idle | background`.

| Setting | Behavior |
|---|---|
| Module disabled | No new explicit/automatic work from that producer; retained content remains readable; existing external attempts remain reconcilable |
| Enabled, automatic off | Explicit `dream` works; no automatic inference or reminders to re-enable it |
| Enabled, automatic idle | Coalesced work may run after observed foreground quiet and during finite drain |
| Enabled, automatic background | Same runner progresses under configured capacity while capture/control/context retain priority |

A selected inference profile may independently refuse automatic use. In that case explicit work remains available if otherwise permitted; automatic jobs wait with a specific reason.

New relevant input coalesces one pending target and preserves first queued time. A quiet delay batches nearby events; maximum age makes it due but does not override disabled, disclosure-incompatible or idle-only policy. Claim one finite slice; leave remainder pending.

During foreground return, stop starting new idle work. Already admitted work may finish or retain uncertainty; do not cancel and repurchase on every keystroke. A stopped process resumes pending jobs at next use. Optional unattended windows are an external OS/host invocation of the same finite maintenance operation, not another scheduler inside Eliot.

Curation output must reach ordinary context/open/method consumers. An unread maintenance report is not product result.

## 11. Consolidation, disagreement and commitments

### 11.1 Consolidation without destructive identity merge

Distinguish:

- source-event replay;
- packet-local grouping;
- same-item revision;
- new synthesis from several episodes;
- correction or split of an erroneous synthesis.

A broader pattern normally creates a separate provisional claim or method linked to exact sources. It does not delete or union source identities. A false merge narrows or splits the derived item while original episodes and historical handles remain.

### 11.2 Disagreement and anticipation

Represent rival explanations as ordinary claims with grounds and counterevidence. Select the cheapest useful discriminating observation; voting is not evidence.

A prediction records trigger, expected observation, material conditions, useful check/action and reconsideration/expiry condition. Expiry does not fabricate outcome or close a commitment.

### 11.3 Commitments

Commitments are ordinary scoped memory items with state, recipient/owner, optional due time and source. Context and inbox read them outside similarity ranking.

Showing, acknowledging or passing a due date does not resolve a commitment. Resolution follows a matching observed result or explicit owner change. Notifications are optional and do not create another task manager.

### 11.4 Self-diagnosis

Ask which connected step failed:

- capture;
- inference/profile/disclosure;
- result readback or cleanup;
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

For erasure, record exact selected scope/command ID as a small text-free durable notice before removal. Cancel affected pending/active jobs, settle local writers and prevent late external results or spool replay from reintroducing erased content.

Page through actual references and remove controlled observations, memory/current/history, conversion assets, source excerpts, packet copies, job input/output blobs, staged files and content-bearing links in scope. Remove or replace controlled backups containing the data.

For inference jobs, erasure also:

1. cancels or marks the external Operation abandoned where possible;
2. invokes `inference.result.release` for retained controller result copies;
3. records cleanup gap when controller copy cannot be confirmed removed;
4. prevents late result ingestion after erasure.

Already delivered provider copies are an external boundary. A controlled controller artifact is not external merely because it is in another local service. Do not report complete erase while it remains.

### 12.2 Backup

Use native logical database export plus referenced immutable blobs and finite selected spool entries. Include schema, all six tables, explicit history/links, methods/continuations/outcomes, retained model/Research results and non-secret configuration metadata.

Remote handles alone do not back up remote bytes. Search indexes are rebuildable; exact sources and paid model output are not.

Pause new mutations/dispatch, drain short transactions, freeze backup set, export through Store-owned maintenance transport, copy referenced blobs, write manifest/checksums/counts and publish completion only after all bytes succeed. Failure leaves live data intact.

### 12.3 Restore

Restore into a fresh candidate directory/database. Native import can partially apply; retry only into another empty candidate. Verify actual current/history/blob reads, apply current deletion notices and hold unfinished external jobs for reconciliation rather than redispatch.

Switch selected data directory through one durable installation configuration update under the same mutex. Keep prior data until explicit retirement. Current credentials and controller profiles are not overwritten by backup settings. Primary reads become available before optional vectors, views or learning refresh.

## 13. Control and observability

Direct controls:

- status and scoped inbox;
- inspect/open;
- pause/resume jobs;
- cancel owned work;
- configure projects, host adapters, disclosure defaults and profile names;
- correct/withdraw/erase;
- backup/restore;
- graceful shutdown.

Status is derived from actual process, configuration, jobs and retained external results. Show distinctly:

- disabled;
- waiting for automatic mode;
- waiting for compatible inference profile;
- disclosure blocked;
- admitted/running;
- result retained remotely;
- result copied locally;
- cleanup pending or released;
- partial;
- unknown;
- failed;
- applied.

Do not equate:

- request receipt with external admission;
- admission with completion;
- completion with retained bytes;
- retained bytes with decoded proposal;
- decoded proposal with published memory;
- published memory with external task success;
- local copy with cleanup of the controller duplicate.

Missing usage/cost is unknown, not zero. Optional notification failure does not block status or control.

## 14. Implementation sequence

Write connected production code first. Run minimum relevant build/Clippy after a coherent code increment. Do not construct a large test framework or force production behavior around speculative tests. Full automated testing follows the completed product implementation; the scenarios below define what that later suite must exercise.

### Slice 1 — Store and local lifecycle

Implement supervisor/daemon/SurrealDB ownership, configuration, capture, exact read after restart, spool, direct status/shutdown and shared revision/history path used by explicit notes/corrections.

Observable path:

```text
real event → committed observation → restart → exact open
```

### Slice 2 — Useful Base

Connect first host capture, continuation lookup/raw bounded tail, exact/full-text retrieval, explicit notes/corrections/commitments, context delivery, source open, pause/stop and Base backup/restore/erase.

Base runs with model/vector/document/Research capabilities disabled.

Observable product path:

```text
session A captures result or explicit lesson
→ process restart
→ relevant session B receives it
→ exact source opens
```

### Slice 3 — Controller inference owner

In `eliot-swarm-controller`, implement [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md):

- static `InferenceProfile`;
- `inference.text`;
- `inference.embed`;
- exact dedup and unknown-outcome behavior;
- durable public result artifact;
- `inference.result.release`;
- no Task/Attempt/workspace/review semantics.

This is adjacent-repository production work, not a Memory-side provider stack.

### Slice 4 — First connected learning

In Memory, add `ControllerTextInferenceClient`, one `episode_learning` handler, disclosure reduction, retained request/result, digest verification, decoder, publication and release acknowledgement.

Observable path:

```text
episode + exact recipe + disclosure
→ one controller inference operation
→ retained and verified body
→ create/revise/no-change
→ next context consumes revision
→ controller duplicate released
```

Exercise unknown outcome, malformed/partial output and controller restart without calling inference twice. Keep Base working with learning disabled.

### Slice 5 — Independent capability increments

Add vector retrieval, project views, documents, Research and additional hosts according to actual prerequisites. Each increment connects output to an existing reader and extends maintenance for retained data. Do not make each earlier extension a prerequisite.

### Slice 6 — Advanced improvement

Add cross-episode curation, recursive improvement, targeted diagnosis, richer disagreement/anticipation and broader integrations only after base paths work. Reuse same jobs, revisions and context; do not create a second cognitive runtime.

### Final verification phase

After product implementation is connected, build the automated suite around real production operations. Start with observable paths above, then concurrency, restart, erasure and optional-module failure. Use real Store/application boundaries; substituted provider responses verify local mapping only and do not qualify a live provider.

Inspect actual latency, I/O, calls, retained bytes, dependencies and code size before claiming optimization. Line count is a diagnostic, not a quota or permission to compress responsibilities into an unreadable monolith.
