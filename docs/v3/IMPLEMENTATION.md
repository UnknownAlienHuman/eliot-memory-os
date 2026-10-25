# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.21 · 2026-10-24 · concrete design for the greenfield rewrite.**

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
    pending\
    failed\
    tmp\
  deletions\
  backups\
  logs\
```

`config.toml` contains practical local settings:

- selected data directory;
- configured projects/workspaces and host binding rules;
- capture exclusions, per-event bounds and retention;
- enabled host adapters and their native executable/config paths;
- controller IPC/data root and private inference-client credential path;
- selected text/embedding profile names;
- project/source disclosure defaults;
- idle timeout and automatic-work mode;
- optional document/Research tools;
- explicitly allowed cross-project reuse scopes.

It is not a generated policy database, route registry, module catalogue or inventory denominator.

Provider connections, provider credentials, adapter IDs and `actual_destination` declarations stay with `eliot-swarm-controller`. Memory stores only selected profile names and frozen non-secret execution identity returned by controller.

### 1.3 Demand start, spool recovery and shutdown

The supervisor holds a named mutex for the stable installation root throughout startup, operation and shutdown. A relay connects first; if no endpoint answers, it starts a supervisor candidate and waits. Only the candidate owning the mutex starts children. An existing owner with an unready daemon is not permission to launch another database.

Create SurrealDB and daemon children suspended, assign them to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resume them. If assignment fails, terminate the still-suspended child. Start and verify the configured database connection before reporting Store ready. Do not kill unrelated processes by name or port.

Restarting a failed daemon does not restart a healthy database. If the supervisor dies, owned children terminate with the Job Object; the next demand start opens existing data.

After Store is ready, the daemon begins bounded fair replay of `spool/pending`. Replay does not block primary exact reads or new capture indefinitely. It pages entries in stable order, processes a finite batch, then yields to foreground work. Corrupt or permanently rejected entries move to `spool/failed`; transient Store failure leaves them pending. A replayed command uses the same application `capture` operation and command ID as direct delivery.

Before normal idle shutdown:

1. stop new external dispatch;
2. stop claiming new background work;
3. allow one finite drain interval for already eligible work and a bounded spool batch;
4. persist collected results and progress;
5. stop daemon and database;
6. wait for exit and release the mutex.

Pending spool data, a completed background job or an internal poll cannot renew the interval indefinitely. Explicit shutdown does not start a final Dreamer cycle. Unknown controller/provider outcomes remain reconcilable after restart; shutdown does not authorize another request ID.

Primary capture and exact/lexical reads become available as soon as Store is ready. They do not wait for controller inference, embeddings, project orientation, graph refresh or complete spool drain.

## 2. Code structure

### 2.1 Start with one Rust package

Use one library package plus a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries. Split a crate only when an actual dependency, deployment or independently changing boundary requires it.

| Module | Owns | Does not own |
|---|---|---|
| `model` | Small values crossing real internal boundaries | Vendor SDKs, runtime, universal contract catalogue |
| `store` | Schema/migrations, fixed queries, atomic writes, exact reads and blobs | Interpretation, host protocol, model selection |
| `memory` | Semantic item operations, revisions, history, grounds and source links | Raw host/provider I/O |
| `context` | Continuation reconstruction, candidate selection, applicability, relation expansion and packing | Second Store or model scheduler |
| `learning` | Purpose-specific input selection, request builders, disclosure reduction, decoders, reducers and publication proposals | Job claims, provider retries or credentials |
| `vectors` | Vector-space identity, result mapping and vector candidate arm | Provider transport or second vector database |
| `jobs` | Due selection, claim/reclaim, finite handler dispatch, reconciliation and result application | Semantic algorithms duplicated from handlers |
| `adapters::host` | Native host event decoding, `CaptureCommand` construction and context emission | Task ownership, semantic publication or Store status invention |
| `adapters::controller` | Authenticated controller IPC, inference methods, Operation/artifact readback, queued cancel and release | Memory job state, publication, provider credentials or route planning |
| `adapters::source` | Document, structure and Research translation | Another memory service |
| `spool` | Atomic pending-command publication, bounded replay inventory and failed quarantine | A second canonical event store |
| `control` | Status/inbox, configuration, maintenance and owner commands | General policy engine |
| `runtime` | Composition, process/task lifetime and shutdown | Cognitive algorithms or global mutable service locator |

Dependency direction:

```text
model + pure transformations          -> no I/O imports
store + outbound adapters + spool     -> model and external dependencies
application operations                -> model, Store API and narrow clients
host / CLI / MCP surfaces             -> application operations
runtime composition                   -> concrete constructors and startup/shutdown
```

Keep IPC, HTTP, SQL, host JSON and filesystem helpers private. Internal calls share typed Rust values; serialize only at storage, process or network boundaries. Add a trait at a real interchangeable I/O boundary, not for every table or function.

### 2.2 Base and additive capabilities

**Base** provides capture, explicit notes/corrections/commitments, exact and lexical retrieval, addressed current work, bounded context/open, restart/spool and maintenance for retained Base data. It starts without controller, model, encoder, converter or Research credentials.

| Capability | Additional dependency | Existing consumer |
|---|---|---|
| First Claude host | One relay process/hook configuration | `capture`, `context`, `open` |
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

1. a narrow external client or host decoder when necessary;
2. one application handler or foreground operation;
3. Store fields/indexes introduced by its first real writer;
4. its real reader/consumer;
5. maintenance for the retained data it adds.

It does not automatically add a process, manifest family, event bus, scheduler, database, context compiler, plugin platform, proof family or generated inventory.

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
| `capture(command)` | `committed`, `staged`, `unknown` or `rejected`, plus existing observation identity when known |
| `context(frame, budget, retrieval=local)` | Packet ID, rendered text, exact included revisions, handles and gaps |
| `open(handle, read_context, range?)` | Exact item/source/representation page, relation descriptors and continuation |
| `record_outcome(report)` | Captured observed result or explicitly sourced report |
| `dream(request)` | Finite interpretation/research/improvement job when its handler is configured |
| `control(command)` | Status/inbox, configure, pause/cancel, correct, withdraw/erase, backup/restore or shutdown |

`record_outcome` reuses capture. An unavailable capability fails specifically; it does not return successful empty output.

### 3.1 Bind work without a scope platform

Configuration owns stable project/workspace IDs and their current roots or resource selectors. A project may be a repository, directory, document set, service or ad hoc work.

Resolve binding per request/event, not through one mutable `session.current_project`. A tool reading another root keeps that resource binding while remaining linked to the originating task. Late events and spool replay use their captured binding, not today's current directory.

Continuation addresses use project/workspace plus the actual host task identity, or the narrowest actor/session fallback. Branch, HEAD and path are observed state, not task identity. Fork and explicit transfer create explicit relations; they do not silently rename or merge interleaved work.

Missing association remains a gap. Capture under an ad hoc/session scope rather than mixing candidate projects or blocking all input until a complete survey exists.

### 3.2 `CaptureCommand`

The relay constructs one complete command before any IPC attempt:

```text
command_id                 relay-generated occurrence/idempotency key
project/workspace binding  exact or explicit unresolved/ad-hoc scope
source_kind                host and native event family
source_native_id           stable stream/session identity
native_event_key           tool_use_id/message_id/agent_id/etc. when supplied
event_kind                 normalized finite enum
occurrence_time            native time and precision when supplied
receipt_time               assigned by receiving owner
body | blob                 exact accepted source bytes
body_length + sha256        verification, not occurrence identity
search_excerpt              bounded derived projection
locator                     transcript/path/url/tool/resource coordinates
disclosure                  local_only | external_allowed
capture_limit               exact host/relay truncation or omission facts
relations                   call/result/parent/task/resource facts supplied by host
```

The command is immutable after first durable publication. Direct call and spool replay use identical serialized bytes and command ID.

A digest collision or same digest on another command does not merge occurrences. Replaying the same command ID with different bytes is a conflict.

Capture exclusions run before command publication. Accepted body bytes remain exact within the declared bound. Search excerpts and extracted fields do not replace the body. A generic field-name sanitizer may not silently erase URLs, endpoints, paths or final messages; a configured secret redaction is explicit in `capture_limit` and locator metadata.

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
- source `command_id` and optional native event key;
- occurrence and receipt times with preserved uncertainty;
- `kind`, exact body or `blob_ref`, body length/digest and bounded searchable excerpt;
- disclosure class: `local_only | external_allowed`;
- captured workspace/task/session/call/parent/resource/version facts;
- continuation and packet references when present;
- source locator and explicit capture limitation;
- exact correction outcome/version handles for structured correction.

Unique identities:

```text
(project, stream, event_key)
(project, command_id)
```

When a native event key is absent, `event_key = command_id`. Identical replay returns the saved observation/result. Reusing one key with different digest/length is a conflict. Different keys with equal bytes remain distinct observations.

A tool result, an agent report about it, a prepared packet and an observed handoff are distinct observations. Replays compare source identity and bytes, not receipt time.

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

A version handle is `(item_id, revision)`. Exact historical read never falls back to latest revision. Current read never resurrects a historical row after deletion.

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
- frozen profile digest, adapter ID, connection digest and `actual_destination`;
- controller result artifact reference, length and digest when present;
- retained Memory raw result/blob and requested/observed metadata;
- controller input-copy state;
- controller result-copy state;
- release Operation ID, release disposition and aggregate cleanup state;
- decoded proposal/no-change/partial/failure state;
- applied result handles, covered input and remaining/unavailable portions.

Each controller copy state is one of:

```text
not_created
retained
cleanup_pending
removed
already_absent
mismatch
unknown
```

Aggregate cleanup state is derived as `retained | cleanup_pending | cleanup_incomplete | released`; it does not hide which copy remains.

One `(project, purpose, target_key)` has at most one active job and one coalesced pending successor. Active includes waiting for or reconciling an admitted external request. Completed history does not occupy the slot.

### 4.7 Blobs, locators and packet records

Large source bytes, prompts, packets and results live under `blobs/`; rows keep opaque references and digests. Save bytes before committing a row that refers to them. Cleanup may remove unreferenced temporary files later; a committed row must never point to bytes that were never saved.

A rendered context packet does not receive a seventh primary table. Record it as an Eliot application observation/blob with:

- packet ID and rendered digest;
- project/workspace/task/session address;
- budget and rendering limits;
- exact included item/source revisions;
- omissions and gaps;
- prepared time;
- host emission result when observed.

Use `link` rows for packet inclusion and observed handoff/action association.

Locators are format-specific and claim only supplied precision:

- code: workspace, captured source identity/version, path and line/symbol range;
- document/PDF: captured source, saved conversion identity and element/page/region when available;
- spreadsheet: source/version, sheet and range;
- image: source/version and region;
- transcript/media: stream/session and event/turn/time range;
- web/research: captured representation/revision and passage range;
- service/runtime: configured environment, actual run/instance identity and observation time.

Dirty/untracked code is cited by retained bytes or retained range, not by HEAD alone. Similarity may suggest continuity but does not rewrite old locators.

### 4.8 Spool command format

A pending spool file contains exactly one versioned `CaptureCommand` plus a small envelope:

```text
schema_version
command bytes/digest
published_at
replay_attempt_count
last bounded non-content error class, when rewritten by daemon
```

The pending filename is derived from command ID, not body hash or wall-clock time alone. Contents are authoritative; filename is navigation.

There is no `committed` spool archive. Canonical committed content is in Store/blob ownership. Failed quarantine may retain the command only when needed for owner inspection or manual retry; retention is bounded and governed by capture/erasure rules.

## 5. Store and spool operations

Store is private application code using the official SurrealDB SDK and fixed parameterized queries. Network, controller, document and Research calls never run inside a database transaction.

Use native keys/indexes for identity. A preceding existence query alone does not prevent concurrent duplicates. Dependent writes use one explicit transaction; zero-row conditional updates abort rather than return an error-shaped success.

Retry database conflicts with the same saved input. A stale semantic revision is different: do not silently replace expected revision and overwrite concurrent change. For uncertain commit, read by owning observation/job identity before repeating.

### 5.1 `capture_event`

Input is one immutable `CaptureCommand`.

Before the transaction, save any referenced body blob to immutable temporary/final storage using deterministic command-owned identity. Then, in one short transaction:

1. resolve or create stream by unique native identity;
2. read by `(project, command_id)` and by `(project, stream, event_key)`;
3. return saved result for an identical replay;
4. reject `COMMAND_ID_CONFLICT` or `EVENT_KEY_CONFLICT` when identity names different length/digest/binding;
5. allocate stream intake sequence;
6. insert observation with exact body/blob identity, native relations, locator, disclosure and capture limits;
7. coalesce only implemented, enabled and necessary follow-up work;
8. commit.

After commit, read observation identity, body length/digest and binding through Store. Only matching readback returns `committed`.

Capture does not call a model. Packet/status/read/claim-renewal/release/embedding-completion events do not automatically become new experience. A structured correction uses §5.4.

### 5.2 Relay delivery and atomic spool publication

The relay serializes one command once.

Direct path:

1. call daemon `capture`;
2. accept `committed` only with matching command/observation/digest readback;
3. accept deterministic `rejected` only when daemon proves no ownership transfer;
4. treat disconnect, timeout or malformed reply after possible send as unknown.

When commit cannot be established, the relay attempts durable spool publication of the same bytes:

1. validate pending directory is owned regular directory, not symlink/reparse redirection;
2. create same-directory unique temporary regular file with create-new semantics;
3. write full bytes and flush userspace buffers;
4. synchronize file contents/metadata;
5. atomically rename to command-ID pending path without replacing a conflicting different file;
6. synchronize parent directory;
7. reopen and verify command ID/length/digest;
8. return `staged`.

If an identical pending file already exists, verify it and return `staged`. Different bytes at same command path are conflict/unknown, never overwrite.

If neither Store commit nor durable pending publication is established, return `unknown`. Do not return `forwarded` as a success state.

### 5.3 Daemon spool replay

The daemon is the only automatic replayer.

For each bounded fair batch:

1. enumerate regular files in stable order from `spool/pending`;
2. refuse symlink/reparse/unexpected file types;
3. bound file size before read;
4. parse closed schema and verify filename/command ID/body digest;
5. call the same `capture_event`;
6. on matching committed readback, remove pending file and synchronize directory;
7. on deterministic permanent rejection/corruption, atomically move to `spool/failed` with bounded sidecar reason;
8. on transient Store/process failure, retain pending and yield;
9. cap attempts/work per activation so a poison item cannot starve newer events.

Replay does not mutate command ID, occurrence time, body, locator or binding. Today’s directory or session cannot replace captured binding.

Erasure can remove matching pending/failed commands before replay. A deletion notice is checked before capture commit so an old spool entry cannot resurrect erased scope.

### 5.4 `publish_memory_revision`

For explicit correction or accepted proposal, one transaction:

1. re-read expected current revision;
2. reject stale expected revision;
3. copy old current row into `memory_history`;
4. write new current revision;
5. insert revision-specific source/grounds/replacement links;
6. settle owning command/job result;
7. coalesce only affected follow-up work;
8. commit.

IDs for proposal-created items are allocated once and retained with decoded job result so a Store retry cannot create another item.

### 5.5 `claim_due_job`

Select only work whose handler is present, enabled and eligible for configured automatic mode. Waiting for idle time, configured profile, disclosure-compatible destination or resume is not failed attempt.

In one short transaction:

1. select due target fairly;
2. move pending row into active slot;
3. freeze finite inputs;
4. set claim/expiry;
5. resolve/freeze exact processing-method revision when required;
6. reduce selected input to one disclosure class;
7. select configured profile name without resolving secrets;
8. commit.

Handler builds and saves exact request bytes/digest before controller I/O. Reclaim never rebuilds different request for admitted Operation.

### 5.6 `retain_external_result`, `apply_job_result` and cleanup state

Controller polling/artifact reading occurs outside Store transactions.

When result artifact exists, Memory reads exact ranges and verifies length/digest. One short transaction stores controller identity, exact Memory blob identity, requested/observed metadata, external status/limits and current per-copy cleanup state.

Decoding occurs from retained Memory bytes. Applying valid proposal uses one transaction with expected revisions, new history/current rows, links, coverage and job disposition. Store conflict reuses saved decoded proposal and never repeats inference.

Cleanup is separate controller operation:

- verified result copy → `inference.release(memory_copy_verified)`;
- terminal no-result → `inference.release(terminal_without_result)`;
- erasure of unresolved work → `inference.release(abandon_for_erasure)` after explicit owner decision.

Release result updates input/result copy states independently. It never rolls back valid Memory publication. Result digest mismatch blocks `memory_copy_verified`; aggregate cleanup cannot bypass it.

### 5.7 Exact `open` and coherent hydration

`open` requires one nonempty handle/locator. Empty exact selector is invalid; broad navigation uses retrieval operation.

Resolve handle type before reading:

```text
current semantic item
exact historical revision
observation/source body
immutable blob/range
converted representation/range
Research report section/citation
job/controller result copied into Memory
```

A current handle returns current revision or explicit absent/withdrawn/erased state. A version handle never falls forward. A retained representation never silently reconverts or substitutes newer source.

Read result envelope includes:

- requested handle/revision/range;
- resolved identity/representation;
- returned byte/item range and digest;
- current/history state;
- capture limitations and material qualifications;
- bounded revision-aware relation descriptors;
- expansion handles;
- next cursor when more retained bytes/descriptors exist;
- explicit missing, forbidden, erased, damaged or unsupported state.

Do not require caller to know both relation endpoints. Opening one claim/method returns descriptors for material grounds, contradictions, replacements, exceptions and outcome links, within bound. Neighbor bodies are separate exact reads.

A cursor binds object, revision, representation, range direction and read options. It is rejected against changed current revision or another object. `truncated=true` requires a continuation or explicit non-pageable gap.

For coherent item hydration, do not mix current row with links from another revision. If required set cannot be read under one snapshot, compare revision fences before/after and retry boundedly.

### 5.8 Packet retention and handoff observation

After context assembly and before host output, save rendered bytes/blob and one packet observation with exact included revisions, budget and gaps. This is not proof of host handoff.

After the host output operation returns, capture a separate handoff observation when the host contract provides a meaningful success/failure result. Link packet to handoff and later action/session where observable. Do not fabricate use/adherence.

A failed packet save prevents a claim that exact packet is replayable, but it need not block a bounded host emission if configured policy permits ephemeral context. In that case return explicit retention gap. A failed host emission leaves prepared packet readable and reports delivery gap.

### 5.9 Bounded reads

All large reads page by real byte/row limits. A row limit is not byte limit. Preserve UTF-8 boundaries and continuation handles. Long JSON, one-line logs and converted documents must not force unbounded allocation.

## 6. First Claude host adapter

### 6.1 Selected event profile

The first adapter supports:

| Native event | Captured content and binding |
|---|---|
| `SessionStart` | session identity, source (`startup/resume/clear/compact/fork` where supplied), cwd/project/workspace hints; then request actual continuation packet |
| `UserPromptSubmit` | exact accepted user prompt, session/task binding and occurrence identity; then request decision-time packet |
| `PostToolUse` | tool name, `tool_use_id`, exact accepted input/result, duration and task/resource binding |
| `PostToolUseFailure` | tool name/id/input, error, interruption/duration facts and task/resource binding |
| `Stop` | main agent `last_assistant_message`, stop metadata and session binding |
| `SubagentStop` | agent ID/type, final message and parent/session binding; handback tool payload remains tool event |
| `PostCompact` | compact summary as derived representation plus source session/trigger |
| `SessionEnd` | lifecycle boundary and reason |

The adapter retains unknown fields only inside a bounded raw source representation when configured; domain projections remain closed and explicit.

`PreToolUse`, permissions and stop/finish gates are outside first Base profile. If later added, they are separate opt-in host effects and cannot mutate memory truth merely by blocking an action.

### 6.2 Relay process behavior

A hook invocation:

1. reads one bounded JSON object from stdin;
2. validates event type and installed-version adapter compatibility;
3. constructs one immutable `CaptureCommand`;
4. attempts direct capture, then durable spool if ownership is unknown;
5. optionally requests context only on supported decision boundary;
6. writes exactly one bounded host-compatible stdout object;
7. writes diagnostics to stderr/log, never mixed into context content;
8. exits with host-appropriate code without claiming more than achieved.

Host timeout budget is split explicitly between capture and context. Capture may return `staged` while context times out. Context failure cannot convert committed/staged capture to total failure in internal state.

### 6.3 Context output

For `SessionStart` and `UserPromptSubmit`, successful context result contains rendered packet text through the host-supported channel. It may include a bounded status prefix only when status is clearly separate from memory content.

If no useful context exists, return explicit no-useful-context/gap according to host contract; do not inject generic ceremony. If packet generation failed, return bounded failure/gap and preserve explicit retrieval path.

A phrase such as “event spooled” is never the context packet.

### 6.4 Installed-version qualification

Before enabling adapter by default, record:

- installed Claude Code version;
- actual hook event names accepted;
- actual input payload samples with secrets removed but structure preserved;
- available final-message and compact-summary fields;
- context output schema/limits and timeout behavior;
- fork/resume/clear/compact behavior;
- subagent event distinctions;
- observed exit-code/error semantics.

Public docs inform implementation but do not substitute this qualification.

## 7. Retrieval, context and exact source opening

### 7.1 Decision frame

A decision frame contains project/workspace/task or actor/session address, observed resource versions, focused question, exact cues, known constraints and requested budget.

Address current work before search. Branch/path alone does not select interleaved tasks.

### 7.2 Candidate arms

Generate bounded candidates independently from direct handles, current-work address, exact cues, full-text search, compatible vectors, current alternatives/grounds, typed relations, project-local methods and eligible reusable methods.

Union before final selection. A lexical candidate does not require vector score. Workspace/task selectors apply before per-arm limits.

### 7.3 Ranking and applicability

Rank relevance separately from support. Scores are relative ordering, not truth probability.

Applicability is `applicable | inapplicable | conditional/unknown`. Typed observed values may decide simple conditions. Token overlap does not prove condition.

Material exception/counterevidence is loaded with claim/method even if it would not rank independently.

### 7.4 Packing

Pack semantic units: current work, exact constraints/corrections, applicable/conditional methods, relevant prior episode, dissent/unknowns/next checks and source handles.

If unit cannot fit, return faithful qualified reduction plus expansion handle or omit whole unit with gap. Never drop negation, version or contraindication. Packet-local grouping reduces repetition but does not merge stored identities/evidence.

### 7.5 Exact source opening

`open` resolves exact item/revision, observation, blob, converted representation, report section or source range. It does not rerun search, conversion, Research or inference merely to satisfy historical handle.

Return metadata/excerpt first and selected ranges next. Missing retained representation is durability gap, not permission to substitute newer source.

Current relation discovery is not semantic top-k. Return relation descriptors before optional neighbor expansion. Relation caps must page.

## 8. Project views, documents and affected grounds

### 8.1 Project views

A project view is versioned answer to one useful question over examined scope. First contact returns exact available facts. Finite job may add semantic explanation.

A view records examined workspace/resource revisions, answer, source handles and gaps. Membership-affecting changes qualify/dirty it. Refresh affected only; retain prior qualified view/direct source access while unavailable.

### 8.2 Documents

```text
captured original bytes
→ finite converter job
→ retained structured representation + status/errors
→ searchable excerpts
→ exact open of saved representation
```

Do not reconvert on read or substitute newer file. Preserve available page/layout/element precision; do not fabricate coordinates. Partial conversion remains useful with explicit coverage. Keep referenced assets before deleting temporaries.

### 8.3 Reconsider affected grounds

Correction, refutation, live-condition change or erasure records actual scope and coalesces follow-up job in primary mutation. Use reverse grounding indexes to page affected conclusion revisions. Load each conclusion's complete groups; navigation links are not evidence.

Known qualification reaches context before replacement explanation. Model may interpret unresolved relation but is not needed to find declared links or broken group. Cycles supply no independent support. Traversal finite/resumable.

## 9. Controller inference, embeddings and Research

### 9.1 One Memory-side controller client

[INFERENCE-CONTRACT](INFERENCE-CONTRACT.md) owns cross-repository methods, authority, artifacts, replay, adapters and release. Memory uses one authenticated client over pinned controller IPC:

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

Concrete adapter reuses exact-revision `swarm-client`; no copied framing, MCP or per-call CLI.

Controller methods:

```text
inference.text
inference.embed
inference.release
operation.get
operation.cancel
artifact.get
artifact.read
```

Controller route is not Task/Attempt and does not own Memory job/recipe/coverage/decoding/publication.

### 9.2 Connection, profile and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile`.

Connection owns transport, private credential reference, non-secret digest and `actual_destination`. Loopback may still be external.

Profile selects closed adapter ID, connection, model, automatic permission, finite limits/formats. Resolved profile inherits destination/connection digest; controller freezes profile digest on admission.

Memory selects profile and reduces supplied content to `local_only | external_allowed`. Project default, stricter sources, source-preserving derivation, mixed-input strictness and reuse non-widening apply. Controller authoritatively checks destination/disclosure/origin/limits/format/capacity.

Do not omit protected material. Incompatibility waits/fails specifically; not no-change. Automatic execution requires Memory mode and profile permission. Missing usage/cost/account remains unknown. No fallback.

### 9.3 Exact request, readback and release

Before controller I/O save stable request ID, profile, disclosure/origin, exact prompt/input blob+length+digest, limits/format and recipe/source revisions.

Controller lifecycle:

```text
saved Memory request
→ inference.text/embed
→ private inference_input
→ frozen Operation profile/connection
→ provider attempt or typed rejection/unknown
→ inference_result when usable body exists
→ operation.get + bounded artifact.read
→ Memory verify/copy exact bytes
→ decode/map/apply
→ correct release disposition
→ per-copy cleanup state
```

Exact replay uses same caller/request/method/canonical identity. Lost admission reply repeats identical request. Known Operation uses readback. Possible-send failure remains unknown. New ID is not recovery.

`complete`/usable `partial` requires artifact readback. Malformed cognitive output remains exact transport output and is not no-change.

Release dispositions and per-copy states are defined solely by Contract 0.4. Cancellation only proves no provider call when queued cancellation wins before send CAS.

### 9.4 Embeddings

Embeddings use same Operation/copy/read/release lifecycle. Canonical body has vector space, query/document role and one vector/error per input key.

Controller owns provider details. Memory maps exact item/revision/representation. Missing/duplicate/unresolvable positions are errors, not zero vectors or shifts.

Coalesce within bounds, preserve successes, leave unresolved explicit. Vector application updates derived fields only; content revision invalidates old vector. Incompatible space pauses vector only and rebuilds finite pages.

### 9.5 Research

Use existing Eliot Research boundary. Separate search, run start, status/artifact identity, actual report section read and cited evidence open.

Save exact request/profile/idempotency before submission. Replay recovers same run where supported. Metadata is not report text. Resume interrupted section/source reads.

Known gaps remain: MCP decoder alignment and citation open independent of active index. Large sections need bounded existing reader.

## 10. Learning and autonomous curation

### 10.1 Episode input and coverage

Group events through actual session/task/call/result/parent relations. Freeze membership and per-stream segments. Distinguish selected, supplied and processed coverage. Unexpanded/trimmed/omitted is not covered. No-change covers supplied input/purpose only. Deferred material goes successor; no global processed bit.

### 10.2 Interpret, correct or keep

Normal job receives episode input, feedback, small related set and exact recipe. It may create provisional claim/method, revise named item/view, identify conflict/unknown or keep/no-change. Direct correction uses §5.4.

### 10.3 Processing-method consumer

Ship default recipe only for implemented purposes. First enable saves as ordinary processing method at stable address. Claim freezes method revision; request builder opens exact body. Reclaim retains. Software update does not overwrite edited/learned method.

Improvement revises addressed processing method. Later jobs consume new revision; running work frozen. No consumer means stored knowledge, not self-improvement.

### 10.4 Outcome feedback

Retain source observations. Reduce attributable feedback into versioned outcome addressed by method revision, attempt/execution, criterion and checked target.

Tool result and summary may both exist but are one attempt. Packet proves offered context, not adherence. Unknown association stays unknown.

`context` reads limitations/counterexamples; `learning` may revise method.

### 10.5 Automatic timing

Capability enablement separate from `automatic = off | idle | background`. Disabled stops new work but retains reads/reconciliation. Off permits explicit dream only. Idle starts after quiet and finite drain. Background progresses under capacity while capture/control/context priority.

Profile may deny automatic. New input coalesces one pending target preserving first queued time. Quiet delay batches; max age does not override policy. Claim finite slice. Foreground stops new idle dispatch; admitted work finishes/unknown. Resume later. Unattended window is external invocation, not scheduler.

Output must reach context/open/method consumer. Unread report not result.

## 11. Consolidation, disagreement and commitments

### 11.1 Consolidation

Distinguish replay, packet grouping, same-item revision, new synthesis and correction/split. Broader pattern creates separate provisional item linked to exact sources; does not merge source IDs. False merge narrows/splits derived item while sources/history survive.

### 11.2 Disagreement and anticipation

Rivals are ordinary claims with grounds/counterevidence. Select cheapest distinguishing observation; voting not evidence. Prediction records trigger, expected observation, conditions, check and reconsideration/expiry. Expiry does not fabricate outcome.

### 11.3 Commitments

Ordinary scoped memory item with owner/recipient, state, optional due time and source. Context/inbox reads by address/scope. Showing/ack/due does not resolve; observed result or owner decision does. Notifications optional, no task manager.

### 11.4 Self-diagnosis

Diagnose capture, source selection/disclosure, admission, controller execution, readback/release, decoding, publication, retrieval/applicability, host delivery, use/correlation or method quality. Correct supported failing step. No recursive jobs from accounting/no-change.

## 12. Deletion, backup and restore

### 12.1 Withdrawal and erasure

Withdrawal stops guidance, not physical deletion.

For erasure record exact scope/command ID as small text-free durable notice. Cancel pending work, queued controller work where possible, settle writers and prevent late controller/Research/spool reintroduction.

Page references and remove controlled observations, memory/history, conversion assets, excerpts, packet copies, job blobs, staged commands and content links. Remove/replace controlled backups.

Inference cleanup uses appropriate disposition. Unresolved erasure fences before cleanup. Controller artifact is controlled. Do not claim complete while copy remains/mismatches. Provider side external.

### 12.2 Backup

Native logical DB export + referenced immutable blobs + finite selected pending spool entries. Include schema, six tables, history/links, methods/continuations/outcomes, retained model/Research results and non-secret config metadata.

Remote handles alone do not back up bytes. Search indexes rebuildable; sources/paid outputs not.

Pause new mutations/dispatch, drain short transactions, freeze set, export through Store, copy blobs, manifest/checksums/counts, publish only all success. Failure leaves live data.

### 12.3 Restore

Fresh candidate directory/database. Retry partial import only another empty candidate. Verify current/history/blob reads, apply deletions and hold external jobs for reconciliation not redispatch.

Switch data directory through durable installation config under mutex. Keep prior until retirement. Credentials/profiles not overwritten. Primary reads before optional refresh.

## 13. Control and observability

Direct controls: status/inbox, inspect/open, pause/resume jobs, cancel queued work, configure projects/hosts/disclosure/profiles, correct/withdraw/erase, backup/restore, shutdown.

Status derives from real process/config/spool/jobs/results. Show:

- capture committed/staged/unknown/rejected;
- pending/failed spool counts and oldest age;
- context prepared/emitted/gap;
- exact-open missing/forbidden/erased/damaged/paged;
- disabled/waiting mode;
- profile/connection unavailable;
- destination/disclosure mismatch;
- automatic denial;
- inference queued/sending/unknown;
- result retained/copied/decoded/applied;
- input/result cleanup states and aggregate;
- abandonment;
- partial/failed/cancelled/erased.

Do not equate any adjacent lifecycle states. Missing usage/cost/account unknown. Notification failure does not block status/control.

## 14. Implementation sequence

Write connected production code first. Run minimum relevant build/Clippy after coherent code increment. Do not construct speculative test framework. Full automated testing follows connected implementation.

Before each slice: one integrator/edge; cheap preflight before setup; no overlap without disposition; measure merged behavior/blockers.

### Slice 1 — Store and local lifecycle

Supervisor/daemon/SurrealDB, config, exact `CaptureCommand`, atomic blob/write, exact read after restart, pending spool publication/replay, status/shutdown and revision/history.

```text
real event → committed or staged → replay if staged → restart → exact open
```

### Slice 2 — Useful Base and first host

Connect Claude relay event profile, continuation lookup/raw bounded tail, exact/full-text retrieval, notes/corrections/commitments, actual SessionStart/UserPromptSubmit context emission, packet retention/handoff observation, source open, pause/stop and Base backup/restore/erase.

Base runs with controller/model/vector/document/Research disabled.

```text
session A real event
→ Store or durable spool ownership
→ restart
→ session B receives bounded actual context
→ exact source/revision/range opens
```

### Slice 3 — Controller inference owner

Implement Contract 0.4: role, connection/profile/digests, destination admission, methods, controlled artifacts, dedup, cancel/unknown, one runner, loopback text then embeddings, readback, per-copy cleanup, three release dispositions, erasure fence; no Task/Attempt/ScriptRun/new table.

### Slice 4 — First learning

Pin `swarm-client`; one controller adapter; one episode handler; disclosure; exact request/result; verification; decode/publication; later context; correct cleanup. Exercise unknown/no-result/cancel/malformed/partial/cleanup/abandon/restart without duplicate inference. Base stays usable disabled.

### Slice 5 — Independent increments

Vectors, views, documents, Research, hosts by real prerequisites. Each connects output to reader and maintenance. No compulsory chain.

### Slice 6 — Advanced improvement

Cross-episode curation, recursive improvement, diagnosis, disagreement/prediction and broader integrations only after base paths work. Same jobs/revisions/context; no second runtime.

### Final verification

After connected product, automated suite over production operations, concurrency, restart, spool durability/replay, exact-open pagination, erasure and optional failure. Stub provider qualifies local mapping only.

Measure actual latency, I/O, calls, retained bytes, dependencies and code size. Line count is diagnostic, not quota.