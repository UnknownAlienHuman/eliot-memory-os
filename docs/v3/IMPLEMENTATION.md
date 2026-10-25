# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.22 · 2026-10-25 · concrete design for the greenfield rewrite.**

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
- one external SurrealDB server child;
- their Windows Job Object;
- exact child executable/configuration identity;
- restart intensity and planned shutdown.

The daemon does not supervise itself. Hosts and `eliot-swarm-controller` do not own this process family. Provider/model processes remain controller/provider concerns.

### 1.2 Data root and configuration

Use one stable installation root, for example:

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  installation.toml
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

`config.toml` contains practical user configuration:

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

`installation.toml` is a small installer-owned input, not a second state store. It pins:

- exact SurrealDB executable path, version and SHA-256;
- exact storage URL/engine and durability parameters;
- namespace/database names;
- loopback endpoint policy;
- schema generation expected by this Eliot build.

The first qualification target is SurrealDB **3.3.4**. The initial production storage candidate is the external server with RocksDB because SurrealDB 3.3 documents RocksDB as the recommended on-disk engine while SurrealKV remains beta. This is a qualification target, not a completed proof: Store readiness is unavailable until the exact Windows binary/engine passes restart, conflict, export/import and power-loss-oriented publication checks. Do not silently fall back to another server version or storage engine.

Provider connections, provider credentials, adapter IDs and `actual_destination` declarations stay with `eliot-swarm-controller`. Memory stores only selected profile names and frozen non-secret execution identity returned by controller.

### 1.3 Demand start, Store admission, spool recovery and shutdown

The supervisor holds a named mutex for the stable installation root throughout startup, operation and shutdown. A relay connects first; if no endpoint answers, it starts a supervisor candidate and waits. Only the candidate owning the mutex starts children. An existing owner with an unready daemon is not permission to launch another database.

Create SurrealDB and daemon children suspended, assign them to a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resume them. If assignment fails, terminate the still-suspended child. Do not kill unrelated processes by name or port.

Store readiness requires all of these observations:

1. the exact configured SurrealDB executable digest matches;
2. the owned child starts and keeps its retained process handle;
3. it binds only the configured loopback endpoint;
4. authenticated RPC `version` matches the pinned exact version;
5. namespace/database selection succeeds;
6. schema generation and `INFO FOR DB/TABLE` checks match §5.2;
7. one bounded write/read/delete probe succeeds through the same Store client used by production.

A listening port or process heartbeat alone is not Store readiness. A version/schema mismatch stops Store mutation before host relays can claim capture ownership.

Restarting a failed daemon does not restart a healthy database. If the supervisor dies, owned children terminate with the Job Object; the next demand start opens existing data and repeats Store admission.

After Store is ready, the daemon begins bounded fair replay of `spool/pending`. Replay does not block primary exact reads or new capture indefinitely. It pages entries in stable order, processes a finite batch, then yields to foreground work. Corrupt or permanently rejected entries move to `spool/failed`; transient Store failure leaves them pending. A replayed command uses the same application `capture` operation and command ID as direct delivery.

Before normal idle shutdown:

1. stop new external dispatch;
2. stop claiming new background work;
3. allow one finite drain interval for already eligible work and a bounded spool batch;
4. persist collected results and progress;
5. stop daemon and database;
6. wait for exit and release the mutex.

Pending spool data, a completed background job or an internal poll cannot renew the interval indefinitely. Explicit shutdown does not start a final Dreamer cycle. Unknown controller/provider outcomes remain reconcilable after restart; shutdown does not authorize another request ID.

Primary capture and exact/lexical reads become available as soon as Store is admitted. They do not wait for controller inference, embeddings, project orientation, graph refresh or complete spool drain.

## 2. Code structure

### 2.1 Start with one Rust package

Use one library package plus a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries. Split a crate only when an actual dependency, deployment or independently changing boundary requires it.

| Module | Owns | Does not own |
|---|---|---|
| `model` | Small values crossing real internal boundaries | Vendor SDKs, runtime, universal contract catalogue |
| `store` | Bounded SurrealDB RPC client, schema/migrations, fixed queries, transactions, exact reads and blob references | Arbitrary SurrealQL surface, interpretation, host protocol, model selection |
| `memory` | Semantic item operations, revisions, history, grounds and source links | Raw host/provider I/O |
| `context` | Continuation reconstruction, candidate selection, applicability, relation expansion and packing | Second Store or model scheduler |
| `learning` | Purpose-specific input selection, request builders, disclosure reduction, decoders, reducers and publication proposals | Job claims, provider retries or credentials |
| `vectors` | Vector-space identity, result mapping and vector candidate arm | Provider transport or second vector database |
| `jobs` | Due selection, claim/reclaim, finite handler dispatch, reconciliation and result application | Semantic algorithms duplicated from handlers |
| `adapters::host` | Native host event decoding, `CaptureCommand` construction and context emission | Task ownership, semantic publication or Store status invention |
| `adapters::controller` | Authenticated controller IPC, inference methods, Operation/artifact readback, queued cancel and release | Memory job state, publication, provider credentials or route planning |
| `adapters::source` | Document, structure and Research translation | Another memory service |
| `spool` | Atomic pending-command publication, bounded replay inventory and failed quarantine | A second canonical event store |
| `platform::windows` | Minimal named mutex, Job Object and durable local-file primitives used by V3 | V2 platform framework, policy, manifests or generic capability registry |
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

Keep RPC, HTTP, SQL, host JSON and filesystem helpers private. Internal calls share typed Rust values; serialize only at storage, process or network boundaries. Add a trait at a real interchangeable I/O boundary, not for every table or function.

The current official SurrealDB Rust SDK is **not** the baseline dependency. The 3.3.4 SDK requires Rust 1.95 while this repository declares workspace MSRV 1.94, and its published package metadata points to a license file outside the current `deny.toml` allowlist. The pinned development toolchain can compile newer Rust, but that does not make the declared MSRV or dependency policy true. Reconsider the SDK only after an exact-version `cargo check`, `cargo deny` and dependency-size preflight passes and demonstrably simplifies the bounded remote client below.

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

When a native event key is absent, `event_key = command_id`. Identical replay returns the saved observation/result. Reusing one key with different bytes/binding is a conflict. Different keys with equal bytes remain distinct observations.

A tool result, an agent report about it, a prepared packet and an observed handoff are distinct observations. Replays compare source identity and bytes, not receipt time.

### 4.3 `memory`

Holds the current editorial revision of a semantic item.

Key fields:

- `id`, `origin_project`, `reuse_scope`, `revision`, `kind`;
- for methods: `method_role = advice | processing` and implemented `processing_purpose`;
- optional exact `address_kind`, `address_key` and derived optional `address_unique_key`;
- `content`, `search_text`, exact cues and advisory aliases;
- disclosure class and source-derived limitations;
- subject/aspect/perspective;
- material applicability conditions/exceptions and optional typed selectors;
- validity interval;
- support limitations separately from retrieval exposure and advisory influence;
- optional commitment state;
- optional vector, effective space and encoded representation identity;
- created/updated times.

`address_unique_key` is `NONE` for an unaddressed item and a canonical project/kind/key value for a complete exact address. A unique index on that derived field gives at most one current addressed item without forbidding multiple unaddressed notes.

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
- derived optional active/pending slot key;
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

A unique optional slot key enforces at most one active job and one coalesced pending successor for `(project, purpose, target_key)`. Terminal history has no slot key.

### 4.7 Blobs, locators and packet records

Large source bytes, prompts, packets and results live under `blobs/`; rows keep opaque references and digests. Publish immutable blob bytes durably before committing a row that refers to them. Cleanup may remove unreferenced temporary files later; a committed row must never point to bytes that were never saved.

A rendered context packet does not receive a seventh primary table. Record it as an Eliot application observation/blob with packet ID/digest, binding, budget, exact included revisions, omissions/gaps, prepared time and observed host emission result. Use `link` rows for inclusion and handoff/action association.

Locators claim only supplied precision: code path/range/version, document page/element/region, sheet/range, image region, transcript turn/time, captured web/research representation/passages or runtime instance/time. Dirty/untracked code is cited by retained bytes or range, not HEAD alone.

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

## 5. Store, schema and durable local publication

### 5.0 Bounded SurrealDB transport

The Store uses one small internal remote-only JSON WebSocket RPC client over the supervisor-owned loopback SurrealDB child. It reuses ordinary dependencies such as `tokio-tungstenite` and `serde_json`; it does not link the database engine and does not import the V2 Store adapter.

Initial RPC surface:

```text
signin
use
version
query
ping
```

The socket sends `Sec-WebSocket-Protocol: json`, has finite frame/message/request deadlines and initially permits one in-flight request per socket. Every request has an exact response ID. The client accepts only the owned loopback endpoint and closed authentication/configuration; no arbitrary external endpoint, live query, generic CRUD builder or caller-supplied SurrealQL is exposed.

Application queries are checked-in `.surql` assets or compile-time fixed strings with JSON variables. Dynamic identifiers are selected from closed enums and rendered by Store code, never supplied as raw user/agent text.

A transport failure after a mutation may have been sent is `OUTCOME_UNKNOWN`. Reconnect does not replay the mutation blindly. The application reads by its unique operation/command/item identity first; only a proven non-commit or a bounded retryable transaction conflict permits the exact transaction to run again.

### 5.1 Schema and migration ownership

The installer/bootstrap owner applies ordered, checksummed `.surql` migrations before Store becomes ready. Do not add SurrealKit, a migration service or a migration database for the initial product.

Baseline schema rules:

- define namespace and a `STRICT` database explicitly;
- define the six application tables as `SCHEMAFULL`;
- define every owned field and type explicitly;
- use `FLEXIBLE` only on a named bounded native-metadata object whose unknown fields are intentionally retained;
- define composite unique indexes for stream and observation identities;
- define unique indexes on `memory.address_unique_key`, `memory_history(item, revision)` and active/pending job slot keys;
- define ordinary indexes only for queries that appear in a connected reader;
- build initial indexes synchronously before ready;
- use `CONCURRENTLY` only for a later online migration with explicit readiness polling;
- never use the 2.x-only `DEFER` clause on the 3.x target.

Store the expected migration number in database parameter `$eliot_schema_generation`. Startup reads `INFO FOR DB` and `INFO FOR TABLE` and compares the actual definitions/digest against checked-in migration metadata. `IF NOT EXISTS` is not enough for a changed definition: a mismatched existing table/field/index blocks mutation until the named migration resolves it.

### 5.2 Transaction and conflict rules

The RPC `query` call executes one complete fixed transaction text with bound variables. The client inspects **every** per-statement status/result; a successful WebSocket response or final `COMMIT`-shaped value cannot hide an earlier failed statement.

SurrealDB transactions provide snapshot isolation. Therefore:

- unique indexes own identity/cardinality whenever possible;
- a record whose current value controls a write is read with `FOR UPDATE`;
- stream sequence allocation locks the stream record;
- memory revision publication locks/rechecks the current item;
- a predicate-only invariant over a set uses a deterministic sentinel/slot record or unique derived key; an existence query alone is not serialization;
- `UPSERT` without an exact deterministic record identity is not an idempotency primitive.

If two transactions modify the same record or unique value, one may fail with a retryable conflict. Retry the **whole** transaction with the same immutable command, IDs and expected revisions under a finite attempt/backoff budget. Unique-constraint conflict after a retry is resolved by exact readback and byte/binding comparison. Unknown transport outcome is reconciled before any retry.

Network, controller, document and Research calls never run inside a database transaction. Blob publication happens before the row transaction; unreferenced immutable blobs are later cleanup candidates.

### 5.3 `capture_event`

Input is one immutable `CaptureCommand`.

Before the transaction, publish any referenced body blob using deterministic command-owned identity. Then, in one transaction:

1. resolve/create stream under unique native identity;
2. read/lock the stream record;
3. read by `(project, command_id)` and `(project, stream, event_key)`;
4. return saved result for identical replay;
5. reject `COMMAND_ID_CONFLICT` or `EVENT_KEY_CONFLICT` for different bytes/binding;
6. allocate stream intake sequence;
7. insert observation with exact body/blob identity, relations, locator, disclosure and capture limits;
8. coalesce only implemented/enabled necessary follow-up work;
9. commit.

After commit, read observation identity, body length/digest and binding through Store. Only matching readback returns `committed`.

Capture does not call a model. Packet/status/read/claim-renewal/release/embedding-completion events do not automatically become new experience. A structured correction uses §5.6.

### 5.4 Windows durable-file primitive and relay spool publication

The initial durability profile is a local fixed Windows volume with a qualified NTFS or ReFS directory. UNC/network/removable roots and reparse traversal are rejected. Temporary and final files are always in the same directory/volume.

One internal Windows primitive owns immutable publication:

1. retain/validate the parent directory without following reparse points;
2. create a unique same-directory temporary regular file with `CREATE_NEW` semantics;
3. write the complete bytes;
4. flush userspace buffers and call `sync_all`/`FlushFileBuffers` on the writable file handle;
5. close the file handle;
6. rename to the absent final name with `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` **without** `MOVEFILE_REPLACE_EXISTING` or cross-volume copy;
7. open the parent directory with write access, `FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OPEN_REPARSE_POINT` and call `FlushFileBuffers`;
8. reopen the final regular file no-follow and verify identity/length/digest.

If the final path already exists, never overwrite it. Open/verify it and perform a successful parent-directory flush before returning prior `staged`; different bytes are conflict.

If rename succeeds but parent sync or final readback fails, publication is **post-commit unknown**, not staged and not a pre-commit failure. Reconciliation reopens the exact final path, verifies bytes, retries directory sync and only then returns staged. The same rule applies to immutable blob publication and deletion notices.

The legacy `atomic_replace_file` donor uses `MOVEFILE_REPLACE_EXISTING` and is therefore not the V3 spool primitive. The existing directory-flush donor demonstrates the required Windows handle flags and error propagation, but V3 keeps only the minimal physical mechanism in its internal module.

Relay delivery:

1. call daemon `capture`;
2. accept `committed` only with matching Store readback;
3. accept deterministic `rejected` only when no ownership transfer occurred;
4. treat disconnect/timeout/malformed reply after possible send as unknown;
5. publish the exact same serialized command through the durable primitive;
6. return `staged` only after successful final verification.

If neither Store commit nor durable pending publication is established, return `unknown`. Do not return `forwarded` as success.

### 5.5 Daemon spool replay

The daemon is the only automatic replayer. For each bounded fair batch:

1. enumerate regular pending files in stable order;
2. refuse symlink/reparse/unexpected types and bound size before read;
3. parse closed schema and verify filename/command ID/body digest;
4. check current deletion notice;
5. call the same `capture_event`;
6. on matching committed readback, delete pending and flush the parent directory;
7. on permanent rejection/corruption, no-replace move to failed, write bounded reason and flush both affected directories;
8. on transient Store failure, retain pending and yield;
9. cap attempts/work so a poison item cannot starve newer events.

A delete/move followed by directory-sync failure has an unknown cleanup outcome; startup reconciliation observes the actual file location and completes the directory flush. Replay never mutates command identity, time, body, locator or binding.

### 5.6 `publish_memory_revision`

For explicit correction or accepted proposal, one transaction:

1. read current item `FOR UPDATE`;
2. reject stale expected revision;
3. copy old current row into `memory_history`;
4. write new current revision;
5. insert revision-specific source/grounds/replacement links;
6. settle owning command/job result;
7. coalesce only affected follow-up work;
8. commit.

IDs for proposal-created items are allocated once and retained with decoded job result so retry cannot create another item.

### 5.7 `claim_due_job`

Select only work whose handler is present, enabled and eligible for configured automatic mode. Waiting for idle time, configured profile, disclosure-compatible destination or resume is not failed attempt.

In one transaction select fairly, claim the active slot, freeze finite inputs and exact processing method, reduce disclosure and select the configured profile name. Handler builds/saves exact request bytes before controller I/O. Reclaim never rebuilds a different request for an admitted Operation.

### 5.8 External result and cleanup state

Controller polling/artifact reading occurs outside Store transactions. Memory verifies exact result ranges, stores controller identity and Memory blob, then decodes from retained bytes. Applying a proposal uses expected revisions and never repeats inference on Store conflict.

Cleanup is a separate controller operation:

- verified result copy → `inference.release(memory_copy_verified)`;
- terminal no-result → `inference.release(terminal_without_result)`;
- erasure of unresolved work → `inference.release(abandon_for_erasure)` after explicit owner decision.

Release updates input/result copy states independently and never rolls back valid Memory publication.

### 5.9 Exact `open`, packet retention and bounded reads

`open` requires one nonempty handle. Resolve current item, exact historical revision, observation/source body, immutable blob/range, converted representation/range, Research section/citation or copied controller result. A current handle returns current/absent/withdrawn/erased; a version handle never falls forward.

Return requested/resolved identity, byte/item range/digest, state, capture limits, material qualifications, bounded revision-aware relation descriptors, expansion handles, cursor and explicit missing/forbidden/erased/damaged/unsupported disposition. Opening one item returns material relation descriptors without requiring the caller to know the neighbor first. A fixed cap without cursor is an explicit incomplete gap.

For coherent hydration, do not mix current row with another revision's links. Use one transaction/snapshot where possible; otherwise compare revision fences before/after and retry boundedly.

After context assembly and before host output, retain rendered packet bytes and one packet observation with exact included revisions, budget and gaps. Host emission produces a separate observation when the host exposes a meaningful result. Prepared is not emitted; emitted is not used; used is not success.

All large reads page by real byte/row limits. Preserve UTF-8 boundaries and identity-bound cursors. Long JSON, one-line logs and converted documents cannot force unbounded allocation.

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

A hook invocation reads one bounded JSON object, validates adapter compatibility, constructs one immutable `CaptureCommand`, attempts direct capture then spool, optionally requests context at a supported decision boundary, writes one bounded host-compatible stdout object, writes diagnostics separately and exits without claiming more than achieved.

Capture and context have separate timeout budgets. Capture may be staged while context times out. Context failure cannot erase committed/staged capture state.

### 6.3 Context output and qualification

For `SessionStart` and `UserPromptSubmit`, successful context contains actual rendered packet text through the supported host channel. Service status or “event spooled” is not context.

Before default enablement record installed Claude Code version, actual event payloads, final-message/compact fields, output schema/limits, timeout/exit semantics, fork/resume/clear/compact behavior and subagent distinctions. Public docs do not substitute installed qualification.

## 7. Retrieval, context and exact source opening

### 7.1 Decision frame and candidate arms

A decision frame contains project/workspace/task or actor/session address, observed resource versions, focused question, exact cues, constraints and budget. Address current work before search.

Generate bounded candidates independently from direct handles, current-work address, exact cues, full-text search, compatible vectors, alternatives/grounds, typed relations, local methods and eligible reusable methods. Union before final selection. Workspace/task selectors apply before arm limits.

### 7.2 Ranking, applicability and packing

Rank relevance separately from support. Applicability is `applicable | inapplicable | conditional/unknown`; token overlap is not proof.

Pack current work, exact corrections, applicable/conditional methods, prior episode, dissent/unknowns/checks and source handles. Load exceptions with the item. If a unit cannot fit, return a faithful qualified reduction plus handle or omit the whole unit with a gap. Do not drop negation/version/contraindication.

### 7.3 Exact source opening

`open` resolves retained exact identities and never reruns search, conversion, Research or inference merely to satisfy a historical handle. Return metadata/excerpt first and bounded ranges next. Missing retained representation is a durability gap, not permission to substitute newer source.

## 8. Project views, documents and affected grounds

### 8.1 Project views

A project view is a versioned answer to one useful question over examined scope. It records revisions, answer, source handles and gaps. Membership-affecting changes dirty/qualify it. Refresh only affected views; serve prior qualified view and direct source access while unavailable.

### 8.2 Documents

```text
captured original bytes
→ finite converter job
→ retained structured representation + status/errors
→ searchable excerpts
→ exact open of saved representation
```

Do not reconvert on read or substitute a newer file. Preserve available precision and explicit partial coverage.

### 8.3 Reconsider affected grounds

Correction/refutation/live-condition change/erasure records actual scope and coalesces follow-up work. Reverse indexes page affected conclusion revisions. Load complete grounds groups; navigation is not evidence. Traversal remains finite/resumable.

## 9. Controller inference, embeddings and Research

### 9.1 One Memory-side controller client

[INFERENCE-CONTRACT](INFERENCE-CONTRACT.md) owns cross-repository methods, authority, artifacts, replay and release. Memory uses one authenticated client over pinned controller IPC for text, embeddings, Operation readback, artifact ranges, queued cancel and release. Concrete adapter reuses exact-revision `swarm-client`; no copied framing, MCP or per-call CLI.

Controller route is not Task/Attempt and does not own Memory job/recipe/coverage/decoding/publication.

### 9.2 Connection, profile and exact lifecycle

Controller owns `InferenceConnection` and `InferenceProfile`; Memory selects profile and reduces disclosure. Controller resolves actual destination and authoritatively checks disclosure/origin/limits/format/capacity. No fallback.

Before controller I/O save stable request ID, profile, disclosure/origin, exact input blob+digest, limits/format and recipe/source revisions. Exact replay uses the same identity. Possible-send failure remains unknown. Known Operation uses readback, not another request ID.

`complete`/usable `partial` requires artifact readback. Malformed cognitive output remains exact transport output and is not no-change. Release dispositions and per-copy states are defined solely by Contract 0.4.

### 9.3 Embeddings and Research

Embeddings use the same Operation/copy/read/release lifecycle and one result/error per input key. Memory maps exact item/revision/representation; zero vectors or shifted positions are forbidden.

Research uses the existing external boundary. Separate search, run start, status/artifact identity, actual report-section read and cited evidence open. Save exact request/idempotency before submission. Known parser/citation gaps remain tracked in the registry.

## 10. Learning and autonomous curation

Group episodes by actual session/task/call/result relations. Freeze membership and distinguish selected, supplied and processed coverage. No global processed bit.

A normal job receives episode input, feedback, a small related set and exact processing recipe. It may create/revise, identify conflict/unknown or keep/no-change. Direct correction uses §5.6.

First enable saves a real recipe as ordinary processing method. Claim freezes revision; request builder opens exact body. Upgrade does not overwrite edited/learned method. A method with no consumer is stored knowledge, not improvement.

Automatic mode is `off | idle | background`; profile may independently deny automatic. New input coalesces one pending target, preserves first queued time and claims finite slices. Foreground stops new idle dispatch; admitted work finishes or remains unknown. Output must reach context/open/method consumer.

## 11. Consolidation, disagreement and commitments

Distinguish replay, packet grouping, same-item revision, new synthesis and correction/split. Broader pattern creates separate provisional item linked to exact sources; it does not merge source IDs.

Rival explanations remain ordinary claims with grounds/counterevidence. Select the cheapest distinguishing observation; voting is not evidence. Prediction records expected observation before action.

Commitment is an ordinary scoped memory item with owner/recipient, state, optional due time and source. Showing/ack/due does not resolve it. Notifications are optional and do not create a task manager.

Self-diagnosis identifies the failed connected edge—capture, Store/spool, source selection, controller admission/execution/readback/release, decoding, publication, retrieval, host delivery, use or method quality—and corrects that edge.

## 12. Deletion, backup and restore

### 12.1 Withdrawal and erasure

Withdrawal stops guidance, not physical deletion.

For erasure, publish an exact text-free deletion notice through the same durable-file primitive, cancel pending work, fence unresolved controller work and prevent late Store/Research/spool reintroduction. Page/remove controlled observations, memory/history, representations, packet/job blobs, staged commands, links and affected backups. Do not claim complete while any controlled copy remains or mismatches.

### 12.2 Backup

Use SurrealDB logical export plus referenced immutable blobs and finite selected pending spool entries. Include schema generation/definitions, six tables, history/links, retained external results and non-secret configuration metadata.

Do **not** copy a live RocksDB/SurrealKV directory as the application backup contract. Freeze mutations/dispatch, complete short transactions, run the exact supported logical export under the owned server, copy referenced blobs, write checksummed manifest/counts and publish backup only after every byte succeeds. Failure leaves live data intact.

### 12.3 Restore

Restore into a fresh candidate directory/database using the same pinned server version/engine and ordered schema owner. Import may partially apply, so retry only into another empty candidate. Verify current/history/blob reads, uniqueness probes, schema generation and deletion notices; hold unfinished external jobs for reconciliation rather than redispatch.

Switch selected data root through one durable installation update under the mutex. Keep prior data until explicit retirement. Credentials/profiles are not overwritten. Primary reads become available before optional refresh.

## 13. Control and observability

Direct controls: status/inbox, inspect/open, pause/resume jobs, cancel queued work, configure projects/hosts/disclosure/profiles, correct/withdraw/erase, backup/restore, shutdown.

Status derives from real facts. Show provider binary/version/digest, storage engine/schema generation, Store readiness gap, capture committed/staged/unknown/rejected, spool counts/age/publication-unknown, context prepared/emitted/gap, exact-open dispositions, job/profile/controller states, result/application and per-copy cleanup.

Do not equate adjacent lifecycle states. Missing usage/cost/account is unknown. Notification failure does not block status/control.

## 14. Implementation sequence

Write connected production code first. Run minimum relevant build/Clippy after each coherent code increment. Do not construct a speculative test framework. Full automated testing follows connected implementation.

Before each slice: one integrator/edge; cheap preflight before setup; no overlap without disposition; measure merged behavior/blockers.

### Slice 0 — dependency and durability preflight

Before Base code:

1. acquire/pin exact SurrealDB 3.3.4 Windows binary and SHA-256;
2. prove the selected binary starts RocksDB on a disposable local root or record an explicit blocker—no SurrealKV fallback;
3. run version/signin/use/query and strict schema/index migration through the minimal RPC client;
4. exercise unique conflict, `FOR UPDATE`, whole-transaction retry and unknown-after-send readback;
5. exercise create-new temp, no-replace write-through rename, directory flush, post-rename sync failure reconciliation, delete/move directory flush and restart readback on the supported filesystem;
6. complete one logical export/import round-trip into a fresh candidate.

This preflight changes dependencies only when evidence requires it. It does not build a second storage framework.

### Slice 1 — Store and local lifecycle

Implement supervisor/daemon/owned SurrealDB, exact Store admission, schema/migrations, `CaptureCommand`, immutable blob publication, exact read after restart, pending spool publication/replay, status/shutdown and revision/history.

```text
real event → committed or staged → replay if staged → restart → exact open
```

### Slice 2 — Useful Base and first host

Connect Claude relay profile, continuation, exact/full-text retrieval, notes/corrections/commitments, actual SessionStart/UserPromptSubmit context emission, packet retention/handoff, source open and Base backup/restore/erase. Base runs with controller/model/vector/document/Research disabled.

### Slice 3 — Controller inference owner

Implement Contract 0.4: role, connection/profile/digests, destination admission, methods, artifacts, dedup, cancel/unknown, one runner, loopback text then embeddings, readback, per-copy cleanup, three release dispositions and erasure fence; no Task/Attempt/ScriptRun/new table.

### Slice 4 — First learning

Pin `swarm-client`; one controller adapter; one episode handler; exact request/result; verification; decode/publication; later context; correct cleanup. Exercise unknown/no-result/cancel/malformed/partial/cleanup/abandon/restart without duplicate inference.

### Slices 5–6 — independent increments and advanced improvement

Add vectors, views, documents, Research and hosts only by real prerequisites, then cross-episode curation/diagnosis after base paths work. Reuse the same jobs/revisions/context; no second runtime.

### Final verification

After connected product, build the suite over production operations, concurrency, restart, Store conflict/unknown outcomes, spool durability/replay, exact-open pagination, backup/restore, erasure and optional failure. Stub providers qualify local mapping only.

Measure actual latency, I/O, calls, retained bytes, dependencies and code size. Line count is diagnostic, not quota.