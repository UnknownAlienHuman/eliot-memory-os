# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.27 · 2026-10-26 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, data and connected operations. [Cognition](COGNITION.md) defines algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) is the sole normative Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) records checked evidence, decisions and open gaps.

Nothing here is implemented merely because it is specified. The complete target is not a prerequisite for useful Base. Build the connected production slices in §14. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 1. Runtime and first use

### 1.1 Process family

The initial Windows profile uses one executable with modes:

```text
eliot supervisor     owns the local process family and privileged maintenance
eliot daemon         serves Memory application operations
eliot relay ...      transient host/CLI adapter
```

The supervisor owns:

- one active `eliot daemon` generation;
- one active external SurrealDB server child;
- at most one isolated disposable SurrealDB candidate while qualifying a restore;
- their Windows Job Object;
- retained executable/process identity;
- root/Owner credential use, schema migration and DB-user rotation;
- the installation-selection generation and planned cutover/shutdown.

The daemon owns application state and ordinary Editor-authenticated Store operations. It does not supervise itself, receive root/Owner credentials or mutate the active installation selection. Hosts and `eliot-swarm-controller` do not own this process family. Provider/model processes remain controller/provider concerns.

### 1.2 Data root and configuration

Use one stable installation root, for example:

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  installation.toml
  data\
    roots\
      <root-id>\
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

- the allowed/base local data directory, not the selected active root;
- configured projects/workspaces and host binding rules;
- capture exclusions, per-event bounds and retention;
- enabled host adapters and their native executable/config paths;
- controller IPC/data root and private inference-client credential path;
- selected text/embedding profile names;
- project/source disclosure defaults;
- idle timeout and automatic-work mode;
- optional document/Research tools;
- explicitly allowed cross-project reuse scopes.

It is not a generated policy database, route registry, module catalogue, runtime inventory or installation pointer.

`installation.toml` is a small supervisor/installer-owned selection record, not a second application state store. It contains only the information needed to select and admit the process family:

- a monotonic installation-selection generation;
- current and previous closed root IDs under `data/roots/`;
- exact Eliot and SurrealDB executable paths, versions, sizes and SHA-256 digests;
- exact canonical storage profile and explicit RocksDB durability mode;
- namespace/database names and expected schema generation;
- the installation-scoped daemon pipe identity and loopback endpoint policy, not trusted pre-existing endpoints;
- non-secret Windows Credential Manager references for root, Owner and Editor, with current/pending/previous references only while a rotation is unresolved;
- the closed launch/environment profile and last admitted non-secret identity.

A daemon may read the non-secret selected root/profile/Editor reference needed to admit ordinary Store access. Only the supervisor resolves root/Owner references or replaces `installation.toml`.

The first qualification target is SurrealDB **3.3.4**. The initial production storage candidate is the external server with RocksDB because SurrealDB 3.3 documents RocksDB as the recommended on-disk engine while SurrealKV remains beta. The supervisor derives one canonical Windows storage URL from the selected closed root ID and appends explicit `sync=every`; callers do not supply alternate URL spellings, root paths or query parameters.

This is a qualification target, not a completed proof. Store readiness is unavailable until the exact Windows binary and profile pass launch-identity, startup, restart, conflict, acknowledged-commit durability, owned-listener/peer admission, typed Store transport, application backup/restore and durable-file/selection checks. Do not silently fall back to another server version, root or storage engine.

Provider connections, provider credentials, adapter IDs and `actual_destination` declarations stay with `eliot-swarm-controller`. Memory stores only selected profile names and frozen non-secret execution identity returned by controller.

### 1.3 Demand start, internal control, local IPC, Store admission and shutdown

The supervisor holds a named mutex for the stable installation root throughout startup, operation and shutdown. A relay connects first; if no daemon endpoint answers, it starts a supervisor candidate and waits. Only the candidate owning the mutex starts children. An existing owner with an unready daemon is not permission to launch another process family or database.

#### Retained executable launch identity

Before creating an owned child, the supervisor opens the approved executable without following a final reparse point, verifies regular-file identity and streams its SHA-256 through a bounded buffer. The retained handle denies later write/delete sharing; retained no-follow handles pin the executable parent, working directory and relevant ancestors so a junction or rename cannot redirect the path after validation.

The supervisor then creates the child suspended, keeps its process handle, re-observes the child image path and file identity against the retained executable, assigns it to the owned Job Object and only then resumes it. Any disagreement terminates the still-suspended child. The lease remains alive through this boundary. A path string, pre-launch digest or PID alone is not launch identity. Slice 0 must prove that the selected sharing modes and ancestor pins work with the exact Eliot and SurrealDB Windows binaries.

#### Supervisor↔daemon inherited control boundary

Before launching the daemon, the supervisor creates two bounded one-way anonymous pipes to form one duplex private control channel. It marks only the daemon ends inheritable and supplies exactly those handles through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with `bInheritHandles=TRUE`; unrelated handles are not inherited. The child-only environment contains only the decimal handle values and protocol generation, never a secret. Both processes clear inheritance on their retained ends immediately after startup.

This is not a named public endpoint. It needs no discovery, DACL-based peer selection or bearer token because the validated supervisor creates the pipes and the validated suspended daemon receives the exact handles. One owner task on each side performs all framing and handle I/O. Frames are versioned, length-prefixed, bounded, correlated by one exact operation ID and restricted to a closed enum such as:

```text
supervisor → daemon:
  store_descriptor
  quiesce
  resume
  maintenance_result
  shutdown_complete

daemon → supervisor:
  daemon_ready
  maintenance_request
  quiesced
  shutdown_ready
  acknowledgement
```

`store_descriptor` carries only non-secret facts needed for independent admission: SurrealDB PID/start time/image and file identity, root/selection generation, endpoint, storage/profile digest and expected schema generation. The daemon opens and retains its own process handle to that child, repeats listener/peer/auth/schema admission and reports `daemon_ready`; a descriptor is not authority by itself.

A maintenance request names only a closed operation kind, operation ID and already retained backup/configuration/credential generation ID. It never carries raw SQL, executable arguments, endpoint, arbitrary filesystem path, password, verifier or credential value. The supervisor independently resolves the named object beneath the installation root, verifies its identity and uses its own root/Owner Credential Manager references.

Only one privileged maintenance operation is active per installation. Ordinary backup creation is daemon-owned; schema migration, DB-user rotation, candidate restore, SurrealDB lifecycle and installation cutover are supervisor-owned. The daemon owns mutation admission, replay/job drain, exact Store readback and quiesce evidence. The supervisor owns privileged execution, child handles, candidate roots and installation selection.

Channel EOF is fail-closed. A daemon that loses the supervisor closes mutation admission, requests relay staging where possible, closes Store sockets and exits within a finite deadline. A supervisor that loses the daemon does not continue a pre-cutover restore/rotation from an unconfirmed request; a candidate is disposable unless durable installation-selection readback already proves cutover. After a possible selection replacement, startup reconciles the actual selection before any retry.

#### Relay→daemon named-pipe boundary

The relay and daemon communicate over one installation-scoped Windows named pipe. The daemon creates the first pipe instance exclusively, rejects remote clients and applies a protected DACL granting only LocalSystem and the configured current-user SID. A stable installation identifier, not a PID or random pathname alone, derives the pipe name; the first-instance flag makes a pre-existing name an admission failure rather than a second daemon.

Every connection is mutually attested before application bytes are trusted:

- the relay obtains the pipe server PID, opens a process handle and verifies start time, session, exact Eliot image path/file identity and membership in the supervisor-owned Job;
- the daemon obtains the pipe client PID and verifies start time, current-user SID/session and the exact approved Eliot relay image identity;
- both observations are bracketed by retained process-handle checks so PID reuse cannot satisfy a stale comparison.

The first Base protocol is one versioned, length-prefixed request and one correlated response per transient connection. It has finite connect/handshake/read/write deadlines, a hard frame limit, an exact request ID and a small server connection cap. Unknown versions, extra frames, partial frames, duplicate IDs and oversize bodies are rejected before dispatch. Capture and context remain separate application operations even when one hook invocation performs both.

Pipe name, liveness, DACL, a bearer token or a caller-supplied PID is not sufficient identity. This local boundary excludes other Windows users, stale generations, pipe squatting and unrelated local binaries; it does not claim to defeat arbitrary malicious code already executing as the same Windows account. That stronger threat requires a different OS/account boundary rather than more application ceremony.

#### Closed SurrealDB process profile

The supervisor creates a minimal child environment block rather than inheriting the caller environment. Preserve only required Windows process variables and explicitly selected SurrealDB settings. Arbitrary `SURREAL_*`, `RUST_LOG`, slow-query, import, Postgres, metrics and OpenTelemetry settings from the parent are not inherited.

The first closed qualification profile is equivalent to:

```text
surreal start <supervisor-derived-rocksdb-url>?sync=every
--bind 127.0.0.1:<per-start-owned-port>
--deny-all
--allow-arbitrary-query system
--deny-arbitrary-query guest,record
--allow-http rpc
--allow-rpc query
--no-defaults
--no-identification-headers
--client-ip none
--allow-origin <installer-owned-reserved-origin>
```

The environment explicitly sets `SURREAL_METRICS_ENABLED=false` and leaves slow-query logging, import, Postgres and telemetry unconfigured. `/ready`, `/health` and `/status` are loopback lifecycle probes supplied by the server; they are not substitutes for Store admission and are never exposed outside the owned listener. HTTP `signin`, `export` and `import` routes are not selected. The only RPC method is `query` behind the private fixed-query Store client.

`--allow-origin` is browser response metadata, not WebSocket authorization. SurrealDB's CORS layer forwards ordinary requests and adds headers; `/rpc` does not reject a WebSocket upgrade by Origin. The security boundary is exact process/connection ownership plus Basic-authenticated handshake and system-only fixed query, not Origin. The reserved Origin remains defense in depth for readable browser HTTP responses and diagnostics only.

#### Per-start port and peer ownership

The Store port is runtime state, not installation identity. Under the installation mutex, the supervisor:

1. binds an exclusive reservation socket to numeric IPv4 loopback port `0` and records the assigned port;
2. creates the SurrealDB child suspended and retains its process handle/PID;
3. drops the reservation immediately before resuming the child;
4. treats bind failure or child exit as a bounded retry on another port after the prior process is fully reaped;
5. waits until `GetExtendedTcpTable` observes a `LISTEN` row on the exact address/port owned by the retained child PID;
6. brackets that observation with retained-handle liveness/identity checks so PID reuse cannot satisfy it;
7. opens a raw `TcpStream` to the exact endpoint and verifies the established server-side peer row belongs to the same child before sending a WebSocket upgrade or any credential;
8. performs `tokio_tungstenite::client_async_with_config` on that already-verified stream.

Closing the reservation creates an unavoidable bind race because the standalone server cannot inherit the socket. The race may cause a retry; it never authorizes talking to whoever won the port. Liveness, a successful TCP connect, HTTP status or matching port alone is not peer identity.

The WebSocket upgrade carries:

- `Authorization: Basic ...` from the selected Credential Manager secret;
- `Surreal-Auth-NS` and `Surreal-Auth-DB` for a database user;
- `Surreal-NS` and `Surreal-DB` for the selected application context;
- `Sec-WebSocket-Protocol: json`;
- finite WebSocket configuration and deadlines.

Root omits database-auth headers until the namespace/database exists. Database users authenticate and select their one configured database during the handshake. RPC `signin` and `use` are therefore unnecessary. Exact binary path/digest plus retained-process/listener/peer identity replaces RPC `version`; WebSocket control Ping/Pong replaces RPC `ping`.

SurrealDB still accepts an anonymous WebSocket upgrade when no Authorization header is supplied. Guest arbitrary query is denied, so it cannot read/write Store data through the selected method surface, but connection-exhaustion behavior must be measured in Slice 0. If random per-start port, bounded server settings and measured behavior are insufficient, pinned WSS or a narrow authenticated proxy is a separate evidence-driven hardening decision; Origin is never promoted as the fix.

#### Root bootstrap, migrations and database users

For local Store credentials, Windows Credential Manager is the only secret authority. Generate the root bootstrap credential once and retain the same secret through all reconciliation attempts. Root bootstrap is deliberately short-lived:

1. on an empty selected root, start one bootstrap child with that root username/password in its child-only environment;
2. wait until upstream startup has persisted the root user and `/ready` succeeds;
3. gracefully stop that child and restart the same root **without** root credentials in its environment;
4. verify listener/peer ownership, then authenticate root in the WebSocket Basic handshake;
5. create the configured namespace, `STRICT` database and two database-scoped users through fixed root queries;
6. prove Owner and Editor can authenticate in pinned Basic handshakes;
7. run ordered checked migrations through a separately authenticated Owner socket and verify schema generation/definitions;
8. restart again without root environment material and repeat Owner admission before starting the daemon.

A bootstrap child may persist root before a later bind/startup failure. That is `OUTCOME_UNKNOWN`, not permission to generate a new root password. Restart without root environment material and try the retained credential. If root authentication succeeds, bootstrap committed. If it fails and no other writer can exist under the installation mutex, stop the child and retry bootstrap with the **same** credential under a finite budget; persistent mismatch blocks rather than rotating or overwriting root.

The two database-scoped users are:

- **Editor** — ordinary daemon Store reads and application mutations;
- **Owner** — supervisor-owned migrations, DB-user rotation and typed restore writes.

The supervisor derives a standard Argon2 PHC verifier locally and provisions users with fixed `PASSHASH` statements; plaintext database-user passwords are not placed in SurrealQL, argv or logs. Slow-query logging remains disabled because `PASSWORD`, `PASSHASH` and `PASSSCRAM` are literal-bearing DDL. SCRAM material is not created while Postgres/SCRAM transports are disabled. Credential headers, DDL buffers, handshake failures and RPC errors are secret-bearing: logs retain only bounded error class and operation identity, never the header, request, statement, password or verifier.

The daemon receives only the non-secret Editor reference and reads only that Credential Manager entry. The supervisor code path resolves root/Owner. Because both processes initially run under one Windows account, this is an application authority boundary against accidental misuse, not a claim that arbitrary malicious same-account code cannot read the user's credentials. A stronger threat model requires a separate OS identity/service account.

#### Startup admission

A normal startup is ordered:

1. read and verify `installation.toml`, selected root and executable identities under the installation mutex;
2. start/admit the selected SurrealDB child;
3. reconcile bootstrap/credential state and run pending checked migrations through root/Owner;
4. create the inherited supervisor channel and launch the validated daemon;
5. send one `store_descriptor`;
6. require the daemon to repeat process/listener/peer/Editor/schema/typed-probe admission and report `daemon_ready`;
7. only then expose the relay pipe and accept capture/read/control operations.

Store readiness requires all of these observations:

1. the exact configured SurrealDB executable path, size and digest match retained installation identity;
2. the owned child starts, retains its process handle and owns the expected loopback listener;
3. `/ready` succeeds for that process after upstream startup/heartbeat gates;
4. the raw TCP connection's server peer is re-observed as the retained child before the authenticated upgrade;
5. database-scoped Editor Basic handshake succeeds with exact authentication and selected namespace/database headers;
6. all RPC methods except fixed `query` and all non-system query subjects/functions/routes are denied as selected;
7. schema generation and `INFO FOR DB/TABLE` checks match §5.1;
8. one bounded typed write/read/delete probe succeeds through the same Store client used by production.

A listening port, process heartbeat, `/health`, `/status`, `/ready`, supervisor descriptor, WebSocket 101 or successful TCP connection alone is not Store readiness. A binary, owner, peer, profile, credential, schema or typed-probe mismatch stops Store mutation before host relays can claim capture ownership.

After Store is ready, the daemon begins bounded fair replay of `spool/pending`. Replay does not block primary exact reads or new capture indefinitely. It pages entries in stable order, processes a finite batch, then yields to foreground work. Corrupt or permanently rejected entries move to `spool/failed`; transient Store failure leaves them pending. A replayed command uses the same application `capture` operation and command ID as direct delivery.

#### Normal and forced shutdown

Normal idle or explicit shutdown is not Job Object termination. The daemon validates the external control operation, then:

1. closes mutation admission; direct capture receives internal `stage_required` before any blob/Store ownership, so the relay publishes the same command to durable spool;
2. stops claiming new background work and pauses admission of new replay items;
3. drains already eligible work and the replay item in flight; reconciles any possible Store write;
4. persists collected results/progress, closes Store sockets and sends `shutdown_ready(operation_id)` to the supervisor;
5. exits only after the supervisor acknowledges the operation or the inherited channel fails.

The supervisor then:

1. rejects a mismatched/stale operation ID;
2. requests the qualified graceful SurrealDB shutdown path;
3. waits through a finite deadline and records the actual child exit;
4. sends `shutdown_complete` when the daemon is still present;
5. if a child does not exit, terminates the owned Job Object as crash containment;
6. releases the installation mutex only after process ownership is settled.

`stage_required` is a private direct-delivery disposition, not a fifth public capture result and not `rejected`. The relay returns public `staged` only after its own immutable pending-file publication succeeds; otherwise it returns `unknown`.

SurrealDB itself bounds its maintenance drain and may continue shutdown after logging cleanup failures. A clean exit is therefore not an application durability receipt. The next start always repeats full admission and exact application readback. A mutation error delivered after RocksDB applied the transaction but before grouped WAL sync completed is `OUTCOME_UNKNOWN`; it is reconciled by application identity before retry.

If the supervisor dies, the Job Object terminates owned children. The next demand start treats this as crash recovery, reads the actual installation-selection generation, opens the selected retained root and repeats full admission. Restarting a failed daemon does not restart a healthy database unless the new daemon fails independent admission of that child.

Pending spool data, a completed background job or an internal poll cannot renew the idle interval indefinitely. Explicit shutdown does not start a final Dreamer cycle. Unknown controller/provider outcomes remain reconcilable after restart; shutdown does not authorize another request ID.

Primary capture and exact/lexical reads become available as soon as daemon admission succeeds. They do not wait for controller inference, embeddings, project orientation, graph refresh or complete spool drain.

## 2. Code structure

### 2.1 Start with one Rust package

Use one library package plus a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries. Split a crate only when an actual dependency, deployment or independently changing boundary requires it.

| Module | Owns | Does not own |
|---|---|---|
| `model` | Small values crossing real internal boundaries | Vendor SDKs, runtime, universal contract catalogue |
| `store` | Bounded authenticated SurrealDB query client, fixed queries, typed DTOs, transactions, exact reads and blob references | Arbitrary SurrealQL or generic Surreal value surface, host protocol, installation selection |
| `memory` | Semantic item operations, revisions, history, grounds and source links | Raw host/provider I/O |
| `context` | Continuation reconstruction, candidate selection, applicability, relation expansion and packing | Second Store or model scheduler |
| `learning` | Purpose-specific input selection, request builders, disclosure reduction, decoders, reducers and publication proposals | Job claims, provider retries or credentials |
| `vectors` | Vector-space identity, result mapping and vector candidate arm | Provider transport or second vector database |
| `jobs` | Due selection, claim/reclaim, finite handler dispatch, reconciliation and result application | Semantic algorithms duplicated from handlers |
| `adapters::host` | Native host event decoding, `CaptureCommand`, mutually attested daemon IPC and context emission | Task ownership, semantic publication or Store status invention |
| `adapters::controller` | Authenticated controller IPC, inference methods, Operation/artifact readback, queued cancel and release | Memory job state, publication, provider credentials or route planning |
| `adapters::source` | Document, structure and Research translation | Another memory service |
| `spool` | Immutable pending publication, bounded replay inventory, pause/drain ownership and failed quarantine | A second canonical event store |
| `platform::windows` | Named mutex, Job Object, retained executable/path leases, exact inherited-handle list, named-pipe peer admission, TCP owner observation, immutable publication and mutable selection replacement | V2 platform framework, policy, manifests or generic capability registry |
| `control` | External status/inbox/configuration/maintenance commands, operation IDs and daemon-side quiesce | Root/Owner credentials, arbitrary supervisor commands or process handles |
| `runtime::supervisor` | Installation selection, privileged control owner, root/Owner operations, migrations, Store candidates, child lifecycle and cutover | Memory semantics or public control surface |
| `runtime::daemon` | Application composition, Editor Store owner, relay accept loop, jobs/replay and bounded shutdown | Privileged credential/process effects |

Dependency direction:

```text
model + pure transformations          -> no I/O imports
store + outbound adapters + spool     -> model and external dependencies
application operations                -> model, Store API and narrow clients
host / CLI / MCP surfaces             -> application operations
runtime composition                   -> concrete constructors, privileged owner and startup/shutdown
```

Keep RPC, HTTP, SQL, host JSON, pipe frames and filesystem helpers private. Internal calls share typed Rust values; serialize only at storage, process or network boundaries. Add a trait at a real interchangeable I/O boundary, not for every table or function.

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

Finite expensive work uses the existing `job` runner. A long-lived task exists only when it must retain an actual resource or continuously receive input. The inherited supervisor channel owner, relay named-pipe accept loop and Store WebSocket owner qualify because they own live OS handles; they are not generic actors. Runtime plugin discovery, dynamic Rust ABI, WASM packaging and hot-generation machinery are not selected.

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
| `control(command)` | Operation ID plus status/inbox, configure, pause/cancel, correct, withdraw/erase, backup/restore/rotate or shutdown state |

`record_outcome` reuses capture. An unavailable capability fails specifically; it does not return successful empty output.

The daemon owns the external `control` operation. A command that requires root/Owner, process lifecycle or installation replacement is converted into one closed privileged maintenance intent on the inherited channel. Returning an operation ID or supervisor acknowledgement is not completion; `control` reads the actual process/credential/selection/Store state until terminal or unknown.

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

Privileged maintenance is not another primary table. The daemon may use an ordinary finite `job` row when the user needs durable status, but supervisor authority and cutover truth come from the inherited operation ID plus actual credential/process/installation readback. Before the daemon exists, startup migration/bootstrap truth is installation/Store state, not a fabricated job row.

### 4.7 Blobs, locators and packet records

Large source bytes, prompts, packets and results live under the selected root's `blobs/`; rows keep opaque references and digests. Publish immutable blob bytes durably before committing a row that refers to them. Cleanup may remove unreferenced temporary files later; a committed row must never point to bytes that were never saved.

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

### 5.0 Owned authenticated transport and wire types

The Store uses one small internal remote-only JSON WebSocket client over the supervisor-owned loopback SurrealDB child. It reuses `tokio-tungstenite` and `serde_json`; it does not link the database engine and does not import the V2 Store adapter.

Initial RPC method surface:

```text
query
```

Authentication and database selection happen in the verified WebSocket upgrade, not through RPC session mutation. The client first creates a raw `TcpStream`, verifies the established server peer belongs to the retained child, then passes that stream plus the secret-bearing custom request to `client_async_with_config`. No credential is sent through `connect_async` to an unverified port.

The request uses Basic Authorization and the exact `Surreal-Auth-NS`, `Surreal-Auth-DB`, `Surreal-NS`, `Surreal-DB` headers appropriate to the account. It requests `json`, validates the 101 response/subprotocol and retains finite frame/message/request deadlines. Connection and query errors never render headers or the request.

Each authenticated socket is owned by one dedicated Tokio task. Callers send bounded typed commands over a private channel; the owner permits exactly one in-flight query, continuously reads control/data frames and is the only code allowed to touch the socket. Ping is answered promptly even while no application caller is polling. A response is delivered only to the exact in-flight request ID.

Caller cancellation does not abandon socket state: the owner either observes and discards the exact terminal response under its deadline or closes the connection. Any send/read timeout, close, protocol violation, unexpected data when no request is in flight, duplicate/wrong response ID or caller loss after a mutation may have been sent poisons the socket and ends the owner task. A late response can never become the next request's result. Mutation outcome is then `OUTCOME_UNKNOWN`; reconnect first repeats raw-peer verification and the authenticated handshake, then application identity readback decides whether retry is allowed. A read-only operation may retry only under its own explicit finite budget.

There is no RPC `signin`, `use`, `version` or `ping` surface. Binary digest/process/listener/peer admission establishes server identity; WebSocket control frames establish transport liveness. Each role/profile gets a fresh authenticated socket rather than mutating one session between principals or databases.

JSON is only the envelope for **closed application DTOs**. It is not a generic SurrealDB value codec: the upstream JSON mapping collapses `NONE` and `NULL`, stringifies native record IDs, UUID, datetime, duration and decimal, and maps non-finite floats to null. Therefore:

- every fixed query has an explicit projection and one exact decoder;
- wire scalars are bounded strings, signed integers, booleans and finite floats;
- application IDs and references use canonical strings under closed table/kind enums;
- time uses an integer epoch plus explicit precision/uncertainty fields;
- optional values have explicit presence/state fields when `NONE` and `NULL` differ;
- vectors reject NaN/Infinity and verify exact dimension/order;
- large or exact bytes remain immutable blobs and cross the Store only by reference/digest;
- no operation decodes generic Surreal `Value`, uses `SELECT *` as a persistence format or relies on implicit native-type JSON round-trip.

SurrealDB's CBOR format preserves special values through vendor-specific tags. V3 does not copy that private tag protocol into another client. A later admitted typed dependency may replace the JSON DTO layer only after exact MSRV/license/size and behavior proof.

Application queries are checked-in `.surql` assets or compile-time fixed strings with JSON-safe bound variables. Dynamic table/index identifiers are selected from closed enums. A variable that can affect grammar is never supplied as raw user/agent text. Query results project only the fields needed by the named operation, with row/byte limits and stable continuation keys.

A transport, shutdown or WAL-sync failure after a mutation may have been applied is `OUTCOME_UNKNOWN`. Reconnect does not replay the mutation blindly. The application reads by its unique operation/command/item identity first; only a proven non-commit or a bounded retryable transaction conflict permits the exact transaction to run again.

### 5.1 Schema, credentials and migration ownership

The supervisor/bootstrap Owner applies ordered, checksummed `.surql` migrations before daemon Store admission. Do not add SurrealKit, a migration service or a migration database for the initial product.

Baseline schema rules:

- define the configured namespace and a `STRICT` database explicitly under `--no-defaults`;
- define the six application tables as `SCHEMAFULL`;
- define every owned field and type explicitly;
- use `FLEXIBLE` only on a named bounded native-metadata object whose unknown fields are intentionally retained;
- keep wire-facing application identity/time/optional representations compatible with §5.0 DTO rules;
- define composite unique indexes for stream and observation identities;
- define unique indexes on `memory.address_unique_key`, `memory_history(item, revision)` and active/pending job slot keys;
- define ordinary indexes only for queries that appear in a connected reader;
- build initial indexes synchronously before ready;
- use `CONCURRENTLY` only for a later online migration with explicit readiness polling;
- never use the 2.x-only `DEFER` clause on the 3.x target.

Store the expected migration number in database parameter `$eliot_schema_generation`. Startup reads `INFO FOR DB` and `INFO FOR TABLE` and compares actual definitions/digests against checked-in migration metadata. `IF NOT EXISTS` is not enough for a changed definition: a mismatched existing table/field/index blocks daemon admission until the named migration resolves it.

The database-scoped Owner owns migrations and user rotation. The ordinary daemon receives only the Editor reference. Root and Owner run their fixed DDL/query corpora only through separately authenticated, peer-verified supervisor sockets. User creation/rotation uses one fixed DDL shape with a locally generated Argon2 PHC verifier in `PASSHASH`; it runs only while slow-query logging and telemetry are disabled and the verifier is never retained in application logs, backup manifests or Store result bodies. Successful DDL is reconciled by independent Basic handshake and restart readback. Root is not a normal migration credential.

### 5.2 Transaction and conflict rules

The RPC `query` call executes one complete fixed transaction text with bound variables. The client inspects **every** per-statement status/result; a successful WebSocket response or final `COMMIT`-shaped value cannot hide an earlier failed statement. Every result is decoded through the operation's explicit DTO, never through a broad row map.

SurrealDB transactions provide snapshot isolation. Therefore:

- unique indexes own identity/cardinality whenever possible;
- a record whose current value controls a write is read with `FOR UPDATE`;
- stream sequence allocation locks the stream record;
- memory revision publication locks/rechecks the current item;
- a predicate-only invariant over a set uses a deterministic sentinel/slot record or unique derived key; an existence query alone is not serialization;
- `UPSERT` without an exact deterministic record identity is not an idempotency primitive.

If two transactions modify the same record or unique value, one may fail with a retryable conflict. Retry the **whole** transaction with the same immutable command, IDs and expected revisions under a finite attempt/backoff budget. Unique-constraint conflict after a retry is resolved by exact readback and byte/binding comparison. Unknown transport, shutdown or WAL-sync outcome is reconciled before any retry.

With the selected RocksDB `sync=every` profile, a transaction is applied before the grouped `flush_wal(true)` completion is returned. Failure at that edge is not proof of rollback. Only a matching application readback can classify it as committed; absence under a qualified healthy Store may permit a retry.

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

### 5.4 Windows durable-file primitives

The initial durability profile is one qualified local fixed NTFS/ReFS volume. UNC/network/removable roots and reparse traversal are rejected. Temporary and final files for one operation are always in the same directory/volume.

#### Immutable no-replace publication

Immutable blobs, pending commands, deletion notices, backup pages/manifests and immutable candidate artifacts use one internal primitive:

1. retain/validate the parent directory without following reparse points;
2. create a unique same-directory temporary regular file with `CREATE_NEW` semantics;
3. write complete bytes through a bounded buffer;
4. flush userspace buffers and call `sync_all`/`FlushFileBuffers` on the writable file;
5. close the file handle;
6. rename to the absent final name with `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` **without** `MOVEFILE_REPLACE_EXISTING` or cross-volume copy;
7. open the parent directory with write access, `FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OPEN_REPARSE_POINT` and call `FlushFileBuffers`;
8. reopen the final regular file no-follow and verify identity/length/digest.

If the final path already exists, never overwrite it. Open/verify it and perform a successful parent-directory flush before returning prior `staged`; different bytes are conflict.

If rename succeeds but parent sync or final readback fails, publication is **post-commit unknown**, not staged and not a pre-commit failure. Reconciliation reopens the exact final path, verifies bytes, retries directory sync and only then returns staged.

The legacy `atomic_replace_file` donor uses `MOVEFILE_REPLACE_EXISTING` and is therefore not this primitive.

#### Mutable installation-selection replacement

`installation.toml` is intentionally different: exactly one current selection must replace the previous generation. Only the supervisor may perform this under the installation mutex:

1. read and retain the current file; require the expected generation;
2. construct a complete next record with `generation = current + 1`, closed current/previous root IDs and explicit current/pending/previous credential references;
3. create/write/flush/close a same-directory temporary file and retain its expected byte digest;
4. call `MoveFileExW(temp, installation.toml, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`;
5. flush the parent directory;
6. reopen no-follow and verify exact bytes/digest, generation, root IDs and credential references;
7. keep the previous root and previous credentials until a later explicit retirement operation.

`ReplaceFileW` is not selected because its advertised write-through flag is not a supported durability mechanism. The mutable replacement is never reused for immutable spool/blob publication.

If the replace call may have succeeded but directory sync/readback fails, the disposition is `SELECTION_UNKNOWN`. Do not write another generation blindly. Startup/reconciliation opens the actual file and classifies:

- expected new generation and bytes → replacement committed;
- exact old generation and bytes → replacement did not commit;
- missing, malformed, unexpected generation or mismatched bytes → fail closed with both roots/credentials retained for owner inspection.

No process resumes mutation after cutover until selection and selected Store readback agree.

#### Relay publication outcome

Direct daemon delivery has four private dispositions:

```text
committed
rejected
stage_required
unknown
```

`stage_required` is returned before blob/Store ownership whenever shutdown, backup, restore cutover or another explicit quiesce has closed mutation admission. It is transient and never maps to public `rejected`.

Relay delivery:

1. call daemon `capture` over the mutually attested named pipe;
2. accept `committed` only with matching Store readback;
3. accept deterministic `rejected` only when no ownership transfer occurred and the command must not be retained;
4. on `stage_required`, unavailable daemon, or disconnect/timeout/malformed reply after possible send, publish the exact same serialized command through the immutable primitive;
5. return public `staged` only after successful final verification;
6. if Store commit and durable pending publication both remain unestablished, return `unknown`.

Do not return `forwarded` as success and do not overload rejection to mean temporary quiesce.

### 5.5 Daemon spool replay

The daemon is the only automatic replayer. One replay owner exposes a pause/drain boundary used by backup, shutdown, restore cutover and erasure. Pausing first stops admission of another item; draining waits for the current item to reach matching Store readback, deterministic rejection, retained pending state or an explicitly reconciled unknown. An unresolved possible Store mutation blocks successful backup/cutover/erasure rather than allowing the same occurrence to fall between Store and spool inventories.

For each bounded fair batch:

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
| `SessionEnd` | session lifecycle boundary and reason |

The adapter retains unknown fields only inside a bounded raw source representation when configured; domain projections remain closed and explicit.

`PreToolUse`, permissions and stop/finish gates are outside first Base profile. If later added, they are separate opt-in host effects and cannot mutate memory truth merely by blocking an action.

### 6.2 Relay process behavior

A hook invocation reads one bounded JSON object, validates adapter compatibility, constructs one immutable `CaptureCommand`, performs daemon calls over the mutually attested one-request pipe boundary, attempts direct capture then spool, optionally requests context at a supported decision boundary, writes one bounded host-compatible stdout object, writes diagnostics separately and exits without claiming more than achieved.

Capture and context have separate timeout budgets. Capture may be staged while context times out. Context failure cannot erase committed/staged capture state. A failed/unknown direct connection is never retried with a new command ID; the relay publishes the same serialized command.

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

## 12. Deletion, backup, restore and credential transitions

### 12.1 Withdrawal and erasure

Withdrawal stops guidance, not physical deletion.

For erasure, publish an exact text-free deletion notice through the immutable primitive, close affected mutation/replay admission, drain or reconcile any in-flight replay, cancel pending work, fence unresolved controller work and prevent late Store/Research/spool reintroduction. Page/remove controlled observations, memory/history, representations, packet/job blobs, staged commands, links and affected backups. Do not claim complete while any controlled copy or possible Store write remains unresolved.

### 12.2 Application-owned backup cut

SurrealDB logical export is not the application backup owner. Although the core exporter reads one database snapshot, the HTTP route can commit status before the export job ends and surface a later job failure only in server logs while the client sees an ordinary body EOF. Import is statement-by-statement and may leave partial state. The selected Store profile therefore keeps HTTP `export` and `import` disabled.

Backup is daemon-owned and operates over the six tables, selected-root immutable blobs, active deletion notices, retained failed quarantine and a finite pending-spool cut:

1. enter `backup_preparing`; close mutation admission, new replay admission, claims, cleanup and blob/deletion maintenance;
2. finish or reconcile all admitted short Store mutations and drain the replay item already in flight; any unresolved possible write blocks successful backup;
3. acquire the cross-process spool publication mutex used by relays, establish a cut ID and enumerate exact immutable pending and retained failed files; a relay blocked behind the cut publishes afterwards and is post-cut;
4. release the publication mutex; keep replay paused and mutation admission closed; direct daemon capture receives `stage_required`, so new accepted commands stage after the cut rather than enter either inventory;
5. page every table through checked-in read-only queries in stable canonical application-identity order with immutable cursor fences;
6. encode each page as a versioned canonical application JSON Lines format: fixed DTO struct/field order, no unordered maps/sets, no Unicode/content normalization, finite numbers only, exact escaped UTF-8 bytes and a header carrying table/schema/page/cursor/count identity;
7. hash exact page bytes; copy and verify every referenced immutable blob, selected pending command, retained failed entry and active deletion notice;
8. include a sanitized non-secret `config.toml` snapshot and digest for later comparison/rebinding, but never a secret or Credential Manager value;
9. write a manifest containing backup-format version, source installation/selection generation, binary/storage/schema identity, cut ID, table/page/row counts and digests, blob/spool/deletion/config inventories and explicit gaps;
10. publish the complete backup through the immutable primitive;
11. record success, failure or post-publication unknown; only then reopen mutation admission and resume replay.

Every table page is read while application mutation admission and replay are closed. Background SurrealDB metadata maintenance does not authorize changes to V3 application rows. The manifest—not EOF—owns completion. A failed backup leaves live data intact and no published successful manifest.

Credentials, root bootstrap material, controller/provider secrets and database-user verifiers are not backup content. Unfinished external jobs retain their exact operation/copy/reconciliation state as ordinary rows; backup never redispatches them. Failed quarantine is restored as failed, never silently promoted to pending.

The first implementation accepts only backup format/schema generations explicitly supported by the running build. Unsupported older/newer input is an exact refusal; do not invent a generic migration framework before a real compatible format exists.

### 12.3 Restore is exact rollback, not hidden merge

The initial restore operation activates the exact application state of one selected backup cut, after applying newer monotonic deletion fences and external spool continuity. It does **not** claim to merge Store rows committed after that backup. Without a retained change log and conflict policy, such a merge cannot be proved.

Therefore:

- if the current Store is admitted, the daemon first creates and verifies a fresh safety backup of the current generation before accepting rollback cutover;
- an owner may explicitly select disaster recovery without a fresh safety backup only when the current Store is unavailable/damaged, and status records that current committed data could not be inventoried;
- the previous root is retained after cutover, so post-backup committed rows remain recoverable there or in the safety backup until explicit retirement;
- only deletion notices and pending/failed spool entries are unioned/merged automatically, because they have monotonic fence or exact command/disposition semantics outside the backed-up Store cut;
- completed Store rows, revisions, jobs and settings from the discarded timeline are not silently copied into the restored root;
- once controller inference is enabled, unresolved external Operations not represented in the target backup block cutover until terminal/released, or require an explicit abandonment disposition; restore must not orphan a possible late result/controlled copy.

Restore never imports a SurrealQL dump and never writes into the selected live root. The supervisor owns the candidate process, root/Owner credentials and installation replacement. The daemon owns user-facing validation, safety backup, current Store/spool/deletion facts and quiesce.

#### Candidate preparation

1. The daemon validates the requested retained backup ID, exact owner intent and safety-backup/disaster-recovery precondition, then sends `maintenance_request(restore, operation_id, backup_id, expected_selection_generation)`; no path or SQL crosses the channel.
2. The supervisor resolves the backup beneath `backups/`, verifies its immutable identity and refuses a stale selection generation.
3. It creates a fresh closed candidate root under `data/roots/` and starts at most one isolated candidate SurrealDB child on another owned dynamic loopback port.
4. It runs the short root-bootstrap child, reconciles unknown bootstrap with the retained candidate credential, restarts without root environment material, creates namespace/`STRICT` DB and candidate Owner/Editor with `PASSHASH`, and applies checked migrations.
5. It verifies backup-format/schema support, manifest and every table page/blob/spool/deletion/config digest before admitting content.
6. It reads the current installation deletion ledger supplied through the closed cut facts and unions it with backup notices. Current/newer notices dominate backup content; a backup can add a fence but never remove or roll one back.
7. It restores only rows/blobs not fenced by that union through fixed candidate Owner queries and explicit table DTOs.
8. It stages verified backup pending/failed entries separately; every fenced command is discarded, and original pending/failed disposition is retained for cutover reconciliation.
9. It compares the sanitized configuration snapshot with current configuration and reports/rebinds differences explicitly; it never overwrites current secrets, paths or profiles silently.
10. It verifies counts/digests after declared fence exclusions, exact current/history/source reads, uniqueness/cardinality probes, deletion fences, job/controller identities and representative write/read/delete behavior.
11. It restarts the candidate under its ordinary Editor profile and repeats full independent admission. Until cutover, the daemon cannot connect to or mutate the candidate.

Any candidate parse, DTO, schema, row, blob, spool, deletion, config, conflict, restart or verification failure discards the entire candidate. A retry starts with another empty candidate.

#### Cutover

1. The supervisor sends `quiesce(operation_id, expected_selection_generation, candidate_root_id)`.
2. The daemon closes mutation/new-replay/job admission; direct capture receives `stage_required`; it drains/reconciles the active replay and every admitted Store mutation, blocks on unresolved write outcome, freezes the current spool/deletion inventory and closes the active Store socket.
3. The daemon sends `quiesced` with exact old root/selection generation, spool/deletion cut facts, unresolved external-operation disposition and safety-backup identity.
4. The supervisor verifies the operation/cut facts, stops the old active SurrealDB child and merges staged backup spool entries with the current installation spool by command ID, exact bytes and disposition: preserve every current entry, reject same-ID/different-bytes and never downgrade failed to pending.
5. It publishes the union deletion ledger and replaces `installation.toml` to select the candidate root and retain the old root as `previous_root_id` using §5.4. If replacement is `SELECTION_UNKNOWN`, it performs exact readback before any further action.
6. When the selected new generation is proven, it treats the admitted candidate as the active Store and sends a fresh `store_descriptor` to the daemon.
7. The daemon independently verifies process/listener/peer, resolves the selected Editor reference, repeats schema/typed-probe admission and sends `daemon_ready`.
8. The supervisor sends `resume`; only then do mutation admission and replay reopen.

If the daemon or inherited channel is lost before selection replacement, the supervisor abandons the candidate and leaves the old selection active. If loss occurs after a possible replacement, startup reads the actual selection and admits that root; it never assumes rollback or repeats the same generation blindly. The prior root remains until explicit retirement.

Primary reads become available after successful cutover/admission; optional embeddings/views/Research refresh later through ordinary jobs. Status names the rollback source cut and previous-root/safety-backup divergence rather than claiming current-row merge.

### 12.4 Credential rotation

Store-user rotation is supervisor-owned and uses current/pending/previous Credential Manager references in `installation.toml`; the daemon never receives root/Owner material.

For Editor rotation:

1. the supervisor creates one pending credential secret and publishes a new selection generation naming `editor_pending` while retaining current/previous references;
2. it uses an independently admitted Owner socket and a fixed `PASSHASH` statement to alter the Editor user;
3. if the mutation outcome is unknown, it probes the pending credential first and the current credential second; it never generates another pending secret;
4. once the pending credential authenticates, it replaces the selection so pending becomes current and old current becomes previous;
5. it sends the new selection/Store descriptor to the daemon; the daemon opens a fresh peer-verified Editor socket and acknowledges admission;
6. only after daemon admission plus restart readback may a later retirement operation delete the previous secret.

If the old credential still works and the pending one does not, the mutation did not commit and may retry with the same pending secret under a finite budget. If neither or both violate the expected transition, rotation blocks with both references retained.

Owner rotation follows the same pattern using root or the retained current Owner as the privileged actor; it does not require daemon reconnection. Root rotation is not part of first Base and cannot be improvised through startup credentials.

### 12.5 Previous-root and credential retirement

Retirement is a separate explicit control operation after a successful cutover/rotation has survived restart and exact readback. It never runs automatically at cutover. It rechecks that the root/credential is not current, pending, referenced by an unresolved operation or required by an unfinished cleanup/erasure obligation. Physical deletion uses bounded traversal and reports partial/unknown rather than changing the active selection to hide residue.

## 13. Control and observability

Direct controls: status/inbox, inspect/open, pause/resume jobs, cancel queued work, configure projects/hosts/disclosure/profiles, correct/withdraw/erase, backup/restore, credential rotation, previous-generation retirement and shutdown.

The daemon owns the external control surface and exact operation IDs. It delegates only closed privileged effects to the inherited supervisor channel. A request/acknowledgement is never reported as completion; status is derived from actual facts.

Status shows at least:

- Eliot/Surreal binary version/digest/signature and retained-launch disposition;
- supervisor/daemon generation, inherited-channel state and last correlated privileged operation;
- installation-selection generation, current/previous/pending root and credential-reference states without secret material;
- daemon named-pipe generation/owner and bounded peer-rejection classes;
- canonical storage URL/engine/sync mode, per-start port and observed listener/peer owner;
- bootstrap/migration/rotation/reconciliation phase;
- Editor/Owner authenticated-handshake readiness and Store socket owner/poison/reconnect state;
- schema generation and Store readiness gap;
- graceful/forced last shutdown;
- capture committed/staged/unknown/rejected and internal `stage_required` count;
- spool pending/failed counts/age/publication-unknown/replay paused-or-in-flight;
- backup cut/disposition/format/manifest and safety-backup identity;
- restore candidate, exact rollback source, quiesce/cutover/selection-unknown state, deletion-union/spool-merge disposition and previous-root divergence;
- context prepared/emitted/gap, exact-open dispositions, job/profile/controller states, result/application and per-copy cleanup.

Do not equate adjacent lifecycle states. Origin/CORS is never displayed as Store authentication. A privileged request is not an effect; candidate verification is not cutover; selection replacement is not daemon admission; prior-root retention is not merged current data. Missing usage/cost/account is unknown. Notification failure does not block status/control.

## 14. Implementation sequence

Write connected production code first. Run minimum relevant build/Clippy after each coherent code increment. Do not construct a speculative test framework. Full automated testing follows connected implementation.

Before each slice: one integrator/edge; cheap preflight before setup; no overlap without disposition; measure merged behavior/blockers.

### Slice 0 — dependency, authority, wire and durability preflight

Before Base code:

1. acquire/pin exact Eliot and SurrealDB Windows binaries, sizes, SHA-256 digests, PE and observed signature dispositions;
2. prove retained no-follow executable/ancestor leases, deny-write/delete sharing, streaming digest, suspended child image identity, exact inherited handle list, Job assignment and resume; force executable swap, reparse, pre-existing writable handle, leaked unrelated handle and post-create mismatch;
3. qualify the two inherited anonymous pipes: exact handle list/environment values, bounded frames/IDs, one privileged operation, EOF/crash behavior and no arbitrary path/SQL/secret payload;
4. prove the selected SurrealDB binary starts and restarts the same canonical selected RocksDB root with explicit `sync=every`, `--no-defaults` and no SurrealKV fallback;
5. prove sanitized environment, dynamic numeric-loopback port, retained process handle, listener owner, established peer owner, disabled metrics/identification/slowlog/telemetry/Postgres/import and allowed/denied HTTP/query/function matrix;
6. qualify relay→daemon named-pipe first-instance/DACL/remote rejection and mutual process attestation; force pipe squat, wrong SID/session/image, stale PID, missing daemon Job membership, oversize/partial frame, excess connection and timeout;
7. prove CORS/Origin does not authorize WebSocket, anonymous upgrade cannot query, and connection-exhaustion behavior stays within the admitted local threat/resource profile;
8. run the short root-bootstrap child, reconcile bind/startup unknown with the same retained root credential, restart without root environment material, authenticate root in a peer-verified Basic handshake, provision database Owner/Editor with `PASSHASH`, then restart and prove both database handshakes again;
9. run strict schema/index migration through supervisor Owner, then prove the query-only dedicated socket owner handles control frames/cancellation: deny RPC `signin`, `use`, `version`, `ping` and every other method; force timeout, caller cancellation, late/wrong response, close and reconnect so no poisoned socket is reused;
10. complete full supervisor descriptor→daemon independent Store admission and relay exposure;
11. freeze explicit JSON-safe DTOs and round-trip optional-state, ID/reference, integer-time, finite-vector and pagination boundaries without generic `Value` or `SELECT *`;
12. exercise unique conflict, `FOR UPDATE`, whole-transaction retry, disconnect and applied-before-WAL-sync/shutdown unknown readback;
13. exercise immutable create-new/no-replace publication and mutable installation replacement separately; force file/rename/parent-sync/readback failures and prove old/new/unknown generation reconciliation;
14. prove `stage_required`, replay pause/drain and exact public `staged|unknown` mapping under backup/shutdown/erasure, including an in-flight replay whose Store outcome is unknown;
15. complete canonical backup and exact-rollback restore into a fresh candidate, including safety backup/disaster mode, exact blobs/deletion notices/pending+failed spool, current-ledger late erasure, current post-cut spool merge, explicit non-merge of post-backup Store rows, unresolved controller-operation block, forced mismatches, unsupported format, candidate discard and previous-root retention;
16. rotate Editor with one pending secret through unknown commit, pending/current probes, selection replacement, daemon reconnect, restart readback and delayed previous-secret retirement; qualify Owner rotation separately;
17. exercise privileged channel loss before and after possible cutover, graceful shutdown with active maintenance/replay and forced Job Object containment, then prove consistent restart admission/readback.

This preflight changes dependencies only when evidence requires it. It does not build a second storage framework, public supervisor API or copied SurrealDB CBOR protocol. Minimal Windows executable-lease, explicit-handle-list, named-pipe peer and TCP-owner functions may be adapted from exact V2 donors; V2 platform/framework/session/lease machinery is not imported.

### Slice 1 — Store and local lifecycle

Implement supervisor/daemon/owned SurrealDB, retained launch identity, inherited privileged channel, mutually attested relay IPC, closed process profile, exact listener/peer and authenticated-handshake admission, supervisor-owned bootstrap/migrations/credentials, daemon-owned Editor socket, typed Store DTOs, `CaptureCommand`, immutable blob publication, exact read after restart, pending spool publication/replay with pause/drain, mutable installation selection, status/shutdown and revision/history.

```text
real event → committed or staged → replay if staged → restart → exact open
```

### Slice 2 — Useful Base and first host

Connect Claude relay profile, continuation, exact/full-text retrieval, notes/corrections/commitments, actual SessionStart/UserPromptSubmit context emission, packet retention/handoff, source open and application-owned Base backup/exact-rollback restore/erase. Base runs with controller/model/vector/document/Research disabled.

### Slice 3 — Controller inference owner

Implement Contract 0.4: role, connection/profile/digests, destination admission, methods, artifacts, dedup, cancel/unknown, one runner, loopback text then embeddings, readback, per-copy cleanup, three release dispositions and erasure fence; no Task/Attempt/ScriptRun/new table.

### Slice 4 — First learning

Pin `swarm-client`; one controller adapter; one episode handler; exact request/result; verification; decode/publication; later context; correct cleanup. Exercise unknown/no-result/cancel/malformed/partial/cleanup/abandon/restart without duplicate inference. Extend restore cutover to reject or explicitly abandon unresolved post-backup controller Operations before switching timelines.

### Slices 5–6 — independent increments and advanced improvement

Add vectors, views, documents, Research and hosts only by real prerequisites, then cross-episode curation/diagnosis after base paths work. Reuse the same jobs/revisions/context; no second runtime.

### Final verification

After connected product, build the suite over production operations, concurrency, restart, executable/pipe/peer ownership, privileged channel and selection replacement, Store conflict/unknown outcomes, authenticated handshake/socket cancellation, spool durability/replay quiesce, exact-open pagination, canonical backup/exact rollback/deletion union/spool merge, credential rotation, erasure and optional failure. Stub providers qualify local mapping only.

Measure actual latency, I/O, calls, retained bytes, dependencies and code size. Line count is diagnostic, not quota.