# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.29 · 2026-10-26 · concrete design for the greenfield rewrite.**

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
- retained executable/process/data-root identity;
- root/Owner credential use, schema migration and DB-user rotation;
- the installation-selection generation and planned cutover/shutdown.

The daemon owns application state and ordinary Editor-authenticated Store operations. It does not supervise itself, receive root/Owner credentials or mutate the active installation selection. Hosts and `eliot-swarm-controller` do not own this process family. Provider/model processes remain controller/provider concerns.

### 1.2 Data root, access profile and configuration

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

The initial profile is one local fixed NTFS/ReFS volume. The installer creates or validates a protected installation-root DACL for the configured user and LocalSystem, rejects unexpected broad read/write principals, network/removable roots and reparse traversal, and applies the same controlled access to data, spool, deletions, backups and logs. Existing roots that do not satisfy the selected access profile block admission rather than being silently “fixed” after content is read.

Source bodies, spool files, databases and backups are plaintext application data protected by the local account/DACL and the volume's own security. V3 does not claim application-level at-rest encryption. Automatic backup destinations remain inside the controlled installation root. A future portable/off-machine backup needs an explicit encryption/destination design; copying a local-only backup outside the controlled root is a user/external boundary and cannot be included in complete erasure claims.

`config.toml` contains practical user configuration:

- the allowed/base local data directory, not the selected active root;
- configured projects/workspaces and host binding rules;
- capture exclusions, per-event bounds and retention;
- enabled host adapters and their native executable/config paths;
- controller IPC/data root and private inference-client credential path/reference;
- selected text/embedding profile names;
- project/source disclosure defaults;
- idle timeout and automatic-work mode;
- optional document/Research tools;
- explicitly allowed cross-project reuse scopes.

It is not a generated policy database, route registry, module catalogue, runtime inventory, logical-principal generator or installation pointer.

`installation.toml` is a small supervisor/installer-owned selection record, not a second application state store. It contains only the information needed to select and admit the process family:

- a monotonic installation-selection generation;
- one stable non-secret Memory installation ID and expected `controller_client_id` that survive root cutover, rollback and inference-token rotation;
- one current and at most one unretired previous closed root ID under `data/roots/`;
- exact Eliot and SurrealDB executable paths, versions, sizes and SHA-256 digests;
- exact canonical storage profile and explicit RocksDB durability mode;
- namespace/database names and expected schema generation;
- the installation-scoped daemon pipe identity and loopback endpoint policy, not trusted pre-existing endpoints;
- non-secret Windows Credential Manager references for root, Owner and Editor, with at most one pending and one unretired previous reference per role;
- the closed launch/environment profile and last admitted non-secret identity.

A second root cutover is refused while `previous_root_id` remains unretired. A second credential rotation for one role is refused while that role has a pending or unretired previous reference. This bounded backpressure prevents an older controlled root/secret from becoming unaddressable merely because another generation was selected.

A daemon may read the non-secret selected root/profile/Editor reference and expected `controller_client_id` needed to admit ordinary Store and optional inference access. Only the supervisor resolves root/Owner references or replaces `installation.toml`. Neither daemon nor restore invents a new controller principal when the expected one is unavailable.

Before any controller application request, `adapters::controller` authenticates with the configured private credential and requires a typed hello receipt whose `client_id`, role and protocol match the admitted installation identity and `inference_client` contract. A missing/mismatched receipt is `caller_identity_unavailable`; the connection closes before application I/O. Supplying a credential file is not itself authenticated-principal proof, and Operator/admin access is not a normal fallback.

The first qualification target is SurrealDB **3.3.4**. The initial production storage candidate is the external server with RocksDB because SurrealDB 3.3 documents RocksDB as the recommended on-disk engine while SurrealKV remains beta. The supervisor derives one canonical Windows storage URL from the selected closed root ID and appends explicit `sync=every`; callers do not supply alternate URL spellings, root paths or query parameters.

This is a qualification target, not a completed proof. Store readiness is unavailable until the exact Windows binary and profile pass launch/root-identity, startup, restart, conflict, acknowledged-commit durability, owned-listener/peer admission, typed Store transport, application backup/restore and durable-file/selection checks. Do not silently fall back to another server version, root or storage engine.

Provider connections, provider credentials, adapter IDs and `actual_destination` declarations stay with `eliot-swarm-controller`. Memory stores only selected profile names, the stable non-secret controller caller identity, frozen non-secret execution identity returned by controller, and non-authoritative credential-reference generation/digest diagnostics. It never stores token bytes or a reusable token verifier.

### 1.3 Demand start, internal control, local IPC, Store admission and shutdown

The supervisor holds a named mutex for the stable installation root throughout startup, operation and shutdown. A relay connects first; if no daemon endpoint answers, it starts a supervisor candidate and waits. Only the candidate owning the mutex starts children. An existing owner with an unready daemon is not permission to launch another process family or database.

#### Retained executable and data-root identity

Before creating an owned child, the supervisor opens the approved executable without following a final reparse point, verifies regular-file identity and streams its SHA-256 through a bounded buffer. The retained handle denies later write/delete sharing; retained no-follow handles pin the executable parent, working directory and relevant ancestors so a junction or rename cannot redirect the path after validation.

The selected/candidate root is derived only from its closed root ID beneath `data/roots/`. The supervisor opens the root and relevant ancestors no-follow, verifies directory/file identity and DACL, denies delete/rename sharing while allowing the Store's ordinary file creation/writes, and retains that root lease for the SurrealDB child's lifetime. Candidate creation uses the same primitive. A path string or selection record without a retained root identity cannot authorize a Store child.

The supervisor creates the child suspended, keeps its process handle, re-observes the child image path and file identity against the retained executable, assigns it to the owned Job Object and only then resumes it. Any disagreement terminates the still-suspended child. Executable/root leases remain alive through the child lifetime. A path string, pre-launch digest or PID alone is not launch identity. Slice 0 must prove the selected sharing modes and ancestor pins work with the exact Eliot/SurrealDB binaries and RocksDB directory access.

#### Supervisor↔daemon inherited control boundary

Before launching the daemon, the supervisor creates two bounded one-way anonymous pipes to form one duplex private control channel. It marks only the daemon ends inheritable and supplies exactly those handles through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with `bInheritHandles=TRUE`; unrelated handles are not inherited. The child-only environment contains only decimal handle values and protocol generation, never a secret. Both processes clear inheritance on their retained ends immediately after startup.

This is not a named public endpoint. It needs no discovery, DACL-based peer selection or bearer token because the validated supervisor creates the pipes and the validated suspended daemon receives exact handles. One owner task on each side performs all framing and handle I/O. Frames are versioned, length-prefixed, bounded, correlated by one exact operation ID and restricted to a closed enum such as:

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

`store_descriptor` carries only non-secret facts needed for independent admission: SurrealDB PID/start time/image/file identity, root/selection generation, endpoint, storage/profile digest and expected schema generation. The daemon opens and retains its own process handle to that child, repeats root/process/listener/peer/auth/schema admission and reports `daemon_ready`; a descriptor is not authority by itself.

A maintenance request names only a closed operation kind, operation ID and already retained backup/configuration/credential generation ID. It never carries raw SQL, executable arguments, endpoint, arbitrary filesystem path, password, verifier or credential value. The supervisor independently resolves the named object beneath the retained installation-root handle, verifies its identity and uses its own root/Owner Credential Manager references.

Only one privileged maintenance operation is active per installation. Ordinary backup creation is daemon-owned; schema migration, DB-user rotation, candidate restore, SurrealDB lifecycle and installation cutover are supervisor-owned. The daemon owns mutation admission, replay/job drain, exact Store readback and quiesce evidence. The supervisor owns privileged execution, child handles, candidate roots and installation selection.

Channel EOF is fail-closed. A daemon that loses the supervisor closes mutation admission, requests relay staging where possible, closes Store sockets and exits within a finite deadline. A supervisor that loses the daemon does not continue a pre-cutover restore/rotation from an unconfirmed request; a candidate is disposable unless durable installation-selection readback already proves cutover. After a possible selection replacement, startup reconciles the actual selection before any retry.

#### Relay→daemon named-pipe boundary

The relay and daemon communicate over one installation-scoped Windows named pipe. The daemon creates the first pipe instance exclusively, rejects remote clients and applies a protected DACL granting only LocalSystem and the configured current-user SID. A stable installation identifier, not a PID or random pathname alone, derives the pipe name; the first-instance flag makes a pre-existing name an admission failure rather than a second daemon.

Every connection is mutually attested before application bytes are trusted:

- the relay obtains the pipe server PID, opens a process handle and verifies start time, session, exact Eliot image path/file identity and membership in the supervisor-owned Job;
- the daemon obtains the pipe client PID and verifies start time, current-user SID/session and exact approved Eliot relay image identity;
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

Root omits database-auth headers until the namespace/database exists. Database users authenticate and select their one configured database during the handshake. RPC `signin` and `use` are unnecessary. Exact binary/path/root/process/listener/peer identity replaces RPC `version`; WebSocket control Ping/Pong replaces RPC `ping`.

SurrealDB still accepts an anonymous WebSocket upgrade when no Authorization header is supplied. Guest arbitrary query is denied, so it cannot read/write Store data through the selected method surface, but connection-exhaustion behavior must be measured in Slice 0. If random per-start port, bounded server settings and measured behavior are insufficient, pinned WSS or a narrow authenticated proxy is a separate evidence-driven hardening decision; Origin is never promoted as the fix.

#### Root bootstrap, migrations and database users

For local Store credentials, Windows Credential Manager is the only secret authority. Generate the root bootstrap credential once and retain the same secret through all reconciliation attempts. Root bootstrap is deliberately short-lived:

1. on an empty selected root, start one bootstrap child with that root username/password in its child-only environment;
2. wait until upstream startup has persisted the root user and `/ready` succeeds;
3. gracefully stop that child and restart the same root **without** root credentials in its environment;
4. verify root/process/listener/peer ownership, then authenticate root in the WebSocket Basic handshake;
5. create the configured namespace, `STRICT` database and two database-scoped users through fixed root queries;
6. prove Owner and Editor can authenticate in pinned Basic handshakes;
7. run ordered checked migrations through a separately authenticated Owner socket and verify schema generation/definitions;
8. restart again without root environment material and repeat Owner admission before starting the daemon.

A bootstrap child may persist root before a later bind/startup failure. That is `OUTCOME_UNKNOWN`, not permission to generate a new root password. Restart without root environment material and try the retained credential. If root authentication succeeds, bootstrap committed. If it fails and no other writer can exist under the installation mutex, stop the child and retry bootstrap with the **same** credential under a finite budget; persistent mismatch blocks rather than rotating or overwriting root.

The two database-scoped users are:

- **Editor** — ordinary daemon Store reads and application mutations;
- **Owner** — supervisor-owned migrations, DB-user rotation and typed restore writes.

The supervisor derives a standard Argon2 PHC verifier locally and provisions users with fixed `PASSHASH` statements; plaintext database-user passwords are not placed in SurrealQL, argv or logs. Slow-query logging remains disabled because `PASSWORD`, `PASSHASH` and `PASSSCRAM` are literal-bearing DDL. SCRAM material is not created while Postgres/SCRAM transports are disabled. Credential headers, DDL buffers, handshake failures and RPC errors are secret-bearing: logs retain only bounded error class and operation identity, never header, request, statement, password or verifier.

The daemon receives only the non-secret Editor reference and reads only that Credential Manager entry. The supervisor code path resolves root/Owner. Because both processes initially run under one Windows account, this is an application authority boundary against accidental misuse, not a claim that arbitrary malicious same-account code cannot read the user's credentials. A stronger threat model requires a separate OS identity/service account.

#### Startup admission

A normal startup is ordered:

1. read and verify `installation.toml`, selected root/access profile and executable identities under the installation mutex;
2. acquire retained selected-root/ancestor handles and start/admit the selected SurrealDB child;
3. reconcile bootstrap/credential state and run pending checked migrations through root/Owner;
4. create the inherited supervisor channel and launch the validated daemon;
5. send one `store_descriptor`;
6. require the daemon to repeat root/process/listener/peer/Editor/schema/typed-probe admission and report `daemon_ready`;
7. only then expose the relay pipe and accept capture/read/control operations.

Store readiness requires all of these observations:

1. exact selected root and executable identities match the installation generation;
2. the owned child starts, retains its process handle and owns the expected loopback listener;
3. `/ready` succeeds after upstream startup/heartbeat gates;
4. the raw TCP connection's server peer is the retained child before authenticated upgrade;
5. Editor Basic handshake succeeds with exact authentication and selected namespace/database headers;
6. all RPC methods except fixed `query` and all non-system query subjects/functions/routes are denied;
7. schema generation and `INFO FOR DB/TABLE` match §5.1;
8. one bounded typed write/read/delete probe succeeds through the production client.

A root path, listener port, process heartbeat, `/health`, `/status`, `/ready`, supervisor descriptor, WebSocket 101 or successful TCP connection alone is not Store readiness. A root, binary, owner, peer, profile, credential, schema or typed-probe mismatch stops Store mutation before relays can claim capture ownership.

After Store is ready, the daemon begins bounded fair replay of `spool/pending`. Replay does not block primary exact reads or new capture indefinitely. It pages entries in stable order, processes a finite batch, then yields. Corrupt or permanently rejected entries move to `spool/failed`; transient Store failure leaves them pending. Replay uses the same capture operation and command ID.

#### Normal and forced shutdown

Normal idle or explicit shutdown is not Job Object termination. The daemon validates the external control operation, then:

1. closes mutation admission; direct capture receives internal `stage_required` before blob/Store ownership;
2. stops claiming new work and pauses new replay;
3. drains eligible work and active replay; reconciles possible Store writes;
4. persists progress, closes Store sockets and sends `shutdown_ready(operation_id)`;
5. exits only after supervisor acknowledgement or inherited-channel failure.

The supervisor then validates the operation ID, requests graceful SurrealDB shutdown, waits through a finite deadline, reports actual exit, and uses Job termination only for deadline/crash containment. It releases the installation mutex only after process ownership is settled.

`stage_required` is private flow control, not a fifth public capture result and not `rejected`. Public `staged` requires exact durable pending-file publication; otherwise `unknown`.

SurrealDB may continue shutdown after logging cleanup failures. A clean exit is not an application durability receipt. Every next start repeats full admission and exact readback. An error after RocksDB applied a transaction but before grouped WAL sync is `OUTCOME_UNKNOWN` and reconciles by application identity.

If the supervisor dies, the Job Object terminates owned children. Next demand start reads the actual selection generation and repeats admission. Restarting a failed daemon does not restart a healthy Store unless the new daemon cannot independently admit it.

Primary capture/reads become available after daemon admission. They do not wait for optional inference, embeddings, views or full spool drain.

## 2. Code structure

### 2.1 Start with one Rust package

Use one library package plus a thin executable selecting supervisor/daemon/relay modes. Ordinary modules provide boundaries. Split a crate only for a real dependency/deployment/independent-change boundary.

| Module | Owns | Does not own |
|---|---|---|
| `model` | Small values crossing real internal boundaries | Vendor SDKs, runtime, universal contract catalogue |
| `store` | Bounded authenticated SurrealDB query client, fixed queries, typed DTOs, transactions, exact reads and blob references | Arbitrary SurrealQL/generic Value, host protocol, installation selection |
| `memory` | Semantic items, revisions, history, grounds and source links | Raw host/provider I/O |
| `context` | Continuation reconstruction, candidate selection, applicability, relation expansion and packing | Second Store or model scheduler |
| `learning` | Purpose-specific input selection, request builders, disclosure reduction, decoders, reducers and proposals | Job claims, provider retries or credentials |
| `vectors` | Vector-space identity, result mapping and vector candidate arm | Provider transport or second vector DB |
| `jobs` | Due selection, claim/reclaim, finite handler dispatch, reconciliation and application | Semantic algorithms duplicated from handlers |
| `adapters::host` | Native host decoding, `CaptureCommand`, mutually attested daemon IPC and context emission | Task ownership or semantic publication |
| `adapters::controller` | Authenticated controller IPC, typed hello verification, inference/readback/cancel/release | Memory job/publication/provider credentials or principal migration |
| `adapters::source` | Document, structure and Research translation | Another memory service |
| `spool` | Immutable pending publication, bounded replay, pause/drain and failed quarantine | Second canonical event store |
| `platform::windows` | Named mutex, Job Object, executable/root leases, inherited-handle list, named-pipe peer admission, TCP owner observation, protected DACL validation, immutable publication and mutable selection replacement | V2 platform/policy/manifest framework |
| `control` | External commands, operation IDs and daemon-side quiesce | Root/Owner credentials, arbitrary supervisor commands or process handles |
| `runtime::supervisor` | Installation selection, privileged channel, root/Owner, migrations, Store candidates, lifecycle/cutover/rotation | Memory semantics/public control |
| `runtime::daemon` | Application composition, Editor Store owner, relay loop, jobs/replay and bounded shutdown | Privileged credential/process effects |

Keep RPC, SQL, host JSON, pipe frames and filesystem helpers private. Internal calls share typed Rust values; serialize only at actual boundaries. Add traits only at real interchangeable I/O boundaries.

The current SurrealDB Rust SDK is **not** baseline: 3.3.4 requires Rust 1.95 while this repository declares 1.94, and its package metadata needs explicit license-policy admission. Reconsider only after exact cargo check/deny/dependency-size proof and demonstrated simplification.

### 2.2 Base and additive capabilities

**Base** provides capture, explicit notes/corrections/commitments, exact/lexical retrieval, current work, bounded context/open, restart/spool and maintenance. It starts without controller, model, encoder, converter or Research credentials.

| Capability | Additional dependency | Existing consumer |
|---|---|---|
| First Claude host | One relay/hook configuration | `capture`, `context`, `open` |
| First learning | Base observations, one controller client, one recipe | `memory`, `context`, `open` |
| Vector retrieval | Base revisions and embedding profile | Candidate arm in `context` |
| Project understanding | Base source access + structure tool | Versioned project views |
| Documents | Base blobs/jobs + converter | Excerpts and exact source `open` |
| Research | Configured Research client | Findings/report/source handles |
| Richer cognition | Claims/methods/outcomes + text inference | Same jobs/revisions/context |
| Another host | Native events/delivery boundary | Same operations |

These increments are not a compulsory chain.

### 2.3 Integration is ordinary code

A capability adds only its real client/decoder, handler/operation, first writer fields/indexes, real consumer and maintenance. It does not automatically add a process, manifest family, bus, scheduler, database, compiler, plugin platform or proof family.

Finite expensive work uses `job`. Long-lived tasks exist only to own a live resource or receive input: supervisor channel owner, relay pipe accept loop and Store socket owner qualify. Runtime plugins/WASM/hot-generation are not selected.

### 2.4 Optional means optional

Construct optional clients only when configured. A capability failure remains local; Base survives. Disabling a producer stops new dispatch without deleting retained readable knowledge. Already admitted controller Operations retain exact identity until reconciled/released/erased. Use Cargo features only when omitting a heavy dependency materially reduces build/package.

## 3. Application surface and work binding

| Operation | Result |
|---|---|
| `attach(workspace, session)` | Binding, continuation address, gaps and actual capabilities |
| `capture(command)` | `committed`, `staged`, `unknown` or `rejected` plus existing observation identity |
| `context(frame, budget, retrieval=local)` | Packet ID, text, exact revisions, handles and gaps |
| `open(handle, read_context, range?)` | Exact page, relations and continuation |
| `record_outcome(report)` | Captured observed result or sourced report |
| `dream(request)` | Finite configured interpretation/research/improvement job |
| `control(command)` | Operation ID and exact status for configure/pause/correct/erase/backup/restore/rotate/retire/shutdown |

The daemon owns external `control`. Privileged work becomes a closed inherited-channel intent. An operation ID or supervisor acknowledgement is not completion; actual process/credential/selection/Store readback owns status.

### 3.1 Work binding

Configuration owns stable project/workspace IDs. Resolve binding per event/request, not one mutable current project. A tool reading another root keeps resource binding and task relation. Late events/spool use captured binding. Continuation address uses project/workspace + host task identity or narrow actor/session fallback. Branch/HEAD/path are observed environment. Missing association is an explicit gap, not permission to mix projects.

### 3.2 `CaptureCommand`

```text
command_id                 occurrence/idempotency key
project/workspace binding  exact or explicit unresolved/ad-hoc
source_kind/native_id      host family and stream/session identity
native_event_key           tool/message/agent ID when supplied
event_kind                 closed normalized enum
occurrence/receipt time    native precision + receiver time
body | blob                exact accepted bytes
body_length + sha256       verification, not occurrence identity
search_excerpt             bounded projection
locator                    transcript/path/url/tool/resource coordinates
disclosure                 local_only | external_allowed
capture_limit              explicit truncation/redaction/omission facts
relations                  supplied call/result/parent/task/resource facts
```

The command is immutable after first durable publication. Equal content does not merge occurrences. Reusing one command/event key with different bytes/binding is conflict. Exclusions/redactions run before publication and remain explicit.

## 4. Physical data model

Use six primary tables plus selected-root blobs. Add fields/indexes only with first real writer and reader.

### 4.1 `stream`

`id`, `project`, `source_kind`, `source_native_id`, optional workspace and `last_ingest_seq`. Unique `(project, source_kind, source_native_id)`. Sequence orders one stream only.

### 4.2 `observation`

Source event/report/application event with project/stream/event key/sequence, command/native IDs, occurrence/receipt times, kind, exact body/blob/digest/excerpt, disclosure, captured work/resource facts, packet/correction references, locator and capture limits.

Unique:

```text
(project, stream, event_key)
(project, command_id)
```

A tool result, agent report, prepared packet and handoff are separate observations.

### 4.3 `memory`

Current semantic revision: identity/origin/reuse/revision/kind; method role/purpose; optional exact address and derived unique key; content/search/cues/aliases; disclosure/limitations; subject/aspect/perspective; conditions/exceptions/selectors; validity; support/exposure/influence; commitment state; vector/effective space/representation; timestamps.

`address_unique_key = NONE` for unaddressed items; a unique index applies only to complete addresses.

### 4.4 `memory_history`

Previous revisions, unique `(item, revision)`. Version handles never fall forward; current reads never resurrect history.

### 4.5 `link`

Revision-aware source/target, relation kind, optional grounds group, locator and qualification. Kinds cover evidence/live requirement/contradiction/replacement/episode/resource/outcome/method/packet/navigation. One non-null grounds group is conjunctive; groups are alternatives; ungrouped support advisory.

### 4.6 `job`

Finite background work retains identity/project/purpose/target/state, active/pending slot, origin/cause, due/attempt/retry/waiting, frozen inputs and recipe revision, claim/limits/disclosure/profile, exact request blob/digest and application result.

For controller-backed work it also retains this exact non-secret identity:

```text
controller_client_id
client_request_id
method + canonical bounded request identity
controller_operation_id when known
profile/adapter/connection/destination snapshot
credential-reference generation/digest diagnostics
result artifact ID/length/digest when known
Memory result blob
controller_reconciliation = not_required | reconcile_required | caller_identity_unavailable
input/result cleanup state and release Operation/disposition
```

The credential diagnostic is over a non-secret reference/generation record, never token bytes or a reusable token verifier. It can explain which credential was presented; it does not own the Operation. Every job for one admitted installation must name its stable `controller_client_id`. A different ID is damage or blocked principal migration, not token rotation.

Per-copy state:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Aggregate cleanup derives from copies. One active + one pending successor per target; terminal history has no slot.

Privileged maintenance is not another primary table. An ordinary job may support durable user-visible status, but authority/cutover truth comes from inherited operation ID plus credential/process/selection/Store readback.

### 4.7 Blobs, locators and packets

Large bytes live in selected-root `blobs/`; rows hold opaque ref/digest. Publish bytes before row commit. Packet is an ordinary observation/blob with exact included revisions/budget/gaps and link descriptors. Locators claim only supplied precision. Dirty/untracked code is retained bytes/range, not HEAD alone.

### 4.8 Spool

One pending file = one versioned command + schema/digest/published time/replay count/bounded non-content error. Filename derives from command ID. No committed archive. Failed quarantine remains bounded and subject to erasure.

## 5. Store, schema and durable publication

### 5.0 Owned transport and wire types

One small JSON WebSocket client over the owned SurrealDB child; no engine link/V2 adapter. RPC surface: `query` only.

The client verifies raw TCP peer ownership before sending a custom Basic-authenticated request with exact auth/selection headers and `json` subprotocol. Each socket has one owner task, one in-flight ID and continuous control/data handling. Caller cancellation drains exact response or closes. Timeout/close/protocol/wrong/late response poisons the socket. Possible mutation send becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth admission and identity readback.

JSON is only for closed DTOs:

- explicit projection/decoder per query;
- bounded strings/signed ints/bools/finite floats;
- canonical application IDs;
- integer time + precision/uncertainty;
- explicit optional state where NONE/NULL differ;
- vectors verify dimension/order and reject non-finite values;
- exact/large bytes stay blobs;
- no generic `Value`, `SELECT *` persistence or implicit special-type round-trip.

Do not copy vendor CBOR tags. Fixed `.surql` assets/strings use JSON-safe bound variables; grammar-changing identifiers come from closed enums. Results have stable order/continuation and real row/byte limits.

### 5.1 Schema, credentials and migration owner

Supervisor/bootstrap Owner applies ordered checksummed migrations before daemon admission. Baseline:

- configured NS + `STRICT` DB under `--no-defaults`;
- six `SCHEMAFULL` tables and every owned field;
- narrowly named bounded `FLEXIBLE` metadata only;
- wire-compatible identities/times/options;
- composite occurrence/idempotency indexes;
- unique address/history/job-slot indexes;
- only reader-backed ordinary indexes;
- initial synchronous indexes; later `CONCURRENTLY` only with readiness polling;
- no 2.x `DEFER`.

`$eliot_schema_generation` plus `INFO FOR DB/TABLE` and checked definitions/digests own admission. `IF NOT EXISTS` is not migration verification.

Daemon gets Editor only. Supervisor root/Owner use fixed corpora over peer-verified sockets. User create/rotation uses locally derived Argon2 `PASSHASH`; slowlog/telemetry off; no verifier in logs/manifests/results. DDL is followed by fresh handshake and restart readback.

### 5.2 Transactions/conflicts

One RPC query executes one fixed transaction and every per-statement status is inspected/decoded. Snapshot isolation rules:

- unique values own identity/cardinality;
- controlling records read `FOR UPDATE`;
- stream sequence/current revision lock and recheck;
- predicate-only set invariant uses deterministic sentinel/unique slot;
- nondeterministic `UPSERT` is not idempotency.

Retry whole immutable transaction only for exact retryable conflict. Unique conflict resolves by readback/byte comparison. Transport/shutdown/WAL unknown reconciles before retry. `sync=every` may apply before fsync result; error is not rollback proof. No network/controller/document/Research call runs inside DB transaction. Blob publication precedes row transaction.

### 5.3 `capture_event`

Publish referenced blob, then one transaction:

1. resolve/create unique stream;
2. lock stream;
3. read command and event identities;
4. identical replay returns saved result;
5. different bytes/binding conflict;
6. allocate sequence;
7. insert observation/relations/limits;
8. coalesce only implemented follow-up;
9. commit.

Post-commit identity/body/binding readback is required for `committed`. Capture does not call a model.

### 5.4 Windows durable-file primitives

#### Immutable no-replace

Retain/validate parent no-follow; create same-directory temp `CREATE_NEW`; bounded write; file flush; close; `MoveFileExW(..., WRITE_THROUGH)` without replace; parent-directory flush; reopen/verify identity/length/digest. Existing exact final is prior success after directory flush; different bytes conflict. Rename then failed sync/readback is post-commit unknown.

#### Mutable installation selection

Supervisor-only under installation mutex:

1. read/retain current and require expected generation;
2. build complete `generation+1` record with stable installation/controller caller identity, current/previous roots and current/pending/previous Store credential refs;
3. write/flush/close temp and retain expected digest;
4. `MoveFileExW(temp, installation.toml, REPLACE_EXISTING | WRITE_THROUGH)`;
5. parent flush;
6. no-follow exact readback of bytes/digest/generation/refs;
7. retain previous controlled copies until explicit retirement.

`ReplaceFileW` is not selected as write-through. A possible replacement with failed readback is `SELECTION_UNKNOWN`; startup classifies exact new, exact old or fail-closed unexpected. No mutation resumes until selection and Store agree.

#### Relay outcome

Private daemon dispositions: `committed | rejected | stage_required | unknown`. `stage_required` occurs before Store/blob ownership while quiesced. Relay publishes the same command on `stage_required`, unavailable or uncertain direct result. Public `staged` requires immutable publication; otherwise `unknown`. No `forwarded` success.

### 5.5 Spool replay

One daemon replayer exposes pause/drain. Pause stops another item; drain reaches matching Store readback, deterministic rejection, retained pending or explicitly reconciled unknown. Unresolved possible write blocks backup/cutover/erasure.

Per bounded fair batch: stable regular-file enumeration; type/size/schema/filename/ID/digest/deletion checks; same capture; committed→delete+parent flush; permanent rejection/corruption→no-replace failed move+reason+both dir flushes; transient failure→retain/yield; poison item cannot starve. Cleanup sync failure reconciles actual location. Command identity/body/binding never mutate.

### 5.6 Memory revision

One transaction locks current, rejects stale revision, copies history, writes new current, inserts revision-specific links, settles command/job, coalesces affected work and commits. New-item IDs allocated once and retained with decoded job result.

### 5.7 Job claim

Only configured/enabled/eligible handlers. Waiting for idle/profile/disclosure/resume is not failure. One transaction fairly claims slot, freezes finite inputs + exact method, reduces disclosure and selects profile. For controller-backed work it loads the admitted installation's expected `controller_client_id`, builds the canonical request identity and saves all request/job fields before possible application I/O. Reclaim never rebuilds a different request for an admitted Operation.

### 5.8 External result/cleanup

Controller authentication/readback happens outside Store. The adapter verifies the typed hello receipt before every new physical connection. Caller mismatch sets `caller_identity_unavailable` and sends no application frame. Verify result ranges, retain controller identity + Memory blob, decode retained bytes. Store conflict replays proposal, not inference. Release dispositions: `memory_copy_verified`, `terminal_without_result`, `abandon_for_erasure`. Input/result states independent; release never rolls back valid publication. Local Operator erasure may delete by exact provenance without exposing result bytes or adopting caller ownership.

### 5.9 Exact `open`

Require one handle. Resolve current, exact history, observation/body/blob/range, converted representation, Research section/citation or copied controller result. Return requested/resolved identity, range/digest, state/limits/qualifications, revision-aware relation descriptors, expansion handles/cursor and exact missing/forbidden/erased/damaged/unsupported disposition.

Coherent hydration uses one snapshot or revision fences. Packet bytes/observation retained before host output; host emission separate. All large reads page by real byte/row limits and preserve UTF-8 boundaries.

## 6. First Claude host adapter

### 6.1 Event profile

| Native event | Captured content/binding |
|---|---|
| `SessionStart` | identity/source/cwd/work hints, then actual continuation packet |
| `UserPromptSubmit` | exact accepted prompt + task identity, then decision packet |
| `PostToolUse` | tool/name/native ID/input/result/duration/resource |
| `PostToolUseFailure` | tool/id/input/error/interruption/duration |
| `Stop` | main final message + stop/session facts |
| `SubagentStop` | agent ID/type/final/parent; handback tool remains tool event |
| `PostCompact` | compact summary as derived representation |
| `SessionEnd` | lifecycle reason |

Unknown fields only in bounded raw representation when configured. `PreToolUse`/permissions/finish gates outside Base.

### 6.2 Relay behavior

Read one bounded JSON object; validate adapter; build immutable command; use mutually attested one-request pipe; direct capture then spool; optionally request context; write one bounded host-compatible stdout object; diagnostics separately. Capture/context budgets separate. Same command ID on uncertainty.

### 6.3 Qualification

SessionStart/UserPromptSubmit success contains actual packet, not service status. Before default enablement record installed Claude version, real payloads, final/compact fields, output schema/limits, timeout/exit, fork/resume/clear/compact and subagent distinctions.

## 7. Retrieval/context/open

Decision frame contains work address, observed versions, focused question, cues, constraints and budget. Address current work before search. Generate bounded direct/address/exact/lexical/vector/grounds/relation/method arms independently; union before selection; scope before arm limits.

Rank relevance separately from support. Applicability is applicable/inapplicable/conditional-or-unknown. Pack current work, corrections, methods+exceptions, prior episode, dissent/checks and source handles. If a unit cannot fit, qualified reduction + handle or explicit gap; never drop negation/version/contraindication.

Exact source open never reruns search/conversion/Research/inference or substitutes newer representation.

## 8. Views, documents and affected grounds

Project view = versioned answer over examined scope with source handles/gaps. Membership changes dirty/qualify it; refresh affected views only; prior qualified view and direct source survive failure.

Documents:

```text
captured original
→ finite converter job
→ retained representation/status/errors
→ searchable excerpts
→ exact open
```

No reconversion on read/newer substitution. Corrections/refutations/conditions/erasure coalesce targeted follow-up. Reverse indexes page conclusion revisions; full grounds groups load; navigation is not evidence; traversal finite/resumable.

## 9. Controller inference, embeddings and Research

One Memory client from [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md) over pinned `swarm-client`; no copied framing/MCP/CLI. Controller route is not Task/Attempt and does not own Memory semantics.

Before any application I/O, the adapter loads the admitted installation's expected stable `controller_client_id`, authenticates with the configured private credential and validates a closed typed hello receipt:

```text
receipt.client_id == installation.controller_client_id == credential.client_id
receipt.role == inference_client
receipt.protocol_version supported
```

The inspected `swarm-client` donor currently discards this receipt, so typed exposure/verification is a required controller change. Mismatch closes the connection before an application frame and holds affected jobs `caller_identity_unavailable`; it does not create a new principal or use Operator/admin as ordinary recovery.

Before first possible application send, atomically save stable caller ID, request ID, method/canonical bounded request identity, profile, disclosure/origin, exact input blob/digest, limits/format, source/recipe revisions and non-authoritative credential-reference generation/digest. Token bytes and reusable token hashes never enter Store.

Exact replay is permitted only under the same authenticated caller. Known Operation uses `operation.get`/artifact/release readback. Possible send with unknown Operation ID replays the same method/request identity under the same caller; proven no-send may dispatch the retained request once. A new request ID or `client_id` is not recovery. Complete/usable partial requires exact-caller artifact readback; malformed output is not no-change. Release semantics are solely Contract 0.6.

A same-`client_id` token rotation can preserve ownership only after old authenticated connections are closed/restarted, the new typed hello is validated and a pre-rotation Operation is read/released. Changing `client_id` is explicit principal migration outside initial Base.

Embeddings use the same Operation/copy/read/release and one result/error per input key; exact revision/representation mapping, no zero/shifted vectors. Research separates search/run/status/artifact/report-section/cited-open and saves idempotency before submission.

## 10. Learning

Episodes group by actual session/task/call/result relations. Freeze membership; selected/supplied/processed coverage distinct; no global bit. Normal job receives episode/feedback/small related set/exact recipe and may create/revise/conflict/unknown/no-change. Direct correction uses §5.6.

First enable saves default processing method; claim freezes revision; upgrade never overwrites edited method. Automatic mode off/idle/background; profile may deny automatic. New input coalesces one pending target and preserves first queued time. Foreground stops new idle dispatch; admitted work finishes/unknown. Output must reach context/open/method consumer.

## 11. Consolidation, disagreement and commitments

Replay, packet grouping, same-item revision, synthesis and correction/split are distinct. Broader pattern is separate provisional item linked to exact sources. Rival explanations remain claims with grounds/counterevidence; choose cheapest distinguishing observation; voting is not evidence. Prediction precedes action.

Commitment is scoped memory with owner/recipient/state/due/source; showing/ack/due does not resolve. Notifications do not create task manager. Self-diagnosis names failed edge—capture, Store/spool, source selection, admission/execution/readback/release, decode/publication/retrieval/delivery/use/method—and corrects that edge.

## 12. Deletion, backup, restore and credential transitions

### 12.1 Withdrawal and physical erasure

Withdrawal stops guidance, not physical deletion.

Erasure publishes a text-free monotonic deletion notice, closes affected mutation/replay admission, drains/reconciles active replay, cancels pending work, fences unresolved controller work and prevents late reintroduction.

Controlled copies include:

- current Store rows and selected-root blobs;
- `spool/pending`, retained failed quarantine and packet/job blobs;
- the one unretired previous root;
- every disposable candidate root;
- controlled backup/safety-backup generations;
- controller input/result copies and affected Research/document representations.

The deletion ledger is an anti-reintroduction fence, not proof of physical deletion. Initial Base does not implement selective offline rewrite of previous roots/backups. If such a generation contains erased scope, complete erasure requires deleting the entire previous/candidate root or backup generation with bounded traversal and parent-directory durability. If the owner retains it, erasure remains incomplete even though it cannot be reactivated without applying the fence. An exported/off-machine copy is outside controlled scope and is reported as such.

Do not claim complete while any controlled copy or possible Store write remains unresolved.

### 12.2 Backup cut

Surreal logical export is not owner: HTTP can hide terminal job failure and import is partial. Backup is daemon-owned over six tables, selected-root blobs, active deletion notices, retained failed quarantine and finite pending spool.

Steps: close mutation/replay/claims/cleanup; reconcile writes and active replay; hold cross-process spool publication lock and cut exact pending+failed inventory; keep new direct capture `stage_required`; page tables through fixed stable DTO queries; encode versioned canonical JSONL with fixed field order/no unordered maps/no normalization/finite numbers/header identity; exact-byte hashes; copy blobs/spool/deletions; include sanitized config; manifest format/schema/selection/binary/storage/cut/count/digest/inventory/gaps plus stable Memory installation ID and `controller_client_id`; immutable publish; reopen only after success/failure/unknown recorded.

Manifest carries the strictest disclosure of included content. The automatic backup remains under the protected local installation root and is never sent to external storage by Base.

Credentials/verifiers/token bytes are excluded. Unfinished external jobs retain exact stable caller/request/method/Operation/artifact/release identity, per-copy cleanup and non-secret credential-reference diagnostics. Failed quarantine restores as failed. Only explicitly supported backup/schema generations accepted.

### 12.3 Restore is exact rollback, not hidden merge

Initial restore activates exact application state of one backup cut after newer deletion fences and external spool continuity. It does not merge Store rows committed later; no retained change log/conflict policy exists.

- healthy current Store first creates verified safety backup;
- disaster recovery without it is explicit and records uninventoried current data;
- previous root remains retained, so later rows remain recoverable until retirement;
- only deletion notices and pending/failed spool auto-union/merge;
- post-backup Store rows/revisions/jobs/settings are not copied silently;
- every restored controller job must name the manifest/installation `controller_client_id`; a different retained ID is damaged/unsupported, not migration;
- restored jobs with known controller Operation IDs are held `reconcile_required`: use exact operation/artifact/release readback under the same authenticated caller, never redispatch;
- possible-send jobs without a known Operation ID replay only the retained method/canonical request identity under the same caller; pending jobs proven unsent may issue that retained request once after new Store admission;
- a credential/hello mismatch becomes `caller_identity_unavailable`: no read/cancel/release or redispatch claim, and controller-copy cleanup/erasure remains incomplete;
- current unresolved external Operations outside target backup block cutover until terminal/released or explicitly abandoned;
- restore is refused while another unretired `previous_root_id` exists. The owner must retire it or first convert it into a controlled typed backup and delete the root.

A previous root is a recovery source, never a directly reselectable active root. Returning to it always uses the typed restore pipeline into a fresh candidate so current deletion fences/config/credentials are applied.

A caller-identity failure does not corrupt unrelated Base records or authorize another provider call. The selected Store may serve Base while inference admission stays closed; status exposes affected job/Operation IDs and exact cleanup debt. Recovery requires a credential for the same registered principal or an explicit non-disclosing local-Operator abandonment/erasure action. Operator access never transfers ownership or creates cognitive result bytes.

#### Candidate preparation

Daemon validates retained backup ID, owner intent and safety/disaster precondition, then sends closed restore request with expected selection generation. Supervisor resolves beneath backups root, refuses stale generation/retained previous root, creates fresh candidate root and one isolated candidate child, runs short bootstrap, creates candidate Owner/Editor with current secrets, migrates, verifies all manifest/page/blob/spool/deletion/config digests, unions current deletion ledger, restores unfenced rows/blobs through fixed Owner DTOs, stages pending/failed separately, compares config explicitly, verifies counts/reads/constraints/jobs and requires all backed-up inference jobs to match the manifest's stable caller identity. It restarts/admitted candidate under Editor. Daemon cannot mutate candidate before cutover. Any failure discards whole candidate.

#### Cutover

Supervisor sends quiesce. Daemon closes mutation/replay/jobs, returns `stage_required`, drains/reconciles writes/replay, freezes spool/deletion facts and closes active Store socket. Supervisor verifies cut facts, stops old Store, merges staged backup spool with current exact command/disposition, publishes deletion union and replaces selection current=candidate/previous=old. `SELECTION_UNKNOWN` resolves by readback. It sends new descriptor; daemon independently admits root/process/listener/peer/Editor/schema/typed probe; only then Base resumes. Controller-backed jobs resume only after their typed hello caller/role/protocol check; otherwise they remain held without blocking unrelated Base reads/capture.

Loss before selection replacement abandons candidate. Loss after possible replacement reconciles actual selection on startup. Previous root remains until explicit retirement. Status names rollback source and divergence, never current-row merge.

### 12.4 Store credential rotation and session revocation

At most one pending/previous reference per role; another rotation is refused until resolved/retired.

Editor rotation must revoke the already authenticated daemon session:

1. supervisor creates one pending secret and publishes pending reference;
2. sends quiesce; daemon closes mutation/replay/jobs, drains writes and **closes the old Editor WebSocket**;
3. supervisor uses a fresh Owner socket and fixed `PASSHASH` mutation;
4. unknown outcome probes pending first/current second; never generates another secret;
5. when pending authenticates, selection promotes pending→current and current→previous;
6. supervisor closes every privileged socket and gracefully restarts SurrealDB so no pre-rotation Basic-authenticated session survives;
7. sends new Store descriptor; daemon independently authenticates current Editor and completes admission;
8. resume only after daemon readiness; previous secret remains through restart readback and later explicit retirement.

If current still works and pending does not, retry same pending under finite budget. If neither/both violate expected transition, block with both refs retained.

Owner rotation follows the same pending/probe/selection/restart pattern using root or current Owner. Root rotation is outside first Base. Store restart is part of rotation completion because changing the stored password alone does not prove revocation of already authenticated WebSocket sessions.

Inference-client token rotation is a separate controller integration governed by Contract 0.6. It keeps the same `controller_client_id`, stops new inference admission, retains one pending/current credential reference, classifies unknown token update with the same pending secret, closes every old authenticated controller connection or restarts the host, validates the new typed hello receipt and proves read/release of a pre-rotation Operation before old-secret retirement. Changing `client_id` is principal migration, not rotation; initial Base has no implicit ownership-transfer path.

### 12.5 Previous-generation retirement

Retirement is separate after successful cutover/rotation survives restart/readback. It rechecks the root/credential is not current/pending, not referenced by unresolved operation and not required by cleanup/erasure.

For a previous root:

- direct reactivation is forbidden;
- if future recovery is required, first create/verify a controlled typed backup;
- scan the root/backup against current deletion notices;
- if erased scope remains, delete the whole generation or keep erasure incomplete;
- delete root tree boundedly, flush affected parents and verify absence;
- only then clear `previous_root_id` in a new selection generation.

For a previous credential, prove all selected Store generations use current credentials and no unresolved rotation references it, delete the Credential Manager entry, verify absence, then clear previous ref. Physical deletion partial/unknown never disappears behind pointer update.

## 13. Control and observability

Controls: status/inbox/open, pause/resume/cancel, configure, correct/withdraw/erase, backup/restore, credential rotation, previous-generation retirement and shutdown.

Daemon owns external surface/operation IDs; delegates only closed privileged effects. Status derives from facts:

- executable/root identity/DACL/signature/launch leases;
- supervisor/daemon generation, inherited channel and privileged operation;
- selection generation, current/previous/pending root and credential refs;
- relay pipe peer-rejection classes;
- storage URL/engine/sync/port/listener/peer;
- bootstrap/migration/rotation/reconciliation;
- Editor/Owner handshakes and socket owner/poison/reconnect;
- schema/Store readiness and shutdown;
- capture/stage_required/spool/replay;
- backup disclosure/cut/manifest/safety generation;
- restore rollback source, non-merge divergence, restored-job reconciliation, candidate/quiesce/cutover/selection unknown/deletion+spool merge;
- previous-root/backup controlled-copy erasure debt;
- expected/authenticated controller client ID, hello role/protocol, credential-reference generation, `caller_identity_unavailable` jobs, exact Operation/artifact/release identity and per-copy cleanup debt;
- context/open/jobs and cognitive publication state.

Do not equate request with effect, candidate with cutover, selection replacement with daemon admission, deletion fence with physical erase, password/token update with live-session revocation, credential-file contents with authenticated principal, Operator erasure with result-byte access, previous-root retention with merged data, or local digest with confidentiality. Unknown usage/cost/account remains unknown.

## 14. Implementation sequence

Production code first; minimum relevant build/Clippy after coherent increments; no speculative test framework; full suite after connected product. Before each slice: one integrator, cheap preflight, terminal overlap disposition, measure behavior/blockers.

### Slice 0 — dependency, authority, wire and durability preflight

1. exact Eliot/Surreal binaries, PE/signature/digests;
2. executable + data-root no-follow/ancestor leases, DACL, sharing, suspended image, exact inherited handles, Job assignment; force swap/reparse/writable handle/leaked handle/root rename;
3. inherited anonymous-pipe protocol/EOF/closed vocabulary/no arbitrary payload;
4. canonical selected RocksDB root `sync=every`, no-defaults/no fallback;
5. sanitized env, dynamic listener/peer, disabled surfaces and denial matrix;
6. relay pipe first-instance/DACL/remote/mutual identity/frame/connection bounds;
7. Origin non-authority, denied guest query and anonymous-socket bounds;
8. short reconciled root bootstrap, Owner/Editor PASSHASH, root-free restarts;
9. supervisor migration and query-only cancellation-safe socket owner;
10. full descriptor→daemon independent admission;
11. JSON DTO edge round-trips;
12. conflict/FOR UPDATE/whole retry/disconnect/applied-before-fsync unknown;
13. immutable no-replace vs mutable selection replace, all sync/readback/unknown outcomes;
14. stage_required/replay pause-drain under backup/shutdown/erase;
15. canonical backup + exact rollback: protected plaintext/disclosure, safety/disaster mode, previous-root backpressure, late erasure, pending+failed spool, non-merge, restored-job reconciliation, unresolved controller block, mismatch/unsupported/candidate discard;
16. Editor rotation with quiesce/old-socket close/PASSHASH/unknown probes/selection/Store restart/new admission/delayed retirement; Owner separately;
17. physical erasure across current/previous/candidate/backups and explicit incomplete state;
18. second cutover/rotation blocked until prior generation retirement;
19. privileged-channel loss pre/post cutover, graceful/forced shutdown and restart.

No second storage framework/public supervisor API/copied CBOR. Minimal exact V2 Windows donors may be adapted; old platform/session/lease machinery is not.

### Slice 1 — Store and local lifecycle

Implement supervisor/daemon/Store, executable+root leases, protected root access, inherited privileged channel, relay IPC, closed process profile, listener/peer/auth admission, bootstrap/migrations/credentials, Editor socket owner, DTOs, CaptureCommand, blobs, spool/replay barrier, mutable selection, status/shutdown and revisions.

```text
real event → committed or staged → replay if staged → restart → exact open
```

### Slice 2 — Useful Base and first host

Claude relay, continuation, exact/full-text retrieval, notes/corrections/commitments, actual context emission, packet retention, source open, protected canonical backup, exact rollback, controlled-copy erase. No controller/model/vector/document/Research dependency.

### Slice 3 — Controller inference owner

Contract 0.6 stable caller registration, typed hello receipt, role/connection/profile/destination/method/artifact/dedup/cancel/unknown/runner/readback, exact-caller result bytes, non-disclosing Operator erasure, per-copy cleanup/release and same-client token rotation/revocation; no Task/Attempt/ScriptRun/new table.

### Slice 4 — First learning

Pinned verified `swarm-client`, one controller adapter, one episode handler, exact request/result, decode/publication/later context/cleanup. Restore reconciles target jobs only under the retained caller, holds `caller_identity_unavailable`, and blocks/abandons out-of-target unresolved Operations without duplicate inference.

### Slices 5–6

Add vectors/views/documents/Research/hosts only by real prerequisites, then advanced curation/diagnosis. Reuse jobs/revisions/context.

### Final verification

After connected product: concurrency/restart, executable/root/pipe/peer ownership, privileged channel/selection, Store conflicts/unknowns, socket cancellation, spool durability/quiesce, exact-open pagination, protected backup/exact rollback/deletion union/spool merge/restored jobs, Store credential revocation, stable controller caller across token rotation and Memory restore, hello mismatch refusal, exact-caller result-byte isolation, physical erasure and optional failures. Stub providers qualify local mapping only.

Measure latency, I/O, calls, retained bytes, dependencies and code size. LOC is diagnostic, not quota.
