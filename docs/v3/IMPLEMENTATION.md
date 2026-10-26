# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.31 · 2026-10-26 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, data and connected operations. [Cognition](COGNITION.md) defines algorithms. [One-shot inference contract](INFERENCE-CONTRACT.md) is the sole normative Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) records checked evidence and open gaps.

Nothing here is implemented merely because it is specified. Build the connected production slices in §15. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 1. Runtime and installation

### 1.1 Process family

The initial Windows profile uses one executable with modes:

```text
eliot supervisor     owns process family and privileged maintenance
eliot daemon         owns Memory application operations and Store mutations
eliot relay ...      transient host/CLI adapter
```

Owned children:

```text
supervisor
├─ daemon
└─ active SurrealDB child
   └─ optional isolated disposable restore candidate during one maintenance operation
```

There is one active daemon, one active Store child and at most one candidate. A new process is introduced only for a real external runtime or failure boundary. Optional cognition remains in daemon modules.

The supervisor is not a public administration service. External control reaches daemon; daemon sends a closed privileged intent over one inherited channel when root/Owner/process/selection authority is needed.

### 1.2 Installation root and selection

Installation is one qualified fixed local NTFS/ReFS root with protected current-user + LocalSystem DACL. Database, source bodies, spool and backups are plaintext application data protected by account, DACL and volume security. Base claims no portable/off-machine encrypted backup.

Supervisor owns mutable `installation.toml` under an installation mutex. Conceptual selection:

```text
selection_generation
stable_memory_installation_id
current_root
previous_root?
controller_id
controller_client_id = memory:<stable_memory_installation_id>
current_controller_token_version
current_controller_credential_ref
pending_controller_credential_ref?
previous_controller_credential_ref?
current_store_editor_ref
pending_store_editor_ref?
previous_store_editor_ref?
current_store_owner_ref
pending_store_owner_ref?
previous_store_owner_ref?
maintenance_state
```

At most one previous root and one pending/previous credential per role. Another cutover or rotation is refused until the earlier generation is explicitly retired.

A previous root is never directly reselected. Recovery goes through typed restore so current deletion fences, controller continuity and credentials are applied.

### 1.3 Startup sequence

```text
supervisor opens/validates executable + installation root/ancestors no-follow
→ reads exact installation selection
→ opens selected Store executable/root identities
→ launches and admits SurrealDB
→ creates inherited daemon control pipes
→ launches daemon suspended, validates image, assigns Job, resumes
→ daemon authenticates Editor and validates schema/query corpus
→ daemon reports ready with exact selection/schema facts
→ supervisor enables relay endpoint publication
```

Startup refuses ambiguity. A path, PID, digest, port, ready response or process exit alone is not identity or completion.

## 2. Windows identity, launch and custody

### 2.1 Retained executable and root identity

Before any owned child is resumed:

1. open executable, selected data root and relevant ancestors without following reparse points;
2. verify expected file/directory identity, regular type, bounded SHA-256 and protected DACL;
3. deny write/delete or root rename sharing where required;
4. create child suspended with closed environment and explicit inherited handle list;
5. compare actual child image/file identity with retained executable;
6. assign the correct Windows Job Object;
7. resume only after all facts agree.

Retained selected-root lease remains for the Store lifetime. A changed path resolving to another file/root is not continuity.

### 2.2 Job Objects and process termination

Supervisor owns one process-family Job with kill-on-close where appropriate. Store and daemon identity includes PID plus creation time and retained process handle. Graceful exit is requested through the owning protocol; bounded failure falls back to Job containment. Clean process exit is not a Store durability receipt.

Candidate Store uses isolated root, port, credentials and Job. It cannot share active Store state or listener.

### 2.3 Closed child environment

Every owned child receives a newly constructed environment block. It contains only required OS locale/path/certificate/temp values plus exact child-specific values. Do not inherit arbitrary `SURREAL_*`, capability, metrics, telemetry, slowlog, import or database endpoint variables.

Secrets are passed only to the child that needs them and are removed after the narrow bootstrap generation. No secret is placed on argv or logged.

## 3. IPC boundaries

### 3.1 Relay→daemon named pipe

One installation-scoped Windows named pipe:

- created first-instance only;
- remote clients rejected;
- DACL limited to expected user/System;
- one bounded versioned request/response per transient connection;
- no generic method discovery or arbitrary file/command surface.

Relay verifies daemon PID, creation time, session, image/file identity and supervisor Job membership. Daemon verifies relay PID, SID, creation time, session and image. Retained process handles bracket PID reuse. Same-account malicious code is outside the declared security boundary, but accidental/stale/foreign-process confusion must fail closed.

The relay never receives Store credentials. Its public capture result is only:

```text
committed | staged | unknown | rejected
```

### 3.2 Supervisor↔daemon inherited channel

Supervisor creates two anonymous one-way pipes before daemon launch and passes only exact daemon ends through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Environment carries handle numbers and protocol generation, not secrets.

Closed frames:

```text
store_descriptor
maintenance_request
maintenance_result
quiesce
quiesced
resume
shutdown_ready
shutdown_complete
daemon_ready
```

Every exchange has exact operation ID and bounded typed payload. Daemon may name an already retained backup/configuration/credential identity. It cannot send raw SQL, argv, endpoint, arbitrary path or secret. Supervisor independently resolves and validates the named object.

Channel loss is fail-closed:

- daemon closes mutation admission, preserves capture by staging where possible and exits boundedly;
- supervisor does not continue an unconfirmed privileged cutover;
- before durable selection replacement, candidate is abandoned;
- after possible replacement, startup reads actual selection before another action.

## 4. SurrealDB child and Store transport

### 4.1 First qualification target

Pin SurrealDB **3.3.4** Windows asset, commit, size and SHA-256. The exact downloaded PE, Authenticode state and live behavior remain Slice 0 qualification facts.

Selected launch profile:

```text
surreal start <supervisor-derived-canonical-rocksdb-url>?sync=every
  --bind 127.0.0.1:<per-start-owned-port>
  --deny-all
  --allow-arbitrary-query system
  --deny-arbitrary-query guest,record
  --allow-http rpc
  --allow-rpc query
  --no-defaults
  --no-identification-headers
  --client-ip none
  --allow-origin <reserved origin; CORS metadata only>
```

No engine fallback. Origin/CORS is not WebSocket authentication.

### 4.2 Listener and peer ownership

Supervisor reserves a loopback port only as a race reduction. It retains child process identity and uses Windows TCP tables to prove listener ownership before credentials are sent. Daemon similarly proves the established socket peer belongs to the retained Store child.

Port, TCP connect, HTTP readiness or WebSocket 101 alone prove nothing. Listener squat, PID reuse, inherited listener and peer mismatch all fail admission.

### 4.3 Root bootstrap, Owner and Editor

Bootstrap sequence:

```text
empty root starts once with one retained root credential in child-only env
→ possible root persistence is reconciled with same secret
→ child stops
→ same root restarts without root env
→ root authenticates on verified peer
→ create NS + STRICT DB + Owner + Editor using PASSHASH
→ apply checked migrations through Owner
→ close privileged sockets
→ root-free restart
→ daemon admits Editor and query-denial matrix
```

Root and Owner remain supervisor-only. Daemon receives Editor only. Plaintext passwords, auth headers, verifier bytes and raw authentication errors never enter logs/manifests/results.

Credential rotation is not complete after password update. Supervisor quiesces daemon, closes authenticated sockets, applies exact PASSHASH mutation through fresh Owner connection, resolves unknown with pending/current credentials, publishes selection, restarts Store and requires fresh daemon Editor admission. Old reference retires later.

### 4.4 Owned WebSocket client

One dedicated task owns each authenticated Store socket:

- one in-flight exact request ID;
- continuous handling of control/data frames;
- Basic-authenticated upgrade on the verified stream with exact namespace/database selection;
- no RPC signin/use/version/ping dependency;
- Ping/Pong only for transport liveness;
- `query` is the only application RPC method.

Caller cancellation drains the exact response or closes the socket. Timeout, close, wrong/late ID, malformed frame or protocol fault poisons the socket. Possible mutation send becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth/schema admission and application readback.

### 4.5 Closed JSON DTOs

JSON carries only explicit DTOs:

- fixed projections and stable order;
- bounded strings, signed integers, booleans and finite floats;
- canonical application IDs;
- integer time plus precision/uncertainty;
- explicit optional state when `NONE` and `NULL` differ;
- vectors with exact dimension/order and finite-value checks;
- exact/large bytes as selected-root blobs.

No generic Surreal `Value`, `SELECT *`, broad CRUD, copied CBOR tags or implicit native-type round-trip. Grammar-changing identifiers come from closed enums; ordinary data uses bound parameters. Every decoder rejects unknown shape that changes semantics.

## 5. Physical Memory data model

Use six primary `SCHEMAFULL` tables plus selected-root blobs. Add a field or index only with its first real writer and reader.

### 5.1 `stream`

```text
id
project
source_kind
source_native_id
workspace?
last_ingest_seq
```

Unique `(project, source_kind, source_native_id)`. Sequence orders one stream only.

### 5.2 `observation`

One source occurrence or application event:

```text
project / stream / event_key / sequence
command_id? / native_id?
occurrence_time / receipt_time
kind
exact inline body or blob ref + length + sha256
bounded search excerpt
source locator
work/task/resource binding
relations supplied by source
capture limits/redactions/omissions
disclosure
packet/correction references
```

Unique `(project, stream, event_key)` and `(project, command_id)` where present. Tool result, agent report, prepared packet and packet handoff are separate observations.

### 5.3 `memory`

Current semantic revision:

```text
id / project / kind / revision
origin / reuse_scope / disclosure
optional exact address + derived unique key
content / search text / cues / aliases
subject / aspect / perspective
conditions / exceptions / selectors
validity / limitations
support / exposure / influence state
commitment state
processing-method purpose/role
vector + effective-space/representation identity when present
timestamps
```

Address unique key is absent for unaddressed items; unique index applies only to complete addresses.

### 5.4 `memory_history`

Previous revisions, unique `(item, revision)`. A version handle never falls forward. A current read never resurrects history.

### 5.5 `link`

Revision-aware source/target, relation kind, optional grounds group, locator and qualification. Kinds cover source/evidence/live requirement/contradiction/replacement/episode/resource/outcome/method/packet/navigation.

One non-null grounds group is conjunctive; groups are alternatives; ungrouped support is advisory. Navigation has no evidential Boolean meaning.

### 5.6 `job`

Finite background work:

```text
id / project / purpose / target
state / active-or-pending slot
origin / cause
due / attempt / retry / waiting reason
frozen input members/ranges
exact processing-method revision
limits / disclosure / profile
exact request blob/length/digest
application result / coverage
per-copy cleanup state
```

For controller-backed work, retain only non-secret Contract 0.9 identity:

```text
controller_id
controller_client_id
selected_token_version
inference_write_id
method + canonical semantic payload identity
controller_admission_seq when known
profile/connection/adapter/destination snapshot
result length/digest when known
Memory result blob
release WriteId/disposition
input/result cleanup state
external-work inventory status
```

No raw token, token hash, provider credential, separately discovered Operation ID, V1 credential ID/generation or `possible_send` state.

Per-copy state:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Aggregate cleanup is derived. One active and one coalesced pending successor per target; terminal history has no slot.

### 5.7 Blobs, locators and packets

Large exact bytes live under selected-root `blobs/`; rows hold opaque reference, length and digest. Publish bytes before row commit. A packet is an ordinary observation/blob plus links containing exact included revisions, rendered digest, budget and gaps.

Locators claim only supplied precision. Dirty/untracked code is retained bytes/range, not HEAD alone.

## 6. Schema, migrations and transactions

### 6.1 Migration owner and admission

Supervisor Owner applies ordered checksummed migrations before daemon admission. Baseline includes:

- configured namespace and `STRICT` database;
- six `SCHEMAFULL` tables and owned fields;
- narrowly named bounded `FLEXIBLE` metadata only where an actual reader exists;
- wire-compatible IDs, times and option states;
- occurrence/idempotency/address/history/job-slot indexes;
- initial synchronous indexes;
- no 2.x-only features such as `DEFER`.

`$eliot_schema_generation`, migration digests and `INFO FOR DB/TABLE` own admission. `IF NOT EXISTS` is not migration verification.

Daemon admission also proves query-only denial matrix and executes fixed typed write/read/delete probes against the selected Store.

### 6.2 Transaction rules

One RPC `query` executes one fixed transaction and every statement status is inspected and decoded.

- unique values own identity/cardinality;
- controlling rows use `FOR UPDATE`;
- stream sequence and current revision are locked and rechecked;
- predicate-only set invariants use a deterministic sentinel or unique slot;
- nondeterministic `UPSERT` is not idempotency;
- blobs publish before row transaction;
- external controller/document/Research/network work never runs inside a Store transaction.

Retry the whole immutable transaction only for an exact retryable conflict. Unique conflict resolves by readback and byte comparison. Transport, shutdown or fsync uncertainty reconciles before retry. `sync=every` may apply before reporting fsync failure; error is not rollback proof.

## 7. Durable local file primitives

### 7.1 Immutable no-replace publication

For blobs, spool entries, deletion notices, backup parts and generations:

1. retain and validate parent without following reparse points;
2. create same-directory temporary regular file with `CREATE_NEW`;
3. write bounded complete bytes;
4. flush file and close;
5. publish with no-replace `MoveFileExW(..., WRITE_THROUGH)`;
6. flush parent directory;
7. reopen and verify exact identity, length and digest.

An existing exact final is prior success only after parent durability and exact comparison. Different bytes conflict. Rename followed by failed directory sync or readback is `unknown`, not unpublished.

### 7.2 Mutable installation replacement

Under installation mutex:

1. read and retain current selection;
2. require expected generation;
3. build complete generation+1 record;
4. write, flush and close same-directory temp;
5. replace with `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`;
6. flush parent;
7. reopen and verify exact bytes, generation and references.

`ReplaceFileW` is not treated as write-through. Possible replacement with failed readback is `SELECTION_UNKNOWN`; startup classifies exact new, exact old or fail-closed unexpected. Mutation does not resume until selection and admitted Store agree.

## 8. Core application operations

### 8.1 `capture_event`

Relay builds immutable command before IPC:

```text
schema version
command ID
project/stream/native event identity
occurrence/receipt time
kind
exact accepted body or blob candidate
length + sha256
bounded excerpt
locator
work/resource binding
relations
capture limits
disclosure
```

Exclusions/redactions happen before publication and remain explicit. Equal content does not merge occurrences. Reusing one command/event identity with different bytes or binding conflicts.

After referenced blob publication, one Store transaction:

1. resolve or create unique stream;
2. lock stream;
3. read command/event identities;
4. identical replay returns saved result;
5. changed bytes/binding conflicts;
6. allocate stream sequence;
7. insert observation and supplied relations;
8. coalesce only implemented follow-up;
9. commit.

Post-commit identity/body/binding readback is required for public `committed`. Capture never calls a model.

### 8.2 Relay disposition and staging

Private daemon result:

```text
committed | rejected | stage_required | unknown
```

`stage_required` is private flow control before Store/blob ownership, used while application writes are quiesced. Relay publishes the same command to spool on `stage_required`, daemon unavailability or uncertain direct result. Public `staged` requires exact immutable publication; otherwise `unknown`.

### 8.3 Spool replay

One daemon replayer exposes pause/drain. A pending file contains one exact versioned command, digest, publication time, replay count and bounded non-content diagnostic. Filename derives from command ID. There is no second committed archive.

For each bounded fair batch:

- enumerate stable regular files;
- validate type, size, schema, filename/ID and digest;
- invoke the same `capture_event`;
- committed replay → delete pending + parent flush;
- deterministic rejection/corruption → no-replace failed move + bounded reason + both directory flushes;
- transient failure → retain and yield;
- sync failure → reconcile actual location;
- poison item cannot starve later items.

Pause stops before another item. Drain reconciles the active item to matching Store readback, deterministic rejection, retained pending or explicit unknown. An unresolved possible Store write blocks backup, cutover and complete erasure.

### 8.4 Memory revision

One transaction locks current item, rejects stale revision, copies prior revision to history, writes new current, inserts revision-specific links, settles command/job, coalesces affected work and commits. A new item ID is allocated once and retained with the decoded result.

### 8.5 Job claim

Only configured, enabled and eligible handlers may claim work. Waiting for idle, profile, disclosure or external continuity is not a failed attempt.

One transaction:

1. fairly selects active slot;
2. freezes finite input members/ranges;
3. freezes exact processing-method revision;
4. reduces disclosure;
5. selects profile;
6. builds exact request bytes and canonical identity;
7. for controller work, creates and stores the canonical ULID `inference_write_id` **before any application send**;
8. commits job/request facts.

Reclaim never creates a different request or `WriteId` for an admitted/possibly admitted call.

### 8.6 Exact `open`

Require one nonempty exact handle/locator. Resolve current item, exact history, observation/body/blob/range, retained representation, Research section/citation or copied controller result.

Return:

```text
requested identity
resolved identity
current/history state
exact returned range + digest
capture/representation limitations
revision-aware relation descriptors
expansion handles/cursor
missing | forbidden | erased | damaged | unsupported
```

Coherent hydration uses one snapshot or revision fences. Large reads page by real byte/row limits and preserve UTF-8 boundaries. Historical open never reruns search, conversion, Research or inference and never substitutes a newer representation.

## 9. First Claude host adapter

### 9.1 Event profile

| Native event | Captured content/binding |
|---|---|
| `SessionStart` | identity/source/cwd/work hints, then actual continuation packet |
| `UserPromptSubmit` | exact accepted prompt + task identity, then decision packet |
| `PostToolUse` | tool/name/native ID/input/result/duration/resource |
| `PostToolUseFailure` | tool/id/input/error/interruption/duration |
| `Stop` | main final message + stop/session facts |
| `SubagentStop` | agent ID/type/final/parent; handback tool remains a tool event |
| `PostCompact` | compact summary as derived representation |
| `SessionEnd` | lifecycle reason |

Unknown fields may be retained only in a bounded configured raw representation. `PreToolUse`, permission and finish gates are outside Base.

### 9.2 Relay behavior

Read one bounded JSON object; validate installed adapter; build immutable command; use the mutually attested one-request pipe; capture then stage when needed; optionally request context; emit one bounded host-compatible stdout object; keep diagnostics separate. Capture and context budgets are separate. Uncertainty reuses the same command ID.

### 9.3 Qualification

`SessionStart` and `UserPromptSubmit` success must contain actual packet content, not service status. Before default enablement record installed Claude version, real payloads, final/compact fields, output schema/limits, timeout/exit behavior, fork/resume/clear/compact and subagent distinctions.

## 10. Retrieval, context, views and documents

A decision frame contains work address, observed versions, focused question, cues, constraints and budget. Address current work before similarity.

Generate bounded arms independently:

```text
direct IDs/handles
current-work address
exact technical cues
lexical search
compatible vectors
claim alternatives
revision-aware relations
grounds/exceptions/outcomes
project-local and eligible reusable methods
```

Scope before arm limits; union before selection. Rank relevance separately from support. Applicability is `applicable | inapplicable | conditional_or_unknown`.

Pack current work, corrections, methods plus exceptions, prior episode, dissent/checks and source handles. If a unit cannot fit, use a faithful qualified reduction plus handle or explicit gap; never drop negation, version or contraindication.

Packet bytes and included revisions are retained before or alongside host emission. `prepared`, `emitted`, action-associated and used/influential remain distinct.

A project view is a versioned answer over an examined scope with exact source handles and gaps. Refresh affected views only; prior qualified view and direct source survive failure.

Document path:

```text
captured original
→ finite converter job
→ retained representation/status/errors
→ searchable excerpts
→ exact open
```

No reconversion on read or silent newer substitution.

## 11. Controller V2 inference extension

The current controller authority is `eliot-swarm-controller@c8c0ee122c98a01be86bc5296a22a389662a1c89`. Its V2 specification selects local JSON-RPC, SQLite WAL and external `WriteId` receipts, and marks the existing Rust/`swarm-client` runtime as V1 legacy. Do not implement Memory inference in that legacy stack.

### 11.1 Dependency boundary

Controller must first deliver its V2 L0/L1 Store/API foundation. Memory integration then adds only:

```text
memory_inference_clients
inference_calls
private call-owned input/result files
```

It reuses controller `write_receipts`. It does not reuse Agent commands/turns, Goals, automation runs/actions, scripts, generic artifacts or a Task/Attempt lifecycle.

### 11.2 Client installation and identity

Controller-local owner command installs or rotates:

```text
client_id = memory:<stable Memory installation ID>
principal = memory_inference
token_version = positive monotonic version
```

It uses controller owner `WriteId`, derives raw token from private controller `routing.key` plus `client_id/token_version`, stores only version and hash in SQLite and writes raw token only to a create-new private credential file. Memory never receives controller owner authority or `routing.key`.

Lost install/rotate reply retries the same owner `WriteId` and re-derives the same token. A changed payload conflicts. Missing/mismatched routing key blocks issuance/reissue.

Before application mutation, Memory authenticates and calls `client.identity`, requiring exact:

```text
controller_id
client_id
principal = memory_inference
token_version
api_version
write_id_floor_ms
write_id_future_skew_ms
```

Possessing a credential file is not proof of authenticated identity. Missing/mismatch closes the connection before `inference.text/embed`.

Before every Memory read/mutation, controller reloads registration and compares current token version/hash. Old transport after rotation receives `credential_stale` and closes. No-token owner fallback, Agent token and project automation token are never accepted.

### 11.3 Call admission

Memory has already committed the call `WriteId` and exact request bytes/digest in its job. Canonical controller identity:

```text
(client_id, WriteId, method, canonical semantic payload)
```

Normal V2 receipt rules:

```text
same ID + same caller/method/payload -> original/current call
same ID + changed semantic payload  -> id_conflict
absent below retained floor         -> id_expired
absent excessive future ID          -> id_future
valid absent ID                     -> first admission only
```

For a valid absent ID, controller validates client, profile, destination, disclosure, format, limits and capacity; durably stages exact private input; then atomically inserts receipt plus queued `inference_calls` row with positive per-client `admission_seq`.

An orphan input file without a committed call is cleanup material and never dispatchable. A committed call with missing/mismatched input is `damaged`, never reconstructed from receipt JSON.

### 11.4 Runner, result and uncertainty

One bounded internal runner:

1. selects eligible queued call under frozen profile concurrency;
2. verifies input, current client registration and frozen profile/connection;
3. compare-and-set `queued → sending` before provider I/O;
4. performs at most one provider attempt;
5. retains native request/readback identity when supplied;
6. publishes exact private result envelope when present;
7. settles bounded non-secret facts and wakes readers.

Possible provider send followed by timeout/process loss/ambiguous transport becomes `unknown` unless exact native readback resolves it. It is never redispatched because Memory repeats the admission `WriteId`.

Restart:

```text
queued + verified input -> eligible once
sending/native accepted -> exact readback or unknown
verified pending result -> finish settlement
abandoned              -> never dispatch/publish late result
```

No adapter performs hidden retry, redirect or fallback.

### 11.5 Read, cancel, release and owner erasure

Exact caller methods:

```text
inference.get
inference.list
inference.high_water
inference.result.read
inference.cancel
inference.release
```

Range read requires exact caller, current credential, retained result digest/length and bounded range. Historical call never falls forward.

Cancel uses its own `WriteId` and succeeds only while queued before `sending`. After provider I/O may have begun, cancellation cannot prove non-execution.

Release dispositions:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

Controller verifies exact deterministic file provenance, regular/no-reparse identity, digest/length where present, deletion and parent durability. Missing exact file is `already_absent`; mismatch blocks deletion. Input/result cleanup is independent and retryable.

Controller owner may run non-disclosing `inference.erase` by exact caller/call or bounded admission sequence. It cannot read result bytes, adopt caller ownership or fabricate a Memory result.

### 11.6 Initial adapters

First text adapter is a closed loopback-compatible OpenAI chat-completions subset:

- one exact user message;
- model, admitted `max_tokens`, closed response format;
- optional Bearer from named private connection;
- no tools, stream, arbitrary extras, environment proxy, redirect, retry or fallback.

Response requires bounded JSON and one usable `choices[0].message.content`. Length finish is partial. Tool-only/content-free/unsupported multimodal output fails. Usage/cost/account remain unknown when absent.

Embedding adapter later enforces exact count/index/dimension/finite values and one effective vector-space identity.

## 12. Backup, restore and external continuity

### 12.1 Backup cut

Daemon backup operation:

1. stop new application mutations and controller-backed admissions;
2. pause replay and reconcile the active item;
3. settle or retain every Store write unknown;
4. persist every created inference `WriteId`;
5. authenticate exact controller client and read `inference.high_water {high_water, earliest_retained_seq}`;
6. under a **brief** spool publication lock, capture or rotate an exact bounded spool inventory/generation cut;
7. release the publication lock so relay can continue post-cut staging;
8. page six Store tables through fixed canonical projections;
9. copy exact selected-root blobs, deletion notices, cut spool entries and sanitized config;
10. write part digests and final manifest with no-replace durability.

The backup never holds spool publication lock while paging Store/copying bytes. Missing or mismatched cut entry fails the backup. Post-cut staged entries remain outside this generation and preserve forward continuity.

Manifest records:

```text
schema/query versions
selection generation/root identity
stable Memory installation ID
controller_id/client_id/token_version
controller high_water + earliest_retained_seq
all in-cut controller job WriteIds/identities
strictest disclosure
part identities/digests/counts
exact spool/deletion cuts
```

Raw Store/controller/provider credentials are excluded.

### 12.2 Restore candidate

Supervisor creates isolated candidate root/port/credentials, starts candidate Store, applies checked schema and imports canonical typed pages through application write operations. It verifies counts, identities, digests, deletion fences, blobs and query denial matrix. Surreal export/import/startup import are not application owners.

Healthy-current restore requires a fresh safety backup. Disaster mode records uninventoried current Memory state. Candidate remains disposable until exact admission.

### 12.3 Cutover

At cutover:

1. daemon quiesces writes/replay/jobs and closes old Editor socket;
2. supervisor merges only deletion continuity and exact spool continuity;
3. selection replacement sets candidate current and old current previous;
4. daemon independently admits selected Store with Editor and schema/query probes;
5. Base resumes;
6. controller-backed inference resumes only after §12.4 continuity is dispositioned.

Channel loss before selection replacement abandons candidate. After possible replacement, startup reads actual selection.

Post-backup Memory rows/jobs/config are not silently merged. They remain in previous root or safety backup until retirement.

### 12.4 In-cut and post-cut controller calls

For every in-cut job, Memory reuses the same `WriteId` and exact bytes:

```text
existing call -> original state/result/release
absent but ID still admissible -> first admission
changed payload -> id_conflict
caller unavailable -> hold; no call
```

There is no unknown separately discovered call ID.

Before **any new controller-backed inference** after restore, Memory pages:

```text
inference.list(after_admission_seq = backup_high_water)
```

Controller returns exact caller’s bounded rows plus `earliest_retained_seq`. If the backup cut precedes a pruned interval, result is `history_gap`, never false empty.

Every returned call is out of target. Restored Memory does not adopt its body as cognitive output because exact job/source/publication mapping is absent. Each call must become terminal and released, or be explicitly abandoned/erased with visible cleanup debt. Unknown provider effect remains unknown.

If controller identity, credential or inventory is unavailable, record `external_work_inventory_unavailable`, keep all new inference disabled and allow Base capture/retrieval to resume independently. A new caller or reset controller cannot silently clear the debt.

### 12.5 Erasure

Deletion ledger prevents reintroduction but is not physical deletion proof. Controlled copies include current/previous/candidate roots, pending/failed spool, selected-root blobs, local backups/safety backups and controller input/result files.

Initial Base does not selectively rewrite offline roots/backups. If they contain erased scope, delete the whole generation with bounded no-follow traversal and parent-directory durability or report erasure incomplete.

Controller erasure fences late publication and deletes exact local copies without exposing result bytes. Provider-side copy/effect is external unless an actual provider guarantee exists.

## 13. Control, status and shutdown

Daemon public operations:

```text
status / inbox
capture / inspect / exact open / retrieve
configure
enable/disable/pause/resume/cancel jobs
correct/withdraw/erase
backup/restore
credential rotation request
shutdown
```

Return operation ID immediately. Privileged effect crosses inherited channel; final status derives from Store, selection, credential and process readback.

Status exposes:

- selected root/schema/query versions;
- Store executable/listener/peer/socket health;
- replay active/pending/failed/unknown;
- capture ownership and packet handoff gaps;
- job active/pending/waiting/unknown;
- controller identity/profile/destination/call/cleanup facts;
- backup/restore cut, candidate and selection states;
- post-restore external-work inventory or history gap;
- previous roots/credentials/copies blocking retirement/erasure;
- process/Job/channel/shutdown state.

Shutdown:

1. stop new mutations and controller admissions;
2. pause/drain replay to explicit state;
3. stop claiming jobs and settle retained external identities;
4. close Store/controller/document/Research sockets;
5. flush local files and report shutdown-ready facts;
6. supervisor requests Store stop and waits boundedly;
7. Job containment handles failure;
8. exact process exit and selection readback complete shutdown.

A clean daemon/Store exit does not retroactively turn unknown application writes into committed or rejected.

## 14. Failure mapping

| Failure | Required result |
|---|---|
| Relay cannot prove daemon identity | no IPC; durable stage or unknown |
| Store peer/listener identity mismatch | no credentials/query; admission fails |
| Store mutation response lost | `OUTCOME_UNKNOWN`; read back by application identity |
| Immutable rename succeeded but sync/readback failed | publication unknown; reconcile final path |
| Selection replacement uncertain | `SELECTION_UNKNOWN`; startup reads actual selection |
| Backup cut entry missing/mismatched | backup fails; no manifest completion |
| Controller token invalid/stale | close transport; no owner/Agent fallback |
| Provider may have received call | retained call `unknown`; no new WriteId/retry |
| Restored backup has post-cut controller calls | inference disabled until listed/dispositioned |
| Controller retention crossed backup high-water | explicit `history_gap`; no empty claim |
| Previous root/backup/call copy remains | erasure/retirement incomplete |
| Supervisor channel lost | daemon closes mutation admission and exits boundedly |

## 15. Implementation sequence

### Slice 0 — qualify hard boundaries

Write production code first and close one hard boundary at a time:

1. installation root/DACL/no-follow executable and root leases;
2. suspended child launch/image comparison/Job containment;
3. inherited supervisor channel;
4. relay named pipe/mutual attestation;
5. Surreal 3.3.4 asset/argv/env/listener/peer/bootstrap/roles;
6. Store WebSocket owner, fixed DTO query corpus and migrations;
7. immutable publication and mutable selection;
8. capture/spool/replay barrier;
9. brief spool cut and typed backup/exact rollback candidate;
10. physical erasure and Store credential revocation;
11. graceful/forced shutdown and restart reconciliation.

Slice 0 does not implement cognition or controller inference.

### Base Slice 1 — first useful persisted path

```text
real relay event
→ daemon pipe
→ blob/Store capture
→ committed or durable staged
→ replay
→ restart
→ exact open
```

Include status and direct control. No packet generation before source ownership works.

### Base Slice 2 — first useful context path

```text
qualified Claude event
→ current-work reconstruction
→ lexical/exact retrieval
→ retained packet
→ actual SessionStart/UserPromptSubmit emission
→ later exact source open
```

Add notes, corrections, commitments, local backup/exact rollback and controlled erase.

### Controller dependency

Controller V2 must implement its own L0/L1 foundation first. Do not patch the legacy runtime to unblock Memory.

### P1a — connected text learning

1. controller `memory_inference` registration/token/`client.identity`;
2. profile/connection/disclosure admission;
3. `WriteId` receipt + private input + `inference_calls` row;
4. bounded text runner/result/read/cancel/release;
5. high-water/list/history-gap and owner non-disclosing erase;
6. one Memory adapter;
7. one `episode_learning` decoder/publication;
8. changed later context consumer;
9. restart, release and backup/restore continuity.

### P1b — controller token rotation

Same owner `WriteId`, deterministic token re-derivation, stale transport closure, pending/current/previous Memory selection and delayed previous-file retirement.

### Later independent increments

- embeddings/vector retrieval;
- project views;
- documents/converters;
- Research fixes;
- richer grounds/reconsideration;
- additional hosts;
- direct HTTPS adapter.

Do not make any of them prerequisites for useful Base or first text learning.

## 16. Verification order and proof ceiling

During implementation:

```text
write connected production code first
→ cargo fmt --check
→ cargo clippy -p <changed-package> --lib --bins -- -D warnings
→ add only another package required by the changed contract
```

A tiny deterministic regression is allowed only where source review cannot establish safety. Broad tests, live harness campaigns, fault injection, Windows/Linux platform matrix and load/retention qualification start after the connected product path exists.

Required final qualification includes real Windows process/pipe/file/Store/backup/restore/erasure paths; same-ID capture and inference lost replies; applied-before-fsync unknown; listener/peer squat; credential revocation; post-backup controller inventory/history gap; actual Claude packet emission; one learning result changing later context; and no duplicate provider execution.

Current proof ceiling is design/source only. No Memory V3 runtime, controller V2 inference extension, Store Windows run, host capture, backup round-trip or learning loop is implemented.
