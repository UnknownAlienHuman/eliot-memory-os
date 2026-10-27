# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.39 · 2026-10-27 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, Store and connected operations. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.17](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the sole active work ledger.

Nothing is implemented merely because it is specified. Build connected production slices in §12. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 0. External prerequisite

Current controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

Controller V2 remains a specification target. Issue #200 now owns separation of binding allocation, selected pointer and effect publication; draft PR #201 fixes fixtures only. V2 L0.1–L1.11 remain unchecked. Memory inference issue #199 stays blocked on #200 and V2 L0/L1.

Memory Slice 0 and useful Base do not depend on controller V2.

## 1. Runtime and installation

### 1.1 Process family

```text
eliot supervisor     privileged installation/process owner
eliot daemon         Memory application + backup-set owner
eliot relay ...      transient host/CLI adapter
```

Owned process shape:

```text
supervisor
├─ daemon
├─ active SurrealDB child
└─ at most one isolated disposable restore candidate
```

Supervisor owns executable/root identity, child handles, Store bootstrap credentials, migrations, Store-user rotation, candidate process/root and final installation cutover.

Daemon owns Memory semantics, Store Editor access, replay/jobs, controller-mutation serialization, backup IDs and installation records, restore file leases, context/retrieval and public control.

### 1.2 Installation layout

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  installation.toml
  controller-write-id.state
  data\roots\<root-id>\
    db\
    blobs\
  spool\
    pending\
    failed\
    tmp\
  deletions\
  backups\
    .tmp-<random>\            # pre-publication staging only
    b_<32-lowercase-hex>\     # final generation
      fence.json
      parts\
      manifest.json?
      abort.json?
      retire.json?
  logs\
```

The initial profile is one fixed local NTFS/ReFS volume. Installer validates a protected current-user + LocalSystem DACL, rejects broad principals, network/removable roots and reparse traversal. Database, source bodies, spool and backups are plaintext application data protected by account/DACL/volume security. Base claims no portable encrypted backup.

`controller-write-id.state` and final backup records are outside rollback Store roots. Exact Memory rollback cannot regress or recreate them.

### 1.3 Configuration and mutable installation selection

`config.toml` contains user configuration only: projects/workspaces, capture limits/exclusions, host adapters, controller endpoint/credential reference, inference profile names, disclosure defaults, automatic-work mode and optional source tools.

Supervisor owns `installation.toml` under the installation mutex:

```text
selection_generation
stable_memory_installation_id
current_root_id
previous_root_id?
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
expected_memory_schema_generation
expected_memory_schema_bundle_sha256
maintenance_state
```

At most one unretired previous root and one pending/previous credential per role. Another cutover or rotation waits until the earlier generation is retired.

### 1.4 Startup sequence

```text
supervisor validates installation selection and executable/root identities
→ starts/adopts exact active SurrealDB child
→ reconciles bootstrap/credentials and applies checked migration bundle through Owner
→ creates inherited supervisor↔daemon channel
→ launches daemon suspended, verifies image and assigns Job
→ sends non-secret Store/process/schema descriptor
→ daemon independently admits root/process/listener/peer/Editor/schema/query path
→ daemon removes/quarantines pre-publication backup temp directories under bounded rules
→ daemon backup-set owner scans final backup directories and terminal markers
→ daemon reconciles Store maintenance mirrors against installation authority
→ daemon reconciles pending release/retention/publication state
→ daemon reports ready
→ supervisor allows relay endpoint publication
```

No host capture reports `committed` before daemon admission. Ordinary jobs cannot run release, retention or backup transitions before backup authority is reconstructed.

## 2. Windows identity, custody and IPC

### 2.1 Retained executable and root leases

Before an owned child resumes:

1. open executable, selected root and relevant ancestors no-follow;
2. verify regular identity, expected digest and DACL;
3. deny write/delete or root-rename sharing as required;
4. create child suspended with a fresh environment and exact inherited-handle list;
5. compare child image/file identity;
6. assign the correct Job Object;
7. resume only after agreement.

Executable/root leases remain through child lifetime. Path, digest or PID alone is not identity.

### 2.2 Process custody and shutdown

Supervisor owns process handles and a process-family Job with kill-on-close where appropriate. Graceful stop is requested through the owning protocol; bounded failure uses Job containment. Clean exit is not Store durability proof.

Candidate Store has an isolated root, dynamic port, credentials and process handle. It never shares active database files/listener.

If daemon or inherited channel is lost while a candidate exists, supervisor kills, reaps and deletes/discards the candidate before another daemon starts or any cutover proceeds. Supervisor loss terminates owned children through the Job.

### 2.3 Relay→daemon named pipe

One installation-scoped Windows named pipe:

- first instance only;
- remote clients rejected;
- DACL limited to expected user/System;
- mutual process attestation;
- one bounded versioned request and correlated response per transient connection;
- finite deadlines, frame limit and connection cap.

Relay verifies daemon PID/creation/session/image/file and supervisor Job membership. Daemon verifies relay PID/SID/creation/session/image. Retained handles bracket PID reuse.

### 2.4 Supervisor↔daemon inherited channel

Two anonymous one-way pipes form one private duplex channel. Only exact daemon ends are inherited via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; environment carries handle numbers and protocol generation, never secrets.

Closed frames include:

```text
store_descriptor / daemon_ready
maintenance_request / maintenance_result
restore_candidate_prepare / restore_candidate_ready
restore_cutover / candidate_discarded
quiesce / quiesced / resume
shutdown_ready / shutdown_complete
```

Every exchange has an exact operation ID and bounded typed payload. Restore/cutover frames carry backup ID, plan/manifest digests, candidate root ID and selection generation—not raw paths, SQL, argv, endpoint or secret.

## 3. SurrealDB child and Store transport

### 3.1 First qualification target

Pin exact SurrealDB 3.3.4 Windows artifact, commit, size and SHA-256. Selected profile:

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
  --allow-origin <reserved origin; CORS metadata only>
```

No engine/version fallback. Origin is not WebSocket authorization.

### 3.2 Listener and peer ownership

Supervisor reserves a loopback port only to narrow the bind race. Windows TCP tables must prove listener ownership. Before credentials, daemon opens raw TCP, proves the established peer belongs to the retained Store process, then performs WebSocket upgrade on that stream.

Port, connect, `/ready`, HTTP status or WebSocket 101 alone proves nothing.

### 3.3 Root bootstrap and Store roles

```text
empty Store starts once with one retained root credential in child-only env
→ root persistence may be unknown
→ child stops
→ same root restarts without root env
→ root authenticates on verified peer
→ create NS + STRICT DB + database Owner + Editor using PASSHASH
→ apply checked migration bundle through Owner
→ close privileged sockets
→ root-free restart
→ daemon admits Editor
```

Unknown bootstrap reuses the same root secret. Root and Owner remain supervisor-only. Daemon receives Editor only. Plaintext password, auth header, verifier and raw auth error never enter logs/manifests/results.

Credential rotation quiesces daemon, closes old sockets, changes PASSHASH through a fresh privileged connection, reconciles unknown using pending/current secrets, publishes selection, restarts Store and requires fresh daemon admission. Password change alone does not revoke an authenticated socket.

### 3.4 Owned query-only WebSocket client

One Tokio task owns each authenticated socket:

- one in-flight exact request ID;
- continuous control/data-frame handling;
- Basic-authenticated upgrade with exact NS/DB headers;
- RPC `query` only;
- finite frame/message/request deadlines.

Caller cancellation drains the exact response or closes the socket. Timeout, close, wrong/late ID, malformed frame or protocol fault poisons it. A mutation possibly sent becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth/schema admission and application identity readback before retry.

### 3.5 Closed DTO wire format

JSON carries explicit operation DTOs only:

- bounded strings, signed integers, booleans and finite floats;
- canonical application IDs as strings;
- integer time plus precision/uncertainty;
- explicit optional state where `NONE` and `NULL` differ;
- vectors with exact dimension/order and finite-value checks;
- exact large bytes as blobs.

Surreal native record IDs, UUID, datetime, decimal and duration never cross as implicit JSON-native application identity. No generic `Value`, `SELECT *`, broad CRUD, copied CBOR tags or user-supplied grammar exists.

## 4. Migration 0001 and schema authority

### 4.1 Migration bundle identity

Migration assets are checked-in UTF-8 with LF endings and deterministic lexical order. Compute:

```text
schema_bundle_sha256 = SHA-256(
  domain tag
  + for each asset: relative path length/path + byte length/bytes
)
```

The assets do **not** contain their own bundle digest literal. The supervisor runner supplies `generation` and computed digest as bound values to one fixed transactional wrapper:

```text
BEGIN TRANSACTION;
  <ordered DDL assets>
  DEFINE PARAM OVERWRITE $eliot_schema_generation VALUE $bound_generation;
  DEFINE PARAM OVERWRITE $eliot_schema_bundle_sha256 VALUE $bound_bundle_sha256;
COMMIT TRANSACTION;
```

Slice 0 must prove exact 3.3.4 bound-value and transactional DDL behavior. On transport/shutdown unknown:

- exact params + exact `INFO FOR DB/TABLE` definitions → committed;
- exact empty fresh candidate → retry same bundle;
- any partial/mismatched state → fail closed; discard fresh candidate or require named migration repair on active root.

`IF NOT EXISTS` is not migration verification.

### 4.2 Application identity

Every externally addressable object has a bounded canonical string field independent of Surreal record ID:

```text
stream_id       s_<26-crockford>
observation_id  o_<26-crockford>
memory_id       m_<26-crockford>
link_id         l_<26-crockford>
job_id          j_<26-crockford>
command_id      c_<26-crockford> or host-native bounded identity
```

Exact grammar and maximum length are validated before Store calls. Native record IDs remain internal implementation detail. Queries bind the canonical string and return explicit projection.

### 4.3 Six Base tables

Migration 0001 defines six `TYPE NORMAL SCHEMAFULL PERMISSIONS NONE` tables. Base fields are introduced only with real writers/readers; later inference migrations extend `job`.

#### `stream`

```text
stream_id: string
project: string
source_kind: string
source_native_id: string
workspace: option<string>
last_ingest_seq: int
created_at_ms: int
updated_at_ms: int
stream_unique_key: string
```

#### `observation`

```text
observation_id: string
project: string
stream_id: string
event_key: string
command_id: option<string>
native_event_key: option<string>
ingest_seq: int
occurrence_time_ms: option<int>
occurrence_precision: string
receipt_time_ms: int
kind: string
body_inline: option<string>
blob_ref: option<string>
body_length: int
body_sha256: string
search_excerpt: string
disclosure: string
locator_json: string
binding_json: string
relations_json: string
capture_limit_json: string
created_at_ms: int
```

Exactly one of `body_inline` or `blob_ref` is present, subject to the configured inline bound.

#### `memory`

```text
memory_id: string
origin_project: string
reuse_scope: string
revision: int
kind: string
address_kind: option<string>
address_key: option<string>
address_unique_key: option<string>
content: string
search_text: string
exact_cues: array<string>
disclosure: string
subject: option<string>
aspect: option<string>
perspective: option<string>
conditions_json: string
exceptions_json: string
valid_from_ms: option<int>
valid_until_ms: option<int>
support_state: string
exposure_state: string
influence_state: string
commitment_state: option<string>
method_role: option<string>
processing_purpose: option<string>
created_at_ms: int
updated_at_ms: int
```

#### `memory_history`

Same semantic projection plus:

```text
history_id: string
memory_id: string
revision: int
replaced_at_ms: int
```

#### `link`

```text
link_id: string
source_kind: string
source_id: string
source_revision: option<int>
target_kind: string
target_id: string
target_revision: option<int>
relation_kind: string
grounds_group: option<string>
locator_json: string
qualification_json: string
created_at_ms: int
```

#### `job`

```text
job_id: string
project: string
purpose: string
target_key: string
state: string
slot_key: option<string>
origin: string
cause_id: option<string>
first_queued_at_ms: int
due_at_ms: option<int>
attempt: int
waiting_reason: option<string>
claim_owner: option<string>
claim_until_ms: option<int>
frozen_input_json: string
method_id: option<string>
method_revision: option<int>
limits_json: string
disclosure: string
profile_name: option<string>
request_blob_ref: option<string>
request_length: option<int>
request_sha256: option<string>
result_json: string
coverage_json: string
cleanup_json: string
created_at_ms: int
updated_at_ms: int
```

### 4.4 Indexes and analyzer

Migration 0001 defines separate index kinds:

```text
DEFINE ANALYZER eliot_base_text TOKENIZERS blank,class FILTERS lowercase;

DEFINE INDEX observation_search ON observation
  FIELDS search_excerpt FULLTEXT ANALYZER eliot_base_text BM25;

DEFINE INDEX memory_search ON memory
  FIELDS search_text FULLTEXT ANALYZER eliot_base_text BM25;
```

Unique/exact indexes include:

```text
stream.stream_id UNIQUE
stream.stream_unique_key UNIQUE
observation.observation_id UNIQUE
observation(project,stream_id,event_key) UNIQUE
observation(project,command_id) UNIQUE
memory.memory_id UNIQUE
memory.address_unique_key UNIQUE
memory_history.history_id UNIQUE
memory_history(memory_id,revision) UNIQUE
link.link_id UNIQUE
job.job_id UNIQUE
job.slot_key UNIQUE
```

Surreal unique indexes ignore `NONE`/`NULL`, so optional `address_unique_key`, optional command identity and active/pending `slot_key` enforce conditional uniqueness without blocking unrelated rows. Slice 0 proves this on exact 3.3.4.

### 4.5 Schema admission

Supervisor and daemon compare:

- `$eliot_schema_generation`;
- `$eliot_schema_bundle_sha256`;
- exact `INFO FOR DB` table/analyzer/param definitions;
- exact `INFO FOR TABLE` fields and indexes for all six tables;
- bounded typed write/read/delete probe through the production client.

Any unknown extra owned field/index, missing definition, mismatched permissions/type or stale digest blocks mutation admission.

## 5. Fixed query corpus

Every operation is a checked-in fixed query with bound data and an explicit response DTO. Initial corpus:

| Query | Required projection / continuation |
|---|---|
| `store_probe` | fixed probe ID, value and delete readback |
| `stream_resolve_lock` | stream ID/key/last sequence with `FOR UPDATE` |
| `capture_read_identity` | observation ID, binding, body length/digest |
| `capture_insert` | complete transaction; no external I/O |
| `memory_open_current` | exact current revision and state |
| `memory_open_history` | exact `(memory_id,revision)` only |
| `observation_open` | exact body/blob metadata and locator |
| `relation_page` | stable `(relation_kind,link_id)` cursor |
| `observation_lexical` | exact IDs + score + bounded excerpt, stable score/ID order |
| `memory_lexical` | exact IDs + score + bounded text, stable score/ID order |
| `job_claim_due` | eligible slot, frozen inputs and claim facts |
| `backup_page_<table>` | canonical application-ID order and exclusive last-ID cursor |
| `schema_readback` | exact params and catalog definitions |

Lexical search uses fixed `@@` predicates, explicit projections and hard row/rendered-byte budgets. Search score ranks candidates only; it is not truth, support or applicability.

No fixed query returns a generic row map. Every cursor binds exact query version, scope, object/revision and options.

## 6. Transactions and durable files

### 6.1 Store transaction rules

- unique values own identity/cardinality;
- controlling rows use `FOR UPDATE`;
- stream sequence and current revision are locked/rechecked;
- a set-wide invariant uses a deterministic sentinel/unique slot;
- nondeterministic `UPSERT` is not idempotency;
- blobs publish before row transaction;
- external calls never run inside Store transactions.

Retry an entire immutable transaction only for an exact retryable conflict. Unknown transport/shutdown/fsync reconciles first. With `sync=every`, an error is not rollback proof.

### 6.2 Immutable file publication

For blobs, spool, deletion notices, terminal records and immutable parts:

```text
same-directory CREATE_NEW temp
→ complete bounded write
→ file flush + close
→ no-replace MoveFileExW WRITE_THROUGH
→ parent-directory flush
→ exact no-follow reopen/readback
```

Existing exact final is prior success only after parent flush/readback. Different bytes conflict. Rename followed by failed parent sync/readback is post-commit unknown.

### 6.3 Atomic final backup-directory publication

The final backup directory must not appear empty.

1. generate 128 OS-random bits and encode `b_<32 lowercase hex>`;
2. create one private same-parent temp directory;
3. write canonical `fence.json` inside it;
4. flush the fence file and temp directory;
5. rename the directory without replacement to `backups/<id>` using write-through semantics;
6. flush the `backups/` parent;
7. open final directory/fence no-follow and verify exact identity/bytes/digest.

Collision abandons the temp directory, allocates another ID and recomputes the plan before any part. Crash before final rename leaves non-restorable/non-pinning temp cleanup debt. A possibly committed rename with failed sync/readback becomes `publication_unknown`; reconciliation opens the final name and pins conservatively.

### 6.4 Mutable installation and external-ID state

`installation.toml` and `controller-write-id.state` use separate expected-state replacement:

```text
read exact old generation/identity
→ write+flush same-directory temp
→ replace with WRITE_THROUGH
→ flush parent
→ exact readback
```

Possible replacement with failed readback is unknown; never write another generation blindly. External-ID state loss is an explicit continuity incident.

## 7. Core application operations

### 7.1 `capture_event`

Relay builds one immutable command before IPC. After any body blob publication, one Store transaction:

1. resolves or creates stream under unique identity;
2. locks stream;
3. reads command/event identities;
4. returns identical replay;
5. rejects changed bytes or binding;
6. allocates stream sequence;
7. inserts observation and source-supplied relations;
8. coalesces only implemented follow-up work;
9. commits.

Matching post-commit readback is required for public `committed`. Capture never calls a model.

### 7.2 Relay delivery and spool

Private daemon result:

```text
committed | rejected | stage_required | unknown
```

`stage_required` occurs before Store/blob ownership during quiesce. Relay publishes the same command immutably on stage-required, unavailable daemon or uncertain direct result. Public `staged` requires durable exact file; otherwise `unknown`.

One daemon replayer processes stable bounded batches with type/size/schema/ID/digest/deletion checks and the same capture operation. Matching Store readback deletes pending with parent flush. Permanent corruption/rejection moves no-replace to failed. Transient failure retains and yields.

Replay exposes pause/drain for backup, shutdown, erasure and cutover. An unresolved possible Store write blocks successful maintenance.

### 7.3 Memory revision and exact open

`publish_memory_revision` locks current, verifies expected revision, copies history, writes new current, adds revision-specific links, settles owning command/job and commits atomically.

`open` requires one exact handle and optional bounded range. It resolves current, exact history, observation/blob/range, converted representation or copied controller result. It returns exact identity, range/digest, state/limitations, relation descriptors, expansion handles and continuation. Historical handles never fall forward.

### 7.4 Job claim

Only configured/enabled/eligible handlers are claimed. Waiting for idle/profile/disclosure/resume is not failure. Claim freezes finite inputs, exact method revision, limits, disclosure and profile. Request bytes and external ID persist before controller I/O.

## 8. First host and retrieval

Initial Claude relay supports SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact and SessionEnd. Relay reads one bounded JSON object, builds one command, performs capture/spool, optionally requests context, emits one bounded host-compatible response and exits.

Address current work before search. Candidate arms are independent: direct handles, work address, exact cues, lexical, compatible vectors, grounds/relations and eligible methods. Apply scope before arm limits and union before selection.

Pack current work, corrections, commitments, methods with exceptions, episodes, dissent/checks and source handles. Omit misleading fragments; return qualified reduction/handle or explicit gap.

## 9. Backup-set owner and backup lifecycle

### 9.1 Owner and lock order

Daemon owns one controller-mutation owner and one backup-set owner.

New fence publication:

```text
close + drain controller-mutation owner
→ acquire backup-set write transition
→ capture controller/spool cut and construct plan
→ atomically publish/read back final backup directory + fence
→ release backup-set transition
→ reopen controller-mutation admission
```

A release/retention send therefore cannot cross a newly visible fence. Abort/retire remove pins; stale pre-terminal snapshots are conservative.

Backup-set owner retains no-follow directory/file handles, rejects reparse/unexpected entries and owns:

- backup ID allocation;
- final record scan and state derivation;
- fence/abort/retire transitions;
- dependency snapshots;
- restore read leases;
- physical backup cleanup.

### 9.2 Backup plan and parts

Before high-water, every created call ID becomes `admitted`, `retired_not_admitted` or `admission_unknown`; every created cancel/release/retention ID becomes `effect_observed`, `retired_not_sent` or `mutation_unknown`. Every admitted call is `controller_closed` or `controller_dependent`.

Canonical plan contains backup ID, expected manifest identity, root/schema/spool cut, controller/client/token/high-water/cut, admitted dependency states, retired attempts, strictest disclosure and gaps. `backup_plan_digest` excludes itself, publication state and later part/manifest digests.

After final fence publication, daemon pages every Base table in stable application-ID order, copies exact referenced blobs and cut spool/deletion/config entries, then publishes final manifest containing the plan digest and actual inventories/digests.

### 9.3 Terminal records

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other malformed/mismatch/ambiguity      -> unresolved/fail closed
```

Abort requires exact fence, no valid manifest, no live writer/restore lease, partial-content cleanup and final-manifest absence readback. Retire requires exact published fence+manifest, no abort and no active restore lease.

Terminal record is create-new, durable, bounded and self-contained. It remains after content cleanup and prevents restore/ID reuse. Terminalization is not erasure.

### 9.4 Restore lease and candidate

Restore is admitted only through the daemon backup-set owner. It holds:

- a logical lease token bound to backup ID/plan/manifest;
- retained no-follow handles to final directory, fence, manifest and required parts;
- delete sharing denied for leased files;
- a final terminal-state recheck immediately before cutover decision.

Daemon sends the supervisor a closed prepare intent. Supervisor creates and admits a fresh candidate Store from typed rows/blobs. Retirement, abort and cleanup wait for the lease.

At cutover daemon quiesces active writes/replay, freezes deletion/spool facts and closes active Store socket. Supervisor stops old Store, applies exact continuity merge, replaces installation selection and presents the selected candidate. Daemon independently admits it before resume.

Daemon/channel loss causes supervisor to terminate/reap/discard candidate before another daemon or cutover. A crash-released lease never authorizes cutover.

### 9.5 Exact rollback and external work

Restore never writes into live root and never invents a merge of later Store rows. Healthy current Store first gets a safety backup; disaster mode records unavailable current inventory. Current deletion notices dominate backup. Current post-cut spool merges by exact command bytes/disposition. Previous root remains until explicit retirement.

`controller_closed` jobs restore from backup facts. `controller_dependent` jobs require exact call/copy. A fixed post-cut interval is inventoried; results are not adopted. Missing caller creates owner-action debt. Any history gap, unknown auxiliary mutation, ambiguous terminal record or missing dependent copy keeps inference disabled while Base remains usable.

## 10. Controller V2 adapter — Contract 0.17

Principal:

```text
principal_kind = memory_inference
client_id = memory:<stable_memory_installation_id>
```

Reads:

```text
client.identity
inference.get
inference.list
inference.high_water
inference.result.read
```

Caller mutations, each with precommitted global `WriteId`:

```text
inference.text
inference.embed later
inference.cancel
inference.release
inference.retention.advance
```

Controller-local owner maintenance: client install/rotate/disable and non-disclosing break-glass erase. Memory cannot invoke owner maintenance.

One bounded runner performs at most one provider attempt. Possible send followed by loss remains `unknown`; no hidden retry/fallback. Exact result is range-read, verified, copied to a Memory blob and decoded. Release is blocked while any final/provisional backup marks the call dependent.

Registration owns monotonic `last_admission_seq` and `retain_after_seq`. Fixed-window list below cut returns `history_gap`; erased content above cut retains bounded text-free membership tombstone until cut advancement.

## 11. Erasure, rotation and observability

Physical erasure publishes a monotonic deletion notice, closes affected mutation/replay, reconciles possible effects, terminalizes and deletes dependent backups/candidates, uses caller cancel/release-abandon where available and deletes controlled rows/blobs/spool/previous roots/controller copies. Missing caller requires observed controller-owner break-glass. Terminal marker, deletion notice and membership tombstone are not physical deletion proof.

Store credential rotation closes sockets and restarts Store. Controller caller rotation preserves stable client ID, fences stale token versions and delays previous-secret deletion until old-call read/release and restart readback.

Status derives from actual facts: executable/root/DACL, process/channel/Store admission, schema generation/bundle digest, query health, capture/spool/replay, backup staging/fence/terminal/lease/candidate/cleanup, controller identity/WriteId/high-water/cut/tombstones, and cleanup/owner debt.

## 12. Implementation sequence

Write production code first. After each coherent increment run:

```text
cargo fmt --check
cargo clippy -p <changed-package> --lib --bins -- -D warnings
```

No broad campaign before connected product.

### Slice 0 — physical, Store and schema preflight

Qualify exact Windows binaries/root leases/DACL, Job custody, inherited channel, relay pipe, SurrealDB 3.3.4/RocksDB `sync=every`, listener/peer ownership, bootstrap roles, query-only DTO client, migration 0001 bundle/params/INFO readback, conflicts/fsync unknowns, immutable/mutable files, external-ID state, staged backup-directory publication, daemon backup-set owner, self-contained terminal records, restore lease/candidate discard, rollback/erasure/rotation/shutdown.

### Slice 1 — useful persistence

```text
real event
→ committed or durably staged
→ replay if staged
→ restart
→ exact open
```

### Slice 2 — first host and useful Base

Qualified Claude relay, continuation, lexical retrieval, actual packet emission, notes/corrections/commitments and Base backup/rollback/erase. Controller inference disabled.

### Controller dependency and inference

Controller issue #200, then V2 L0/L1. Never extend V1.

P1a implements stable caller, WriteId state, controller-mutation owner, calls/private copies/runner, admission/auxiliary cut, daemon backup-set integration, release/retention/list/tombstones and one episode result changing later context. P1b adds token rotation and delayed credential retirement.

### Final qualification

After connected product: concurrency/restart/crash, Windows custody/IPC, Store migration/durability, spool, exact-open pagination, lexical plans, backup publication/terminal/lease/cutover/erasure, controller idempotency/retention/authority/provider uncertainty and measured load/retention campaigns.