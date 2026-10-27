# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.40 · 2026-10-27 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, Store and connected operations. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.18](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the sole active work ledger.

Nothing is implemented merely because it is specified. Build connected production slices in §12. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 0. External prerequisite

Current controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

Controller V2 remains specification-only. Issue #200 owns separation of binding allocation, selected pointer and effect publication; PR #201 is fixture-only. V2 L0.1–L1.11 remain unchecked. Memory inference issue #199 stays blocked on #200 and V2 L0/L1.

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

Supervisor owns executable/root identity, child handles, Store bootstrap credentials, migrations, Store-user rotation, candidate process/root and final cutover.

Daemon owns Memory semantics, Store Editor access, replay/jobs, controller-mutation serialization, backup IDs and installation records, bounded restore leases, retrieval/context and public control.

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
    .tmp-<random>\
    b_<32-lowercase-hex>\
      fence.json
      parts\
      manifest.json?
      abort.json?
      retire.json?
  logs\
```

Initial profile is one fixed local NTFS/ReFS volume. Installer validates protected current-user + LocalSystem DACL, rejects broad principals, network/removable roots and reparse traversal. Database, source bodies, spool and backups are plaintext application data protected by account/DACL/volume security. Base claims no portable encrypted backup.

External-ID state and final backup records are outside rollback Store roots.

### 1.3 Configuration and installation selection

`config.toml` contains projects/workspaces, capture bounds/exclusions, host adapters, controller endpoint/credential reference, profile names, disclosure defaults, automatic-work mode and optional source tools. It is not a policy database or installation pointer.

Supervisor owns `installation.toml` under installation mutex:

```text
selection_generation
stable_memory_installation_id
current_root_id
previous_root_id?
controller_id
controller_client_id
current/pending/previous controller credential refs
current/pending/previous Store Editor refs
current/pending/previous Store Owner refs
expected_memory_schema_generation
expected_memory_schema_bundle_format
expected_memory_schema_bundle_sha256
maintenance_state
```

At most one unretired previous root and one pending/previous credential per role. Another cutover/rotation waits.

### 1.4 Startup sequence

```text
supervisor validates installation and executable/root identities
→ starts/adopts exact active SurrealDB child
→ reconciles bootstrap/credentials
→ applies or verifies checked migration bundle through Owner
→ creates inherited supervisor channel
→ launches and verifies daemon
→ sends non-secret Store/process/schema descriptor
→ daemon independently admits root/process/listener/peer/Editor/schema/query path
→ daemon cleans/quarantines pre-publication backup temp directories under bounded rules
→ backup-set owner scans final backup directories and terminal markers
→ daemon reconciles Store maintenance mirrors and pending release/retention state
→ daemon ready
→ relay endpoint becomes available
```

No host capture reports `committed` before admission. Ordinary jobs cannot run backup-dependent release/retention before installation authority is reconstructed.

## 2. Windows identity, custody and IPC

### 2.1 Retained executable and root leases

Before child resume:

1. open executable, selected root and relevant ancestors no-follow;
2. verify regular identity, digest and DACL;
3. deny write/delete or root-rename sharing as required;
4. create child suspended with fresh environment and exact inherited-handle list;
5. compare actual child image/file identity;
6. assign Job Object;
7. resume only after agreement.

Executable/root leases remain through child lifetime. Path, digest or PID alone is not identity.

### 2.2 Candidate custody and shutdown

Supervisor owns child handles and process-family Job. Graceful stop is requested through the owner protocol; bounded failure uses Job containment. Clean exit is not Store durability proof.

Candidate Store has isolated root, port, credentials and process handle. If daemon/channel is lost while candidate exists, supervisor kills, reaps and discards it before another daemon starts or cutover proceeds. Supervisor loss terminates owned children through the Job.

### 2.3 Relay pipe

One installation-scoped Windows named pipe is first-instance-only, remote-rejected, protected by expected user/System DACL, mutually process-attested and limited to one bounded versioned request/response per transient connection.

Relay verifies daemon PID/creation/session/image/file and Job membership. Daemon verifies relay PID/SID/creation/session/image. Retained handles bracket PID reuse.

### 2.4 Inherited supervisor channel

Two anonymous one-way pipes form one private duplex channel. Only exact daemon ends are inherited via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; environment carries handle values and protocol generation, never secrets.

Closed frames include:

```text
store_descriptor / daemon_ready
maintenance_request / maintenance_result
restore_candidate_prepare / restore_candidate_ready
restore_cutover / candidate_discarded
quiesce / quiesced / resume
shutdown_ready / shutdown_complete
```

Payloads use operation ID plus bounded typed identity/digests, never raw SQL, argv, endpoint, arbitrary path or secret.

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

### 3.2 Listener, peer and authentication

Supervisor reserves loopback port only to narrow the bind race. Windows TCP tables prove listener ownership. Before credentials, daemon opens raw TCP, proves established peer belongs to retained Store process, then performs Basic-authenticated WebSocket upgrade on that stream with exact NS/DB headers.

Port, connect, `/ready`, HTTP status or WebSocket 101 alone proves nothing.

### 3.3 Bootstrap and Store roles

```text
empty Store starts once with retained root credential in child-only env
→ possible root persistence
→ child stops
→ same root restarts without root env
→ root authenticates on verified peer
→ create NS + STRICT DB + Owner + Editor using PASSHASH
→ apply checked migration bundle through Owner
→ close privileged sockets
→ root-free restart
→ daemon admits Editor
```

Unknown bootstrap reuses the same root secret. Root and Owner remain supervisor-only. Daemon receives Editor only. Plaintext passwords, auth headers, verifiers and raw auth errors never enter logs/manifests/results.

Credential rotation quiesces daemon, closes sockets, changes PASSHASH through a fresh privileged connection, reconciles pending/current secrets, publishes selection, restarts Store and requires fresh admission.

### 3.4 Owned query-only client

One Tokio task owns each authenticated socket with one in-flight request ID, continuous control/data-frame handling, RPC `query` only and finite deadlines.

Caller cancellation drains the exact response or closes the socket. Timeout, close, wrong/late ID, malformed frame or protocol fault poisons it. A mutation possibly sent becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth/schema admission and application readback.

### 3.5 Closed DTO format

JSON carries explicit operation DTOs only:

- bounded strings, signed integers, booleans and finite floats;
- canonical application IDs as strings;
- integer time plus precision/uncertainty;
- explicit optional state where `NONE` and `NULL` differ;
- exact large bytes as blobs;
- vectors only when later enabled, with exact dimension/order and finite values.

Surreal native record IDs, UUID, datetime, decimal and duration never cross as implicit application identity. No generic `Value`, `SELECT *`, broad CRUD, copied CBOR tags or user-supplied grammar exists.

## 4. Migration 0001 and schema authority

### 4.1 Non-self-referential bundle identity

Migration bundle preimage is versioned and includes the exact runner wrapper:

```text
schema_bundle_sha256 = SHA-256(
  domain = "eliot-memory-schema-bundle-v1"
  + schema_bundle_format = 1
  + runner_protocol = 1
  + exact transactional wrapper template bytes
  + for each DDL asset in lexical order:
      relative path length/path + byte length/UTF-8-LF bytes
  + exact expected-catalog template bytes
)
```

The wrapper template contains placeholders for ordered DDL and bound metadata; it does not contain the resulting digest literal. Bound generation/digest values are outside the preimage.

Fixed execution shape:

```text
BEGIN TRANSACTION;
  <ordered DDL assets>
  DEFINE PARAM OVERWRITE $eliot_schema_bundle_format VALUE $bound_format;
  DEFINE PARAM OVERWRITE $eliot_schema_generation VALUE $bound_generation;
  DEFINE PARAM OVERWRITE $eliot_schema_bundle_sha256 VALUE $bound_digest;
COMMIT TRANSACTION;
```

Slice 0 must prove exact 3.3.4 bound-value and transactional DDL behavior. On unknown outcome:

- exact metadata plus exact catalog → committed;
- exact empty fresh candidate → retry same bundle;
- partial/mismatched state → fail closed; discard fresh candidate or require named repair on active root.

`IF NOT EXISTS` is not migration verification.

### 4.2 Application IDs

Every externally addressable object has a bounded canonical string field independent of Surreal record ID:

```text
stream_id       s_<26-crockford>
observation_id  o_<26-crockford>
memory_id       m_<26-crockford>
link_id         l_<26-crockford>
job_id          j_<26-crockford>
command_id      c_<26-crockford> or bounded host-native identity
```

Exact grammar/length are validated before Store calls. Native record IDs remain internal.

### 4.3 Base tables

Migration 0001 defines six `TYPE NORMAL SCHEMAFULL PERMISSIONS NONE` tables:

- `stream`: canonical identity, project/source identity, optional workspace, last sequence, timestamps and derived unique key;
- `observation`: occurrence/idempotency identity, times, kind, exact inline body or blob reference, length/digest, bounded search excerpt, disclosure, locator/binding/relations/capture-limit canonical JSON and timestamp;
- `memory`: current semantic revision, origin/reuse/disclosure, optional exact address and derived unique key, content/search/cues, conditions/exceptions, validity, support/exposure/influence, commitment/method state and timestamps;
- `memory_history`: exact previous semantic projection keyed by `(memory_id,revision)`;
- `link`: revision-aware source/target, relation kind, optional grounds group, locator and qualification;
- `job`: finite work state, optional active/pending slot, scheduling/claim facts, frozen input/method, limits/disclosure/profile, request/result/coverage/cleanup and timestamps.

Exactly one observation body location is present: bounded inline text or immutable blob reference. Later inference migrations extend `job`; they do not create another scheduler/table family.

### 4.4 Analyzer and indexes

```text
DEFINE ANALYZER eliot_base_text TOKENIZERS blank,class FILTERS lowercase;

DEFINE INDEX observation_search ON observation
  FIELDS search_excerpt FULLTEXT ANALYZER eliot_base_text BM25;

DEFINE INDEX memory_search ON memory
  FIELDS search_text FULLTEXT ANALYZER eliot_base_text BM25;
```

Exact/unique indexes cover canonical IDs, stream native identity, observation event/command identity, Memory address, history revision, link ID and active/pending job slot.

Surreal unique indexes ignore `NONE` and `NULL`; optional address/command/slot fields therefore implement conditional uniqueness. Slice 0 proves exact 3.3.4 behavior under concurrent writes.

### 4.5 Plain INFO catalog admission

Schema admission uses plain:

```text
INFO FOR DB;
INFO FOR TABLE <closed table name>;
```

`STRUCTURE` is forbidden because it is an internal unstable output.

The client parses the returned maps, selects only owned categories/names, sorts keys and compares exact server-canonical `DEFINE` strings against the checked expected-catalog template for pinned 3.3.4. Raw JSON object byte order is irrelevant.

Owned DB categories:

```text
analyzers: eliot_base_text
params: eliot_schema_bundle_format, eliot_schema_generation, eliot_schema_bundle_sha256
tables: stream, observation, memory, memory_history, link, job
```

For each owned table compare the exact `fields` and `indexes` maps plus table definition. Unknown extra owned names, missing names or mismatched definitions block mutation admission. Database users/accesses are verified through separate authenticated role handshakes and are not part of the application schema map.

Admission also runs one bounded typed write/read/delete through the production client.

## 5. Fixed query corpus

Every operation is a checked-in fixed query with bound data and explicit DTO. Initial corpus:

| Query | Projection / continuation |
|---|---|
| `store_probe` | fixed probe identity/value/delete readback |
| `stream_resolve_lock` | stream identity/key/last sequence with `FOR UPDATE` |
| `capture_read_identity` | observation ID, binding, body length/digest |
| `capture_insert` | complete transaction; no external I/O |
| `memory_open_current` | exact current revision/state |
| `memory_open_history` | exact `(memory_id,revision)` only |
| `observation_open` | exact body/blob metadata and locator |
| `relation_page` | stable `(relation_kind,link_id)` cursor |
| `observation_lexical` | bounded top-K snapshot, no durable cursor |
| `memory_lexical` | bounded top-K snapshot, no durable cursor |
| `job_claim_due` | eligible slot, frozen input and claim facts |
| `backup_page_<table>` | canonical application-ID order and exclusive last-ID cursor |
| `schema_readback` | metadata params and plain INFO maps |

### 5.1 Exact full-text shape

A lexical query that returns BM25 score must use a numbered match reference:

```text
SELECT observation_id,
       search::score(0) AS score,
       search_excerpt
FROM observation
WHERE project = $project
  AND search_excerpt @0@ $query
ORDER BY score DESC, observation_id ASC
LIMIT $hard_limit;
```

The Memory query is identical in shape using `memory_id` and `search_text`.

Plain `@@` is used only when no score/highlight is requested. A score of zero is a valid match for a very common term and is not filtered out.

BM25 IDF and ordering can change as the corpus changes. Therefore lexical retrieval returns one bounded top-K statement snapshot per call. It exposes no durable page cursor. A later expansion is a new retrieval snapshot with its own observed Store revision/high-water facts. Deterministic canonical-ID tie-break orders equal scores inside one snapshot.

Search score ranks candidates only; it is not truth, support or applicability.

### 5.2 Cursor rules

Only queries whose ordering key remains stable across calls expose a cursor. Every cursor binds query version, scope, object/revision and options. No fixed query returns a generic row map.

## 6. Transactions and durable files

### 6.1 Store transactions

Unique values own identity/cardinality. Controlling rows use `FOR UPDATE`. Stream sequence/current revision lock and recheck. A set-wide invariant uses deterministic sentinel/unique slot. Nondeterministic `UPSERT` is not idempotency. Blobs publish before row transaction. External calls never run inside Store transactions.

Retry the entire immutable transaction only for an exact retryable conflict. Unknown transport/shutdown/fsync reconciles first. With `sync=every`, an error is not rollback proof.

### 6.2 Immutable publication

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

### 6.3 Atomic final backup directory

1. generate 128 OS-random bits and encode `b_<32 lowercase hex>`;
2. create private same-parent temp directory;
3. write canonical `fence.json` inside;
4. flush fence file and temp directory;
5. no-replace rename directory to `backups/<id>` with write-through semantics;
6. flush `backups/` parent;
7. reopen final directory/fence no-follow and verify exact identity/bytes/digest.

Collision abandons temp, allocates a new ID and recomputes plan. Pre-rename crash leaves non-restorable/non-pinning temp cleanup debt. A possibly committed rename with failed sync/readback becomes `publication_unknown` and pins after reconciliation.

### 6.4 Mutable installation/external-ID state

`installation.toml` and `controller-write-id.state` use expected-state replacement:

```text
read exact old generation/identity
→ write+flush same-directory temp
→ replace with WRITE_THROUGH
→ flush parent
→ exact readback
```

Possible replacement with failed readback is unknown; never write another generation blindly.

## 7. Core application operations

### 7.1 Capture and spool

Relay builds one immutable command before IPC. After any body blob publication, one Store transaction resolves/locks stream, reads command/event identities, returns identical replay, rejects changed bytes/binding, allocates sequence, inserts observation/relations, coalesces only implemented follow-up and commits. Matching readback is required for public `committed`.

Private daemon result:

```text
committed | rejected | stage_required | unknown
```

`stage_required` occurs before Store/blob ownership. Relay publishes the same command immutably on stage-required, unavailable daemon or uncertain direct result. Public `staged` requires durable exact file.

One daemon replayer uses stable bounded batches and the same capture operation. Matching Store readback deletes pending with parent flush. Permanent corruption/rejection moves no-replace to failed; transient failure retains and yields. Replay exposes pause/drain for maintenance.

### 7.2 Revision, jobs and exact open

Memory revision locks current, verifies expected revision, copies history, writes new current, adds revision-specific links, settles owner and commits atomically.

Job claim selects only configured/enabled/eligible handlers, freezes finite input/method/limits/disclosure/profile and persists request bytes/external ID before controller I/O.

`open` requires one exact handle and optional bounded range. It returns exact identity, revision/representation, range/digest, state/limitations, relation descriptors, expansion handles and continuation. Historical handles never fall forward.

## 8. Host, retrieval and context

Initial Claude relay supports SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact and SessionEnd. Capture and context have separate budgets; context failure never undoes capture.

Address current work before retrieval. Candidate arms are direct/address/exact/lexical/vector/grounds/relation/method. Apply scope before arm limits and union before final selection.

Pack current work, corrections, commitments, methods with exceptions, episodes, dissent/checks and source handles. Omit misleading fragments; return qualified reduction/handle or explicit gap.

## 9. Backup-set owner and lifecycle

### 9.1 Lock order and plan

Daemon owns one controller-mutation owner and one backup-set owner.

```text
close/drain controller mutation
→ enter backup-set transition
→ disposition external IDs and capture controller/spool cut
→ build canonical plan
→ atomically publish/read back final directory + fence
→ leave transition
→ reopen controller mutation
```

A release/retention send cannot cross a newly visible fence.

Backup-set owner validates final entries no-follow, derives state, publishes terminal records, computes dependency snapshots, owns restore leases and cleanup.

Every created call is `admitted | retired_not_admitted | admission_unknown`; every cancel/release/retention ID is `effect_observed | retired_not_sent | mutation_unknown`; every admitted call is `controller_closed | controller_dependent`.

Plan contains backup ID, expected manifest identity, root/schema/spool cut, controller/client/token/high-water/cut, dependencies, retired attempts, disclosure and gaps. Digest excludes itself, publication state and later part/manifest digests.

After final fence, daemon pages Base tables in canonical ID order, copies exact blobs and cut spool/deletion/config, then publishes final manifest.

### 9.2 Terminal records

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other ambiguity                         -> unresolved/fail closed
```

Abort requires exact fence, no manifest, no writer/restore lease, partial cleanup and manifest absence readback. Retire requires exact published fence+manifest, no abort and no active lease. Terminal record is self-contained, durable and retained after content cleanup. Terminalization is not erasure.

### 9.3 Bounded restore lease

Before lease admission validate manifest part count, per-part bytes, total bytes, unique canonical relative paths and format/schema support against hard limits.

Hold for whole restore:

- logical lease bound to backup/plan/manifest;
- final directory handle;
- fence and manifest handles;
- `FILE_SHARE_READ` only on retained handles;
- final terminal/manifest identity recheck before cutover.

Do not retain handles to every part. Iterate deterministic manifest order: open one part no-follow with read access and `FILE_SHARE_READ` only, verify regular identity/path/length/digest, copy+verify into candidate, close, continue.

Logical owner blocks daemon cleanup/retirement; active part handle blocks write/delete during read; digest catches pre-open substitution. This closes the race with bounded handles.

Supervisor creates/adopts the candidate from closed identity/digest intent. At cutover daemon quiesces active Store/replay, freezes deletion/spool facts and closes active socket; supervisor stops old Store, applies exact continuity merge, replaces selection and presents the selected candidate; daemon independently admits it before resume.

Daemon/channel loss forces candidate kill/reap/discard before restart/cutover.

### 9.4 Exact rollback and external work

Restore never writes into live root or invents merge of later rows. Healthy current Store first gets safety backup; disaster mode records unavailable current inventory. Current deletion notices dominate backup; current post-cut spool merges by exact bytes/disposition; previous root remains until retirement.

Closed jobs restore from backup facts. Dependent jobs require exact controller call/copy. Fixed post-cut interval is inventoried; results are not adopted. Missing caller creates owner-action debt. Any history gap, terminal ambiguity, limit violation, unknown auxiliary effect or missing dependent copy keeps inference disabled while Base remains usable.

Store maintenance mirrors are reconciled against installation authority before job claims. Stale future-timeline rows cannot create terminal records, clear pins or replay old release/retention.

## 10. Controller V2 adapter — Contract 0.18

Principal:

```text
principal_kind = memory_inference
client_id = memory:<stable-memory-installation-id>
```

Reads: identity/get/list/high-water/result-range. Mutations: text/embed later/cancel/release/retention-advance, each with precommitted global `WriteId`. Owner-only: client install/rotate/disable and non-disclosing break-glass erase.

One bounded runner performs at most one provider attempt. Exact result is range-read, verified, copied and decoded. Release is blocked while any final/provisional backup marks the call dependent.

Registration owns monotonic admission and retention cuts. Fixed-window list below cut returns history gap; erased content above cut retains bounded membership tombstone until cut advancement.

## 11. Erasure, rotation and observability

Physical erasure publishes a deletion notice, closes affected mutation/replay, reconciles possible effects, terminalizes and deletes dependent backup content after leases, uses caller cancel/release-abandon where available and deletes controlled rows/blobs/spool/previous roots/controller copies. Missing caller requires observed owner break-glass. Tombstones/markers are not physical deletion proof.

Store credential rotation closes sockets and restarts Store. Controller caller rotation preserves stable client ID, fences stale token versions and delays old-secret deletion until old-call read/release and restart readback.

Status derives from executable/root/DACL, process/channel/Store admission, schema format/generation/bundle digest/catalog, query health, capture/spool/replay, backup staging/fence/terminal/lease/limits/candidate/cleanup, controller identity/WriteId/high-water/cut/tombstones and cleanup debt.

## 12. Implementation sequence

Write production code first. After each coherent increment run:

```text
cargo fmt --check
cargo clippy -p <changed-package> --lib --bins -- -D warnings
```

### Slice 0

Qualify exact Windows binaries/root leases/DACL, Job custody, IPC, SurrealDB 3.3.4/RocksDB `sync=every`, listener/peer ownership, bootstrap roles, query-only DTO client, migration bundle wrapper/params/plain INFO catalog, FTS numbered-score query, conflicts/fsync unknowns, immutable/mutable files, external-ID state, staged backup directory, backup owner, terminal records, bounded streaming restore lease, candidate discard, rollback/erasure/rotation/shutdown.

### Slice 1

```text
real event → committed or durable stage → replay → restart → exact open
```

### Slice 2

Qualified Claude relay, continuation, lexical top-K retrieval, actual packet emission, notes/corrections/commitments and Base maintenance with inference disabled.

### Controller and inference

Controller issue #200, then V2 L0/L1. Never extend V1. P1a implements stable caller, calls/copies/runner, cut/retention, backup integration and one result changing later context. P1b adds rotation and delayed credential retirement. Broader capabilities follow independently.

Broad deterministic/live/platform/load campaigns follow connected product.