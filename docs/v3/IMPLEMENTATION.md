# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.38 · 2026-10-27 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, Store and connected operations. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.16](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the sole active work ledger.

Nothing is implemented merely because it is specified. Build connected production slices in §15. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 0. External prerequisites

Current controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

Controller V2 is still a specification target. Its roadmap L0.1–L1.11 is unchecked. Issue #200 must repair binding-revision allocation/schema authority before V2 implementation; draft PR #201 fixes only validator fixtures. Memory inference issue #199 remains blocked on #200 and controller L0/L1.

Memory Slice 0 and useful Base do not depend on controller V2.

## 1. Runtime and installation

### 1.1 Process family

Initial Windows profile uses one executable with modes:

```text
eliot supervisor     privileged installation/process owner
eliot daemon         Memory application owner
eliot relay ...      transient host/CLI adapter
```

Owned process shape:

```text
supervisor
├─ daemon
└─ active SurrealDB child
   └─ at most one isolated disposable restore candidate
```

Supervisor owns process handles, executable/root identity, Store bootstrap credentials, migrations, Store-user rotation, candidate lifecycle and installation cutover. Daemon owns Memory semantics, Store Editor access, replay/jobs, backup cuts, retrieval/context and public control.

### 1.2 Installation layout

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  installation.toml
  controller-write-id.state
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
    <random-128-bit-backup-id>\
      fence.json?
      parts\
      manifest.json?
      abort.json?
      retire.json?
  logs\
```

Initial profile is one fixed local NTFS/ReFS volume. Installer validates protected current-user + LocalSystem DACL, rejects unexpected broad principals, network/removable roots and reparse traversal. Database, source bodies, spool and backups are plaintext application data protected by account/DACL/volume security. Initial Base claims no portable encrypted backup.

`controller-write-id.state` and installation-scoped backup records live outside rollback Store roots. Exact Memory rollback cannot remove, regress or recreate them.

### 1.3 Configuration and mutable installation selection

`config.toml` contains user configuration only: project/workspace binding, capture bounds/exclusions, host adapters, controller endpoint/credential reference, selected inference profiles, disclosure defaults, automatic-work mode and optional source tools. It is not a policy database, module catalogue or installation pointer.

Supervisor owns `installation.toml` under installation mutex:

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
maintenance_state
```

At most one unretired previous root and one pending/previous credential per role. Another cutover or rotation waits until earlier generation retirement.

`stable_memory_installation_id` is random and non-secret. It is not derived from path, root generation, username, executable or token.

### 1.4 Startup sequence

```text
supervisor validates selection + executable/root identities
→ scans installation-scoped backup directories and terminal markers
→ starts/adopts exact SurrealDB child
→ reconciles bootstrap/credentials and runs checked migrations through Owner
→ creates inherited supervisor↔daemon channel
→ launches daemon suspended, verifies image and assigns Job
→ sends non-secret Store descriptor + authoritative backup-set summary
→ daemon independently admits root/process/listener/peer/Editor/schema/query path
→ daemon reconciles Store maintenance mirrors against installation records
→ daemon reconciles unresolved publication/terminal/retention state
→ daemon reports ready
→ supervisor allows relay endpoint publication
```

No host capture reports `committed` before daemon admission. The ordinary job runner cannot execute backup/retention/release work before installation-scoped backup authority is scanned. No controller release or retention advance is sent while backup state is unresolved.

## 2. Windows identity, launch and custody

### 2.1 Retained executable and root leases

Before owned child resumes:

1. open executable, selected data root and relevant ancestors without following reparse points;
2. verify regular file/directory identity, expected digest and DACL;
3. deny write/delete or root-rename sharing where required;
4. create child suspended with closed environment and exact inherited-handle list;
5. compare actual child image/file identity;
6. assign correct Job Object;
7. resume only after agreement.

Executable/root leases remain through child lifetime. Path string, pre-launch digest or PID alone is not identity.

### 2.2 Job custody and shutdown

Supervisor owns one process-family Job with kill-on-close where appropriate. Process identity includes PID, creation time and retained handle. Graceful stop is attempted through owning protocol; bounded failure uses Job containment. Clean process exit is not Store durability receipt.

Candidate Store has isolated root, port, credentials and Job. It never shares live database files or listener.

### 2.3 Closed child environments

Construct fresh environment blocks containing only required OS locale/path/certificate/temp facts plus exact child settings. Do not inherit arbitrary `SURREAL_*`, `RUST_LOG`, metrics, telemetry, slow-query, import or Postgres settings.

Secrets go only to the narrow child that needs them and are removed after bootstrap. No secret enters argv or logs.

## 3. IPC boundaries

### 3.1 Relay→daemon named pipe

One installation-scoped Windows named pipe:

- first instance only;
- remote clients rejected;
- DACL limited to expected user/System;
- mutually attested process identities;
- one bounded versioned request and correlated response per transient connection;
- finite deadlines, frame limit and connection cap.

Relay verifies daemon PID/creation/session/image/file and supervisor Job membership. Daemon verifies relay PID/SID/creation/session/image. Retained handles bracket PID reuse.

Same-account arbitrary malicious code is outside claimed boundary; accidental/stale/foreign-process confusion fails closed.

### 3.2 Supervisor↔daemon inherited channel

Supervisor creates two anonymous one-way pipes and passes only exact daemon ends through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Child environment carries handle values and protocol generation, never secrets.

Closed frames:

```text
store_descriptor / daemon_ready
maintenance_request / maintenance_result
quiesce / quiesced / resume
shutdown_ready / shutdown_complete
```

Every exchange has operation ID and bounded typed payload. Daemon may name retained backup/config/credential identity; it cannot send raw SQL, argv, endpoint, arbitrary path or secret. Supervisor independently resolves named object.

Channel loss is fail-closed. Before selection replacement, candidate is abandoned. After possible replacement, startup reads actual selection before another action.

## 4. SurrealDB child and Store transport

### 4.1 First qualification target

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

### 4.2 Listener and peer ownership

Supervisor reserves loopback port only to narrow bind race. Windows TCP tables prove listener owner. Before credentials, daemon opens raw TCP and proves established server peer belongs to retained Store process, then performs WebSocket upgrade on that stream.

Port, TCP success, `/health`, `/ready`, HTTP 200 or WebSocket 101 alone proves nothing.

### 4.3 Root bootstrap and Store roles

```text
empty Store starts once with retained root credential in child-only env
→ root persistence may be unknown
→ child stops
→ same Store restarts without root env
→ root authenticates on verified peer
→ create NS + STRICT DB + database Owner + Editor with PASSHASH
→ checked migrations through Owner
→ close privileged sockets
→ root-free restart
→ daemon admits Editor
```

Unknown bootstrap reuses same retained root secret. Root and Owner remain supervisor-only. Daemon receives Editor only. Plaintext password, auth header, verifier and raw auth error never enter logs/manifests/results.

Credential rotation quiesces daemon, closes old sockets, changes PASSHASH through fresh privileged connection, reconciles unknown using pending/current secrets, publishes selection, restarts Store and requires fresh daemon admission. Password change alone does not revoke authenticated WebSocket.

### 4.4 Owned query-only WebSocket client

One Tokio task owns each authenticated socket:

- one in-flight exact request ID;
- continuous control/data frame handling;
- Basic-authenticated upgrade with exact NS/DB headers;
- `query` only; no RPC signin/use/version/ping dependency;
- finite frame/message/request deadlines.

Caller cancellation drains exact response or closes socket. Timeout, close, wrong/late ID, malformed frame or protocol fault poisons it. Possible mutation send becomes `OUTCOME_UNKNOWN`; reconnect repeats peer/auth/schema admission and application readback.

### 4.5 Closed DTO wire format

JSON carries explicit operation DTOs only:

- fixed projections/order;
- bounded strings, signed integers, booleans and finite floats;
- canonical application IDs;
- integer time plus precision/uncertainty;
- explicit optional state where `NONE` and `NULL` differ;
- vectors with exact dimension/order/finite checks;
- exact large bytes as blobs.

No generic Surreal `Value`, `SELECT *`, broad CRUD, copied vendor CBOR tags or implicit native-type round-trip. Grammar-changing identifiers come from closed enums; ordinary data uses bound variables.

## 5. Physical Memory data model

Use six `SCHEMAFULL` tables plus selected-root blobs. Add fields/indexes only with first real writer and reader.

### 5.1 `stream`

```text
id, project, source_kind, source_native_id, workspace?, last_ingest_seq
```

Unique `(project, source_kind, source_native_id)`. Sequence orders one stream only.

### 5.2 `observation`

```text
project, stream, event_key, sequence
command_id?, native_event_key?
occurrence_time + precision, receipt_time
kind
exact inline body or blob ref + length/digest
bounded search excerpt
locator
work/task/resource binding
source-supplied relations
capture limitations/redactions
disclosure
packet/correction references
```

Unique `(project, stream, event_key)` and `(project, command_id)` where present. Equal bytes do not merge occurrences.

### 5.3 `memory`

```text
id, project, kind, revision
origin, reuse_scope, disclosure
optional address + derived unique key
content, search text, cues, aliases
subject/aspect/perspective
conditions/exceptions/selectors
validity/limitations
support/exposure/influence
commitment state
processing-method role/purpose
vector/effective-space/representation when present
timestamps
```

### 5.4 `memory_history`

Previous revisions, unique `(item, revision)`. Version handles never fall forward.

### 5.5 `link`

Revision-aware source/target, relation kind, optional grounds group, locator and qualification. Grounds within one group are conjunctive; groups are alternatives; ungrouped support advisory; navigation carries no evidential Boolean meaning.

### 5.6 `job`

Finite background/application-maintenance work:

```text
id, project, purpose, target
state, active/pending slot
origin/cause
due/attempt/retry/waiting reason
frozen input members/ranges
exact processing-method revision
limits/disclosure/profile
exact request blob/length/digest
application result/coverage
per-copy cleanup state
```

Controller-backed fields:

```text
controller_id
controller_client_id
selected_token_version
inference_write_id
method + canonical semantic request identity
controller_admission_state = prepared | admitted | retired_not_admitted | admission_unknown
controller_admission_seq when admitted
controller_dependency_state = controller_closed | controller_dependent
profile/connection/adapter/destination snapshot
result length/digest when known
Memory result blob
cancel_write_id? + effect_observed | retired_not_sent | mutation_unknown
release_write_id? + release disposition + auxiliary state
retention_write_id? + expected/new cut + auxiliary state
input/result cleanup state
external-work inventory status
owner_action_required? + observed owner readback?
```

A caller cleanup or retention advance is an ordinary finite job/maintenance record with exact expected state and its own precommitted WriteId. No new table or scheduler is needed.

Backup publication/terminal state is mirrored in an ordinary maintenance job:

```text
backup_candidate_id
backup_plan_digest
observed_fence_digest?
observed_manifest_digest?
terminal_operation_id?
controller_id/client_id/high_water/retain_after_seq
exact controller_dependent call ids/sequences
publication_state = preparing | publication_unknown | published | aborted_before_publish | retired
mirror_state = current | superseded_by_installation_state
```

This row is never authority and may be rolled back. Startup/restore reconcile it against installation-scoped records before job claims. A restored future-timeline mirror cannot create fence/abort/retire records, clear pins or send release/retention.

Controller-owner erase is not a Memory mutation. Memory may retain non-content `owner_action_required` and later observed owner result; it never generates/submits owner erase WriteId.

Never store raw controller token/hash/provider credential, V1 Operation ID, V1 credential ID/generation or `possible_send` ledger.

Per-copy state:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Aggregate cleanup derives from exact copies. One active + one coalesced successor per target; terminal history has no slot.

### 5.7 Blobs, packets and locators

Large exact bytes live under selected-root `blobs/`; rows keep opaque ref, length and digest. Publish before row commit. Packet is ordinary observation/blob plus links containing exact included revisions, rendered digest, budget and gaps.

Locators claim only supplied precision. Dirty/untracked code is retained bytes/range, not HEAD alone.

## 6. Schema, migrations and transactions

### 6.1 Migration owner

Supervisor Owner applies ordered checksummed migrations before daemon admission:

- configured namespace + `STRICT` DB under `--no-defaults`;
- six `SCHEMAFULL` tables and explicit fields;
- narrowly named bounded `FLEXIBLE` metadata only with real reader;
- occurrence/idempotency/address/history/job-slot indexes;
- initial indexes synchronously;
- no 2.x-only clauses.

`$eliot_schema_generation`, migration digests and `INFO FOR DB/TABLE` own admission. `IF NOT EXISTS` is not migration verification.

### 6.2 Transaction rules

One fixed query executes one complete transaction and every statement result is inspected.

- unique values own identity/cardinality;
- controlling rows use `FOR UPDATE`;
- stream sequence/current revision lock/recheck;
- set-wide invariant uses deterministic sentinel/unique slot;
- nondeterministic `UPSERT` is not idempotency;
- blobs publish before row transaction;
- external calls never run inside Store transactions.

Retry entire immutable transaction only for exact retryable conflict. Unknown transport/shutdown/fsync reconciles first. With `sync=every`, mutation may apply before fsync error reaches caller; error is not rollback proof.

## 7. Durable local files and external-ID state

### 7.1 Immutable no-replace publication

For blobs, spool, deletion notices, backup fences/parts/manifests/terminal markers and immutable candidate artifacts:

1. retain/validate parent no-follow;
2. create same-directory temp with `CREATE_NEW`;
3. write complete bounded bytes;
4. flush file and close;
5. no-replace `MoveFileExW(..., WRITE_THROUGH)`;
6. flush parent directory;
7. reopen and verify exact identity/length/digest.

Existing exact final is prior success only after parent flush/readback. Different bytes conflict. Rename followed by failed sync/readback is post-commit unknown.

### 7.2 Mutable installation selection

Supervisor-only under installation mutex:

1. read current and require expected generation;
2. construct complete generation+1 record;
3. write/flush temp;
4. `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`;
5. flush parent;
6. exact no-follow readback.

Possible replace with failed readback is `SELECTION_UNKNOWN`; startup classifies exact old, exact new or fail-closed unexpected. Previous root/credentials remain until explicit retirement.

### 7.3 Controller WriteId state

```text
controller-write-id.state {
  schema_version
  controller_id
  controller_client_id
  last_ulid
}
```

Under own cross-process mutex:

1. authenticate current controller identity and read floor/future-skew;
2. read retained state and require matching controller/client;
3. create monotonic canonical ULID after retained value and at least admitted floor/current monotonic time;
4. replace state atomically with generation/digest/readback discipline;
5. persist exact ID in owning job/maintenance record;
6. only then send.

Crash after state advance burns ID. Crash before job persistence must not send. Exact rollback never replaces this file. Total state loss is explicit continuity incident, not permission to reuse old semantics with new IDs.

### 7.4 Backup identifiers and terminal records

The backup-set owner obtains 128 random bits from the OS CSPRNG and encodes one fixed-width non-secret backup ID. It attempts create-new top-level directory/fence publication. Any existing directory or terminal marker is a collision; generate another ID and never overwrite or reuse.

Terminal operation IDs are deterministic from a closed domain tag plus backup ID, plan digest and, for retirement, manifest digest. A retry produces exact marker bytes; a different reason/payload conflicts rather than overwriting.

`abort.json` and `retire.json` contain only bounded non-content fields and are self-contained terminal authority after creation prerequisites are proven. They remain after content-bearing files are removed.

## 8. Core application operations

### 8.1 `capture_event`

Relay builds one immutable command before IPC. After referenced blob publication, one Store transaction resolves/locks stream, reads command/event identities, returns identical replay, rejects changed bytes/binding, allocates sequence, inserts observation/relations and coalesces only implemented work. Matching post-commit readback is required for public `committed`.

Capture never calls model.

### 8.2 Relay delivery and spool

Private daemon result:

```text
committed | rejected | stage_required | unknown
```

`stage_required` occurs before Store/blob ownership during quiesce. Relay publishes same command immutably on stage-required, daemon unavailable or uncertain direct result. Public `staged` requires durable exact file; otherwise `unknown`.

One daemon replayer uses stable bounded batches, type/size/schema/ID/digest/deletion checks and same capture operation. Matching Store readback deletes pending with parent flush. Permanent corruption/rejection moves no-replace to failed. Transient failure retains and yields. Poison entry cannot starve queue.

Replay exposes pause/drain for backup, shutdown, erasure and cutover. Unresolved possible Store write blocks successful maintenance.

### 8.3 `publish_memory_revision`

One transaction locks current, checks expected revision, copies old row to history, writes new current, adds revision-specific links, settles owning command/job, coalesces affected follow-up and commits. New IDs allocated once and retained before retry.

### 8.4 Controller-mutation owner and backup-set owner

Select only configured/enabled/eligible handlers. Waiting for idle/profile/disclosure/resume is not failure. Claim freezes finite sources, exact method revision, limits, disclosure and profile. Exact request bytes and call WriteId persist before controller I/O.

One daemon controller-mutation owner is the only code permitted to send caller mutations across Memory→controller:

```text
inference.text / inference.embed
inference.cancel
inference.release
inference.retention.advance
```

One backup-set owner owns backup IDs, installation-record scan, pin-set transitions, restore leases and physical backup cleanup. It retains no-follow directory/file handles and rejects reparse/unexpected entries.

Backup closes/drains the controller-mutation owner before publishing a new fence. Abort/retire transitions finish under the backup-set owner before release/retention is re-evaluated. No mutation may pass a stale controlled-set snapshot.

Before `inference.release`, the mutation owner obtains a current backup-set snapshot and blocks release when any restorable backup or unresolved fence marks the call `controller_dependent`. The check repeats immediately before send.

Before `inference.retention.advance`, it computes the cut from current restorable backups and unresolved fences. A restored pending advance is not sent; current desired state is recomputed first.

Restore obtains a read lease from the backup-set owner. Retirement/abort/cleanup for that backup wait through candidate verification and final pre-cutover recheck. Crash drops the lease and the candidate is discarded.

### 8.5 Exact `open`

Require one nonempty handle. Resolve current item, exact history, observation/blob/range, converted representation, Research section/citation or copied controller result. Return requested/resolved identity, exact range/digest, state/limitations, revision-aware relation descriptors, expansion handles/cursor and explicit missing/forbidden/erased/damaged/unsupported disposition.

Fixed cap without cursor is incomplete. Historical handles never fall forward. Coherent hydration uses one snapshot or revision fences.

## 9. First Claude host adapter

Initial events:

| Event | Captured/returned behavior |
|---|---|
| SessionStart | session/work binding and actual continuation packet |
| UserPromptSubmit | exact prompt and decision-time packet |
| PostToolUse | tool ID/input/result/duration/resource binding |
| PostToolUseFailure | tool ID/input/error/interruption facts |
| Stop | main final host-supplied message |
| SubagentStop | subagent identity/final/parent binding |
| PostCompact | summary as derived representation |
| SessionEnd | lifecycle boundary/reason |

Relay reads one bounded JSON object, builds one `CaptureCommand`, uses mutually attested pipe, attempts direct capture then spool, optionally requests context, emits one bounded host-compatible output and exits. Capture/context budgets are separate. Same command ID survives uncertainty.

Default enablement requires installed-version payload/output/timeout/fork/resume/compact/subagent qualification.

## 10. Retrieval, context and source opening

Address current work before similarity search. Candidate arms are independent: direct handles, work address, exact cues, lexical, compatible vectors, grounds/relations and applicable methods. Apply project/work scope before arm limits and union before final selection.

Rank relevance separately from support. Applicability is applicable/inapplicable/conditional-or-unknown. Pack current work, corrections, methods with exceptions, prior episode, dissent/checks and source handles. Omit misleading fragments; return qualified reduction/handle or explicit gap.

Retain rendered packet bytes and exact included revisions before host output. Prepared/emitted/associated/used remain separate observations/facts.

## 11. Controller V2 adapter — Contract 0.16

### 11.1 Principal and identity admission

```text
principal_kind = memory_inference
client_id = memory:<stable_memory_installation_id>
```

`client.identity` must match installation selection:

```text
controller_id
client_id
principal kind
token_version
api_version
WriteId floor/future-skew
```

No owner/Agent/automation/plugin/no-token fallback. Controller checks registration/version before every call; stale transport closes.

### 11.2 Minimal API

Reads:

```text
client.identity
inference.get
inference.list
inference.high_water
inference.result.read
```

Caller mutations, each with precommitted global WriteId:

```text
inference.text
inference.embed later
inference.cancel
inference.release
inference.retention.advance
```

Controller-local owner maintenance: client install/rotate/disable and non-disclosing break-glass erase. Memory cannot invoke owner maintenance.

### 11.3 Live call lifecycle

```text
Memory persists exact request + call WriteId
→ same method/ID/bytes sent
→ controller first-admits or returns existing call
→ one bounded provider attempt
→ exact result private file when present
→ Memory range-reads and verifies/copies
→ cognitive decode/publication
→ release only when no controlled backup dependency remains
```

Possible provider send becomes `unknown`; never another attempt under new ID. Store conflict reuses retained result, not provider call.

Cancel, release and retention advance each have their own durable WriteId. At backup cut each becomes effect-observed, retired-not-sent or unknown. An old backup never first-admits an absent auxiliary ID.

### 11.4 Admission and retention

Controller registration owns:

```text
last_admission_seq
retain_after_seq
```

First admission transaction checks signed-64 exhaustion, increments sequence and inserts receipt/call. Never derive from retained rows.

`inference.high_water` returns:

```text
high_water = last_admission_seq
retain_after_seq
observed_earliest_retained_seq?  # diagnostic only
```

`inference.list(after, through, cursor, limit)` fixes membership `(after, through]`. Cursor binds controller/client, bounds, API version and page shape. `after < retain_after_seq` returns `history_gap` even if rows remain.

Erasing content for call above cut leaves bounded text-free membership tombstone until cut advancement.

`inference.retention.advance` uses caller WriteId, expected current cut and monotonic new cut. It cannot exceed high-water/decrease. Restorable and unresolved provisional backups pin the post-cut denominator; in-cut dependencies remain unreleased and never lower the cut.

### 11.5 Cleanup authority

With valid caller:

```text
queued -> optional inference.cancel
then inference.release(...), subject to current controlled backup set
```

Owner `inference.erase` is local break-glass only. Memory records `owner_action_required` and later non-content readback; it never creates/submits owner erase ID.

### 11.6 Private credential publication

Controller-local owner derives token and writes only to admitted private create-new/no-reparse destination with restrictive ACL, file/parent durability and exact readback. Memory receives credential reference/bundle, never owner token or routing key. Lost reply retries same owner WriteId and re-derives same token.

## 12. Learning and cognition integration

Group episodes by actual session/task/call/result relations. Freeze membership and selected/supplied/covered ranges. Normal job receives episode, feedback, small related set and exact recipe. It may create/revise, identify conflict/unknown or valid no-change.

First enable stores real default processing method; upgrades do not overwrite edited revision. Automatic mode is off/idle/background; profile may deny automatic. New input coalesces one successor. Output must reach context/open/method consumer.

Operational failure/no-result/malformed/truncated/omitted coverage is not cognitive no-change. Useful partial output records coverage. Cleanup state separate from cognitive result.

## 13. Backup, rollback, retention, terminal state and erasure

### 13.1 Admission/dependency/auxiliary closure and immutable plan fence

1. stop new application mutations and controller-backed work;
2. close/drain the controller-mutation owner and reconcile in-flight send/readback;
3. pause replay and reconcile active item/Store-write unknowns;
4. persist every created call/cancel/release/retention WriteId;
5. authenticate exact controller caller;
6. classify every call ID as admitted, retired-not-admitted or admission-unknown;
7. classify every auxiliary ID as effect-observed, retired-not-sent or mutation-unknown from exact call/current-cut readback;
8. classify every admitted call as controller-closed or controller-dependent;
9. read `high_water + retain_after_seq` only after classification;
10. under brief spool-publication lock capture exact spool cut/generation and immutable entry inventory; release lock;
11. allocate a fresh non-reused backup ID through the backup-set owner;
12. construct canonical backup plan over backup ID, expected manifest identity, selected root/schema/spool cut, controller/client/token/high-water/cut, admitted dependencies, call/auxiliary dispositions, disclosure and gaps;
13. compute `backup_plan_digest` excluding its own field, publication state and later page/part/manifest digests;
14. publish/read back installation-scoped create-new `fence.json` outside rollback Store roots;
15. only then page Store/copy parts and publish final manifest.

Final manifest repeats `backup_plan_digest` and actual inventories/digests. It never requires a precommitted digest of itself. Store maintenance row mirrors status only.

### 13.2 Installation-scoped states and terminal tombstones

```text
backups/<backup-id>/
  fence.json?
  parts/...
  manifest.json?
  abort.json?
  retire.json?
```

State order:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication-unknown
all malformed/mismatched/both-terminal  -> unresolved/fail closed
```

Abort/retire markers are self-contained terminal authority after creation prerequisites. They bind backup ID, plan/fence identity, deterministic terminal operation ID and closed reason code; retire also binds manifest digest. Later deletion of fence/manifest/parts does not invalidate terminal state. Surviving files that disagree are integrity failure.

### 13.3 Post-cut retention denominator

```text
required_retain_after_seq =
  minimum high_water among:
    valid published non-retired restorable backups
    unresolved preparing/publication-unknown fences
```

After controlled-set change is durable, recompute current desired cut, create a fresh maintenance record with expected/new cut and precommitted WriteId, then send. Restored pending retention intent is reconciled or retired, never blindly replayed. Crash before fresh advance is conservative.

### 13.4 Published backup retirement and abort

Retirement never deletes authoritative files first.

1. require exact valid published backup, no active restore lease and serialize through backup-set owner;
2. construct deterministic self-contained `retire.json`;
3. publish create-new/no-reparse with file/parent durability and exact readback;
4. only then mark generation non-restorable and exclude it from release/retention pin scans;
5. recompute denominators;
6. clean content-bearing parts/manifest/fence later; retain terminal tombstone.

Abort is valid only before successful publication, after exact manifest absence, no live writer/restore lease and partial-content cleanup. It publishes a self-contained `abort.json`. Abort and retire are mutually exclusive. Unknown terminal publication leaves state unresolved and pinned.

Terminal state is not physical erasure. Remaining content keeps erasure incomplete.

### 13.5 Exact rollback and restore lease

Restore never writes into live root or invents merge of later Store rows. Healthy current Store first receives safety backup; disaster mode records unavailable current inventory.

The backup-set owner admits restore only for a valid published non-retired backup and returns a read lease with retained no-follow handles to fence, manifest and required parts. Retirement/abort/cleanup wait while the lease exists. Restore holds it through candidate materialization, verification and final pre-cutover terminal-record recheck.

Build/verify a fresh candidate under supervisor Owner, apply migrations, restore typed rows/unfenced blobs, stage backup spool separately, compare config, restart/admit candidate under Editor, then quiesce active Store and cut over through expected-generation selection replacement. On crash the lease disappears and the disposable candidate is discarded.

Current deletion notices dominate backup. Current post-cut spool merges by command ID/exact bytes/disposition. Failed never becomes pending. Previous root remains until explicit retirement.

### 13.6 Restored controller work and maintenance mirrors

In-cut restored calls:

```text
controller_closed
  restore from backup facts; controller row may be absent

controller_dependent
  exact call and required copy must remain; absence/mismatch is damaged/history_gap

retired_not_admitted
  old call ID stays retired

admission_unknown
  hold with inference disabled
```

Auxiliary IDs:

```text
effect_observed     retain observed effect; never resend old ID
retired_not_sent    never send old ID
mutation_unknown    hold until exact readback
```

Before job claims, installation records supersede restored Store mirrors. A stale mirror is marked `superseded_by_installation_state` and cannot create terminal records, clear pins or send release/retention.

After post-cut inventory, still-needed cancel/release is recomputed from current call and backup-set state. Retention target is recomputed from current installation records and controller cut. Any new mutation receives a fresh WriteId.

### 13.7 Controller external-work inventory

Capture inventory high-water and page:

```text
inference.list(
  after = backup_high_water,
  through = inventory_high_water
)
```

Every returned post-cut call lies outside backup's admitted set. Do not adopt result as restored cognition. With valid caller, cleanup uses recomputed cancel/release-abandon after controlled-set checks. Without caller, create `owner_action_required` debt.

New inference remains disabled until inventory completes and every row is dispositioned. `history_gap`, controller/caller unavailability, call/auxiliary unknown, publication/terminal-record unknown, missing dependent copy or identity reset leaves `external_work_inventory_unavailable`; Base remains usable.

### 13.8 Erasure and retention tombstones

Publish monotonic text-free deletion notice, close affected mutation/replay admission, drain possible writes, cancel/fence jobs/controller calls and delete controlled current rows/blobs/spool/previous roots/candidates/backups/controller copies.

Before caller abandon or owner break-glass, terminalize and physically delete every controlled backup that marks the call dependent; otherwise erasure remains blocked/incomplete.

Valid caller uses `inference.release(abandon_for_erasure)`. Owner break-glass is external/manual authority and complete only after observed readback.

For controller call above `retain_after_seq`, content/sensitive facts delete immediately but bounded text-free membership tombstone remains until cut advancement. If even tombstone deletion required, retire every controlled backup pinning interval and advance cut first.

Deletion fence/controller tombstone/backup terminal marker is not physical proof. Previous root/backup containing erased scope must be deleted wholly or erasure remains incomplete. Provider-held/off-machine copies are external.

## 14. Control and observability

Controls: status/open/configure/pause/cancel/correct/withdraw/erase/backup/restore/rotate/retire/shutdown.

Status derives from actual facts:

- executable/root/DACL/selection generation;
- supervisor/daemon/channel/process/Store admission;
- schema/query health and socket owner;
- capture/stage/spool/replay;
- controller mutation barrier, call/auxiliary cut dispositions and release/retention fences;
- backup ID/fence/plan digest, restore lease, preparing/publication-unknown/published/aborted/retired state and physical cleanup debt;
- restored mirror reconciliation and rollback divergence;
- controller identity/token version/WriteId state/high-water/retain cut/inventory/tombstones;
- job/result/publication, caller cleanup and owner-action-required debt.

Do not equate request with effect, plan digest with manifest digest, backup scan with restore lease, Store mirror with installation authority, terminal marker with physical erasure, deletion fence/tombstone with physical erase, password change with session revocation, candidate verification with cutover or observed earliest row with guaranteed retention.

## 15. Implementation sequence

Write production code first. After each coherent increment run:

```text
cargo fmt --check
cargo clippy -p <changed-package> --lib --bins -- -D warnings
```

No broad campaign before connected product.

### Slice 0 — physical/Store preflight

Qualify exact Windows binaries/root leases/DACL, Job custody, inherited channel, relay pipe, Surreal 3.3.4/RocksDB `sync=every`, listener/peer ownership, bootstrap roles, query-only DTO client, migrations/conflicts/fsync unknowns, immutable/mutable files, WriteId-state primitive, backup-set owner/IDs/terminal markers/restore leases, replay barrier, typed backup/rollback/erasure, Store credential revocation and bounded shutdown.

### Slice 1 — useful persistence

```text
real event
→ committed or durably staged
→ replay if staged
→ restart
→ exact open
```

### Slice 2 — first host and useful Base

Claude relay, continuation, lexical retrieval, actual packet emission, notes/corrections/commitments and Base backup/rollback/erase. Controller inference disabled.

### Controller dependency

Controller issue #200, then V2 L0/L1 under its roadmap. Never extend V1.

### Inference P1a

Stable caller, controller-local install, rollback-safe WriteId state, controller-mutation owner, backup-set owner, admission/dependency/auxiliary cut classification, canonical plan digest, installation-scoped fence/self-contained abort-retire records, restore lease, client/call/receipt/private-copy schema, text runner, controlled-set release+retention, erased tombstones, owner break-glass, one episode result changing later context and backup/restore inventory.

### Inference P1b and later

Token rotation/stale-session fence/delayed retirement; then embeddings, project views, documents, Research and additional hosts independently. Advanced curation only after connected Base paths.

### Final qualification

After connected product: concurrency/restart/crash, Windows custody/IPC, Store durability, spool/backup/rollback/restore-lease/terminal-cleanup/erasure, host delivery, controller idempotency/cut dispositions/plan digest/release+retention fences/tombstones/history-gap/authority/rotation, provider uncertainty and load/retention campaigns.