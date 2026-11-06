# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.59 · 2026-11-06 · design for the greenfield rewrite.**

This document owns runtime, Store, physical maintenance and implementation order.
[Architecture](ARCHITECTURE.md) owns purpose/invariants; [Cognition](COGNITION.md) owns
algorithms; the [Inference contract](INFERENCE-CONTRACT.md) owns external calls.
[ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the sole active work ledger.

Build connected increments in §11. A specified mechanism is not implemented behavior.
Do not construct later scaffolding before its first writer and consumer exist.

## 0. External prerequisite

Memory Base does not depend on controller inference. The controller foundation already
exists in the inspected snapshot; the Memory principal, one-shot methods and required
readback do not. [Inference §0](INFERENCE-CONTRACT.md#0-authority-and-prerequisites)
owns the pinned source comparison and proposed extension.

Do not schedule controller L0/L1 or the old #200 Agent-binding model as Memory work.
Enable model-assisted jobs only after the scoped extension is implemented and admitted.
Missing inference never justifies a fallback to controller owner or Agent credentials.

## 1. Runtime and installation

### 1.1 Process family

```text
eliot supervisor     privileged installation/process owner
eliot daemon         Memory application + backup-set owner
eliot relay ...      transient host/CLI adapter
```

Supervisor owns executable/root identity, child handles, Store bootstrap credentials,
migrations, Store-user rotation, candidate process/root and final cutover. Daemon owns
Memory semantics, Editor access, replay/jobs, backup IDs/records/leases/cleanup,
retrieval/context and public control. Its controller-mutation owner is needed only
when the inference extension is enabled.

### 1.2 Installation layout

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  installation.toml
  controller-write-id.state       # only when inference is provisioned
  data\roots\<root-id>\{db,blobs}\
  spool\{pending,failed,tmp}\
  deletions\                     # typed erasure / influence-withdrawal notices
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

Initial profile is one fixed local NTFS/ReFS volume with protected user+LocalSystem
DACL. Reject network/removable roots, broad principals and reparse traversal. Data is
plaintext under OS/volume protection; Base claims no portable encrypted backup.
External-ID state and final backup authority remain outside rollback Store roots.

### 1.3 Installation selection

Under the installation mutex, supervisor owns selection generation, stable Memory
installation ID, current/previous roots, current/pending/previous Store credential
references, expected schema format/generation/digest and maintenance state. Inference
adds controller/client/token references without another installation registry.
The same record owns the notice checkpoint and active erasure admission fence in §10;
restoring a Store root never replaces or resets these outside-root facts.
A new cutover/rotation waits while an earlier previous generation remains unretired.

Parse configuration with the format's parser and validate the selected values. A missing
optional value may use its documented default; unreadable, malformed or unsupported
selected configuration is an explicit error, not a silent default. In particular, an
unavailable capture/disclosure policy cannot become permissive admission.

### 1.4 Startup

```text
validate installation + executable/root identities
→ start/adopt exact active Store
→ reconcile bootstrap/credentials
→ apply/verify migration bundle through Owner
→ create inherited channel and launch daemon
→ daemon admits process/listener/peer/Editor/schema/query path
→ reconcile implemented spool/backup/maintenance state
→ daemon ready
→ expose relay
```

No capture is committed before admission. Once backup exists, startup cleans/quarantines
pre-publication temps and reconstructs final fence/terminal authority before maintenance.
Once inference exists, reconcile external mutations and release/retention before new jobs.
An absent optional module is not an empty successful reconciliation handler.

## 2. Windows identity, custody and IPC

Before child resume, retain no-follow executable/root/ancestor handles, verify identity,
digest and DACL, deny required write/delete/rename sharing, launch suspended with exact
inherited handles, compare the actual child image, assign its Job and only then resume.

Supervisor owns process-family Job and candidate custody. Daemon/channel loss while a
candidate exists requires termination, reaping and discard before another daemon/cutover.

Relay uses one first-instance, remote-rejected, protected named pipe with mutual process
attestation and one bounded request/response per connection. Supervisor↔daemon uses two
inherited anonymous pipes with closed typed frames. Restore frames carry operation ID,
backup ID, plan/manifest digests, candidate root ID and selection generation, never
arbitrary path, SQL, argv, endpoint or secret.

These checks apply before the affected credential/effect boundary; the later broad
Windows campaign does not authorize an insecure development shortcut.

### 2.1 Liveness and bounded recovery

The existing supervisor observes daemon process exit and bounded health replies while
it owns that process. Process-alive, responsive, operation-progress and committed outcome
are separate facts. An IPC timeout is unresponsive/unknown, not proof that a mutation
failed or that a live job made progress. The transient relay is not the watchdog.

Use finite configured drain/stop/restart deadlines and a bounded recovery budget for
the same incident. Exhaustion leaves actionable status and owner-controlled recovery,
not an unbounded respawn loop. After restart, application readback resolves outstanding
operations before retry. Optional log/metric failure must not overwrite a known operation
result; diagnostics use existing status/log surfaces, not another monitoring service.

## 3. SurrealDB child and Store transport

Pin the exact SurrealDB 3.3.4 Windows artifact. Selected profile: external RocksDB
`sync=every`, loopback dynamic port, `--deny-all`, HTTP `rpc`, RPC `query`, system-only
arbitrary query, no defaults/identification headers and sanitized environment. Origin/
CORS is not WebSocket authentication. This remains an unqualified deployment target.

Before credentials, Windows TCP ownership must bind listener and established peer to
the retained Store process. Basic-authenticated WebSocket selects exact NS/DB.

Root bootstrap is short-lived. Reconcile unknown persistence using the same root
credential; restart without root environment; provision STRICT DB + database Owner/
Editor with PASSHASH; apply migration through Owner; close privileged sockets, restart
again and admit daemon Editor. Daemon never receives root/Owner credentials.

One Tokio task owns each query-only socket with one in-flight ID and continuous
control-frame handling. Timeout, cancellation ambiguity, wrong/late response or protocol
fault poisons it. Possible mutation send becomes `OUTCOME_UNKNOWN`; reconnect repeats
admission and exact application readback, not blind mutation replay.

JSON carries explicit bounded DTOs: strings, signed integers, booleans, finite floats,
integer times with precision, explicit optional states and immutable blob references.
Native Surreal IDs/special values stay inside Store statements. No generic `Value`,
`SELECT *`, broad CRUD, copied CBOR tags or user-supplied grammar crosses the application
boundary. Bind/decode absence explicitly as required by §4.4.

## 4. Migration 0001 and schema authority

Executable schema, wrapper and query bytes have one owner: the Store source package,
not a second copy under documentation. [Store ownership](store/README.md) links the
unmerged source candidate and the retired design inputs. Selecting that owner does not
accept its current bytes: [D4 findings](ANALYSIS-REGISTRY.md#store-reconciliation)
remain open where code, semantic representations or execution evidence are missing.

### 4.1 Bundle identity and catalog

The SHA-256 preimage contains:

```text
domain "eliot-memory-schema-bundle-v1"
schema_bundle_format = 1
runner_protocol = 1
exact transactional wrapper template
ordered UTF-8/LF DDL assets
expected-catalog template
```

Encode each segment as unsigned 64-bit big-endian byte length followed by its exact
bytes, in the listed order (including each asset name before its contents); format
numbers use canonical decimal ASCII. Bind the
format/generation/digest values after hashing; the digest never contains itself.
Migration assets contain DDL, not their own BEGIN/COMMIT or metadata wrapper. The runner
adds exactly one wrapper and overwrites three metadata params in that transaction.

Retained exact-tag evidence covers PARAM cancellation and cancelled index overwrite,
not the complete wrapper over Windows/RocksDB. Store bring-up executes the selected
bytes and bound metadata through its real client before admitting writes. Check every
statement status and exact metadata/catalog readback. Unknown commit is not rollback.
Full injected-failure coverage over every DDL boundary remains later qualification.

Admission uses plain `INFO FOR DB` / `INFO FOR TABLE`, not `STRUCTURE`. Parse owned maps,
sort category/name keys and compare server-canonical definitions. The expected catalog
is a version-pinned projection of the shipped migration, generated/checked against a
clean exact-engine run. A list of names or lines copied from DDL is not that projection.
Never derive the expected value from the active database being admitted, normalize away
unrecognized differences or write another SurrealQL canonicalizer. Compare the complete
owned set, not just names which happen to match. Credentials are admitted separately.

An unknown outcome is committed only after exact metadata+catalog readback. An exactly
empty fresh candidate may retry the same bundle; partial/mismatched state fails closed.
Discard a mismatched disposable candidate instead of hiding drift with `IF NOT EXISTS`.
An active-root mismatch requires an explicit named repair.

### 4.2 Exact 3.3.4 DDL grammar boundary

The retained design selects these exact-tag parser forms:

- `DEFINE TABLE <name> TYPE NORMAL SCHEMAFULL PERMISSIONS NONE`;
- `DEFINE FIELD <field> ON TABLE <table>`, with each selected clause once;
- `TYPE option<T>` and `TYPE array<T>`;
- canonical emitted order for `READONLY`, `DEFAULT`, `VALUE`, `ASSERT`, `COMMENT`
  and `PERMISSIONS`; `DEFAULT` and `VALUE` must not coexist;
- `FLEXIBLE` only immediately after an object-compatible TYPE;
- `DEFINE ANALYZER ... TOKENIZERS blank,class FILTERS lowercase`;
- separate UNIQUE and `FULLTEXT ANALYZER ... BM25` indexes;
- `DEFINE PARAM OVERWRITE $name VALUE <expression>`.

Parser acceptance and canonical rendering are separate from executing the complete
asset. Duplicate clauses, unsupported types and guessed syntax are defects, not reasons
for a runtime fallback. Verify pinned source when changing a selected form.

### 4.3 Application ID generation

Before mutation, the owning producer generates `<prefix>_<26 canonical Crockford Base32 chars>`.
Prefixes are `s` stream, `o` observation, `m` memory, `h` memory_history, `l` link and
`j` job. Draw 128 OS-random bits; encode fixed-width uppercase with first digit `0..7`.
Validate exact prefix/length/regex. These IDs contain no time ordering promise.

For capture, the trusted relay (or daemon for direct local input) generates the proposed
observation ID before the first send or spool publication; `command_id` is that same
`o_` ID. It does not need a running daemon to stage input. The daemon allocates other
object IDs when their owning operation first needs them. Retain IDs in the immutable
command/transaction plan before mutation; replay reuses them. A collision with another object is `ID_COLLISION`/integrity failure,
not silent regeneration after ownership transfer. Order by explicit time/sequence and
ID tie-break, not the random ID alone.

### 4.4 Derived unique keys and absence

For `H(domain, components...)`, encode domain and then each component as unsigned
64-bit big-endian UTF-8 byte length followed by exact bytes; hash the concatenation
with SHA-256 and encode lowercase hex. No Unicode normalization or separators are
implied. Store readable components separately and verify the digest in the writer:

```text
stream_unique_key  = H("stream-v1", project, workspace_id, source_kind, source_native_id)
address_unique_key = H("memory-address-v1", origin_project, kind, address_kind, address_key)
slot_key           = H("job-slot-v1", project, purpose, target_key, slot_kind)
```

The stream key includes every component of its immutable identity, including workspace.
Equal native source/event keys in different workspaces are distinct occurrences; a replay
in the same workspace still resolves the original stream. An adapter namespaces native
identifiers before freezing them; path, branch, text similarity and the currently active
session cannot supply a missing identity. A changed workspace creates a different stream,
not an in-place reassignment. This corrects the earlier draft key: update source bundle/
query identities together, without fallback to the workspace-less key.

Retained 3.3.4 source evidence says UNIQUE skips a tuple containing NONE or NULL. V3
writes only NONE/omission for absent conditional keys; NULL is not an alternative
representation. Express semantic unknown through a closed state where needed.

JSON binding does not by itself select Surreal NONE. Each optional DTO field has a
fixed presence/value mapping; its query produces native NONE for absence. Required
values and inconsistent presence/value tuples reject before send. Read projections
must expose enough information to distinguish an allowed absence from a malformed or
unexpected value. An ordinary nullable JSON field without that contract is insufficient.
Keep this mapping in the specific writer/decoder, not a generic Surreal value codec.

Concurrency through Eliot's client remains unqualified. A unique-index declaration
alone does not prove the complete operation or replace replay comparison.

### 4.5 Canonical projections and bounds

Preserve accepted raw bytes separately from structured projections. Projection JSON
uses UTF-8, lexicographically sorted object keys, no duplicate keys/insignificant
whitespace, finite numbers and no Surreal special values. Retain canonical strings;
decoding must reproduce their bytes/digest. Pin the actual serializer's representation
before publishing golden bytes, rather than assuming key sorting defines every number.

The source package owns concrete limits alongside its typed writer/readers. For each
operation distinguish raw field bytes, aggregate object bytes, encoded request bytes,
maximum projected row bytes, page rows and encoded response bytes. Bound array elements
as well as their count. Character limits and row counts are not byte budgets.

Before send, validate the exact serialized request including envelope and escaping.
Before unbounded buffering/decoding, enforce message and aggregate-response caps. Size
pages from the worst admitted projected row plus envelope/array overhead; `$hard_limit`
is a validated bound, not an unrestricted caller value. A smaller page must not skip a
row or advance its cursor before that row has actually been delivered.

Every admitted object must fit its exact-open, history and backup paths, including a
one-row page. Otherwise lower the admitted object bound or use an already supported
immutable blob/range path. Do not accept content that cannot later be read or backed up,
silently truncate an exact read, or increase every query limit to the largest object.
A transport cap is a final safety guard, not a paging implementation.

A response-size/decode failure after a possible mutation send is unknown until exact
readback. It is not proof of rejection and must not trigger a fresh mutation ID.
Hashing `QuerySpec` limits does not enforce any of these checks.

#### 4.5.1 First Base limits

These are selected initial engineering limits, not measured capacity. Define them once
in the owning Rust code and use them in the relay, Store writer/decoder and exact open.
`KiB = 1024 bytes`; all text sizes are UTF-8 bytes, not characters or tokens.

| Value | Initial maximum | Enforcement / oversize result |
|---|---:|---|
| One source/work/locator identifier | 256 bytes | Reject, never shorten identity. Generated IDs keep §4.3's stricter grammar. |
| Capture metadata, excluding body and search excerpt | 32 KiB canonical JSON; 64 relation descriptors | Bound every element and aggregate before custody. |
| Inline accepted text body / search excerpt | 16 KiB / 4 KiB | Excerpt is derived and labelled; raw body is never silently shortened. |
| Accepted blob body | 16 MiB | Only after spool/blob/range readback is implemented; until then reject above inline capacity. |
| Complete memory revision DTO | 64 KiB canonical JSON | Includes conditions, exceptions, scopes, cues and method body; history uses the same cap. |
| One Store or local IPC request/response | 1 MiB serialized, including envelope | Check before send and while receiving; possible mutation send still means unknown on failure. |
| Exact body range | 64 KiB decoded bytes | One identity-bound range; never buffer the entire blob to serve a range. |
| One spool `command.json` / total spool | 256 KiB / 256 MiB and 1,024 entries | Count pending, failed and temporary entries together under §7.5's publication lock; no eviction of accepted input. |
| Candidate page / emitted Base packet | 32 candidates / 32 KiB UTF-8 | Page byte cap and host inline limit ([Cognition §6.5.1](COGNITION.md#651-first-claude-output-boundary)) also apply; omissions carry gaps. |

A capture above inline capacity uses the existing durable spool and bounded blob reads,
not a 16 MiB IPC frame or a new upload service. Spool quota counts actual file bytes,
not only body bytes. Full quota rejects new custody, never discards old input; restored
backlog above a narrower quota drains without admitting more. These are admission limits,
not permission to skip a retained command during recovery. One-row exact/history reads must fit
with worst-case escaping; split candidate pages before the response cap. Configuration
may narrow admission/selection limits, but must not strand already accepted data: keep
build-bounded readers able to open it. An incompatible read cap rejects configuration.
Backup/job/inference aggregate limits are separate later-operation decisions; these
values neither enable those operations nor qualify their performance.

### 4.6 READONLY, row assertions and operation ownership

Retained exact-tag evidence: READONLY allows initial and same-value assignment, but
rejects later changed values. It does not generate identity or establish provenance.
IDs and creation facts remain producer-owned and command-retained under §4.3.

Field type coercion precedes ASSERT. Row context includes value/before/after/input;
use only expressions whose exact behavior is established. Regex validation is string
comparison such as `$value = /.../`, not `TYPE regex` for an ordinary string.

Selected row invariants below are requirements, not claims that the candidate assets
already enforce them. Qualify cross-field expressions before relying on them. Fixed
application transactions own replay, byte digests, sequence allocation, revision CAS
and set-wide concurrency; database assertions are defense in depth.

### 4.7 Tables, immutable fields and assertions

All six tables are `TYPE NORMAL SCHEMAFULL PERMISSIONS NONE`. Identity and creation
facts are READONLY with §4.6 semantics. String/array limits have absolute build bounds;
configuration may narrow them. Add exposed operations with their first writer/consumer,
not a generic CRUD method for every table.

| Table | Identity and immutable facts | Mutable/projection state and consumer |
|---|---|---|
| `stream` | stream_id, project, source_kind/native_id, workspace_id, stream_unique_key, created_at_ms | last_ingest_seq, updated_at_ms; capture allocation and ordered replay |
| `observation` | observation_id, stream/event/command/native-event identity, command_sha256, event_sha256, capture_format, ingest_seq, source bytes, occurrence/receipt/creation facts and captured work binding | Immutable accepted observation; exact open/replay. An operation-owned observation may also contain immutable operation_result_json (§7.4/7.6). |
| `memory` | memory_id, origin_project, created_at_ms | revision, kind, reuse_scope/reuse_projects, address tuple/key, content/search_text/exact_cues, disclosure, subject/aspect/perspective, conditions/exceptions, validity, support/exposure/influence, commitment/method state and updated_at_ms |
| `memory_history` | history_id, memory_id, revision, exact semantic snapshot, replaced_at_ms | Immutable prior revision; historical open and provenance |
| `link` | link_id, source/target kind+ID+optional revision, relation_kind, grounds_group, locator/qualification, created_at_ms | Immutable relation; bounded forward/reverse traversal |
| `job` | job_id, project, purpose/target, first_queued_at_ms, created_at_ms | Pending intent may coalesce; claim freezes input/method/limits/disclosure/profile; state, slot, due/attempt/claim, result/coverage/cleanup serve one finite consumer |

Observation projects workspace/task/actor/session, call/parent observation and resource/
version into explicit columns. Locator, binding, relations and capture-limit projections
remain canonical bounded JSON strings. Store body length/digest and exactly one location:

```text
body_storage = inline  <=> body_inline present AND blob_ref absent
body_storage = blob    <=> blob_ref present AND body_inline absent
```

The application verifies actual UTF-8/blob byte length and SHA-256. Memory validity
requires from <= until when both exist. Address key is present exactly when the complete
address tuple exists and its digest matches.

History stores `snapshot_json` as `{"format":1,"memory":{...}}`, using the same complete
semantic revision DTO as current open, plus outer history ID/memory ID/revision/replaced
time. Outer and inner identity/revision must agree. Include all scopes, target membership,
conditions, exceptions, disclosure, validity, cues and method/commitment states. Do not
maintain duplicate flattened history columns or fill missing fields from current state.
Historical open, backup and restore share this decoder. The source candidate's unversioned
string does not yet implement it. [§7.4.1](#741-command-body-and-revision-projection)
defines the complete Base revision fields and their command-to-result projection.

The following spellings are the selected fresh-V3 codecs, not aliases for the retired
pack or source candidate. Writers, queries, DTOs and history must agree with the admitted
schema bundle. Unknown discriminants/formats reject as unsupported; malformed tuples
reject as invalid/damaged, never as an ordinary semantic `unknown` or a permissive default.
Any needed old-data conversion is explicit and versioned, not a fallback reader.

#### 4.7.1 Occurrence time

Capture owns these immutable observation fields; exact open returns them together:

| Field | Encoding and meaning |
|---|---|
| `occurrence_source` | Optional bounded exact source time spelling, including supplied fractional digits/zone. Numeric input keeps its original token, not a float re-rendering; unit/time scale belongs to the captured source format. |
| `occurrence_precision` | `unknown`, `date`, `second`, `millisecond`, `submillisecond`, `native`: source resolution, not certainty. `native` means a source-defined clock/unit not represented by the other resolutions. |
| `occurrence_certainty` | `exact`, `approximate`, `unknown`: source assertion at that resolution, not independent proof of the event's time. |
| `occurrence_offset_seconds` | Optional signed offset supplied by the source; absence is not UTC and seconds are not rounded to minutes. |
| `occurrence_time_ms` | Optional signed-64 UTC Unix-millisecond projection, only when the admitted source format yields an unambiguous representable instant. Finer input is floored for this projection only; exact source precision remains above. |

A date-only value does not invent midnight; a timezone-free local time does not adopt
this machine's timezone. Native clocks and unparseable/out-of-range values retain the
permitted source and an explicit projection gap, not a fabricated instant. Without source
time, the optional fields are absent and precision/certainty are `unknown`. A timestamp
before the epoch is not clamped to zero. Parsing alone never upgrades certainty.
Source-format conversion is adapter code, not model inference. For example, an exact date and an approximate millisecond timestamp
remain different tuples. Receipt time and stream sequence still describe capture/order;
none of these fields makes a wall-clock change feed.

These fields date the captured occurrence. Dates mentioned inside its body remain
attributed content unless an admitted source format binds them to that occurrence.
Validity intervals do not supply event time or an obligation deadline.

#### 4.7.2 Reuse and guidance states

`origin_project` never changes. The revision writer owns `reuse_scope` and the bounded,
sorted, duplicate-free `reuse_projects` array of canonical project IDs:

| `reuse_scope` | Eligible destination projects before current authorization/disclosure checks |
|---|---|
| `origin` | Origin only; `reuse_projects` is empty. |
| `selected` | Origin plus the explicitly listed additional projects. The list is nonempty and excludes origin. No wildcard or missing-list default. |
| `owner_local` | Projects admitted by the current owner's configuration for this Memory installation; `reuse_projects` is empty. This grants neither remote disclosure nor another installation's access. |

Apply this eligibility inside every retrieval arm before its limit, then enforce current
caller authorization and disclosure at delivery. A caller-supplied project string is not
an authority. A shared method does not grant access to its private raw sources or permit
revealing them through a summary. Automatic generalization may select scope only within
owner-configured permission; it never broadens that permission. Unimplemented membership
writes/reads leave `selected` unavailable, not equivalent to `owner_local`.

Support, exposure and influence are independent revision fields:

| Field | Closed values and consumer meaning |
|---|---|
| `support_state` | `unknown`, `supported`, `disputed`, `refuted`. Records assessed support within its conditions and retained grounds; citations, retrieval count and model confidence do not set it by themselves. |
| `exposure_state` | `normal`, `reduced`, `hidden`. Controls automatic presentation priority/eligibility, not truth, withdrawal or permission for explicit inspection. |
| `influence_state` | `active`, `withdrawn`, `superseded`. Only active, non-hidden, non-refuted items may be offered as positive guidance, still subject to applicability and current notices. |

Conditional applicability is computed by Cognition §3, not encoded as influence.
Unknown/disputed advice stays explicitly qualified; refuted/superseded material may be
returned as an authorized counterexample or history, never silently as current advice.
Supersession records exact replacement revision links (multiple for a split); a missing
or deleted replacement does not reactivate its predecessor. Withdrawal follows §10 even
when support remains `supported`. Historical open preserves the old tuple plus current
suppression/authorization qualifications; it cannot bypass current policy.

#### 4.7.3 Job state and claim ownership

Use one scheduling state and a separate cognitive result/cleanup, not extra `unknown`
and `reconcile_required` lifecycle states:

| `job.state` | Slot and permitted work |
|---|---|
| `pending` | Pending slot; coalescible intent, no worker claim or external send. |
| `claimed` | Active slot; exact input/method/limits/disclosure/profile frozen atomically, one current worker claim. |
| `running` | Active slot and current claim; execute only that frozen work and retained external identity. |
| `waiting` | Active slot and frozen tuple remain; resume/reconcile the same work, not a new call. |
| `succeeded`, `failed`, `cancelled` | No slot or current claim. Retain outcome/coverage and any external cleanup debt; terminal scheduling is not controller-closed backup status. |

`waiting_reason` is present exactly for `waiting`: `capacity`, `dependency`, `policy`,
`external_pending` or `reconcile_required`. Missing call-admission/send/semantic-commit
outcome selects `waiting/reconcile_required`; it cannot become `failed` or `cancelled`
merely to free the slot. Known external work still in progress uses `external_pending`.
Claimed/running require an owner/expiry pair; in waiting that pair may be retained
or cleared when the worker relinquishes it. Request blob/length/digest are always all
present or all absent. Validate each tuple in the owning transaction.

Pending intent may coalesce in existing coverage/source references; `frozen_input_json`
is absent, not a fake completed snapshot. Claim resolves finite input and method revision
when the purpose uses a method, freezes the complete tuple and atomically moves pending
to active. New input goes to the one pending successor. After the first claim the job
never returns to pending or changes its frozen tuple. Cancellation before claim may
terminate without a frozen tuple; changed work requires a distinct job, not reused identity.

Reuse `attempt` as the monotonically increasing worker-claim generation (initially zero),
not a provider-attempt/usage count. Each new claim/reclaim increments it once; exact
claim replay does not. Exhaustion rejects. Worker-driven state changes/publication must
match the current installation selection generation, job ID, claim owner, attempt and
exact frozen tuple, and require an unexpired claim. An expired/old worker cannot publish
after recovery or cutover.
Reclaim can recover stored results or read the same controller call; it cannot replace
an unknown call ID. Lease expiry is not proof that a provider never received the request.

For cognitive jobs, `succeeded` requires completed frozen input and an accepted `changes`
or `no_change` result. A terminal partial result is `failed` with cognitive `partial`
and exact remaining coverage; useful accepted revisions remain available. Decode failure
or definite operational failure is failed with its own result kind. A known stale-revision
conflict may fail; an unknown commit must reconcile first. `cancelled` requires known
non-start or observed cancellation/terminal disposition, not a timeout. None authorizes
an automatic replacement model call. Cleanup uncertainty after a known semantic outcome
stays in cleanup facts; it does not change that outcome or rerun interpretation. The
inference contract separately governs release, retention and backup dependencies.

### 4.8 Indexes connected to readers

Unique identities:

```text
stream.stream_id; stream.stream_unique_key
observation.observation_id
observation(project,stream_id,event_key)
observation(project,command_id)            # NONE skipped
memory.memory_id; memory.address_unique_key
memory_history.history_id; memory_history(memory_id,revision)
link.link_id
job.job_id; job.slot_key                  # NONE skipped
```

Reader-backed continuation/relation/job indexes:

```text
observation(stream_id,ingest_seq,observation_id)
observation(project,workspace_id,task_id,receipt_time_ms,observation_id)
observation(project,workspace_id,actor_id,session_id,receipt_time_ms,observation_id)
memory(origin_project,kind,memory_id)
link(source_kind,source_id,source_revision,relation_kind,link_id)
link(target_kind,target_id,target_revision,relation_kind,link_id)
job(state,due_at_ms,first_queued_at_ms,job_id)
job(project,purpose,target_key,state,job_id)
```

Continuation uses these columns, not scan/parse of binding_json. Separate FULLTEXT BM25
indexes serve observation.search_excerpt and memory.search_text under the selected
`blank,class` / `lowercase` analyzer. Index syntax/source evidence does not prove every
reader's bounded execution; inspect actual plans/cardinality as each reader is connected.
Slice 2 connects an indexed `memory.exact_cues` lookup under §7's shared normalization.
Scope before its limit; hydrate only selected IDs. Do not scan bodies or load a whole
project to satisfy a small cue match. Admit its actual fixed query/index plan together.

## 5. Fixed query corpus

Every exposed operation uses checked-in fixed statements, bound data, explicit
projections and DTOs. A statement fragment is not an application operation. Capture,
revision and claim/settle need complete transactions with replay/result decoding, not
several independently committed primitives. Add no arbitrary SQL or dynamically loaded
migration/query directory.

For each selected operation, keep its writer/reader and bounds with the source:

| Operation | Required result and consumer |
|---|---|
| Capture/replay | Exact accepted identity, source digest and binding; relay/replayer may then acknowledge/remove pending input |
| Current/history/source open | Exact identity/revision, admitted scope and all relevant qualifications; host or cognition, with no fall-forward |
| Continuation/retrieval | Bounded candidates plus exact handles/revisions and coverage; qualified context builder, not raw SQL output |
| Revision | History/current/grounds and original operation result published together; replay returns that result even after later revisions |
| Research submit/read | Persisted question and original job identity; bounded status/answer references for the requesting agent, through §7.6 |
| Job claim/settle | Exact claim/frozen tuple and durable outcome; one worker and later semantic consumer |
| Backup/catalog | Complete bounded typed pages under §8 cut, or exact owned schema facts; never a public broad-read API |

A constant `RETURN { ok: true }` establishes only a response path. Do not advertise
Store readiness from it. The first real capture/readback establishes the needed write
path; a create/read/delete transaction with no retained witness is not restart or
lost-commit proof. No new probe ledger is needed.

### 5.1 Exact full-text shape

Scored search uses a numbered match reference. Syntax illustration only:

```text
SELECT observation_id, search::score(0) AS score, search_excerpt
FROM observation
WHERE project = $project AND search_excerpt @0@ $query
ORDER BY score DESC, observation_id ASC
LIMIT $hard_limit;
```

Memory uses memory_id/search_text. Plain `@@` is unscored only. A zero score remains a
match. Retained exact tests establish numbered scores and representative index iteration,
not the performance or access policy of Eliot's entire corpus.

Apply admitted project/reuse/disclosure eligibility before arm limits. Exact IDs and a
private Editor connection are not authorization for a public caller. Internal unscoped
lookups and backup queries must not become user APIs. Before any context/open result
crosses its caller boundary, enforce its scope and disclosure, and resolve all required
qualifications for the exact revision. Missing condition/exception/validity fields are
not empty conditions. Hydrate from that exact revision or report a gap; never quietly
substitute a later current row. Cross-project reuse stays unavailable until its actual
membership writer and scoped reader exist.

BM25 order changes with corpus statistics. Return one bounded top-K snapshot per call,
never a cross-call page cursor. A later expansion is a new snapshot.

### 5.2 Bound-data and plan qualification

Bound variables always carry ordinary data. Parser acceptance does not prove bound
`DEFINE PARAM` execution over the real client. Verify exact selected metadata statements
and resulting plain INFO before admitting that bundle.

Stable-key cursors bind query version, scope, identity/revision and options. A walk over
receipt time plus random ID is not a durable change feed: later inserts may sort before
its cursor. State the covered cut and concurrent-write limitations; complete replay uses
retained stream sequence/cut semantics, not an unproved wall-clock high-water. Backup
pages are complete only under the coherent cut in §8.

For each connected reader retain in PR/check evidence the query digest, representative
input, result decoder and EXPLAIN. Optimizer choice is version/dataset evidence, not a
truth contract. Correctness cannot depend on index use; latency/admission budgets may
reject an unbounded scan. The complete plan/load matrix follows the connected product.

## 6. Transactions and durable files

SurrealDB 3.3.4 `SELECT ... FOR UPDATE` requires exact native record-ID targets; a table,
range or subquery target is rejected. See the pinned
[negative cases](https://github.com/surrealdb/surrealdb/blob/1ac2b1dba7cd177621a4cf5d507caebeb2414395/language-tests/tests/language/statements/select/for_update.surql)
and [literal/parameter cases](https://github.com/surrealdb/surrealdb/blob/1ac2b1dba7cd177621a4cf5d507caebeb2414395/language-tests/tests/language/statements/select/for_update_locked_read.surql).
`FROM stream WHERE ... FOR UPDATE` and `FROM job WHERE ... FOR UPDATE` are not valid
owner-row locking queries. A LIMIT or unique WHERE predicate does not change the target.

Within one fixed transaction, resolve the internal record ID, verify exact cardinality
and application identity, then register/recheck the exact record read when needed and
perform the conditional update. Keep native IDs in server-side variables, not public
DTOs or caller-chosen grammar. Revalidate a selected job's state, due time and slot in
the claim transaction; selection alone grants no ownership. An absent identity and
set-wide cardinality require UNIQUE/slot constraints, not a supposed predicate lock.

Treat conflicts as transaction outcomes, not a promise that another worker blocks on
a row. Verify the exact backend behavior before concurrent admission. Stream sequence,
revision CAS, claimed input and their dependent writes must share the same transaction.
Check its complete result, including commit. Separate query calls do not retain a lock
or transaction across the socket merely because one task owns that socket.

After a definite retryable conflict, retry the entire immutable transaction, never
its remaining statements. Unknown transport/shutdown/fsync reconciles first; an error
under `sync=every` is not rollback proof. The purely Store-owned idempotent capture/revision
completion in §7.2/§7.4 may repeat the same command after exact lookup; this does not authorize
repeating an external effect or replacing its identity. No partially executed multi-statement sequence may
report committed capture. Nondeterministic UPSERT is not idempotency. Publish blobs
before row transactions; never perform provider or filesystem effects inside them.

Immutable files use same-directory CREATE_NEW temp, complete write, file flush,
no-replace write-through rename, parent flush and exact no-follow readback. Mutable
installation/external-ID state uses expected-generation replacement and old/new/unknown
reconciliation. These are selected durability requirements, not qualified Windows facts.

## 7. Core operations and host

Base uses no model. Capture/open/revision retain their transactions below; relays cannot
forge operation results or mutate tables. Apply §7.1 before payload-bearing files/IPC.
The agent-facing adapters accept intentions and fill internal IDs, binding, time and
honest defaults; they do not expose storage forms:

| Agent input | Existing owner |
|---|---|
| Context for work/question/artifact | [Cognition §6](COGNITION.md#6-retrieval-and-context): bounded selection and readable answer. |
| Open source/revision | §7.3: exact detail on demand. |
| Remember text, optional sources | Capture/direct note; ambiguity remains attributed input, never a capture failure or silent goal amendment. |
| Correct item / update goal, plan or progress | §7.4: resolve target/expected revision, hydrate and construct a complete replacement. Preserve qualifiers; changed assertions do not inherit old support. |
| Ask/follow up/read/cancel Dreamer | §7.6: existing finite jobs and answer/status. |

### Shared cues and automatic output

One pure versioned normalizer supplies both prepared `memory.exact_cues` and event lookup:
§4.4's `H("cue-v1", kind, source-qualified canonical identity)`.

| Cue | Canonical identity from the admitted source decoder |
|---|---|
| Artifact | Repository/workspace + source-relative path, `/` separators and authoritative spelling; alternatively the source's stable resource ID. Resolve aliases against the source, not raw absolute-path strings. |
| Symbol | Canonical artifact + resolved container/name or stable symbol ID. |
| Error | Tool/rule namespace + documented stable code; unknown prose remains lexical evidence. |

No lossy lowercasing, substring equivalence or model-invented identity. Unresolved identity
remains searchable/openable; no exact-match claim. Keep artifact version/hash separate
from the stable key: first find past experience, then qualify it against the current version.
Use existing fields/indexes, not another cue service/table.

[Claude mapping](COGNITION.md#651-first-claude-output-boundary) is verified per installed
host. Event → accepted capture/spool → addressed/cue reads → qualified baseline/update →
source recheck → output. Reuse one Store client, batch independent fixed reads, hydrate
selected revisions once, then revalidate live pointers/notices under the delivery fence.
No model/embedding/Research or external-search call, corpus scan, graph rebuild or background join.

The relay's absolute deadline covers capture, reads, checks and output. Initial targets:
configurable **250 ms automatic wait**, **warm p95 ≤100 ms** from event receipt through local
response; unmeasured engineering goals. Report relay/cold Store startup separately;
explicit requests may have a larger budget. No useful update or deadline before writing
returns successful empty output; partial write is unknown, never a second response.

[Presentation/cache](COGNITION.md#621-proactive-attention-without-repeated-context) and
[handoff](COGNITION.md#65-handoff) own concurrency and failure semantics. Capture already
staged/committed remains so; unavailable optional retrieval omits only its contribution.
Packet/handoff retention uses best-effort daemon capture with current policy checks,
without a required storage round trip, receipt queue or later dispatch of old output.

### 7.1 Capture policy before durable custody

The relay applies the owner's selected capture exclusions and byte limits before the
first payload-bearing spool/temp file, blob, diagnostic or outbound IPC. Daemon capture
and every import adapter enforce the same admission rule; daemon unavailability is not
permission to stage otherwise excluded input. Policy load/validation failure rejects
that capture without echoing the excluded payload. No model decides this admission.

Retain exact **accepted** bytes with the applied policy revision and capture limitations.
A permitted redacted/partial representation records that transformation and cannot be
called the complete original. Metadata, locators and error messages must not retain
excluded content by another route. Never persist an unredacted shadow merely for replay.
This is configured exclusion, not a promise to detect every possible secret.

The admitted command remains immutable. Replay under a stricter current policy may
withhold it and require cleanup; it must not rewrite bytes under the same identity or
re-introduce excluded/deleted input. Recheck current disclosure and suppression before
context emission, external send and semantic publication, including delayed job results.
Previously emitted bytes cannot be recalled by a later policy change; report that limit.

### 7.2 Capture command, commit and replay

`CaptureCommandV1` is the shared input for the relay, durable spool and owning Store
operation. Use this one typed envelope, not separate similar definitions in each module.
Top-level fields are exactly those below; `?` means omitted when absent, never JSON null.
Reject extra/duplicate fields and unsupported formats before payload custody. Raw host
JSON belongs in the accepted body, not additional command fields. §4.5.1 limits apply
to decoded fields **and** the final encoded envelope.

| Field | Input and owner |
|---|---|
| `format` | Integer 1. No permissive old-format reader. |
| `observation_id`, `command_id` | The same producer-retained `o_` ID (§4.3), frozen before first publication/send. |
| `stream` | Exactly `{project,workspace_id,source_kind,source_native_id}`; nonempty canonical strings. Project/workspace come from admitted installation/host binding, not a prompt or cwd guess. Compute the complete key in §4.4. |
| `kind` | Nonempty kind selected by the admitted adapter/operation. Ordinary event capture rejects §7.5's reserved kinds even when supplied in otherwise valid JSON. |
| `native_event_key?` | Exact native occurrence key only when the admitted source contract establishes its stability. Absence selects command-derived identity; do not synthesize a native key from text or time. |
| `occurrence` | Exactly §4.7.1's fields: required `occurrence_precision`/`occurrence_certainty`; optional `occurrence_source`, `occurrence_offset_seconds`, `occurrence_time_ms`. Preserve the source token/offset and distinguish an absent projection from zero. |
| `receipt_time_ms` | Signed-64 Unix milliseconds assigned at first receipt, not regenerated on replay or used to infer source order. |
| `binding` | Object with only optional `task_id`, `actor_id`, `session_id`, `call_id`, `parent_observation_id`, `resource_id`, `resource_version`. IDs are source-qualified by the adapter; parent uses the `o_` grammar. No duplicated project/workspace here. Missing task falls back only to an actual actor/session pair. Incomplete association remains captured with a gap, not assigned to similar work. Resource version requires resource ID. |
| `locator_json?` | Canonical JSON object string containing attributed source locator data. Opaque to the capture writer: not an executable path, access grant or substitute for exact observation identity. Apply capture policy and metadata limits to it. |
| `disclosure` | `local_only` or `external_allowed`, selected within current owner policy. Source text cannot broaden permission; replay/emission recheck current policy. |
| `capture_limit_json` | Canonical string encoding exactly `{format:1,policy_revision,source_completeness,transformation,reasons}` as specified below. Required even for unchanged complete input. |
| `relations_json` | Canonical string encoding the bounded source-relation array below; use `[]` for none. It is not a generic link mutation or a support/permission assertion. |
| `search_excerpt` | Bounded derived text from the accepted body; empty is allowed when no admitted text projection exists. Never excerpt an excluded original or replace the accepted body with this search field. |
| `body` | Exactly `{body_storage:"inline",body_inline,body_length,body_sha256}` or `{body_storage:"blob",blob_ref,body_length,body_sha256}`. Inline is a UTF-8 string; blob bytes use §7.5 body.bin. Length is a nonnegative signed-64 byte count; SHA-256 is lowercase hex. Verify actual bytes, not only tuple consistency. Blob key is `sha256:` plus that digest; never a filesystem path. |

In capture limits, `policy_revision` is the bounded nonempty identity of the applied
owner policy, not permission from the source. `source_completeness` is `complete`,
`partial` or `unknown` relative to this source occurrence, not the whole conversation.
`transformation` is `none`, `redacted` or `representation`. `reasons` is a sorted unique
subset of `source_partial`, `source_completeness_unknown`, `policy_redaction`,
`derived_representation`, exactly matching those non-default states. Missing evidence
of completeness is unknown; accepting all received bytes alone does not establish it.
No excluded original may survive in metadata, a search excerpt or a replay shadow (§7.1).

A source relation has exactly `relation_kind`, `target_kind`, `target_id`, optional
`target_revision` and optional canonical-object string `qualification_json`. Observation
targets use `o_` and no revision; memory targets use `m_` and a positive exact revision.
Sort unique descriptors by canonical UTF-8 bytes before freezing; at most 64 fit within
the aggregate metadata cap. Ordinary event capture admits only `parent`, `reply_to`,
`result_of`, `derived_from`; operation-owned records admit only their owner's declared
relations. Unknown native relations remain attributed raw input, not invented active
edges. These are source assertions: a missing target remains an unresolved qualification,
not a fabricated source, independent support or permission to disclose it. The operation
assigns link IDs and source identity; input cannot choose another row as the link source.

Project nested fields into the existing explicit Store columns. Derive `binding_json`
from `{project,workspace_id,...binding}` and require exact agreement on decode. Store
`capture_format=format`, the two computed input digests and the complete capture-limit/
relation/locator strings. Observation `created_at_ms` uses its frozen first receipt time.
`stream_id`, `ingest_seq`, link IDs and operation results are owning-transaction outputs,
not accepted caller fields. A reserved record still validates its owning body/result
contract (§7.4, §7.6 or Cognition §6.5); this envelope grants no generic mutation authority.
All command metadata is integer-only. Absence, empty string, zero and unknown are not
interchangeable; §4.4 owns the fixed optional-field mapping to Store NONE.

The admitted host adapter selects occurrence identity, not the body hash:

- With a documented stable native event key, `event_key = H("native-event-v1", kind,
  native_event_key)`. It is scoped by the resolved stream and project.
- Without one, `event_key = H("capture-event-v1", command_id)`. Retrying the saved command
  is idempotent; a new callback is a new occurrence. Do not promise host-redelivery
  deduplication without a stable key or substitute text/time similarity.

Store `command_sha256 = H("capture-command-v1", canonical command)` and
`event_sha256 = H("capture-event-content-v1", canonical semantic projection)`.
For the latter, copy the decoded command, omit only `observation_id`, `command_id` and
`receipt_time_ms`, and replace `body` with `{body_length,body_sha256}`; then canonicalize.
Everything else, including workspace, occurrence, binding, policy/limitations and source
relations, remains bound. Hashes and derived event/stream keys are not command members.
A native redelivery may change its proposed ID/receipt time or equivalent body storage,
not its semantic fields. A changed admitted representation/policy is an identity conflict,
not permission to overwrite the original occurrence. Equal bytes alone never deduplicate.
The selected root/spool pathname is not a command field; copying a blob into an admitted
root changes neither digest. A blob key does not authorize another project's bytes.

Production ingress first publishes the immutable command under §7.5, **before any
possible Store send**, then verifies blob publication when needed. Spooling only after
a timeout leaves a crash window in which the command identity and accepted input vanish.
Slice 0 may exercise direct capture with a disposable caller retaining the command;
it is not the production host durability path. Execute **one** fixed Store transaction,
not `StreamInsert`, `StreamAdvance` and `ObservationInsert` as separate calls:

1. Resolve the stream by its unique key; compare its complete tuple. Resolve any matches
   for `(project, command_id)` and `(project, stream_id, event_key)` before allocating
   a sequence. Multiple matches pointing to different observations are an integrity error.
2. A command match requires the original command digest; a native-event-only match requires
   the event digest and semantic tuple. Return the original observation/sequence/result.
   A mismatch is `identity_conflict`, not overwrite, a new ID or a second observation.
3. Only a new occurrence creates the stream if absent, rechecks its exact record (§6),
   checked-increments `last_ingest_seq` (first is 1), and inserts the observation and
   supported source relations. All writes commit together. Signed-64 exhaustion rejects;
   replay allocates nothing. For implemented Dreamer preparation, coalesce eligible primary
   input into its target job in this transaction (§7.6); replay adds nothing. Do not queue
   unimplemented jobs.
4. Check every statement and commit result, then decode the accepted observation ID,
   stream ID, sequence, original receipt time and hashes. Native redelivery returns the
   stored observation ID, not the caller's new proposed ID. Matching operation readback
   resolves commit; exact open separately reports current content availability (§7.3).
   A later forbidden, erased or damaged body is not proof of rollback or permission to
   repeat the mutation with a fresh identity.

A duplicate-key/conflict result is not success: look up and compare the same immutable
command/event. If a possible send lost its outcome, poison the socket and read back
through a newly admitted connection. A matching committed row resolves the operation;
absence alone does not prove rollback while the prior transaction may still commit.
When lookup is authoritatively empty, the same admitted capture command may enter the
idempotent transaction again: its unique identities must converge even if the earlier
transaction finishes concurrently. This is completion under the same identity, not proof
of rollback. Lookup failure stays unknown. Never mint replacement IDs or perform provider
I/O on this retry. An unreferenced pre-published blob is cleanup debt, not committed capture.

| Private result | Relay / replay action |
|---|---|
| `committed` | Return the recorded canonical identity. Remove a pending command only after matching readback. |
| `rejected` | Return a definite validation/policy/identity error without echoing private input; do not retry changed input under this ID. |
| `stage_required` | No Store claim. Keep the already-published production entry pending; a direct development caller has no custody guarantee until §7.5 succeeds. |
| `unknown` | Preserve the same command for reconciliation; neither report committed nor infer rejection. |

`stage_required` is not an acknowledgement. **Staged** means verified durable custody,
not proof that Store has or has not committed. The relay returns its command ID/digest,
not a fabricated committed-source handle. A lost daemon reply can leave a staged entry
with unknown Store outcome. §7.5 owns publication, replay and removal; never recapture
with a new receipt time, ID or binding.

### 7.3 Exact open and byte ranges

Use closed selectors: observation ID; memory ID plus `current`; or memory ID plus an
exact positive revision. Resolve `current` once and return that resolved revision.
An explicit revision reads that version from current/history, never the newest substitute.
Resolve and project within one consistent fixed read: a revision moving from current to
history cannot become `missing` because two independent lookups straddled its replacement.
Qualify that read's snapshot semantics on the selected engine; do not infer them from a
socket or substitute the latest revision. Empty selectors reject.

Content-bearing `complete`/`range` responses include requested/resolved identity,
representation/revision, `body_length`, `body_sha256`, capture limitations and qualifications.
For an observation, body means its exact accepted bytes. For a memory revision, body means
the UTF-8 bytes of `content`; also return `revision_sha256`, SHA-256 of the complete
canonical semantic revision DTO (§4.7), without a history wrapper or trailing LF.
Current notice/access qualifications are outside those immutable bytes and hashes.
Cognition's memory source hash uses `revision_sha256`, not the content-only body hash.
Equal text with different conditions therefore does not identify the same semantic value.

Other dispositions are `missing`, `forbidden`, `erased`, `damaged` or `unsupported`;
return the requested selector and a bounded reason, not partial content, source hashes,
lengths or private qualifications. Authorize the selector before disclosing existence.
Unavailable Store/transport or notice authority is an operation error, not `missing`
or an empty restriction set. Recheck current scope/suppression at the delivery boundary.

Body ranges use unsigned byte offset and positive length within §4.5.1, with checked
arithmetic. Return exact bytes as base64, range length/hash, total length and next offset
(or absent at end). A text preview is separate; a UTF-8 code point split at a byte
boundary is not damaged source. Offset at EOF yields an empty complete range; beyond EOF
rejects. Continuation uses the resolved exact ID/revision, never `current` again, and
repeats body length/hash plus `revision_sha256` for memory. Changed identity, length or
hash rejects, not a new search. Metadata remains typed and size-bounded.
The full digest identifies the immutable object; a range digest verifies only the returned
range, not the whole object. Verify full length/hash when publishing or opening the full
body, and retain protected no-follow custody during range reads. Integrity failure reports
damaged, never a claimed exact body.

### 7.4 Direct revision and lost replies

`create` and `revise(expected_revision)` are separate closed inputs. Create publishes
revision 1 only when absent; revise requires the exact current positive revision and
publishes its checked successor. The authorized revision entrypoint freezes one target,
full replacement, attributed cause and fresh `o_` command ID before durable custody.
Before the first Store send, publish the complete command through §7.5; a process-local
variable does not survive a lost reply followed by restart. Use command-derived event
identity, never native-event deduplication of the attributed cause. No model is needed.

Use an operation-owned `observation` with reserved kind `memory_change` and that command
ID, not a new mutation table. Its body is the canonical `MemoryChangeV1` below;
`operation_result_json = {"format":1,"memory_id":...,"revision":...}` records the
original result. Wrap the body in `CaptureCommandV1` with `native_event_key` absent;
allocate its stream sequence and retain both input digests under §7.2 in the same
revision transaction. The result is output, not part of either input digest. Ordinary
relay capture cannot write this kind/result. All copies obey §7.1; do not modify an
already captured observation or silently redact a frozen semantic update into another edit.

#### 7.4.1 Command body and revision projection

`MemoryChangeV1` has exactly the fields below. Use §4.5 canonical JSON without a trailing
LF; `?` means omitted, never null. Reject unknown members, duplicate keys, wrong types
and unsupported formats. This is the body of the existing operation, not another RPC,
queue or generic patch language. One command changes one memory item.

| Field | Meaning and validation |
|---|---|
| `format` | Integer 1. |
| `mode` | `create` or `revise`. |
| `memory_id` | Retained `m_` identity. The revision owner allocates it for create before staging; revise names the existing item. No address-based upsert or automatic replacement ID. |
| `expected_revision?` | Absent for create; positive signed-64 for revise, below its maximum so the successor is representable. It is never `current`, zero or a caller-selected new revision. |
| `replacement` | Complete mutable value in the table below, not a partial field patch. Required empty arrays stay explicit. Omitting an optional field removes it in the new revision; it never means inherit from current. |
| `cause` | Nonempty attributed explanation, at most 4 KiB UTF-8. The authenticated operation/binding identifies the requester; this text does not grant authority or prove the claim true. |
| `grounds` | Complete intended grounds for the new revision. Each entry is `{relation_kind,target,grounds_group?}`; kind is `supports`, `refutes` or `derived_from`. Target is an exact persisted source selector below. A group is a nonempty identifier, permitted only for supports; §3 of Cognition owns conjunctive/alternative interpretation. |
| `replacements` | Exact persisted memory selectors replacing this item. Nonempty exactly when replacement influence is `superseded`; otherwise empty. This operation does not mutate those targets or implement an atomic multi-item split. |

A source selector is `{kind:"observation",id,sha256}` or
`{kind:"memory",id,revision,sha256}`, with §7.3's body/revision hash respectively.
No `current`, unresolved alias, path or future/pending result is accepted. Before a new
publication, resolve and authorize each selector and verify the exact bytes/revision;
missing, damaged, erased or unreadable required grounds reject that publication rather
than being dropped. Resolve a matching original operation result before revalidating
now-unavailable grounds: later source loss cannot authorize repeating a committed edit.

The source lists together allow at most 64 entries and 32 KiB canonical JSON. Sort each
list by canonical UTF-8 bytes and reject duplicate descriptors. Empty grounds means no
asserted support, not verified truth. The command's own observation is attribution, not
independent support for itself. A referenced private source does not permit broadening
the replacement's disclosure or reuse. Authorization applies to the existing item's
origin project, requested fields and sources, not merely to a readable reused copy.
For revise, the admitted command's stream.project must equal that immutable origin;
access through another project's reuse scope grants neither write authority nor rebinding.

`replacement` has precisely these fields. All sizes are UTF-8 bytes; §4.5.1's 64 KiB
limit applies to the **complete resulting revision**, including generated fields.
The additional collection limits here are initial engineering choices, not measurements.

| Fields | Base value |
|---|---|
| `kind` | `note`, `claim`, `explanation`, `prediction`, `commitment`, `project_view` or `method`. An unimplemented kind-specific consumer remains unavailable; storing its data does not execute it. |
| `content` | Exact nonempty text; never a caller path or deferred body-fetch request. It includes the instruction body when the item is a method. |
| `search_text`, `exact_cues` | Search text at most 4 KiB; sorted unique array of at most 64 nonempty cues, each at most 256 bytes. Derive both from permitted replacement data, not blind inheritance; typed cues use §7's shared normalizer. Publish with the same revision (§7.4.2). Neither is hidden content or an authority. |
| `reuse_scope`, `reuse_projects` | §4.7.2 values; at most 64 project identifiers, each within §4.5.1. Required even when the list is empty. |
| `disclosure` | `local_only` or `external_allowed`, within current owner policy. An explicit value does not itself confer permission. |
| `conditions_json`, `exceptions_json` | Each is a canonical JSON string encoding an array of at most 32 nonempty qualification strings, each at most 2 KiB; `[]` is explicitly none. Base preserves these as data, not an executable expression language. A material unevaluated condition/exception keeps applicability conditional_or_unknown; matching text is not evaluation. |
| `support_state`, `exposure_state`, `influence_state` | Exactly §4.7.2's three independent vocabularies; all required. No confidence/rank-to-support conversion or default active state on decode. |
| `address_kind?`, `address_key?` | Both present or both absent; nonempty identifiers within §4.5.1. The writer derives address_unique_key under §4.4. A conflicting unique address rejects; it never updates a different item. |
| `subject?`, `aspect?`, `perspective?` | Nonempty bounded identifiers, at most 256 bytes each. Absence is distinct from an empty label. |
| `valid_from_ms?`, `valid_until_ms?` | Signed-64 UTC milliseconds; when both exist require from <= until. An absent endpoint is unbounded, not zero or the machine's current time. |
| `commitment_state?` | Exactly for kind commitment: `open`, `resolved` or `cancelled`. Resolution is an attributed explicit update, not inferred from a reminder, due date or display. |
| `method_role?`, `processing_purpose?` | Role is present exactly for kind method: `advice` or `processing`. Purpose is a nonempty bounded identifier present exactly for processing. A processing consumer must validate its purpose-specific instruction/input/result contract before use; method text cannot alter execution permissions or budgets. |

No memory ID, origin, revision counter, timestamp, derived key or current notice overlay
is accepted inside replacement. The writer constructs `MemoryRevisionV1` by adding
`memory_id`, `origin_project`, `revision`, `created_at_ms`, `updated_at_ms` and, only for
an addressed item, `address_unique_key` to those exact fields. Create takes origin from
the admitted command's stream.project, revision 1 and creation/update time from its frozen
receipt time. Revise preserves origin/creation from the compared current row, increments
the expected revision and uses the command's frozen receipt time for updated_at_ms and
the history row's replaced_at_ms. Wall-clock order is not revision order; replay never
regenerates timestamps.

Current open, history's inner memory object, revision_sha256 and typed backup all use
this same complete projection. History stores the **previous** projection without
recomputing its search text, filling omissions or applying current notices to its hash.
Grounds/replacement links are immutable and keyed to the exact new revision; old links
remain historical, never inherited as the new revision's grounds. Their complete set is
separate from the row hash. Publishing different grounds requires a new revision, not
late amendment of a published revision's declared support. Preserve source lineage for
the operation observation too, so §10 erasure reaches its derived command body.

The complete MemoryChangeV1 body has a 128 KiB build cap. A body above the 16 KiB inline
limit uses §7.5's existing body.bin/blob custody; until that path exists reject it before
staging, not after changing memory. Validate the complete serialized transaction and
history/read/backup projections against §4.5, including nested JSON escaping. Check the
old history snapshot as well as the proposed replacement. No silent shortening, partial
history, larger IPC frame or second correction store is allowed.

#### 7.4.2 Atomic publication and replay result

Before a new mutation, the daemon validates policy/notices and immutable bodies under
the existing affected-publication admission, covering the target and selected sources.
Keep that admission and source custody through commit/reconciliation; erasure, policy
replacement or cutover cannot pass between validation and publication. This preflight
is not filesystem/host/controller I/O inside a database transaction.

In one fixed Store transaction: look up operation identity/digest **before** revision CAS;
return an already committed matching result without rewriting anything. Otherwise
recheck exact target/source row identities and expected revision, insert the previous
full snapshot for revise, then publish current, exact grounds/replacement links and the
operation observation/result together. Invalid rows, scope, history or links abort all
these writes. No provider/filesystem effects or delayed source-validation job belong in
that transaction. Only implemented reverse-impact work may be coalesced; no empty
successful job is created.

A new explicit revise with the same semantic value still creates its one successor and
attributed cause; exact command replay does not. A stale new command conflicts even if
its replacement happens to equal current. Never silently rebase expected_revision, merge
fields from a newer revision, remove an exception to fit, or retry changed bytes under
the original operation ID. The owner must submit a new explicit edit after resolving
the conflict. Auxiliary history/link identities remain owned by §4.3's retained plan,
not arbitrary caller-selected mutations or a second command ledger.

Revision publication participates in the same affected-delivery fence as §10 notices:
close new emissions using that memory and drain in-flight emission before acquiring
the shared Store client or a request lane needed by final context validation. Then
commit/reconcile the revision before reopening. This orders an acknowledged correction against context
output; checking a revision only during packing leaves a race. No spool mutex is held
across this Store/host work. Unknown publication keeps affected guidance withheld, not
all unrelated capture stopped. The fence is an existing operation boundary, not a new
queue or coordinator.

Same command/digest returns its original result even after later revisions. Open that
exact resulting revision through §7.3; never replace it with current. The operation
result and the open disposition are separate: later denial, damage or an unavailable
read cannot turn a confirmed revision into a failed write or trigger another revision.
A changed command is identity conflict; a new command with stale expected revision is
revision conflict. Possible commit with a lost reply is unknown until lookup by operation
identity, not a second revision. The same-input reconciliation rule in §7.2 applies only
to this complete idempotent transaction, with original-result lookup before CAS. A pending
proposal is not a committed revision on which another edit may base its expected revision.
Erasure may suppress the old result, but must not make the operation eligible to run again
(§10). Withdrawal/reactivation still use the outside-root notice authority in §10; writing
influence_state=active cannot clear a current withdrawal. Post-cut commands follow §8.2.

Connect this in Slice 2 with the existing revision/open/context owners: create; revise
with an omitted optional field and explicit empty grounds; two edits against the same
revision; lost reply followed by a later revision and replay of the original ID; changed
exceptions with unchanged text; an oversized inline command; and unavailable/erased
required grounds. Inspect the original result, both exact revisions and later context.
These are acceptance cases for that path, not a new test framework or runtime evidence.

### 7.5 Durable ingress and replay

Use the existing installation spool and one daemon replay owner, not a broker, second
database or job framework. Its durable unit is one self-contained directory:

```text
spool/tmp/<random>/                  private construction or retired cleanup
spool/pending/<command_id>/          published custody; eligible for reconciliation
spool/failed/<command_id>/           withheld custody; no automatic replay
  command.json
  body.bin?                         exact raw bytes, present only for blob storage
```

`command.json` is canonical UTF-8 JSON with exactly `format=1`, `installation_id`,
`command_sha256`, `event_sha256` and the complete `command: CaptureCommandV1` (§7.2).
The hashes bind that command, not this enclosing file. Directory name and command ID
must agree; installation ID must match the selected installation, not a restored root.
Unknown format, duplicate JSON keys, extra members, malformed size/hash tuples, reparse
paths and missing/extra files reject. Inline bytes remain in the command; blob bytes
are only in `body.bin`, whose exact length/hash must match. No path from input is opened.
The same envelope serves authorized operation-owned `memory_change`, `context_packet`,
`context_handoff` and `research_request` records. Ordinary event capture rejects these reserved kinds;
only the owning operation admits them. A kind or installation ID in a file
is not authority. Apply the same closed dispatch before first send and during replay:
revision uses §7.4's complete transaction; research submission uses §7.6; context provenance
only stores its validated facts under Cognition §6.5; ordinary capture uses §7.2. No generic insert path may bypass
an operation owner. Replaying packet/handoff storage never emits context or starts a job.

**Publish before send.** All relay publishers and daemon cleanup use the same protected
installation-scoped OS mutex, available even while the daemon is down. Validate policy,
complete command and bounds before writing. Under that mutex: recheck current notices;
compare any existing pending/failed entry for this ID; count bounded spool usage; create the private temp;
write and flush every member; verify bytes; flush the directory; no-replace rename into
pending on the same volume; flush both parents and read back the final entry (§6).
Hold it through this bounded local publication, not across Store/IPC/network I/O. A
finite lock wait/write failure is not staged. Without qualified durable directory
publication on the selected platform, staging is unavailable, not best-effort success.
An ambiguous rename/flush keeps the same
ID for custody reconciliation; it is not a definite rejection or permission to overwrite.
A matching pending entry reuses its custody; a conflicting entry fails integrity. A
failed entry stays withheld rather than being silently requeued. No age-based eviction,
truncation, fresh-ID retry or separate quota-reservation ledger is permitted.

Only after durable publication may the relay notify the daemon with command ID/digest
and await a bounded result. Notification is a wake-up hint: startup and periodic bounded
scans also discover pending entries. The daemon's one replay owner performs the operation;
a relay notification does not start a competing mutation path. No notification, timeout
or relay death removes an entry. The caller may report staged when custody is known even
if canonical outcome is still unknown; it reports committed only from matching readback.

For each pending entry, retain no-follow read custody, validate its envelope/body and
current scope/policy/notices, then resolve existing operation identity before mutation.
Publish a required blob into the active root before its transaction, without changing
the command. Native-event replay compares §7.2's semantic identity even when the stored
observation ID differs from the proposed ID. Revision replay uses §7.4's original result.
No unknown effect becomes a new command, and no independent filesystem or provider effect
is placed inside a Store retry. Retirement must use the same admitted root/selection
generation as readback; after cutover leave pending for §8.2's restore reconciliation.

| Observed state | Replay / recovery action |
|---|---|
| Matching committed result and durable referenced body | Under the publication mutex, rename pending into a private unique temp, flush parents, then delete it. A crash during cleanup leaves only harmless retired cleanup or an idempotently replayable pending entry, not a half-deleted pending command. |
| Store unavailable, uncertain result or maintenance pause | Keep pending unchanged. Apply finite per-attempt deadlines and capped backoff; no busy loop or drop after a retry count. Stop new attempts on shutdown and preserve unresolved entries. |
| Definite invalid input, identity conflict, damaged or unsupported entry | Withhold in failed under the same mutex; expose ID and bounded reason through existing status, never the private body. Quarantine describes custody, not proof that an earlier possible send failed. An unavailable diagnostic after restart stays unknown, not invented rejection. |
| Current policy or deletion barrier forbids input | Do not publish/replay it. Withhold and perform the owning cleanup under §10; erasure debt cannot be cleared by moving bytes into failed. |
| Abandoned temp after obtaining the publication mutex | No active publisher can own it. Remove or quarantine within quota; temp contents are never an accepted pending operation to replay. |

Start with one in-flight replay. Retry eligibility uses monotonic deadlines (initial
1 second, exponential backoff capped at 30 seconds), not source wall-clock time. These
are engineering defaults, not latency guarantees. Visit eligible entries in bounded
rounds; one failing entry must not starve unrelated entries. Do not add persisted attempt
rows: pending files retain custody and a restart may rebuild transient scheduling.
Ingest sequence records actual Store commit order, not guaranteed host occurrence order;
retain explicit source sequence/parent facts when available. Semantic dependencies must
be checked by the owning operation, not guessed from file names or mtime.

Do not reclaim blobs by age or one empty reference query: pending/failed commands,
in-flight transactions and retained backup/previous roots may still need them. Keep
unreferenced blobs as visible cleanup debt until the maintenance owner can establish
that none of these consumers holds them. A full spool rejects new ingress, not readback,
replay or cleanup of already accepted entries. Before enabling this path, observe the
same disposable command across a lost notification, restart, lost commit reply, quota
rejection and interrupted retirement; each reports custody and canonical outcome
separately. This is a connected Slice 1 exit, not a new test programme or a runtime PASS.

### 7.6 Dreamer and agent research

This operation connects Cognition §8 to the existing capture/job/revision owners. It is
part of the inference increment, not a model call hidden inside Base retrieval.

| Caller | Operation and result |
|---|---|
| New primary outcome/correction/task handoff | Coalesce exact source references for `purpose=prepare`, target=current work/view, in the owning capture/revision transaction. Context packet/handoff receipts are not primary input. One active job plus one pending successor. |
| Agent asks Dreamer | Submit a captured question with `purpose=research`, target=that request observation ID; return the original request/job identity and scheduling state. Distinct questions have distinct targets, even on the same work. |
| Agent reads / follows up | Read bounded job status and accepted answer revision references; ordinary exact open supplies content. A follow-up submits another question with an exact `reply_to`; no transcript/session store. |
| Agent cancels | Existing job cancellation/readback; timeout or a new question is not proof of cancellation. |

For the submitted turn, the daemon's owning adapter builds a reserved `research_request`
CaptureCommandV1 with `native_event_key` absent. Its canonical body is `ResearchRequestV1` with exactly `format=1`,
`job_id`, nonempty `question`, `sources` (exact persisted selectors from §7.4.1), and
optional `reply_to` (one such selector). The owner allocates and retains the job ID before
staging; it is not a caller-supplied mutation authority. Existing body/selector limits and
blob custody apply. Resolve/authorize all selectors; `reply_to` must identify a prior research
request or answer. Question text and earlier answers are context, not verified premises.
Work binding comes from the admitted envelope, not inferred question text.
The caller's finite wait is invocation behavior, not part of the persisted question.

Use one fixed transaction: resolve the immutable command first; on a new request, capture
it and its source relations, insert the pending job, and retain
`operation_result_json={format:1,job_id}` together. Replay returns that original job even
after completion. No model call occurs in the transaction. Unsupported capability returns
unavailable, never a successful placeholder job. Generic event replay cannot submit research.

Claim freezes the selected question, relevant prior answer, current view/method revisions,
new evidence, limits and profile under §4.7.3. Both prepare and research use the same finite
processor and §7.4 revision writer. A research answer is a scoped view/explanation with
exact grounds; the job's result/coverage names accepted output revisions and remaining
input. Dependent writes use confirmed exact revisions; independent partial output stays usable.
External acquisition uses its configured owner; capture new evidence before a new claim.

In each job-owned revision transaction, the publisher also creates one internal
`prepared_by` link from the exact output memory revision to its job ID, under the same
claim and replay identity. A `no_change` settlement links only the exact revision it
evaluated, never a newer current revision. This is a P1a-only `target_kind=job` relation,
outside public source selectors, grounds and ordinary candidate traversal; only the
publisher creates it. The existing source/revision link index supplies bounded exact job
lookup. The link proves association; the accepted result and coverage determine §8.2's
preparation state. Partial/missing coverage cannot become `covered` from a link alone.

Serve explicit requests ahead of speculative preparation within existing worker capacity;
never hold capture/context on a research join. Read status or accepted partial output within
the requested deadline and return the job handle if still running. Status polling does no
inference. Read pending work by its existing indexed target/slot; a missing/truncated
preparation relation yields unknown, not a scan of past jobs. Source implementation supplies
the internal relation, closed job-purpose/result codecs and aggregate limits before
exposing this handler; the architecture adds no table, worker fleet or research engine.

## 8. Backup-set owner and lifecycle

The daemon's existing backup-set owner controls publication, leases and cleanup;
supervisor controls the disposable candidate and root selection. This section selects
one **Base logical snapshot**: fixed typed table exports plus immutable files, not a
copy of a live RocksDB directory, executable SQL dump or new backup service. Base needs
no controller. A cut containing external-call history/debt needs the separate admitted
inference encoding under [Inference §8–10](INFERENCE-CONTRACT.md#8-memory-backup-interaction);
turning inference off does not make that history disappear or qualify it as Base.

When inference is enabled, keep the existing order: close/drain controller mutation →
backup-set transition → classify external IDs/high-water → capture local cut → publish
and read back fence → leave transition → reopen controller mutation. Do not replace its
dependency/retention rules with Base's empty external inventory.

For Base, serialize backup against restore/cutover, rotation, config replacement, notice
publication and erasure. Drain **known outcomes**, not merely client tasks; an unresolved
possible Store commit prevents a coherent cut. Pause canonical mutation/replay and blob
cleanup until export and final manifest readback finish. Reads may continue. Under the
spool mutex take an exact inventory of both pending and failed entries, then release it.
Keep those entries pinned against moves/removal while copying; new post-cut staging may
continue within quota. Never hold that mutex across Store/host/supervisor I/O. Unresolved
notice publication or an active erasure fence prevents starting the cut. A new restrictive
control request may cancel the bounded backup, not modify its cut midway.

Freeze root/selection, schema, non-secret configuration and notice head with that cut.
Record independent counts for all six tables while writes remain stopped. Page each by
its canonical application ID, with explicit projections and §4.5 byte bounds. Copy every
required referenced blob and every inventoried spool member. Temporary/unpublished spool
entries are not admitted input; failed entries remain withheld, not silently omitted or
made replayable. A damaged selected member makes the backup incomplete.

Allocate `backup_id = b_` plus 32 lowercase hex OS-random digits, and an ordinary `o_`
operation ID before publication. Retry resolves that operation in existing backup records
before creating another set; conflicting bindings reject. Freeze the plan in §8.3.
In a private same-parent temp,
write/flush/read back `fence.json`, flush the directory, then no-replace rename the whole
directory to the backup ID, flush parent and reopen no-follow. The first visible final
directory therefore contains its fence. Resolve a collision before publication with a
new backup ID/plan; after possible publication reconcile that exact ID, never overwrite.
Pre-publication temps are cleanup debt, not restorable sets. An uncertain final publication
pins conservatively; any final fence or terminal consumes its backup ID permanently.

Write each part using §6's immutable publication. Compare the actual inventory against
the frozen table counts, complete required-body closure, spool list, notice chain and
config identity; matching hashes of only the files that happen to exist are insufficient.
Publish `manifest.json` last, no-replace, and verify its bytes plus fence binding before
reporting `published`. Missing/extra/duplicate members cannot yield a complete manifest.

A restart does not resume a paged export against a newly mutable Store. First reconcile
the same fence/manifest. If the manifest was durably published, keep that result; otherwise
stop/reap the old writer, establish final-manifest absence and abort the incomplete set.
Uncertain absence remains unresolved. An aborted operation keeps its result; a fresh
export needs a new operation ID, cut and backup ID, not newer rows appended to old parts.
Cancellation or capacity/I/O failure follows this same rule; reopen application admission only after the owning cut has been safely released.

Abort requires exact fence, no valid manifest, no writer/restore lease and known cleanup
disposition. Retire requires exact fence+manifest, no abort and no restore lease. Publish
and read back the self-contained terminal **before** deleting its fence/manifest/parts;
retain the terminal permanently. No restored Store mirror may create or remove authority.

```text
valid standalone retire                  retired/non-restorable
valid standalone abort                   aborted-before-publish
fence + matching manifest, no terminal    published; validate contents before restore
fence without valid manifest/terminal     preparing/publication_unknown
malformed/both/mismatch/ambiguity          unresolved; fail closed
```

### 8.1 Bounded restore lease

Validate §8.3/8.4 and the exact admitted schema bundle before allocating a candidate.
An unsupported schema requires an explicit conversion, not a permissive restore decoder.
A request names a known backup ID, not an arbitrary archive/path. Existing maintenance
state retains its restore operation ID, backup/plan/manifest hashes and expected selection
generation before candidate work. Retry reads that state instead of starting another
restore. Keep a logical lease bound to backup/plan/manifest and no-follow
final-directory, parts-directory, fence and manifest handles with FILE_SHARE_READ only.
Reject reparse points, non-regular members and path aliases; hashes alone do not authorize
opening an outside file. The logical owner blocks terminalization and cleanup.

In manifest path order open **one** part with write/delete sharing denied, verify its
exact path/identity/length/hash, copy and verify it into the isolated candidate, then close
it. Keep only the bounded ancestor handles needed for that member, not every part handle.
Stream raw bodies; bound JSONL lines before decoding. Check the entire inventory, six
counts, unique application identities, history envelopes, blob closure and notice chain.
Native record IDs are reconstructed internally by fixed bound restore statements; never
execute SQL or deserialize arbitrary Store values supplied by a backup.

Apply the shipped schema through supervisor Owner admission, restore typed application
fields through the owning client, then read back ordered application DTOs and required
bodies against the export. Exclude native database IDs from comparison, not replay IDs,
sequence counters, revision/history, optional-state distinctions or operation results.
A partial import is a disposable candidate, never an active root or successful restore.

Current §10 notices are checked before copying affected content and again before
admission. A known erasure covering a required member prevents normal restore of that
set; do not import it and call a silently filtered database an exact restore. Withdrawal
qualifications do not alter historical bytes. Backup configuration is comparison/recovery
material, not permission to loosen current capture/disclosure policy or replace secrets.

After complete candidate readback, retain the lease through final fence/manifest/terminal,
current-notice and installation-generation checks. Supervisor alone performs expected-
generation cutover and independently validates candidate identity. Lost cutover reply
reconciles selected root/generation; it does not repeat import or select a second candidate.
Daemon/channel loss kills/reaps/discards an unselected candidate; supervisor loss is
contained by its Job. Once selection may have changed, read it back before deleting any
root. Preserve the previous root until its separate retirement. A scan is not a lease.

### 8.2 Exact rollback and external work

Never restore into the live root or merge later Store rows into restored cognition.
Healthy current Store first gets a safety backup; failure to make it stops normal restore.
Explicit disaster mode records unavailable current inventory, not an invented safety copy.
Reconcile cut spool by exact command/file identity, not age: restore pending as pending
and failed as failed. A matching current entry is reused; a conflicting one is quarantined,
never overwritten. Apply present notices/policy before enabling replay. Post-cut capture
may be admitted as source input; post-cut `memory_change` stays withheld. Read its original
result from the previous root when available; otherwise outcome is unknown. Adoption
requires an explicit new operation against the restored current revision.

Notice/checkpoint continuity, installation credentials/root selection, external-ID state
and the live backup catalogue are **not restored from this snapshot**. Backup notice bytes
may repair missing files only if they reconstruct the retained checkpoint exactly (§10.3).
A backup's active influence flag cannot cancel a later withdrawal. Missing continuity is
not an empty notice set: isolate recovery and report the gap. Enabling recovery requires
an explicit owner decision acknowledging unknown history; it cannot bypass known notices
or claim that prior withdrawals/deletions were preserved.

Before new job claims, reconcile future-timeline/unmatched Store maintenance mirrors;
they cannot create terminal records, clear pins or replay stale effects. With inference
enabled, use its exact in-cut closed/dependent classification and fixed post-cut inventory.
History gap or a missing external copy disables inference, not an otherwise valid Base;
a broken local cut/lease/root invariant independently blocks its affected operation.

### 8.3 Base format and complete inventory

All control JSON is canonical §4.5 UTF-8 plus one LF, closed fields, integer-only metadata,
no duplicate keys or unknown formats. Hash exact file bytes with SHA-256 lowercase hex.
`plan_sha256` hashes canonical plan JSON plus LF, without containing itself. No compression,
encryption, multipart archive framing or second serialization framework is selected.

| Record | Exact fields / validation |
|---|---|
| Plan (embedded in fence) | `format=1`, `profile="base"`, `backup_id`, `operation_id`, `installation_id`, `source_root_id`, `selection_generation`, `schema={bundle_format,generation,sha256}`, `tables`, `spool`, `notice_head`, `config_sha256`. IDs/generations use existing admitted installation/schema types; root IDs are identities, not paths. |
| `tables` | Six `{name,row_count}` entries in lexical name order: job, link, memory, memory_history, observation, stream. Counts are nonnegative signed-64, measured under the cut; a zero table is explicit, never omitted. |
| `spool` | Sorted unique `{command_id,state,command_file_sha256}` entries, with state `pending` or `failed`. Hash is of exact command.json bytes, not its inner command hash. The command determines whether exact body.bin is required. |
| `notice_head` | Exact `{sequence,sha256}` from current installation authority. Zero/null only for a truly empty initialized chain; include every notice through this head. |
| `fence.json` | `{format:1,plan,plan_sha256}`. Backup directory, embedded backup ID and computed plan hash agree. No manifest/part hash appears in the plan. |
| `manifest.json` | `{format:1,backup_id,plan_sha256,fence_sha256,parts,total_bytes}`. `parts` is a path-sorted unique list of `{path,bytes,sha256}` for every payload file; `total_bytes` is their checked sum. Metadata files do not list/hash themselves. |
| `abort.json` / `retire.json` | `{format:1,kind,backup_id,operation_id,backup_operation_id,plan_sha256,fence_sha256,reason,cleanup}`; retire also requires `manifest_sha256`. Kind agrees with filename. Abort reasons: `cancelled`, `capacity`, `source_unavailable`, `integrity_failure`, `deadline`, `io_failure`; retire: `owner_request`, `retention`, `erasure`. Cleanup is `pending` or `complete` **as observed at publication**, not a mutable progress field. Later completion requires actual readback. |

A terminal retains `backup_operation_id = plan.operation_id` even after the fence is
removed; its own `operation_id` identifies the abort/retire request. Retry finds the
original set, including a retired set, never a replacement. Same terminal-operation
ID/bytes is replay; changed bytes conflict. A terminal does not claim cleanup that has
not been observed.

Only the following payload paths are allowed. Page numbers are eight decimal digits,
start at 00000001 and are contiguous per table/notice stream. Member paths use `/`, exact
case and the displayed grammar; reject absolute paths, `..`, alternate separators/streams,
empty components, links and unlisted files. Do not sanitize an invalid path into a valid one.

| Payload | Bytes and required completeness |
|---|---|
| `parts/tables/<table>/<page>.jsonl` | One canonical `{format:1,table,row}` plus LF per line, no blank lines. `row` is the full schema-versioned application backup DTO owned with its writer/reader, not SELECT *, native IDs or an exact-open subset missing replay fields. Preserve canonical nested JSON strings verbatim. Global per-table application-ID order is strict; no duplicate IDs across pages. Decode the same history/absence representations as §4.7. A zero-count table has no pages; every other count must match exported and restored rows. |
| `parts/blobs/<64-lowercase-hex>.bin` | Exact raw body bytes for each required canonical blob reference; filename digest, actual bytes and referencing length/hash agree. Include the full required set, not unreferenced cleanup debris. Identical body storage does not merge occurrence identities or permissions. |
| `parts/spool/<pending-or-failed>/<command_id>/command.json` and optional `body.bin` | Exact §7.5 members for every plan entry. No tmp directory or extra member. Each entry's state, file hash, command/body tuple and installation binding must agree; a failed entry is not a gap the exporter may discard. |
| `parts/notices/<page>.jsonl` | Concatenate exact NoticeV1 file bytes, preserving each LF, in sequence order through notice_head. Reconstructed per-line hashes must form the full chain and end at that head. These bytes are recovery material, not replacement authority. No pages for a zero head. |
| `parts/config.toml` | One non-secret snapshot from the admitted configuration owner's explicit export allowlist, parsed by that same owner; its exact hash equals config_sha256. No credential values, bootstrap environment, installation selection, external-ID allocator or inferred secret filtering. An unsupported required setting makes export unsupported, not silently omitted. Restore compares settings; it never automatically applies older permissions. |

No installation.toml, live database files, logs, executables, previous roots or nested
backups belong in parts. Build the required-body set from full table DTOs and selected
spool entries, then compare it with actual members. Explicitly absent source states stay
absent; the exporter cannot invent absence to excuse a missing required body. Dangling
historical evidence with an already recorded qualification is not fabricated content.
Missing, duplicate, truncated or surplus parts reject restore before cutover, even when
every listed part's individual hash is correct. Hashes detect integrity, not authority
against an attacker able to replace the entire untrusted set and its metadata.

### 8.4 Bounds, outcomes and connected check

Initial limits are selected engineering defaults, not measured performance. Enforce them
while enumerating/writing and **before** allocation/parsing during restore; never truncate
a count, inventory or file to fit. Source field/query limits in §4.5 still apply.

| Boundary | Build limit |
|---|---:|
| Fence / manifest / one terminal | 1 MiB / 8 MiB / 16 KiB |
| Payload files / all six tables' rows | 16,384 / 1,000,000 |
| One payload part / one JSONL row including LF | 16 MiB / 1 MiB |
| Entire set, including metadata and temporary copies | 4 GiB |
| Spool / notices / configuration snapshot | §4.5.1 / §10.1 / 256 KiB |
| One active part and body-copy buffer | One member / 64 KiB; a bounded JSONL row may need its own decoder buffer |

A 16 MiB file is streamed, not sent through the 1 MiB Store/IPC frame. Shorten query pages
by encoded bytes as well as rows. Before each write reserve/check remaining actual-byte
budget, including temporary replacement overhead; a full disk yields incomplete/unknown,
not a shortened complete backup. Finite operation/I/O deadlines apply; on expiry release
or reconcile owned resources before resuming work. Never extend a cut indefinitely.

Narrower configuration limits new exports, not the ability to parse an already accepted
set within build limits. An insufficient restore resource budget returns capacity failure
and leaves the backup and active root intact. A larger legitimate installation may exceed
this profile: report that limit rather than making a lossy backup or silently raising caps.

Report creation `published | rejected | aborted | unknown` separately from current set
lifecycle and cleanup debt. Rejected requires known non-publication; aborted requires
terminal readback. Published requires final manifest readback, not a restore exercise. Restore is successful
only after candidate checks, actual selection readback and admitted daemon/open on that
selection. Candidate validated, cutover unknown, and selected-but-startup-unavailable are
distinct failure/status facts; none permits deleting the previous root or guessing success.

Connect this with Slice 3's actual exporter/importer: empty table; last page/blob missing;
extra part; interrupted manifest publication; post-cut spool arrival; current deletion
notice; and lost cutover reply. Observe exact open after restart of the selected candidate.
No separate backup database, general serializer, job family or new test/report framework
is required; source execution and Windows durability remain unqualified until observed.

## 9. Controller V2 adapter

Implement only the [proposed inference boundary](INFERENCE-CONTRACT.md), after its
controller-side owner resolves the listed choices and supplies the handlers. Use the
existing private controller transport, new scoped principal and current commands/writes
namespace. No assumed write_receipts table, routing key, mutation-floor service or Agent
binding machinery belongs here.

Memory persists IDs before send, validates exact reply identity, copies/verifies result,
decodes it and publishes a revision consumed later. It exposes disabled/unavailable
rather than pretending the extension exists. The inference contract owns method names,
auxiliary readback, credential transitions, release and retention; do not duplicate them
as a second adapter protocol here.

## 10. Erasure, rotation and observability

Withdrawal stops guidance; erasure also denies content access and removes controlled
copies. Both use the existing `deletions/` directory outside rollback roots. The daemon
owns these operations; the supervisor owns the continuity checkpoint in existing
`installation.toml`. No new table, queue, service or general mutation ledger is needed.
Stored support/exposure/influence remain revision facts. Current notices overlay them;
do not create a cosmetic revision or a second Store flag merely to mirror a notice.
Exact open returns applicable withdrawal qualifications; erasure returns no target bytes.

### 10.1 Notice command and durable encoding

Only the authorized control operation may withdraw, reactivate or erase. Captured text,
a model proposal, a packet marker or an ID in a file grants no such authority. Freeze
one command before possible publication; retries retain its operation ID and exact
canonical bytes. Check an existing operation ID **before** looking up a possibly erased
target: same command returns its recorded notice, changed command is identity conflict.

`NoticeCommandV1` has exactly `format=1`, `installation_id`, `operation_id` (the existing
`o_` grammar), `kind`, `target`, `reason`, and the conditional fields below. This command
ID does not require a placeholder observation. `kind` is `withdraw`, `reactivate` or
`erase`; `reason` is `owner_request`, `policy_change` or `correction`, not free text or
permission. Use §4.5 canonical JSON, integer-only metadata and §4.3 identities.

| Field | Closed representation / rule |
|---|---|
| `target` | `{kind:"memory",id,scope:"all_revisions"}`; `{kind:"memory",id,scope:"revision",revision}` with a positive revision; or `{kind:"observation",id}` for erase only. No wildcard, path, query, implicit current revision or similarity match. Resolve `current` before freezing a revision-specific command. |
| `reactivates` | Only and always for reactivate: `{operation_id,notice_sha256}` naming one committed withdrawal with exactly the same target/scope. Resolve and check both values; no "clear everything" operation. |
| `cause` | Only for daemon-generated erasure barriers on affected observations: `{operation_id,notice_sha256}` naming the root erase, which has no cause. This links cleanup to its authorized request; it does not broaden that request's content scope. |
| `replay_keys` | Present exactly with `cause`: `{command,event}`. Derive `command=H("erased-command-v1",project,command_id)` and `event=H("erased-event-v1",project,stream_unique_key,event_key)` under §4.4, from verified captured identities. Both are lowercase SHA-256 hex; no body, excerpt, raw native key or mutable physical path is retained. |

The durable `NoticeV1` is exactly `{format:1,sequence,previous_sha256,command}`.
Sequence is a checked positive signed-64 integer; first is 1. Previous hash is null only
for sequence 1, otherwise the SHA-256 of the complete preceding file. Write canonical
UTF-8 plus one LF to `deletions/<20-digit-zero-padded-sequence>.json`; the filename must
match the record. Hash exact file bytes, not a re-rendering or a field containing itself.
Reject unknown/extra members, duplicate keys, invalid tuples and conflicting IDs.

Initial build bounds are 16 KiB per file, 65,536 final files and 64 MiB aggregate final
bytes; they are engineering limits, not measured capacity. Validate before allocation,
publication and startup parsing. Stream the bounded directory; do not read a caller path.
Capacity exhaustion leaves a named incomplete operation, never eviction of a barrier.
Narrower configuration cannot make already accepted notices unreadable. A publisher keeps at most one
16 KiB temporary file and reconciles abandoned temps before the next publication. They
are cleanup debt, not notices; §6 owns their durability/custody.

### 10.2 Effective scope and reactivation

A withdrawal remains effective unless a committed reactivation names **that exact**
withdrawal ID/hash. Replay of that reactivation cannot cancel a later withdrawal.
Overlapping revision-specific and all-revision withdrawals are independent: cancelling
one leaves every other applicable withdrawal in force. All-revision scope includes
later revisions of the same memory ID. Changing an address or making a new revision
cannot bypass it; do not recycle erased identities.

Erasure is monotonic and dominates every withdrawal/reactivation, regardless of file
order. Revision erasure denies that revision and its attributable copies, not unrelated
revisions; all-revision erasure also forbids future writes under that memory ID. A new
revision transaction checks its exact proposed revision and all-revision barriers before
commit. Observation erasure also rejects either replay-key match, even when native-event
redelivery proposes another observation ID or changed bytes. Do not compare only the
body hash, or require a command digest match to enforce an erasure barrier.

If a revision erase removes current (including after restore), do not promote a surviving
historical version or reset the revision counter. Unaffected history remains exactly
openable. Any memory erasure notice forbids a fresh create under that ID; revise requires
a remaining non-erased current row. Resuming an item with no current row requires an
explicitly authorized new memory ID, not an automatic replacement or replay.

Reactivation removes a suppression fact; it does not make old content true, change its
stored influence/support, restore erased bytes, publish a new revision or replay a job.
Normal current scope, applicability and revision checks still apply. Invalid/missing
reactivation references never mean permission. A matching but already reactivated
withdrawal is a harmless recorded no-op, not a request to cancel newer withdrawals.

### 10.3 Publication, continuity and recovery

The existing installation record retains `notice_head={sequence,sha256}`; only a newly
initialized installation has `{0,null}`. Supervisor alone advances it using the existing
expected-generation installation writer. It never comes from a restored Store or backup.
One daemon notice operation is outstanding at a time; cutover waits for it to reconcile.

Close the affected publication/delivery admission and drain in-flight emission before
publishing a restrictive notice. Under §7.5's spool publication mutex, validate the checked
head and any tail, construct/flush/verify the next immutable file, no-replace publish it,
flush the parent and read it back. Release that mutex **before** Store, host or supervisor
IPC. A file/rename/flush ambiguity is unknown, not rejection or a fresh operation ID.

The daemon asks the supervisor to advance the checkpoint with expected installation
selection generation, expected old head and exact next file hash/sequence. Supervisor
validates the retained file and predecessor under installation mutex → spool mutex,
then durably replaces/readbacks `installation.toml`. No caller path or notice content
is accepted on this privileged request. Lost reply reconciles that same file/head; a
mismatched generation/head is not overwritten. No caller holds the spool mutex while
waiting for the installation owner. Relays never publish notices or update checkpoints.

A valid single uncheckpointed successor conservatively applies withdrawal/erasure but
**not reactivation**. Do not start another notice, destructive cleanup or report committed
notice publication until checkpoint readback. Startup adopts only that exact successor
through the same owner protocol; absence of its reply is not reason to regenerate it.
Missing predecessors, checkpoint/hash mismatch, multiple tails or malformed records
make notice continuity unavailable. Do not skip a bad file and accept the remaining set.
Consumers fail closed at the affected boundary; if scope cannot be established, withhold
capture/replay/content delivery installation-wide while exposing non-content status.

Startup and restore verify the chain through the current checkpoint before admitting
content. Owned backup copies may repair missing files only when exact bytes reconstruct
that retained checkpoint; never select a lower head or overwrite current notices with
a backup set. Loss of the outside-root checkpoint itself is unknown continuity under
§8.2, not a fresh empty installation. This detects missing/corrupt records relative to
retained authority, not hostile replacement of the entire installation or secure erasure.

### 10.4 Physical erasure and observable result

Base serializes one erase through existing maintenance state. Before publishing its root
notice, durably retain that operation and close new ingress while exact replay identities
are being collected; relays obey this fence even when the daemon is down. Unreadable
maintenance state is not open admission. Drain/reconcile possible Store and host effects,
then walk affected source/derived copies in bounded pages. No late commit may recreate a
row already cleared. Unknown effects retain suppression and explicit cleanup debt.

Before deleting an affected observation or its only identity-bearing copy, publish and
checkpoint its cause-linked erase barrier with both replay keys. Reuse an already checked
matching barrier for the same root/target/keys after restart. Missing identity coverage
blocks deletion of that last metadata and remains incomplete; do not invent keys from
text or treat an empty lookup as proof. This applies to operation-owned correction,
packet/handoff and other derived observations too. Their lineage identifies controlled
copies, not permission to delete independent equal-text occurrences. If a whole retained
root/backup must be discarded, first account for its affected occurrence identities.

Once the complete affected identity set is barrier-covered and in-flight writes are
resolved, the maintenance owner may reopen unrelated ingress; targeted admission remains
closed permanently. Clear the persisted broad fence only after this readback. Retry or
restart resumes this erase, never reactivates it. Insufficient capacity leaves the fence
and the remaining work visible; do not throw away keys or split an unverified set into
claimed-complete batches. Content cleanup may proceed per verified copy with debt for
unresolved copies; a barrier is never itself a deletion certificate.

After leases, terminalize dependent backups and remove controlled current/history rows,
blobs, spool and packet/job copies. Remove previous roots/candidates/backups wholly where
safe selective rewriting is absent. Respect shared references and exact ownership.
Current notices remain outside that deletion set and survive backup retirement. Do not
prune them merely because their target row or a backup has disappeared. A future bounded
compaction needs its own continuity proof; no such compactor is required for Base.

Report notice outcome `committed | rejected | unknown` separately from controlled cleanup
`not_applicable | pending | complete | unknown` and external cleanup/authority debt through
existing status/control. A rejected attempt cannot undo an earlier committed erasure. "Committed"
means exact notice/checkpoint readback, not deletion. Controlled `complete` requires
readback of all owned copies in the completed inventory and no unresolved local effect;
Store outage, incomplete traversal or failed filesystem deletion cannot produce it.
Controller cleanup uses caller authority or observed owner break-glass; absent authority
is external debt. Already delivered host transcripts and provider copies are outside
Memory's deletion guarantee; unlinking local files is not proof of media sanitization.

When connecting this Slice 3 path, observe withdrawal W1 → reactivation(W1) → W2 → replay
of reactivation(W1): W2 still suppresses. Also exercise overlapping scopes, erase followed
by old capture/new-ID native redelivery, publication/checkpoint interruption and restore
with a missing notice. Inspect the real consumer and controlled copies, not just marker
existence. Source implementation and Windows durability qualification remain required.

Store rotation closes sockets and restarts Store. Controller rotation uses its own
contract and stable client identity; do not give daemon privileged credentials to repair
it. Status reports actual executable/root/DACL, process/channel/Store/schema/query,
capture/spool/replay, maintenance/lease/candidate and cleanup readback. Only report
controller identity/cut/state when that integration actually exists.

## 11. Implementation sequence

Build one working path at a time. The rows below are implementation order, not new
crates, registries, mandatory PRs or a requirement to repair the V2 toolchain first.
Runtime work remains separately authorized; documentation changes do not implement it.

| Increment | Connected change | Observable exit / do not include yet |
|---|---|---|
| Asset repair (#5326/#5327) | Fix existing schema/query owner, selected codecs and bounds; replace capture primitives with a complete transaction and exact-open projection | Package fmt/Clippy and embedded inspection pass; still **not** a working Store. Do not add network/provider/backup machinery to `inspect`. |
| Slice 0 — inline capture/open | Verified Store startup/admission → one bounded client → §7.2 transaction → §7.3 exact open | Disposable caller retains the command for direct readback/retry. Same command changes nothing; changed input conflicts. Inline-only; no production-host crash-custody claim until Slice 1. No model/backup prerequisite. |
| Slice 1 — durable ingress/restart | §7.5 publish before send → single replay owner → Store/open → retire pending | Input survives restart and lost notification/reply under the same ID. Full quota does not evict old input; interrupted cleanup does not destroy pending custody. Native-event identity alone permits redelivery deduplication; equal bytes from distinct occurrences remain distinct. |
| Slice 2 — useful context and corrections | Host event → addressed/artifact/error cues → compact baseline or useful update → emission; thin note/correction → §7.4 → later history/context | Agent recovers goal, model/state, attempts, unknowns and next step where supported. Resume/compact rebuilds; tool results activate prepared knowledge; unchanged reads add nothing. Source/qualification changes pass dedup; optional receipt failure does not suppress context. No model required. |
| Slice 3 — Base maintenance | Quiesced cut → backup/fence/manifest → isolated restore/cutover; notices → erasure; rotation/shutdown | Disposable data exercises actual paths with inference disabled. No user-data migration/destructive command is enabled before its own boundary works. |
| Inference P1a — Dreamer | Accepted scoped controller extension → background preparation or explicit research question → one persisted call → useful revision → tool/context read; dependency-aware backup/release | Both callers use one job handler. A follow-up retains its own request identity; unknown send is not repeated under a new ID. Only model-assisted work waits for this boundary. |
| Inference P1b and later | Outcome/test/correction → revise knowledge or processing method → later use; credential rotation and separately selected acquisition/vectors/documents/hosts | Inspect a changed consumer and retained counterexample. External research acquisition is separate from the already available local Dreamer dialogue. |

Slice 2 is the first useful local memory milestone. Full backup/restore and optional
inference are separate increments; each shipped operation still includes its own custody,
scope and current-notice checks. Do not turn the whole Base completion list into a gate
before connecting capture → work reconstruction → context → exact open.

At that connection, record warm/cold latency, emitted UTF-8 bytes (tokens only with a real
counter), Store/model call counts and omitted decision-critical facts. Inspect one fresh
resume, a tool loop with a previous failed attempt, a changed premise and compaction:
can the agent identify the right next action/query and open its evidence without repeated
unchanged context? Later compare brief versus
flat/raw retrieval at equal context budget, including write/refresh cost. A smaller packet
that increases wrong actions or repeated failures is a regression. Use existing observations;
no new scoring service or test campaign is required before writing this path.

### 11.1 Source placement and handoff

The only existing proposed V3 package is `crates/storage/eliot-v3-store-schema` in the
separate source PR; it owns executable assets/digests. It is not present on this docs
baseline. Reconcile current main into that existing writer branch, do not fork its owner.
For the first runnable path use one planned package `bins/eliot-v3` (package `eliot-v3`,
binary `eliot`) with an ordinary Rust library and modules. **It does not exist yet.**
Create it with Slice 0's actual caller, not an empty architecture scaffold. Existing
V1/V2 bins are donors, not an instruction to wire their whole runtime into V3.

| Location | First responsibility / rule |
|---|---|
| Existing schema package: migration, wrapper, `src/queries.rs`, `src/lib.rs` | One executable SQL/bundle owner. Keep complete operation statements, projections, catalog and digests synchronized; no SQL copies in docs/runtime. |
| Planned runtime `src/main.rs`, `src/lib.rs` | Select supervisor/daemon/relay mode and compose only implemented operations. No successful stubs for later modes. |
| Planned runtime `src/store.rs` | One admitted client, bindings/decoders and operation calls using schema-package assets. No general SQL API. |
| Planned runtime `src/capture.rs`, `src/open.rs` | §7.2 identities/outcomes and §7.3 exact reads, used immediately by the first caller. |
| Later `src/spool.rs` | Slice 1: §7.5 publication/quota/replay/retirement, reused by §7.4; no second queue database. |
| Later `src/context.rs`, `src/host.rs` | Slice 2: shared cue normalization, bounded selection, volatile presentation cache and pure renderer; thin note/update adapters, callbacks and actual output. No checkpoint service, receipt registry or new host framework. |
| Later maintenance modules in the same package | Slice 3 with real backup/restore/erasure callers; no crate/process per operation. |
| Later `src/learning.rs`, `src/research.rs` in the same package | One Dreamer preparation handler and thin question/status adapters over existing jobs, retrieval and revisions; no second scheduler or conversation store. |

These are default source locations, not installed interfaces or a new module registry.
A different location requires a concrete existing owner/caller advantage, not a new
abstraction layer. The first source commit updates the source map to its actual paths.

For each row, read only its linked owner rules, implement the caller/result/consumer,
then format and run minimum changed-package Clippy. Run exact-engine execution only for
the connected DDL/transaction/read path; record the actual environment and outcome.
Use disposable input to observe the exit, not a new test/report factory. Broad crash,
concurrency, Windows and load campaigns follow the assembled product.

```text
cargo fmt -p eliot-v3-store-schema --check
cargo clippy -p eliot-v3-store-schema -- -D warnings
```

These commands apply after the source package is present; add the same package-scoped
checks for `eliot-v3` when it exists. Compilation is not the observable exit. Credential
identity, privacy admission, byte limits, atomicity and unknown-outcome handling ship
with their first effect, not as later hardening. An unavailable check is recorded, never
relabelled PASS. Fix only a V2 tooling dependency that demonstrably blocks the assigned
V3 operation; corpus retirement and generic validator modernization are not prerequisites.

## 12. Qualification ceiling

Retained exact-tag source/tests cover selected parser, READONLY/ASSERT, optional UNIQUE,
PARAM rollback, plain INFO and numbered FTS behavior. The pinned FOR UPDATE cases also
rule out the former table-target queries. These are source findings, not a local run of
Eliot's wrapper, client or Windows/RocksDB deployment.

Run focused execution as each real path is connected; do not label unrun paths ready.
The later complete campaign covers every DDL interruption/rollback point, concurrent
uniqueness/conflict handling, bind/decode and catalog drift, representative FTS/plans/load,
Windows IPC/ACL/custody, crash/restart, coherent backup/rollback, limits/leases/substitution,
rotation/erasure, and external unknown/retention behavior when inference is enabled.
A passing compile or copied upstream test cannot replace those executions.
