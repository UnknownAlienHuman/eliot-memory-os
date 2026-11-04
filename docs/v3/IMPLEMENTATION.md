# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.49 · 2026-11-04 · design for the greenfield rewrite.**

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
stream_unique_key  = H("stream-v1", project, source_kind, source_native_id)
address_unique_key = H("memory-address-v1", origin_project, kind, address_kind, address_key)
slot_key           = H("job-slot-v1", project, purpose, target_key, slot_kind)
```

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
| Candidate page / emitted Base packet | 32 candidates / 32 KiB UTF-8 | Page also has an encoded-byte cap; packet omissions carry explicit gaps. |

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
| `observation` | observation_id, stream/event/command/native-event identity, command_sha256, event_sha256, capture_format, ingest_seq, source bytes, occurrence/receipt/creation facts and captured work binding | Immutable accepted observation; exact open/replay. An operation-owned observation may also contain immutable operation_result_json (§7.4). |
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
string does not yet implement it.

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

Capture, exact open and direct revision have distinct transactions below. The relay
cannot submit arbitrary table mutations or manufacture operation results. Apply §7.1
before any payload-bearing file or IPC. Model calls are absent from all Base operations.
Job claim/settle uses §4.7.3 only when its real worker exists.

The initial Claude relay enables only host events verified against the installed host
contract. Address work before search; deliver actual context at supported boundaries.
Unsupported events/operations are unavailable, not successful empty handlers. Cognition
owns context selection and packing; host emission is not part of Store commit.

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

`CaptureCommandV1` is a closed DTO, not arbitrary host JSON. Before first send/stage,
freeze `format=1`, proposed `observation_id=command_id` (§4.3), the stream tuple
`(project, source_kind, source_native_id, workspace_id)`, `kind`, source event identity,
occurrence tuple, first `receipt_time_ms`, captured work/resource binding, locator,
disclosure, policy revision/limitations, source relations, search excerpt and body
length/SHA-256/location (§4.7). Host JSON stays in the accepted body. Command metadata
has no floating-point fields. Internal native Store IDs and `ingest_seq` are not inputs.
Reject disagreement between structured binding columns and their canonical projection.

The admitted host adapter selects occurrence identity, not the body hash:

- With a documented stable native event key, `event_key = H("native-event-v1", kind,
  native_event_key)`. It is scoped by the resolved stream and project.
- Without one, `event_key = H("capture-event-v1", command_id)`. Retrying the saved command
  is idempotent; a new callback is a new occurrence. Do not promise host-redelivery
  deduplication without a stable key or substitute text/time similarity.

Store `command_sha256 = H("capture-command-v1", canonical command)` and
`event_sha256 = H("capture-event-content-v1", canonical semantic projection)`.
The latter excludes proposed observation/command IDs, receipt time and physical body
location, but retains body length/hash, event/stream identity and every semantic field
above, including policy and limitations. Hashes do not contain themselves. Body location
is a checked inline value or owned blob key, never a caller-supplied filesystem path.
For blob bodies the key is `sha256:` plus the 64 lowercase hex body digest, fixed before
custody. The selected root and spool pathname are not command fields: copying bytes
from spool to an admitted root does not change the command or either digest. A key is
not authorization to read another project's bytes. A second delivery may have a
different proposed ID/receipt time, not different meaning.

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
   replay allocates nothing. Do not queue unimplemented jobs.
4. Check every statement and commit result, then decode the accepted observation ID,
   stream ID, sequence, original receipt time and hashes. Native redelivery returns the
   stored observation ID, not the caller's new proposed ID. Verify exact open can read it.

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
Source/representation handles keep their exact identity. Empty selectors reject.

An authorized response includes requested/resolved identity, representation/revision,
full body length/SHA-256, capture limitations, qualifications and a closed disposition:
`complete`, `range`, `missing`, `forbidden`, `erased`, `damaged` or `unsupported`.
Unavailable Store/transport is an operation error, not `missing`. Recheck current scope
and suppression before returning content; forbidden responses disclose no source bytes.

Body ranges use unsigned byte offset and positive length within §4.5.1, with checked
arithmetic. Return exact bytes as base64, range length/hash, total length and next offset
(or absent at end). A text preview is separate; a UTF-8 code point split at a byte
boundary is not damaged source. Offset at EOF yields an empty complete range; beyond EOF
rejects. A continuation repeats the same identity/revision/full digest. Changed identity,
length or digest rejects, not a new search. Metadata remains typed and size-bounded.
The full digest identifies the immutable object; a range digest verifies only the returned
range, not the whole object. Verify full length/hash when publishing or opening the full
body, and retain protected no-follow custody during range reads. Integrity failure reports
damaged, never a claimed exact body.

### 7.4 Direct revision and lost replies

`create` and `revise(expected_revision)` are separate closed inputs. Create publishes
revision 1 only when absent; revise requires the exact current positive revision and
publishes its checked successor. The command freezes the target memory ID (a retained newly generated ID for create),
a full replacement semantic DTO, attributed cause/source and a fresh `o_` command ID
before send. Before the first Store send, the authorized revision owner durably
publishes this complete command through §7.5; a process-local variable does not survive
a lost reply followed by restart. Use command-derived event identity, not native-event
deduplication for the attributed cause. No model is needed.

Use an operation-owned `observation` with reserved kind `memory_change` and that command
ID, not a new mutation table. Its immutable body records the permitted command/cause;
`operation_result_json = {"format":1,"memory_id":...,"revision":...}` records the
original result. Represent its admitted input as a `CaptureCommandV1` with this
reserved kind; allocate its stream sequence and retain both digests under §7.2 in
the same revision transaction. The result is output, not part of either input digest.
Ordinary relay capture cannot write this kind/result. The row uses the same policy,
size and provenance rules; do not modify an already captured observation.

In one transaction: check the operation identity/digest **before** revision CAS; resolve
create/expected revision; insert the prior full snapshot into history for revise; publish
current, exact grounds/replacement links and the operation observation/result together.
Invalid scope, source, history or links abort the whole operation. Only implemented
reverse-impact work may be coalesced; no empty successful job is created.

Same command/digest returns its original result even after later revisions. Open that
exact resulting revision through §7.3; never replace it with current. A changed command
is identity conflict; a new command with stale expected revision is revision conflict.
Possible commit with a lost reply is unknown until lookup by operation identity, not a
second revision. The same-input reconciliation rule in §7.2 applies only to this complete
idempotent transaction, with original-result lookup before CAS. A pending proposal is not
a committed revision on which another edit may base its expected revision. Erasure may suppress the old result, but must not make the operation
eligible to run again (§10). Withdrawal/reactivation still use the outside-root notice
authority in §10; a generic revision cannot bypass it.

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
The same envelope can hold the reserved `memory_change` input, but only its authorized
daemon front door may admit it; ordinary relay capture still rejects that kind. A kind
or installation ID in a file is not a grant of authority. Replay checks current policy
and dispatches to the owning capture or revision transaction, never generic inserts.

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

## 8. Backup-set owner and lifecycle

This section solely owns Memory's physical backup format, publication and restore.
Controller-dependent cut/release semantics belong to
[Inference §8–10](INFERENCE-CONTRACT.md#8-memory-backup-interaction). Inference-disabled
Base neither authenticates a controller nor constructs fake external-call inventory.

One daemon backup-set owner serializes record transitions, dependency snapshots, leases
and cleanup. When inference is enabled, take locks in this order:

```text
close/drain controller mutation
→ enter backup-set transition
→ classify external IDs and capture controller high-water
→ capture Store/replay/spool cut and build plan
→ publish/read back final directory + fence
→ leave transition
→ reopen controller mutation
```

For Base omit the external-call steps, not Store consistency. Pause/drain canonical
mutation and replay across paged Store export, or use a separately established coherent
snapshot; timestamps and successive SELECT pages alone are not a snapshot. With the
selected quiesced path, hold canonical mutation/replay closed until table/blob capture
finishes; direct capture returns stage_required. Take the spool publication lock only
for a brief exact inventory/generation cut, then allow post-cut relay staging while
copying. On failure, reconcile exact capture state before reopening; never acknowledge
uncommitted data to shorten the pause.

Backup ID is `b_` plus 32 lowercase hex digits from 128 OS-random bits. It does not come
from rollback state or wall clock. The canonical plan binds backup/root/schema/spool
cut, controller cut/dependencies when present, selected config/disclosure and gaps.
Plan digest excludes itself, publication state and later part/manifest digests. The
manifest repeats the plan digest and adds exact actual inventories/digests.

Before any part, create a private same-parent temp directory, write canonical fence.json,
flush file+directory, atomically no-replace rename to the final backup ID, flush parent
and reopen final directory/fence no-follow for exact readback. Final directory never
appears empty. Collision discards temp and recomputes the plan with a new ID before
publication. Pre-rename temps are non-restorable/non-pinning cleanup debt. A possibly
committed rename is publication_unknown and pins conservatively after reconciliation.
Any final fence/terminal record consumes that ID permanently.

Page the fenced Base tables in canonical application-ID order; copy exact referenced
blobs, cut spool, suppression/deletion notices and admitted config; publish the final manifest only
when every expected member and digest agrees. Missing/truncated/extra/conflicting parts
cannot become a complete backup.

Terminal records are create-new, durable and self-contained: format, kind, backup ID,
plan digest, observed fence digest, terminal operation ID, closed reason and, for retire,
observed manifest digest. Abort requires exact fence, no valid manifest/writer/restore
lease, exact partial-cleanup disposition and final-manifest absence readback. Retire
requires exact published fence+manifest, no abort and no restore lease.

```text
valid standalone retire                  retired/non-restorable
valid standalone abort                   aborted-before-publish
fence + matching manifest, no terminal    published/restorable
fence without valid manifest/terminal     preparing/publication_unknown
malformed/both/mismatch/ambiguity          unresolved; fail closed
```

Retain self-contained terminal markers after content cleanup. Terminalization is not
erasure. Restored maintenance rows cannot create installation authority.

### 8.1 Bounded restore lease

Before candidate work validate format/schema, finite part count, unique canonical
relative paths, per-part and total bytes against build and narrower configured limits.
Keep a logical lease bound to backup/plan/manifest plus no-follow final-directory,
parts-directory, fence and manifest handles with FILE_SHARE_READ only.

In deterministic manifest order open one part with write/delete sharing denied, verify
regular identity/path/length/digest, copy+verify into the candidate and close it before
the next part. Never retain an unbounded all-parts handle set. Logical owner blocks
terminalization/cleanup; directory handles block replacement; the active part handle
blocks changes during read; digest detects pre-open substitution.

Retain the lease through final terminal/manifest identity recheck before cutover.
Supervisor owns the disposable candidate process/root and selection change, not backup
interpretation. Daemon/channel loss forces candidate kill/reap/discard before another
daemon or cutover. Supervisor loss is contained by its Job. A scan is not a lease.

### 8.2 Exact rollback and external work

Never restore into the live root or merge later Store rows into restored cognition.
Healthy current Store first gets a safety backup; disaster mode records unavailable
current inventory. Current suppression/deletion notices in §10 dominate backups before
any restored guidance, job or replay becomes available. A backup's active influence flag
cannot cancel a later withdrawal. Reconcile spool by the plan's exact command inventory,
not wall-clock age. Included pending commands retain their original identity. Post-cut
capture may be admitted as source input under current policy; post-cut `memory_change`
commands are withheld, not replayed into rolled-back cognition. Read their original result
from the retained previous root when available; unavailable outcome stays unknown. Adopting
such a change requires a new explicit operation against the restored current revision,
never an automatic rewrite of the old command. Retain the previous root until retirement.

Missing notice continuity is not an empty notice set. Keep that recovery isolated and
report the gap; enabling it requires an explicit owner recovery decision acknowledging
unknown history, never a claim that prior withdrawals/deletions were preserved. Known
notices cannot be bypassed by that decision.

Before new job claims, reconstruct installation authority and reconcile future-timeline/
unmatched Store maintenance mirrors. They cannot create terminal records, clear pins
or replay stale effects. With inference enabled apply the contract's exact in-cut
closed/dependent classification and fixed post-cut inventory. History gap or missing
external copy disables inference, not an otherwise valid Base. A broken local Store/
lease/cutover invariant still blocks the affected local operation independently.

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
| Slice 2 — useful context and corrections | Verified host boundary → addressed exact/lexical retrieval → deterministic packet → actual host emission; §7.4 direct update → later exact history/context | Host receives goal/constraints/qualified evidence and source handles. Correction survives another revision and a lost reply. Empty, unavailable and truncated retrieval differ. No generated summary or model required. |
| Slice 3 — Base maintenance | Quiesced cut → backup/fence/manifest → isolated restore/cutover; notices → erasure; rotation/shutdown | Disposable data exercises actual paths with inference disabled. No user-data migration/destructive command is enabled before its own boundary works. |
| Inference P1a | Accepted scoped controller extension → one persisted call → decoded revision → later context; dependency-aware backup/release | Unknown send is not repeated under a new ID. Only this row waits for controller decisions; do not scaffold it in Base. |
| Inference P1b and later | Credential rotation, then independently selected vectors/views/documents/Research/hosts | Add each capability only with its real input, failure result and consumer. |

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
| Later `src/spool.rs`, host/context and maintenance modules in that package | §7.5 owns publication/quota/replay/retirement; add with Slice 1 and reuse it for §7.4. Host and maintenance arrive with their callers. No second queue database or crate/process per noun. |

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
