# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.44 · 2026-10-28 · design for the greenfield rewrite.**

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

Initial profile is one fixed local NTFS/ReFS volume with protected user+LocalSystem
DACL. Reject network/removable roots, broad principals and reparse traversal. Data is
plaintext under OS/volume protection; Base claims no portable encrypted backup.
External-ID state and final backup authority remain outside rollback Store roots.

### 1.3 Installation selection

Under the installation mutex, supervisor owns selection generation, stable Memory
installation ID, current/previous roots, current/pending/previous Store credential
references, expected schema format/generation/digest and maintenance state. Inference
adds controller/client/token references without another installation registry.
A new cutover/rotation waits while an earlier previous generation remains unretired.

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

Use one unambiguous, documented length-prefix encoding for these segments. Bind the
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

Before mutation, daemon generates `<prefix>_<26 canonical Crockford Base32 chars>`.
Prefixes are `s` stream, `o` observation, `m` memory, `h` memory_history, `l` link and
`j` job. Draw 128 OS-random bits; encode fixed-width uppercase with first digit `0..7`.
Validate exact prefix/length/regex. These IDs contain no time ordering promise.

Retain the selected ID in the immutable command/proposal before retryable mutation.
Replay reuses it. A collision with another object is `ID_COLLISION`/integrity failure,
not silent regeneration after ownership transfer. Order by explicit time/sequence and
ID tie-break, not the random ID alone.

### 4.4 Derived unique keys and absence

Use domain-separated SHA-256 over length-prefixed UTF-8 components, never ambiguous
concatenation. Store readable components separately and verify the digest in the writer:

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

### 4.6 READONLY, row assertions and operation ownership

Retained exact-tag evidence: READONLY allows initial and same-value assignment, but
rejects later changed values. It does not generate identity or establish provenance.
IDs and creation facts remain daemon-generated and command-retained.

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
| `observation` | observation_id, stream/event/command/native-event identity, ingest_seq, source bytes, occurrence/receipt/creation facts and captured work binding | Immutable accepted observation; exact open, continuation and retrieval projections |
| `memory` | memory_id, origin_project, created_at_ms | revision, kind, reuse_scope, address tuple/key, content/search_text/exact_cues, disclosure, subject/aspect/perspective, conditions/exceptions, validity, support/exposure/influence, commitment/method state and updated_at_ms |
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

History uses one typed, versioned `snapshot_json` of the complete replaced semantic
projection, plus its identity/revision/replaced time. Do not maintain duplicate flattened
semantic columns. Its decoder verifies agreement with the outer identity/revision and
preserves all conditions, exceptions, scopes, disclosure, validity, cues and method/
commitment states. Historical open, backup and restore use that same decoder, never
reconstruct missing history from the current row. The candidate's unversioned string
alone does not yet implement this contract.

Closed enum spellings must be agreed with their writer and consumer before admission.
The retired pack and source candidate disagree on precision, reuse, support, influence
and unknown-job encoding; the exact unresolved choices are in R-183. They are not safe
aliases. Preserve temporal resolution separately from certainty; preserve conditional
applicability separately from withdrawal/supersession. A `selected` reuse label needs
persisted target membership and an enforcing reader; until connected, reject that mode
rather than treating it as permission for every project. Do not create a new policy DB.

Job claim owner/expiry are both present or absent; request blob/length/digest are all
present or absent. Pending uses the pending-slot digest; claimed/running/waiting use the
active-slot digest; terminal uses NONE. Recheck these invariants transactionally.
Claim-time immutability is not create-time READONLY: pending fields must remain safely
coalescible, then the claim transaction freezes the complete tuple once. New input after
claim goes to the one pending successor; it never rewrites an active request.

An uncertain effect keeps its active slot and requires reconciliation. Claim expiry,
worker loss or a waiting state does not authorize another provider attempt. A stale
worker cannot publish using only job ID: settlement must match the retained claim and
frozen input/revision. Exact state/reason encoding must express these distinctions.

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

Retry the entire immutable transaction only after a definite retryable conflict with
no external effect. Unknown transport/shutdown/fsync reconciles first; an error under
`sync=every` is not rollback proof. No partially executed multi-statement sequence may
report committed capture. Nondeterministic UPSERT is not idempotency. Publish blobs
before row transactions; never perform provider or filesystem effects inside them.

Immutable files use same-directory CREATE_NEW temp, complete write, file flush,
no-replace write-through rename, parent flush and exact no-follow readback. Mutable
installation/external-ID state uses expected-generation replacement and old/new/unknown
reconciliation. These are selected durability requirements, not qualified Windows facts.

## 7. Core operations and host

Capture owns one immutable relay command. Publish its blob, then in one transaction
resolve/recheck stream, read replay identities, reject changed bytes/binding, allocate
the sequence, insert observation/relations and coalesce only implemented work. Matching
readback establishes committed. Replay compares the complete immutable semantic command,
including kind, work binding, disclosure and capture limitations; matching body bytes
alone are insufficient. Capture never calls a model.

Private result is `committed | rejected | stage_required | unknown`. Relay stages the
same command when direct ownership is unavailable/uncertain. One daemon replayer owns
pending files; it removes one only after matching commit readback and supports bounded
pause/drain for maintenance. Staged is durable custody, not a canonical Store commit.

Revision preserves exact history and publishes current/links/original operation result
atomically. Its writer must retain the command identity/result in the existing owning
records; checking only the present revision cannot reconcile a lost reply after another
revision. Reject reuse with changed semantic input, including scope/disclosure. Until
that complete transaction and readback exist, primitive inserts/updates are not an API.
Do not solve this gap with a general second mutation-ledger framework.

Job claim freezes finite input/method/limits/disclosure/profile under §4.7. Exact open
resolves one handle/range; a historical handle never falls forward. Initial Claude relay
supports SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact
and SessionEnd only as verified against the installed host. Address work before search
and emit actual packet content at admitted boundaries; prepared packet metadata alone is
not delivery. Cognition owns selection/packing.

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
blobs, cut spool, deletion notices and admitted config; publish the final manifest only
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
current inventory. Current deletion notices dominate backups. Merge current post-cut
spool only by exact identity/bytes/disposition; retain the previous root until retirement.

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

Physical erasure publishes a deletion notice, closes affected mutation/replay, fences
jobs and reconciles possible effects. After leases, terminalize dependent backups and
delete their controlled content. Remove affected current/history rows, blobs, spool,
packet/job copies; delete affected previous roots/candidates/backups wholly where safe
selective offline rewriting is absent. Respect shared references and exact ownership.
Caller cleanup or observed owner break-glass covers controller copies; missing authority
leaves explicit debt. A marker is not deletion proof; provider-side copies remain external.

Store rotation closes sockets and restarts Store. Controller rotation uses its own
contract and stable client identity; do not give daemon privileged credentials to repair
it. Status reports actual executable/root/DACL, process/channel/Store/schema/query,
capture/spool/replay, maintenance/lease/candidate and cleanup readback. Only report
controller identity/cut/state when that integration actually exists.

## 11. Implementation sequence

One coherent increment connects caller → operation → durable result/unknown → consumer
and relevant restart/readback. The following are increments, not mandatory separate
crates, issues, PRs or stages of a new manager. Runtime work needs its own authorization.

| Increment | Implement now | Exit for that increment |
|---|---|---|
| Slice 0 — minimal Store path | Exact child/process/credential admission, selected schema, one bounded client, capture/open transactions and required file/ID helpers | A disposable input can be committed/read back through the real client; uncertain mutation is not falsely acknowledged. No model or backup implementation prerequisite. |
| Slice 1 — capture and restart | Relay command, durable spool, single replay owner, exact identity/open and restart | One real input survives direct/staged ownership and restart; replay does not duplicate it. |
| Slice 2 — useful host context | Selected host events, addressed continuation, exact/lexical retrieval, notes/corrections/commitments, packet emission | Host receives useful qualified context and can open exact sources/history. |
| Slice 3 — Base maintenance | Coherent backup cut, fenced publication, terminal records, bounded restore/cutover, erasure, rotation and shutdown | Actual maintenance paths work with inference disabled; no user-data migration or destructive operation is enabled prematurely. |
| Inference P1a | Scoped controller extension, persisted job/ID, verified result consumer and external cut/release/retention integration | One finite episode changes later context without hidden retries or rollback resubmission. |
| Inference P1b and later | Credential rotation and independently selected vectors/views/documents/Research/hosts | Each feature has its own actual consumer; no unused adapter blocks Base. |

Implement the invariants needed by each path with that path. Do not defer credential
checks, exact mutation identity, size bounds or unknown handling to a final test phase.
Conversely, do not require the complete DDL/crash/load/backup campaign before writing
capture/open. Features absent from an increment are unavailable, not successful stubs.

After coherent Rust increments run formatting and minimum changed-package Clippy:

```text
cargo fmt --check
cargo clippy -p <changed-package> -- -D warnings
```

No broad test factory is introduced by this documentation task. Follow the owner's
code-first order; the complete deterministic/platform/crash/load campaign comes after
the assembled product. The controller repository owns checks for its own runtime.

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
