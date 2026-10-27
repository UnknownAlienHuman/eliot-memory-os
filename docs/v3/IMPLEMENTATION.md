# Eliot Memory OS V3 — Implementation

**Revision 1.0-draft.42 · 2026-10-27 · concrete design for the greenfield rewrite.**

This document turns [Architecture](ARCHITECTURE.md) into the Memory runtime, Store and connected operations. [Cognition](COGNITION.md) owns algorithms. [Inference Contract 0.18](INFERENCE-CONTRACT.md) is the sole Memory↔controller boundary. [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) is the sole active work ledger.

Nothing is implemented merely because it is specified. Build connected production slices in §12. Do not construct scaffolding for a later capability before its first real writer and consumer exist.

## 0. External prerequisite

Current controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
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

Supervisor owns executable/root identity, child handles, Store bootstrap credentials, migrations, Store-user rotation, candidate process/root and final cutover.

Daemon owns Memory semantics, Store Editor access, replay/jobs, controller-mutation serialization, backup IDs/records, bounded restore leases, retrieval/context and public control.

### 1.2 Installation layout

```text
%LOCALAPPDATA%\Eliot\
  config.toml
  installation.toml
  controller-write-id.state
  data\roots\<root-id>\
    db\
    blobs\
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

Initial profile is one fixed local NTFS/ReFS volume with protected user+LocalSystem DACL. Network/removable roots, broad principals and reparse traversal are rejected. Data is plaintext under OS/volume protection; Base claims no portable encrypted backup.

External-ID state and final backup records are outside rollback Store roots.

### 1.3 Installation selection

Supervisor owns `installation.toml` under installation mutex. It retains selection generation, stable Memory installation ID, current/previous roots, controller/client/token references, current/pending/previous Store credentials, expected schema bundle format/generation/digest and maintenance state. Another cutover/rotation waits while an earlier previous generation remains unretired.

### 1.4 Startup

```text
validate installation + executable/root identities
→ start/adopt exact active Store
→ reconcile bootstrap/credentials
→ apply/verify migration bundle through Owner
→ create inherited channel and launch daemon
→ daemon independently admits process/listener/peer/Editor/schema/query path
→ clean/quarantine pre-publication backup temps
→ reconstruct final backup/terminal authority
→ reconcile stale Store maintenance mirrors and pending release/retention
→ daemon ready
→ expose relay
```

No capture is `committed` before admission. Backup-dependent release/retention cannot run before installation authority is reconstructed.

## 2. Windows identity, custody and IPC

Before child resume, retain no-follow executable/root/ancestor handles, verify identity/digest/DACL, deny required write/delete/rename sharing, launch suspended with exact inherited handles, compare actual child image, assign Job and only then resume.

Supervisor owns process-family Job and candidate custody. Daemon/channel loss while candidate exists forces candidate termination, reaping and discard before another daemon or cutover.

Relay uses one first-instance, remote-rejected, protected named pipe with mutual process attestation and one bounded request/response per connection.

Supervisor↔daemon uses two inherited anonymous pipes with closed typed frames. Restore frames carry operation ID, backup ID, plan/manifest digests, candidate root ID and selection generation—never arbitrary path, SQL, argv, endpoint or secret.

## 3. SurrealDB child and Store transport

Pin exact SurrealDB 3.3.4 Windows artifact. Selected profile is external RocksDB `sync=every`, loopback dynamic port, `--deny-all`, HTTP `rpc`, RPC `query`, system-only arbitrary query, no defaults, no identification headers and sanitized environment. Origin/CORS is not WebSocket authentication.

Before credentials, Windows TCP ownership must prove listener and established peer belong to retained Store process. Basic-authenticated WebSocket selects exact NS/DB.

Root bootstrap is short-lived. Same root credential reconciles unknown persistence; Store restarts without root environment, provisions STRICT DB + database Owner/Editor with PASSHASH, applies migration through Owner, closes privileged sockets, restarts again and admits daemon Editor.

One Tokio task owns each query-only socket with one in-flight ID and continuous control-frame handling. Timeout, cancellation ambiguity, wrong/late response or protocol fault poisons it. Possible mutation send becomes `OUTCOME_UNKNOWN`; reconnect repeats admission and exact application readback.

JSON carries explicit DTOs only: bounded strings, signed integers, booleans, finite floats, integer times with precision, explicit optional states and immutable blob references. Surreal native IDs/special types remain internal. No generic `Value`, `SELECT *`, broad CRUD, copied CBOR tags or user-supplied grammar exists.

## 4. Migration 0001 and schema authority

### 4.1 Bundle identity and catalog

Bundle SHA-256 preimage includes:

```text
domain "eliot-memory-schema-bundle-v1"
schema_bundle_format = 1
runner_protocol = 1
exact transactional wrapper template
ordered UTF-8/LF DDL assets
expected-catalog template
```

Bound format/generation/digest values are outside the preimage. Fixed wrapper executes ordered DDL and overwrites three metadata params in one transaction.

Exact-tag evidence establishes that persisted `DEFINE PARAM` is rolled back by `CANCEL TRANSACTION`, and the 3.3.4 index tests include cancelled index overwrite retaining the previous definition. It does **not** establish the whole proposed wrapper over every table, field, analyzer, index and bound metadata value on the selected Windows/RocksDB transport. Slice 0 must execute that exact wrapper against 3.3.4 and prove:

- every checked-in DDL asset parses in the exact order used by the runner;
- bound RPC variables are accepted in the three `DEFINE PARAM ... VALUE $bound_*` statements;
- a forced pre-commit failure leaves no partial owned catalog or metadata;
- a lost commit reply is classified only by exact params + catalog readback;
- a fresh mismatched candidate is discarded rather than repaired with `IF NOT EXISTS`;
- an active-root mismatch requires an explicit named migration repair.

Schema admission uses plain `INFO FOR DB` and `INFO FOR TABLE`; `STRUCTURE` is forbidden. Plain INFO returns maps whose owned values are server-canonical `DEFINE` strings. Parse owned maps, sort keys and compare exact strings against the checked expected-catalog template. Raw JSON order is irrelevant. Dynamic metadata param values are compared to the bound typed values; static table/field/index/analyzer definitions are exact strings. Users/accesses are admitted separately through role handshakes.

Unknown outcome is committed only by exact metadata+catalog readback. Exact empty fresh candidate may retry the same bundle; partial/mismatched state fails closed.

### 4.2 Exact 3.3.4 DDL grammar boundary

Migration assets use only parser forms confirmed in tag `v3.3.4`:

- `DEFINE TABLE <name> TYPE NORMAL SCHEMAFULL PERMISSIONS NONE`;
- `DEFINE FIELD <field> ON TABLE <table>` with one occurrence of each selected clause;
- `TYPE option<T>` and `TYPE array<T>` for optional/array fields;
- `READONLY`, `DEFAULT`, `VALUE`, `ASSERT`, `COMMENT` and `PERMISSIONS` in their canonical emitted order;
- `FLEXIBLE` only immediately after an object-compatible `TYPE`, never as a free later clause;
- `DEFINE ANALYZER ... TOKENIZERS blank,class FILTERS lowercase`;
- separate `DEFINE INDEX ... UNIQUE` and `DEFINE INDEX ... FULLTEXT ANALYZER ... BM25` definitions;
- `DEFINE PARAM OVERWRITE $name VALUE <expression>`.

The field parser accepts most clauses in flexible input order, but checked-in assets use the server's canonical `to_sql` order so expected catalog strings are stable for the pinned version. Duplicate clauses, `DEFAULT`+`VALUE`, unsupported flexible types and guessed syntax are compile-time asset defects, not runtime fallbacks.

### 4.3 Application ID generation

Base object IDs are generated by the daemon before Store mutation:

```text
<prefix>_<26 canonical Crockford Base32 chars>
```

Prefixes:

```text
s stream
o observation
m memory
h memory_history
l link
j job
```

Generation rules:

- draw exactly 128 bits from the OS CSPRNG;
- encode fixed-width uppercase Crockford Base32 with the first character restricted to `0..7` so the 26-character form is canonical;
- do not encode wall-clock time and do not claim chronological ordering;
- validate exact regex, prefix and length before any Store call;
- persist the chosen ID in the owning immutable command/proposal before retryable Store mutation;
- a collision with a different object is `ID_COLLISION`/integrity failure, not silent regeneration after ownership transfer;
- exact command/proposal replay reuses the same ID.

Time ordering always uses explicit time/sequence plus canonical ID tie-break, never ID lexicographic order alone.

### 4.4 Derived unique keys and absence

Never concatenate components with an ambiguous delimiter. Derived keys are lowercase SHA-256 over a domain tag and length-prefixed UTF-8 components:

```text
stream_unique_key  = H("stream-v1", project, source_kind, source_native_id)
address_unique_key = H("memory-address-v1", origin_project, kind, address_kind, address_key)
slot_key           = H("job-slot-v1", project, purpose, target_key, slot_kind)
```

Store readable components separately. Fixed Rust query builders compute and verify the digest; private query corpus is the only writer.

The exact 3.3.4 unique-index implementation skips the whole unique tuple when **any** indexed component is `NONE` or `NULL`. V3 therefore standardizes absence:

- `NONE`/omitted field means “not applicable / no optional identity”; this is the only absence state used by conditional unique keys;
- `NULL` is not written to those fields;
- semantic “known unknown” is represented by an explicit closed state field when required;
- JSON DTOs never collapse `NONE` and `NULL` implicitly.

Optional address/command/slot keys are `NONE` when absent. Slice 0 still proves concurrent insert/conflict behavior through the production client.

### 4.5 Canonical projections and bounds

Raw accepted source bytes remain the source blob/inline body. Structured projection fields use one application canonical JSON codec:

- UTF-8;
- object keys sorted lexicographically;
- no duplicate keys;
- no insignificant whitespace;
- finite numbers only;
- no Surreal native/special values;
- exact per-field and aggregate byte limits checked before Store I/O.

The Store retains canonical JSON strings, not generic objects. A decoder must reproduce identical bytes/digest before using the projection. Source raw bytes are never replaced by this projection.

### 4.6 `READONLY`, row assertions and operation ownership

Exact 3.3.4 behavior is narrower than “server-owned immutable field”:

- a `READONLY` field may receive its initial value on create;
- a later write of the same value is accepted;
- a later changed value is rejected;
- `READONLY` does not generate identity, discard caller input or validate provenance.

Therefore IDs and creation facts remain daemon-generated and command-retained before Store mutation. `READONLY` is defense against later changed values, not the identity owner.

Field processing coerces the declared type before evaluating `ASSERT`. Assertion context exposes the current value and row/document context, including `$value`, `$before`, `$after`, `$input` and current-row references. Checked-in assertions use only exact row-local expressions qualified by language tests and Slice 0. They do not own cross-row cardinality, sequence allocation, replay identity, digest computation or set-wide concurrency; those stay in fixed transactions, locks and unique indexes.

For bounded strings, pattern assertions use string-vs-regex expressions such as `$value = /.../`; `TYPE regex` is a regex-value type and is not used to validate ordinary ID strings. Byte length/digest of source/blob content is checked by application code because string length is not a substitute for UTF-8 byte length.

### 4.7 Tables, immutable fields and assertions

All six tables are `TYPE NORMAL SCHEMAFULL PERMISSIONS NONE`. Identity and creation fields are `READONLY` with the semantics in §4.6. Closed literals are used for stable enums such as disclosure, occurrence precision, body storage and job state. String/digest/array limits are explicit absolute bounds; user configuration may narrow them.

#### `stream`

```text
stream_id READONLY
project READONLY
source_kind READONLY
source_native_id READONLY
workspace_id option<string> READONLY
stream_unique_key READONLY
last_ingest_seq int >= 0
created_at_ms READONLY
updated_at_ms
```

#### `observation`

```text
observation_id READONLY
project READONLY
stream_id READONLY
event_key READONLY
command_id option<string> READONLY
native_event_key option<string> READONLY
ingest_seq int > 0 READONLY
occurrence_time_ms option<int> READONLY
occurrence_precision literal READONLY
receipt_time_ms int READONLY
kind bounded string READONLY
body_storage "inline" | "blob" READONLY
body_inline option<string> READONLY
blob_ref option<string> READONLY
body_length int >= 0 READONLY
body_sha256 lowercase-hex-64 READONLY
search_excerpt bounded string READONLY
disclosure "local_only" | "external_allowed" READONLY
workspace_id/task_id/actor_id/session_id option<string> READONLY
call_id/parent_observation_id/resource_id/resource_version option<string> READONLY
locator_json/binding_json/relations_json/capture_limit_json canonical bounded strings READONLY
created_at_ms READONLY
```

A row-local assertion evaluated after field values are final requires exactly one body location:

```text
body_storage = "inline" <=> body_inline present AND blob_ref absent
body_storage = "blob"   <=> blob_ref present AND body_inline absent
```

The fixed capture query independently verifies UTF-8/blob byte length and SHA-256.

#### `memory`

```text
memory_id READONLY
origin_project READONLY
reuse_scope bounded closed value
revision int > 0
kind bounded string
address_kind/address_key option<string>
address_unique_key option<lowercase-hex-64>
content bounded string
search_text bounded string
exact_cues bounded array<string>
disclosure closed literal
subject/aspect/perspective option<string>
conditions_json/exceptions_json canonical bounded strings
valid_from_ms/valid_until_ms option<int>
support_state/exposure_state/influence_state closed literals
commitment_state/method_role/processing_purpose option<bounded string>
created_at_ms READONLY
updated_at_ms
```

If both validity bounds exist, `valid_from_ms <= valid_until_ms`. `address_unique_key` is present iff the complete address tuple is present and matches the fixed-query digest.

#### `memory_history`

Immutable exact previous semantic projection with:

```text
history_id READONLY
memory_id READONLY
revision int > 0 READONLY
replaced_at_ms READONLY
```

#### `link`

```text
link_id READONLY
source_kind/source_id READONLY
source_revision option<int > 0> READONLY
target_kind/target_id READONLY
target_revision option<int > 0> READONLY
relation_kind READONLY
grounds_group option<string> READONLY
locator_json/qualification_json canonical bounded strings READONLY
created_at_ms READONLY
```

#### `job`

```text
job_id READONLY
project READONLY
purpose/target_key READONLY
state closed Base literal
slot_key option<lowercase-hex-64>
origin/cause_id
first_queued_at_ms READONLY
due_at_ms option<int>
attempt int >= 0
waiting_reason option<string>
claim_owner/claim_until_ms option
frozen_input_json canonical bounded string
method_id/method_revision option
limits_json canonical bounded string
disclosure closed literal
profile_name option<string>
request_blob_ref/request_length/request_sha256 option tuple
result_json/coverage_json/cleanup_json canonical bounded strings
created_at_ms READONLY
updated_at_ms
```

Assertions require:

- claim owner and expiry are both present or both absent;
- request blob/length/digest are all present or all absent;
- pending state uses a `pending` slot digest;
- claimed/running/waiting states use the matching `active` slot digest;
- terminal states have `slot_key = NONE`;
- optional revision/length values are positive/non-negative as appropriate.

Fixed claim/settle queries recheck these invariants transactionally; field assertions are defense in depth, not a substitute for operation ownership.

### 4.8 Indexes connected to readers

Unique/exact:

```text
stream.stream_id
stream.stream_unique_key
observation.observation_id
observation(project,stream_id,event_key)
observation(project,command_id)       # NONE skipped
memory.memory_id
memory.address_unique_key             # NONE skipped
memory_history.history_id
memory_history(memory_id,revision)
link.link_id
job.job_id
job.slot_key                           # NONE skipped
```

Continuation and exact-reader indexes:

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

Direct work-address reconstruction therefore does not parse or scan `binding_json`. JSON retains source detail; explicit columns/indexes own continuation.

Full-text:

```text
DEFINE ANALYZER eliot_base_text TOKENIZERS blank,class FILTERS lowercase;
observation.search_excerpt FULLTEXT BM25
memory.search_text FULLTEXT BM25
```

Exact tag tests prove analyzer/index syntax and indexed iteration for numbered match predicates. Slice 0 must still run `EXPLAIN` for every selected continuation/unique/FTS query over representative cardinality and reject a migration/query bundle whose required reader falls back to an unbounded table scan.

## 5. Fixed query corpus

Every operation is a checked-in fixed query with bound data and explicit DTO. Initial corpus includes store probe, stream resolve/lock, capture identity/insert, direct work-task/session continuation, current/history/source open, forward/reverse relation pages, bounded lexical top-K, due-job claim, canonical backup table pages and schema readback.

### 5.1 Exact full-text shape

Scored search uses a numbered match reference:

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

Memory query uses `memory_id`/`search_text`. Plain `@@` is unscored only.

Exact 3.3.4 language tests prove:

- `search::score(n)` binds to the matching `@n@` predicate;
- `EXPLAIN` can report `Iterate Index` for the FULLTEXT predicate;
- a returned score may be exactly `0` and the row is still a match;
- no matching indexed term returns an empty result rather than a fabricated score.

BM25 ordering changes with corpus statistics. Lexical retrieval is one bounded top-K statement snapshot per call and exposes no cross-call page cursor. A later expansion is a new snapshot with new observed Store/schema/query facts.

Only stable-key readers expose cursors. Every cursor binds query version, scope, identity/revision and options.

### 5.2 Bound-data and plan qualification

Ordinary data always uses bound variables. The initial bundle does not claim source qualification for bound variables inside `DEFINE PARAM` merely because the parser accepts a full expression. Slice 0 must execute the exact RPC query with bound metadata values and compare resulting plain INFO output.

For each fixed reader, Slice 0 records the exact query asset digest, representative input shape, `EXPLAIN` result and bounded result DTO. An optimizer choice is evidence for the pinned dataset/version, not a permanent semantic contract; correctness never depends on index use, but latency/admission budgets may reject an unbounded plan.

## 6. Transactions and durable files

Unique values own identity/cardinality. Controlling rows use `FOR UPDATE`. Stream sequence/current revision lock and recheck. Set-wide invariants use deterministic slots. Nondeterministic `UPSERT` is not idempotency. Blobs publish before row transactions. External calls never run inside Store transactions.

Retry the entire immutable transaction only for exact retryable conflict. Unknown transport/shutdown/fsync reconciles first. With `sync=every`, an error is not rollback proof.

Immutable files use same-directory `CREATE_NEW` temp, complete write, file flush, no-replace write-through rename, parent-directory flush and exact no-follow readback. Mutable installation/external-ID state uses expected-generation replacement and exact old/new/unknown reconciliation.

Final backup directory is published atomically from a same-parent temp directory containing an already durable fence. Pre-rename temp never pins; post-rename uncertainty pins after reconciliation.

## 7. Core operations and host

Capture uses one immutable relay command. After blob publication, one transaction resolves/locks stream, reads replay identities, rejects changed bytes/binding, allocates sequence, inserts observation/relations, coalesces implemented work and commits. Matching readback is required for `committed`; capture never calls a model.

Private daemon result is `committed | rejected | stage_required | unknown`. Relay stages the same command when direct ownership is unavailable/uncertain. One daemon replayer owns pending files and exposes pause/drain for maintenance.

Memory revision preserves history and publishes current/links/result atomically. Job claim freezes finite inputs/method/limits/disclosure/profile. Exact `open` resolves one handle/range and never falls historical identity forward.

Initial Claude relay supports SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact and SessionEnd. Address current work before search; pack corrections, commitments, methods+exceptions, episodes, dissent and handles.

## 8. Backup-set owner and lifecycle

Daemon owns controller-mutation and backup-set owners.

```text
close/drain controller mutation
→ enter backup-set transition
→ disposition external IDs and capture controller/spool cut
→ build canonical plan
→ atomically publish/read back final directory + fence
→ leave transition
→ reopen controller mutation
```

Every call ID is admitted/retired-not-admitted/unknown; every cancel/release/retention ID is observed/retired-not-sent/unknown; every admitted call is controller-closed/dependent.

Plan digest excludes itself, publication state and later parts/manifest. After fence publication, daemon pages Base tables in canonical application-ID order, copies exact referenced blobs/cut spool/deletions/config and publishes the manifest.

Self-contained abort/retire terminal records remain authoritative after cleanup. Malformed/both/mismatch combinations fail closed. Terminalization is not erasure.

### 8.1 Bounded restore lease

Before lease admission validate format/schema, part count, unique canonical relative paths, per-part bytes and total bytes against build hard limits and configured narrower limits.

Retain for whole restore:

- logical lease bound to backup/plan/manifest;
- final backup directory handle;
- `parts/` directory handle;
- fence and manifest handles;
- `FILE_SHARE_READ` only;
- final terminal/manifest identity recheck before cutover.

Stream parts in deterministic manifest order. Open one no-follow read handle with `FILE_SHARE_READ` only, verify regular identity/path/length/digest, copy+verify into candidate and close before the next part.

Logical owner blocks daemon terminalization/cleanup; retained directory handles block directory replacement; active part handle blocks part write/delete while read; digest catches pre-open substitution. No unbounded handle set exists.

Supervisor owns candidate process/root only. Daemon/channel loss forces candidate kill/reap/discard before restart/cutover.

### 8.2 Exact rollback and external work

Restore never writes live root or invents merge. Healthy current Store first gets safety backup. Current deletion notices dominate backup; current post-cut spool merges by exact bytes/disposition; previous root remains until retirement.

Controller-closed jobs restore from backup facts; dependent jobs require exact call/copy. Fixed post-cut interval is inventoried and not adopted as cognition. Missing caller creates owner-action debt. History gap, terminal/auxiliary uncertainty, limit violation or missing dependent copy disables inference while Base remains usable.

Store maintenance mirrors are reconciled against installation authority before job claims and cannot create terminal records, clear pins or replay stale effects.

## 9. Controller V2 adapter

Contract 0.18 uses stable `memory_inference` client ID, current token version, precommitted global WriteIds and one provider attempt. Reads are identity/get/list/high-water/result-range; caller mutations are text/embed later/cancel/release/retention; owner-only operations install/rotate/disable/erase.

Exact result is copied and decoded. Release remains blocked by any final/provisional dependent backup. Registration owns monotonic admission and retention cuts. Fixed-window list below cut returns history gap; erased content above cut retains bounded membership tombstone until cut advancement.

## 10. Erasure, rotation and observability

Physical erasure publishes a deletion notice, closes affected mutation/replay, reconciles effects, terminalizes/deletes dependent backup content after leases, uses caller cancel/release-abandon where available and deletes controlled current/previous data. Missing caller requires observed owner break-glass. Markers/tombstones are not physical deletion proof.

Store credential rotation closes sockets and restarts Store. Controller rotation preserves stable client ID and delays previous-secret deletion until old-call read/release and restart readback.

Status derives from executable/root/DACL, process/channel/Store admission, schema format/generation/bundle/catalog, query health, capture/spool/replay, backup staging/terminal/lease/limits/candidate/cleanup, controller identity/high-water/cut/tombstones and cleanup debt.

## 11. Implementation sequence

After each coherent production increment run:

```text
cargo fmt --check
cargo clippy -p <changed-package> --lib --bins -- -D warnings
```

Slice 0 qualifies Windows/IPC/Surreal/Store, exact migration 0001 grammar, `READONLY`/ASSERT/absence semantics, wrapper bound values and full DDL rollback, catalog readback, unique/concurrency behavior, fixed query DTOs, FTS score/EXPLAIN, durable files/IDs, backup-set owner, terminal records, bounded restore lease, rollback/erasure/rotation/shutdown.

Slice 1 closes event→Store/spool→replay→restart→exact-open. Slice 2 adds qualified Claude context, direct work indexes, lexical top-K, notes/corrections/commitments and Base maintenance with inference disabled.

Then controller #200 and V2 L0/L1; never extend V1. Inference P1a adds stable caller/calls/copies/runner/cut/retention/backup integration and one result changing later context. P1b adds rotation; broader capabilities follow independently. Broad suites follow connected product.

## 12. Qualification ceiling

Static exact-tag source and language tests now establish the selected clause grammar, `READONLY` update behavior, row-local assertion variables, unique `NONE`/`NULL` skipping, persisted-parameter rollback, plain INFO maps, numbered FTS score and representative index iteration.

They do **not** establish the final Windows binary/process profile, the complete migration wrapper over RocksDB, bound metadata through the production WebSocket client, concurrent unique/lock behavior, every expected catalog string, all reader plans, crash durability or application DTO correctness. Those remain Slice 0 runtime qualification and must not be upgraded to `IMPLEMENTED` by prose or upstream tests.