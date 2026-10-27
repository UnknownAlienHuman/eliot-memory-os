# Eliot V3 — One-shot inference contract

**Revision 0.18-draft · 2026-10-27 · shared Memory OS ↔ `eliot-swarm-controller` V2 boundary; not implemented.**

This is the sole normative contract for one-shot text and embedding execution. Memory owns semantic work; controller owns authenticated physical model execution and bounded temporary copies. The boundary does not create a controller Agent, native session, Goal, Task/Attempt workflow, automation run, script, generic service-account platform, second receipt store or retry ladder.

## 0. Authority and prerequisites

Inspected controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

Controller V2 is specification-only. Issue #200 owns separation of binding allocation, selected pointer and effect publication; PR #201 is fixture-only. Issue #199 owns this extension after #200 and V2 L0/L1. No implementation may patch controller V1 to make this contract appear available.

## 1. Ownership

Memory daemon owns:

- finite job, exact sources and coverage;
- recipe revision and disclosure reduction;
- exact request bytes and Memory-side external `WriteId`s;
- result verification/copy, decode/publication and later consumer;
- one controller-mutation owner;
- one backup-set owner, backup IDs, installation records, bounded restore leases and cleanup;
- backup cut classification and release/retention fences;
- caller-authorized cancel/release requests.

Memory supervisor owns executable/root/process custody, disposable candidate Store process/root and final installation cutover. It never owns backup-file interpretation.

Controller owns caller authentication, profiles/actual destination, global `WriteId` receipts, provider invocation/readback, private input/result copies, call status, retention, membership tombstones and cleanup facts.

Controller owner may install/rotate/disable a Memory principal and perform non-disclosing break-glass erase. Memory never receives owner authority.

## 2. Principal, credential and identities

One stable principal represents one Memory installation:

```text
principal_kind = memory_inference
client_id      = memory:<stable-memory-installation-id>
```

Distinct values:

```text
controller_id
client_id
token_version
raw token
```

`client_id` survives Memory restart, Store cutover, rollback and token rotation. Changing it is unsupported principal migration.

Each controller-backed job retains, without secrets:

```text
controller_id
controller_client_id
selected_token_version
inference_write_id
method + canonical request identity
controller_admission_state
controller_admission_seq when admitted
controller_dependency_state
profile/connection/adapter/destination snapshot
result digest/length when present
cancel/release/retention WriteIds and auxiliary states
per-copy cleanup state
```

Call admission:

```text
prepared | admitted | retired_not_admitted | admission_unknown
```

Auxiliary cut state:

```text
effect_observed | retired_not_sent | mutation_unknown
```

Backup dependency:

```text
controller_closed | controller_dependent
```

A retired ID can never be sent later.

## 3. Exact controller surface

Authenticated reads:

```text
client.identity
inference.get
inference.list
inference.high_water
inference.result.read
```

Authenticated caller mutations, each with one precommitted global external `WriteId`:

```text
inference.text
inference.embed                 # later
inference.cancel                # own queued call only
inference.release
inference.retention.advance
```

Controller-local owner maintenance:

```text
memory.client.install
memory.client.rotate
memory.client.disable
inference.erase                 # non-disclosing break-glass
```

No method creates or reuses Agent, generation, binding, turn, command, Goal, automation, workspace, native session, Task, Attempt, review or acceptance objects.

## 4. Provisioning and connection identity

Controller-local owner install/rotate uses the normal owner `WriteId` path. It commits one exact registration/version transition, derives the raw Memory token under a dedicated domain tag from the private routing key + client ID + token version, stores only version/hash and publishes the raw token into one admitted private credential bundle.

The destination is no-reparse, restrictive-ACL, create-new, file/parent durable and exact-read-back. Raw token never enters argv, SQLite, receipt result, logs, diagnostics or status. Lost reply retries the same owner WriteId and re-derives the same token.

`client.identity` returns:

```text
controller_id
client_id
principal = memory_inference
token_version
api_version
write_id_floor_ms
write_id_future_skew_ms
```

Memory requires exact equality with installation selection and credential bundle before application calls.

Before every read or mutation, controller reloads current registration and checks enabled principal, exact client ID, exact token version/current hash and unambiguous peer classification. A stale connection receives `credential_stale` and closes after the terminal response.

## 5. External WriteId state and live replay

Memory owns one locked atomic state outside rollback Store roots:

```text
controller-write-id.state {
  schema_version
  controller_id
  client_id
  last_ulid
}
```

Generation order:

1. authenticate identity and observe controller floor/future skew;
2. lock and reread state;
3. generate a monotonic ULID after retained value and admitted floor/current monotonic time;
4. atomically replace and read back state;
5. persist exact ID in the owning job/maintenance record;
6. only then send.

Crash after advancement burns an ID. Crash before job persistence must not send. Rollback never rolls the file backward. Total state loss is a continuity incident.

Live call identity is:

```text
WriteId + client_id + method + canonical semantic payload digest
```

Canonical payload contains behavior-changing fields only: profile, origin, disclosure, input digest/length, response role and finite limits.

```text
existing ID + same identity -> original/current call
existing ID + mismatch      -> id_conflict
valid absent live ID        -> first admission
absent below floor/window   -> id_expired
absent excessive future ID  -> id_future
```

Normal disconnect/restart repeats the same method, ID and bytes. Provider-send uncertainty remains retained call state. Restore never first-admits an absent old call or auxiliary ID.

## 6. Minimal controller state and runner

Reuse V2 `write_receipts`. Add only:

```text
memory_inference_clients
inference_calls
private call-owned inference_input/result files
```

Registration owns monotonic `last_admission_seq` and `retain_after_seq`. First admission checks signed-64 exhaustion, increments the allocator and inserts receipt/call in one transaction. Never derive sequence from retained rows.

Exact input is durably published before provider I/O. One bounded runner verifies input/current registration/profile, CASes `queued -> sending`, performs at most one provider attempt, retains native readback identity when available, publishes exact result when present and never performs hidden retry, redirect or fallback.

Possible send followed by loss becomes `unknown` unless native readback resolves it.

Each call creates at most `inference_input` and `inference_result`. Per-copy state:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Raw input/result/provider errors/credentials never enter receipts or call rows.

## 7. Profiles, destination and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile` records. Connection owns adapter/transport, endpoint, provider credential reference and actual destination. Profile owns connection/digest, requested model, automatic-use permission, finite limits and formats.

A loopback gateway forwarding to cloud is external. Memory selects a profile name only. It cannot provide arbitrary endpoint, headers, extras, retries or fallback.

Memory reduces contributing material to `local_only | external_allowed`; derived content cannot widen a stricter source it still reveals. Controller checks destination/disclosure before provider I/O. Mismatch or unavailable capacity is operational failure/waiting, not cognitive no-change.

## 8. Controller-mutation and backup-set owners

One daemon controller-mutation owner serializes call, cancel, release and retention advance.

One daemon backup-set owner owns backup ID allocation, final backup directory publication, installation-record scan/state derivation, fence/abort/retire transitions, dependency snapshots, bounded restore leases and physical backup cleanup. It is an in-process owner task with retained OS handles, not another service or table.

New fence lock order:

```text
close and drain controller-mutation owner
→ enter backup-set transition
→ publish/read back final fence authority
→ leave transition
→ reopen mutation admission
```

No release or retention advance can cross a newly visible fence. Terminal transitions remove pins, so stale pre-terminal observations are conservative.

## 9. Backup IDs and atomic first visibility

Backup ID grammar:

```text
b_<32 lowercase hexadecimal characters>
```

It is generated from 128 OS-random bits and never derived from Store rollback state or wall clock.

Before any part:

1. build canonical backup plan and digest;
2. create a private same-parent temp directory;
3. write canonical `fence.json` inside;
4. flush fence file and temp directory;
5. no-replace atomically rename the directory to `backups/<id>` with write-through semantics;
6. flush `backups/` parent;
7. reopen final directory/fence no-follow and verify exact identity/bytes/digest.

Final directory first becomes visible with authoritative fence already inside.

- collision: discard temp, generate a new ID and recompute plan;
- crash before rename: temp staging is non-restorable/non-pinning cleanup debt;
- possible rename with failed sync/readback: `publication_unknown`; reconciliation opens the final name and pins conservatively;
- a final fence or terminal marker permanently consumes the ID.

## 10. Backup cut, plan and terminal records

Before high-water, Memory stops new controller-backed work, drains controller mutation, pauses replay and dispositions every created call/cancel/release/retention ID.

Every admitted call is:

```text
controller_closed
  backup contains every terminal Memory-owned fact/body it needs,
  no future settlement/publication is possible,
  no controller copy/readback/cleanup remains

controller_dependent
  backup still needs controller state, result/copy or cleanup/readback
```

Canonical plan includes backup ID, expected manifest identity, root/schema/spool cut, controller/client/token/high-water/retain-cut, admitted calls/dependencies, retired attempts, disclosure and gaps. `backup_plan_digest` excludes itself, publication state and later part/manifest digests. Final manifest repeats it plus actual inventories/digests.

Terminal records are create-new, durable and self-contained:

```text
format_version
kind = aborted_before_publish | retired
backup_id
backup_plan_digest
observed_fence_digest
terminal_operation_id
closed reason_code
observed_manifest_digest?   # retire only
```

Abort requires exact fence, no valid manifest, no writer/restore lease, exact partial cleanup and final-manifest absence readback. Retire requires exact published fence+manifest, no abort and no restore lease.

State is terminal-first:

```text
valid standalone retire -> retired/non-restorable
valid standalone abort  -> aborted-before-publish
fence + matching manifest + no terminal -> published/restorable
fence + no valid manifest/terminal      -> preparing/publication_unknown
other malformed/mismatch/ambiguity      -> unresolved/fail closed
```

Terminalization is not erasure.

## 11. Release, retention and erasure

`inference.cancel` applies only to the caller's queued call before sending. `inference.release` disposition is:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

Before release, mutation owner obtains a current backup-set snapshot and rechecks immediately before send. Any restorable backup or unresolved fence marking the call dependent blocks release.

Controller-owner `inference.erase` is local non-disclosing break-glass. Memory cannot submit it and records owner-action debt until readback.

`retain_after_seq` guarantees complete membership above the cut. Calls at/below cut may prune only when terminal, copies released/absent and no readback remains. Open/unknown/unreleased calls never prune merely because they are below cut.

Required cut is the minimum high-water among published non-retired backups and unresolved preparing/publication-unknown fences. In-cut dependencies remain unreleased rather than lowering the monotonic cut. Erasing content above cut leaves a bounded text-free membership tombstone until cut advances.

## 12. Bounded restore lease and candidate custody

Restore is admitted only by daemon backup-set owner. Before candidate work it validates finite manifest limits:

```text
part_count <= configured hard maximum
part_bytes <= per-part maximum
total_part_bytes <= total restore maximum
all relative paths canonical and unique
```

The lease holds for the whole restore:

- one logical lease bound to backup ID/plan/manifest;
- a no-follow handle to the final directory;
- no-follow handles to `fence.json` and `manifest.json`;
- share mode `FILE_SHARE_READ` only for those retained handles, denying write/delete/rename opens;
- a final terminal-record and manifest-identity recheck immediately before cutover decision.

It does **not** retain a handle for every part. Parts are streamed in deterministic manifest order:

1. open one part no-follow with read access and `FILE_SHARE_READ` only;
2. verify regular-file identity, canonical relative path, exact length and digest;
3. copy and verify it into the candidate;
4. close the part handle before opening the next part.

The daemon owner prevents its own retirement/cleanup while leased; the active part handle prevents replacement during read; digest verification detects pre-open substitution. This closes the race without an unbounded kernel-handle set.

Supervisor receives only closed backup identity/digests and candidate/cutover intent. It owns candidate process/root, not backup-file authority.

Daemon/channel loss while candidate exists requires supervisor to terminate, reap and discard candidate before another daemon starts or cutover proceeds. Supervisor loss is contained by its Job. A scan without a held lease is not restore authority.

## 13. Restore and stale mirrors

In-cut restored jobs:

```text
controller_closed       restore from backup facts; controller row may be absent
controller_dependent    exact call and required copy must remain
retired_not_admitted    never send old ID
admission_unknown       hold; inference disabled
```

Capture one inventory high-water and page fixed interval `(backup_high_water, inventory_high_water]`. Post-cut results are outside restored cognition. Valid caller uses dependency-aware cleanup; missing caller creates owner-action debt.

Before ordinary job claims, daemon scans installation records, reconstructs backup state, reconciles Store maintenance mirrors and marks future-timeline/unmatched rows `superseded_by_installation_state`. Such rows cannot create terminal records, clear pins or send old release/retention effects.

Any history gap, unknown auxiliary mutation, terminal ambiguity, limit violation, missing dependent copy or identity reset leaves inference disabled while Base remains usable.

## 14. Store/query compatibility required by Memory

Although controller does not own Memory Store, the consumer contract relies on three exact Memory-side facts:

1. BM25 score queries use numbered match references:

```text
WHERE search_text @0@ $query
SELECT ..., search::score(0) AS score
ORDER BY score DESC, canonical_id ASC
LIMIT $hard_limit
```

A zero BM25 score is a valid match. Base lexical retrieval is one bounded top-K snapshot per call, not a durable page cursor across corpus changes.

2. Schema admission uses plain `INFO FOR DB` / `INFO FOR TABLE` maps. `STRUCTURE` is forbidden because it is an internal unstable output. Memory parses owned maps, sorts keys and compares exact pinned-version server-canonical `DEFINE` strings; raw JSON object byte order is irrelevant.

3. Schema-bundle identity includes a runner protocol version and exact transactional wrapper template in addition to ordered DDL assets. Bound generation/digest values are outside the preimage, avoiding self-reference.

These requirements prevent restore/inference consumers from relying on an ambiguous Memory Store schema or lexical continuation.

## 15. Rotation and request shape

Memory selection keeps current, pending and at most one previous credential for exact controller/client/version. Unknown rotation retries the same owner WriteId and token derivation. Pending identity must authenticate and read a pre-rotation call before promotion. Previous secret retires only after reconnect, old-call read/release and restart readback.

Initial `inference.text` accepts one bounded exact UTF-8 prompt, digest/length, profile, origin, disclosure, closed response format and finite output/time limits.

Initial adapter is a closed loopback-compatible OpenAI chat-completions subset: one model, one user message, admitted max tokens and optional JSON-object format. No tools, streaming, arbitrary fields, ambient proxy, redirects, hidden retry or fallback. Loopback does not prove local destination.

## 16. Implementation order and evidence

P1a begins only after controller #200 and V2 L0/L1:

1. stable controller identity and scoped registration;
2. identity/current-token fence;
3. profile/destination/disclosure admission;
4. WriteId-backed text call and private copies;
5. get/read/cancel/release/high-water/list/retention;
6. tombstones and owner break-glass;
7. Memory external-ID state and mutation owner;
8. daemon backup-set owner, atomic first fence and terminal records;
9. call/auxiliary cut and dependency classification;
10. bounded restore lease/candidate crash custody and stale-mirror reconciliation;
11. one episode result copied, decoded, consumed later and released.

P1b adds install/rotate lost-reply reconciliation, stale-session reaping and delayed previous-secret retirement. Embeddings and direct HTTPS are later increments.

Required evidence includes same-ID live replay, one provider attempt, cut disposition for every external mutation, final directory never visible without fence, pre-rename temp never pins, post-rename unknown pins after reconciliation, terminal marker survives cleanup, bounded part streaming under finite limits, restore lease blocks retirement/deletion, daemon loss discards candidate, dependent call remains unreleased, fixed inventory returns history gap below cut, exact-caller result access and one episode revision changing later context.

## 17. Frozen non-goals

Do not:

- implement in controller V1;
- use Agent/Goal/automation/script/MCP/CLI subprocess per call;
- accept owner/Agent/no-token fallback;
- invent another Operation/Task/submission ledger;
- add a controller backup-pin service/table;
- derive backup IDs or WriteIds from rollback Store state;
- create an empty final backup directory;
- retain unbounded part handles for restore;
- use unstable `INFO ... STRUCTURE` as schema API;
- expose a lexical cursor whose BM25 corpus snapshot is not retained;
- restore without a held lease;
- let Store mirrors create installation authority;
- first-admit absent old IDs from backup;
- release pinned calls or advance retention past pinned high-water;
- let Memory submit controller-owner erase;
- store prompts/results/secrets in receipts/logs/generic artifacts;
- claim provider-side deletion or non-execution from local cleanup.