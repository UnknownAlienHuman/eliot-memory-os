# Eliot V3 — One-shot inference contract

**Revision 0.13-draft · 2026-10-26 · shared Memory OS ↔ `eliot-swarm-controller` V2 boundary; not implemented.**

This is the sole normative contract for one-shot text and embedding execution. Memory owns semantic work; controller owns authenticated physical model execution and bounded temporary copies. The boundary does **not** create a controller Agent, native session, Goal, Task/Attempt/review workflow, automation run, script, generic service-account platform, second receipt store or hidden retry ladder.

## 0. Current authority and prerequisites

Inspected controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

That V2 specification selects local JSON-RPC, one SQLite WAL Store, canonical global ULID `WriteId` receipts and a fresh layered implementation. Existing Rust/`swarm-client`/generic Operation runtime is V1 legacy pending deletion and donor-only.

Current prerequisites:

- controller V2 roadmap L0.1–L1.11 is unimplemented;
- issue #200 must repair binding-revision allocation/schema authority before L0/L1;
- PR #201 fixes validator fixtures only, not allocator semantics;
- issue #199 owns this later Memory extension after #200 and V2 L0/L1;
- no Memory implementation may patch controller V1 to make this contract appear available.

Source/design completion is not runtime qualification.

## 1. Ownership

Memory owns:

- finite job, exact sources and coverage;
- processing-method revision and disclosure reduction;
- exact request bytes and every Memory-side external `WriteId`;
- result verification/copy, cognitive decoding/publication and later consumer;
- backup admission closure, dependency classification, provisional publication fences and release fences;
- its caller-authorized cancel/release requests.

Controller owns:

- caller authentication and current-credential fence;
- inference connection/profile configuration and actual destination;
- global `WriteId` receipt semantics;
- provider invocation/readback;
- private input/result copies;
- call status, retention, erased tombstones and cleanup facts.

Controller owner may install/rotate/disable a Memory principal and perform local break-glass erase without reading result bytes. Memory never receives owner authority, cannot submit owner erase and cannot adopt an owner receipt as its own effect.

## 2. Principal, credential and job identity

Controller adds one principal kind:

```text
memory_inference
```

One principal represents one stable Memory installation:

```text
client_id = memory:<stable-memory-installation-id>
```

Distinct values:

```text
controller_id      stable non-secret identity of one controller data root
client_id          stable logical Memory caller and call owner
token_version      positive monotonic current credential version
raw token          replaceable authentication material
```

The installation ID is random and non-secret; it is not a path, username, PID, Store-root generation, backup generation, executable digest or token digest. `client_id` survives Memory restart, Store-root cutover, exact rollback, backup restore and token rotation. Changing it is unsupported principal migration.

Every controller-backed Memory job retains, without secrets:

```text
controller_id
controller_client_id
selected_token_version
inference_write_id
method + canonical semantic request identity
controller_admission_state
controller_admission_seq when admitted
controller_dependency_state
profile/connection/adapter/destination snapshot
result digest/length when present
cancel WriteId when created
release WriteId + disposition when created
per-copy cleanup state
```

Admission state:

```text
prepared
admitted
retired_not_admitted
admission_unknown
```

Backup dependency state for an admitted call:

```text
controller_closed
controller_dependent
```

`retired_not_admitted` is terminal for that call WriteId: exact healthy cut readback proved absence, and the ID can never be sent later. No backup contains raw token, token hash, routing key, provider credential or reusable verifier.

## 3. Exact JSON-RPC surface

Authenticated `memory_inference` reads:

```text
client.identity
inference.get
inference.list
inference.high_water
inference.result.read
```

Authenticated mutations, each with a precommitted global external `WriteId`:

```text
inference.text
inference.embed                 # after connected text
inference.cancel                # own queued call only
inference.release
inference.retention.advance
```

Controller-local owner maintenance, never callable as `memory_inference`:

```text
memory.client.install
memory.client.rotate
memory.client.disable
inference.erase                 # break-glass, non-disclosing owner cleanup
```

No call creates or reuses a controller Agent, generation, binding, turn, command, Goal, rule activation, automation action, workspace, native harness session, Task, Attempt, review, submission or acceptance object.

## 4. Provisioning and private credential publication

Memory never receives controller owner authority or direct controller Store access.

A controller-local owner command installs or rotates one principal through the normal owner `WriteId` path. It:

1. resolves current controller root and stable `controller_id`;
2. commits one exact registration/version transition;
3. derives raw Memory token with a dedicated domain tag from private routing key + `client_id` + `token_version`;
4. stores only version/hash in SQLite;
5. publishes raw token only into a create-new private credential bundle;
6. returns bounded non-secret identity/readback.

Destination is presentation, not registration identity. It must be under an admitted private directory/handle, with no reparse traversal, restrictive DACL, create-new semantics, file and parent-directory durability and exact readback. Arbitrary absolute-path write authority is not exposed. Raw token never enters argv, SQLite, receipt result, logs, diagnostics or status.

Lost install/rotate reply retries the same owner `WriteId` and re-derives the same token. Missing/mismatched routing key blocks issue/reissue. An already presented token may still verify against retained hash for bounded cleanup/readback, matching V2 routing-key failure semantics.

## 5. Connection identity and current-version fence

Memory uses controller V2 JSON-RPC transport implementation. It does not use MCP, spawn general CLI per application call, copy framing code or use retired `swarm-client`.

Authenticated `client.identity` returns:

```text
controller_id
client_id
principal = memory_inference
token_version
api_version
write_id_floor_ms
write_id_future_skew_ms
```

Memory requires exact equality with installation selection and credential bundle before any application call. Missing, malformed or mismatched fields close the connection with a typed failure.

Before **every** Memory read or mutation, controller reloads registration and requires:

```text
registration exists and is enabled
principal kind == memory_inference
principal.client_id == registration.client_id
principal.token_version == registration.token_version
presented token matches current hash
peer classification is not ambiguous
```

A stale authenticated connection receives `credential_stale` and closes after the terminal response. A new token version may read/release pre-rotation calls because ownership is stable `client_id`.

## 6. Installation-scoped external WriteId generator

V2 external `WriteId` is a **global** canonical 26-character ULID, not a per-principal namespace. Memory owns one locked atomic generator state outside selected/rollback Store roots:

```text
controller-write-id.state {
  controller_id
  client_id
  last_ulid
}
```

Generation order:

1. authenticate `client.identity` and observe controller floor/future-skew;
2. lock state file;
3. generate monotonic ULID after retained value and at least admitted floor/current monotonic time;
4. atomically publish and read back generator state;
5. persist exact WriteId in owning Memory job/maintenance record;
6. only then send controller mutation.

Crash after generator advancement but before job commit burns an ID. A job may never be sent with an ID not durably retained. Exact Memory rollback does not roll this file backward.

This applies to:

```text
inference.text/embed
inference.cancel
inference.release
inference.retention.advance
```

Total installation-state loss is a declared continuity gap. Reinitialize only after exact controller identity/floor readback; never replay a retained job under an invented replacement ID.

## 7. Live call identity and replay

Memory commits call `WriteId` and exact request bytes/digest before first send. Call identity:

```text
WriteId globally unique
+ principal = client_id
+ method
+ canonical semantic payload digest
```

Canonical payload contains behavior-changing bounded fields only:

```text
method
profile name
origin = explicit | automatic
disclosure = local_only | external_allowed
input digest + exact byte length
response/embedding role
finite output/time/batch limits
```

It excludes transport request ID, connection metadata, pager/display options, client timeout and wait duration.

Normal live V2 rules:

```text
existing ID + same principal/method/payload -> original/current call
existing ID + any mismatch                 -> id_conflict
valid absent ID                            -> first admission only
absent below retained floor/window         -> id_expired
absent excessive future ID                 -> id_future
```

After normal disconnect or daemon restart, Memory deliberately invokes the same method with the same retained WriteId and exact bytes. Controller returns the existing call or performs first admission. Provider-send uncertainty is retained call state, never permission to use another WriteId.

**Restore is stricter:** an old backup never first-admits an absent call WriteId. Section 15 owns cut classification and restore behavior.

## 8. Minimal durable controller state

Reuse V2 `write_receipts`. Add only:

```text
memory_inference_clients
inference_calls
private call-owned inference_input/result files
```

Conceptual registration:

```text
MemoryInferenceClient {
  client_id,
  token_version,
  token_hash,
  disabled,
  last_admission_seq,
  retain_after_seq,
  created_at,
  updated_at
}
```

`last_admission_seq` and `retain_after_seq` begin at 0. First admission transaction checks signed-64 exhaustion, increments `last_admission_seq`, inserts receipt/call and retains allocated sequence. Never derive sequence from `MAX(inference_calls)` after pruning.

Conceptual call:

```text
InferenceCall {
  id = WriteId,
  admission_seq,
  caller_id,
  method,
  canonical_payload_digest,
  frozen profile/connection/adapter/destination,
  origin,
  disclosure,
  input digest/length/copy state,
  state,
  native_request_id?,
  result digest/length/copy state?,
  observed model/usage/cost/account when supplied,
  terminal_code?,
  erased_tombstone?,
  created_at,
  updated_at
}
```

Raw input/result bytes, provider credentials and raw provider errors do not enter receipts/call rows.

## 9. Profiles, destination and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile` records distinct from Agent harness profiles.

Connection owns versioned adapter/transport, canonical endpoint, named private provider credential reference, `actual_destination = local|external` and explicit transport-security behavior. Profile owns connection/digest, requested model, automatic-use permission, finite input/output/time/concurrency/batch limits and supported formats.

A loopback gateway forwarding to cloud is external. Memory chooses a profile name only. It cannot supply arbitrary endpoint, headers, provider extras, fallback or retry ladder.

Memory reduces contributing material to `local_only|external_allowed`; derived content cannot widen a stricter source it still reveals. Controller resolves destination and checks disclosure before provider I/O. Unavailable profile/capacity or mismatch is operational failure/waiting, not cognitive no-change.

## 10. Controlled input/result copies

One call creates at most:

```text
inference_input
inference_result
```

They are private deterministic call-owned files, not generic artifacts.

For a valid absent live call WriteId, controller validates caller/profile/disclosure/limits, durably publishes exact input without replacement, then rechecks receipt and atomically inserts receipt + queued call. Orphan files are non-dispatchable cleanup material. A committed call with missing/mismatched input is `damaged`.

A visible result is written as one bounded private envelope, durably published and verified before transactional settlement. Restart may finish settlement from an exact pending envelope. A settled row with missing/mismatched result is `damaged`.

Per-copy state:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Aggregate cleanup is derived: `retained | cleanup_pending | cleanup_incomplete | released`.

## 11. Bounded runner and provider uncertainty

One internal bounded runner:

1. selects eligible queued call under frozen profile concurrency;
2. verifies exact input/current registration/frozen profile;
3. CAS `queued -> sending` before provider I/O;
4. performs at most one provider attempt;
5. retains native request/readback identity when available;
6. publishes exact result when present and settles bounded facts;
7. never performs hidden retry, redirect or fallback.

Possible provider send followed by ambiguous loss becomes `unknown` unless exact native readback resolves it.

```text
queued + verified input -> eligible once
sending/accepted        -> exact readback or unknown
verified pending result -> finish settlement
abandoned               -> never dispatch/publish late result
```

## 12. Caller cleanup, backup release fences and owner break-glass

`inference.get` returns bounded non-content status only to exact current `client_id`.

`inference.result.read` requires exact ownership, current credential, retained matching result and bounded range. It returns exact bytes plus offset/length/digest; never another call/result.

`inference.cancel` has its own precommitted WriteId and can cancel only exact caller's queued call before sending. After possible provider I/O it cannot prove non-execution.

`inference.release` has its own precommitted WriteId and one disposition:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

`abandon_for_erasure` is the normal caller-authorized fence against future dispatch, settlement and publication. Controller verifies deterministic file provenance/identity/digest, exact deletion and parent-directory durability. Missing exact file becomes `already_absent`; mismatch blocks deletion; partial cleanup remains visible/retryable.

Normal cleanup with a valid caller:

```text
queued call: optional inference.cancel
then inference.release(...)
```

Before sending any release that could delete state or bytes, Memory checks both:

1. every locally retained restorable backup manifest; and
2. every unresolved provisional backup-dependency fence.

If either marks the call `controller_dependent`, release is blocked and remains pending. Current Memory may copy/use a result, but controller state/copies needed by a backup candidate remain unreleased.

Once all dependent backups are retired/replaced/non-restorable and every provisional publication outcome is reconciled, the release fence clears and ordinary cleanup may proceed. Erasure first deletes or invalidates every dependent controlled backup/candidate, then uses caller abandon.

Controller-owner `inference.erase` is a **local break-glass path** for a missing/disabled caller or explicit emergency. Its WriteId is generated/submitted by controller owner, not Memory. Memory may retain bounded non-content `owner_action_required` and consume later owner readback, but cannot send owner mutation or claim it from request alone. If caller cleanup is unavailable and no owner result is observed, cleanup remains visible debt and rollback/erasure is incomplete.

## 13. Guaranteed retention, tombstones and bounded inventory

`retain_after_seq` is the guaranteed completeness cut for post-cut membership:

```text
every call with admission_seq > retain_after_seq
must retain bounded non-content membership metadata
```

Calls at/below cut may be pruned only when terminal, every local copy is released/absent, no open effect/readback remains and receipt/FK rules permit deletion. Open, unknown or unreleased calls are never pruned merely because they are below cut.

This no-prune rule also protects an in-cut `controller_dependent` call, even when its sequence is at/below current monotonic cut: Memory keeps required copies unreleased while the backup or provisional publication fence exists.

Erasing a call above cut removes/fences content and sensitive facts immediately but leaves bounded text-free tombstone sufficient for fixed-window inventory:

```text
caller_id
call_id
admission_seq
erased_or_abandoned state
cleanup disposition
```

Tombstone remains until cut advances beyond its sequence. If owner requires deletion of even tombstone, every controlled backup pinning interval must first retire and cut durably advance. Otherwise erasure remains incomplete rather than silently breaking inventory.

`inference.high_water` returns:

```text
high_water = last_admission_seq
retain_after_seq
observed_earliest_retained_seq?   # diagnostic only
```

`inference.list` captures immutable membership bounds:

```text
after_admission_seq
through_admission_seq <= authenticated high_water
cursor?
limit
```

Cursor binds controller/client identity, after/through bounds, API version and page shape. State may change during paging; membership `(after, through]` cannot. If `after < retain_after_seq`, return `history_gap` even when some older rows happen to remain.

`inference.retention.advance` is a normal caller mutation:

```text
write_id
expected_retain_after_seq
new_retain_after_seq
```

It only increases, checks expected current value and never exceeds admitted high-water. Same WriteId replay is exact; mismatch conflicts.

## 14. Backup-set retention lifecycle

For exact `controller_id + client_id`, post-cut denominator requires:

```text
required_retain_after_seq =
  minimum controller high_water among every locally retained restorable backup
```

If no restorable backup remains, Memory may advance to a current durable continuity cut.

Rules:

1. publish/retire local backup generation durably and read back the resulting controlled backup set;
2. persist a Memory maintenance record with exact expected/new cut and retention-advance WriteId;
3. send `inference.retention.advance`;
4. reconcile lost reply with same WriteId;
5. never lower cut after restoring older Memory state.

Crash before advance is conservative. Advance before durable backup-set readback is invalid. A newly retained backup below current cut is not post-cut-controller-continuous and must be rejected or marked with explicit history-gap risk.

In-cut dependencies do **not** lower this monotonic cut. They are protected by backup/provisional manifests plus release fences from §12. This remains correct even when an old dependent call sequence is already below current cut.

Portable/off-machine copies are outside initial controlled backup ownership and do not pin retention/release without a future registration protocol.

## 15. Memory backup admission closure, provisional publication and rollback

A controlled Memory backup records:

```text
controller_id
controller_client_id
selected token_version
controller high_water
controller retain_after_seq
all admitted in-cut call WriteIds + admission_seq + canonical identity
per-call controller_closed | controller_dependent
all retired_not_admitted local attempts
known result/release/cleanup facts
explicit admission/authority gaps
```

Before reading high-water, Memory:

1. stops new controller admissions;
2. pauses/drains the **single controller-dispatch owner** so no send races the cut;
3. persists every created call/cancel/release WriteId;
4. authenticates exact controller/client identity;
5. classifies every call WriteId:
   - `inference.get` proves one call → `admitted`, retain exact `admission_seq`;
   - exact healthy absence with no in-flight sender → `retired_not_admitted`, ID forbidden from later send;
   - unavailable/ambiguous readback → `admission_unknown`, controller continuity incomplete;
6. reconciles created cancel/release from actual call state, or retires a proven-unsent auxiliary mutation;
7. classifies every admitted call:
   - `controller_closed` only when backup contains exact terminal Memory-owned result/no-result, no future controller settlement/publication is possible, and no controller copy/cleanup/readback remains required;
   - otherwise `controller_dependent`;
8. reads `high_water + retain_after_seq`;
9. durably records one ordinary Memory maintenance/job fence containing:
   - backup generation/candidate ID;
   - expected final manifest path/identity and digest;
   - controller/client/high-water/cut facts;
   - exact dependent call IDs/sequences;
   - publication state `preparing`;
10. only then begins publishing backup parts/manifest.

No new table is required. The ordinary maintenance/job owner is sufficient.

### Provisional publication states

```text
preparing
publication_unknown
published
aborted_before_publish
```

The controller-dispatch owner and every release path honor `preparing` and `publication_unknown` as active dependency fences.

If manifest publication completes with exact file and parent-directory durability/readback, Memory atomically marks the backup retained/published in its controlled backup set. The provisional fence is cleared only after backup-set readback includes the exact manifest and the dependency index/scan can reproduce every call.

If failure is definitely before final rename and exact final-path readback proves absence, mark `aborted_before_publish` and clear the provisional fence.

If final rename may have succeeded but directory sync/readback fails, mark `publication_unknown` and keep every dependency fenced. Startup or maintenance reconciliation must:

```text
exact matching final manifest exists
  -> finish parent durability/readback, promote to published retained backup

exact final absent + operation proven pre-rename failure
  -> mark aborted_before_publish, clear fence

malformed/mismatched/ambiguous final state
  -> keep publication_unknown and block release
```

No startup may send release before all unresolved provisional backup fences are reconciled or conservatively retained.

The installation-scoped WriteId generator is not rolled back with Store root.

### In-cut jobs after restore

```text
controller_closed
  restore entirely from backup facts;
  pruned controller row is permitted and must not trigger first admission

controller_dependent
  exact call and every required copy must remain;
  absence/mismatch is damaged/history_gap

retired_not_admitted
  never send old ID; optionally schedule fresh successor after inventory

admission_unknown
  hold; inference remains disabled
```

Payload mismatch is `id_conflict`; unavailable caller holds without call.

### Post-cut calls

Memory captures one inventory `through_admission_seq = current high_water`, then pages:

```text
inference.list(after = backup_high_water,
               through = inventory_high_water)
```

Because every definitely absent cut attempt was retired, returned calls lie outside backup's admitted external-work set. Results are not adopted as cognition. With valid caller, cleanup uses caller cancel/release-abandon after backup/provisional dependency checks. Without caller, Memory records owner-action-required debt and waits for controller-local owner readback.

All new controller-backed inference stays disabled until inventory completes and every row is dispositioned. Base remains usable. `history_gap`, unavailable controller/caller, admission unknown or identity reset leaves `external_work_inventory_unavailable`; it never becomes false empty or complete rollback.

## 16. Rotation and disable

Memory selection keeps at most current, pending and one unretired previous credential reference for exact controller/client/version. Another rotation waits.

Unknown rotate/file result retries same owner WriteId and re-derives same token. Pending identity must authenticate and read a pre-rotation call under unchanged `client_id` before selection promotion. Old authenticated transports are fenced by current-version checks. Previous credential retires only after daemon reconnect, old-call read/release and restart/readback.

Disabling client is separate. It blocks new calls and must explicitly disposition queued/unknown calls/copies; it is not rotation.

## 17. Initial request shapes and adapters

`inference.text` uses one bounded exact UTF-8 prompt, digest/length, profile, origin, disclosure, closed response format and finite output/time limits.

`inference.embed` later uses bounded keyed inputs and one result/error per key, with exact vector-space identity, count/index/dimension/order and finite-value checks. No zero-vector repair.

Initial text adapter is a closed loopback-compatible OpenAI chat-completions subset: one model, one user message, admitted max tokens and optional JSON-object format. No tools, streaming, temperature, stop list, arbitrary fields, ambient proxy, redirects, hidden retry or fallback. Loopback does not prove local destination. Direct HTTPS is later and separately qualified.

## 18. Implementation order

### P1a — after controller V2 L0/L1 and #200

1. stable controller identity;
2. client registration with `last_admission_seq` and `retain_after_seq`;
3. `client.identity` and current-version fence;
4. connection/profile/disclosure admission;
5. global WriteId-backed `inference.text`, call-owned input/result and bounded runner;
6. get/range-read/cancel/release/high-water/list/retention-advance;
7. erased tombstones plus non-disclosing owner break-glass;
8. Memory WriteId generator, dispatch barrier, admission/dependency cut classification;
9. provisional backup publication fences and startup reconciliation;
10. backup dependency release fences;
11. one episode result copied, decoded, published, consumed later and eventually released;
12. backup admission/high-water/retention/inventory round-trip.

### P1b

Install/rotate lost-reply reconciliation, stale transport reaping, pending/current/previous selection and delayed retirement.

### Later

Embeddings, direct HTTPS, richer provider readback and larger streaming payloads only after measured need.

## 19. Required verification

Eventually prove:

- exact controller V2 implementation revision and #200 closure;
- global WriteId collision and floor/future behavior;
- generator continuity across Memory rollback;
- same live call WriteId before send/lost reply/restart;
- backup cut admits, retires or gaps every created call ID before high-water;
- retained backup never first-admits absent old call ID;
- controller-closed job restores without controller row;
- controller-dependent job below current cut blocks release and restores exact row/result;
- crash before manifest rename clears only after exact absence proof;
- rename succeeded + parent-sync/readback failure keeps publication-unknown provisional fence;
- startup blocks release until provisional publication reconciliation;
- backup retirement clears release fence and permits release/prune;
- auxiliary cancel/release/retention IDs and cut reconciliation;
- per-client allocator exhaustion and no `MAX+1` derivation;
- retain-after ordering, erased tombstone membership, history gap and stable paging;
- caller `release(abandon_for_erasure)` versus owner-local break-glass authority;
- missing caller keeps cleanup debt until observed owner readback;
- install/reissue/rotation with safe private credential publication;
- no owner/Agent/automation fallback;
- input copy before provider I/O and orphan/damaged cases;
- queued→sending crash and possible-send→unknown without second provider attempt;
- result settlement/range read and owner result-byte denial;
- independent input/result cleanup and partial retry;
- profile/destination/disclosure/capacity denial before provider I/O;
- post-cut inventory and out-of-target caller cleanup;
- controller unavailable/history gap leaves inference disabled while Base remains useful.

## 20. Frozen non-goals

Do not:

- implement this in controller V1;
- use controller Agent/Goal/automation/script/MCP/CLI subprocess per call;
- accept owner/Agent/no-token fallback;
- invent another Operation/Task/submission ledger;
- add a backup-pin service/table when ordinary maintenance job + manifest is sufficient;
- derive admission sequence from retained rows;
- use observed earliest row as retention guarantee;
- roll back/reuse Memory WriteId generator;
- first-admit absent old call from retained backup;
- send a `retired_not_admitted` WriteId;
- release a controller-dependent call while a retained or provisional backup fence pins it;
- clear a publication-unknown fence without exact final-path reconciliation;
- lower monotonic `retain_after_seq` to pin an in-cut dependency;
- let Memory submit controller-owner erase or invent its receipt;
- delete membership metadata above cut without tombstone or prior cut advance;
- generate unrecorded cancel/release/cleanup IDs after failure;
- store raw tokens/provider secrets/prompts/results in receipts/logs/generic artifacts;
- expose result bytes to owner break-glass;
- retry/redirect/fallback provider calls after possible send;
- claim provider-side deletion/non-execution from local cleanup.