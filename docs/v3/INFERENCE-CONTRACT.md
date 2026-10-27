# Eliot V3 — One-shot inference contract

**Revision 0.10-draft · 2026-10-26 · shared Memory OS ↔ `eliot-swarm-controller` V2 boundary; not implemented.**

This is the sole normative contract for one-shot text and embedding execution. Memory owns semantic work; controller owns authenticated physical model execution and bounded temporary copies. The boundary does **not** create a controller Agent, native session, Goal, Task/Attempt/review workflow, automation run, script, generic service-account platform, second receipt store or hidden retry ladder.

## 0. Current authority and prerequisites

The inspected controller authority for this revision is:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

That V2 specification selects local JSON-RPC, one SQLite WAL Store, canonical global ULID `WriteId` receipts and a fresh layered implementation. The existing Rust/`swarm-client`/generic Operation runtime is V1 legacy pending deletion and is a donor only.

Current prerequisites are explicit:

- controller V2 roadmap L0.1–L1.11 is still unimplemented;
- controller issue #200 must repair binding-revision allocation and restore green schema validation before L0/L1 implementation;
- PR #201 repairs only invalid validator fixtures and does not close the allocator defect;
- controller issue #199 owns the future Memory extension after V2 L0/L1 and #200;
- no Memory implementation may patch the retired V1 runtime to make this contract appear available.

Source/design completion is not runtime qualification.

## 1. Ownership

Memory owns:

- the finite job and its exact sources/coverage;
- processing-method revision;
- disclosure reduction;
- exact request bytes and every Memory-side external `WriteId`;
- result verification/copy;
- cognitive decoding/publication;
- later consumer;
- backup/restore disposition of its jobs.

Controller owns:

- caller authentication and current credential fence;
- static inference connection/profile configuration;
- actual destination and disclosure admission;
- global `WriteId` receipt semantics;
- provider invocation/readback;
- private input/result copies;
- bounded call status, retention and cleanup facts.

Controller owner may install/rotate/disable a Memory principal and erase exact calls without reading result bytes. It cannot adopt caller ownership or fabricate a Memory result.

## 2. Principal and credential identity

Controller adds one principal kind:

```text
memory_inference
```

One principal represents one stable Memory installation:

```text
client_id = memory:<stable-memory-installation-id>
```

The installation ID is a random non-secret installation identity, not a path, username, PID, root generation, backup generation, executable digest or token digest.

Distinct values:

```text
controller_id      stable non-secret identity of one controller data root
client_id          stable logical Memory caller and call owner
token_version      positive monotonic current credential version
raw token          replaceable authentication material
```

`client_id` survives daemon restart, Memory Store cutover, exact rollback, backup restore and token rotation. Existing calls remain owned by `client_id`; rotation changes only authentication material. Changing `client_id` is unsupported principal migration.

Every controller-backed Memory job retains, without secrets:

```text
controller_id
controller_client_id
selected_token_version
inference_write_id
method + canonical semantic request identity
controller admission_seq when known
profile/connection/adapter/destination snapshot
result digest/length when present
cancel WriteId when created
release WriteId + disposition when created
per-copy cleanup state
```

No backup contains the raw token, token hash, controller routing key, provider credential or reusable verifier.

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
inference.embed                 # after the connected text path
inference.cancel                # own queued call only
inference.release
inference.retention.advance
```

Controller-local owner maintenance, never callable as `memory_inference`:

```text
memory.client.install
memory.client.rotate
memory.client.disable
inference.erase                 # non-disclosing exact cleanup/abandonment
```

No call creates/reuses a controller Agent, generation, binding, turn, command, Goal, rule activation, automation action, workspace, native harness session, Task, Attempt, review, submission or acceptance object.

## 4. Provisioning and private credential publication

Memory never receives controller owner authority or direct controller Store access.

A controller-local owner command installs/rotates one principal through the normal owner `WriteId` path. It:

1. resolves the current controller data root and stable `controller_id`;
2. commits one exact registration/version transition;
3. derives the raw Memory token with a dedicated domain tag from controller-private routing key + `client_id` + `token_version`;
4. stores only version/hash in SQLite;
5. publishes the raw token only into a create-new private credential bundle;
6. returns bounded non-secret identity/readback.

The credential destination is presentation, not registration identity. It must be under an explicitly admitted private directory/handle, with no reparse traversal, restrictive DACL, create-new semantics, file and parent-directory durability and exact readback. Arbitrary absolute-path write authority is not exposed. Raw token never enters argv, SQLite, receipt result, logs, diagnostics or status.

Lost install/rotate reply retries the same owner `WriteId`; controller re-derives the same token. Missing/mismatched routing key blocks issue/reissue. An already presented retained token may still verify against its hash for bounded cleanup/readback, matching V2 routing-key failure semantics.

## 5. Connection identity and current-version fence

Memory uses the controller V2 JSON-RPC transport implementation. It does not use MCP, spawn the general CLI per application call, copy framing code or use retired `swarm-client`.

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

Memory requires exact equality with installation selection and credential bundle before any application call. Missing/malformed/mismatched fields close the connection with a typed failure.

Before **every** Memory read/mutation, controller reloads registration and requires:

```text
registration exists and is enabled
principal kind == memory_inference
principal.client_id == registration.client_id
principal.token_version == registration.token_version
presented token matches current hash
peer classification is not ambiguous
```

A stale authenticated connection receives `credential_stale` and closes after the terminal response. The new token version may read/release pre-rotation calls because ownership is stable `client_id`.

## 6. Installation-scoped external WriteId generator

V2 external `WriteId` is a **global** canonical 26-character ULID, not a per-principal namespace. Memory therefore owns one locked atomic generator state outside selected/rollback Store roots, for example:

```text
controller-write-id.state {
  controller_id
  client_id
  last_ulid
}
```

Generation order:

1. authenticate `client.identity` and observe controller floor/future-skew bounds;
2. lock the state file;
3. generate a monotonic ULID strictly after the retained local value and with timestamp at least the admitted daemon floor/current monotonic time;
4. atomically publish and read back the new generator state;
5. persist that exact WriteId in the owning Memory job/maintenance record;
6. only then send the controller mutation.

A crash after generator advancement but before job commit merely burns an ID. A job may never be sent with an ID that was not durably retained. Exact Memory rollback does not roll this installation-scoped state backward.

This rule applies to:

```text
inference.text/embed
inference.cancel
inference.release
inference.retention.advance
```

A total installation-state loss is a declared continuity gap: reinitialize only after exact controller identity/floor readback; never reuse a retained job's semantic request under a newly invented ID.

## 7. Inference call identity and replay

Memory commits the call `WriteId` and exact request bytes/digest before first send. Call identity is:

```text
WriteId globally unique
+ principal = client_id
+ method
+ canonical semantic payload digest
```

Canonical payload contains only behavior-changing bounded fields:

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

Normal V2 rules:

```text
existing ID + same principal/method/payload -> original/current call
existing ID + any mismatch                 -> id_conflict
valid absent ID                            -> first admission only
absent below retained floor/window         -> id_expired
absent excessive future ID                 -> id_future
```

After disconnect/restart/restore, Memory deliberately invokes the same method with the same retained WriteId and exact bytes. Controller returns the existing call or performs first admission. There is no separately discovered Operation ID and no Memory `possible_send/proven_no_send` ledger.

Provider-send uncertainty is retained call state, never permission to use another WriteId.

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

`last_admission_seq` and `retain_after_seq` begin at 0. On first admission, one transaction checks signed-64 exhaustion, increments `last_admission_seq`, inserts receipt/call and retains the allocated sequence. Never derive sequence from `MAX(inference_calls)` after pruning.

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
  created_at,
  updated_at
}
```

Raw input/result bytes, provider credentials and raw provider errors do not enter receipts/call rows.

## 9. Profiles, destination and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile` records distinct from Agent harness profiles.

Connection owns versioned adapter/transport, canonical endpoint, named private provider credential reference, `actual_destination = local|external` and explicit transport-security behavior.

Profile owns connection/digest, requested model, automatic-use permission, finite input/output/time/concurrency/batch limits and supported response formats.

A loopback gateway forwarding to cloud is external. Memory chooses a profile name only. It cannot supply arbitrary endpoint, headers, provider extras, fallback or retry ladder.

Memory reduces contributing material to `local_only|external_allowed`; derived content cannot widen a stricter source it still reveals. Controller resolves actual destination and checks disclosure before provider I/O. Unavailable profile/capacity or mismatch is operational failure/waiting, not cognitive no-change.

## 10. Controlled input/result copies

One call creates at most:

```text
inference_input
inference_result
```

They are private deterministic call-owned files, not generic nonsecret artifacts.

For a valid absent call WriteId, controller validates caller/profile/disclosure/limits, durably publishes exact input without replacement, then rechecks receipt and atomically inserts receipt + queued call. Orphan files are non-dispatchable cleanup material. Committed call with missing/mismatched input is `damaged`.

A visible result is written as one bounded private envelope, durably published and verified before transactional settlement. Restart may finish settlement from an exact pending envelope. Settled row with missing/mismatched result is `damaged`.

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

Possible provider send followed by ambiguous loss becomes `unknown` unless exact native readback resolves it. Restart rules:

```text
queued + verified input -> eligible once
sending/accepted        -> exact readback or unknown
verified pending result -> finish settlement
abandoned               -> never dispatch/publish late result
```

## 12. Read, cancel, release and owner erasure

`inference.get` returns bounded non-content status only to exact current `client_id`.

`inference.result.read` requires exact ownership, current credential, retained matching result and bounded range. It returns exact bytes plus offset/length/digest; never another call/result.

`inference.cancel` has its own precommitted WriteId and can cancel only exact caller's queued call before sending. After possible provider I/O it cannot prove non-execution.

`inference.release` has its own precommitted WriteId and one disposition:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

Controller verifies deterministic file provenance/identity/digest, exact deletion and parent-directory durability. Missing exact file becomes `already_absent`; mismatch blocks deletion; partial cleanup remains visible/retryable.

Controller owner `inference.erase` accepts exact non-content caller/call/range identity, fences future dispatch/settlement/publication and returns cleanup facts only. Owner cannot read result bytes or adopt caller ownership.

Out-of-target restore cleanup uses an ordinary durable Memory cleanup job/record containing exact call identity and its cancel/release/erase WriteId before send. Lost cleanup replies replay the same ID; no unrecorded cleanup effect is created.

## 13. Guaranteed retention and bounded inventory

`retain_after_seq` is the controller's **guaranteed completeness cut**, not merely the earliest row currently present.

Meaning:

```text
every call with admission_seq > retain_after_seq
must retain bounded non-content metadata
```

Calls at/below the cut may be pruned only when terminal, every local copy is released/absent, no open effect/readback remains and receipt/FK rules permit deletion. Open/unknown/unreleased calls are never pruned merely because they are below the cut.

`inference.high_water` returns:

```text
high_water = last_admission_seq
retain_after_seq
observed_earliest_retained_seq?   # diagnostic only
```

Observed earliest physical row is not a restore guarantee.

`inference.list` captures one immutable membership bound:

```text
after_admission_seq
through_admission_seq <= authenticated high_water
cursor?
limit
```

The cursor binds controller/client identity, after/through bounds, API version and page shape. State may change during paging; membership `(after, through]` cannot. If `after_admission_seq < retain_after_seq`, return `history_gap` even when some older rows happen to remain.

`inference.retention.advance` is a normal receipted mutation:

```text
write_id
expected_retain_after_seq
new_retain_after_seq
```

It only increases, checks expected current value and never exceeds admitted high-water. Same WriteId replay is exact; mismatch conflicts.

## 14. Backup-set retention lifecycle

For exact `controller_id + client_id`, Memory computes:

```text
required_retain_after_seq =
  minimum controller high_water among every locally retained restorable backup
```

If no restorable backup remains, Memory may advance to a current durable continuity cut.

Rules:

1. publish/retire the local backup generation durably and read back the resulting controlled backup set;
2. persist a Memory maintenance record with exact expected/new cut and retention-advance WriteId;
3. send `inference.retention.advance`;
4. reconcile lost reply with the same WriteId;
5. never lower the cut after restoring older Memory state.

Crash before advance is conservative. Advancing before durable backup-set readback is invalid. A newly retained backup whose high-water is below current `retain_after_seq` is not controller-continuous and must be rejected or marked with explicit `history_gap` risk.

Portable/off-machine copies are outside initial controlled backup ownership and do not pin controller retention unless a future explicit registration protocol is added.

## 15. Memory backup and rollback

A controlled Memory backup records:

```text
controller_id
controller_client_id
selected token_version
controller high_water
controller retain_after_seq
all in-cut job WriteIds/canonical identities
known result/release/cleanup facts
```

Before the cut, Memory stops new controller admissions, persists every created WriteId, reconciles active submission/readback to a typed state, authenticates exact caller and reads high-water/retention.

The installation-scoped WriteId generator state is not rolled back with the Store root.

### In-cut jobs

After restore, each retained job uses the same WriteId/exact bytes:

```text
same call exists -> read/cancel/release original
valid absent call -> first admission
payload mismatch -> id_conflict
caller unavailable -> hold; no call
```

### Post-cut calls

Memory captures one inventory `through_admission_seq = current high_water`, then pages:

```text
inference.list(after = backup_high_water, through = inventory_high_water)
```

Every returned call is out of target. Its result is not adopted as cognition without exact restored job/source/publication mapping. Each call must become terminal/released or explicitly abandoned/erased with durable local disposition. Unknown provider effects remain unknown.

All new controller-backed inference stays disabled until the inventory is complete and every row is dispositioned. Base capture/retrieval remains usable.

`history_gap`, unavailable controller/caller or identity reset leaves `external_work_inventory_unavailable`; it never becomes an empty set or complete rollback claim.

## 16. Rotation and disable

Memory selection keeps at most current, pending and one unretired previous credential reference for exact controller/client/version. Another rotation waits.

Unknown rotate/file result retries the same owner WriteId and re-derives the same token. Pending identity must authenticate and read a pre-rotation call under unchanged client_id before selection promotion. Old authenticated transports are fenced by current-version checks. Previous credential retires only after daemon reconnect, old-call read/release and restart/readback.

Disabling a client is separate. It blocks new calls and must explicitly disposition queued/unknown calls/copies; it is not rotation.

## 17. Initial request shapes and adapters

`inference.text` uses one bounded exact UTF-8 prompt, digest/length, profile, origin, disclosure, closed response format and finite output/time limits.

`inference.embed` later uses bounded keyed inputs and one result/error per input key, with exact effective vector-space identity, count/index/dimension/order and finite-value checks. No zero-vector repair.

Initial text adapter is a closed loopback-compatible OpenAI chat-completions subset: one model, one user message, admitted max tokens and optional typed JSON-object format. No tools, streaming, temperature, stop list, arbitrary fields, ambient proxy, redirects, hidden retry or fallback. Loopback does not prove local destination. Direct HTTPS is later and separately qualified.

## 18. Implementation order

### P1a — after controller V2 L0/L1 and #200

1. stable controller identity;
2. client registration with `last_admission_seq` and `retain_after_seq`;
3. `client.identity` and current-version fence;
4. connection/profile/disclosure admission;
5. global WriteId-backed `inference.text`, call-owned input/result and bounded runner;
6. get/range-read/cancel/release/high-water/list/retention-advance and non-disclosing erase;
7. Memory installation-scoped WriteId generator and durable auxiliary mutation IDs;
8. one episode result copied, decoded, published, consumed later and released;
9. backup high-water/retention/inventory round-trip.

### P1b

Install/rotate lost-reply reconciliation, stale transport reaping, pending/current/previous selection and delayed retirement.

### Later

Embeddings, direct HTTPS, richer provider readback and larger streaming payloads only after measured need.

## 19. Required verification

Eventually prove:

- exact controller V2 implementation revision and #200 closure;
- global WriteId collision and floor/future behavior;
- generator continuity across Memory rollback;
- same call WriteId before send/lost reply/restart/restore;
- auxiliary cancel/release/retention IDs before send;
- per-client admission allocator exhaustion and no `MAX+1` derivation;
- retain-after advance ordering, history gap and stable list paging;
- install/reissue/rotation with safe private credential publication;
- no owner/Agent/automation fallback;
- input copy before provider I/O and orphan/damaged cases;
- queued→sending crash and possible-send→unknown without second provider attempt;
- result settlement/range read and owner result-byte denial;
- independent input/result cleanup and partial retry;
- profile/destination/disclosure/capacity denial before provider I/O;
- backup in-cut replay, post-cut inventory and out-of-target cleanup records;
- controller unavailable/history gap leaves inference disabled while Base remains useful.

## 20. Frozen non-goals

Do not:

- implement this in controller V1;
- use controller Agent/Goal/automation/script/MCP/CLI subprocess per inference call;
- accept owner/Agent/no-token fallback;
- invent another Operation/Task/submission ledger;
- derive admission sequence from retained rows;
- use observed earliest row as a retention guarantee;
- roll back/reuse the Memory WriteId generator;
- generate unrecorded cancel/release/cleanup IDs after a failure;
- store raw tokens/provider secrets/prompts/results in receipts/logs/generic artifacts;
- expose result bytes to owner erase;
- retry/redirect/fallback provider calls after possible send;
- claim provider-side deletion/non-execution from local cleanup.