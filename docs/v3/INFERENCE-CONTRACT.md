# Eliot V3 — One-shot inference contract

**Revision 0.9-draft · 2026-10-26 · shared Memory OS ↔ `eliot-swarm-controller` V2 boundary; not implemented.**

This is the sole normative contract for one-shot text and embedding execution. It keeps Memory semantics in Memory and physical model execution in controller. It deliberately does **not** create a controller Agent, native session, Goal, Task/Attempt/review workflow, automation rule/run, generic service-client platform, second receipt store or hidden retry ladder.

## 0. Authority and inspected baseline

The current controller authority inspected for this revision is:

```text
UnknownAlienHuman/eliot-swarm-controller
main = c8c0ee122c98a01be86bc5296a22a389662a1c89
merged PR #197
```

That V2 specification selects local JSON-RPC, one SQLite WAL Store, canonical external ULID `WriteId` receipts, exact caller/custody classification and a fresh layered implementation. It declares the existing Rust/`swarm-client`/Operation stack to be V1 legacy pending deletion.

Therefore:

- controller revision `e42c464d` and its `swarm-client`, roles, generic Operation table and artifact grants remain **donors only**;
- no V3 implementation may add Memory inference to that retired V1 stack;
- controller-specific names in older Memory Architecture/Implementation/Cognition text are superseded by this contract where they conflict;
- controller V2 needs one explicit, narrow Memory inference extension after its L1 Store/API foundation exists.

The contract prevents these failures:

1. implementing against a controller subsystem already selected for deletion;
2. allowing Memory to enter the controller as owner, agent, project automation or generic writer;
3. losing request identity when a reply is lost or Memory is restored;
4. replaying a provider call after a possible send;
5. persisting prompts, embedding input, provider secrets or raw client tokens in generic receipts/config/logs;
6. treating token-file possession as authenticated identity without controller readback;
7. exposing result bytes through owner cleanup authority;
8. restoring an old Memory backup while silently ignoring controller calls admitted after that backup cut;
9. creating another Task/Attempt/Operation or submission-state machine around one bounded model call.

Memory owns the finite job, frozen sources, recipe, disclosure reduction, exact request bytes, decoding, publication and cognitive consumer. Controller owns caller authentication, static inference configuration, provider invocation/readback, `WriteId` idempotency, temporary controlled copies and non-content cleanup facts.

## 1. Exact application surface

Controller V2 adds one principal kind:

```text
memory_inference
```

One principal represents one stable Memory installation. It is not controller owner, an Agent routing principal, a project rule principal, script/action custody or a generic service account. Omitting or clearing its token never falls back to owner authority.

Allowed JSON-RPC methods are exactly:

```text
reads:
  client.identity
  inference.get
  inference.list             # own bounded non-content rows only
  inference.high_water       # own monotonic admission sequence and retained floor
  inference.result.read      # own retained result bytes only

mutations, each with a canonical external WriteId:
  inference.text
  inference.embed
  inference.cancel           # own queued call only
  inference.release

local owner maintenance, not callable as memory_inference:
  memory.client.install
  memory.client.rotate
  memory.client.disable
  inference.erase            # non-disclosing exact cleanup/abandonment
```

No call creates or reuses a controller Agent, generation, turn, command, Goal, rule activation, automation run/action, workspace, native harness session, Task, Requirement, Attempt, review, submission or acceptance object.

`inference.list` is not a general Operation browser. It returns only this exact caller's bounded call identity, admission sequence, state, result-present flag and cleanup disposition. It never returns input/result bytes, prompts, provider errors or another caller's identity.

## 2. Stable caller and credential identity

The boundary has four distinct values:

```text
controller_id      stable non-secret identity of one controller data root
client_id          stable Memory principal identity
token_version      positive monotonic credential version
raw token          current replaceable authentication material
```

For one Memory installation:

```text
client_id = memory:<stable-memory-installation-id>
```

`client_id` survives Memory daemon restart, Store-root cutover, exact rollback, backup restore and token rotation. It is not derived from PID, executable path, Memory data-root generation, backup generation, token digest, time or controller process boot.

Call/result ownership is always `client_id`. `token_version` authenticates the current physical credential and never rewrites existing call ownership or `WriteId`.

Changing `client_id` is principal migration. Initial V3 provides no migration/adoption path. Controller owner cannot relabel old calls to a new client, and Memory cannot recover by inventing a new caller.

Every controller-backed Memory job retains, without secrets:

```text
controller_id
controller_client_id
selected token_version
inference_write_id
method + canonical bounded request identity
controller admission_seq when known
profile/connection/adapter/destination snapshot
result digest/length when present
release/cleanup WriteId and per-copy disposition
```

The Memory backup never contains the raw token, controller `routing.key`, token hash, provider credential or reusable verifier.

## 3. Provisioning and rotation owner

Memory never receives controller owner authority or direct controller Store access.

Provisioning is a controller-local owner command, conceptually:

```text
eliot memory-client install \
  --client-id memory:<installation-id> \
  --credential-out <absolute-private-create-new-path> \
  --id <owner-write-id>

eliot memory-client rotate \
  --client-id memory:<installation-id> \
  --expected-version <n> \
  --credential-out <absolute-private-create-new-path> \
  --id <owner-write-id>
```

The command:

1. resolves the current controller data root and its stable `controller_id`;
2. uses controller owner admission locally; it never sends owner authority to Memory;
3. commits one exact `memory_inference` registration/update through the normal V2 `WriteId` receipt path;
4. derives the raw token with a domain-separated keyed function over controller private `routing.key`, `client_id` and `token_version`;
5. stores only the version and token hash in SQLite;
6. writes a create-new private credential bundle containing `controller_id`, `client_id`, `token_version` and raw token;
7. never writes raw token to SQLite, receipt result, argv, logs, diagnostics or status.

Because the token is deterministically re-derived from private `routing.key` and the committed version, a lost install/rotate reply does not require a pending secret bundle or replacement token. Retrying the same owner `WriteId` returns the same registration and re-derives the same token. A different semantic payload under that ID is `id_conflict`.

A missing/mismatched controller `routing.key` blocks install, rotate and token reissue. Existing presented tokens may still verify against their stored hashes for bounded readback/cleanup, matching controller V2 routing-key failure semantics.

`memory.client.rotate` atomically increments `token_version` once and preserves `client_id` and every existing call. Another rotation is refused while Memory installation selection still has unresolved pending/previous credential publication.

## 4. Connection identity and per-request fence

Memory uses the pinned controller V2 JSON-RPC client/transport implementation. It does not use MCP, spawn the general-purpose CLI for application calls, copy framing code or connect to the retired `swarm-client` protocol.

Before any application mutation, Memory performs `client.identity` over the authenticated connection. The closed result is:

```text
controller_id
client_id
principal = memory_inference
token_version
api_version
write_id_floor_ms
write_id_future_skew_ms
```

Memory requires exact equality with installation selection and the supplied credential bundle. Missing, unknown or malformed fields fail closed. Mismatch closes the connection before `inference.text/embed` and yields a typed local failure such as:

```text
CONTROLLER_ID_MISMATCH
CALLER_IDENTITY_UNAVAILABLE
TOKEN_VERSION_MISMATCH
API_VERSION_UNSUPPORTED
```

Possessing a credential file is not proof that the connected daemon authenticated it.

Before **every** Memory-client read or mutation, controller reloads the registration and requires:

```text
registration exists
registration.principal == memory_inference
registration.disabled == false
principal.client_id == registration.client_id
principal.token_version == registration.token_version
presented token matches current hash
live peer classification is not ambiguous
```

An old authenticated transport evaluated after rotation receives `credential_stale`; client and server close it after the terminal response. New version may read/release pre-rotation calls because ownership is the stable `client_id`.

The no-token owner fallback and Agent/project tokens are never accepted for this surface.

## 5. `WriteId` is the inference call identity

Memory generates a canonical ULID `WriteId` **and commits it to the Memory job before the first send**. The controller call identity is:

```text
(client_id, write_id, method, canonical semantic payload)
```

For `inference.text/embed`, the call ID equals `write_id`. There is no separately discovered Operation ID and no Memory-side `possible_send`/`proven_no_send` state.

Canonical semantic payload contains only behavior-changing bounded fields:

```text
method
profile name
origin = explicit | automatic
disclosure = local_only | external_allowed
input digest + exact byte length
response format / embedding role
finite output/time/batch limits
```

It excludes JSON-RPC request id, connection metadata, wait/display options and client timeout.

Normal V2 receipt rules apply:

```text
same WriteId + same caller/method/payload -> return current original call
same WriteId + different semantic payload -> id_conflict
absent old/below-floor WriteId            -> id_expired
absent excessive-future WriteId           -> id_future
valid absent WriteId                      -> first admission only
```

After disconnect or restore, Memory deliberately invokes the same method with the same retained `WriteId` and exact bytes. Controller either returns the existing call or performs the first admission. It never creates a second provider attempt for an already admitted call.

Provider-send uncertainty is a state of the retained inference call, not permission to use another `WriteId`.

## 6. Minimal durable controller state

Controller reuses V2 `write_receipts` and adds only the state that the new product edge actually owns:

```text
memory_inference_clients   one current scoped registration per Memory installation
inference_calls            one durable one-shot call/result/cleanup row
```

It does not force inference into `commands`, Agent turns, automation runs/actions or generic nonsecret artifact storage.

Conceptual registration:

```text
MemoryInferenceClient {
  client_id,
  token_version,
  token_hash,
  disabled,
  created_at,
  updated_at
}
```

Conceptual call:

```text
InferenceCall {
  id = WriteId,
  admission_seq,
  caller_id,
  method,
  canonical_payload_digest,
  profile/connection/adapter digests,
  actual_destination,
  origin,
  disclosure,
  input_digest/input_length/input_copy_state,
  state,
  native_request_id?,
  result_digest/result_length/result_copy_state?,
  observed_model?, usage/cost/account facts when actually supplied,
  terminal_code?,
  created_at, updated_at
}
```

`admission_seq` is a positive monotonic per-client controller sequence allocated in the same transaction as first admission. It is used only for bounded backup/restore inventory; it is not a scheduler, semantic ordering or evidence score.

Raw input/result bytes, provider credentials and raw provider error bodies do not enter `write_receipts` or `inference_calls`.

## 7. Connections, profiles and disclosure

Controller owns static inference configuration distinct from harness profiles:

```text
InferenceConnection {
  name,
  adapter/transport version,
  canonical endpoint,
  named private provider-credential reference,
  actual_destination = local | external,
  explicit transport-security behavior
}

InferenceProfile {
  name,
  adapter version,
  connection reference/digest,
  requested model,
  allow_automatic,
  finite input/output/time/concurrency/batch limits,
  supported response formats
}
```

A loopback gateway that forwards to cloud is `external`. Endpoint locality is not destination proof. Provider secrets resolve in controller memory only after caller/profile admission and never enter Memory, config projections, call receipts, logs or result metadata.

Memory chooses a profile name only. It cannot construct arbitrary endpoints, headers, query parameters, provider extras, fallback models or retry ladders.

Memory reduces supplied material to:

```text
local_only
external_allowed
```

Derived content cannot widen the strictest source it still reveals. Controller resolves the actual connection and validates disclosure at admission. Protected content is not silently removed to make an external route pass.

Unavailable profile/connection/capacity or disclosure mismatch is an operational waiting/rejection/failure. It is not cognitive `no_change` and does not mark source coverage complete.

Reconfiguration affects new first admissions only. An admitted call retains exact non-secret behavior digests and destination.

## 8. Controlled input and result copies

One call creates at most:

```text
inference_input
inference_result
```

Both are private controller files under deterministic call-owned internal identities. They are not generic V2 `artifacts/`, because that store is defined for bounded nonsecret immutable configuration snapshots.

### Input admission

For a valid absent `WriteId`, controller:

1. validates current client/token, profile, disclosure, format, limits and capacity;
2. writes exact accepted input to a create-new private temporary file;
3. flushes file, publishes without replacement, flushes parent directory and reopens exact bytes/digest;
4. rechecks the receipt inside the single-writer transaction, then atomically inserts the external receipt and queued `InferenceCall` referencing digest/length/internal copy identity;
5. if a concurrent exact replay won, returns that call and removes only its unreferenced duplicate staging file; a payload conflict never replaces either file;
6. returns the call state.

An orphan file without a committed call is cleanup material and is never dispatchable. A committed call with missing/mismatched input is `damaged`, never reconstructed from receipt JSON.

### Result publication

When a visible response body exists, controller writes one bounded private result envelope containing exact body plus bounded nonsecret response facts, flushes/publishes/verifies it, then settles the call transactionally. Restart may finish settlement from an exact verified pending result envelope. A settled row with missing/mismatched result is `damaged`.

Per-copy state is:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Aggregate cleanup is derived and cannot hide a remaining copy:

```text
retained | cleanup_pending | cleanup_incomplete | released
```

No content-bearing diagnostic is logged. Provider-safe terminal codes may be retained without result bytes. Raw provider errors are not automatically Memory content.

## 9. Request and result shapes

Initial API frame remains below the controller V2 4 MiB transport maximum; profiles impose a smaller finite input limit. Larger streaming/upload protocols are later work, not an implicit fallback.

### 9.1 `inference.text`

Conceptual request:

```json
{
  "write_id": "canonical-ulid-created-by-memory",
  "profile": "memory-text-default",
  "origin": "explicit",
  "disclosure": "local_only",
  "prompt": "exact UTF-8 prompt",
  "prompt_sha256": "lowercase-sha256",
  "max_output_tokens": 4096,
  "response_format": "json_object"
}
```

Validation recomputes exact prompt digest/length. `response_format` is a closed enum. `origin=automatic` requires profile permission.

### 9.2 `inference.embed`

Conceptual request:

```json
{
  "write_id": "canonical-ulid-created-by-memory",
  "profile": "memory-vector-default",
  "origin": "automatic",
  "disclosure": "external_allowed",
  "role": "document",
  "inputs": [
    {"input_key": "memory:abc@7", "text": "...", "text_sha256": "..."}
  ]
}
```

`role = query | document` maps through the selected adapter's declared task parameter/prefix. Canonical result contains one exact result/error per input key and one effective vector-space identity: profile digest, observed model, dimensions and role.

Missing, duplicate or unresolvable positions, inconsistent dimensions, non-finite values or shifted assignment fail. Controller never repairs with zero vectors.

## 10. Bounded runner and provider uncertainty

One bounded controller runner consumes queued inference calls. It is an internal owner, not an automation rule or Agent.

1. select an eligible queued call under frozen profile concurrency;
2. verify exact input copy, current client registration and frozen profile/connection;
3. compare-and-set `queued → sending` before provider I/O;
4. perform at most one provider attempt outside the SQLite transaction;
5. retain native request/readback identity when the adapter supplies it;
6. publish exact result when present and settle bounded facts;
7. wake readers and continue finite work.

Possible provider send followed by timeout, process loss or ambiguous transport becomes `unknown` unless the adapter's exact native readback resolves it. It is never redispatched because Memory repeats the admission `WriteId`.

Restart rules:

```text
queued + verified input       -> eligible once
sending/native accepted       -> exact native readback or unknown
verified pending result       -> finish settlement
abandoned                     -> never dispatch or publish late result
```

No adapter performs hidden retry, redirect or fallback. A native provider idempotency key may be used only when its exact semantics are qualified; it does not weaken controller `WriteId` ownership.

## 11. Read, cancel, release and erasure authority

`inference.get` returns bounded non-content status only to the exact current `client_id`. Missing usage/cost/account facts remain unknown.

`inference.result.read` requires:

```text
call belongs to current client_id
call is settled/partial with exact result digest/length
current token_version is valid
result copy is retained and not released
requested range is bounded
```

It returns exact range bytes plus offset/length/digest metadata. It never falls forward to another call/result.

`inference.cancel` is an external mutation with its own `WriteId` and succeeds only for the exact caller's queued call before `sending`. After provider I/O may have begun, cancellation cannot prove non-execution and does not rewrite the call to failed.

`inference.release` is an external idempotent mutation over one exact call with one of:

```text
memory_copy_verified
terminal_without_result
abandon_for_erasure
```

- `memory_copy_verified`: Memory has durably copied and verified exact result bytes.
- `terminal_without_result`: call is terminal and no future result can appear.
- `abandon_for_erasure`: fence queued/sending/unknown settlement/publication before controlled-copy deletion.

For every expected file, controller verifies call provenance, deterministic internal location, regular-file/no-reparse identity, digest/length where present, exact deletion and parent-directory durability. Missing exact file becomes `already_absent`; mismatch blocks deletion. Partial cleanup remains visible/retryable.

Controller owner may invoke `inference.erase` over exact caller/call identities or a bounded admission-sequence range. It returns only non-content disposition/cleanup facts. Owner cannot call `inference.result.read`, adopt caller ownership or fabricate a Memory result through this branch.

Provider non-execution, provider-side deletion, billing reversal and remote retention are never claimed from local cleanup.

## 12. Memory backup, rollback and external-work inventory

A Memory backup retains:

```text
controller_id
controller_client_id
selected token_version
controller inference high-water admission_seq at the backup cut
all in-cut job WriteIds and canonical request identities
known result/release/cleanup facts
```

Before taking that cut, Memory:

1. stops new controller-backed admissions;
2. persists every already-created inference `WriteId` in its job rows;
3. reconciles its active submission/readback step to a typed state;
4. authenticates exact client identity;
5. reads `inference.high_water {high_water, earliest_retained_seq}` and records both values in the backup manifest.

The high-water is meaningful only for the exact `controller_id + client_id`. It is not inferred from ULID time. Controller never prunes open, unknown or unreleased calls. When it prunes terminal released call rows/receipts, it advances `earliest_retained_seq` so an old restore receives an explicit gap rather than a false empty inventory.

### Restore of in-cut jobs

After exact identity authentication, every retained job retries/reads by the same `WriteId`:

```text
same call exists  -> return/read/release original call
call absent and WriteId still admissible -> first admission using exact retained bytes
payload mismatch  -> id_conflict
caller unavailable -> hold job; no call
```

There is no unknown call ID.

### Calls admitted after the backup cut

A rollback may discard Memory rows for calls admitted after the recorded high-water while those calls/results/copies still exist in controller. Before any new automatic inference after restore, Memory pages:

```text
inference.list(after_admission_seq = backup_high_water)
```

If `backup_high_water < earliest_retained_seq - 1`, the read returns `history_gap`; restore must not treat that as an empty set.

Every returned call is **out of target**. Restore does not adopt its result as cognitive output because the restored Store lacks the exact job/source/publication mapping. Each call must become terminal and released, or be explicitly abandoned/erased with visible cleanup debt. Unknown possible provider effects remain unknown.

All new controller-backed admissions stay disabled until this bounded inventory is complete and empty or every row has an explicit retained disposition. Base capture/retrieval may resume without inference.

If controller identity, caller credential or this inventory is unavailable, restore records `external_work_inventory_unavailable`, leaves inference disabled and does not claim complete rollback/erasure. A new caller, reset controller data root or owner assertion cannot silently clear the debt.

This rule closes the disaster-restore case where current Memory Store is unreadable: the backup's controller high-water, not the lost current Store, defines the external continuity denominator.

## 13. Credential rotation reconciliation

Memory installation selection keeps at most one current, one pending and one unretired previous credential reference, each bound to exact `controller_id/client_id/token_version`. Another rotation is refused until pending/previous is resolved.

After an unknown rotate/write-file result:

1. retry the same controller owner `WriteId`; registration returns the same committed version;
2. re-derive the same token and write/verify the pending credential path without replacement;
3. authenticate pending and require exact `client.identity`;
4. read one pre-rotation call under the same `client_id`;
5. atomically publish pending→current and current→previous in Memory installation selection;
6. reconnect daemon and prove old call read/release;
7. retire previous credential file only in a later explicit cleanup step.

If pending/current observations disagree, neither authenticates, selection is unreadable or old call ownership changes, rotation remains incomplete and both references are retained.

Disabling a client is a separate authority transition. It blocks new reads/mutations and must explicitly disposition queued/unknown calls/copies; it is not token rotation.

## 14. Initial provider adapters

Initial text adapter is a closed loopback-compatible OpenAI chat-completions subset:

```text
openai_chat_completions_loopback_v1
POST <base>/chat/completions
Content-Type: application/json
Accept: application/json
optional Bearer from named private connection reference
```

Request body contains only model, one exact user message, admitted `max_tokens` and typed `json_object` format when selected. No tools, streaming, temperature, stop list, arbitrary fields, environment proxy, redirects, hidden retry or fallback model.

Response requires bounded JSON and one usable `choices[0].message.content`. Length finish is partial, never complete. Tool-only, content-free or unsupported multimodal output fails. Usage/cost/account remain unknown when absent.

Initial embedding adapter is a closed `openai_embeddings_loopback_v1` subset with exact count/index/dimension/finite-value checks.

Loopback does not prove local destination. Direct HTTPS is a later separately qualified adapter with pinned TLS behavior, no ambient proxy/redirect and the same no-replay/copy lifecycle.

## 15. Implementation increments

Do not make full rotation or embeddings a prerequisite for first useful learning.

### P1a — controller V2 foundation and connected text inference

After controller V2 L1 Store/API exists:

1. add stable `controller_id` if absent;
2. add the exact `memory_inference` client registration and scoped token derivation;
3. add `client.identity` and per-method current-version fence;
4. add inference connections/profiles and disclosure admission;
5. add `write_receipts`-backed `inference.text`, `inference_calls`, controlled input/result copies and bounded runner;
6. add get/range-read/cancel/release/high-water/list and non-disclosing owner erase;
7. connect one Memory adapter and one episode-learning result to a later context consumer;
8. prove same-WriteId lost reply, restart, result copy/release and restore high-water inventory.

### P1b — credential rotation

Then add install/rotate lost-reply reconciliation, stale transport reaping, pending/current/previous selection and delayed previous-file retirement.

### Later

- `inference.embed` and vector-space identity;
- direct HTTPS adapter;
- richer native provider readback where real providers expose it;
- larger streamed payload protocol only after measured need.

## 16. Required verification

Source review, schema execution and Clippy are not runtime qualification. The connected boundary must eventually prove at least:

- exact current controller V2 implementation revision and API schema;
- client install retry, token-file loss/reissue, rotation and stale transport denial;
- no owner/Agent/automation fallback for missing or invalid Memory token;
- same `WriteId` before send, lost reply, daemon restart and Memory restore;
- `id_conflict`, expired/future ID and receipt retention behavior;
- input file before provider I/O; orphan/missing/mismatch cases;
- queued→sending crash and possible-send→unknown with no second provider call;
- pending/settled result crash and bounded range read;
- result-byte denial to owner erase path;
- independent input/result cleanup and partial cleanup retry;
- profile/destination/disclosure/capacity denial before provider I/O;
- backup high-water, in-cut readback and post-cut out-of-target inventory;
- controller unavailable during disaster restore leaves inference disabled, Base usable;
- embedding count/index/dimension/finite-value negatives;
- provider adapter has no redirect, ambient proxy, retry or fallback.

## 17. Frozen non-goals

Do not:

- implement this contract in retired controller V1 code;
- revive `swarm-client`, Manager/Operator roles or generic Operation/artifact grants for Memory;
- route one-shot inference through Agent commands, Goals, automation runs/actions, scripts, MCP or CLI subprocesses;
- let no-token owner fallback authenticate Memory;
- store raw Memory or provider tokens in SQLite, receipts, logs or backups;
- trust a credential file without `client.identity` readback;
- use a new `WriteId` after an uncertain submission;
- infer call ordering from ULID timestamps instead of controller admission sequence;
- put content-bearing prompts/results in generic nonsecret controller artifacts;
- retry a possible provider effect;
- adopt post-backup results into restored cognition without exact job/source mapping;
- resume automatic inference while post-cut controller inventory is unresolved;
- let owner erase read result bytes or relabel caller ownership;
- treat local controlled-copy deletion as provider-side deletion/non-execution/no-charge;
- add a generic service-client framework, Task engine, workflow DB or proof ceremony for this one edge.
