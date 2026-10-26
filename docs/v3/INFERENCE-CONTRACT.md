# Eliot V3 — One-shot inference contract

**Revision 0.5-draft · 2026-10-26 · shared boundary for Memory OS and `eliot-swarm-controller`; not implemented.**

This is the sole normative Memory↔controller contract for one-shot model execution. It prevents these wrong implementations:

1. wrapping one memory extraction in controller Task/Attempt/review/acceptance;
2. copying provider credentials, routing and retry logic into Memory OS;
3. restoring the old Governor platform around a reversible request;
4. routing inference through ScriptRun/module-binding machinery because it is taskless;
5. retaining controller prompt/result copies indefinitely;
6. calling an unspecified “OpenAI-compatible” service through arbitrary fields;
7. losing input cleanup when an Operation has no result;
8. changing caller identity during credential rotation and thereby orphaning retained Operations/artifacts;
9. restoring a Memory job under a new principal and redispatching inference because exact-caller readback is no longer available.

Memory owns its finite job, frozen sources, exact recipe, disclosure reduction, stable request identity, decoding and publication. Controller owns caller authentication, configured connection/profile, provider invocation, Operation deduplication/readback and temporary controlled copies.

## 1. Public methods

Initial public methods:

```text
inference.text
inference.embed
inference.release
```

Existing controller methods remain responsible for:

```text
operation.get
operation.cancel
artifact.get
artifact.read
```

`inference.text` and `inference.embed` are mutations because they may spend quota and create an external effect. `inference.release` is idempotent over one exact inference Operation and releases every controller-owned content copy permitted by the validated disposition, including input-only Operations.

None of these methods creates or requires Task, Requirement, Attempt, binding, workspace, native agent session, review, submission, acceptance, ScriptRun or Memory-side provider credentials.

## 2. Narrow caller authority

Controller adds one authenticated role:

```text
inference_client
```

It is not Manager, Operator, Observer, Participant or bound Module. It has no MCP discovery surface and no generic writer authority.

Complete application surface:

```text
mutations:
  inference.text
  inference.embed
  inference.release
  operation.cancel       # only own still-queued inference Operation

reads:
  operation.get          # only own retained Operation receipt
  artifact.get           # only own retained inference result
  artifact.read          # only own retained inference result
```

Store dispatches this role through an explicit allowlist before generic writer handling. Existing exact-caller Operation/artifact authorization is reused; there is no second receipt store or admin-shaped fallback.

### 2.1 Stable logical caller identity

Controller credentials contain two different things:

```text
client_id   logical retained principal
secret      replaceable authentication material
```

For Memory OS, `client_id` is installation-scoped and stable across daemon restart, Store rollback and token rotation. Conceptually:

```text
eliot-memory:<stable-installation-id>
```

The exact string format is implementation-owned, but it is generated once, bounded, non-secret and retained in Memory installation identity and controller registration. It is not derived from PID, executable path, data-root generation, backup generation, token digest or wall clock.

Every Memory inference job retains:

```text
controller_client_id
client_request_id
controller_operation_id when known
result artifact identity/digest when known
credential generation/digest as non-authoritative diagnostics only
```

The Operation owner is `controller_client_id`, not the token generation. A new credential with the same authenticated `client_id` may read/cancel/release retained Operations according to their current state. A token change must not rewrite `caller_id`, request identity, Operation ID or artifact provenance.

Changing `client_id` is **principal migration**, not credential rotation. No implicit migration is selected. Without an explicit controller-side transfer protocol that rewrites/aliases every retained Operation, artifact grant and cleanup owner atomically, a new `client_id` cannot adopt old work. Memory must not use local Operator access or a new request ID as a normal recovery shortcut.

### 2.2 Direct IPC client

Memory calls controller through exact-revision `swarm-client`, not MCP or a spawned CLI.

The pinned client:

- connects to the configured local IPC root;
- sends one `client.hello` carrying `client_id + token` before any application request;
- never automatically resends an application request;
- reports cancellation/disconnect/partial reply after possible write as `OUTCOME_UNKNOWN` and retires the connection.

Memory does not copy framing/authentication code. Changing the Git pin is an explicit integration update.

Memory configuration stores only:

```text
controller IPC/data root
private inference-client credential path/reference
expected stable controller_client_id
bounded IPC settings
selected inference profile names
```

Raw token bytes never enter Memory Store rows, backups, logs or public status. The public inference payload must fit the configured IPC frame; the initial contract has no generic upload/session path.

### 2.3 Credential rotation and connection revocation

The controller currently authenticates once during `client.hello` and retains the resulting Principal for that connection. Therefore changing the stored token hash alone does not revoke an already authenticated socket.

A qualified inference-client credential rotation must:

1. keep the same `client_id`;
2. stop new inference admission for that principal or place it in a bounded rotating state;
3. create one pending secret and durable pending generation/reference;
4. update the token hash for the same registered `client_id`;
5. classify unknown update outcome by probing pending credential first and current credential second; never generate another pending token;
6. close every authenticated connection for that `client_id` or restart the controller host before declaring the old token revoked;
7. reconnect Memory with the pending/current credential and prove `operation.get` plus an allowed artifact/release read against a retained pre-rotation Operation;
8. promote pending to current and retain old secret/reference until restart/readback confirms continuity;
9. retire the old secret only in a later explicit cleanup step.

If both credentials authenticate, neither authenticates, or old authenticated sessions cannot be enumerated/closed, rotation is incomplete. It must not be reported as revocation.

The pinned controller revision `e42c464d` supplies authenticated IPC and exact-caller ownership donors, but it does **not** implement `inference_client`, inference methods or this rotation/revocation workflow. Runtime status remains `NOT IMPLEMENTED`.

## 3. Connections and profiles

Controller owns static `InferenceConnection` and `InferenceProfile` records. Neither is an agent Route, dynamic registry or admission-proof platform.

### 3.1 `InferenceConnection`

A connection owns:

```text
name
versioned transport ID
canonical endpoint
private credential reference
actual_destination = local | external
explicit transport-security behavior
```

`actual_destination` describes where supplied content ultimately goes. A loopback gateway forwarding to cloud is external.

Connection files are absolute, bounded private regular files with closed schema. Secrets never enter Operation JSON, logs, digests or receipts. Initial adapters support no arbitrary headers, query parameters, extra body, environment proxy or redirects.

`connection_digest` covers non-secret behavior-changing fields, not credential bytes/path. Credential/account rotation under unchanged digest is not proof of identical provider account; unavailable account/billing identity remains unknown.

### 3.2 `InferenceProfile`

A profile selects:

```text
name
versioned adapter ID
connection reference/digest
requested model
actual destination
allow_automatic
finite input/output/time/concurrency limits
supported response formats
```

Controller validates positive finite bounds and a supported adapter/connection/model combination. `profile_digest` covers all non-secret behavior-changing fields. Reconfiguration affects new explicit requests and never mutates an admitted Operation snapshot.

Memory selects only a profile name. It does not construct provider headers, arbitrary extras or fallback ladders. There is no implicit provider/model/account/destination fallback.

## 4. Disclosure and admission

Memory reduces all supplied material to:

```text
local_only
external_allowed
```

Project default may be narrowed by a source. Derived content cannot widen the strictest source it still contains or reveals. Mixed input uses the strictest class. Reuse scope does not widen disclosure.

Controller resolves the actual profile/connection and authoritatively checks:

- caller role and stable client identity;
- profile/connection existence and enabled state;
- `actual_destination` versus disclosure;
- automatic-use permission;
- exact input digest/length and IPC/profile limits;
- output/format limits;
- known capacity.

Protected content is not silently omitted to make an external destination pass. Admission failure is not cognitive no-change and does not mark input processed.

## 5. Controlled input and result artifacts

One inference Operation creates at most:

```text
inference_input
inference_result
```

Before provider I/O, controller stages exact accepted input under deterministic Operation-owned identity, verifies bytes/digest and commits Operation metadata without raw input in generic JSON. An orphan file without committed Operation is never dispatchable and is cleanup material.

When visible result exists, controller stages exact bounded bytes, verifies digest/length, publishes the file and settles the Operation with a closed receipt. Provider-safe failure metadata may exist without `inference_result`; raw provider errors are not automatically cognitive content.

Crash states remain explicit:

- metadata but no exact input/result file → unavailable/damaged, never complete;
- exact file present but settlement missing → restart may verify and finish settlement;
- settled receipt without exact file/digest → damaged result, not no-change.

Per-copy cleanup state:

```text
not_created
retained
cleanup_pending
removed
already_absent
mismatch
unknown
```

Aggregate state is derived:

```text
retained
cleanup_pending
cleanup_incomplete
released
```

A single boolean cannot hide one remaining controlled copy.

## 6. `inference.text`

Conceptual request:

```json
{
  "client_request_id": "stable-memory-job-attempt-key",
  "profile": "memory-text-default",
  "origin": "explicit",
  "disclosure": "local_only",
  "prompt": "exact UTF-8 prompt",
  "prompt_sha256": "lowercase-sha256",
  "max_output_tokens": 4096,
  "response_format": "json_object"
}
```

`origin` is `explicit | automatic`. Automatic requests are rejected before provider I/O unless profile permits them.

Validation includes bounded request ID, exact bytes/digest, caller continuity, frame/profile limits, profile/connection/destination, output/format, automatic permission and capacity. Memory recipe/source IDs remain inside Memory's exact retained request; controller does not own the cognitive schema.

## 7. `inference.embed`

Conceptual request:

```json
{
  "client_request_id": "stable-memory-embedding-attempt-key",
  "profile": "memory-vector-default",
  "origin": "automatic",
  "disclosure": "external_allowed",
  "role": "document",
  "inputs": [
    {"input_key": "memory:abc@7", "text": "...", "text_sha256": "..."}
  ]
}
```

`role = query | document` maps through the adapter's actual task parameter/prefix.

Canonical result contains one exact result or error per input key and one effective space identity: profile digest, observed model, dimensions and role. Missing/duplicate/unresolvable positions, inconsistent dimensions and non-finite vectors are errors. Never repair with zero vectors or shifted assignment.

## 8. Admission, replay and retained identity

Operation identity is:

```text
(controller_client_id,
 client_request_id,
 method,
 canonical bounded request identity)
```

Canonical identity includes input digest/length rather than raw bytes. Exact replay by the same stable caller returns the original Operation/admission state. Different method/profile/limits/format/role/input digest under the same request ID is `REQUEST_ID_CONFLICT`.

The existing Operation table is sufficient initially:

- `caller_id` — stable `controller_client_id`;
- `client_request_id` — caller correlation key;
- `original_request_json` — bounded identity, never raw prompt/input;
- `effective_request_json` — frozen profile/connection, controlled input and execution facts;
- `result_json` — closed public receipt and per-copy cleanup;
- existing state — queued, sending, native accepted, settled, rejected, cancelled, abandoned or unknown.

Do not add `inference_runs`, a second scheduler or generic external-job platform. The generic mutation helper is not called unchanged because it would persist raw payload and cannot stage private artifacts correctly.

## 9. Initial adapters

Initial text adapter:

```text
openai_chat_completions_loopback_v1
```

Closed wire:

```text
POST <base>/chat/completions
Content-Type: application/json
Accept: application/json
optional Bearer from private connection file
```

Body contains only model, one user message with exact prompt, admitted `max_tokens`, and typed `json_object` response format when supported. No tools, streaming, temperature, stop list, arbitrary headers/fields or fallback model.

Response requires bounded JSON and one usable `choices[0].message.content`. Record observed model/finish/response ID/usage only when supplied. Tool-only/content-free/unsupported multimodal output fails. Length finish is partial, never complete. No hidden retry; possible-send transport failure is unknown.

Initial embedding adapter:

```text
openai_embeddings_loopback_v1
```

It posts bounded model/input array, verifies indices/count/finite vectors/consistent dimension and emits §7 canonical per-input output.

Loopback does not prove local destination. Current controller `reqwest` lacks qualified direct HTTPS/TLS in the inspected build; a future HTTPS adapter requires explicit TLS qualification, no redirects/proxies and identical no-replay/copy lifecycle.

## 10. One bounded runner

One controller runner consumes queued `inference.text/embed` Operations. It reuses Operation ledger/wake signal and is not another process or scheduler.

1. select eligible queued Operation under frozen profile concurrency;
2. verify exact input artifact and frozen profile/connection/caller state;
3. CAS `queued → sending` before provider I/O;
4. perform one provider attempt outside Store transaction;
5. retain native admission/response identity when supplied;
6. persist exact result when present and terminal receipt;
7. wake readers and continue finite work.

Possible-send timeout/loss becomes unknown unless native idempotency/readback resolves it. A new request ID is not recovery.

Restart behavior:

- verified queued input remains eligible;
- sending/native-accepted uses native readback when supported, otherwise unknown;
- verified pending result may finish settlement;
- abandoned never redispatches/publishes late result;
- no restart automatically issues another provider call.

## 11. Public receipt and artifact authorization

`operation.get` grants a bounded receipt to the exact authenticated `controller_client_id` without Task linkage. Only that principal receives its `client_request_id`. Projection never exposes arbitrary provider JSON or credentials.

Receipt contains status, optional result artifact/digest/length/encoding, requested profile/adapter/connection/model/destination, observed provider/model/response/finish/usage/cost when known, limits and independent input/result cleanup state.

Missing usage/cost/account remains unknown, never zero/inferred.

`inference_result` authorization requires:

- artifact kind `inference_result`;
- settled target Operation names same artifact/digest/length;
- requesting principal's `client_id` equals retained `caller_id`, or verified local Operator uses an explicitly permitted diagnostic/erasure path;
- released content is unreadable.

`inference_input` has no public read grant. Do not relabel artifacts as script/native result or trust metadata alone.

## 12. Cancellation, restore and caller loss

`operation.cancel` handles only exact caller's still-queued inference Operation. Cancellation races runner CAS; one wins. Once provider I/O may have begun, local cancellation cannot prove non-execution.

A Memory backup retains non-secret `controller_client_id`, request ID, Operation ID, artifact/release identity and cleanup state, but never token. Restore verifies the currently configured inference credential authenticates as the same `controller_client_id` **before** reconciling any restored inference job.

Restored jobs:

- known Operation ID → `operation.get`/artifact/release readback under same caller; never redispatch;
- stable request ID but unknown Operation ID after possible send → exact replay under same caller only, returning original Operation or conflict;
- no admitted Operation and proven no-send → request may proceed under retained exact request identity;
- credential authenticates as another `client_id` → `caller_identity_unavailable`; no read/cancel/release or redispatch claim is made;
- out-of-target current Operations during Store rollback block cutover until terminal/released or explicitly abandoned by an authorized erasure owner.

Loss of the old logical caller prevents complete controlled-copy cleanup. Recovery requires restoring a credential for the same registered `client_id` or an explicit verified local-operator abandonment/erasure action. Operator access does not transfer ownership, fabricate cognitive result or authorize duplicate inference.

## 13. `inference.release`

Request names target Operation, disposition and expected artifact/digest/length when required.

Controller independently validates authenticated caller, target owner/state, artifact identities and disposition.

### 13.1 `memory_copy_verified`

Only when exact result is retained and Memory acknowledges durable matching copy. Input/result become cleanup targets.

### 13.2 `terminal_without_result`

Only when rejected, failed without retained result or cancelled before send, and no future result can publish. Input is cleanup target; result is `not_created`.

### 13.3 `abandon_for_erasure`

Allowed for exact caller or verified local Operator when erasure explicitly ends reconciliation of queued/sending/unknown work. Controller atomically marks Operation abandoned and fences future dispatch, settlement and publication before deleting controlled copies. Late provider content is discarded by exact file owner; only bounded non-content facts remain.

This cannot prove provider non-execution, deletion or no charge.

### 13.4 Physical cleanup

For each expected file controller verifies Operation provenance, canonical path, regular-file/no-reparse identity, length/digest when present, exact deletion and parent-directory durability. Missing exact file becomes `already_absent`; mismatch blocks deletion. Partial input/result cleanup remains visible and retryable under same caller/Operation identity.

Release is idempotent. Memory records release Operation ID, disposition and each copy state. Release failure never rolls back a verified Memory publication.

## 14. Reuse and explicit non-donors

Reuse:

- exact-revision `swarm-client` authenticated bounded IPC and no application replay;
- stable `client_id` Principal donor and token-hash authentication;
- Operation exact caller/request identity and conflict behavior;
- exact-caller operation/artifact authorization;
- existing Operation states/failure observations;
- immutable artifact publish/read/digest verification;
- wake signal and bounded worker pattern;
- bounded no-redirect/no-hidden-retry HTTP patterns.

Do not reuse:

- Task/Attempt/workspace/review/acceptance lifecycle;
- ScriptRun/interpreter/effect lifecycle;
- Manager/Operator as ordinary inference caller;
- module binding or agent route types;
- generic mutation storing raw request;
- generic writer fallback;
- hidden provider retry/fallback;
- credential rotation that changes `client_id`;
- old authenticated connections left alive after token change;
- normal recovery through Operator/admin read or a new request ID;
- another task/profile/capability/receipt registry.

## 15. Implementation order and open runtime gaps

1. add `inference_client` role and closed dispatch/read scopes;
2. add stable installation-scoped registration and private credential materialization;
3. add same-`client_id` token rotation with active-connection revocation and retained-operation continuity proof;
4. add inference artifact domains and exact private cleanup owner;
5. add connection/profile parser/digests/admission;
6. implement staged-input mutation identity and `inference.text` runner;
7. add result readback, cancellation and all release dispositions;
8. connect one Memory job/restore reconciliation path;
9. add embeddings through the same lifecycle;
10. qualify direct HTTPS only when explicitly needed.

At the inspected controller revision `e42c464d`, the following remain absent: `inference_client`, inference methods, inference artifact kinds, runner, release cleanup, same-principal credential rotation/revocation and Memory restore continuity. This document is design, not runtime proof.