# Eliot V3 — One-shot inference contract

**Revision 0.7-draft · 2026-10-26 · shared boundary for Memory OS and `eliot-swarm-controller`; not implemented.**

This is the sole normative Memory↔controller contract for one-shot model execution. It prevents these wrong implementations:

1. wrapping one memory extraction in controller Task/Attempt/review/acceptance;
2. copying provider credentials, routing and retry logic into Memory OS;
3. restoring the old Governor platform around a reversible request;
4. routing inference through ScriptRun/module-binding machinery because it is taskless;
5. retaining controller prompt/result copies indefinitely;
6. calling an unspecified “OpenAI-compatible” service through arbitrary fields;
7. losing input cleanup when an Operation has no result;
8. changing caller identity during credential rotation and thereby orphaning retained Operations/artifacts;
9. restoring a Memory job under a new principal and redispatching inference because exact-caller readback is no longer available;
10. treating a successful `client.hello` as sufficient while discarding the authenticated principal, role, credential generation or protocol returned by controller;
11. turning local-Operator erasure authority into normal result-byte disclosure or ownership transfer;
12. reusing generic `client.register` for inference setup/rotation even though it permits current-GM authority, refuses an existing client and stores the supplied token verifier in generic Operation JSON;
13. claiming credential revocation from a token-hash update while an already authenticated Principal has no generation fence.

Memory owns its finite job, frozen sources, exact recipe, disclosure reduction, stable request identity, decoding and publication. Controller owns caller authentication, configured connection/profile, provider invocation, Operation deduplication/readback and temporary controlled copies.

## 1. Application methods

Initial inference-client surface:

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

`inference.text` and `inference.embed` may spend quota and create an external effect. `inference.release` is idempotent over one exact inference Operation and releases every controller-owned content copy permitted by the validated disposition, including input-only Operations.

None of these methods creates or requires Task, Requirement, Attempt, binding, workspace, native agent session, review, submission, acceptance, ScriptRun or Memory-side provider credentials.

## 2. Narrow caller authority

Controller adds one authenticated role:

```text
inference_client
```

It is not Manager, Operator, Observer, Participant or bound Module. It has no MCP discovery surface and no generic writer authority. `Principal::require_writer` must continue to reject it; the Store dispatches only the exact allowlist in §1 after current registration/generation validation.

### 2.1 Stable logical caller identity

Controller credentials contain different objects:

```text
client_id               stable retained principal
credential_id           non-secret identity of one secret generation
credential_generation   monotonic authorization generation
secret/token             replaceable authentication material
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
authenticated credential_generation as diagnostics
non-secret credential_id/reference as diagnostics
```

The Operation owner is `controller_client_id`, not a token or credential generation. A new credential generation under the same authenticated `client_id` may read/cancel/release retained Operations according to their state. Rotation must not rewrite `caller_id`, request identity, Operation ID or artifact provenance.

Changing `client_id` is **principal migration**, not credential rotation. Initial V3 selects no migration. Without an explicit controller-side transfer protocol that atomically rewrites or aliases every retained Operation, artifact grant and cleanup owner, a new `client_id` cannot adopt old work. Memory must not use local Operator access or a new request ID as normal recovery.

### 2.2 Direct IPC client and verified hello receipt

Memory calls controller through exact-revision `swarm-client`, not MCP or a spawned CLI.

The inspected client:

- connects to the configured local IPC root;
- sends one `client.hello` carrying `client_id + token` before any application request;
- never automatically resends an application request;
- reports cancellation/disconnect/partial reply after possible write as `OUTCOME_UNKNOWN` and retires the connection.

At controller revision `e42c464d`, the host returns:

```text
client_id
role
protocol_version
```

but `swarm-client::Client::connect` discards that result and returns only the socket-backed client. That API is an incomplete donor for Memory identity continuity. The current Principal also carries no credential generation.

Before the inference adapter exists, controller and `swarm-client` must expose a closed typed hello receipt containing at least:

```text
client_id
role
credential_generation
protocol_version
```

No application-capable handle is returned unless:

```text
receipt.client_id == installation.controller_client_id
receipt.client_id == credential.client_id
receipt.role == inference_client
receipt.credential_generation == installation expected generation
receipt.credential_generation > 0
receipt.protocol_version supports generation-fenced inference
no unknown receipt fields or malformed values
```

Any mismatch closes/poisons the connection before an application frame and becomes `CALLER_IDENTITY_UNAVAILABLE`, `CREDENTIAL_GENERATION_MISMATCH` or `HOST_HANDSHAKE_FAILED` as appropriate. Memory does not infer authenticated identity solely from the credential material it supplied, and it does not accept a Manager/Operator/Module session with a matching-looking ID.

Memory does not copy framing/authentication code. Changing the Git pin is an explicit integration update.

Memory user configuration stores only controller IPC/data root, bounded IPC settings and selected inference profile names. The supervisor/installer-owned installation identity stores expected stable `controller_client_id`, expected credential generation and non-secret current/pending/previous credential references. Raw token bytes never enter Memory Store rows, backups, logs or public status. The public inference payload must fit the configured IPC frame; the initial contract has no generic upload/session path.

### 2.3 Setup and rotation are specialized local-Operator operations

Generic controller `client.register` is **not** reused for inference credentials. At `e42c464d` it:

- accepts current GM or local Operator through `gm::require_authority`;
- rejects an already registered `client_id` with no implicit rotation;
- accepts `token_hash` in the public mutation payload;
- passes that payload through the generic mutation ledger, which stores canonical full params in `operations.original_request_json`.

The current `client.list` projection is correctly limited to `client_id`, role and disabled state; this safe projection is retained. The problem is setup/rotation authority and secret-derived verifier retention in the generic Operation, not `client.list`.

Initial V3 adds two closed controller-local maintenance operations, names shown normatively:

```text
inference.client.install
inference.credential.rotate
```

Only the verified local bootstrap Operator may invoke them. Current GM authority is insufficient. They are not available to `inference_client`, Manager, Module or MCP discovery.

The installer creates one high-entropy token and one independent non-secret `credential_id` before calling controller. The token/verifier is secret-bearing. A specialized transaction may retain the verifier only in the private `client:<id>` authentication registration. It must never place token bytes, `token_hash`, another token-derived fingerprint or reusable verifier into:

```text
operations.original_request_json
operations.effective_request_json
operations.result_json
observations
client.list / status
logs / telemetry / diagnostics
Memory configuration, Store or backup
```

The durable non-secret mutation identity is:

```text
(local Operator caller,
 client_request_id,
 method,
 target client_id,
 credential_id,
 expected credential generation)
```

The caller must retain exactly one pending token for one `credential_id`; it must not generate a second token under the same retained identity. Controller does not need to persist a token-derived request fingerprint to compensate for a caller that violates this rule.

`inference.client.install`:

1. requires the expected installation-scoped client ID and absent registration;
2. creates role `inference_client`, `credential_id`, `credential_generation=1`, verifier and `disabled=false` atomically with a redacted Operation receipt;
3. exact replay returns the same generation/credential ID;
4. any existing incompatible registration is conflict, never overwrite or migration.

`inference.credential.rotate`:

1. requires local Operator, exact target `client_id`, role `inference_client`, current `credential_id` and expected positive generation;
2. atomically replaces only verifier/credential ID and increments generation once;
3. preserves client ID, role and all Operation/artifact ownership;
4. exact replay returns the retained new generation;
5. stale expected generation or different credential ID is conflict;
6. never temporarily creates a second principal or aliases ownership.

### 2.4 Generation fencing revokes old application authority

Authentication captures the current registration generation in the server-side Principal. Every inference-client application dispatch must reload the current registration and require:

```text
registration exists
registration.role == inference_client
registration.disabled == false
principal.credential_generation == registration.credential_generation
```

This check occurs before every inference read or mutation, including specialized/readback paths, and before provider admission. No inference-client method may bypass it through a long-poll, module or generic-writer path.

Rotation is serialized with application admission by the existing single Store owner. A request that passed the generation check before rotation may remain an admitted Operation owned by the same stable caller. A request evaluated after rotation with the old Principal is rejected before application admission. The new credential reads any prior Operation because ownership did not change.

Generation mismatch returns a terminal authentication error such as `CREDENTIAL_STALE`. `swarm-client` treats it as connection-poisoning and closes its physical session. The server should also stop or reap a stale session after its terminal response so idle stale transports cannot accumulate. Application authority is revoked by the generation fence; a full controller restart is not required merely to invalidate the old token.

If generation fencing is not implemented, changing the stored verifier does **not** revoke already authenticated Principals and rotation is unqualified. Host restart is only a fallback for an implementation that lacks the selected generation fence, not the V3 target.

### 2.5 Rotation reconciliation

The installer retains one pending secret/reference while current remains available. After a lost rotation reply:

1. authenticate pending token and require typed hello with expected new generation;
2. if pending fails, authenticate current token and require the old generation;
3. never create another pending token during classification;
4. if pending succeeds, read the rotation receipt and one pre-rotation Operation under the same `client_id`;
5. publish installation selection pending→current/current→previous with exact generation readback;
6. retire previous secret only in a later explicit cleanup step after Memory reconnect/readback.

If both observations contradict the one-verifier/generation transition, neither authenticates, hello identity/role/generation mismatches, or selection cannot be read back, rotation is incomplete. Keep both credential references and block another rotation. A retained old transport is not authorization once its generation is stale, but its failure/closure remains observable.

The pinned controller revision `e42c464d` supplies authenticated IPC and exact-caller ownership donors, but it does **not** implement `inference_client`, specialized install/rotation, credential generation, typed hello exposure or stale-session fencing. Runtime status remains `NOT IMPLEMENTED`.

## 3. Connections and profiles

Controller owns static `InferenceConnection` and `InferenceProfile` records. Neither is an agent Route, dynamic registry or admission-proof platform.

### 3.1 `InferenceConnection`

A connection owns:

```text
name
versioned transport ID
canonical endpoint
private provider-credential reference
actual_destination = local | external
explicit transport-security behavior
```

`actual_destination` describes where supplied content ultimately goes. A loopback gateway forwarding to cloud is external.

Connection files are absolute, bounded private regular files with closed schema. Provider secrets never enter Operation JSON, logs, digests or receipts. Initial adapters support no arbitrary headers, query parameters, extra body, environment proxy or redirects.

`connection_digest` covers non-secret behavior-changing fields, not credential bytes/path. Provider credential/account rotation under unchanged digest is not proof of identical provider account; unavailable account/billing identity remains unknown.

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

- current caller role, stable client identity and credential generation;
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

Validation includes bounded request ID, exact bytes/digest, caller/generation continuity, frame/profile limits, profile/connection/destination, output/format, automatic permission and capacity. Memory recipe/source IDs remain inside Memory's exact retained request; controller does not own the cognitive schema.

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

Canonical identity includes input digest/length rather than raw bytes. Exact replay by the same stable caller returns the original Operation/admission state regardless of later credential generation. Different method/profile/limits/format/role/input digest under the same request ID is `REQUEST_ID_CONFLICT`.

The existing Operation table is sufficient initially:

- `caller_id` — stable `controller_client_id`;
- `client_request_id` — caller correlation key;
- `original_request_json` — bounded inference identity, never raw prompt/input or caller-token verifier;
- `effective_request_json` — frozen profile/connection, controlled input and execution facts;
- `result_json` — closed public receipt and per-copy cleanup;
- existing state — queued, sending, native accepted, settled, rejected, cancelled, abandoned or unknown.

Do not add `inference_runs`, a second scheduler or generic external-job platform. Generic mutation is not called unchanged because it would persist raw payload and cannot stage private artifacts correctly. Credential install/rotation use their own redacted transaction for the same reason.

## 9. Initial provider adapters

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
3. verify the caller registration still exists with role `inference_client`; credential generation need not remain the original dispatch generation because Operation ownership is the stable caller, but new application admission uses the current generation;
4. CAS `queued → sending` before provider I/O;
5. perform one provider attempt outside Store transaction;
6. retain native admission/response identity when supplied;
7. persist exact result when present and terminal receipt;
8. wake readers and continue finite work.

Possible-send timeout/loss becomes unknown unless native idempotency/readback resolves it. A new request ID is not recovery.

Restart behavior:

- verified queued input remains eligible under the still-registered stable caller and frozen profile;
- sending/native-accepted uses native readback when supported, otherwise unknown;
- verified pending result may finish settlement;
- abandoned never redispatches/publishes late result;
- no restart automatically issues another provider call.

Credential rotation does not cancel an already admitted Operation. Disabling/removing the principal is a separate authority change and must define what happens to its queued/unknown controlled copies before execution resumes.

## 11. Public receipt and artifact authorization

`operation.get` grants a bounded receipt to the exact currently authenticated `controller_client_id` without Task linkage. Only that principal receives its `client_request_id`. A verified local Operator may receive a separately defined bounded non-content diagnostic/erasure status; that path is not the normal receipt and never transfers caller ownership. Projection never exposes arbitrary provider JSON or credentials.

Receipt contains status, optional result artifact/digest/length/encoding, requested profile/adapter/connection/model/destination, observed provider/model/response/finish/usage/cost when known, limits and independent input/result cleanup state.

Missing usage/cost/account remains unknown, never zero/inferred.

`inference_result` byte authorization requires:

- artifact kind `inference_result`;
- settled target Operation names same artifact/digest/length;
- requesting principal's current authenticated `client_id` equals retained `caller_id`;
- its credential generation is current for the physical request;
- released content is unreadable.

A verified local Operator erasure branch may validate provenance and delete exact controlled copies without receiving result bytes. It does not satisfy `artifact.get/read`, create a Memory result or adopt cleanup ownership. `inference_input` has no public read grant. Do not relabel artifacts as script/native result or trust metadata alone.

## 12. Cancellation, restore and caller loss

`operation.cancel` handles only exact caller's still-queued inference Operation. Cancellation races runner CAS; one wins. Once provider I/O may have begun, local cancellation cannot prove non-execution.

A Memory backup retains non-secret `controller_client_id`, request ID, Operation ID, artifact/release identity and cleanup state, but never token/verifier. Restore validates a typed hello receipt proving the configured current credential authenticates as the same `controller_client_id`, expected current generation, `inference_client` role and supported protocol **before** reconciling restored inference jobs.

Restored jobs:

- known Operation ID → `operation.get`/artifact/release readback under same caller; never redispatch;
- stable request ID but unknown Operation ID after possible send → exact replay under same caller only, returning original Operation or conflict;
- no admitted Operation and proven no-send → request may proceed under retained exact request identity;
- credential/hello authenticates as another `client_id`, stale/unexpected generation, role or unsupported protocol → `caller_identity_unavailable`; no read/cancel/release or redispatch claim is made;
- out-of-target current Operations during Store rollback block cutover until terminal/released or explicitly abandoned by an authorized erasure owner.

Loss of the old logical caller prevents complete controlled-copy cleanup. Recovery requires restoring a current credential for the same registered `client_id` or an explicit verified local-Operator abandonment/erasure action. Operator access does not transfer ownership, disclose result bytes, fabricate cognitive result or authorize duplicate inference.

## 13. `inference.release`

Request names target Operation, disposition and expected artifact/digest/length when required.

Controller independently validates current authenticated caller/generation, target owner/state, artifact identities and disposition.

### 13.1 `memory_copy_verified`

Only when exact result is retained and Memory acknowledges durable matching copy. Input/result become cleanup targets.

### 13.2 `terminal_without_result`

Only when rejected, failed without retained result or cancelled before send, and no future result can publish. Input is cleanup target; result is `not_created`.

### 13.3 `abandon_for_erasure`

Allowed for exact caller or verified local Operator when erasure explicitly ends reconciliation of queued/sending/unknown work. Controller atomically marks Operation abandoned and fences future dispatch, settlement and publication before deleting controlled copies. The Operator branch receives only bounded disposition/cleanup facts, not result bytes or caller ownership. Late provider content is discarded by exact file owner; only bounded non-content facts remain.

This cannot prove provider non-execution, deletion or no charge.

### 13.4 Physical cleanup

For each expected file controller verifies Operation provenance, canonical path, regular-file/no-reparse identity, length/digest when present, exact deletion and parent-directory durability. Missing exact file becomes `already_absent`; mismatch blocks deletion. Partial input/result cleanup remains visible and retryable under the same stable caller/Operation identity.

Release is idempotent. Memory records release Operation ID, disposition and each copy state. Release failure never rolls back a verified Memory publication.

## 14. Reuse and explicit non-donors

Reuse from exact controller source:

- authenticated bounded IPC framing and no application replay;
- host-side hello identity fields, after adding typed generation-aware exposure;
- stable `client_id` Principal and token-verifier authentication;
- Store-side reloading of current client registration before generic dispatch;
- safe `client.list` projection that omits the verifier;
- Operation exact caller/request identity and conflict behavior;
- exact-caller operation/artifact authorization;
- existing Operation states/failure observations;
- immutable artifact publish/read/digest verification;
- wake signal and bounded worker pattern;
- bounded no-redirect/no-hidden-retry HTTP patterns.

Do not reuse unchanged:

- current `swarm-client::connect`, which discards authenticated hello identity;
- generic `client.register` for inference setup or rotation;
- generic mutation storage of secret-bearing credential params;
- current Principal/current-registration check without credential generation;
- current-GM authority for installation-scoped inference credentials;
- Task/Attempt/workspace/review/acceptance lifecycle;
- ScriptRun/interpreter/effect lifecycle;
- Manager/Operator as ordinary inference caller;
- local Operator as result-byte reader or ownership-transfer mechanism;
- module binding or agent route types;
- generic writer fallback;
- hidden provider retry/fallback;
- credential rotation that changes `client_id`;
- normal recovery through Operator/admin read or a new request ID;
- another task/profile/capability/receipt registry.

## 15. Implementation order and open runtime gaps

1. add `inference_client` role and make generic writer deny it;
2. add generation-bearing Principal/registration and validate current generation before every inference method;
3. expose/validate typed `client.hello` receipt before returning an application-capable client;
4. implement local-Operator-only redacted `inference.client.install` and `inference.credential.rotate`; never persist token verifier in generic Operation JSON;
5. make stale-generation response poison/close the client and reap stale server sessions;
6. prove same-client rotation by reading/releasing a pre-rotation Operation with the new generation;
7. add inference artifact domains, exact-caller byte grants and non-disclosing Operator erasure branch;
8. add connection/profile parser/digests/admission;
9. implement staged-input mutation identity and `inference.text` runner;
10. add result readback, cancellation and all release dispositions;
11. connect one Memory job/restore reconciliation path;
12. add embeddings through the same lifecycle;
13. qualify direct HTTPS only when explicitly needed.

At inspected controller revision `e42c464d` and the searched current repository, the following remain absent: `inference_client`, inference methods, inference artifact kinds, runner, release cleanup, credential generation/fencing, typed hello exposure/verification, specialized redacted install/rotation, non-disclosing Operator erasure and Memory restore continuity. This document is design, not runtime proof.
