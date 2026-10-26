# Eliot V3 — One-shot inference contract

**Revision 0.8-draft · 2026-10-26 · shared Memory OS ↔ `eliot-swarm-controller` boundary; not implemented.**

This is the sole normative contract for one-shot text and embedding execution. It keeps Memory semantics in Memory and physical model execution in controller. It deliberately does **not** create Task/Attempt/review machinery, another scheduler, another receipt store, generic provider fields, implicit retries or caller migration.

The contract prevents these failures:

1. copying provider credentials/routing into Memory;
2. wrapping one reversible inference request in the agent-task lifecycle;
3. persisting prompts, embedding inputs or token verifiers in generic Operation JSON;
4. orphaning old Operations by changing `client_id` during token rotation or restore;
5. trusting the credential file supplied by Memory instead of the authenticated hello result;
6. treating a verifier update as revocation while an already authenticated Principal remains usable;
7. disclosing inference result bytes through Operator cleanup authority;
8. duplicating provider work after a lost reply or restored backup;
9. creating a durable “possibly submitted/proven unsent” state machine that duplicates controller idempotency.

Memory owns the finite job, frozen sources, prompt/embedding recipe, disclosure reduction, exact request identity, decoding and publication. Controller owns caller authentication, profiles/connections, provider invocation, Operation deduplication/readback and temporary controlled copies.

## 1. Exact application surface

Controller adds one role:

```text
inference_client
```

It is not Manager, Operator, Observer, Participant or Module. `Principal::require_writer` continues to reject it. It has no MCP discovery surface and no generic mutation fallback.

Allowed methods are exactly:

```text
mutations:
  inference.text
  inference.embed
  inference.release
  operation.cancel       # own queued inference Operation only

reads:
  operation.get          # own retained inference Operation only
  artifact.get           # own retained inference_result only
  artifact.read          # own retained inference_result only
```

Store dispatches this allowlist only after current registration and credential-generation validation. No Task, Requirement, Attempt, binding, workspace, native agent session, review, submission, acceptance or ScriptRun is created.

## 2. Caller and credential identity

Controller authentication has four distinct values:

```text
client_id               stable retained principal
credential_id           non-secret identity of one secret generation
credential_generation   positive monotonic authorization generation
secret/token             replaceable authentication material
```

For one Memory installation, `client_id` is generated once and retained conceptually as:

```text
eliot-memory:<stable-installation-id>
```

It survives daemon restart, Store-root cutover, rollback, backup restore and token rotation. It is not derived from PID, executable path, data-root generation, backup generation, token digest or time.

Operation/artifact ownership is the stable `client_id`, never `credential_id`, generation or token. Same-client rotation must not rewrite `caller_id`, request identity, Operation ID or artifact provenance.

Changing `client_id` is principal migration. Initial V3 provides no migration or ownership-transfer path. A new principal cannot adopt old work through Operator access, a new request ID or metadata rewriting.

Every Memory controller-backed job retains, without secrets:

```text
controller_client_id
client_request_id
method + canonical bounded request identity
controller_operation_id when known
result artifact identity/digest/length when known
profile/adapter/connection/destination snapshot
credential_id + credential_generation used for the physical connection
release Operation/disposition and per-copy cleanup state
controller_reconciliation state
```

Credential identity is diagnostic/admission evidence. It does not own the Operation.

## 3. Generation-aware hello protocol

Memory uses the exact pinned `swarm-client`, never MCP, a copied framing implementation or a spawned general-purpose controller CLI.

The first generation-aware inference protocol is exactly:

```text
protocol_version = 2
```

Version 1 is not generation-aware and cannot authorize V3 inference. Support is never inferred from unknown JSON fields.

`swarm-client` must expose `connect_verified` or an equivalent closed constructor. The successful typed hello receipt is exactly:

```text
client_id
role
credential_id
credential_generation
protocol_version
```

No application-capable handle is returned unless:

```text
receipt.client_id == installation.controller_client_id
receipt.client_id == supplied credential.client_id
receipt.role == inference_client
receipt.credential_id == installation.selected_credential_id
receipt.credential_generation == installation.selected_credential_generation
receipt.credential_generation > 0
receipt.protocol_version == 2
no missing, unknown or malformed receipt fields
```

Mismatch closes/poisons the connection before any application frame and returns a typed failure such as:

```text
CALLER_IDENTITY_UNAVAILABLE
CREDENTIAL_ID_MISMATCH
CREDENTIAL_GENERATION_MISMATCH
HOST_HANDSHAKE_FAILED
```

Memory does not infer authenticated identity from its own credential file and never substitutes Manager/Operator/Module authority.

At inspected controller revision `e42c464d`, host hello returns `client_id`, role and protocol version, but `swarm-client::Client::connect` discards that result. The current Principal also has no credential ID/generation. That revision is a donor, not an implementation of this section.

## 4. Provisioning owner and secret path

Memory never receives controller `operator.json` or any controller Operator token.

Provisioning is owned by a **controller-local maintenance command** running against the controller data root, conceptually:

```text
swarm inference-client install \
  --client-id <stable-memory-client-id> \
  --credential-out <absolute-private-new-path>

swarm inference-client rotate \
  --client-id <stable-memory-client-id> \
  --credential-out <absolute-private-pending-path>
```

The command:

1. validates the controller data root and loads its own private `operator.json` internally;
2. exclusively creates and durably flushes one pending private credential bundle containing `client_id`, a stable `client_request_id`, one high-entropy token, one independent non-secret new `credential_id`, and the expected current credential ID/generation (or install generation 0);
3. on command retry, loads that exact pending bundle instead of generating replacement material;
4. invokes the specialized Store operation over authenticated local IPC;
5. returns a closed non-secret receipt containing client ID, credential ID and committed generation;
6. never prints token/verifier bytes, places them on argv, logs them or gives controller Operator authority to Memory.

The private bundle exists before a possible Store commit, so a process crash cannot commit an authentication verifier whose token is unrecoverable. After an unknown reply, the same command reloads the same pending bundle and classifies by authenticated hello/exact replay. It never overwrites an existing pending path.

The Memory installer/supervisor coordinates only the bundle reference and non-secret receipt in `installation.toml`. The daemon receives the selected inference credential reference needed to connect; it never receives controller Operator credentials.

A failed or unknown provisioning command retains one pending credential bundle/reference for reconciliation. It does not generate another token under the same retained mutation identity.

## 5. Specialized install and rotation

Generic `client.register` is not reused. At `e42c464d` it accepts current-GM authority, rejects an existing client and sends `token_hash` through generic mutation persistence. That is unsuitable for installation-scoped inference credentials.

Controller adds two non-MCP, local-Operator-only Store operations:

```text
inference.client.install
inference.credential.rotate
```

Their secret-bearing request is handled by a specialized transaction. Token bytes, `token_hash`, token-derived fingerprints and reusable verifiers may exist only in the private authentication registration and must never enter:

```text
operations.original_request_json
operations.effective_request_json
operations.result_json
observations
client.list / status
logs / telemetry / diagnostics
Memory Store / backup / configuration
```

The durable redacted mutation identity is:

```text
(local Operator caller,
 client_request_id,
 method,
 target client_id,
 new credential_id,
 expected current credential_id/generation)
```

### 5.1 `inference.client.install`

It atomically:

1. requires the expected stable client ID and absent registration;
2. creates role `inference_client`, supplied independent `credential_id`, generation `1`, verifier and `disabled=false`;
3. writes a redacted Operation receipt;
4. returns exact replay of the same receipt;
5. rejects any incompatible existing registration without overwrite or migration.

### 5.2 `inference.credential.rotate`

It atomically:

1. requires local Operator, exact target client ID, role `inference_client`, current credential ID and expected positive generation;
2. replaces only verifier/credential ID and increments generation exactly once;
3. preserves caller identity and all Operation/artifact ownership;
4. returns exact replay of the retained new credential ID/generation;
5. rejects stale generation, wrong current credential ID or a different new credential ID as conflict;
6. never creates a second principal or ownership alias.

`client.list` remains a non-secret projection of client ID, role and disabled state. It never exposes verifier or credential material.

## 6. Generation fencing and revocation

Authentication captures `credential_id` and `credential_generation` in the server-side Principal. Before **every** inference-client read or mutation, Store reloads the registration and requires:

```text
registration exists
registration.role == inference_client
registration.disabled == false
principal.credential_id == registration.credential_id
principal.credential_generation == registration.credential_generation
```

This check occurs before provider admission, artifact read, Operation read/cancel and release. No long-poll, module or generic-writer path bypasses it.

The single Store owner serializes rotation with application admission:

- a request admitted before rotation remains an Operation owned by the same stable caller;
- an old Principal evaluated after rotation receives terminal `CREDENTIAL_STALE` before application admission;
- the new generation may read/release pre-rotation Operations because caller ownership is unchanged.

`swarm-client` treats `CREDENTIAL_STALE` as connection-poisoning and closes the transport. Controller reaps the stale session after its terminal response. A full host restart is not the selected revocation mechanism.

If generation fencing is absent, token replacement is not qualified revocation.

## 7. Rotation reconciliation

Memory installation selection retains at most one current, one pending and one unretired previous inference credential reference, each bound to exact non-secret credential ID/generation. Another rotation is refused while pending/previous remains unresolved.

After a lost rotate reply:

1. probe the pending credential and require hello with the expected new credential ID/generation;
2. if pending fails, probe current and require the old credential ID/generation;
3. never generate another pending token during classification;
4. when pending succeeds, read the redacted rotation receipt and one pre-rotation Operation under the same client ID;
5. atomically publish pending→current and current→previous in Memory installation selection;
6. reconnect the daemon and prove old Operation read/release;
7. retire previous secret/reference only in a later explicit cleanup step.

Contradictory observations, neither credential authenticating, hello/receipt disagreement or unreadable selection leaves rotation incomplete with both references retained.

## 8. Connections, profiles and disclosure

Controller owns static `InferenceConnection` and `InferenceProfile` records.

A connection contains:

```text
name
versioned adapter/transport ID
canonical endpoint
private provider-credential reference
actual_destination = local | external
explicit transport-security behavior
```

A loopback gateway forwarding to cloud is `external`. Provider secret bytes never enter Operation JSON, logs, digests or receipts. Initial adapters support no arbitrary headers, query parameters, extra body, environment proxy or redirects.

A profile contains:

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

Digests cover non-secret behavior-changing fields. Reconfiguration affects new admissions only. Memory selects a profile name; it cannot construct provider headers, arbitrary extras or fallback ladders.

Memory reduces supplied material to:

```text
local_only
external_allowed
```

Derived content cannot widen the strictest source it still reveals. Controller authoritatively validates current caller/generation, profile/connection, actual destination, origin, exact input digest/length, format, limits and known capacity. Protected content is not silently omitted to pass external admission.

Admission failure is operational failure, not cognitive no-change, and does not mark input processed.

## 9. Controlled input and result copies

One inference Operation creates at most:

```text
inference_input
inference_result
```

Before provider I/O, controller stages exact accepted input under deterministic Operation-owned identity, verifies bytes/digest and commits bounded Operation metadata without raw prompt/input in generic JSON. An orphan file without a committed Operation is cleanup material and never dispatchable.

When a visible result exists, controller stages bounded bytes, verifies digest/length, publishes the exact file and settles with a closed receipt. Provider-safe failure metadata may exist without a result artifact. Raw provider errors are not automatically cognitive content.

Crash handling is explicit:

```text
metadata but missing/mismatched exact file -> unavailable/damaged
exact pending file but settlement missing  -> verify and finish settlement
settled receipt but missing/mismatched file -> damaged result
```

Per-copy state is:

```text
not_created | retained | cleanup_pending | removed | already_absent | mismatch | unknown
```

Aggregate cleanup is derived and cannot hide a remaining copy:

```text
retained | cleanup_pending | cleanup_incomplete | released
```

## 10. Text and embedding requests

### 10.1 `inference.text`

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

`origin` is `explicit | automatic`. Automatic admission requires profile permission. Validation covers exact bytes/digest, caller/generation, frame/profile limits, destination/disclosure, format and capacity.

### 10.2 `inference.embed`

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

`role = query | document` maps through the selected adapter's actual task parameter/prefix. Canonical result contains one exact result/error per input key plus one effective space identity: profile digest, observed model, dimensions and role. Missing/duplicate/unresolvable positions, inconsistent dimensions or non-finite vectors fail. Never repair with zero vectors or shifted assignment.

## 11. Operation identity and reconciliation

Inference Operation identity is:

```text
(controller_client_id,
 client_request_id,
 method,
 canonical bounded request identity)
```

Canonical identity contains input digest/length, not raw input. Same caller + exact identity returns the original Operation/admission state regardless of later credential generation. Different method/profile/limits/format/role/input digest under the same request ID is `REQUEST_ID_CONFLICT`.

The existing Operation table is sufficient:

- `caller_id` — stable controller client ID;
- `client_request_id` — caller correlation key;
- `original_request_json` — bounded redacted identity;
- `effective_request_json` — frozen profile/connection/input/execution facts;
- `result_json` — closed receipt and cleanup state;
- existing queued/sending/native-accepted/settled/rejected/cancelled/abandoned/unknown states.

Do not add `inference_runs`, another scheduler or a submission-phase ledger.

`swarm-client` never automatically resends an application request. When Memory has no known Operation ID after disconnect/restore, it deliberately invokes the **same method with the exact retained identity once after verified hello**. Controller then performs one `reconcile-or-admit` decision:

```text
matching Operation exists   -> return original Operation/admission receipt
no matching Operation exists -> create the first admission
same request ID, other identity -> REQUEST_ID_CONFLICT
caller unavailable          -> no call; hold job
```

Memory does not need a durable `possible_send` versus `proven_no_send` state. Provider-send uncertainty remains inside the admitted controller Operation and is never permission to call the provider again.

## 12. Bounded runner and provider uncertainty

One controller runner consumes queued `inference.text/embed` Operations using the existing Operation ledger/wake signal.

1. select eligible queued Operation under frozen profile concurrency;
2. verify exact input artifact, caller registration and frozen profile/connection;
3. CAS `queued → sending` before provider I/O;
4. perform one provider attempt outside Store transaction;
5. retain native admission/response identity when supplied;
6. persist exact result when present and terminal receipt;
7. wake readers and continue finite work.

Possible provider send followed by timeout/loss becomes `unknown` unless native idempotency/readback resolves it. It is never redispatched merely because Memory replays the admission identity.

Restart behavior:

```text
verified queued input          -> eligible once
sending/native accepted        -> native readback or unknown
verified pending result        -> finish settlement
abandoned                      -> never dispatch/publish late result
```

Credential rotation does not cancel an admitted Operation. Disabling/removing the stable principal is a separate authority transition that must disposition queued/unknown copies explicitly.

## 13. Initial provider adapters

Initial text adapter:

```text
openai_chat_completions_loopback_v1
POST <base>/chat/completions
Content-Type: application/json
Accept: application/json
optional Bearer from private connection file
```

Body contains only model, one exact user message, admitted `max_tokens` and typed `json_object` format when supported. No tools, streaming, temperature, stop list, arbitrary fields, redirects, hidden retry or fallback model.

Response requires bounded JSON and one usable `choices[0].message.content`. Length finish is partial, never complete. Tool-only, content-free or unsupported multimodal output fails. Usage/cost/account remain unknown when absent.

Initial embedding adapter:

```text
openai_embeddings_loopback_v1
```

It posts bounded model/input array and verifies count, indices, finite vectors and consistent dimensions.

Loopback does not prove local destination. Direct HTTPS is a later separately qualified adapter with pinned TLS behavior, no proxies/redirects and the same no-replay/copy lifecycle.

## 14. Read, cancel, release and erasure authority

`operation.get` returns a bounded receipt only to the exact currently authenticated stable caller. Only that caller receives its `client_request_id` and result artifact identity. Missing usage/cost/account is unknown, never zero or inferred.

`inference_result` byte authorization requires:

```text
artifact kind == inference_result
settled Operation names exact artifact/digest/length
requesting current principal.client_id == retained caller_id
requesting credential ID/generation is current for this physical request
content is not released
```

`inference_input` has no public read grant.

`operation.cancel` handles only the exact caller's queued inference Operation. After provider I/O may have begun, cancellation cannot prove non-execution.

`inference.release` is idempotent over one exact inference Operation and supports:

```text
memory_copy_verified    exact result durably copied by Memory
terminal_without_result terminal state with no possible future result
abandon_for_erasure     fence queued/sending/unknown publication, then erase
```

For every expected file controller verifies Operation provenance, canonical path, regular-file/no-reparse identity, length/digest when present, exact deletion and parent-directory durability. Missing exact file becomes `already_absent`; mismatch blocks deletion. Partial cleanup remains visible and retryable.

A verified local Operator may invoke a separate bounded erasure/abandonment branch that validates exact provenance, fences late publication and deletes controlled copies. It returns only non-content disposition/cleanup facts. It cannot satisfy `artifact.get/read`, disclose result bytes, adopt caller ownership or fabricate a Memory result. Provider non-execution/deletion/no-charge is never claimed.

## 15. Memory backup and restore

A Memory backup retains stable caller/request/method/canonical request identity, known Operation/artifact/release identity, cleanup state and selected non-secret credential ID/generation. It never contains token/verifier bytes.

Before reconciling restored inference jobs, Memory authenticates the selected current credential and validates the exact protocol-v2 hello receipt.

Restored job handling is only:

```text
known controller_operation_id
  -> operation/artifact/release readback; never redispatch

unknown controller_operation_id
  -> exact same-caller reconcile-or-admit call using retained method/request identity

caller/credential/role/protocol unavailable
  -> caller_identity_unavailable; hold job and cleanup debt; no call
```

A new caller or request ID is not recovery. Local Operator erasure can end controlled-copy reconciliation but cannot transfer ownership or produce a cognitive result. Out-of-target current Operations may block Store-root rollback cutover until terminal/released or explicitly abandoned.

## 16. Implementation increments

Do not make full rotation a prerequisite for first useful inference.

### P1a — connected inference

1. add `inference_client` and deny generic writer authority;
2. add credential ID/generation to registration and Principal;
3. implement protocol-v2 typed hello and verified client constructor;
4. implement controller-local one-time install at generation 1;
5. enforce generation check on every allowed method;
6. add profile/connection parsing and disclosure admission;
7. add controlled input/result domains;
8. implement `inference.text`, runner, exact result readback and release;
9. connect one Memory episode-learning job and restore reconciliation path.

### P1b — credential rotation

1. implement rotate with current/pending/previous identity;
2. classify lost reply using retained pending/current credentials;
3. reject/reap stale sessions through generation fencing;
4. prove pre-rotation Operation read/release with the new generation;
5. retire old secret/reference in a later cleanup step.

### P2

Add embeddings through the same lifecycle, then qualify direct HTTPS only when required.

## 17. Reuse and current gaps

Reuse from inspected controller source:

- authenticated bounded IPC framing and no automatic application replay;
- stable caller/request Operation conflict behavior;
- exact-caller Operation/artifact authorization;
- immutable artifact publish/read/digest verification;
- existing Operation states, wake signal and bounded worker pattern;
- safe non-secret `client.list` projection;
- bounded no-redirect/no-hidden-retry HTTP patterns.

Do not reuse unchanged:

- `swarm-client::Client::connect` that discards hello result;
- generic `client.register` or generic mutation storage for inference credentials;
- current-GM authority for installation credentials;
- Principal validation without credential ID/generation;
- Manager/Operator as ordinary inference caller;
- Task/Attempt/ScriptRun/module binding;
- Operator result-byte reads or ownership transfer;
- hidden provider retry/fallback;
- caller migration as token rotation;
- a new request ID after uncertainty;
- another task/profile/capability/receipt registry.

At controller revision `e42c464d`, these remain absent: `inference_client`; protocol-v2 verified hello; credential ID/generation and stale-session fence; controller-local redacted install/rotation; inference methods/artifacts/runner/release; non-disclosing Operator erasure; and Memory restore continuity. This contract is design, not runtime proof.
