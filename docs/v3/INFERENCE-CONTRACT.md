# Eliot V3 — One-shot inference contract

**Revision 0.4-draft · 2026-10-24 · shared boundary for Memory OS and `eliot-swarm-controller`; not implemented.**

This is the sole normative Memory↔controller contract for one-shot model execution. It prevents these wrong implementations:

1. wrapping one memory extraction in controller Task/Attempt/review/acceptance;
2. copying provider credentials, routing and retry logic into Memory OS;
3. restoring the old Governor route/capability/fingerprint platform around a reversible request;
4. routing inference through ScriptRun/module-binding machinery merely because it is taskless;
5. retaining controller copies of prompts or results indefinitely after Memory no longer needs them;
6. calling an unspecified “OpenAI-compatible” service through arbitrary headers/body fields and treating interface similarity as qualified behavior;
7. losing the input-cleanup path when an Operation fails, is cancelled or is abandoned before producing a result.

Memory owns its finite job, frozen source membership, exact processing recipe, disclosure reduction, stable request identity, cognitive decoding and publication. Controller owns configured connections and credentials, physical provider invocation, Operation deduplication/readback and temporary controlled input/result copies.

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

`inference.text` and `inference.embed` are mutations because they may spend quota and create an external effect. `inference.release` is an idempotent mutation over one exact inference Operation. It releases every controller-owned content copy that the validated disposition permits, including an input-only Operation with no result.

None of these methods creates or requires:

- Task or Requirement;
- Attempt;
- binding, workspace or native agent session;
- review, submission or acceptance;
- agent tools or continuation;
- ScriptRun registry, interpreter or effect lifecycle;
- a Memory-side provider credential.

## 2. Narrow caller authority and direct IPC

Controller adds one authenticated role:

```text
inference_client
```

It is not Manager, Operator, Observer, Participant or a bound Module. It has no MCP discovery surface and no generic writer authority.

Its complete application surface is:

```text
mutations:
  inference.text
  inference.embed
  inference.release
  operation.cancel       # only its own still-queued inference Operation

reads:
  operation.get          # only its own retained Operation receipt
  artifact.get           # only its own retained inference result
  artifact.read          # only its own retained inference result
```

The Store dispatches this role through an explicit allowlist before generic writer handling. `Principal::require_writer` continues to reject it outside that branch. A local setup owner registers the credential once; the credential carries no project, Task, workspace or binding authority.

Existing exact-caller Operation readback is reused. There is no second receipt store.

### 2.1 Direct IPC client

Memory calls controller through the existing authenticated local IPC protocol, not MCP and not a spawned CLI command.

The current `swarm-client` already:

- accepts an arbitrary method name and JSON params;
- performs no task or role policy;
- retries only Windows pipe establishment before authentication/application I/O;
- never automatically resends an application request;
- reports cancellation/disconnect/partial reply after possible write as `OUTCOME_UNKNOWN` and retires the connection.

Memory reuses this implementation as an exact-revision Git dependency from the controller repository. It does not copy framing or authentication code. `publish=false` is not a reason to fork the protocol; changing the pin is an explicit integration update.

Memory configuration stores only:

```text
controller data root / IPC root
private inference-client credential file
bounded IPC settings, normally controller defaults
selected inference profile names
```

The public inference payload must fit the configured IPC frame. The initial contract has no generic upload/session protocol for oversized prompts; admission returns `IPC_FRAME_LIMIT` or `INPUT_LIMIT_EXCEEDED` before provider I/O.

## 3. Static connections and profiles

Controller configuration owns static `InferenceConnection` and `InferenceProfile` records. Neither is an agent Route, dynamic registry, capability-evidence record or admission receipt.

### 3.1 `InferenceConnection`

A connection owns transport and secret material independently of model behavior:

```toml
[[inference_connections]]
name = "memory-loopback-gateway"
transport = "loopback_http_v1"
base_url = "http://127.0.0.1:8000/v1/"
credential_file = "C:\\EliotPrivate\\memory-gateway.json" # optional
actual_destination = "external"                             # local | external
```

`actual_destination` describes where supplied content ultimately goes, not merely the next TCP hop. A loopback gateway forwarding to a cloud provider is `external`. Controller cannot infer upstream egress from a loopback URL; the local installation declares it and the frozen receipt preserves it.

The connection reader follows the existing bounded-private-file pattern:

- absolute configured path;
- bounded regular file, no symlink or pipe;
- closed schema;
- optional `none` or Bearer authentication for the first adapter;
- secrets never copied into Operation JSON, logs, profile digest or public receipts.

The initial connection contract does not support arbitrary request headers, arbitrary query parameters, arbitrary `extra_body`, environment proxy discovery or redirects.

Controller computes a non-secret `connection_digest` over behavior-changing connection fields:

```text
connection name
+ transport ID
+ canonical endpoint
+ actual destination
+ authentication mode, not credential bytes/path
+ explicit transport-security options
```

Credential/account rotation under an unchanged connection digest is not described as a proven identical account. Unavailable account or billing identity remains unknown.

### 3.2 `InferenceProfile`

A profile selects one versioned serializer/decoder and model over one connection:

```toml
[[inference_profiles]]
name = "memory-text-default"
adapter = "openai_chat_completions_loopback_v1"
connection = "memory-loopback-gateway"
model = "configured-model-id"
allow_automatic = false
max_input_bytes = 262144
max_output_tokens = 4096
timeout_seconds = 120
max_concurrency = 1
response_formats = ["text", "json_object"]
```

Numeric values are examples, not normative defaults.

The resolved profile inherits `actual_destination` and `connection_digest` from its connection. Controller validates finite positive bounds and a supported adapter/connection/model combination.

Controller computes the immutable `profile_digest` over non-secret behavior-changing fields:

```text
profile name
+ versioned adapter ID
+ connection reference and connection digest
+ requested model
+ actual destination
+ automatic-use flag
+ input/output/time/concurrency limits
+ response-format capabilities
```

A manually maintained generation counter is not required. Reconfiguration changes the digest and affects a new explicit request; it never mutates the snapshot retained by an admitted Operation.

There is no implicit fallback. An unavailable connection, profile, provider, model or capacity returns a specific waiting, rejection, failure or unknown state. Controller does not silently switch provider, model, account, destination, retention or billing semantics.

## 4. Disclosure and authoritative admission

Memory reduces the material actually supplied to one value:

```text
local_only
external_allowed
```

Rules:

- project configuration supplies the default;
- an observation or source can be stricter;
- a derived item cannot be less restrictive than content it still contains or reveals;
- mixed input uses the strictest contributing value;
- reusable scope does not widen disclosure;
- protected material is not silently omitted merely to make another profile admissible.

Memory selects a profile name and sends the reduced disclosure with the exact input. Controller authoritatively resolves the profile and connection, inherits `actual_destination`, and checks:

- profile and connection existence/enabled state;
- disclosure versus actual destination;
- explicit versus automatic origin;
- input/output/time and format limits;
- adapter/connection compatibility;
- known capacity before provider I/O where possible.

`local_only` requires `actual_destination=local`. Memory must not pre-approve a request from a loopback URL or stale duplicate connection configuration.

If necessary material cannot use the selected profile, the job waits or fails with a specific profile/destination/disclosure state. That is not no-change and does not mark input processed.

This two-state reduction is deliberately smaller than the old privacy-policy platform. It is checked at the actual external-send owner.

## 5. Controlled request and result artifacts

One inference Operation owns at most two controller content artifacts:

```text
inference_input
inference_result
```

Both use deterministic controller-generated IDs, immutable regular files and exact digests. Each has a row in the existing `artifacts` table.

### 5.1 Input artifact

The public request carries prompt or embedding inputs, but generic mutation code must **not** store raw content in `operations.original_request_json`.

Custom inference admission:

1. validates request identity, hashes, bounds and profile/disclosure compatibility;
2. builds one canonical input payload;
3. atomically publishes an `inference_input` file before provider I/O;
4. inserts the artifact row and inference Operation in one short Store transaction;
5. stores only bounded identity facts in Operation request/effective records:
   - content artifact identity;
   - content length and digest;
   - profile name/digest and connection digest;
   - adapter, requested model and actual destination;
   - origin, disclosure and output limits;
   - method-specific role/format fields.

A crash before DB commit may leave an unregistered file. It is an orphan eligible for bounded local cleanup and never authorizes provider execution.

`inference_input` is controller-private. Memory already owns the source request and receives no artifact read grant for this duplicate.

### 5.2 Result artifact

A usable provider response is published as `inference_result`.

Text results contain the exact visible assistant content selected by the versioned adapter, not the complete HTTP envelope or hidden reasoning. Embedding results contain one canonical JSON body with independent per-input outcomes.

Before publishing the file, controller records bounded pending-result identity on the Operation:

```text
status
expected artifact ID
byte length
content digest
requested/observed execution facts
finish/usage/limit metadata
```

Then it atomically publishes the file and settles the Operation with artifact row and closed public receipt in one transaction.

Crash states remain explicit:

- pending metadata but no file → result body unavailable; never complete;
- exact file present but settlement missing → restart verifies expected file and may finish settlement;
- settled receipt without exact file/digest → damaged retained result, not successful no-change.

A received provider error may be represented by bounded safe failure metadata without an `inference_result`. Raw provider error bodies are not automatically retained as cognitive content.

### 5.3 Per-copy cleanup state

Controller tracks cleanup independently for input and result:

```text
not_created
retained
cleanup_pending
removed
already_absent
mismatch
unknown
```

The aggregate release state is derived:

```text
retained
cleanup_pending
cleanup_incomplete
released
```

A single aggregate boolean is insufficient because one file may be removed while the other remains or fails exact verification.

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

`origin` is `explicit` or `automatic`. Automatic requests are rejected before provider I/O unless the frozen profile allows automatic use.

Validation checks:

- bounded stable request ID;
- exact prompt bytes and digest;
- IPC/profile input limit;
- profile and connection existence/enabled state;
- actual destination versus disclosure;
- requested output not exceeding profile;
- response format supported by adapter/profile;
- automatic-use permission;
- known controller capacity.

Memory recipe and source IDs are not controller domain objects. They are already bound inside the exact prompt and retained Memory job. Controller does not validate the cognitive JSON schema beyond requested transport response format.

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

`role` is `query` or `document` and maps through the selected adapter's actual task parameter or prefix.

Canonical result body:

```json
{
  "space": {
    "profile_digest": "...",
    "observed_model": "...",
    "dimensions": 1024,
    "role": "document"
  },
  "items": [
    {"input_key": "memory:abc@7", "vector": [0.1, 0.2]},
    {"input_key": "memory:def@2", "error": {"code": "INPUT_TOO_LARGE"}}
  ]
}
```

Each input has exactly one independently addressable result or error. Missing, duplicate or unresolvable positions are errors; they are never repaired with zero vectors or shifted assignment. A provider that aggregates several inputs into one vector does not satisfy this contract for independent Memory items.

## 8. Admission and exact replay

Controller reuses its existing identity rule:

```text
(caller identity, client_request_id, method, canonical bounded request identity)
```

Canonical identity includes input digest/length rather than raw bytes. Exact replay returns the original Operation/admission state. Different method, profile, limits, format, role or input digest under the same request ID is `REQUEST_ID_CONFLICT`.

The existing Operation table is sufficient initially:

- `original_request_json` — bounded identity, never raw prompt/input;
- `effective_request_json` — frozen profile/connection snapshot, controlled input reference and execution/readback facts;
- `result_json` — closed public result and per-copy release state;
- existing Operation state — queued, sending, native accepted when known, settled, rejected, cancelled, abandoned or outcome unknown.

Do not add `inference_runs`, a generic external-job framework or a second scheduler before an actual field cannot be represented or queried through this owner.

The generic mutation helper is reused conceptually for identity and receipts, but not called unchanged: it would persist raw public payload and cannot stage private files correctly.

## 9. Initial provider adapters

### 9.1 Text adapter

The first text implementation is exactly:

```text
openai_chat_completions_loopback_v1
```

It calls a configured loopback HTTP origin. The gateway may serve a local model or forward to an external provider; `actual_destination` records that distinction.

Wire behavior is closed and versioned:

```text
POST <base>/chat/completions
Content-Type: application/json
Accept: application/json
optional Bearer authorization from the private connection file
```

Request body contains only:

```text
model
messages = [{ role: "user", content: exact prompt }]
max_tokens = admitted max_output_tokens
response_format = { type: "json_object" } only when requested and supported
```

The adapter sends no tools, streaming flag, temperature, stop list, arbitrary headers, arbitrary provider fields or fallback model. Provider-specific changes require another typed adapter revision.

Response decoding requires a bounded JSON response with one usable `choices[0].message.content` string. It records observed model, finish reason, response ID and usage only when supplied. Tool calls, content-free answers and unsupported multimodal blocks fail explicitly. `finish_reason=length` or equivalent yields `partial`, never `complete`.

No hidden transport/SDK retry is enabled. A received non-success response is retained as one failed attempt with bounded safe metadata. A transport failure after possible send is `unknown`.

### 9.2 Embedding adapter

The first embedding implementation is exactly:

```text
openai_embeddings_loopback_v1
```

It uses bounded `POST <base>/embeddings` with `model` and input array. The adapter verifies response indices, count, finite numeric vectors and one consistent dimension, then converts output into the canonical per-input body in §7. Provider batching failure does not shift results or create zero vectors.

### 9.3 Transport hardening and HTTPS

The current controller OpenCode HTTP client is a donor for:

- no redirects;
- no environment proxy;
- no hidden retries;
- connect and request deadlines;
- bounded response/error bodies;
- safe public errors;
- unknown outcome after possible mutation send.

It is not reused as a session/provider abstraction.

Current controller `reqwest` uses `default-features=false` with `json,stream`; direct external HTTPS is therefore not qualified by current source. A later adapter such as `openai_chat_completions_https_v1` must explicitly enable/qualify TLS, require HTTPS, keep redirects and implicit proxies disabled, and retain the same no-replay and controlled-copy lifecycle.

## 10. One bounded runner

A small controller runner consumes only queued `inference.text` and `inference.embed` Operations. It reuses controller wake signal and Operation ledger; it is not a second scheduler or process.

Execution:

1. select eligible queued Operation under frozen profile concurrency limit;
2. verify private input artifact and frozen profile/connection snapshot;
3. CAS `queued → sending` before provider I/O;
4. perform one provider attempt outside Store transaction;
5. record native admission/response identity when actually supplied;
6. persist pending result metadata, exact result file and terminal receipt;
7. wake readers and continue finite work.

Timeout or connection loss after possible send becomes `outcome_unknown` unless native idempotency/readback resolves it. A new request ID is not recovery.

At controller restart:

- queued Operations with verified input remain eligible;
- sending/native-accepted Operations use native readback when supported;
- otherwise they remain `outcome_unknown`;
- verified pending result file may finish settlement;
- abandoned Operations never re-enter provider dispatch or publish a late result;
- no restart path automatically issues another provider call.

## 11. Public result and cleanup receipt

`operation.get` grants a bounded receipt to the exact caller without Task linkage. Projection is closed and never exposes arbitrary provider JSON or credential data.

Conceptual result:

```json
{
  "status": "complete",
  "artifact_ref": "inference-result-id",
  "byte_length": 1234,
  "sha256": "...",
  "encoding": "utf-8",
  "requested": {
    "profile": "memory-text-default",
    "profile_digest": "...",
    "adapter": "openai_chat_completions_loopback_v1",
    "connection_digest": "...",
    "model": "configured-model-id",
    "actual_destination": "local"
  },
  "observed": {
    "provider": "...",
    "model": "...",
    "response_id": "..."
  },
  "finish_reason": "stop",
  "usage": {"input_tokens": 1000, "output_tokens": 200},
  "cost": null,
  "limits": [],
  "controlled_copies": {
    "input": "retained",
    "result": "retained"
  },
  "release_state": "retained"
}
```

Application status is:

```text
complete
partial
failed
unknown
```

Rules:

- `complete`/`partial` require exact retained result bytes and usable artifact readback;
- empty, malformed or cognitively invalid text may still be a transport-complete body; Memory decides decode success;
- `unknown` retains Operation/request/profile identity and does not authorize another call;
- requested and observed facts remain distinct;
- missing usage/cost/response ID/account stays absent or explicit unknown, never zero or inferred;
- truncation/output-limit facts appear in `limits` and cannot be hidden behind `complete`;
- cleanup projection reports input and result independently.

Controller artifact authorization is closed. Add `InferenceResult` provenance verification:

- artifact kind is `inference_result`;
- settled inference Operation names same artifact, digest and length;
- requesting principal is exact Operation caller or verified local operator;
- released content is not readable.

Do not relabel result as `script_result` or `native_result`, trust metadata alone, or grant it through Task scope. `inference_input` has no public read grant.

## 12. Cancellation and abandonment

`operation.cancel` handles only an exact caller's still-queued inference Operation. Cancellation races runner CAS; one wins.

Once provider I/O may have begun, local cancellation cannot prove non-execution. Preserve Operation for reconciliation. A future adapter may expose native cancellation, but acknowledgement never proves no response, copy or charge occurred.

Queued cancellation produces a terminal no-result Operation whose input artifact is releasable through `inference.release` with `terminal_without_result`.

An `outcome_unknown` Operation is not ordinary terminal failure. It may be abandoned only through the explicit `abandon_for_erasure` release disposition in §13. That decision prevents future controller reconciliation/publication for the Operation but cannot delete provider-held data or undo a provider-side effect.

## 13. `inference.release`

Release is the only content-cleanup mutation for an inference Operation. It is safe for three validated dispositions:

```text
memory_copy_verified       Memory copied and verified an existing result
terminal_without_result    Operation can no longer produce a result and has none
abandon_for_erasure        owner accepts loss of reconciliation for erasure
```

Conceptual request:

```json
{
  "client_request_id": "stable-release-key",
  "operation_id": "inference-operation-id",
  "disposition": "memory_copy_verified",
  "expected_input_sha256": "optional-known-input-digest",
  "expected_result": {
    "artifact_ref": "inference-result-id",
    "sha256": "..."
  }
}
```

`expected_result` is:

- required for `memory_copy_verified`;
- absent for `terminal_without_result` when no result exists;
- optional for `abandon_for_erasure` only when the result is absent or intentionally discarded under erasure.

Controller independently validates caller, target Operation, artifact identities and disposition eligibility:

### 13.1 `memory_copy_verified`

Allowed only when target Operation has a retained result matching expected artifact/digest and Memory acknowledges its durable exact copy. Input and result become cleanup targets.

### 13.2 `terminal_without_result`

Allowed only when target Operation is rejected, failed without retained result, or cancelled before send, and no future controller result can be published. Input is cleanup target; result state is `not_created`.

### 13.3 `abandon_for_erasure`

Allowed for exact caller or verified local operator when erasure requires ending reconciliation of queued/sending/unknown work.

Before deleting content, controller atomically marks the target Operation abandoned and fenced from dispatch, settlement and result publication. A late provider response is not exposed as a result; any controller-received content is discarded through the same exact-file owner and only bounded non-content late-arrival facts remain.

This disposition cannot prove that provider execution, storage or billing did not occur. The public receipt states that external effects/copies remain unknown or external.

### 13.4 Cleanup algorithm

Release is a narrow owner operation:

1. validate disposition and exact expected identities;
2. transactionally reserve `cleanup_pending` independently for input and result and retain the release Operation;
3. outside transaction, verify and remove only exact regular files under controller artifact root;
4. transactionally delete matching artifact rows and store per-copy outcome;
5. derive aggregate `released` or `cleanup_incomplete` and settle release Operation.

Add private `ArtifactFiles::remove_exact(record)`. It rejects symlinks, path mismatch and digest mismatch and synchronizes the parent directory. There is no public generic artifact-delete method.

Per-copy outcomes:

```text
removed
already_absent
not_created
mismatch
unknown
```

Crash recovery:

- file still present + cleanup pending → verify and continue removal;
- exact file absent + matching pending artifact row → finalize as already absent;
- mismatch/unrelated reference → retain `mismatch`, never delete guessed path;
- release replay returns retained release result;
- partial success remains explicit per copy.

After successful release:

- controller retains only bounded text-free identity/status/deduplication facts;
- later `artifact.read` returns released/unavailable;
- Memory backup contains its copied result bytes when a result existed;
- target Operation cannot recreate released controller content.

If cleanup is incomplete, Memory may still use a verified result but reports controlled duplicate gap. Erasure is incomplete while either controller content copy remains. Provider-held copies are outside `inference.release`.

## 14. Reuse and explicit non-donors

Reuse from current controller:

- `swarm-client` authenticated bounded IPC and no-application-replay semantics;
- Operations exact caller/request identity and conflict behavior;
- exact-caller `operation.get` authorization;
- existing Operation states and failure observations;
- immutable `ArtifactFiles` publish/read/digest verification;
- generic `artifacts` table;
- controller wake signal and bounded worker pattern;
- current bounded/no-redirect/no-hidden-retry HTTP patterns.

Extend narrowly:

- `InferenceClient` role and allowlist;
- exact-revision Memory dependency on `swarm-client`;
- static connection/profile config and versioned adapter IDs;
- inference validators and custom admission;
- `inference_input` / `inference_result` artifact kinds;
- closed result and per-copy cleanup projection;
- one inference runner;
- `remove_exact` and three-disposition `inference.release` recovery.

Do **not** reuse as inference lifecycle:

- Task/Requirement/Attempt;
- `script.run`, script registry, bundles, interpreter identities, ScriptEffect or automation cause;
- Module binding/handshake/supervisor;
- agent `Route.native_options`;
- OpenCode session/service semantics;
- arbitrary `extra_headers`/`extra_body` or blind retry loop;
- review/submission/acceptance;
- generic artifact deletion endpoint.

The taskless ScriptRun fixture qualifies Store admission only and explicitly does not execute worker. Production ScriptRun owns a different product: registered scripts, interpreter/process custody, start gates, automation authority, effects and multiple artifacts. Its recovery ideas are useful; its lifecycle is not this implementation.

## 15. Status and failure vocabulary

The exact public schema is implementation-owned, but it must distinguish at least:

```text
PROFILE_NOT_FOUND
PROFILE_DISABLED
CONNECTION_NOT_FOUND
DESTINATION_MISMATCH
AUTOMATIC_USE_DISABLED
IPC_FRAME_LIMIT
INPUT_LIMIT_EXCEEDED
OUTPUT_LIMIT_EXCEEDED
RESPONSE_FORMAT_UNSUPPORTED
CAPACITY_UNAVAILABLE
REQUEST_ID_CONFLICT
EXTERNAL_OUTCOME_UNKNOWN
INPUT_NOT_RETAINED
RESULT_NOT_RETAINED
RESULT_DIGEST_MISMATCH
PROVIDER_RESPONSE_INVALID
PROVIDER_OUTPUT_UNSUPPORTED
RELEASE_DISPOSITION_INVALID
RELEASE_RESULT_REQUIRED
RELEASE_RESULT_UNEXPECTED
RESULT_RELEASE_CONFLICT
RELEASE_CLEANUP_PENDING
RELEASE_CLEANUP_INCOMPLETE
ABANDONED_FOR_ERASURE
```

These are operational states, not cognitive outcomes. Memory never converts them into `changes=[]` or successful no-change.

## 16. Implementation order

Controller owner:

1. add `InferenceClient` and exact Store-call allowlist;
2. add static connection/profile config and canonical connection/profile digests;
3. add closed request DTOs and method policy;
4. add controlled input admission without raw payload in Operation JSON;
5. add one Operation-backed runner and `openai_chat_completions_loopback_v1` with hidden retries disabled;
6. add pending-result recovery, immutable result artifact and closed public receipt/grant;
7. add per-copy cleanup state, `remove_exact` and idempotent `inference.release` for result, no-result and erasure-abandon dispositions;
8. add `openai_embeddings_loopback_v1` through the same lifecycle;
9. qualify direct HTTPS only in a later adapter with explicit TLS feature;
10. run minimum relevant build/Clippy after each coherent production increment.

Memory owner, after Base:

1. pin/reuse controller `swarm-client` rather than copying IPC;
2. implement one controller adapter for text/embed/read/cancel/release;
3. add disclosure fields/reduction;
4. save exact request before I/O;
5. copy and verify result before decode/release;
6. publish through existing job/revision path;
7. call `inference.release` with correct disposition;
8. retain per-copy cleanup and external-boundary status;
9. keep Base usable with learning disabled.

The full automated test suite follows connected product implementation. Fixtures or serializer tests do not qualify a provider route or demonstrate learning.
