# Eliot V3 — One-shot inference contract

**Revision 0.2-draft · 2026-10-24 · shared boundary for Memory OS and `eliot-swarm-controller`; not implemented.**

This contract defines the smallest external model boundary needed by Memory OS. It prevents five wrong implementations:

1. wrapping one memory extraction in controller Task/Attempt/review/acceptance;
2. copying provider credentials, routing and retry logic into Memory OS;
3. restoring the old Governor route/capability/fingerprint platform around a reversible one-shot request;
4. routing inference through ScriptRun/module-binding machinery merely because it is taskless;
5. retaining controller copies of prompts and results indefinitely after Memory has made its own verified copy.

Memory owns its finite job, frozen source membership, exact processing recipe, disclosure reduction, decoding and publication. Controller owns the configured provider connection, physical model invocation, request deduplication, operation readback and temporary controlled input/result copies.

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

`inference.text` and `inference.embed` are mutations because they can spend quota and create an external effect. `inference.release` is an idempotent mutation over the exact inference Operation and releases all controller-owned content for that Operation after Memory acknowledges a verified durable copy.

None of these methods creates or requires:

- Task or Requirement;
- Attempt;
- binding, workspace or native agent session;
- review, submission or acceptance;
- agent tools or continuation;
- ScriptRun registry, interpreter or effect lifecycle;
- a Memory-side provider credential.

## 2. Narrow caller authority

Controller adds one authenticated role:

```text
inference_client
```

It is not a Manager, Operator, Observer, Participant or bound Module. It has no MCP discovery surface and no generic writer authority.

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

The Store dispatches this role through an explicit allowlist before generic writer handling. `Principal::require_writer` continues to reject it outside that branch. A local setup owner may register/issue the credential once; the credential does not carry project, Task, workspace or binding authority.

Existing exact-caller Operation readback is reused. The role does not need a second receipt store.

## 3. Static `InferenceProfile`

Controller configuration owns static profiles. A profile is not an agent `Route`, dynamic registry, capability-evidence record or admission receipt.

Conceptual shape:

```toml
[[inference_profiles]]
name = "memory-local-default"
adapter = "openai-compatible"
connection = "local-model-service"
model = "configured-model-id"
locality = "local"                 # local | external
allow_automatic = false
max_input_bytes = 262144
max_output_tokens = 4096
timeout_seconds = 120
max_concurrency = 1
response_formats = ["text", "json_object"]
```

Numeric values are examples, not normative defaults.

The controller validates finite positive bounds and a supported adapter/connection/model. Credentials and secret connection material remain in controller-owned protected configuration.

The immutable profile identity is an automatically computed canonical SHA-256 digest over the non-secret behavior-changing fields:

```text
profile name
+ adapter and connection reference
+ requested model
+ locality
+ automatic-use flag
+ input/output/time/concurrency limits
+ response-format capabilities
```

A manually maintained generation counter is not required. Reconfiguration changes the digest and affects a new explicit request; it never mutates the snapshot retained by an admitted Operation.

There is no implicit fallback. An unavailable profile, provider, model or capacity returns a specific waiting/unavailable/failure state. Controller does not silently switch provider, model, account, locality, retention or billing semantics.

## 4. Disclosure

Memory reduces the actual supplied input to one value:

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
- `local_only` requires a `local` profile;
- protected input is not silently omitted merely to make an external profile admissible.

If necessary material cannot use the selected profile, the job waits or fails with a disclosure/profile gap. That is not no-change and does not mark the input processed.

This two-state reduction is deliberately smaller than the old privacy-policy platform. It is checked deterministically at the actual external-send boundary.

## 5. Controlled request and result payloads

A one-shot inference creates two controller-owned content objects:

```text
inference_input
inference_result
```

Both are immutable private files with a row in the existing `artifacts` table. They use deterministic controller-generated IDs and exact digests.

### 5.1 Input copy

The public request carries the prompt or embedding inputs, but the generic mutation path must **not** store those bytes verbatim in `operations.original_request_json`.

Custom inference admission:

1. validates bounds, hashes and profile/disclosure compatibility;
2. builds a canonical input payload;
3. atomically publishes an `inference_input` file before any provider I/O;
4. inserts the artifact row and inference Operation in one short Store transaction;
5. stores only bounded identity facts in the Operation request/effective record:
   - content artifact reference;
   - content length and digest;
   - profile name and digest;
   - origin, disclosure and output limits;
   - method-specific role/format fields.

An exact replay reads the retained Operation. A race or crash before the DB commit may leave an unregistered file; it is an orphan eligible for bounded local cleanup and never authorizes provider execution.

`inference_input` is controller-private. Memory already owns the source prompt/input and does not need public artifact read access to this duplicate.

### 5.2 Result copy

A terminal provider response is published as an `inference_result` artifact. Text results contain exact returned bytes; embedding results contain one canonical JSON body with the independent per-input outcomes.

Before publishing the file, the controller records a bounded pending-result identity on the Operation:

```text
status
expected artifact ID
byte length
content digest
requested/observed route facts
finish/usage/limits metadata
```

Then it atomically publishes the file and settles the Operation with the artifact row and closed public receipt in one transaction.

This ordering makes crash states explicit:

- pending metadata but no file → result body unavailable; never complete;
- exact file present but settlement missing → restart verifies the expected file and can finish settlement;
- settled receipt without exact file/digest → retained result is damaged, not successful no-change.

The controller does not need a second result database.

## 6. `inference.text`

Conceptual request:

```json
{
  "client_request_id": "stable-memory-job-attempt-key",
  "profile": "memory-local-default",
  "origin": "explicit",
  "disclosure": "local_only",
  "prompt": "exact UTF-8 prompt",
  "prompt_sha256": "lowercase-sha256",
  "max_output_tokens": 4096,
  "response_format": "json_object"
}
```

`origin` is `explicit` or `automatic`. An automatic request is rejected before provider I/O unless the frozen profile allows automatic use.

Validation checks:

- bounded stable request ID;
- exact prompt bytes and digest;
- profile existence and enabled state;
- profile locality versus disclosure;
- input/output limits;
- supported response format;
- automatic-use permission;
- controller capacity where known.

The Memory recipe and source IDs are not controller domain objects. They are already bound inside the exact prompt and retained Memory job. Controller does not parse or validate the cognitive JSON schema beyond the requested transport response format.

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

Result body:

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

The canonical identity includes the input digest/length rather than the raw content bytes. An exact replay returns the original Operation/admission state. Different method, profile, limits or input digest under the same request ID is `REQUEST_ID_CONFLICT`.

The existing generic Operation table is sufficient for the first implementation:

- `original_request_json` — bounded request identity, never raw prompt/input;
- `effective_request_json` — frozen profile snapshot, controlled input reference and execution/readback facts;
- `result_json` — closed terminal/public result and release state;
- existing Operation state — queued, sending, native accepted when actually known, settled, rejected, cancelled or outcome unknown.

Do not add `inference_runs`, a generic external-job framework or a second scheduler before a real field cannot be represented or queried through this owner.

The generic mutation helper is reused conceptually for request identity and receipts, but not called unchanged: it would persist the public raw payload and cannot perform the required private-file staging around the Store transaction.

## 9. One bounded runner

A small controller inference runner consumes only queued `inference.text` and `inference.embed` Operations. It uses the controller's existing wake signal and due Operation ledger; it is not a second scheduler or process.

Execution:

1. select an eligible queued Operation under the frozen profile's concurrency limit;
2. verify the exact private input artifact and profile snapshot;
3. CAS `queued → sending` before provider I/O;
4. perform one external attempt outside the Store transaction;
5. record provider-native admission/response identity when actually supplied;
6. persist pending result metadata, exact result file and terminal receipt as specified in §5.2;
7. wake readers and continue finite work.

A timeout or connection loss after bytes may have been sent becomes `outcome_unknown` unless provider-native idempotency/readback resolves it. Hidden SDK retries are disabled where possible. A new request ID is not recovery.

At controller restart:

- queued Operations with verified input remain eligible;
- sending/native-accepted Operations use provider-native readback if supported;
- otherwise they become/remain `outcome_unknown`;
- a verified pending result file may finish settlement;
- no restart path automatically issues another provider call.

## 10. Public result receipt and artifact authority

`operation.get` already grants a bounded receipt to the exact caller without Task linkage. Add closed projection fields for inference methods; never expose arbitrary provider JSON.

Conceptual public result:

```json
{
  "status": "complete",
  "artifact_ref": "inference-result-id",
  "byte_length": 1234,
  "sha256": "...",
  "encoding": "utf-8",
  "requested": {
    "profile": "memory-local-default",
    "profile_digest": "...",
    "model": "configured-model-id",
    "locality": "local"
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
  "release_state": "retained"
}
```

Application status is one of:

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
- requested and observed route/model facts remain distinct;
- missing usage/cost/response ID stays absent or explicit unknown, never zero or inferred;
- truncation/output-limit facts appear in `limits` and cannot be hidden behind `complete`.

Controller's artifact authorization is closed. Add an `InferenceResult` provenance decoder that verifies:

- artifact kind is `inference_result`;
- the settled inference Operation names the same artifact, digest and length;
- the requesting principal is the exact Operation caller or verified local operator;
- released content is not readable.

Do not relabel the artifact as `script_result` or `native_result`, trust metadata alone, or grant it through Task/GM scope. `inference_input` has no public read grant.

## 11. Cancellation

The existing `operation.cancel` handles only an exact caller's still-queued inference Operation. Cancellation races with the runner's `queued → sending` CAS; one wins.

Once provider I/O may have started, local cancellation cannot prove non-execution. The initial implementation returns the existing not-queued/unknown disposition and preserves the Operation for reconciliation. A future adapter may expose provider-native cancellation, but an acknowledgement never becomes proof that no response or charge occurred.

Cancellation must not delete input needed to reconcile an uncertain attempt. Content cleanup happens through `inference.release` after a terminal/abandoned disposition that permits release.

## 12. `inference.release`

Memory reads the result artifact in bounded ranges, verifies length/digest and durably stores the exact result in its own job/blob before decoding or release.

Then it calls:

```json
{
  "method": "inference.release",
  "params": {
    "client_request_id": "stable-release-key",
    "operation_id": "inference-operation-id",
    "result_artifact_ref": "inference-result-id",
    "expected_result_sha256": "..."
  }
}
```

Controller verifies the exact caller, target Operation, result identity and terminal/owner-authorized abandonment state. Release covers **both** controller-owned content artifacts:

```text
inference_input
inference_result, when present
```

Release is a narrow two-phase owner operation:

1. transactionally reserve `cleanup_pending` on the target inference Operation and retain the release Operation;
2. outside the transaction, verify and remove only the exact regular files under the controller artifact root;
3. transactionally delete the matching artifact rows and set `release_state=released` with bounded digest/length/time facts;
4. settle the release Operation.

Add a private `ArtifactFiles::remove_exact(record)` primitive. It rejects symlinks/path mismatch/digest mismatch and synchronizes the parent directory. There is no public generic artifact-delete method.

Crash recovery:

- file still present + `cleanup_pending` → verify and continue removal;
- exact file absent + matching pending artifact row → finalize DB cleanup as already physically removed;
- mismatch or unrelated reference → retain `cleanup_incomplete`, never delete by guessed path;
- release replay returns the retained release result.

After release:

- controller keeps only bounded text-free request/result receipt facts needed for deduplication and status;
- later `artifact.read` returns released/unavailable, never another body;
- Memory backup contains its copied result bytes, not merely the controller handle.

If cleanup fails, Memory can still decode/use its verified result but reports a controlled duplicate gap. Erasure remains incomplete while either controller-owned input or result content remains.

Provider-held copies are an external boundary; `inference.release` cleans only controller-managed content.

## 13. Reuse and explicit non-donors

Reuse from the current controller:

- `operations` exact `(caller, client_request_id)` identity and conflict behavior;
- exact-caller `operation.get` receipt authorization;
- existing Operation states and failure observations;
- atomic immutable `ArtifactFiles` publish/read/digest verification;
- the generic `artifacts` table;
- the controller wake signal and bounded worker pattern;
- existing `reqwest` dependency and transport hardening patterns.

Extend narrowly:

- `InferenceClient` role and allowlist;
- inference request validators and profile config;
- `inference_input` / `inference_result` artifact kinds;
- closed public result projection and `InferenceResult` artifact provenance;
- one inference runner;
- `remove_exact` and `inference.release` recovery.

Do **not** reuse as the inference lifecycle:

- Task/Requirement/Attempt;
- `script.run`, script registry, bundles, interpreter identities, ScriptEffect or automation cause;
- Module binding/handshake/supervisor;
- agent `Route.native_options`;
- review/submission/acceptance;
- a generic artifact deletion endpoint.

The current taskless ScriptRun fixture qualifies Store admission only and explicitly does not execute the worker. The production ScriptRun path owns a different product: registered scripts, interpreter/process custody, start gates, automation authority, effects and multiple artifacts. Its recovery ideas are useful; its lifecycle is not the one-shot inference implementation.

## 14. Status and failure vocabulary

The exact public vocabulary is implementation-owned, but it must distinguish at least:

```text
PROFILE_NOT_FOUND
PROFILE_DISABLED
PROFILE_LOCALITY_MISMATCH
AUTOMATIC_USE_DISABLED
INPUT_LIMIT_EXCEEDED
OUTPUT_LIMIT_EXCEEDED
RESPONSE_FORMAT_UNSUPPORTED
CAPACITY_UNAVAILABLE
EXTERNAL_OUTCOME_UNKNOWN
INPUT_NOT_RETAINED
RESULT_NOT_RETAINED
RESULT_DIGEST_MISMATCH
RESULT_RELEASE_CONFLICT
RELEASE_CLEANUP_PENDING
RELEASE_CLEANUP_INCOMPLETE
```

These are operational states, not cognitive outcomes. Memory never converts them into `changes=[]` or successful no-change.

## 15. Implementation order

Controller owner:

1. add `InferenceClient` and its exact Store-call allowlist;
2. add static profile config and canonical profile digest;
3. add closed request DTOs/method policy;
4. add controlled input artifact admission without raw payload in Operation JSON;
5. add one Operation-backed inference runner and one actual text adapter with hidden retries disabled;
6. add pending-result recovery, immutable result artifact and closed public receipt/grant;
7. add `remove_exact` plus idempotent `inference.release` for input and result;
8. add embeddings through the same lifecycle;
9. run the minimum relevant build/Clippy after each coherent production increment.

Memory owner, after Base:

1. add disclosure fields/reduction;
2. add `ControllerTextInferenceClient`;
3. save exact request before I/O;
4. copy and verify result before decode;
5. publish through the existing job/revision path;
6. call `inference.release` after durable copy;
7. expose waiting/unknown/remote-copy/cleanup states;
8. keep Base usable with learning disabled.

The full automated test suite follows the connected product implementation. Fixtures or serializer tests do not qualify a provider route or demonstrate learning.
