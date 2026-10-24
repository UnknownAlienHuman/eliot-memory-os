# Eliot V3 — One-shot inference contract

**Revision 0.1-draft · 2026-10-24 · shared boundary for Memory OS and `eliot-swarm-controller`; not implemented.**

This contract defines the smallest external model boundary needed by Memory OS. It exists to prevent three wrong implementations:

1. wrapping one memory extraction in controller Task/Attempt/review/acceptance;
2. copying provider credentials, routing and retry logic into Memory OS;
3. restoring the old Governor route/capability/fingerprint platform around a reversible one-shot request.

Memory owns the job, frozen input, recipe, disclosure reduction, decoding and publication. Controller owns the configured provider connection, model invocation, request deduplication, durable result readback and cleanup of its temporary controlled copy.

## 1. Methods

Initial public methods:

```text
inference.text
inference.embed
inference.result.release
```

Existing controller operations remain responsible for:

```text
operation.get
operation.cancel
artifact.get
artifact.read
```

`inference.text` and `inference.embed` are mutations because they can spend quota and create external effects. `inference.result.release` is an idempotent mutation over the exact inference Operation/result. Artifact reads remain read-only.

None of these methods creates or requires:

- Task or Requirement;
- Attempt;
- binding/workspace/native session;
- review, submission or acceptance;
- agent tools or continuation;
- a Memory-side provider credential.

## 2. Static `InferenceProfile`

Controller configuration owns static profiles. A profile is not an agent `Route`, dynamic registry or admission receipt.

Conceptual shape:

```toml
[[inference_profiles]]
name = "memory-local-default"
revision = 1
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

Numeric values above are examples, not normative defaults.

The implementation validates finite positive bounds and a supported adapter/connection/model. Credentials and secret connection material stay in controller-owned protected configuration.

A profile has one immutable non-secret snapshot identity for an admitted request:

```text
profile name
+ profile revision or canonical digest
+ adapter/connection reference
+ requested model
+ locality
+ automatic-use flag
+ input/output/time/concurrency limits
+ response-format capabilities
```

Reconfiguration affects a new explicit request. It never changes the profile snapshot retained by an admitted Operation.

There is no implicit fallback. Unavailable profile, provider, model or capacity returns a specific unavailable/waiting/failure result. Controller does not silently switch provider, model, account, locality, retention or billing semantics.

## 3. Disclosure

Memory reduces the actual supplied input to one value:

```text
local_only
external_allowed
```

Rules:

- project configuration supplies the default;
- an observation/source can be stricter;
- a derived item cannot be less restrictive than content it still contains or reveals;
- mixed input uses the strictest contributing value;
- reusable scope does not widen disclosure;
- `local_only` requires a `local` profile;
- input is not silently omitted merely to make an external profile admissible.

If protected material is necessary and no local profile is available, the job waits or fails with a disclosure/profile gap. That is not no-change and does not mark the input processed.

This two-state reduction is deliberately smaller than the old privacy-policy platform. It is checked deterministically at the actual external-send boundary.

## 4. `inference.text`

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

The request validator checks:

- a bounded stable request ID;
- exact prompt bytes and digest;
- profile existence and enabled state;
- profile locality versus disclosure;
- requested output not exceeding the profile;
- response format supported by the profile;
- automatic-use permission;
- controller capacity before admission where known.

The Memory recipe and source IDs are not controller domain objects. They are already bound inside the exact prompt and retained Memory job. Controller does not parse or validate the cognitive JSON schema beyond the requested transport response format.

## 5. `inference.embed`

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

`role` is `query` or `document` and maps through the selected adapter's actual task parameter/prefix.

Result body contains:

```json
{
  "space": {
    "profile_revision": "...",
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

## 6. Admission, deduplication and external execution

Controller reuses its existing request identity rule:

```text
(caller identity, client_request_id, canonical method parameters)
```

An exact replay returns the original Operation/admission state. Different parameters under the same ID are rejected.

Before provider I/O, controller persists:

- exact canonical request or content-addressed prompt/input reference;
- frozen profile snapshot identity;
- request/disclosure/origin facts;
- Operation identity and current state.

Provider I/O runs outside the Store transaction.

Controller performs one external attempt. A timeout or connection loss after bytes may have been sent becomes `unknown` unless provider-native idempotency/readback establishes the result. Hidden SDK retries are disabled where possible. A new client request ID is not recovery.

If admission reply is lost, Memory repeats the exact request to the same controller as the same authenticated client. Once an Operation ID is known, Memory uses `operation.get` and result readback instead of calling inference again.

## 7. Public result receipt

`operation.get` for an inference Operation exposes a closed method-specific result; it does not expose arbitrary private provider JSON.

Conceptual result:

```json
{
  "status": "complete",
  "artifact_ref": "artifact-id",
  "byte_length": 1234,
  "sha256": "...",
  "encoding": "utf-8",
  "requested": {
    "profile": "memory-local-default",
    "profile_revision": "...",
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

- `complete`/`partial` require retained exact body bytes and usable artifact readback;
- empty, malformed or cognitively invalid text can still be a transport-complete body; Memory decides decode success;
- `unknown` retains Operation/request/profile identity and does not authorize another call;
- requested and observed route/model facts remain distinct;
- missing usage/cost/response ID stays absent or explicit unknown, never zero or inferred from configuration;
- truncation/output-limit facts appear in `limits` and cannot be hidden behind `complete`.

The existing public projection must return the actual inference artifact reference directly. Memory does not inspect controller SQLite, private files or logs.

## 8. Copy acknowledgement and release

Memory reads the artifact in bounded ranges, verifies byte length/digest and durably stores the exact body in its job/blob before decoding.

Then it calls:

```json
{
  "method": "inference.result.release",
  "params": {
    "client_request_id": "stable-release-key",
    "operation_id": "inference-operation-id",
    "artifact_ref": "artifact-id",
    "expected_sha256": "..."
  }
}
```

Controller verifies that the artifact is the exact result owned by that inference Operation. Release is idempotent.

Release means:

- Memory has acknowledged a durable matching copy;
- controller may remove its operation-owned content bytes and adapter staging data;
- controller retains only bounded text-free receipt facts needed for deduplication, status and audit;
- later `artifact.read` may return released/unavailable, not substitute another body;
- a release retry returns the retained release result.

Controller must not delete the only readable result before a matching acknowledgement. Memory backup contains its copied bytes, not merely the controller handle.

If release/cleanup fails, Memory can still decode/use its copied result but reports a controlled duplicate cleanup gap. Erasure remains incomplete while that controller-owned copy exists. No general-purpose artifact deletion API or Memory retention graph is required for this initial owner-scoped path.

## 9. Cancellation and erasure

`operation.cancel` requests cancellation of admitted/running inference. Cancellation acknowledgement does not prove the provider stopped; unresolved execution remains `unknown` until readback settles it.

Memory erasure of source/result scope:

1. prevents new dispatch/publication;
2. cancels or reconciles the exact inference Operation;
3. removes Memory input/result bytes and derived publications in scope;
4. calls `inference.result.release`/owner cleanup when controller content exists;
5. reports remaining provider copies as an external boundary;
6. does not call inference again to reconstruct or sanitize content.

## 10. Status and failure codes

The exact public error vocabulary is owned by implementation, but it must distinguish at least:

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
RESULT_NOT_RETAINED
RESULT_DIGEST_MISMATCH
RESULT_RELEASE_CONFLICT
RESULT_RELEASE_INCOMPLETE
```

These are operational states, not cognitive outcomes. Memory does not convert them into `changes=[]` or successful no-change.

## 11. Implementation order

Controller owner:

1. add closed profile config and validation;
2. add method policy and request DTOs;
3. persist request/profile snapshot before provider I/O;
4. implement one actual text adapter with hidden retries disabled;
5. persist exact result bytes and public receipt;
6. implement bounded artifact readback and idempotent release;
7. add embeddings through the same operation/result lifecycle;
8. run minimum relevant build/Clippy after each coherent production increment.

Memory owner, after Base:

1. add disclosure fields/reduction;
2. add `ControllerTextInferenceClient`;
3. save exact request before I/O;
4. copy and verify result before decode;
5. publish through existing job/revision path;
6. acknowledge/release controller copy;
7. expose specific waiting/unknown/cleanup states;
8. keep Base usable with learning disabled.

The full automated test suite follows the connected product implementation. Fixtures or serializer tests do not qualify a provider route or demonstrate learning.
