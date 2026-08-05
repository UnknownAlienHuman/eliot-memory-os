# ELIOT Records Forensic Audit — addendum: lossy generic payload transport

Date: 2026-08-05  
Repository: `eliot-memory-os`  
Branch at discovery: `codex/cognitive-completion-v2`  
Published audit commit before this addendum: `08ad49b1d8a5a8e47c1ce04f4b4ca8ac81e1b44c`  
Canonical project: `87731db9-1e51-8fde-a4db-222705d7d03a` (`eliot-memory-os`)  
Audit TaskContract: `03a1a297-ebc1-417f-b29b-88963372eec9`  
GitHub issue: <https://github.com/UnknownAlienHuman/eliot-memory-os/issues/10>  
Status: `CONFIRMED_DATA_INTEGRITY_DEFECT`; acceptance remains `0/2`, `open`

## 1. Why this addendum exists

The two main audit reports were already hashed, committed, and pushed before the final
Eliot publication readback. That readback exposed a new loss-of-information defect.
Changing either sealed report would invalidate the hashes stored in Eliot, so the new
evidence is recorded here as a separate append-only artifact.

This addendum does not modify product source and does not promote any memory record.

## 2. Triggering evidence

### 2.1 Audit publication receipt

Write:

- observation: `observation:7d2f4c8a-6e31-4b79-9a5d-0c84f1e267b3`
- receipt/write ID: `7d2f4c8a-6e31-4b79-9a5d-0c84f1e267b3`
- write status: `committed`
- exact L2 fence: revision `192`
- `missing_handles=[]`
- `forbidden_handles=[]`

The input contained the exact scalar value:

```text
observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240
```

The stored/read-back value was:

```text
observation:f31e5b3f
```

The record itself remained fetchable by its full top-level observation handle. The
loss occurred inside the arbitrary JSON payload.

### 2.2 Earlier independent occurrence

The accidental empty collective trace written at revision `190` already displayed the
same shape:

- full caller trace ID:
  `collective:d398ad35-0683-41e3-a8eb-69deb65f7bc0:019fd1be-9afd-7c60-881e-5526ebaead7b`
- stored payload trace ID: `collective:d398ad35`
- stored `write_receipt`: `null`, although the caller response contained a receipt
- observation: `observation:019fd1be-9afd-7c60-881e-55411f0166e2`

At that point the truncation could still have been attributed to one subsystem. The
controlled matrix below proves a general generic-payload failure.

## 3. Controlled MCP-only round-trip matrix

The probe used only the governed Eliot MCP write and exact L2 readback surfaces. No raw
SQL, SurrealDB CLI query, filesystem injection, or direct store mutation was used.

Probe identity:

- observation: `observation:6a8d3e21-9c47-4f65-b2a1-7d90e3c456f8`
- receipt/write ID: `6a8d3e21-9c47-4f65-b2a1-7d90e3c456f8`
- status: `committed`
- exact L2 fence: revision `193`
- `missing_handles=[]`
- `forbidden_handles=[]`
- observation hash label: `cognitive observation 4815c5e0bdf2ceac`

| Shape | Input | Exact readback | Result |
|---|---|---|---|
| plain hyphen | `alpha-beta` | `alpha-beta` | preserved |
| bare UUID | `f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240` | same | preserved |
| record-like UUID | `observation:f31e5b3f-7f0b-4ca2-9a4e-1f7c6d89b240` | `observation:f31e5b3f` | corrupted |
| colon + words | `memory:operator-runtime-proof` | `memory:operator` | corrupted |
| digest-like | `sha256:abc-def-0123456789` | `sha256:abc` | corrupted |
| URL | `https://example.test/a-b?x=y#z` | same | preserved |
| Windows path | `C:\Temp\a-b.json` | same | preserved |
| nested record-like UUID | full record-like UUID | `observation:f31e5b3f` | corrupted |
| array record-like UUID | full record-like UUID | `observation:f31e5b3f` | corrupted |
| nested/array colon + words | `memory:operator-runtime-proof` | `memory:operator` | corrupted |
| array digest-like | `sha256:abc-def-0123456789` | `sha256:abc` | corrupted |

Observed rule:

```text
prefix:value-with-hyphen -> prefix:value
```

The loss is recursive and independent of JSON nesting. A hyphen alone is safe. A bare
UUID is safe. The combination of a record-like `prefix:` and a hyphenated identifier is
unsafe. URLs and Windows paths do not match the failing record-like form and survived.

## 4. Source localization

### 4.1 MCP ingress preserves a generic JSON value

`crates/eliot-app/src/mcp_stdio.rs:2738-2746` defines
`CognitiveObservationToolInput.payload` as `serde_json::Value`.

`crates/eliot-app/src/mcp_stdio/task_handlers.rs:3281-3338`:

1. deserializes the MCP arguments with `serde_json::from_value`;
2. computes a hash over `serde_json::to_vec(&input.payload)`;
3. moves `input.payload` unchanged into `ToolObservationRecordCommand`.

No handle parser or record-ID constructor is called for nested payload strings here.

### 4.2 Admission clones the payload without normalization

`crates/eliot-engine/src/admission.rs:19-53` validates encoding and command shape, then
builds the write envelope.

`crates/eliot-engine/src/admission.rs:127-133` copies
`body.payload.clone()` directly into `ToolObservationInput`.

`crates/eliot-engine/src/writer.rs:1618-1625, 2153, 2391-2398` carries the
admitted envelope through the writer actor to the canonical store without rewriting
nested strings.

The CodeCortex call graph independently resolves the path:

```text
dispatch_write_cognitive_observation
  -> WriteAdmissionService::admit
  -> WriterHandle::submit
```

### 4.3 The entire envelope is bound as ordinary JSON

`crates/eliot-store/src/canonical_store.rs:2327-2351` passes the complete envelope to
`ApplyWriteEnvelope` inside a `serde_json::Value` variable object.

`crates/eliot-store/src/surreal_rpc.rs:59` negotiates the WebSocket subprotocol `json`.
Lines `99-105` send the query and bound variables through the JSON RPC method. Lines
`124-174` serialize and parse that RPC traffic with `serde_json`.

### 4.4 Generic payloads are stored directly

`crates/eliot-store/src/surql/apply_write_envelope.surql` stores envelope payload objects
without a lossless transport wrapper:

| Entity | Direct assignment |
|---|---:|
| evidence atom | line 193 |
| tool observation | line 218 |
| claim card | line 352 |
| verification run | line 378 |
| failure fingerprint | line 401 |

The exact L2 query returns these payloads directly; there is no repair layer on read.

### 4.5 Canonical receipt bodies use a different, protected path

`crates/eliot-store/src/canonical_store.rs:5353-5407` serializes canonical
`receipt_body` to bytes and supplies `receipt_body_json_b64`, while also fragmenting
selected identifiers character by character.

`crates/eliot-store/tests/canonical_store.rs:1594-1687` contains
`canonical_receipt_body_preserves_arbitrary_json_scalars`. Its fixture includes:

- colon + hyphen strings;
- UUID-looking strings;
- Windows paths;
- URLs;
- Unicode;
- nested objects and arrays.

The focused isolated real-SurrealDB run passed:

```text
Summary [7.180s] 1 test run: 1 passed, 7 skipped
nextest log SHA-256: 91c79bc2e075ff2f6f2a6e220291d0abe163aa6b920a6fafa0d065f6d86ce6ea
temporary roots removed: true
host configuration changes: 0
```

This passing test is not evidence that generic payloads are safe. It demonstrates that
the protected canonical receipt-body route is safe and explains why the direct generic
payload route escaped the existing regression suite.

### 4.6 The project already knew the transport defect; the previous repair was incomplete

This audit did not discover an entirely new SurrealDB behavior. The current project
worklog already documents the same boundary:

- `docs/architecture/COGNITIVE_COMPLETION_V2_WORKLOG.md:1183-1197` records that
  SurrealDB 3.1.4 JSON-RPC parameter coercion converts a recovery-looking bound string
  into a record and truncates the remainder before SurrealQL can cast it. The accepted
  workaround was `string_fragments`: transport characters separately and rebuild an
  explicit string inside SurrealQL.
- `docs/architecture/COGNITIVE_COMPLETION_V2_WORKLOG.md:1710-1714` records that
  record-shaped strings inside `receipt_body` became a shorter record prefix. The
  authoritative child transport was changed to `receipt_body_json_b64` and decoded as
  exact JSON in Rust.

The new revision-193 matrix proves that the old repair was applied only to selected
identifiers and canonical receipt bodies. The generic envelope payload remained a
directly bound recursive JSON value and therefore still crosses the known lossy path.
This is an incomplete earlier repair and a regression-test coverage failure, not merely
an undocumented third-party quirk.

The collective-trace occurrence follows the same route. The engine generates a full
`collective:<task_uuid>:<message_uuid>` value, nests it in a generic JSON payload, and
passes that payload through admission and the writer unchanged. Its shortening to
`collective:d398ad35` is therefore another manifestation of the same boundary defect.

## 5. Interpretation and uncertainty

Installed SurrealDB version: `3.1.4 for windows on x86_64`.

Current official SurrealDB 3.x documentation says ordinary strings are not eagerly
converted to record IDs; explicit record syntax or conversion is required:

- <https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/strings>
- <https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/record-ids>

Therefore the observed behavior is not an accepted SurrealQL language rule.

Evidence-supported conclusion:

- confidence `high`: Eliot's current generic envelope/RPC/store path is not byte-exact
  for record-like colon-hyphen strings;
- confidence `high`: corruption occurs after MCP ingress and before or during durable
  store representation/readback;
- confidence `high`: the narrow failing boundary is SurrealDB 3.1.4 materialization of
  WebSocket JSON-RPC variables, before SurrealQL executes. The current worklog's earlier
  discriminators independently reached the same boundary and proved that a later cast
  cannot recover the lost suffix;
- unverified: the exact internal SurrealDB parser/function responsible. Eliot must still
  treat byte-exact payload transport as its own protocol invariant and cannot rely on the
  direct generic binding contract.

The official semantic contradiction makes a regression or protocol mismatch more likely
than intentional behavior.

## 6. Blast radius

Confirmed live:

- arbitrary JSON payloads of `eliot_write_cognitive_observation`;
- the same failure at top level, in nested objects, and in arrays;
- at least two independent records and two different writer call sites.

High-confidence source-derived blast radius:

- evidence atom payloads;
- claim card payloads;
- verification run payloads;
- failure fingerprint payloads;
- any other subsystem persisted through `ToolObservationRecord` with direct payload data.

Not affected by this probe:

- the top-level observation ID used for record lookup;
- plain hyphenated strings;
- bare UUID strings;
- the tested URL and Windows path forms;
- canonical receipt bodies recovered from their base64 representation.

Potential consequences:

1. provenance handles in payloads can silently point to a different/nonexistent record;
2. task, trace, receipt, digest, and evidence references can lose identity entropy;
3. exact readback can succeed at the record level while returning corrupted contents;
4. deduplication, replay, verification linkage, and audit reconstruction may operate on
   shortened identifiers;
5. historical generic payload values may be unrecoverable if no canonical/base64 or
   external source copy exists.

Severity: `P0 candidate / P1 confirmed repair`. The integrity defect is confirmed. The
full historical affected-record count is not yet known, so a system-wide corruption
claim is not made.

## 7. Required repair and replay plan

1. Introduce an authoritative lossless representation for every arbitrary payload,
   preferably canonical JSON bytes plus base64 and a digest, before the RPC boundary.
2. Decode the authoritative representation in Rust on every read path; treat the direct
   Surreal object as a query projection, not as the source of exact bytes.
3. Extend the current receipt-body protection instead of implementing ad hoc escaping for
   individual fields. The failure is recursive and applies to unknown future keys.
4. Add an isolated real-SurrealDB regression for direct generic
   `ToolObservationRecord.payload`, using the exact matrix from revision `193`.
5. Add equivalent coverage for evidence, claim, verification, and failure payloads because
   all five use the same direct assignment pattern.
6. Assert byte-exact equality after write/read, not merely successful fetch or record count.
7. Inventory historical payload strings matching record-like colon-hyphen forms. Do not
   silently rewrite them: compare with canonical/base64 sources or replay the producing
   operation.
8. Mark unreconstructable records as candidate/stale/corrupted and exclude them from
   verifier authority until replayed.
9. Preserve revisions `190`, `192`, and `193` as regression fixtures.
10. Add a protocol-level test around `SurrealRpcTransport::query` to localize whether the
    loss happens during server parameter materialization and to preserve a focused
    upstream-compatible reproducer.

## 8. Tooling limitations encountered during localization

- Code graph query succeeded only against the explicit `eliot-memory-os-final-v11`
  namespace. The default `eliot-memory-os` graph remains stale.
- Rust LSP returned `unlinked-file` for both inspected source files, so LSP diagnostics
  were not accepted as compiler proof.
- `cargo metadata --no-deps` correctly resolved the workspace root, five packages, and
  `eliot-store`; Cargo metadata, exact source anchors, live MCP readback, and the isolated
  test are the accepted evidence for this addendum.
- One ast-grep macro pattern resolved the envelope construction at
  `canonical_store.rs:2342`; a field-only Rust pattern was invalid and was not used as
  evidence.

## 9. GitHub tracking

The confirmed defect and its acceptance checklist are tracked in:

- issue #10 — <https://github.com/UnknownAlienHuman/eliot-memory-os/issues/10>

The issue was created only after a duplicate search returned no matching open issue. It
contains the governed revision-193 matrix, causal path, known incomplete-repair history,
blast radius, test gap, and repair/replay acceptance conditions.

## 10. Acceptance boundary

This work proves and localizes a defect; it does not repair it.

```yaml
CompletionProof:
  task_goal: localize the newly observed Eliot payload truncation
  acceptance_items:
    - item: reproduce through governed MCP write/readback
      status: verified
      evidence: observation:6a8d3e21-9c47-4f65-b2a1-7d90e3c456f8 at revision 193
      verifier: exact L2 matrix comparison
      residual_uncertainty: none for ToolObservation payload reproduction
    - item: identify current source path and test gap
      status: verified
      evidence: exact Rust/SurrealQL/worklog anchors plus focused isolated test
      verifier: source inspection, CodeCortex trace, cargo metadata, nextest 1/1
      residual_uncertainty: exact upstream SurrealDB internal function remains unresolved
    - item: repair and replay affected records
      status: not_verified
      evidence: none
      verifier: not run; product source intentionally unchanged
      residual_uncertainty: historical affected-record count unknown
  changed_files:
    - reports/audit/ELIOT_RECORDS_FORENSIC_AUDIT_ADDENDUM_20260805.md
  checks_run:
    - exact governed MCP round-trip at revisions 192 and 193
    - source and graph causal slice
    - reconciliation against the project's earlier JSON-RPC coercion repairs
    - cargo metadata --no-deps
    - focused isolated real-SurrealDB regression, 1/1 passed
  checks_not_run_and_why:
    - full Rust suite: no product source changed; unrelated dirty product work exists
    - mutation/replay: outside read-only audit scope and lacks accepted controller evidence
  remaining_uncertainty:
    - exact upstream SurrealDB internal parser/function
    - historical corpus impact count
  final_status: PARTIAL_PROGRESS
```

candidate_only; requires reconciliation/replay before activation
