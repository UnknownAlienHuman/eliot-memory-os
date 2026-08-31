# Governor observation source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from origin/main`
for the complete branch delta, including deletions. Open the verified bundle and
read every required item before mutation. A route alone is navigation, not
reading evidence.

Record the route receipt ID, read receipt ID, required handles/fragments and
hashes, verified bundle SHA-256, and explicit reading attestation. Optional
fragments are loaded only when the current decision crosses their boundary. A
legacy `ELIOT_*` compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale/missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Purpose and owner boundary

This package is the Governor-owned semantic boundary for normalized observation
capture. It owns observation admission, safe candidate fallback, active-plan
compilation and the rebuildable journal projection. It will also host the
private first-pass classifier after the foundation record-family contract can
represent the evidence that classifier needs.

It does not own sensors, Host/process truth, Canonical Store execution, task
selection, epistemic promotion, memory lifecycle, graph relations, Context
admission, finish or external effects.

Read the repository and `crates/governor/AGENTS.md`, the owning issue/PR, exact
foundation contracts and applicable Architecture/Implementation fragments
before mutation. Use one issue-numbered branch and one primary mutable path
scope.

## Current ContractChallenge: record-family evidence

Issue #217 blocks ordinary-family classifier implementation.

The current `eliot-observation-contracts::ObservationRecordEnvelope` preserves
only:

```text
record_id;
caller-supplied ObservationRecordKind;
one generic ObservationEventCore for every ordinary family;
optional CoverageGap;
journal_control_event;
parent_record_id.
```

The foundation crate separately defines richer `AuditRecord`,
`TelemetryRecord`, `ChangeRecord` and `MaintenanceRecord` values, but those
family-specific fields do not survive inside the public envelope consumed by
this package. The contract also contains no accepted
`ObservationKind -> ObservationRecordKind` matrix.

Consequences:

- `CoverageGap` is mechanically exact;
- `journal_control_event` mechanically requires `Audit` and is already checked
  by the foundation contract;
- ordinary `Audit`, `Telemetry`, `Change` and `Maintenance` labels cannot be
  independently confirmed or contradicted from the current envelope;
- a table inferred from event prose, event kind, producer role, recency or model
  judgement would create a new public semantic contract in the wrong owner.

Until #217 freezes one field-complete versioned contract and compatibility rule:

```text
do not add src/classifier.rs with an ordinary-family mapping;
do not report exact, compatible or conflicting ordinary classification;
do not add a local RecordFamilyEvidence/public schema substitute;
do not treat caller-supplied kind as independent classification proof;
do not weaken capture to reject a shape-valid ambiguous observation.
```

Return this ContractChallenge to the integration owner. Work that does not
require the missing distinction may continue. Shape-valid ordinary material is
preserved under the existing capture/candidate ceiling; it is not promoted by a
private guess.

## `governor.observation.classifier` after #217

The classifier remains a private module inside this package, not a separate
crate. Its exact API must consume the accepted foundation contract rather than
redefine public fields. An acceptable closed private result will distinguish:

```text
Exact;
CompatibleHint;
AmbiguousPreserveCandidate;
ConflictingHint.
```

Required behavior after the contract is frozen:

1. Consume only a validated, bounded, versioned record-family representation.
2. Use only mechanical discriminators owned by the foundation contract.
3. Preserve ambiguity rather than choose by convenience or textual similarity.
4. Route a mechanically proved conflict through the existing pre-stage
   rejection and safe `ObservationCandidate` fallback.
5. Remain deterministic, total, bounded and side-effect free.
6. Never change `EpistemicStatus`, `Assertability`, evidence authority,
   influence, task binding, lifecycle, relation, authority or finish state.
7. Preserve request/idempotency identity and replay the original disposition.

Donor boundary:

```text
crates/smart/eliot-memory::classify
  retain only the small table-driven idea after it is reconciled with the
  accepted foundation contract;

MemoryPlane, MemoryId, local revision allocation, delivery dedup, retrieval,
status/lifecycle/influence mutation and UnderstandingView
  reject completely as duplicate state ownership.
```

Minimum classifier fixtures after #217:

```text
every mechanically exact family;
compatible caller hint;
wrong-hint conflict;
ambiguous record preserved as candidate;
coverage gap and journal-control rules;
same input gives identical result;
no result raises support/assertability/influence;
production admission conflict yields fallback and no accepted record;
replay preserves the original classification-dependent disposition;
v1 compatibility input never becomes exact without evidence.
```

## `governor.observation.admission`

Owned entrypoints:

```rust
ObservationSubmission::validate
ObservationSubmission::request_digest
ObservationJournal::admit
ObservationAdmissionReceipt::validate
ObservationAdmissionRejection::validate
```

Required order:

```text
canonical request identity and exact replay/conflict check
→ foundation record/evidence/fence validation
→ accepted first-pass classification consistency, when available
→ task-selection/scope/durability checks
→ safe candidate fallback on pre-stage rejection
→ immutable accepted receipt or rejection projection.
```

Admission owns semantic acceptance but performs no database write in this pure
projection. The store path later persists only the named prepared transition.
The journal maps are rebuildable fixtures/projections, not an independent
canonical database.

Never:

- convert malformed or ambiguous input to success by default;
- silently select the latest task or nearest `WorkScope`;
- treat a transport/durability receipt as epistemic proof;
- reuse an idempotency key for different canonical bytes;
- mutate an accepted receipt on replay;
- drop a safe raw candidate merely because reusable classification failed.

## `governor.observation.plan_compilation`

Owned entrypoints include `compile_plan` and coverage assessment helpers.
Compilation consumes registered obligation profiles and exact source visibility;
it cannot let a producer self-certify complete coverage. Absence means complete
only against a declared denominator and cursor interval. Blind, unavailable,
partial and unknown states remain distinct.

## `governor.observation.journal_projection`

`ObservationJournal` is an in-memory, rebuildable deterministic projection used
for admission/replay fixtures. It owns no durable storage technology and cannot
survive an invalidated canonical source as authority. Every state-changing
method must be reconstructible from immutable receipt/rejection entries.

## Hard boundaries

Do not add:

- SurrealDB/vendor SDKs, raw queries, filesystem/network/process access or model
  calls;
- canonical memory, task, policy, lifecycle, graph, support, influence or
  finish ownership;
- direct Canonical Store/ORS/Watchdog spool writes;
- semantic classification based on free-form prose or a model;
- a separate observation-classifier crate while the cell shares this package's
  owner, contract island and proof boundary;
- a second record-family contract or receipt lifecycle;
- a catch-all success/error string that erases exact rejection identity;
- unbounded collections or synchronous work.

Return a ContractChallenge when requested behavior needs a new public field-level
contract, another mutable owner, raw-source parsing, task-selection authority,
model interpretation, store execution or a second receipt lifecycle.

## Proof

Minimum package proof for source changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-observation --all-targets
cargo test --locked -p eliot-observation
cargo clippy --locked -p eliot-observation --all-targets -- -D warnings
```

A classifier/admission change additionally requires the real capture provider →
Governor admission fixture, including rejection fallback, replay, task/scope
mismatch and no-journal-write-on-conflict. A record-envelope contract change
also requires every serialized producer/consumer compatibility fixture from
#217. Plan/coverage changes require exact denominator, blind-interval and
producer-silence fixtures.

Package tests prove only pure classification/admission/projection behavior. They
do not prove store persistence, daemon wiring, host observation, Context use,
Product Pulse or release support. Automatic GitHub Actions remain disabled;
report `NOT_EXECUTED`, simulation and unavailable edges exactly.
