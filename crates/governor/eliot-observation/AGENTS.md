# Governor observation source instructions

## Purpose and owner boundary

This package is the Governor-owned semantic boundary for normalized observation
capture. It owns deterministic first-pass classification, safe candidate
fallback, observation admission, active-plan compilation and the rebuildable
journal projection. It does not own sensors, Host/process truth, Canonical Store
execution, task selection, epistemic promotion, memory lifecycle, graph
relations, Context admission, finish or external effects.

Read the repository and `crates/governor/AGENTS.md`, the owning issue/PR,
`classifier.module.toml`, exact foundation contracts and applicable
Architecture/Implementation fragments before mutation. Use one issue-numbered
branch and one primary mutable path scope.

## Functional cells

### `governor.observation.classifier`

Target private module:

```text
src/classifier.rs
```

Required private API or an equivalently closed representation:

```rust
pub(crate) enum FirstPassClassificationDisposition {
    Exact,
    CompatibleHint,
    AmbiguousPreserveCandidate,
    ConflictingHint,
}

pub(crate) struct FirstPassClassification {
    pub expected_record_kind: Option<ObservationRecordKind>,
    pub observed_record_kind: ObservationRecordKind,
    pub disposition: FirstPassClassificationDisposition,
    pub reason_ref: &'static str,
}

pub(crate) fn classify_record(
    record: &ObservationRecordEnvelope,
) -> FirstPassClassification;

pub(crate) fn validate_record_classification(
    record: &ObservationRecordEnvelope,
) -> Result<FirstPassClassification, ObservationClassificationError>;
```

Classification algorithm:

1. Validate or consume only an already normalized bounded record shape. The
   classifier does not parse raw host payloads or infer a `WorkScope`.
2. A dedicated `CoverageGap` shape is an exact operational discriminator and
   cannot be relabelled by a caller hint.
3. An event family with one unambiguous operational record family may return
   `Exact`.
4. When the contract admits several record families, preserve the supplied
   family only as `CompatibleHint`; do not select from prose, recency,
   popularity, source role or semantic similarity.
5. When evidence is insufficient, return `AmbiguousPreserveCandidate`. The
   normal capture path preserves the observation as a cold/bounded candidate.
6. When an exact discriminator contradicts the supplied family, return
   `ConflictingHint`; normal admission must fail into the existing
   `ObservationCandidate` fallback rather than commit a convenient family.
7. Results are deterministic, total and side-effect free. Equivalent normalized
   input produces the same disposition and reason reference.
8. Classification never changes `EpistemicStatus`, `Assertability`, evidence
   authority, influence, task binding, lifecycle, relation or finish state.

Donor boundary:

```text
crates/smart/eliot-memory::classify
  retain only the table-driven first-pass idea;

MemoryPlane, MemoryId, local revision allocation, delivery dedup, retrieval,
status/lifecycle/influence mutation and UnderstandingView
  reject completely as duplicate state ownership.
```

Integration points:

- `ObservationSubmission::validate` checks exact classification conflicts after
  the foundation record shape validates;
- `ObservationJournal::admit` preserves the existing idempotency/replay order;
- a classification conflict is a typed pre-stage rejection with no accepted
  journal record and with the existing safe candidate when its base shape is
  admissible;
- classification does not add a second receipt or public journal state;
- a public schema field is added only when an actual consumer cannot obtain the
  required result through the existing admission contract and a separate
  compatibility decision approves it.

Minimum fixtures:

```text
table-driven exact families;
compatible hint;
wrong-hint conflict;
ambiguous record preserved as candidate;
coverage gap cannot be relabelled;
same input gives identical result;
no result raises support/assertability/influence;
production admission conflict yields fallback and no accepted record;
replay preserves the original classification-dependent disposition.
```

### `governor.observation.admission`

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
→ first-pass classification consistency
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

### `governor.observation.plan_compilation`

Owned entrypoints include `compile_plan` and coverage assessment helpers.
Compilation consumes registered obligation profiles and exact source visibility;
it cannot let a producer self-certify complete coverage. Absence means complete
only against a declared denominator and cursor interval. Blind, unavailable,
partial and unknown states remain distinct.

### `governor.observation.journal_projection`

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
mismatch and no-journal-write-on-conflict. Plan/coverage changes require exact
denominator, blind-interval and producer-silence fixtures.

Package tests prove only pure classification/admission/projection behavior. They
do not prove store persistence, daemon wiring, host observation, Context use,
Product Pulse or release support. Automatic GitHub Actions remain disabled;
report `NOT_EXECUTED`, simulation and unavailable edges exactly.
