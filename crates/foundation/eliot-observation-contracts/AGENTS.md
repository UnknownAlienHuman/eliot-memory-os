# Observation contract source instructions

## Purpose and authority

This C0 package is the single owner-neutral source of normalized observation,
obligation, coverage-gap and record-family wire contracts. It validates supplied
values and deterministic compatibility projections. It does not observe a host,
classify prose, admit a journal record, persist canonical state, select a task,
promote epistemic support or decide finish.

Read issue #217, the exact normative pair and every affected producer/consumer
before changing a public shape. Governor classifier work in #242 consumes this
contract; it must not redefine the family vocabulary privately.

## v1 compatibility boundary

The original `src/lib.rs` is the v1 contract implementation and remains
byte-preserved behind the additive crate root. Its `ObservationRecordEnvelope`
contains one caller-selected `ObservationRecordKind` and one generic
`ObservationEventCore` for ordinary records. Consequently an ordinary v1 label
is a hint, not independent family evidence.

The following v1 shapes retain mechanical exactness:

```text
dedicated CoverageGap payload
  -> exact COVERAGE_GAP;

journal_control_event = true with a valid ordinary event
  -> exact AUDIT control record;

ordinary generic event + caller kind
  -> compatible hint only, never exact.
```

Do not infer family from `ObservationKind`, producer name, event prose, recency,
model output or caller confidence.

## v2 record-family contract

`ObservationRecordEnvelopeV2` contains one closed `RecordFamilyPayloadV2`.
Exact ordinary variants directly carry the existing field-complete owners:

```text
AuditRecord;
TelemetryRecord;
ChangeRecord;
MaintenanceRecord.
```

Do not copy their fields into a second v2 struct. A schema change to one family
changes its existing owner and all affected compatibility fixtures.

Dedicated v2 variants own only shapes not represented by those records:

```text
CoverageGapRecordV2;
JournalControlAuditRecordV2;
AmbiguousOrdinaryRecordV2.
```

`caller_family_hint` is a consistency hint:

```text
exact payload + matching/no hint
  -> Exact;

exact payload + conflicting hint
  -> FamilyHintConflict;

ambiguous ordinary payload + ordinary hint
  -> CompatibleHint;

ambiguous ordinary payload + no hint
  -> AmbiguousCandidate;

ambiguous ordinary payload + CoverageGap hint
  -> ShapeConflict.
```

A compatible hint is never serialized or reported as exact classification.

## Legacy migration

Use only `import_legacy_v1` for a v1-to-v2 compatibility projection. The request
must retain:

```text
parsed v1 record;
immutable artifact/blob handle for the original bytes;
SHA-256 of the exact original bytes.
```

The import also stores a digest of the canonical parsed v1 shape. Validation
recomputes the entire deterministic v2 projection and disposition; changed
projection bytes fail closed. The importer does not read storage, mutate the v1
record or strengthen its evidence ceiling.

Historical v1 bytes remain replay/forensic evidence. They are not rewritten into
an apparently native v2 source record.

## Governor consumer boundary

After this contract is accepted, the private Governor classifier may:

```text
validate the v2 record;
consume RecordFamilyClassification;
accept mechanically exact or compatible input according to admission policy;
preserve AmbiguousCandidate as a safe ObservationCandidate;
route FamilyHintConflict/ShapeConflict through typed pre-stage rejection;
preserve existing request/idempotency identity and fallback ordering.
```

The Governor classifier may not:

```text
construct exact family evidence from a generic event;
change epistemic status, lifecycle, influence or support;
write a store directly;
turn ambiguity into data loss;
create another public record-family enum or mapping.
```

## Hard boundaries

Do not add:

- free-form or model-based classification;
- a second record-family package or field owner;
- vendor/host/runtime/store types;
- direct filesystem, process, network or database access;
- task selection, authority, policy, lifecycle, support, relation or finish
  semantics;
- generic JSON as a substitute for unresolved family fields;
- automatic GitHub Actions.

Return a ContractChallenge when requested work requires a new public semantic
field with no accepted owner, a lossy legacy conversion, another mutable owner,
or proof unavailable inside the granted contract/consumer unit.

## Proof

Minimum package proof for source changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-observation-contracts --all-targets
cargo test --locked -p eliot-observation-contracts
cargo clippy --locked -p eliot-observation-contracts --all-targets -- -D warnings
```

Required contract fixtures include:

```text
every field-complete family round-trip;
existing family record reuse;
ObservationKind cannot mint exact family;
compatible hint and ambiguity;
wrong hint and CoverageGap relabelling conflicts;
journal-control non-recursion;
v1 ordinary import remains non-exact;
dedicated v1 exact-shape import;
legacy projection tamper rejection;
unknown-field rejection;
stable v2 contract identity.
```

A public-shape change also requires at least one real Governor consumer fixture
and an explicit serialized v1 compatibility test before root-workspace support
can be promoted. Package proof does not establish capture-provider wiring,
canonical persistence, runtime observation or Product Proof. Record every
unexecuted edge exactly.
