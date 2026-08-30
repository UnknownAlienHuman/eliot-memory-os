# I0.5 conformance-contract source instructions

## Purpose

This prototype package is the single owner-neutral C0 contract for the
orthogonal status dimensions required by Implementation I0.5. It exists so
bootstrap, Module/Capability Registry projections, reports and ControlBoard do
not each invent their own support vocabulary.

The package is stateless and effect-free. It validates supplied values; it does
not discover source, run an instrument, observe a process, decide support,
promote a capability, persist canonical state or render a report.

Issue #220 owns this contract package. Issue #216 is the first consumer
migration. Do not add the package to the root workspace until implementation,
package proof and one real bootstrap consumer fixture exist.

## Why this package exists

Current source has no Rust owner for:

```text
ContractMaturity;
ImplementationSupport;
EvidenceExecutionStatus;
SupportObservationState;
the exact five-domain CurrentSystemEvidenceSnapshot closure.
```

`eliot-bootstrap` currently combines a flat key/value record, one
`EvidenceEvaluation` enum and a list of unavailable domain names. It must not
become the cross-system owner of support states.

Do not reuse these nearby but different types:

```text
eliot-instrument-api::ExecutionStatus
  instrument stage lifecycle, including ACCEPTED/RUNNING/SUCCEEDED;

EvidenceStatus / EpistemicStatus
  support of an observation or proposition;

runtime/service health states
  process and generation operation;

SourceStatus in eliot-bootstrap
  availability of one compiler input projection.
```

Similarity of names does not make these contracts interchangeable.

## FunctionalCapabilityCell

```text
cell_id: foundation.conformance.support-contracts
lifecycle_owner: none; stateless contract
mutable_state: none
allowed_effects: none
source_layer: C0
first_consumer: eliot-bootstrap CurrentSystemEvidenceSnapshot v2 migration
replacement_boundary: this versioned public contract and consumer fixtures
proof_ceiling: package contract proof only
```

One crate is justified because the types form one stable dependency-light
contract island with multiple real consumers and one independent invariant/test
surface. Do not split one enum per crate.

## Required public enums

Wire spellings are fixed by Implementation I0.5 and use
`SCREAMING_SNAKE_CASE`.

```rust
pub enum ContractMaturity {
    Skeleton,
    Compatible,
    Stable,
    Replaceable,
    Retired,
}

pub enum ImplementationSupport {
    CurrentVerified,
    CurrentUnverified,
    Partial,
    Blocked,
    Target,
    Experimental,
    Deferred,
    Degraded,
    Stale,
    NotApplicable,
}

pub enum EvidenceExecutionStatus {
    NotExecuted,
    Simulated,
    Executed,
    UnknownOutcome,
}

pub enum SupportObservationState {
    Observed,
    NotRunning,
    Unavailable,
    Unknown,
    Stale,
    Conflicted,
}

pub enum EvidenceDomain {
    Source,
    Build,
    Runtime,
    Store,
    Integrations,
}
```

Do not add `Success`, `Ready`, `Pass`, `Complete`, `Healthy` or a generic
`Status` alias. Those words answer different questions.

## Required public records

Freeze field types with the contract owner before source implementation. The
records must be equivalent to the normative I0.5 shape and must not use
`serde_json::Value`, vendor types or report strings.

### `DomainCoverage`

Must preserve at least:

```text
domain: EvidenceDomain;
state: SupportObservationState;
source handles;
evidence references;
blind or unobserved boundaries;
observation time when available;
expiry when applicable;
invalidation set.
```

### `CapabilitySupportRow`

Must preserve at least:

```text
contract_ref;
support_claim_ref;
support_observation_state;
contract_maturity;
implementation_support;
evidence_execution_status;
source handles;
evidence references;
blind boundaries;
invalidation set.
```

Every load-bearing collection is bounded. Set-like handles are canonicalized and
unique; source order is preserved only where the accepted contract declares it
meaningful.

Do not add a mutable current-support registry to this crate. Rows are immutable
values supplied by the actual owner/evidence compiler.

## Required pure API

Use these functions or an equivalently narrow public contract:

```rust
pub fn validate_domain_coverage(
    coverage: &[DomainCoverage],
) -> Result<(), ConformanceContractError>;

pub fn validate_capability_support_row(
    row: &CapabilitySupportRow,
) -> Result<(), ConformanceContractError>;

pub fn validate_support_claim_set(
    rows: &[CapabilitySupportRow],
) -> Result<(), ConformanceContractError>;
```

Optional constructors are allowed only when they cannot bypass the validators.
A constructor named `current_verified` must require every proof-bearing input;
it cannot fill evidence, currentness or invalidation with defaults.

## Validation logic

### Five-domain closure

`validate_domain_coverage`:

1. accepts exactly one row for each closed domain:
   `Source`, `Build`, `Runtime`, `Store`, `Integrations`;
2. rejects missing and duplicate domains;
3. validates all handles, blind boundaries, times and invalidation entries;
4. does not infer one domain from another;
5. treats `NotRunning` as a valid local observation, not a global compiler
   failure;
6. preserves `Unavailable`, `Unknown`, `Stale` and `Conflicted` distinctly.

### Orthogonal status axes

`validate_capability_support_row` must enforce:

```text
observation state != contract maturity;
observation state != implementation support;
observation state != evidence execution;
contract maturity != implementation support;
evidence execution != verifier/evaluation result.
```

In particular:

- `Observed` never implies `CurrentVerified` or `Executed`;
- `NotRunning`, `Unavailable`, `Unknown`, `Stale` or `Conflicted` never promote
  support;
- `NotExecuted` and `Simulated` cannot satisfy a real-effect/current-behavior
  support claim;
- source presence without behavior proof is at most `CurrentUnverified` with
  the actual execution state;
- `CurrentVerified` requires exact current scoped evidence, `Executed`, at
  least one source/evidence handle and a non-empty invalidation set;
- an invalidated dependency makes the dependent support row `Stale` rather
  than silently retaining current support;
- `Retired` contract maturity cannot be combined with current operational
  support unless an accepted compatibility/migration field explicitly explains
  the limited retained surface;
- report wording, test count, manifest presence and source type existence cannot
  promote a row.

Do not invent an evaluation PASS field in this package. A support row references
executed evidence; the applicable evaluator/verifier contract owns the result.

### Claim-set closure

`validate_support_claim_set`:

- rejects duplicate `support_claim_ref` identities;
- rejects duplicate ownership of one contract/scope claim;
- preserves rows in deterministic canonical order for digesting;
- rejects a stronger derived claim than its cited evidence permits;
- does not calculate product acceptance or aggregate one scalar score.

## Bootstrap migration boundary

Issue #216 must consume this crate rather than duplicate the enums.

Required migration behavior:

```text
old flat EvidenceRecord/EvidenceEvaluation snapshot
→ explicit legacy import;
→ all unrepresented domains become Unknown;
→ support ceiling no stronger than exact retained evidence;
→ old bytes and digest remain historical evidence;
→ new snapshot uses five DomainCoverage rows and CapabilitySupportRow values.
```

The existing string `eliot-current-system-evidence-snapshot-v2` does not prove
that the current flat schema satisfies v2. The migration must either assign a
new version or define an explicit compatibility profile; it cannot silently
reinterpret old bytes as complete.

`SourceStatus` may remain inside bootstrap only for the compiler input envelope.
It must not be re-exported as support or observation status.

## Expected consumers

First real consumer:

```text
eliot-bootstrap::CurrentSystemEvidenceCompiler.
```

Expected later consumers, activated only by real edges:

```text
conformance documentation projection;
Module/Capability Registry support views;
ControlBoard current-system view;
report renderer;
release/support admission checks.
```

Consumers compile against this contract package. They do not depend on
bootstrap compiler implementation or a Meta runtime-status owner.

## Error contract

`ConformanceContractError` should be closed and path-specific, including at
least:

```text
invalid text/handle;
missing domain;
duplicate domain;
duplicate claim;
invalid time/expiry;
invalid support combination;
missing evidence for CurrentVerified;
missing invalidation set;
non-canonical set/order when validating serialized output;
unsupported contract version.
```

Return all safely discoverable structural defects when practical. Do not expose
raw Serde errors as the public agent-facing explanation.

## Required fixtures

Minimum package fixtures:

```text
exact five-domain closure;
missing domain;
duplicate domain;
Observed + NotExecuted cannot be CurrentVerified;
source-only observation cannot claim runtime/store support;
NotRunning != Unavailable != Unknown;
stale and conflicted remain distinct;
CurrentVerified without exact evidence fails;
CurrentVerified without invalidation fails;
Simulated cannot satisfy real-effect support;
permutation-independent semantic set identity;
duplicate support claim rejection;
legacy flat import remains partial/unknown;
unknown enum value and incompatible version fail closed.
```

Consumer fixtures:

```text
eliot-bootstrap imports every public type from this crate;
bootstrap cannot construct CurrentVerified from EvidenceEvaluation alone;
source-only bootstrap snapshot retains unknown runtime/store/integrations;
serialization round-trip uses exact I0.5 wire values.
```

## Hard boundaries

Do not add:

- mutable state, registry ownership, cache or global singleton;
- filesystem, process, runtime, store, network or model calls;
- support promotion, Product acceptance, finish or release authority;
- report/ControlBoard rendering;
- instrument execution or verifier result ownership;
- vendor/framework types;
- free-form status strings or generic JSON;
- a second copy of the enums in bootstrap, runtime-status or reports;
- root workspace membership before implementation and proof;
- an automatic GitHub Actions trigger.

Return a `ContractChallenge` when:

- a requested rule needs verifier/evaluator semantics not present in I0.5;
- field-level currentness/expiry/invalidation types are still ambiguous;
- a consumer requires another state owner;
- compatibility with the current flat snapshot cannot be expressed without
  changing old bytes;
- package proof would require a runtime/store observation.

## Implementation write scope

The source implementation agent receives only:

```text
crates/foundation/eliot-conformance-contracts/src/**;
crates/foundation/eliot-conformance-contracts/tests/**;
this package manifest only when dependencies are required;
```

Root `Cargo.toml`, `Cargo.lock`, bootstrap source and consumer integration belong
to separate integration units. One implementation worker does not admit its own
package to the workspace.

## Proof and admission

After source exists, minimum package proof:

```text
cargo fmt --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml -- --check
cargo check --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml --all-targets
cargo test --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml
cargo clippy --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml --all-targets -- -D warnings
```

If the package remains under the root directory while excluded from the
workspace, use the exact standalone/exclusion setup chosen by the integration
owner; do not mutate root topology merely to make a command convenient.

Workspace admission requires all of:

```text
field-level contract review;
source implementation;
nonzero package fixtures;
first bootstrap consumer compile fixture;
no duplicate status owner;
current-main rebase;
integration-owner review;
a separate root Cargo.toml/Cargo.lock unit.
```

Package proof establishes only the I0.5 value/invariant contract. It does not
prove current repository/runtime/store/integration observation, bootstrap
capture, support promotion, Product acceptance or release. Report unexecuted
proof exactly.
