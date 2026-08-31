# I0.5 conformance-contract source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Read the verified bundle before mutation and record the route/read receipt IDs,
required handles, hashes, verified bundle SHA-256, and explicit reading
attestation in the work unit or pull request. Running `scripts/docs_router.py
route` alone is navigation, not reading evidence. Re-run the reader whenever the
mutable path, causal property, authority boundary, or evidence scope expands.

If no non-baseline route matches, a required item is stale or missing, or the
scope exceeds the read receipt, stop and repair or rerun the route; silence is
not permission. See
[`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Purpose

This package is the single owner-neutral C0 contract for the orthogonal status dimensions required by Implementation I0.5. It exists so bootstrap, Module/Capability Registry projections, reports, and ControlBoard do not each invent their own support vocabulary.

The package is stateless and effect-free. It validates supplied values; it does not discover source, run an instrument, observe a process, decide support, promote a capability, persist canonical state, or render a report.

Issue #263 owns the source implementation. Issue #216 is the first consumer migration. Do not add the package to the root workspace until implementation, package proof, and one real bootstrap consumer fixture exist.

## Functional capability cell

```text
cell_id: foundation.conformance.support-contracts
lifecycle_owner: none; stateless contract
mutable_state: none
allowed_effects: none
source_layer: C0
first_consumer: eliot-bootstrap CurrentSystemEvidenceSnapshot migration
replacement_boundary: this versioned public contract and consumer fixtures
proof_ceiling: isolated package contract proof only
```

One crate is justified because the types form one stable dependency-light contract island with multiple real consumers and one independent invariant/test surface. Do not split one enum per crate.

## Required public vocabulary

Wire spellings follow Implementation I0.5 and use `SCREAMING_SNAKE_CASE`:

```text
ContractMaturity:
  SKELETON | COMPATIBLE | STABLE | REPLACEABLE | RETIRED

ImplementationSupport:
  CURRENT_VERIFIED | CURRENT_UNVERIFIED | PARTIAL | BLOCKED | TARGET |
  EXPERIMENTAL | DEFERRED | DEGRADED | STALE | NOT_APPLICABLE

EvidenceExecutionStatus:
  NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME

SupportObservationState:
  OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED

EvidenceDomain:
  SOURCE | BUILD | RUNTIME | STORE | INTEGRATIONS
```

Do not add a generic `Status`, `Success`, `Ready`, `Pass`, `Complete`, or `Healthy` alias.

## Required records

`DomainCoverage` preserves one domain, one observation state, source/evidence handles, blind boundaries, observation/expiry times, and an invalidation set.

`CapabilitySupportRow` preserves contract and claim identity; claim domain and required dependency domains; the exact observation/maturity/support/execution dimensions; source/evidence handles; blind boundaries; invalidation set; evaluation time; proof profile; and an optional compatibility rule for a retired contract.

Every load-bearing collection is bounded, canonicalized, and duplicate-free. Values are immutable inputs from the actual compiler/owner; this crate owns no current-support registry.

## Required pure API

Intrinsic row/collection validation and snapshot-bound validation remain distinct:

```rust
pub fn validate_domain_coverage(
    coverage: &[DomainCoverage],
) -> Result<(), ConformanceContractError>;

pub fn validate_capability_support_row(
    row: &CapabilitySupportRow,
) -> Result<(), ConformanceContractError>;

pub fn validate_capability_support_row_against_coverage(
    row: &CapabilitySupportRow,
    coverage: &[DomainCoverage],
) -> Result<(), ConformanceContractError>;

pub fn validate_support_claim_set(
    rows: &[CapabilitySupportRow],
) -> Result<(), ConformanceContractError>;

pub fn validate_conformance_contract_set(
    contract_set: &ConformanceContractSet,
) -> Result<(), ConformanceContractError>;
```

The one-row validator cannot prove a current dependency by itself. `CURRENT_VERIFIED` is accepted as a complete contract-set result only after the row is checked against exact five-domain coverage at the same evaluation boundary.

Canonicalization functions may accept arbitrary source ordering, but strict validators reject non-canonical serialized order and duplicate identities.

## Invariants

1. Exactly one `DomainCoverage` row exists for every closed domain.
2. Observation state, contract maturity, implementation support, and evidence execution remain independent axes.
3. `OBSERVED` never implies `CURRENT_VERIFIED` or `EXECUTED`.
4. `CURRENT_VERIFIED` requires `EXECUTED`, non-skeleton/non-retired maturity, a nonblank proof profile, current unblinded `OBSERVED` evidence for the claim domain and every required dependency domain, exact source/evidence handles, and a nonempty invalidation set.
5. `NOT_RUNNING`, `UNAVAILABLE`, `UNKNOWN`, `STALE`, and `CONFLICTED` cannot satisfy a current verified dependency.
6. Source-only evidence cannot verify a runtime, store, or integration claim.
7. `NOT_APPLICABLE` carries no required dependency domain and no execution claim.
8. A retired contract can be exposed as current only through an explicit compatibility rule and can never be `CURRENT_VERIFIED`.
9. Duplicate claim/domain/handle identity fails closed.
10. Canonicalization of set-like inputs is permutation-invariant.
11. Invalidated or stale evidence cannot retain a current support claim.
12. No aggregate product-acceptance or scalar quality score belongs here.

## Bootstrap migration boundary

Legacy flat bootstrap evidence imports explicitly as partial/unknown. Unrepresented domains become `UNKNOWN`. A legacy `VerifierBacked` label does not become `EXECUTED` or `CURRENT_VERIFIED`. Old bytes and digest remain historical evidence; they are not reinterpreted as a complete five-domain snapshot.

## Hard boundaries

Do not add:

- mutable state, caches, registries, or global singletons;
- filesystem, process, runtime, store, network, or model calls;
- support promotion, Product acceptance, finish, or release authority;
- report or ControlBoard rendering;
- instrument execution or verifier-result ownership;
- vendor/framework types or generic JSON;
- a second status vocabulary in bootstrap, runtime-status, or reports;
- root workspace admission in this issue;
- an automatic GitHub Actions trigger.

## Proof

Minimum package proof when a Rust runner is available:

```text
cargo fmt --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml -- --check
cargo check --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml --all-targets
cargo test --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml
cargo clippy --manifest-path crates/foundation/eliot-conformance-contracts/Cargo.toml --all-targets -- -D warnings
```

Until those commands execute, every source commit remains `CURRENT_UNVERIFIED / NOT_EXECUTED`.

## Working discipline

Push every completed atomic source slice immediately to the issue branch. Do not keep a large unpushed local diff while continuing analysis.
