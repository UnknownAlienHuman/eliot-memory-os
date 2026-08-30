## I18.33. Crate fleet build and verification economics

Crate topology is verified as a development-system property. Every first-party crate exposes one generated Instrument Plane entrypoint:

```text
eliot dev crate check <package>
```

The command resolves the current `ModuleTestCapsule` and runs only applicable contract/schema/format checks, exact-package Cargo check or Clippy, unit/property/model/golden tests, nextest selectors, declared compile-fail/doctest/parser corpora and local restart/fault cases for service crates. Its receipt records selected/executed counts, `BuildFingerprint`, target root, `CrateContextProfile`, `CrateBuildProfile`, raw/normalized evidence, proof ceiling and mandatory consumer/edge checks not yet run.

Crate-local PASS proves only the crate contract. Public-contract changes schedule direct-consumer compatibility and affected reverse-dependency checks; process/module promotion additionally requires its cohort and real-edge profile.

### Fleet conformance

The generated `crate-fleet` profile checks:

```text
workspace members/default-members and C0–C4 dependency direction;
contract-hub churn, reverse fan-out and measured workset profiles;
FunctionalCapabilityCell and EffectiveMicroModuleManifest coverage;
public contract digests, unique catalogue entries and consumer coverage;
crate-to-runtime-bundle mapping and ModuleReplacementClass;
independent ModuleTestCapsule and ProofLatencyProfile;
zero-test/stale-test metadata and feature/dependency duplication;
proc-macro, build-script and native-link islands;
forbidden direct process/store/vendor calls;
package owner and metadata completeness.
```

Outcomes are `PASS`, `PARTIAL`, `REVIEW_REQUIRED` and `FAIL`. Missing or stale catalogue/manifest/graph/context evidence is PARTIAL; crossed empirical ranges open `CrateScaleReview`; cycles, a second mutable-state owner, missing lifecycle owner/test seam, forbidden layer edges, public vendor leakage or absent required proof fail the applicable admission. A correct but slow proof is `MANUAL_OR_SLOW_LANE`, not semantic invalidity; it leaves the crate eligible for explicit slow/manual proof but blocks automatic interactive scheduling until a measured profile admits it.

### Build modes and cache evidence

ELIOT measures three distinct modes:

```text
interactive incremental
  one worktree/BuildFingerprint target root, Cargo incremental and focused selectors;

shared non-incremental
  incremental off, optional pinned sccache and exact compiler/profile/feature/environment identity;

clean/release
  locked inputs, declared cache state and real codegen/link/runtime proof.
```

A cache hit never substitutes for execution. Each build-mode experiment records cold/warm time, Cargo critical units and parallelism, cache hit/miss/eviction, memory/disk, target-lock wait, representative rebuild fan-out and artifact identity. Incremental and shared-cache paths remain separate empirical profiles; unknown cache identity forces rebuild.

### Test-binary organization and sharding

Default organization per production crate is:

```text
unit/property tests beside private core logic;
one public-contract integration harness at `tests/contract.rs` with submodules under `tests/contract/`;
at most one separate edge harness when the crate owns a real process/store/protocol edge;
large scenarios in dedicated scenario/edge crates;
shared fixture crate only when multiple packages reuse it;
explicit harness/oracle for compile-fail and UI tests.
```

A source file does not automatically become a top-level integration-test binary. Heavy dev-dependencies are isolated; binary crates remain thin; doctests are admitted only for short public examples and nextest does not replace them. Stable test identity drives nextest partitions/shards, and every shard contributes to one `TestSelectionReceipt`; missing, zero-test or parser-failed shards prevent aggregate PASS.

### Many-crate performance profile

Required measurements include Cargo metadata graph/latency, cold/warm package-selective and workspace builds, `cargo --timings` critical path, reverse-dependency fan-out, process link time, proc-macro/build-script cost, incremental target size and lock waits, shared-cache behavior, nextest archive/reuse/partition cost, and rust-analyzer latency/memory.

Representative edits cover leaf implementation, high-fan-out contract, compatible refactor, additive/breaking public contract, feature/dependency, root manifest/lock/toolchain and simultaneous worktrees.

When `WorkspaceScaleProfile` crosses a condition in I2.23, a bounded review may change `default-members`, extract a heavy optional workspace, admit shared non-incremental cache or workspace-hack only after proof, split a compile/context bottleneck, merge ineffective micro-crates, shard CI/nextest or change WIP/resource limits. The change is accepted only when intended context/build/test/ownership outcomes improve without material regression in Product Pulse, dependency clarity, recovery or agent correctness.

