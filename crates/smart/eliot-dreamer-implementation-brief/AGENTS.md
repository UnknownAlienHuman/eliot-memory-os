# `eliot-dreamer-implementation-brief` implementation contract

<!-- eliot-doc-routing:start -->
## Mandatory documentation reading

Follow the [verified reading protocol](../../../docs/architecture/READING_PROTOCOL.md). From the repository
root, read the owning Issue's `## Read` with the actual mutable paths:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Open the verified bundle and read every required item before editing. Record its
route/read identities, hashes and reading attestation. Reroute when scope changes;
without an owning Issue, use the protocol's path/topic mode. Reading references
do not grant write scope. Do not substitute a legacy compatibility map for a read.
<!-- eliot-doc-routing:end -->

Owning issue: [#651 — A-09 evidence-bound Implementation self-query projection](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/651).

## Authority

Implement only the pure deterministic `ArchitectureSelfQuery` / `ImplementationBrief` profile projector. The package owns its Implementation snapshot, evidence-join and candidate-output contracts. It reuses the exact A-03 self-query closure and I0.5 conformance axes. It owns no source discovery, test execution, provider, Store, support mutation, work planning, authority, effect or Finish path.

## Mandatory invariants

- exactly the existing `ArchitectureSelfQuery` job with `ImplementationBrief` output profile;
- governing Architecture remains accepted authority and cannot be overridden by Implementation or observations;
- `ContractMaturity`, `ImplementationSupport`, `EvidenceExecutionStatus`, `SupportObservationState` and `EvidenceDomain` remain independent;
- source, compile, package, integration, Edge, runtime, Product and release stages remain independent;
- stale, skipped, simulated, partial, missing, failed, unknown and conflicted evidence remain distinct;
- all mechanisms, statements, obligations, denominator members, evidence records and gaps are explicitly accounted;
- exact replay is deterministic and changed same-identity content conflicts;
- every collection, string, input/output byte count and work unit is bounded;
- diagnostics are bounded and contain no secret or protected content;
- all 39 `WORK_UNIT_CASE: 651/1..39` tests are substantive and execute production code.

## Required verification

```bash
cargo fmt --manifest-path crates/smart/eliot-dreamer-implementation-brief/Cargo.toml -- --check
cargo test --manifest-path crates/smart/eliot-dreamer-implementation-brief/Cargo.toml --all-targets
cargo clippy --manifest-path crates/smart/eliot-dreamer-implementation-brief/Cargo.toml --all-targets -- -D warnings
cargo doc --manifest-path crates/smart/eliot-dreamer-implementation-brief/Cargo.toml --no-deps
git diff --check
```

Workspace admission remains #968.
