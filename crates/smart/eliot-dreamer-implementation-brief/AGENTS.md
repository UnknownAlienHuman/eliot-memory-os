# `eliot-dreamer-implementation-brief` implementation contract

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Every implementation Issue lists what to read in a `## Read` section: handle
selectors (`I5.19`, `I1.1..I1.8`, `A4.*`, `APPENDIX-L`) and repository files,
one per list item. Draft it with `python scripts/docs_router.py route --path
<repository/path> --format issue` and keep only what the change needs.

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

With `--issue`, the required reading is the Decision Safety Floor, the items the
Issue declares and the nearest `AGENTS.md` files; path routes become optional
pointers. Without an Issue, use `--path <repository/path> --topic "<causal
property>"` for every mutable path family, or `--changed-from origin/main` for
the complete branch delta. Open the verified bundle and read every required
item before mutation. A route alone is navigation, not reading evidence.

Record the route receipt ID, read receipt ID, declared reading or matched
routes, required handles, fragment paths and SHA-256 values, verified bundle
SHA-256, and explicit reading attestation in the work unit or pull request.
Optional fragments are loaded only when the current decision crosses their
stated boundary. A legacy `ELIOT_*` compatibility map is never an acceptable
read receipt.

If the Issue has no `## Read` section, a declared item does not resolve, no
non-baseline route matches a path read without an Issue, a required item is
stale or missing, or scope expands beyond the receipt, stop and repair the Issue
or the route; silence is not permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
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
