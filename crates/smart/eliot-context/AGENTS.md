# Context compiler source instructions

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


## Purpose and owner boundary

This package is the current consolidated C1 owner of pure context candidate
validation, whole-unit admission, bounded decision-local compilation, exact cue
orientation helpers and their rebuildable projections. It owns no canonical
memory, retrieval provider, model route, task selection, authority, host
delivery, or finish decision.

Read issue #248 before changing local admission integrity. Larger provider,
contract, source-layout and facade-retirement work remains separate; do not
reactivate historical function-per-crate prototypes because a planning
document named them.

## Current compiler path

```text
owner-supplied ContextInput
+ exact-revision ContextRecipe
-> structural/fence/identity validation
-> deterministic whole-unit ordering
-> role and total budget admission
-> complete units, exact handles, suppressions/quarantine/revalidation
-> explicit unknowns and dimensioned PacketQualityScorecard.
```

Every input atom is already a candidate from another admitted owner. This
package neither retrieves it nor changes its epistemic status or authority.

## Admission integrity invariants

1. `ContextRecipe.recipe_revision` must equal `ContextInput.task_revision`.
   Structural validity alone cannot make a stale recipe applicable to a newer
   task view.
2. One input read set contains each `ContextAtom.atom_id` at most once.
   Duplicate atoms are rejected before sorting, budgeting or rendering.
3. One recipe contains at most one `RoleBudget` for each `ContextRole`.
   `budget_for` must never depend on caller order among duplicate budgets.
4. `required_roles` is a semantic set and cannot contain duplicates.
5. Every required role has one declared role budget. A zero role budget is
   valid: required/protected atoms remain available as exact handles rather
   than being silently discarded.
6. Whole-unit admission remains intact. Do not split one semantic atom merely
   to make it fit.
7. Safety-floor material, omissions, stale/conflicting material and unknowns
   remain visible through typed disposition/handles; fluent truncation is
   forbidden.
8. Compilation is deterministic, bounded, stateless and side-effect free.

## Deferred contract and topology work

Do not hide the following inside a local integrity patch:

```text
owner-neutral provider denominator and ProviderContribution closure;
contract/candidate/admission/assembly source-cell split inside the accepted
physical package;
canonical digest replacement for Debug-formatted revisions/fences;
Governor provider and Host delivery edges;
Decision-Safety-Floor/handle scorecard contract changes requiring consumer
migration.
```

Those changes require their own contract, consumer and affected-edge units.

## Hard boundaries

Do not add:

- canonical writes, direct store/process/filesystem/network access or model calls;
- retrieval, task selection, delivery, authority, policy, lifecycle, support or
  finish ownership;
- a second Context compiler/facade or mutable Understanding owner;
- arbitrary JSON to avoid a missing field-level contract;
- order-dependent policy meaning;
- silent omission of required atoms or unknowns;
- a new crate without an independent contract/proof/replacement seam;
- automatic GitHub Actions.

Return a ContractChallenge when requested work needs another owner, an
unaccepted public contract, a provider denominator, a host effect, or evidence
unavailable inside this package-local unit.

## Proof

Minimum package proof for Rust changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-context --all-targets
cargo test --locked -p eliot-context
cargo clippy --locked -p eliot-context --all-targets -- -D warnings
```

Required integrity fixtures:

```text
recipe/input revision mismatch;
duplicate atom identity;
duplicate role budget;
duplicate required role;
zero required-role budget produces HandleOnly;
matching revision preserves the existing deterministic compile path.
```

Package proof establishes only pure compiler integrity. Provider admission,
canonical source projection, Context consumer/host delivery and
`D3B_REACTIVE_CONTEXT_PULSE_01` remain separate Edge/Product proofs. Report
all unexecuted boundaries exactly.
