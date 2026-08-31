# Context compiler source instructions

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
retirement of the duplicate eliot-understanding compilation facade;
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
