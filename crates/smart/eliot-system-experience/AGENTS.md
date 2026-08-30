# System-experience projection source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## Purpose

This package is a stateless compatibility projection over immutable
Governor/store-owned experience evidence. It exists only while current consumers
or migration fixtures need the package boundary. It is not Canonical Memory,
the SystemObservationJournal, the EliotSystemExperienceBank, a lifecycle owner,
a relation owner, an index, or a current-system status owner.

The previous `SystemExperienceOwner` and its `Arc<Mutex<State>>` were an
architectural duplicate owner. Do not recreate that state under another name.
Issue #39 owns final consumer migration and retirement; issue #209 owns this
bounded source repair.

## Public function

```rust
project_experience(
    ExperienceProjectionRequest,
    &[ExperienceRecord],
    &[RelationRecord],
) -> Result<ExperienceProjection, ExperienceProjectionError>
```

The caller supplies:

- one non-zero source revision assigned by the real owner;
- one exact WorkScope-relative scope;
- one frozen, independently recheckable record denominator;
- immutable experience and relation values;
- optional task, lifecycle, epistemic-status and conjunctive text filters;
- one bounded output limit.

The function:

1. validates request bounds and exact denominator semantics;
2. validates every evidence and relation contract;
3. rejects wrong-scope records, duplicate identities and unknown relation
   endpoints;
4. canonicalizes set-like query fields;
5. orders records and relations by stable identity;
6. applies the bounded deterministic filter;
7. reports provider omission separately from query-limit omission;
8. returns only relations whose endpoints are in the returned record set;
9. computes and self-validates one deterministic content digest.

Equivalent admitted inputs in a different order must produce byte-equivalent
semantic output and the same digest.

## Hard boundaries

This package must remain stateless and effect-free.

Do not add:

- `Arc`, `Mutex`, `RwLock`, global state, cache, database, filesystem or network
  access;
- record admission, lifecycle transition, relation admission, revision
  assignment, persistence, event history or canonical receipts;
- retrieval-driven reinforcement, use/helpfulness tracking, support changes,
  influence promotion or causal attribution;
- task selection, current-system truth, policy, authority, finish or external
  effects;
- model/provider SDKs, Dreamer calls or unbounded graph traversal;
- a second experience-projection contract when the owner-neutral replacement
  edge lands.

A source digest proves deterministic content identity only. It does not prove
coverage, correctness, current applicability, use, causal contribution,
canonical admission or Product support.

## Compatibility and removal

The public v2 surface intentionally removes the old mutable-owner API. Before
promotion, inspect reverse Cargo/source consumers and classify each one:

```text
migrate to Governor/store-owned immutable projection;
retain as an exact compatibility fixture with expiry;
delete as unreferenced.
```

Do not add a facade that reconstructs the old owner. When the planned
owner-neutral experience-projection edge has real consumers and proof, this
package should be removed or reduced to an explicit migration re-export.

## Proof

Minimum package proof:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-system-experience --all-targets
cargo test --locked -p eliot-system-experience
cargo clippy --locked -p eliot-system-experience --all-targets -- -D warnings
```

Required discriminators include:

- input permutation invariance;
- exact complete and partial denominator behavior;
- provider omission versus query-limit omission;
- wrong WorkScope;
- duplicate experience/relation identity;
- unknown relation endpoint;
- malformed evidence contract;
- oversized source/query;
- tampered digest;
- consumer compilation or explicit no-consumer evidence.

Package proof establishes only pure projection behavior. It does not establish
the Governor/store provider edge, Context consumer edge, runtime support,
SystemObservationJournal import, Product Pulse or final #39 retirement.
Automatic GitHub Actions remain disabled; report unexecuted checks exactly.

Return a ContractChallenge when work requires a mutable owner, store read,
canonical transition, new field-level public schema without an accepted owner,
or another package/runtime boundary.
