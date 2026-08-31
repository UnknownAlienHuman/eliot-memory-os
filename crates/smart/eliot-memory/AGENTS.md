# Legacy `eliot-memory` source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from origin/main`
for the complete branch delta, including deletions. Open the verified bundle and
read every required item before mutation. A route alone is navigation, not
reading evidence.

Record the route receipt ID, read receipt ID, required handles/fragments and
hashes, verified bundle SHA-256, and explicit reading attestation. Optional
fragments are loaded only when the current decision crosses their boundary. A
legacy `ELIOT_*` compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale/missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Status

This package is a **legacy migration donor scheduled for retirement** under
issues #39 and #218. It is not Canonical Memory, not the Governor admission
owner, not the EliotSystemExperienceBank, not a current Context provider and not
a runtime cache with independent authority.

The current source contains an in-process `MemoryPlane` backed by
`Arc<Mutex<State>>`. That state duplicates responsibilities assigned by the
accepted Architecture/Implementation to Governor, Canonical Memory, bounded
projection owners and the host delivery path. Do not preserve that ownership by
renaming the type or splitting it into more Smart crates.

Read the repository instructions, #39, #218, the exact current normative pair
and the target owner contract before changing this package.

## Current source evidence

At source head `6294451f8802dd3b65ba5b2a70e3dd8f70867663`:

```text
exact `use eliot_memory` search           → 0 results;
exact `eliot_memory::` search             → 0 results;
Cargo dependency outside root manifest   → 0 results;
root workspace membership/dependency     → present;
broad `eliot_memory` matches              → MCP tool/query names, not crate imports.
```

This is source-search evidence, not executed Cargo proof. Until exact
`cargo metadata`, reverse-dependency and lockfile evidence runs, the package is
`STALE / NOT_EXECUTED`, not safely removed or supported.

## Existing responsibilities that must not survive here

The old package currently combines:

```text
MemoryId and local revision allocation;
capture/admission and local persistence;
status revision;
lifecycle transition;
influence admission;
retrieval and ranking;
per-session delivery deduplication;
history;
UnderstandingView construction.
```

These are not one valid Smart capability cell. They cross canonical state,
semantic admission, lifecycle, influence, retrieval, host delivery and Context
boundaries.

No new code may extend, repair or generalize these paths in this package.

## Allowed work

A work unit touching this package must have one of these dispositions:

### 1. Consumer inventory

Prove one exact current producer/consumer/reference edge and classify it as:

```text
migrate to an accepted current owner;
retain temporarily as an exact compatibility fixture with owner and expiry;
document/donor evidence only;
dead reference to remove.
```

Repository text similarity and root workspace membership are not runtime
consumers.

### 2. Pure donor extraction

A small pure algorithm may be moved only when:

- its target FunctionalCapabilityCell and lifecycle owner already exist;
- its public contract is owned outside this package;
- the old failure and discriminator are explicit;
- it carries no local identity, revision, lifecycle, influence, delivery or
  canonical state;
- package proof and the real provider/consumer edge are named.

The current `classify` helper is only an idea donor for the Governor observation
classifier. Issue #217 must first close the record-family wire contract. Do not
copy the local `ObservationHint`, `RecordKind` or `EpistemicStatus` vocabulary
as a new public contract.

### 3. Compatibility proof

Add or retain a fixture only when a real current consumer needs exact legacy
bytes or behavior. The fixture must name:

```text
consumer;
compatibility surface;
proof ceiling;
expiry;
removal condition.
```

A compatibility facade must not reconstruct `MemoryPlane` or become a hidden
second store.

### 4. Removal

After exact no-consumer proof, remove the package from root members/dependencies,
update the lockfile and delete the source in a dedicated workspace-topology
unit. Do not mix removal with unrelated semantic implementation.

## Forbidden work

Do not add:

- a new `MemoryPlane`, repository, index, cache or service owner;
- new capture, revise-status, lifecycle, influence, retrieval or delivery APIs;
- a database/filesystem/network/model/provider adapter;
- new local IDs, revision counters, event history or receipts;
- retrieval-driven reinforcement or delivery-as-use state;
- a second `UnderstandingView` or Context compiler;
- a wrapper that keeps the old owner alive under current names;
- a new consumer or root runtime dependency;
- a new crate merely to preserve one of the old nouns;
- an automatic GitHub Actions trigger.

Return a `ContractChallenge` when requested work requires preserving any old
mutable owner, inventing a missing target contract, or changing a current owner
outside the declared work unit.

## Ownership routing

Use these target boundaries rather than this package:

```text
safe observation capture and first-pass admission
  → Governor observation owner;

canonical cognitive inheritance and semantic transitions
  → logical Governor / Canonical Store path;

memory existence, support, accessibility and permitted influence
  → separate canonical contracts and governed transitions;

bounded read/query/projection
  → immutable owner-supplied projection contract;

Context inclusion
  → Context Compiler admission;

host/session delivery dedup and acknowledgement
  → host/Governor delivery owner;

Dreamer curation or semantic reinterpretation
  → candidate-only cold path.
```

## Proof and retirement gate

Before any source extraction:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-memory --all-targets
cargo test --locked -p eliot-memory
cargo clippy --locked -p eliot-memory --all-targets -- -D warnings
```

Before workspace removal, produce exact evidence for:

```text
cargo metadata --locked --format-version 1;
Cargo.toml and Cargo.lock reverse-dependency closure;
source/test/generated/config/Skill references;
root default-member and affected package build behavior;
current-main ancestry and changed-path scope.
```

Run only the affected product/edge proof for behavior actually migrated. A
no-consumer removal does not claim capture, Context, runtime or Product support.

No check has been executed by this routing change. Report package, edge,
runtime/data migration and Product proof as `NOT_EXECUTED` until exact receipts
exist.
