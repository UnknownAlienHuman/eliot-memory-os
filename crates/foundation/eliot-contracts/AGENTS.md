# `eliot-contracts` epoch-identity work

## Scope

Issue #289 freezes the field and migration contract for parent #64. This directory is the existing C0 contract hub; do **not** create `eliot-epoch-contracts` or another package merely to move one type. The first Rust implementation belongs in a private `epoch.rs` module of this package and is exported through the existing package surface.

This work unit is contract-only. It must not edit Rust, `StateFence`, Host/Kernel/ORS/store consumers, the root workspace, `Cargo.lock`, runtime manifests, or support status.

## Functional capability cell

```text
cell_id: foundation.authority.epoch-identity
lifecycle_owner: none; stateless contract
mutable_state: none
effects: none
current source owner: eliot-contracts
first consumer migration: eliot-host-state
integration owner: #64
```

The contract is justified inside the existing hub because epoch identity is a stable, dependency-light primitive used across Host, Kernel, ORS, protocol, daemon, store, Watchdog, User Broker, runtime-status, recovery, receipts, MACs, and State Fences. A new crate would add a third physical/type owner before any consumer migration.

## Required source design for the later implementation unit

Implement exactly one canonical family:

```rust
EpochLineageId
EpochId
EpochTransition
EpochRelation
LegacyScalarEpoch
LegacyEpochImport
EpochContractError
```

Expected source functions are listed in `epoch-id.contract.toml`. Preserve these rules:

1. `EpochId` authority is exact tuple identity: `(lineage_id, sequence)`.
2. Numeric sequence comparison is valid only inside one exact lineage.
3. No `Ord` or `PartialOrd` implementation is allowed for `EpochId` or `EpochLineageId`.
4. A direct child is exactly one sequence step in one lineage with an explicit parent.
5. Restore, migration, corruption recovery, and break-glass mint genesis in a globally distinct lineage.
6. Canonical digest input binds the versioned domain separator, lineage, and sequence.
7. Legacy scalar input is compatibility evidence only; it cannot authorize anything until exact installation/Host lineage evidence produces an explicit migration result.
8. Unknown, ambiguous, or conflicted legacy lineage becomes suspended/manual recovery, never “current lineage”.
9. No `EpochId -> u64`, `as_u64`, `value`, implicit `From`, default lineage, or lossy compatibility adapter is allowed.

## No-third-type migration

`eliot-host-state` currently owns a local `EpochIdentity`/`EpochTransition`. The first consumer wave must remove that implementation or convert it to a compatibility re-export/type alias of this package. It must not retain two independent validators, two serde shapes, or a wrapper that reintroduces ordering.

The old scalar `eliot_contracts::AuthorityEpoch` remains only as a bounded compatibility input while consumers migrate. New authority-bearing fields cannot use it. Removing or renaming it belongs to the integration wave after reverse-consumer proof; do not break the workspace in the contract implementation unit.

## Required proof for the Rust implementation

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-contracts --all-targets
cargo test --locked -p eliot-contracts
cargo clippy --locked -p eliot-contracts --all-targets -- -D warnings
git diff --check
```

Package tests must include every minimum fixture named by the TOML contract. Then the Host consumer wave must run `eliot-host-state` package proof plus a shared golden corpus. Package proof does not establish Kernel/store/recovery behavior.

## Prohibited shortcuts

Do not:

- order UUIDs, timestamps, or unrelated lineages;
- infer lineage from a process, PID, current directory, latest Host record, largest scalar, or current runtime;
- reuse Host-specific `PlatformHandle` in the public foundation contract;
- expose vendor, storage, Windows, Tokio, process, or runtime types;
- rewrite durable scalar records in place;
- close #64 from a contract/package test;
- change the oracle to accept a scalar-only consumer;
- merge this PR while another writer owns `crates/foundation/eliot-contracts`.

## Working discipline

Create one fresh issue branch per migration wave. Push each completed atomic slice immediately. Before editing a consumer, re-read current `main`, open PR path claims, the nearest `AGENTS.md`, and `epoch-id.contract.toml`. Stop with a Contract Challenge when exact legacy lineage evidence is unavailable or a consumer requires lossy scalar compatibility.

## Proof ceiling

The present PR is:

```text
STATIC_FIELD_AND_MIGRATION_CONTRACT_ONLY
TARGET
NOT_EXECUTED
```

It changes no Rust, runtime, authority, durable state, support, or Product behavior.
