# `eliot-runtime-contracts` Control Reserve work

## Scope

Issue #293 freezes the owner-neutral capacity contract for parent #65. This package already owns dependency-light runtime schemas and pure legality checks; do **not** create `eliot-control-reserve`, a scheduler crate, or another permit owner merely to move these types.

The present work unit is contract-only. It must not edit Rust, `eliot-kernel-core`, `eliot-kernel-service`, ORS, Store, Host, ProcessExecutor, Watchdog, notification, IPC, runtime configuration, the root workspace, `Cargo.lock`, or support status.

## Functional capability cell

```text
cell_id: foundation.runtime.control-reserve-contract
lifecycle_owner: none; stateless contract
mutable_state: none
allowed_effects: none
source_owner: eliot-runtime-contracts
first implementation consumer: eliot-kernel-core FrontDoor
integration owner: #65
```

`ControlReserveProfile` describes and validates the capacity vector. It does not own queues, semaphores, memory, ORS transactions, Store connections, process slots, pipes, notifications, CPU, disk, permits, or health state. The actual owner of each bottleneck enforces and observes its own partition.

## Required source design for the later Rust unit

Implement a private `control_reserve.rs` module and export exactly one contract family:

```rust
CapacityClass
NormalWorkClass
ControlOperationClass
EmergencyOperationClass
CapacityBottleneck
CapacityUnit
CapacityEnforcement
BottleneckCoverageState
CapacityLimit
BottleneckCapacityProfile
ControlReserveProfile
CapacityRequest
CapacityPermitBinding
CapacityReleaseEvidence
CapacityAdmissionDisposition
ReserveHealthDisposition
ControlReserveContractError
```

Required pure functions are listed in `control-reserve.contract.toml`. Keep validation separate from physical acquisition. The contract may classify a request and validate an owner-produced permit/release record; it must never allocate or retain capacity.

## Admission algorithm

For every request:

1. validate exact profile/product/config/generation identity and invalidation set;
2. resolve the exact bottleneck row from the complete denominator;
3. reject `UNKNOWN`/`UNSUPPORTED` rows for claims requiring that reserve dimension;
4. validate that operation class maps to exactly one capacity class;
5. validate unit and amount without converting heterogeneous units to a scalar percentage;
6. ensure the selected class has its own non-borrowable partition;
7. let the bottleneck owner acquire atomically under its own implementation;
8. bind the owner-produced permit to operation identity, owner generation, canonical Authority Epoch, profile revision and exact capacity amount;
9. release or reconcile through the same durable operation identity;
10. derive health/degradation only from the complete vector and owner evidence.

Normal admission may be rejected/backpressured while protected control remains available. A protected request may fail independently at one bottleneck without claiming every control path failed. An emergency slot exists only where explicitly preallocated and may record reserve loss/gaps or enter recovery; it is not spare workload capacity.

## Exact protected operations

The protected class is limited to:

```text
cancellation;
fencing and revocation;
health/readiness control;
critical telemetry and coverage-gap publication;
Critical Attention transition;
Problem/Incident transition;
persistent notification/inbox transition;
safe shutdown and drain;
recovery, containment and exact unknown-outcome reconciliation.
```

Normal reads/writes, interactive work, verification, background work, model jobs, swarm work, reporting, maintenance and pipeline downstream headroom do not gain protected capacity merely because they are important or delayed.

## Bottleneck denominator

The profile must contain one explicit row for every I14.3 dimension:

```text
Kernel control channel;
Kernel runnable control slots;
ORS transaction slots;
ORS durable queue bytes;
Store connection slots;
Store transaction slots;
Store pending-write memory;
process launch slots;
process cancellation/termination/Job-control path;
notification/persistent inbox transition;
CPU control task slots;
protected memory bytes;
pipe/message bytes;
file descriptors/handles;
disk queue/write capacity.
```

A row is `CLAIMED`, `UNSUPPORTED`, or `UNKNOWN`; omission is invalid. `CLAIMED` requires an enforcement mode, owner, exact unit/limits, proof profile and invalidation set. Priority-only scheduling is not an enforcement mode.

## Required tests for the Rust implementation

- saturating every normal partition leaves the corresponding protected partition available;
- a normal operation cannot request or receive protected/emergency capacity;
- a protected operation cannot be disguised as normal or vice versa;
- emergency capacity is preallocated outside normal/protected accounting and cannot be borrowed;
- omitted, duplicate, unknown and unsupported bottleneck rows fail or degrade exactly as declared;
- bytes, handles, slots and concurrency are never summed into one utilization percentage;
- one exhausted dimension names the exact bottleneck and does not fabricate global exhaustion;
- loss of the last-resort slot produces `CONTROL_GUARANTEE_LOST`, never `HEALTHY`;
- stale operation, generation, epoch or profile identity rejects permit/release evidence;
- restart reconciliation cannot revive a leaked in-memory permit;
- profile canonicalization is permutation-invariant and duplicate-free;
- `DownstreamHeadroomReservation` cannot be converted to a protected permit;
- normal Store/daemon admission uses the normal class in the first consumer edge.

## Migration waves

```text
contract + property fixtures
→ Kernel FrontDoor normal/protected split
→ ORS and Store reserve adapters
→ Host/process/IPC/Watchdog/notification adapters
→ multidimensional fault matrix and #11 Product Pulse
```

Each wave uses a fresh current-main issue branch and separate PR. The Kernel adapter must remove the current ambiguity in which ordinary authorization and long-running control effects consume one pool. Do not solve it by renaming the existing pool.

## Prohibited shortcuts

Do not:

- implement one global semaphore or one scalar reserve percentage;
- use priority alone as reserve isolation;
- let normal work borrow protected/emergency capacity;
- classify arbitrary work as `control` to evade backpressure;
- keep a protected permit across unbounded model/network/tool work;
- use an in-memory idempotency ledger as durable permit/effect reconciliation;
- infer permit ownership from a live process, PID, task, queue entry or surviving counter;
- claim a bottleneck protected without physical/configuration enforcement and an independent proof;
- treat `DownstreamHeadroomReservation` as Kernel Control Reserve;
- close #65 from package tests or one Kernel semaphore;
- merge while another writer owns this package path.

## Package proof for the later implementation

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-runtime-contracts --all-targets
cargo test --locked -p eliot-runtime-contracts
cargo clippy --locked -p eliot-runtime-contracts --all-targets -- -D warnings
git diff --check
```

Package proof establishes only the contract. Every claimed bottleneck needs a real owner adapter and fault proof; #11 remains the Product Pulse owner.

## Working discipline

Push each completed atomic slice immediately. Before a consumer edit, refresh current `main`, inspect open PR path claims and read the nearest `AGENTS.md`. Return a Contract Challenge when a bottleneck cannot be partitioned, its unit/owner is unknown, durable operation identity is unavailable, or the proposed proof only measures priority rather than preserved capacity.

## Proof ceiling

The present PR is:

```text
STATIC_FIELD_AND_ADAPTER_MIGRATION_CONTRACT_ONLY
TARGET
NOT_EXECUTED
```

It changes no source behavior, runtime capacity, authority, durable state, support, or Product outcome.
