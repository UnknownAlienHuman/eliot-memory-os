## I18.26. Parallel build and test execution for agent swarms

Parallel agents use Cargo package selection and one InstrumentRunner-controlled build projection. They do not independently launch unrestricted `cargo --workspace` commands.

```text
one work item
  → primary crate + frozen contract + BuildFingerprint + target class;

private crate change
  → `cargo check -p` + applicable `ModuleTestCapsule` + affected edges;

public contract change
  → provider + reverse consumer closure + compatibility fixtures;

identical BuildFingerprint
  → one producer, multiple waiters;

read-only audits on immutable base
  → reuse exact immutable artifacts/evidence;

different toolchain/features/environment/candidate
  → separate build lineage;

unknown cache identity
  → rebuild.
```

Target coordination:

```text
one Cargo producer per target root unless exact tool evidence proves safe concurrency;
worktree/build-class roots follow I2.22;
verification and interactive diagnostics pre-empt background coverage/mutation/indexing;
failed producer wakes waiters with the same evidence;
no silent retry storm;
cancellation preserves raw evidence and quarantines incomplete artifacts;
disk cleanup is lineage- and lease-aware.
```

Test coordination:

```text
nextest inventory is discovered once per exact candidate/profile;
selected tests are partitioned/sharded by stable identity;
resource/serial groups prevent shared-port/DB/profile collision;
all shards contribute to one TestSelectionReceipt;
missing shard, zero-test shard or parser failure prevents aggregate PASS;
retries preserve first failure and retry policy.
```

Build performance is observed, not assumed:

```text
cargo --timings feeds CrateBuildProfile;
private/public change costs are tracked separately;
proc-macro/build-script and link bottlenecks are attributed;
target lock wait and peak memory affect WIP admission;
crate count alone does not trigger a full build or refactor.
```

Local interactive builds use per-worktree incremental state. Shared/CI/swarm reuse is measured separately with non-incremental compilation plus an admitted compiler-cache bridge; incrementally compiled crates are not assumed cacheable. Nextest build archives may be produced once and reused by bounded partitions only under the exact candidate/toolchain/profile/environment identity.

Optional compiler cache is admitted only behind exact fingerprint and supply-chain policy. Cache is a performance aid, never proof. This coordinator remains an InstrumentRunner capability; Durable Jobs, Ready Queue, budgets and task priority remain owned by Governor/Agent Coordinator.

