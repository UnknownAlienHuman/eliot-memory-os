## I2.3. Workspace topology and dependency direction

### Root core workspace

The first production workspace contains crates required for daily development and normal local runtime. It uses:

```toml
[workspace]
resolver = "3"
members = ["crates/*", "bins/*", "tests/*"]
default-members = [
  # daily core packages and primary binaries only
]
```

`default-members` is not all members. A normal root command must not accidentally build fuzzing, mutation, cloud SDKs, all vendors, and laboratory tools.

### Federated workspaces

A separate Cargo workspace is created not because there are many crates, but when a dependency island exists:

```text
a different toolchain or target;
a WASM, fuzz, Miri, Kani, or nightly-only contour;
a heavy vendor SDK that invalidates the core cache;
an upstream project preserved without rewriting;
an incompatible dependency, MSRV, or license profile;
an experimental distributed, actor, or runtime branch;
an independent release cadence for an optional Module family.
```

Initial repository topology:

```text
/workspace/core         # root production workspace and daily default-members
/workspace/modules      # optional module families when extracted
/workspace/lab          # fuzz, mutation, model experiments, benchmarks
/workspace/tools        # xtask, schema/profile generators, release tools
/upstream               # unchanged external source/bundles where applicable
```

These directories appear physically as their first real consumer appears. One root workspace is allowed until a cache or dependency conflict is demonstrated.

Cross-workspace connection uses:

```text
versioned EBP/protocol schema;
immutable artifact manifest;
a public ELIOT contract crate or generated schema package;
contract digest and compatibility receipt;
```

One lockfile is not an architectural objective. One semantic owner and one causal order matter more than one Cargo workspace.

### Source layers

```text
C0 primitives/contracts
  ids, time, errors, schemas, protocol, module/client SDK;

C1 pure domain cores
  state machines, validation, ranking, reconciliation, policy functions;

C2 application services
  task/read/write/context/coordination services over ports;

C3 adapters/instruments
  SurrealDB, Windows, Cargo, providers, MCP, code tools;

C4 process/surface composition
  binaries, service hosts, CLI, UI, bridges.
```

Dependency direction is outward only:

```text
C4 → C3 → C2 → C1 → C0
```

A dependency on a deeper stable contract is allowed, but not on higher-layer implementation. Cargo graph cycles are prohibited.

### Contract hubs

A crate with large reverse-dependency fan-out is a load-bearing hub. It must:

```text
have minimal dependencies;
contain no vendor or framework types;
change rarely;
separate additive schema change from breaking change;
have a public-contract digest and consumer tests;
not become a dumping ground for common types.
```

Unstable logic belongs near leaf crates, not in `eliot-common` or `eliot-types`.

### Runtime control does not change source ownership

```text
Host starts Kernel;
Kernel starts generations;
Governor schedules Modules;
Watchdog observes processes;
Modules return candidates and events.
```

These runtime arrows do not authorize importing the managed component's internal types. A callback does not transfer ownership to the caller.

### Lessons from Rust microservice systems

ELIOT adopts:

```text
small stable contract crates;
one mutable-state owner per service;
thin binary and composition crates;
explicit health, readiness, and capacity surfaces;
composable timeout/load-shed/rate-limit/observability middleware;
idempotent request/effect identity;
consumer/provider contract tests;
process deployment only at a real failure boundary.
```

ELIOT does not adopt:

```text
a network hop between every source module;
service-per-entity/table;
a separate database for each helper capability;
chatty distributed transactions;
Kubernetes or gRPC as mandatory local baseline;
protocol-generated types as the sole domain model.
```

Tower-like `Service` and `Layer` composition is allowed inside transport and service crates. Tonic-like multi-crate organization is useful as an example of separate contract, codegen, health, and transport packages. But local Windows ELIOT remains process-sparse: most source micro-modularity is statically linked into a few supervised runtime bundles.

