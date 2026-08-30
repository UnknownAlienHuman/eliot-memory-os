## I2.19. Layered module cell

Every nontrivial capability has an internal direction:

```text
L0 Contract
  ELIOT-owned types, schemas, errors, invariants;

L1 Core
  pure logic or explicit state machine;

L2 Ports
  narrow traits for storage, clock, process, filesystem, tools, events;

L3 Adapters
  Windows, SurrealDB, Cargo, provider and tool implementations;

L4 Service
  lifecycle, concurrency, retry, health, recovery;

L5 Surface
  MCP, IPC, CLI, UI, EBP translation.
```

These are logical layers. They become separate crates when they create an independent context, test, or dependency seam. For a small capability, L0–L2 may remain in one pure crate, L3 in an adapter crate, and L4–L5 in a composition crate.

Hard rules:

```text
Core does not import Adapter or Surface;
Service depends on Ports;
Adapter does not decide task truth, policy, or finish;
Surface does not bypass Service or Governor admission;
fake-port proof is not represented as real-edge proof;
the public contract is not owned by a vendor library.
```

### Portable component cell

A capability intended for more than one execution contour is organized around one semantic core:

```text
<component>-contract
  ELIOT-owned types/WIT-compatible domain schema;

<component>-core
  deterministic state transition / pure logic;
  no Tokio, Wasmtime, process, DB or provider dependency;

<component>-wasm
  thin WIT adapter and guest packaging;

<component>-native
  thin EBP/native-process adapter;

<component>-conformance
  common fixtures, differential/property tests and generation comparator.
```

The adapter is intentionally boring: decode, validate, call core, encode. It cannot add retries, policy, task state or external effects. If behavior differs between core, WASM and native execution, the generation is not promotable until the difference is explicitly accepted as a contract revision.

A component that has only one justified contour need not create empty adapter crates. The structure is introduced when a second backend, portability proof or independent sandbox boundary is real.

