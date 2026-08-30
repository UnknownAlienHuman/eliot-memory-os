## I14.19. WASM components

WASM Component Model is the **default first contour** for pure, bounded, portable experimental logic. Every new Prototype follows the `PrototypeContourDecision` contract in I0.12; choosing an isolated native process requires an explicit capability/isolation reason, and a static native bundle is never the first contour for new experimental behavior. WASM is not a universal plugin mechanism and does not replace native process isolation for OS-heavy work.

Guest linear-memory and capability isolation do not prove Windows host isolation, build-time safety, filesystem/network confinement, credential safety, supply-chain integrity or cleanup of native helpers. The component build and host-call implementations remain separate admitted boundaries; claims beyond the measured Wasmtime/WIT property use the native sandbox/VM profile or stay explicitly unproven.

### Baseline

```text
runtime: pinned Wasmtime generation behind `eliot-wasm-host`;
production guest target: `wasm32-wasip2`;
interface: ELIOT-owned versioned WIT worlds;
WASI 0.3 / `wasm32-wasip3`: laboratory profile until exact Windows toolchain,
component, streaming/async and migration conformance passes.
```

The chosen target is recorded in the GenerationManifest. `wasm32-unknown-unknown` may be used for a completely self-contained library experiment, but it is not the standard capability-oriented component target.

### Admissible component classes

```text
policy/routing/scoring functions;
validators and schema transformations;
deterministic workflow nodes;
context/ranking transforms;
retry/error classifiers;
pure planner/reviewer support logic.
```

Not admitted as ordinary WASM components:

```text
Cargo/rustc/Git/LSP/browser/debugger processes;
canonical storage;
credential-bearing provider adapters;
unbounded async I/O;
code that requires raw shell/filesystem/network;
logic whose primary state cannot be externalized or migrated.
```

### WIT capability boundary

A world imports only named capabilities. Absence of filesystem, network, process, secrets or clock imports means that the guest cannot request those effects through the supported host surface. Host calls remain proposals or bounded data operations; they do not bypass Governor authority.

Every manifest declares:

```text
component/interface/artifact digests;
allowed imports/exports and capability grants;
state class and migration contract;
memory/table/instance/stack limits;
wall deadline, epoch/fuel policy and cancellation;
max host calls, input/output bytes and artifact access;
privacy/source policy;
shadow/canary comparator and rollback generation.
```

Wasmtime Store limits are enforced per invocation/generation. Epoch interruption is the default wall/cancellation mechanism for longer code; fuel may additionally bound deterministic CPU work. Pooling and AOT/precompiled artifacts are performance Defaults only after exact-engine compatibility and memory/latency measurements.

### Core, guest and native equivalence

The semantic core lives outside Wasmtime and has no runtime dependency. The WASM guest and native process adapters invoke the same core or satisfy the same conformance corpus. Differential tests compare:

```text
result and error class;
proposed commands/effects;
state delta;
resource/host-call envelope;
determinism under the same seed and input.
```

A backend-specific divergence is either a documented contract revision or a promotion failure.

### Generation and activation

A component is immutable after publication. Normal lifecycle:

```text
DRAFT
→ BUILT
→ CONFORMANCE_PASSED
→ REPLAY_PASSED
→ SHADOW
→ CANARY
→ ACTIVE
→ DRAINING
→ RETIRED | REJECTED | ROLLED_BACK.
```

These labels are a projection of the canonical ModuleGeneration/GenerationCutover machines; they do not create another mutable owner.

Shadow execution uses isolated state, cannot perform external effects and cannot influence scheduler decisions. The comparator records exact, semantic, invariant, effect-proposal, latency, memory, host-call and nondeterminism divergence. Canary thresholds are empirical per component class, never copied as universal constants.

### State migration and rollback

Preferred state ownership:

```text
host owns versioned snapshot;
component receives snapshot/input;
component returns delta/proposal;
host validates and commits under normal authority.
```

A stateful component must export/import a versioned state through an explicit migration contract. Migration is independently tested, reversible or backup-protected, and is not combined with unrelated behavioral change when that would destroy diagnosis.

Rollback is a routing operation:

```text
new requests → prior compatible generation;
candidate stops admission;
in-flight work drains/cancels according to exact disposition;
already authorized effects follow their operation permits;
state uses the prior compatible snapshot or a forward repair.
```

Old epochs are never reactivated.

### Native/static promotion

A WASM component is promoted to isolated native process only when measurement shows a material benefit and the native backend passes the same contract, differential, fault, shadow and rollback proofs. Static integration into `eliotd`/Kernel additionally requires a stable interface, trusted supply chain, hot-path profiling and normal binary release/rollback.

Promotion to native is not a required maturity stage. A policy, validator, routing or transformation component may remain an active WASM generation indefinitely when its measured overhead is immaterial and the capability-isolation/replacement value is higher.

Direct in-process `.dll`/`.so` hot unloading is not an admitted middle step. A C ABI or `abi_stable` can stabilize representation but does not isolate panics, UB, allocator ownership, callbacks, threads or unload lifecycle.

