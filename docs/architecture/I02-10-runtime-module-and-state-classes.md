## I2.10. Runtime module and state classes

Module manifest declares three orthogonal classifications: execution contour, runtime role and state ownership. None of them is inferred from a crate name.

### `ModuleExecutionContour`

| Contour | Use | Isolation / replacement | Examples |
|---|---|---|---|
| `wasm_component` | Pure or nearly pure experimental logic with a narrow capability surface | Wasmtime Store/instance; immutable component generation | routing/scoring policy, validators, deterministic transforms, context assembly policy |
| `native_process` | OS, Cargo, Git, LSP, browser, native libraries, credentials or long CPU work | separate process/Job Object; versioned protocol; rolling generation | testd, code tools, provider bridges, professional tools |
| `static_native` | Trusted Kernel/control path or a measured stable hot path | new signed binary/process generation; Host/Kernel cutover | authority/fencing core, serialization hot path after proof |
| `development_only` | generators, fuzzers, benchmarks, migration/test utilities | never required by production runtime | simctl, schema/profile generators, fuzz targets |

Rules:

```text
crate boundary ≠ process boundary;
process boundary ≠ Windows service boundary;
WASM/native/static are deployment contours over the same ELIOT-owned contract;
static native is not a default reward for maturity;
in-process Rust dynamic libraries are not an ordinary promotion step;
OS-heavy capability does not gain authority merely by running outside WASM.
```

A component may remain WASM permanently when its latency is negligible relative to model/tool work and isolation is valuable. Native promotion requires profiling and the same conformance corpus. Static integration is the last step and is performed only by a normal release generation; there is no live unload/reload of Rust code inside Kernel or `eliotd`.

### `ModuleRuntimeClass`

| Class | Examples | Default replacement |
|---|---|---|
| `kernel_internal` | fencing/front door | Host-managed Kernel generation |
| `daemon_service` | task/context/job service | service restart or daemon generation |
| `process_bridge` | MCP/LSP/provider/tool bridge | independent process generation |
| `component_host` | Wasmtime or native component pool | host generation + component route cutover |
| `test_execution_plane` | build/test/simulation service | independent testd generation |
| `derived_index` | code graph/cue/search | rebuild/shadow/switch |
| `operational_worker` | crawler/external queue | checkpoint/quiesce/switch |
| `cognitive_service` | Dreamer/model router | job-bound route switch |
| `supervisor_security` | Watchdog sensor | independent service generation |
| `surface` | UI/notifications | independent restart/switch |
| `development_tool` | impact/schema/simulation generator | never required at runtime |

### `ModuleStateClass`

```text
stateless
  no state survives request/process;

host_state_externalized
  state remains in ELIOT-owned snapshot/delta form; generation is replaceable;

rebuildable
  derived state recreates from canonical/external sources;

checkpointed_operational
  non-semantic state resumes from versioned checkpoint/reconciliation;

external_canonical_adapter
  adapter owns no ELIOT semantics; authoritative data lives behind declared surface.
```

No hot-replaceable Module declares `canonical_semantic`. Canonical storage, semantic admission and mechanical fencing remain one path with separated responsibilities.

### `ModuleReplacementClass` and `IterationLane`

Source decomposition and runtime replacement are independent decisions. Every independently planned capability declares one replacement class:

```text
component_generation
  one sandboxed component generation can shadow/canary/cut over independently;

process_generation
  one native process generation can be replaced through I14.14;

daemon_generation
  crates linked into `eliotd` change through a side-by-side daemon generation while Kernel,
  canonical store and independent services remain alive;

host_generation
  Host/Kernel/service-shell change through the external Host/SCM cutover contract;

offline_release
  no safe online cutover exists yet; explicit owner/reason/recovery required.
```

`daemon_generation` is a real online system-replacement boundary even though Rust code is not unloaded inside a process. A regularly edited crate is not forced into WASM or its own process when that would duplicate state ownership, add IPC latency or weaken the public contract.

Its development loop is classified separately:

```text
interactive
  package proof normally returns within the qualified interactive profile;

normal
  independently runnable but not expected on every edit;

slow
  long compile/simulation/integration proof; scheduled as a Durable Job;

manual_release
  proof/replacement requires explicit release or platform boundary.
```

`ProofLatencyProfile` and replacement cost determine scheduling. Unknown or slow proof moves the capability out of automatic interactive scheduling; it does not by itself make the Module incorrect or require an arbitrary split.

### Execution-selection decision

Choose the least privileged contour that can express the capability:

```text
pure + bounded host calls
  → WASM Component candidate;

needs OS/native tool or broad async I/O
  → native process generation;

measured control-path bottleneck with stable contract and complete rollback
  → static native release candidate;

uncertain
  → native process first; do not use in-process dynamic loading as compromise.
```

The decision and rejected alternatives are recorded in the Module Catalog. A later change of contour is a promotion/migration, not an invisible build optimization.

