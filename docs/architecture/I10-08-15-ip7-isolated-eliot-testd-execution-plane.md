### I10.8.15. IP7 — isolated `eliot-testd` execution plane

`InstrumentRunner` remains the canonical profile coordinator in `eliotd`; `eliot-testd` is a replaceable native execution service. This split keeps compilation, proc macros, linkers, large outputs, fuzzers and simulators outside the control plane.

```text
InstrumentRunner
  owns profile resolution, stage graph, durable job relation and evidence aggregation;

eliot-testd
  owns worktree/sandbox provisioning, toolchain/cache access, concrete stage execution,
  streaming parsers, component builds and simulation workers;

ProcessExecutor
  owns Windows process-tree semantics for every launched tool;

Governor
  owns evidence admission, verifier applicability and finish.
```

Minimal service cells:

```text
worktree manager;
build-sandbox manager;
toolchain/executable registry;
dependency/cache manager;
Cargo/nextest runner;
diagnostic normalizers;
test scheduler;
simulation runner;
WASM component builder;
generation publisher client;
artifact/receipt client.
```

`TestdJobRequest` is typed and references an immutable Instrument/Profile revision. It cannot contain a free-form shell string. Tool surfaces exposed through `eliot.verify` remain intents (`crate-fast`, `component-conformance`, `sim-replay`, `trace-inspect`), not dozens of independent MCP authorities.

`eliot-testd` uses dedicated resource pools:

```text
interactive check/test;
verification;
component build;
simulation/concurrency;
fuzz/mutation/coverage/nightly.
```

Load shedding stops background and speculative jobs before control-plane work. Restart reuses only exact BuildFingerprint artifacts and parser checkpoints; unknown tool outcome is reconciled, not blindly rerun.

