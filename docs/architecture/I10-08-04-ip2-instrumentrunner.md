### I10.8.4. IP2 — InstrumentRunner

`InstrumentRunner` performs deterministic orchestration only:

```text
resolve exact InstrumentProfile revision;
resolve and verify executable/component/simulator identities;
resolve WorkScope, candidate, target layout and environment;
submit each external/build/test stage through `TestExecutionPlane` under a durable stage identity;
allow only explicitly pure in-process transforms to bypass testd;
observe/reconcile stage state independently of the requesting transport;
receive testd streaming/parser checkpoints and raw evidence handles;
write one InstrumentRun per stage;
aggregate VerificationProfileRun or DiagnosticBrief input;
submit canonical observations through the ordinary governed write path.
```

One logical InstrumentRunner means one canonical profile/admission/result path, not one global thread, one process or one giant tool-specific struct. `eliot-testd` executes admitted external stages and uses `ProcessExecutor`; InstrumentRunner never recreates tool launch semantics. Profile stages form a bounded DAG:

```text
independent stages may run concurrently;
causally dependent stages remain ordered;
identical build stages use single-flight by exact build fingerprint;
one target root has one build-coordination owner;
no DB transaction, ordering slot or global lock is held while a tool runs;
tool-specific logic remains in profile, parser and executable micro-modules.
```

`BuildExecutionKey` includes workspace, worktree/candidate, toolchain, feature/profile set, environment and build class. An artifact may be reused only under an exact compatible key and evidence receipt. This avoids hundreds of agents launching duplicate or mutually blocking Cargo builds while preserving worktree isolation.

It does not:

```text
invent commands from natural language;
choose architecture or task goal;
run arbitrary shell verifier strings supplied by an agent;
mark a claim verified or task complete;
accept a tool's own freshness/completeness claim without validation;
hide failed/missing stages behind a successful aggregate.
```

The same profile compiler is used by:

```text
local verify/inspect/assist;
agent verifier requests;
external patch candidate verification;
Justfile wrappers;
CI;
FinishService verifier binding.
```

No fifth verification path is permitted.

