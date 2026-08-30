## I18.8. Instrument Plane self-tests and fault contracts

### ProcessExecutor

```text
parent-child-grandchild termination;
stdout saturation;
stderr saturation;
both streams saturated;
idle and wall timeout;
cancel/exit race;
helper escape attempt;
Job Object close cleanup;
resource limit and access denial;
exact executable/environment identity;
InstrumentRunner/eliotd death while a tool is active;
reconciliation of process outcome and raw streams after restart;
no blind rerun when effect/output outcome is unknown.
```

### Parsers and normalizers

```text
rustc/Clippy JSON unknown fields and multi-span diagnostics;
Cargo driver error before compiler output;
nextest list/JUnit build, launch, test and timeout failures;
missing/corrupt JUnit;
Windows/Unix/non-ASCII paths;
truncated and non-UTF-8 output;
SCIP unknown records and partial index;
raw evidence retained when normalization fails.
```

### Evidence

```text
stale candidate cannot bind as exact;
partial coverage cannot create negative fact;
contradicted heuristic remains visible but downgraded;
raw handle remains retrievable;
same evidence cannot be rebound to another candidate;
unknown tool/parser version blocks authoritative profile;
profile aggregate cannot hide missing required stage.
```

### Process/module contracts

```text
malformed input;
version mismatch;
deadline and cancel;
quiesce/checkpoint;
stale epoch;
restart/reconcile;
permission/privacy denial;
hot cutover before/after linearization;
unknown external effect;
local degradation without Kernel loss.
```

