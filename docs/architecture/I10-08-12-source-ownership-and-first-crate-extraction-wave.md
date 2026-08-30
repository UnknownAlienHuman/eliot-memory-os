### I10.8.12. Source ownership and first crate extraction wave

The current repository begins with five broad crates, but the target Instrument Plane is crate-first under I2. The migration does not create a parallel product; it extracts existing responsibilities into narrower packages inside the same Cargo workspace.

First extraction ownership:

```text
eliot-types
  → eliot-contracts / eliot-evidence / eliot-receipts;
  → eliot-instrument-api;
  → stable data-only foundation contracts;

eliot-windows-ipc
  → eliot-platform-windows / eliot-process / eliot-ipc;
  → the single platform-specific unsafe/process boundary;

eliot-engine
  → eliot-instrument-runner;
  → eliot-instrument-cargo / nextest / rustc / rustfmt / scip;
  → eliot-code-graph / eliot-code-cortex / eliot-build-test-graph / eliot-test-selection;

eliot-app
  → eliot-cli and thin process composition targets;
  → no verification/process/domain logic.
```

Initial source layout:

```text
crates/foundation/eliot-evidence/
crates/foundation/eliot-receipts/
crates/instrument/eliot-instrument-api/
crates/kernel/eliot-process/
crates/kernel/eliot-platform-windows/
crates/instrument/eliot-process-executor/
crates/instrument/eliot-instrument-runner/
crates/instrument/eliot-instrument-rustc/
crates/instrument/eliot-instrument-nextest/
crates/instrument/eliot-instrument-scip/
crates/instrument/eliot-code-graph/
crates/instrument/eliot-code-cortex/
crates/instrument/eliot-build-test-graph/
crates/surfaces/eliot-cli/
```

Existing `verification.rs`, `patch.rs`, `codecortex.rs`, process helpers and command definitions are migrated into these crates or reduced to compatibility facades during one bounded transition. They do not remain alternative owners.

Migration order:

```text
1. freeze current public behavior and raw evidence fixtures;
2. extract stable contract crates;
3. extract ProcessExecutor boundary;
4. extract InstrumentRunner and parsers;
5. redirect high-level verification, PatchRunner, Justfile and CI;
6. extract code-intelligence backends/compositor;
7. remove old private execution/parsing paths;
8. compare CrateBuildProfile and CrateContextProfile before/after.
```

Acceptance requires:

```text
no duplicate process semantics;
no duplicate verification profile authority;
package-selective tests for every extracted crate;
real-edge tests through ProcessExecutor;
smaller AgentWorkUnitBrief context than the old broad crate;
no regression in product pulse;
old facade can be deleted without losing behavior.
```

The target split is a DEFAULT. Exact package names may change after CURRENT_SYSTEM_AUDIT, but the ownership and context boundaries may not be collapsed back into one Instrument/CLI hotspot without evidence.

