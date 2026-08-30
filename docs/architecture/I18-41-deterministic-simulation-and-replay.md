## I18.41. Deterministic simulation and replay

ELIOT tests distributed/control semantics through a pure simulation boundary before relying on live timing.

Virtualized inputs:

```text
logical clock and timers;
seeded RNG and ID generator;
message delivery, duplication, reorder, delay and loss;
process/node lifecycle;
store responses, torn/unknown commits and outbox delivery;
provider/tool/model cassettes;
filesystem/network where the chosen simulator supports them;
failpoints at named transition boundaries.
```

The first owner is `eliot-sim-core`, which drives pure command/event/state transitions without Tokio, DB, model SDK or Wasmtime. Framework adapters are admitted by scope:

```text
Loom
  exhaustive small synchronization primitives;

Shuttle
  larger randomized concurrent state spaces; passing is not proof;

Turmoil
  deterministic Tokio network/filesystem/lifecycle scenarios;

MadSim
  optional broad async/distributed simulation after compatibility proof.
```

Each run creates `SimulationSeedArtifact`:

```text
scenario and code/profile digests;
seed and deterministic config;
event schedule/failpoints/cassettes;
terminal state and invariant results;
minimal failure trace and FailureCapsule ref.
```

Minimum scenarios:

```text
stale lease/fencing token;
duplicate command/effect delivery;
effect committed then acknowledgement lost;
writer/scheduler/Kernel restart;
unknown store outcome;
cancellation vs completion race;
promotion/cutover/rollback race;
mailbox overload and load shedding;
old generation output after epoch change;
Watchdog/testd loss during a run.
```

A simulation PASS proves only the modeled contracts. At least one real-edge/live fault test remains required for Integration/Product/Release proof.

