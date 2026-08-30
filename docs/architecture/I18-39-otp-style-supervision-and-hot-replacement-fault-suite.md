## I18.39. OTP-style supervision and hot-replacement fault suite

Every runtime bundle/module declares child restart class and group strategy from I14.10. The suite verifies behavior, not labels.

### `one_for_one`

```text
crash optional child;
only that child generation restarts;
sibling state/service remain available;
old epoch cannot emit new effects;
restart budget and Problem State update.
```

### `rest_for_one`

```text
crash provider in an ordered branch;
explicit downstream dependents quiesce/restart;
predecessors remain alive;
restart order and State Fence refresh are exact.
```

### `one_for_all`

```text
one tightly coupled child fails;
all declared group members terminate/restart;
no old member remains effect-capable;
strategy is rejected unless independent recovery is unsafe.
```

### Child classes

```text
permanent restarts after any non-retirement exit;
transient restarts after abnormal exit;
temporary never restarts automatically.
```

### Restart-intensity cases

```text
burst within admitted budget recovers;
repeated same failure reaches quarantine/escalation;
all attempts remain in logs/Problem State;
no infinite restart storm;
higher supervisors do not multiply attempts beyond their envelope.
```

### Hot upgrade

```text
candidate starts without effect authority;
old admissions quiesce;
state/checkpoint transformation is versioned;
ORS cutover and new Authority Epoch are durable;
old in-flight operations get one disposition;
rollback is a new forward cutover;
crash before/after linearization reconciles differently and correctly;
no orphan descendants remain.
```

Process-level scenarios run through Host/Kernel/ProcessExecutor. Actor-library unit tests cannot prove OS process recovery.

