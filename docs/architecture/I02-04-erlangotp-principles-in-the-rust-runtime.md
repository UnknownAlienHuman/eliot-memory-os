## I2.4. Erlang/OTP principles in the Rust runtime

ELIOT adopts operational principles, not BEAM syntax:

```text
small state owners;
message passing instead of shared mutable cross-Module state;
supervision tree;
crash containment;
bounded restart intensity;
explicit child classes;
immutable release generations;
state migration before cutover;
observable recovery outcome.
```

### Supervision strategies

Two orthogonal fields use the same canonical vocabulary as I14.10:

| Field | Values | Use |
|---|---|---|
| group strategy | `one_for_one` | restart only the independent failed child; DEFAULT |
| group strategy | `rest_for_one` | restart failed child and explicitly declared downstream dependents |
| group strategy | `one_for_all` | rare; only for a small inseparable supervision group |
| child class | `temporary` | do not restart automatically after completion or failure |
| child class | `transient` | restart only after abnormal exit |
| child class | `permanent` | restart after any non-retirement exit within policy |

The strategy is declared in the Module or Service manifest. Supervisor does not infer it from process name.

### Restart intensity

Every supervisor branch has:

```text
attempt budget;
rolling observation window;
exponential/jittered backoff;
last-known-good generation;
quarantine condition;
escalation target;
Problem State and receipts.
```

Repeated failure does not create an endless restart loop. After budget exhaustion, the branch is quarantined or escalation moves one level higher.

### Rust boundary

Rust provides no safe general replacement of arbitrary machine code inside a live process while preserving state, as BEAM does. Therefore:

```text
source crate
  built and tested independently;

in-process service
  replaced by restarting the current disposable service or by a new `eliotd` generation;

process Module
  replaced by an individual side-by-side process generation;

Kernel/Host
  replaced by an external-supervisor cutover.
```

Rust `cdylib` unloading and arbitrary in-process code injection are not production plugin mechanisms.

### Actor implementation

ELIOT-owned supervision semantics remain behind the `eliot-runtime` facade. The DEFAULT is supervised Tokio tasks and typed bounded mailboxes. `ractor` may be used for suitable service trees only after an empirical gate and does not define:

```text
authority;
restart policy;
receipts;
state ownership;
cluster semantics;
canonical task lifecycle.
```

A distributed actor-cluster library is not a production dependency without separate conformance and failure proof.

### Graceful stop

Every supervised task or process passes through:

```text
stop admission
→ cancellation signal
→ stop accepting new work
→ checkpoint/flush/disposition effects
→ bounded wait
→ forced termination if required
→ no-orphan verification
→ receipt.
```

