## I2.6. Error and crash model

```text
library crates
  typed errors through `thiserror`;

process/protocol boundaries
  stable ErrorCode + structured RecoveryDirective;

binaries
  `anyhow` is allowed only after a domain error is converted into operator context;

panic
  an implementation defect, not normal control flow.
```

An error preserves:

```text
operation identity;
module/crate/generation;
State Fence and Authority Epoch;
causal chain;
retryability semantics;
known/unknown effect status;
raw evidence handle.
```

An in-process panic permits local restart only under I2.4 and I14. Otherwise the generation terminates. A process crash is a normal supervision event, but not successful recovery without a verifier.

