# Instrument source instructions

This subtree owns typed build/test/process instrumentation and evidence
normalization. It does not own durable tasks, scheduling, budgets, acceptance,
finish, canonical writes, or agent/model policy. Issue #20 owns `eliot-testd`;
#13 binds cells/proofs and #11 owns the operational Product Pulse.

## Hard boundaries

- Execute only registered typed Instrument profiles bound to exact source,
  artifact, environment, WorkScope/State Fence and admitted effect ceiling.
- Shared process execution owns spawn, streams, Job Object lineage, timeout,
  cancellation, descendant cleanup and unknown-outcome reconciliation. Do not
  grow private `Command` wrappers in each adapter.
- Preserve material stdout/stderr/raw artifacts or an immutable
  Blob/OmittedPayload handle before parsing/reduction.
- Keep execution, parsing, evaluation, artifact binding, independence and
  coverage as separate evidence dimensions. Exit code zero is not canonical
  truth or task completion.
- `NOT_EXECUTED`, `SIMULATED`, `EXECUTED` and `UNKNOWN_OUTCOME` remain distinct.
- Caches are optional, exact BuildFingerprint/environment keyed and rebuildable.
  They never reuse a prior verifier verdict or make a stale artifact current.
- Sandboxes/worktrees/temp roots are owned, bounded and cleaned. No path escape,
  ambient credential inheritance or shared production state.
- Instrument pools must not consume Kernel Control Reserve or silently starve
  interactive verification.

## Proof and stop condition

A change requires a fake-executor Module Proof and the real compiler/test/process
edge when mechanics can differ. Cover pipe pressure, timeout, cancellation,
crash, descendant leak, cleanup failure, cache mismatch/corruption and raw-output
omission. Acceptance/finish changes are out of scope and require Governor work.

Stop when requested code would create a task scheduler, canonical writer,
verifier authority, generic shell profile, provider policy or hidden ambient
process capability.
