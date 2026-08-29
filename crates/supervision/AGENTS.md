# Supervision source instructions

This subtree owns deterministic supervision mechanics and typed Watchdog
observations. It does not own canonical task/memory truth, semantic diagnosis,
repair policy, general process control, or finish. Issue #16 is the owner; #13
binds cells/proofs and #11 supplies live coverage evidence.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Hard boundaries

- Keep observation/decision logic deterministic, typed and free of durable
  semantic state.
- Watchdog durable state is limited to bounded non-semantic spool envelopes,
  cursors, gaps, leases and integrity anchors with one writer.
- Every coverage claim states the observable interval/lease/cursor denominator.
  Missing sensors, spool pressure or expired supervision is `PARTIAL/UNKNOWN`
  and lowers the applicable governance guarantee.
- A model or heuristic may propose an explanation; it cannot authorize a
  blocker, canonical Incident transition, containment or repair.
- Containment is an exact pre-authorized action bound to installation/process
  generation, ownership challenge, epoch/fence, policy and outcome evidence.
  PID/name/path/port alone are never sufficient.
- Canonical Signal/Problem/Incident observations enter only through the normal
  Governor transition path. No direct canonical-store credentials or writes.
- Watchdog remains an independently supervised SCM sibling during declared
  intervals; Host/Kernel loss must not be reinterpreted as continuous coverage.
- Restart-budget exhaustion quarantines/escalates rather than looping.

## Proof and stop condition

Changes require deterministic duplicate/reorder/gap/pressure tests and the
actual sensor/spool/SCM/containment edge they affect. Coverage, process identity,
service lifecycle or reconciliation changes require the applicable #11 failure
scenario and independent readback.

Stop when requested behavior needs project semantics, generic repair recipes,
canonical writes, model authority, or broader process control than the exact
containment contract.
