# Kernel and Host source instructions

This subtree implements failure-surviving machine/runtime mechanics. It does
not own project semantics, task meaning, memory truth, provider policy, model
behavior, or finish.

## Owners

- installation transaction and approved artifact projection: installer/Host;
- `HostStateJournal`, Host activation and managed dependency lineage: Host,
  issue #14;
- Authority Epochs, fencing, ORS, Control Reserve, Generation Registry and
  active process/session/broker bindings: Kernel, issue #15;
- Windows process, Job Object, service and protected-path mechanics:
  `eliot-platform-windows` and declared IPC/process contracts;
- generated cell/owner/proof identity: #13;
- installed/live process proof: #11.

## Hard boundaries

- ORS stores opaque operational envelopes, checkpoints, locators, ordering and
  reconciliation state. It must not answer semantic task/memory/project queries.
- Kernel validates immutable identity, principal, epoch/fence, ordering,
  transition/effect class, operation manifest and generation compatibility. It
  does not reinterpret policy, WorkScope, task, plan, verifier or finish.
- Host may install, start, stop, fence, restart and restore an admitted
  generation. It does not perform canonical writes or semantic recovery.
- No SurrealDB SDK/credentials, model/Dreamer/Researcher dependency, MCP/UI
  meaning, legacy `eliot-app` ownership, or generic shell execution.
- Process ownership requires immutable artifact/config/protocol identity,
  installation/generation lineage and OS evidence. PID/name/path/port alone are
  insufficient.
- Every mutable state has exactly one writer. A cache or read model is
  revision/fence keyed, rebuildable and cannot create authority/freshness.
- Unknown commit/effect remains reconciling; never retry blindly.

## Change discipline

Do not put semantic shortcuts into Kernel to make `eliotd` loss easier. Do not
put process mechanics into Host/Kernel state-machine crates to avoid using the
platform/process owner. Split code only at a causal state/effect/dependency and
independent proof seam, not by file length.

## Proof and stop condition

Minimum proof is the owning cell's deterministic Module Proof plus the affected
real Windows/process/protocol edge. Changes to activation, fencing, ORS,
Control Reserve, generation cutover, journal or child lifecycle also require the
applicable #11 crash/restart/no-orphan/readback pulse.

Stop when a request requires task semantics, canonical-store interpretation,
model/provider behavior, direct user credential use, or a second owner for
state already declared above.
