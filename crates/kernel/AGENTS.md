# Kernel and Host source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` for the complete branch delta, including deletions. Open the
verified bundle and read every required item before mutation. A route alone is
navigation, not reading evidence.

Record the route receipt ID, read receipt ID, matched routes, required handles,
fragment paths and SHA-256 values, verified bundle SHA-256, and explicit reading
attestation in the work unit or pull request. Optional fragments are loaded only
when the current decision crosses their stated boundary. A legacy `ELIOT_*`
compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale or missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

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
  `eliot-platform-windows` and the shared contract/integration issue #100;
- generated cell/owner/proof identity: #13;
- installed/live process proof: #11.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

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
put duplicate process mechanics into Host/Kernel state-machine crates. Split
only at a causal state/effect/dependency and independent proof seam.

## Proof and stop condition

Minimum proof is the owning cell's deterministic Module Proof plus the affected
real Windows/process/protocol edge. Changes to activation, fencing, ORS,
Control Reserve, generation cutover, journal or child lifecycle also require the
applicable #11 crash/restart/no-orphan/readback pulse.

Stop when a request requires task semantics, canonical-store interpretation,
model/provider behavior, direct user credential use, or a second owner for
state already declared above.
