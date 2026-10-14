# Instrument source instructions

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

This subtree owns typed build/test instrumentation and evidence normalization.
It does not own durable tasks, scheduling, budgets, acceptance, finish,
canonical writes, or agent/model policy. Issue #20 owns `eliot-testd`; #100 owns
the shared native-process contract; #13 binds cells/proofs and #11 owns the
operational Product Pulse.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Hard boundaries

- Run only registered typed Instrument profiles bound to exact source,
  artifact, environment, WorkScope/State Fence and admitted effect ceiling.
- Native child lifecycle and evidence collection use the shared contract from
  #100; adapters do not invent private launch or retry semantics.
- Preserve material raw output or an immutable Blob/OmittedPayload handle before
  parsing or reduction.
- Keep execution, parsing, evaluation, artifact binding, independence and
  coverage as separate evidence dimensions. Exit code zero is not canonical
  truth or task completion.
- `NOT_EXECUTED`, `SIMULATED`, `EXECUTED` and `UNKNOWN_OUTCOME` remain distinct.
- Caches and sandboxes are bounded, identity-keyed, rebuildable and isolated
  from production state.
- Instrument evidence enters canonical state only through the Governor path;
  this subtree has no canonical-store authority.

## Proof and stop condition

A change requires a fake-executor Module Proof and the real affected
compiler/test/process edge. Cover timeout, cancellation, crash, cleanup,
cache mismatch and raw-output omission.

Stop when requested code would create a task scheduler, canonical writer,
verifier authority, provider policy or a second authority owner.
