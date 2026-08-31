# Meta, repair and verification source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from origin/main`
for the complete branch delta, including deletions. Open the verified bundle and
read every required item before mutation. A route alone is navigation, not
reading evidence.

Record the route receipt ID, read receipt ID, required handles/fragments and
hashes, verified bundle SHA-256, and explicit reading attestation. Optional
fragments are loaded only when the current decision crosses their boundary. A
legacy `ELIOT_*` compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale/missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

This subtree owns bounded diagnostic, repair-decision, verification, runtime
status and improvement-assessment mechanics. It does not own canonical task or
memory truth, broad scheduling, policy, provider/model authority, direct store
writes, or self-promotion. Issue #17 owns Doctor; #13 owns cell/proof metadata;
#11 owns live runtime evidence.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Hard boundaries

- Doctor is a short-lived executor of immutable registered recipe revisions.
  Diagnose-only cannot cross into mutation; no generic shell recipe.
- Recipe/attempt identity uses an explicit versioned canonical encoding and
  digest. Never derive durable identity from Rust `Debug`, incidental display
  text, field order or process-local state.
- Process exit or recipe self-report cannot mark repair resolved. Terminal state
  requires the applicable independent verifier and reconciled external outcome.
- Unknown effect/commit remains `UNKNOWN_OUTCOME/RECONCILING`; never retry
  blindly. Budget/cooldown exhaustion quarantines/escalates.
- Verification records execution, parsing, evaluation, artifact binding,
  independence, coverage, fence and freshness separately. A test count or exit
  code is not Product Proof.
- Runtime status is read-only, fail-closed evidence projection. It cannot infer
  installed/current/healthy state from files, ports, PIDs or stale manifests.
- Improvement/learning output remains candidate evidence until the normal
  Governor/Architecture promotion path; Meta cannot change its own oracle,
  policy or support status.
- No canonical-store credentials, task/finish authority, persistent autonomous
  model loop, self-update or self-promotion in Doctor/Meta processes.

## Proof and stop condition

Doctor changes require canonical ID vectors, registered/unregistered recipe
negatives, guarded/diagnose-only/effect cases, crash/unknown outcome,
verifier-stale/unavailable and budget exhaustion. Verification/status changes
require false-positive/false-freshness negatives and the real affected edge;
live support claims require #11.

Stop when requested behavior needs semantic admission, canonical write,
provider/model policy, task scheduling, Architecture authority or a repair
process that owns its own success criteria.
