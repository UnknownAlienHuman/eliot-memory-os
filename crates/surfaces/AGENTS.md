# Surface and user-session source instructions

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

This subtree exposes operator, agent/MCP, notification and interactive-user
boundaries. A surface translates and presents current contracts; it does not
become a task, memory, policy, route, credential, process, canonical-store or
finish owner. Issues #7–#9 own current integration regressions; #77 owns the
host-request/agent-bridge protocol migration; #23 owns User Broker; #13 owns
thin surface cell/proof binding.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Hard boundaries

- CLI/MCP/UI adapters decode, authenticate, validate, call one current owner and
  encode/project typed results. They do not add semantic defaults, retry policy,
  task selection, finish or canonical write shortcuts.
- A displayed ID, successful tool response or UI terminal state is not a
  canonical receipt/readback. Preserve host correlation, Kernel request,
  bridge, attempt and operation identities separately.
- Host requests carry inert operation intent and opaque correlation only. A host
  or bridge never mints principal, Session, task/WorkScope, State Fence,
  Authority Epoch, idempotency/cancellation identity or effect ceiling.
- Attach/discovery returns one exact WorkScope/task binding or typed ambiguity.
  Never silently select a historical/newest/similar task.
- Default output preserves the Decision Safety Floor and uses bounded previews
  plus reversible expansion handles. Truncation cannot hide scope, authority,
  material unknowns, verifier or recovery directives.
- User Broker registration binds installation, SID, interactive session,
  artifact/generation, nonce, process lineage, epoch, lease and expiry. One
  active registration per installation+SID+session.
- Credentials/resources are materialized only in the exact approved child and
  remain absent from argv, ambient environment, logs, model context and
  canonical memory. Revalidate resource identity immediately before use.
- No generic user-session shell or caller-provided arbitrary executable.
- UI/broker lifetime is not canonical task lifetime; loss narrows only the
  dependent route/resource and triggers exact reconciliation.

## Proof and stop condition

Surface changes require malformed/unknown method, reconnect, duplicate, late,
dropped and reordered event tests plus the real host/bridge/UI edge. User Broker
changes require SID/session/epoch challenge, logoff/lease loss, credential
non-disclosure, resource substitution and Job Object cleanup proof.

Stop when requested behavior needs semantic admission, task ownership, process
execution, credential storage, provider routing, canonical storage or finish.
