# Storage source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Every implementation Issue lists what to read in a `## Read` section: handle
selectors (`I5.19`, `I1.1..I1.8`, `A4.*`, `APPENDIX-L`) and repository files,
one per list item. Draft it with `python scripts/docs_router.py route --path
<repository/path> --format issue` and keep only what the change needs.

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

With `--issue`, the required reading is the Decision Safety Floor, the items the
Issue declares and the nearest `AGENTS.md` files; path routes become optional
pointers. Without an Issue, use `--path <repository/path> --topic "<causal
property>"` for every mutable path family, or `--changed-from origin/main` for
the complete branch delta. Open the verified bundle and read every required
item before mutation. A route alone is navigation, not reading evidence.

Record the route receipt ID, read receipt ID, declared reading or matched
routes, required handles, fragment paths and SHA-256 values, verified bundle
SHA-256, and explicit reading attestation in the work unit or pull request.
Optional fragments are loaded only when the current decision crosses their
stated boundary. A legacy `ELIOT_*` compatibility map is never an acceptable
read receipt.

If the Issue has no `## Read` section, a declared item does not resolve, no
non-baseline route matches a path read without an Issue, a required item is
stale or missing, or scope expands beyond the receipt, stop and repair the Issue
or the route; silence is not permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

This subtree owns the closed canonical storage contract, provider adapters,
BlobStore mechanics, export/backup and migration behavior. It executes the sole
canonical write path but does not own semantic admission, task/finish meaning,
authority epochs, process adoption, or provider/model policy. Issue #19 is the
integration owner; arbitrary JSON byte preservation is #10.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Hard boundaries

- Public callers use store-neutral typed contracts and closed named operations.
  No raw SurrealQL, generic query/upsert, caller-defined mutation command or
  adapter-side semantic defaulting.
- SurrealDB SDK and credentials remain confined to the admitted Surreal adapter
  and bridge contour. Never leak vendor types into public ELIOT contracts.
- The bridge executes the exact admitted `PreparedTransition`/MutationPlan
  identity. It cannot rebuild, widen, normalize or retry a different operation.
- The external Surreal process owns DB files under one Host-managed immutable
  generation. The bridge does not infer/adopt/kill a server by PID, name, path
  or port.
- Unknown transaction outcome remains operational reconciliation state until
  exact receipt/outbox/readback resolution. No blind retry.
- Blob durability proves bytes only. Semantic references still require the
  canonical transition path. One active owner writes a blob root, and
  deduplication never crosses privacy/retention/erasure domains by digest alone.
- Backup/restore/migration must not revive purged payload, revoked influence,
  stale sessions/epochs or old credentials. Live DB file copying is not a
  supported backup contract.
- In-memory providers are test/reference contours, not proof of the real
  Surreal/Blob edge.

## Change discipline

A schema/provider convenience is not permission to add semantic ownership.
Keep exact-byte authority representation versioned and digest-bound; queryable
objects are projections. Any new named operation declares allowed transition
class, scopes, parameter schema and maximum epistemic/control effect.

## Proof and stop condition

Minimum proof is provider-independent contract tests plus the affected real
Surreal or Blob edge. Transaction changes cover crash before/after commit,
idempotency, duplicate, unknown response and exact receipt reconciliation.
Root/generation changes require exclusive-root and #11 restart/readback proof.
Payload changes run the complete #10 top-level/nested/array/export matrix.

Stop when a request needs semantic policy, task/finish interpretation, Kernel
fencing ownership, Host process adoption, or a second mutable root owner.
