# `eliot-contracts` package instructions

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
permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## Durable package boundary

`eliot-contracts` is the dependency-light, stateless C0 island for ELIOT-owned,
owner-neutral contract primitives: shared identifiers, counters, revisions,
fences, receipt metadata, digest/time values, and other policy-free values.
Package membership does not grant lifecycle, authority, storage, or runtime
ownership. Keep the hard dependency direction one-way from contracts to domain
and ports; do not expose vendor, process, runtime, storage, provider, or UI
types.

One issue and pull request introduces or migrates one primitive family and its
exact compatibility contour. Select the actual semantic owner before editing.
Reuse an existing owner and never create a third same-meaning type, package,
wrapper, or string facade. Every public primitive has an explicit namespace and
non-interchangeability rule; identical spelling does not establish equality.

## Contract and migration rules

Before Rust mutation, record the causal property, owner, affected fields and
schemas, direct and reverse consumers, dependency/lockfile decision, old
failure or representation gap, negative cases, migration/removal path, rollback
boundary, and proportional independent proof. Validation, serde, schema,
versioning, compatibility, and reverse-consumer proof must match the future
impact of the family. A contract or package test cannot claim consumer,
runtime, store, or Product conformance by itself.

Compatibility is explicit and loss-visible. Reject ambiguous or stale input at
the boundary, preserve provenance where legacy input is evidence, and never
use an implicit `From<String>`, default/genesis upgrade, lossy scalar
conversion, or infallible adapter to manufacture authority or equality.
Foundation values own no runtime, process, provider, policy, admission,
completion, effect, store, or lifecycle behavior.

## Authority, scope, and routing

Root `AGENTS.md`, `WORKFLOW.md`, the current open issue/PR, Architecture and
Implementation authority, and the routed documentation receipt determine the
current task. These package instructions provide durable boundaries; an open
issue may narrow the exact path and proof but cannot widen higher-level
authority. One mutable path has one writer. Workers do not perform
uncoordinated fetch, pull, push, ref, workflow, or integration mutations.

Before any material source or contract change, verify the published authority
receipt, clean issue worktree/base, nearest instructions, current issue path
claim, and one-writer ownership. Run the canonical documentation reader from
the repository root and read every required fragment in the emitted bundle:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Record the route/read receipt, matched routes, handles, hashes, and attestation
in the work unit or pull request. Re-route when path, causal property,
authority boundary, or evidence scope expands. A missing route, stale required
item, unresolved owner, duplicate identity, dependency inversion, scope drift,
or unattainable proof is a STOP condition; preserve the unknown and escalate
through the issue owner, integration owner, or Contract Challenge rather than
weakening the oracle.

## Historical contract context

Issue #289 and its epoch-identity contract are historical context, not the
active work unit. Preserve its accepted no-third-type and explicit migration
rules. When the epoch family is touched, read the exact
`crates/foundation/eliot-contracts/epoch-id.contract.toml` input and route the
applicable Architecture/Implementation fragments. Do not infer that a later
issue inherits #289's scope, owner, proof ceiling, or prohibitions.

## Verification

Documentation-only policy edits do not authorize Rust, Cargo, schema, runtime,
store, or Product-semantic changes. `docs_router.py route` alone is navigation,
not reading evidence. After a docs-only policy edit, run the routed post-read
checks, `just quick`, and `git diff --check`; report baseline, unrelated,
skipped, failed, or unavailable checks honestly. Future Rust changes use exact
issue-owned package and consumer gates proportional to causal closure; this
file hard-codes no primitive family or implementation gate.
