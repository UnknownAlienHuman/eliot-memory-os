# Development workflow

## Authority and current scope

[AGENTS.md](AGENTS.md) owns agent-work rules. The [version boundary](docs/ARCHITECTURE_CONTRACT.md)
identifies the V3 contract owners; the [existing registry](docs/v3/ANALYSIS-REGISTRY.md#documentation-stages)
owns documentation stages. An issue defines the requested change, not another architecture.

Use current `main` as the integration base. PR #5325 is merged; its former writer
exception has ended even while issue #5324 remains open for documentation checks.
New changes use a fresh issue-numbered branch. For an existing open implementation
PR, the root reconciles current `main` into that same writer branch before continuing;
do not create an overlapping PR or overwrite concurrent work.
Retained V2 source and `workstreams/ACTIVE.toml` do not assign V3 implementation.
The source issue defines its scope: #5326 / PR #5327 repairs the Store asset package,
not the later network client or an entire daemon rewrite.

## One bounded change

1. Resolve the owning issue/PR, current base and candidate head. The root performs
   upstream synchronization and records remote, refs, SHA, UTC time and result.
   Workers use that base without fetching/pulling or mutating authority refs.
2. Check `git status --short --branch` and `git rev-parse HEAD` in the assigned
   checkout. Preserve unrelated changes. One manager uses one mutating worktree;
   one file scope has one writer. Read-only reviewers share no write authority.
3. Read the [task route](docs/v3/README.md#task-routes), owning sections and relevant
   source. Use the [bounded task format](docs/v3/DEVELOPMENT.md#one-bounded-task) in the
   existing issue/PR; it records outcome, owner, paths, caller/consumer and checks.
4. Correct the owner document and affected consumers together. Replace duplicated
   policy in indexes with links. Update the existing registry row, not a new log.
5. Inspect the diff and run the smallest applicable checks. Publish the exact
   candidate and limitations for an independent reviewer and integration owner.

For new work, use `<kind>/<issue>-<slug>` with kind `work`, `fix`, `docs`, `chore`,
`refactor` or `test`. Keep one issue/branch/PR per coherent change, not one per
checkbox. Do not reuse merged, closed or superseded branches. Before publication,
re-read the remote head; reconcile concurrent edits instead of overwriting them.
GitHub API writes must use the same branch/scope and an expected-head lease.

## Verification and integration

Use the [V3 check recipes](docs/v3/DEVELOPMENT.md#checks): diff/whitespace, the existing
link-only scan, boundary-specific review and minimum changed-package fmt/Clippy for
source. Each recipe names its proof limit and failure action. The legacy `just quick`
is not the V3 prose default; broad tests follow the assembled product.

Documentation integration is not product acceptance. Clearly marked runtime gaps may
remain open after the documentation merges; they must not keep an otherwise reviewed
and checked documentation baseline indefinitely outside `main`. Contract contradictions,
missing review or a failed applicable merge check still require concrete resolution.

A PR records the owning issue, base/candidate identity, scope, source/read evidence,
actual check results and unresolved items. A source review, compile, runtime exercise
and product qualification are distinct evidence. Do not claim one from another.

The writer/manager cannot approve or merge its own result. Independent review and
required repository checks remain necessary. V3 direct reading does not satisfy or
waive the legacy final-tree evidence verifier. If that verifier cannot represent the
V3 task, record the concrete incompatibility and its owner; do not fabricate receipts,
weaken protection or modify CI within a prose-only task. All workflows remain unchanged.

Follow the [integration procedure](docs/v3/DEVELOPMENT.md#documentation-integration)
for the actual final candidate, PR evidence, review and CI readback. Record a blocker
as head/run + failed step + next owner/action in the existing registry, not merely
"CI pending" after a failed run. Integrate only the reviewed candidate, verify `main`
and the merged PR state, then retire the branch.

## Placement and maintenance

Keep current owner contracts, stable developer/operator guidance, the requested
consolidated audit and its requirement/source map. Keep active decisions and next
steps only in `docs/v3/ANALYSIS-REGISTRY.md`; Git history and issue/PR discussion keep
chronology. The [development guide](docs/v3/DEVELOPMENT.md) maps files, checks and companion
updates, without copying product mechanisms or work status. No new audit framework,
progress journal, donor dump or branch handoff file.

Do not commit credentials, runtime databases, logs, build output, generated read
bundles/receipts, downloaded sources or local agent state. External repositories own
their specifications and roadmaps; retain a pinned observation only where a decision
needs it, with date and evidence limit.

## Retained V2 edits only

The generated block below applies only to explicitly assigned retained V2 edits,
not V3 documents or their entry-point prose. Its reader records donor evidence;
it does not adopt a V3 contract or prove comprehension.

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
permission. See [`docs/architecture/READING_PROTOCOL.md`](docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->
