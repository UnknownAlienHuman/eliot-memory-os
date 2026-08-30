# Development workflow

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` for the complete branch delta, including deletions. The command
runs the canonical router, verifies every required item against its routed
SHA-256 and byte count, and renders the bounded content. Read the generated
bundle before mutation; a route listing by itself does not satisfy this gate.

Record the read receipt ID, bundle SHA-256, matched routes, required handles, and
an explicit reading attestation in the pull request. Optional fragments are
loaded only when the current decision crosses their boundary. If no route
matches, an item is stale, or scope expands, stop and rerun or repair the route.
See [`docs/architecture/READING_PROTOCOL.md`](docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## One authority surface

`main` is the current product source and documentation authority. Issues define
work; branches and worktrees execute it; pull requests integrate it. Reports,
audits, research dumps, local state, and generated evidence are not parallel
sources of truth.

Canonical navigation:

- Architecture authority: `docs/ARCHITECTURE_CONTRACT.md`;
- exact pair identity: `docs/normative-pair.toml`;
- product/source map: `docs/PROJECT_MAP.md`;
- documentation map: `docs/README.md`;
- active programmes: `workstreams/ACTIVE.toml`;
- repository agent rules: `AGENTS.md`.

## Work lifecycle

```text
open issue with owner, causal property, scope, proof, and non-goals
→ fetch/prune and fast-forward main only
→ create a fresh issue-numbered branch from exact origin/main
→ claim one mutable path scope
→ route, verify, and read the bounded documentation bundle
→ implement and run Module/Edge/Product proof as applicable
→ open PR to main with read receipt and attestation
→ integrate by squash after current-main and proof checks
→ close issue and retire the branch
```

Normal branch form:

```text
<kind>/<issue-number>-<short-slug>
```

Allowed kinds: `work`, `fix`, `docs`, `chore`, `refactor`, `test`.
Provider-generated names, random adjective names, personal namespaces, and dated
campaign branches are not accepted for new work.

## Branch validity

A standard issue-numbered branch is valid only when:

1. the branch issue is open and describes the current causal change;
2. the branch was created from current `origin/main`;
3. current `origin/main` remains an ancestor before further mutation and merge;
4. its PR is open when one exists;
5. the declared mutable path scope has no other writer.

`workstreams/ACTIVE.toml` lists programmes, shared routing inputs, and any rare
explicit exception. It intentionally does not duplicate every ephemeral issue
branch; the issue and PR own that current state. There are no active long-lived
or nonstandard implementation branches.

Do not repair a superseded branch in place. Start a fresh branch and carry only
the reviewed change. A merged, closed, abandoned, or superseded branch is
retired. Branch content never outranks `main`, even when it contains newer dates
or more prose.

## Worktrees and writers

Use one worktree per mutating branch. Record the primary path scope in the issue
or PR. Two agents may read the same files, but they do not mutate the same scope
concurrently. Contract changes land before dependent implementation waves, and
the integration owner revalidates consumers after the contract change.

## Documentation and evidence placement

Keep in Git:

- current canonical Architecture and Implementation;
- stable operator/developer documentation;
- ADRs for accepted load-bearing decisions;
- generated projections only when an active consumer and regeneration check
  exist;
- bounded reusable workstream briefs and routing metadata.

Do not keep in the active tree:

- historical audits, recovery programmes, progress logs, or one-off reports;
- donor research packages or reverse-engineering dumps;
- copies of documentation owned by Eliot Search or Eliot Research;
- swarm conversations/results;
- local databases, code-graph snapshots, runtime state, or credentials;
- generated documentation bundles or read receipts.

Investigation findings belong in the owning issue/PR. Large generated evidence
belongs in CI artifacts or an external content-addressed store. Retired content
remains recoverable from Git history; it is not copied into an `archive/`
directory that agents may mistake for current authority.

## Integration and proof

A PR states:

- owning issue/workstream;
- exact base and candidate revisions;
- changed causal property and path scope;
- documentation route/read receipt, bundle hash, handles, and agent attestation;
- proof executed and proof ceiling;
- affected edges and Product Pulse, or why they are not applicable;
- migration/rollback/removal consequences;
- residual unknowns.

Ordinary PR CI checks current source shape and compilation. The expensive full
workspace test/Clippy/build gate is a separately invoked source-candidate or
release operation, not a tax on every local change. A green check is not product
acceptance: source, build, runtime, store, and Product Proof remain separate
evidence dimensions.
