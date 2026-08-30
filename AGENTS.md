# Repository agent instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` to include the complete branch delta, including deleted paths. The
reader runs the deterministic router, verifies every required file/fragment
against its routed SHA-256 and byte count, and materializes the exact bounded
bundle. Open and read that bundle before mutation.

Running `scripts/docs_router.py route` alone is navigation, not reading evidence.
Record the read receipt ID, bundle SHA-256, matched routes, and an explicit
attestation in the work unit or pull request. Optional fragments are loaded only
when the current decision crosses their stated boundary. A legacy `ELIOT_*`
compatibility map never satisfies the gate.

If no non-baseline route matches, a required item is missing/stale, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`docs/architecture/READING_PROTOCOL.md`](docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## Authority

`main` is the only current source and documentation authority. Never treat an
old branch, worktree, report, audit, generated index, local database, agent
memory, or prior conversation as current repository state.

Read, in order:

1. [`WORKFLOW.md`](WORKFLOW.md);
2. [`workstreams/ACTIVE.toml`](workstreams/ACTIVE.toml);
3. the owning open GitHub issue and current PR, when one exists;
4. the nearest `AGENTS.md` from the repository root down to every mutable path;
5. [`docs/ARCHITECTURE_CONTRACT.md`](docs/ARCHITECTURE_CONTRACT.md) and only the
   applicable canonical Architecture/Implementation sections;
6. the exact source, contracts, tests, and one-hop dependencies for the work.

A deeper `AGENTS.md` narrows the work allowed in that subtree. It cannot expand
authority granted by the root instructions, owning issue, Architecture, or
Implementation. In particular, `crates/eliot-app/AGENTS.md` marks the old
`eliot-governor` surface as a migration/regression facade rather than a current
composition root.

## Mandatory code and Code Graph routing

Before a material source, manifest, test, or build-configuration change, route
the exact path:

```text
python scripts/code_navigation.py route --path <repository/path>
```

Use the returned package, module locator, nearest `AGENTS.md`, logical blocks,
documentation routes, and one-hop dependencies as the minimum discovery scope.
See [`docs/CODE_NAVIGATION.md`](docs/CODE_NAVIGATION.md).

For every nontrivial source change, actively use CodeBase Memory MCP before and
after editing:

- confirm the exact project, source/worktree revision, index generation/status,
  and graph schema;
- query package/symbol ownership, definitions, implementations, references,
  inbound/outbound calls, tests, and reverse impact;
- run `check_index_coverage` for every graph-cited path and before any negative,
  exhaustive, dead-code, or deletion claim;
- after editing, refresh/reindex, run `detect_changes`, repeat the affected graph
  queries and coverage checks, then execute exact source/build/test verifiers;
- record `CodeUnderstandingProof` and `CompletionProof` in the issue or PR.

Code Graph output is derived navigation/impact evidence, not source, semantic,
runtime, or product authority. Stale, partial, ambiguous, skipped, excluded, or
unknown coverage cannot prove absence, non-impact, dead code, safe deletion, or
complete test selection. When CodeBase Memory MCP is unavailable or cannot
cover the exact scope, record that limitation and fall back to exact source,
Cargo metadata, compiler/LSP, and owning verifier evidence; never invent a graph
receipt.

Do not commit `.codebase-memory/` or graph snapshots, let the external MCP write
ELIOT canonical memory/ADRs, create a second always-on watcher for the same
repository root, or introduce a runtime dependency on the external MCP.

## Mandatory preflight

Before reading deeply or changing anything:

```powershell
git fetch origin --prune
git switch main
git pull --ff-only origin main
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
```

The revisions must match and the worktree must be clean. Create a fresh branch
from that exact commit:

```powershell
git switch -c <kind>/<issue>-<short-slug>
```

Allowed kinds: `work`, `fix`, `docs`, `chore`, `refactor`, `test`.

Do not continue in a branch merely because it exists locally or was mentioned
by another agent. A standard issue-numbered branch is mutable only while its
owning issue is open, its current PR is open when one exists, and current
`origin/main` is an ancestor. A nonstandard, shared, or long-lived branch is
mutable only when `workstreams/ACTIVE.toml` names it as an explicit exception.
Otherwise stop, preserve any candidate through its issue/PR, and create a fresh
branch from current `main`.

## Work ownership

- One issue → one bounded causal change → one branch → one PR.
- One mutable path scope has one writer.
- A worker does not merge its own work or modify the oracle to make a patch pass.
- Branches are disposable execution state; accepted work lives in `main`.
- Documentation follows the same issue/branch/PR path as source.
- Core/daemon work follows [`workstreams/core-daemons/AGENTS.md`](workstreams/core-daemons/AGENTS.md).
- Dreamer is not part of the core/daemon workstream.

## GitHub Actions policy

Automatic GitHub Actions runs are disabled by repository policy.

- Every workflow may use only `on: workflow_dispatch`.
- Never create, restore, enable, or retain `push`, `pull_request`,
  `pull_request_target`, `merge_group`, `schedule`, `workflow_run`,
  `repository_dispatch`, `workflow_call`, release, issue, discussion, branch,
  tag, package, page-build, status, watch, or any other automatic trigger.
- Never add a branch-local, PR-only, temporary, audit, export, validation,
  packaging, merge, or release workflow with an automatic trigger.
- Do not change `.github/workflows/**` unless the current user request explicitly
  requires that exact workflow change. Even then, the trigger remains
  `workflow_dispatch` only.
- Run ordinary verification locally. A GitHub-hosted workflow runs only after a
  person starts it manually from the Actions UI or an equivalent explicit
  manual dispatch.

A CI result is never required merely to open or update a PR. Creating an
automatic workflow to obtain proof is a policy violation, not a workaround.

## Repository hygiene

Do not commit:

- research packages, donor dumps, downloaded archives, or copied external
  product documentation;
- dated audit reports, progress diaries, recovery-program transcripts, swarm
  chat/results, or generated certificates;
- `.eliot/`, `.codebase-memory/`, runtime databases, logs, reports, build output,
  credentials, or machine-local agent configuration.

Use issue/PR comments for investigation findings, CI artifacts for generated
reports, and external repositories for Eliot Search or Eliot Research product
documentation. Git history preserves retired material without exposing it as
current authority.

## Verification

Run the smallest proof that can fail on the changed path. Documentation and
routing changes must run the shard, router, read-bundle, and code-navigation
self-tests/checks included in `just quick`. Use `just quick` for bounded
documentation/configuration changes and the applicable package/edge proof for
Rust changes. Run broader suites only when the change closure requires them.
Report every skipped, failed, simulated, or unavailable check exactly.
