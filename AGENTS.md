# Repository agent instructions

## Authority

`main` is the only current source and documentation authority. Never treat an
old branch, worktree, report, audit, generated index, local database, agent
memory, or prior conversation as current repository state.

Read, in order:

1. [`WORKFLOW.md`](WORKFLOW.md);
2. [`workstreams/ACTIVE.toml`](workstreams/ACTIVE.toml);
3. the owning open GitHub issue and current PR, when one exists;
4. the nearest `AGENTS.md` from the repository root down to every mutable path;
5. [`docs/ARCHITECTURE_CONTRACT.md`](docs/ARCHITECTURE_CONTRACT.md), the
   [mandatory documentation route](docs/architecture/AGENT_READING.md), and
   only the applicable canonical Architecture/Implementation sections;
6. the exact source, contracts, tests, and one-hop dependencies for the work.

A deeper `AGENTS.md` narrows the work allowed in that subtree. It cannot expand
authority granted by the root instructions, owning issue, Architecture, or
Implementation. In particular, `crates/eliot-app/AGENTS.md` marks the old
`eliot-governor` surface as a migration/regression facade rather than a current
composition root.

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

## Mandatory documentation route

Before the first mutable edit, route the complete planned changed-path set and
the closest task profile through the accepted normative pair:

```powershell
python scripts/docs_router.py route `
  --task <task-profile> `
  --path <planned-path-1> `
  --path <planned-path-2> `
  --write-receipt .eliot/reading/<issue>.json
```

Read every required source slice returned by the router. Use `--content` or
`materialize`; an index, summary, agent memory, or generated projection is not a
substitute for the source bytes. Record the pair key, reading-map SHA-256,
matched routes, required selectors, and receipt SHA-256 in the issue/PR. The
local receipt is evidence state and is not committed.

Rerun routing before continuing whenever the changed-path set, causal owner,
external effect, or task scope expands. An unmapped path/task is a fail-closed
error. Add an explicit route, or use `--allow-fallback` only as a visible scoped
deviation recorded in the receipt; never silently load or skip arbitrary parts
of the books.

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
- `.eliot/`, `.eliot-docs/`, `.codebase-memory/`, runtime databases, logs,
  reports, build output, credentials, or machine-local agent configuration.

Use issue/PR comments for investigation findings, CI artifacts for generated
reports, and external repositories for Eliot Search or Eliot Research product
documentation. Git history preserves retired material without exposing it as
current authority.

## Verification

Run the smallest proof that can fail on the changed path. Use `just quick` for
bounded documentation/configuration changes and the applicable package/edge
proof for Rust changes. Run broader suites only when the change closure requires
them. Report every skipped, failed, simulated, or unavailable check exactly.
