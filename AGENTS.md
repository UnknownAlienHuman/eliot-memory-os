# Repository agent instructions

## Authority

`main` is the only current source and documentation authority. Never treat an
old branch, worktree, report, audit, generated index, local database, agent
memory, or prior conversation as current repository state.

Read, in order:

1. [`WORKFLOW.md`](WORKFLOW.md);
2. [`workstreams/ACTIVE.toml`](workstreams/ACTIVE.toml);
3. the owning open GitHub issue and current PR, when one exists;
4. [`docs/ARCHITECTURE_CONTRACT.md`](docs/ARCHITECTURE_CONTRACT.md) and only the
   applicable canonical Architecture/Implementation sections;
5. the exact source, contracts, tests, and one-hop dependencies for the work.

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

Run the smallest proof that can fail on the changed path. Use `just quick` for
bounded documentation/configuration changes and the applicable package/edge
proof for Rust changes. Run broader suites only when the change closure requires
them. Report every skipped, failed, simulated, or unavailable check exactly.
