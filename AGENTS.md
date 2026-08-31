# Repository agent instructions

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


## Authority

`main` is the only current source and documentation authority. Never treat an
old branch, worktree, report, audit, generated index, local database, agent
memory, or prior conversation as current repository state.

Upstream synchronization is root-owned and controller-coordinated. While online
agents are active, the root controller performs the coordinated upstream fetch
approximately hourly, and also at an explicit integration boundary when needed,
then publishes an authority receipt recording:
- remote URL;
- tracked ref (`refs/heads/main` / `origin/main`);
- commit SHA;
- synchronization result / status;
- UTC timestamp.

Managers and workers never execute `git fetch`, `git pull`, or ref-mutating
network operations. They must not switch, fast-forward, or update the
controller/authority checkout or authority branches. Issue worktrees and branches
are provisioned from the published SHA; ordinary issue-branch creation remains
allowed in isolated worktrees. Managers and workers locally verify their base
commit and worktree against the published authority receipt without updating refs.

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

## Mandatory preflight

Before reading deeply or changing anything:

```powershell
git status --short --branch
git rev-parse HEAD
```

Verify that `HEAD` matches the exact base commit SHA from the published authority
receipt and that the worktree is clean. Create a fresh branch from that exact
commit:

```powershell
git switch -c <kind>/<issue>-<short-slug>
```

Allowed kinds: `work`, `fix`, `docs`, `chore`, `refactor`, `test`.

Do not continue in a branch merely because it exists locally or was mentioned
by another agent. A standard issue-numbered branch is mutable only while its
owning issue is open, its current PR is open when one exists, and the verified
base revision remains an ancestor. A nonstandard, shared, or long-lived branch is
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

## Agent operations and audit escalation

- **Antigravity agent operations**: Antigravity runs in a read-only operations
  reporting mode for session status, routing evidence, receipt verification,
  tool execution telemetry, and candidate findings. It has no authority to issue
  leases, mutate canonical truth, apply unverified patches, or invoke
  Antigravity recursively.
- **Mandatory manager-triggered audit**: A manager must immediately trigger a
  bounded audit and escalate to an independent, different verifier upon
  detecting:
  1. *Scope drift*: changes to files outside the declared mutable path scope or
     work beyond the owning issue;
  2. *Forbidden commands*: execution of unauthorized network commands, `git fetch`,
     `git pull`, `git push`, branch resets, or workflow trigger mutations;
  3. *Unsupported claims*: ungrounded assertions of conformance, missing
     verification evidence, or premature completion claims;
  4. *Missing tests*: omitted unit, integration, or edge proofs for modified
     logic;
  5. *Provider/session anomalies*: Governor denials, stale memory projections,
     context corruption, session leaks, or abnormal tool failure loops.
- Work cannot proceed or integrate while an audit escalation remains open.

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
routing changes must run the shard, router, and read-bundle self-tests/checks
included in `just quick`. Use `just quick` for bounded documentation/configuration
changes and the applicable package/edge proof for Rust changes. Run broader
suites only when the change closure requires them. Report every skipped, failed,
simulated, or unavailable check exactly.
