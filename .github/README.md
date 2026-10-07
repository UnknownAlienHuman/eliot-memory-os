# GitHub control plane

GitHub coordinates current work; it is not a second Architecture, state owner,
or evidence store. `main` remains the sole source/documentation authority. The
owning issue describes one causal change, the branch executes it, and the pull
request integrates it.

## Work item surfaces

| Surface | Purpose | Authority / proof ceiling |
|---|---|---|
| `ISSUE_TEMPLATE/work-unit.yml` | Open one bounded work unit with causal property, owner/path scope, contracts, proof, and stop condition | Creates an issue only; no implementation or authority |
| `pull_request_template.md` | Bind candidate/base identity, mutable-state owner, proofs, boundaries, rollback, and residual unknowns | Integration-candidate description only |
| GitHub issue/PR comments | Current investigation evidence, review, challenges, and integration decisions | Evidence for the exact issue/candidate; not canonical product state |

Do not create committed worklogs, audit reports, campaign directories, or
branch-handoff documents to duplicate issue/PR state.

## Workflows

Every repository-owned workflow except `ci.yml` uses `workflow_dispatch` only.
Those workflows do not run on pushes, pull requests, schedules,
merges, releases, or any other automatic event. A person starts one explicitly
from the Actions UI or an equivalent authenticated manual dispatch. Ordinary
verification is run locally.

`ci.yml` is the **sole automatic workflow** (accepted issue #3004): one
automatic, required, Windows compile-only merge check. It runs for every
opened, updated, reopened, or ready pull request targeting `main`, keeps a
manual rerun, and runs diagnostically for every pushed `main` commit. No other
workflow may gain an automatic trigger without its own accepted issue and a
full migration of this policy surface (`AGENTS.md`, `WORKFLOW.md`, the
`ci.yml` exception record, `scripts/verify-github-workflows.py`,
`config/doc-code-conformance.toml`, and the #1225 allocation).

The retained expected enforcement rule for that check is
`config/merge-compile-enforcement.json`. It names the *emitted* check identity
(job `merge-compile`, app `github-actions`, app id `15368`), never the workflow
display name, and `scripts/verify-branch-protection.py` reads live protection
back and compares against it. The comparison is bound in both directions: it
reports `BP-RULE-UNBOUND` when the retained context is no longer emitted by
`.github/workflows/ci.yml`, and `BP-APP-UNBOUND`/`BP-APP-MISMATCH` when the live
requirement is not bound to the declared check app — a bare context can be
satisfied by any app posting that name, which is weaker than the stated
guarantee. The tool only ever reads protection; applying it is a separate
governed repository setting.

### `repository-policy.yml`

Manual repository-routing and authority-surface check.

Checks:

- issue-numbered branch name and open owning issue;
- current `main` ancestry;
- accepted normative-pair and active-workstream records;
- absence of retired research/audit/campaign/local-state surfaces;
- current routing files and required cognitive/core workstream inputs.

Proof ceiling: repository routing and authority-surface integrity only.

### `ci.yml`

Automatic compile-only merge check (the sole automatic workflow).

Checks the exact integration candidate — the checked-out synthetic merge for
pull requests (base SHA, head SHA, merge SHA/tree recorded; branch-head-only
checkout fails), the exact pushed commit for `main` pushes, the selected
ref/SHA for manual reruns — through:

- the closed MergeCompile profile owned by `scripts/verify.ps1`, invoked
  exactly once: the shared source/policy oracle gates, locked Cargo metadata,
  formatting check, workspace all-target check, `cargo test --no-run`
  compilation of every workspace test target with zero execution, bounded
  Clippy over directly changed packages with normal warning semantics,
  compile-only standalone/excluded-package coverage, and locked restore plus
  Release build of both `Eliot.Operator` and `Eliot.Operator.Tests` with zero
  harness execution;
- hash-locked Python verification dependencies
  (`scripts/requirements-verification.txt` with `--require-hashes`).

Before the profile, a preparation step materializes the approved
dependency-policy inputs through their existing owner (the project-local
Surreal provisioner plus locked prefetch of exactly the pinned
dependencies, including standalone workspaces only where an accepted
adjacent lock exists). It records materialization outcomes and never
writes locks, receipts, or verdicts; missing or substituted inputs fail
the offline gate with its own findings.

The same step first materializes the scanner identity the offline gate
depends on. The gate resolves its scanner through `PATH` and then admits
only digest-matched bytes, so a clean runner must provision the exact
version, release-archive digest and executable digest declared in
`config/dependency-policy.toml` `[scanner]`
(`scripts/provision-dependency-scanner.py`) rather than install a latest
`cargo-deny`. The archive digest authenticates the download; the
executable digest is the identity compared against the gate's receipt.
A missing, substituted or digest-mismatched scanner fails the step and
keeps the gate failed — it is never a PASS.

Least privilege: GitHub-hosted Windows runners, `contents: read`, no
repository/environment secrets, `persist-credentials: false`, no
`pull_request_target`, no writes to issues, PRs, releases, repository contents,
or branch refs. Cache holds only rebuildable Cargo registry/git inputs bound
to OS, toolchain, lock/config identity, profile, and event class; fork pull
requests restore without saving into the trusted `main` namespace; every cache
hit still runs every mandatory gate. Cancellation is event-specific: a PR
update cancels only that PR's obsolete run; each pushed `main` SHA keeps a
terminal diagnostic result.

Proof ceiling: compile-only merge candidate (`MERGE_COMPILE_SOURCE_ONLY`). It
does not execute or prove broad unit behavior, lint cleanliness, release
packaging, an installed Windows service tree, store recovery, external
providers, or a Product Pulse. Manual `Review` and source-candidate workflows
retain their stronger executed-test semantics.

### `source-candidate.yml`

Manual, explicit full source-candidate gate.

Runs formatting, locked (`--locked`) workspace all-target check, Clippy, nonzero
workspace tests, and workspace all-target build on one exact source SHA, with
the toolchain identity shown from the pinned `rust-toolchain.toml` (no latest
installer). Restores `Eliot.Operator` and `Eliot.Operator.Tests` in locked mode
against their checked-in `packages.lock.json` files, builds Eliot.Operator
Release, and explicitly executes the `Eliot.Operator.Tests` harness. The
optional live-scenario input intentionally fails until the live Windows harness
exists; it cannot be used to manufacture runtime proof.

Proof ceiling: full source candidate only. Release packaging belongs to
`scripts/` and `docs/release/`; live Windows acceptance belongs to issue #11.

### `integration.yml`

Manual Windows integration run on one admitted SHA/profile (`workflow_dispatch` only).

Proof ceiling: manual structural integration run only.

### `wasm-modules.yml`

Manual affected-component WASM build/test lane (`workflow_dispatch` only).

Proof ceiling: WASM component lane build/test run only.

## Branch and integration rules

Normal branches use:

```text
<work|fix|docs|chore|refactor|test>/<open-issue>-<short-slug>
```

They start from current `origin/main`, contain one mutable path owner, and have
one PR. Closed, merged, superseded, or abandoned branches are retired. A
nonstandard branch is invalid unless `workstreams/ACTIVE.toml` contains a
short-lived explicit exception; there are no current exceptions.

Use squash integration unless the owning issue requires preserved merge
structure. After integration, accepted source lives in `main`; branch names and
PR prose never outrank it.

## Adding or changing GitHub automation

A change requires an owning issue and must state:

- event trigger and permissions;
- exact mutable/read surfaces;
- cache/artifact/secret handling;
- proof ceiling and false-success condition;
- cancellation/concurrency behavior;
- replacement/removal path.

The default trigger remains `workflow_dispatch` only; `pull_request_target`,
schedules, releases, broad branch pushes, and arbitrary dispatch inputs stay
rejected on every workflow. Any further automatic trigger needs its own
accepted owning issue plus a full migration of this policy surface. Workflow
names such as `release`, `certified`, `production`, or `live` are used only
when the workflow owns that exact decision and executes the required proof. A
source check may not be renamed into a release or Product-Pulse gate.
