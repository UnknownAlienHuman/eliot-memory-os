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

All repository-owned workflows use **`workflow_dispatch` only**. They do not run
on pushes, pull requests, schedules, merges, releases, or any other automatic
event. A person starts a workflow explicitly from the Actions UI or an
equivalent authenticated manual dispatch. Ordinary verification is run locally.

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

Manual bounded integration-source check.

Checks the selected checked-out source revision through:

- normative identity and Cargo metadata;
- formatting and workspace all-target check through `scripts/verify.ps1`;
- Eliot.Operator Release build.

Proof ceiling: source/build integration candidate. It does not prove complete
workspace tests, an installed Windows service tree, store recovery, or a Product
Pulse.

### `source-candidate.yml`

Manual, explicit full source-candidate gate.

Runs formatting, workspace all-target check, Clippy, nonzero workspace tests,
workspace all-target build, and Eliot.Operator Release build on one exact source
SHA. The optional live-scenario input intentionally fails until the live Windows
harness exists; it cannot be used to manufacture runtime proof.

Proof ceiling: full source candidate only. Release packaging belongs to
`scripts/` and `docs/release/`; live Windows acceptance belongs to issue #11.

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

The trigger remains `workflow_dispatch` only. Workflow names such as `release`,
`certified`, `production`, or `live` are used only when the workflow owns that
exact decision and executes the required proof. A source check may not be renamed
into a release or Product-Pulse gate.
