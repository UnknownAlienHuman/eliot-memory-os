# Development workflow

## One authority surface

`main` is the current product source and documentation authority. Issues define
work; branches and worktrees execute it; pull requests integrate it. Reports,
audits, research dumps, local state, and generated evidence are not parallel
sources of truth.

Canonical navigation:

- Architecture authority: `docs/ARCHITECTURE_CONTRACT.md`;
- exact pair identity: `docs/normative-pair.toml`;
- product/source map: `docs/PROJECT_MAP.md`;
- active work: `workstreams/ACTIVE.toml`;
- repository agent rules: `AGENTS.md`.

## Work lifecycle

```text
open issue with owner, causal property, scope, proof, and non-goals
→ update main locally with fetch/prune + fast-forward only
→ create a fresh issue-numbered branch from exact origin/main
→ claim one mutable path scope
→ implement and run Module/Edge/Product proof as applicable
→ open PR to main
→ integrate by squash after current-main and proof checks
→ close issue and retire the branch
```

The normal branch form is:

```text
<kind>/<issue-number>-<short-slug>
```

Allowed kinds are `work`, `fix`, `docs`, `chore`, `refactor`, and `test`.
Provider-generated names, random adjective names, personal namespaces, and dated
campaign branches are not accepted for new work.

## Branch rules

1. A branch has one open issue and at most one open PR.
2. A branch is mutable only while listed as mutable in
   `workstreams/ACTIVE.toml`.
3. Current `origin/main` must be an ancestor before mutation and before merge.
4. Do not repair an old branch in place after its work was superseded. Start a
   fresh branch and carry only the reviewed change.
5. A merged, closed, superseded, or abandoned branch is retired immediately.
6. Branch content never outranks `main`, even when it contains newer-looking
   dates or more documentation.
7. A local worktree whose branch is not current and active is read-only until
   discarded or explicitly recovered through a new issue.

The temporary legacy branch for PR #26 is listed separately in the active
registry. It is retained only to preserve that candidate and is not mutable
until refreshed from current `main`.

## Worktrees and writers

Use one worktree per mutating branch. Record the primary path scope in the issue
or PR. Two agents may read the same files, but they do not mutate the same scope
concurrently. Contract changes land before dependent implementation waves, and
the integration owner revalidates all consumers after the contract changes.

## Documentation and evidence placement

Keep in Git:

- current canonical Architecture and Implementation;
- stable operator/developer documentation;
- ADRs for accepted load-bearing decisions;
- generated projections only when an active consumer and regeneration check
  exist;
- active workstream briefs and machine-readable routing.

Do not keep in the active tree:

- historical audits, recovery programmes, progress logs, or one-off reports;
- donor research packages or reverse-engineering dumps;
- copies of documentation owned by Eliot Search or Eliot Research;
- swarm conversations/results;
- local databases, code-graph snapshots, runtime state, or credentials.

Investigation findings belong in the owning issue/PR. Large generated evidence
belongs in CI artifacts or an external content-addressed store. Retired content
remains recoverable from Git history; it is not copied into an `archive/`
directory that agents may mistake for current authority.

## Integration and proof

A PR states:

- owning issue/workstream;
- exact base and candidate revisions;
- changed causal property and path scope;
- proof executed and proof ceiling;
- affected edges and Product Pulse, or why they are not applicable;
- migration/rollback/removal consequences;
- residual unknowns.

A green local test is not product acceptance. Source, build, runtime, store, and
Product Proof remain separate evidence dimensions. Documentation cleanup never
promotes runtime support.
