# Active workstreams

This directory routes current implementation programmes. It does not replace
GitHub issues, pull requests, or the canonical Architecture/Implementation pair.

Rules:

- `main` is the sole authority branch.
- Ordinary work uses a fresh issue-numbered branch from current `main`.
- The owning issue/PR is the live record for that ephemeral branch.
- `ACTIVE.toml` lists programmes and exceptional nonstandard/long-lived
  branches; it does not duplicate every normal issue branch.
- A nonstandard branch absent from the exception registry is read-only
  archaeology.
- Investigation results live in issues/PRs; only bounded reusable briefs and
  routing metadata live here.

## Current programmes

### Core and daemons

Issues #13–#24 cover Host, Kernel, `eliotd`, Watchdog, Doctor, storage,
testd, WASM/native contours, User Broker, and Researcher provider execution.
Use [`core-daemons/AGENTS.md`](core-daemons/AGENTS.md). Dreamer is excluded.
Each issue receives a new issue-numbered branch when an agent actually starts
that work.

### Cognitive micro-modules

PR #26 is the sole active nonstandard branch. Merged PR #31 refreshed
`cognitive-micromodules-wave-01` from current `main`. Mutation is permitted only
inside the exact prototype-manifest/assignment scope declared in
`ACTIVE.toml`; the branch is not a place for unrelated fixes, implementation,
or general Dreamer development. It is retired when PR #26 is merged, closed, or
superseded.
