# Active workstreams

This directory is the only checked-in registry of current implementation work.
It does not replace GitHub issues or the canonical Architecture/Implementation
pair.

Rules:

- `main` is the sole authority branch.
- A new implementation branch is created fresh from current `main` for one
  issue; it is not pre-created here.
- `ACTIVE.toml` lists active workstreams and any exceptional retained branch.
- A branch not listed as mutable is not a place to continue work.
- Investigation results live in issues/PRs; only bounded reusable briefs and
  routing metadata live here.

## Current work

### Core and daemons

Issues #13–#24 cover Host, Kernel, `eliotd`, Watchdog, Doctor, storage,
testd, WASM/native contours, User Broker, and Researcher provider execution.
Use [`core-daemons/AGENTS.md`](core-daemons/AGENTS.md). Dreamer is excluded.
Each issue receives a new issue-numbered branch from current `main` when an
agent actually starts it.

### Cognitive micro-modules

PR #26 preserves the current candidate on the legacy branch
`cognitive-micromodules-wave-01`. The branch is retained, but it is stale after
the documentation/main cutover and is not mutable until refreshed from current
`main`. No other legacy cognitive/Dreamer branch is active.
