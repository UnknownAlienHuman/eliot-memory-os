# Active workstreams

This directory routes current implementation programmes. It does not replace
GitHub issues, pull requests, or the canonical Architecture/Implementation pair.

Rules:

- `main` is the sole authority branch.
- Ordinary work uses a fresh issue-numbered branch from current `main`.
- The owning issue/PR is the live record for that ephemeral branch.
- `ACTIVE.toml` lists programmes and exceptional nonstandard/long-lived
  branches; it does not duplicate every normal issue branch.
- A nonstandard branch not listed as an exception is read-only archaeology.
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

PR #26 preserves the current candidate on the legacy branch
`cognitive-micromodules-wave-01`. It is the only retained nonstandard branch and
is explicitly non-mutable until refreshed from current `main`. No other legacy
cognitive/Dreamer branch is active.
