# Active workstreams

This directory routes current implementation programmes. It does not replace
GitHub issues, pull requests, or the canonical Architecture/Implementation pair.

## Rules

- `main` is the sole source and documentation authority.
- Each implementation unit uses a fresh issue-numbered branch from current
  `main` and one PR back to `main`.
- The owning issue/PR is the live record for that branch.
- `ACTIVE.toml` lists programmes and their reusable routing inputs; it does not
  create shared implementation branches.
- A nonstandard branch requires an explicit temporary exception. There are no
  active exceptions now.
- Investigation findings remain in issues/PRs or CI artifacts. Only reusable
  contracts, manifests, inventories, and bounded work briefs remain in Git.

## Current programmes

### Core and daemons

Issues #13–#24 cover Host, Kernel, `eliotd`, Watchdog, Doctor, storage,
testd, WASM/native contours, User Broker, and Researcher provider execution.
Use [`core-daemons/AGENTS.md`](core-daemons/AGENTS.md). Dreamer is excluded.

### Cognitive micro-modules

The validated candidate scaffold is now on `main` under `crates/smart/` plus
its declared Governor/Meta in-place assignment manifests. Issues #38–#45 own
the current contract, donor-migration, integration, and self-learning gaps.

The wave, edge, donor, decision, and per-cell `module.toml` files are planning
and assignment metadata. They do not admit a package to the root workspace,
implement Rust behavior, activate a runtime generation, or establish support.
Each cell is implemented and proved through its own issue-numbered branch and
PR; no shared cognitive implementation branch exists.
