# ADR 0005: Isolated clone for sandboxed Codex commits

## Status

Accepted after the first Phase L3 live dogfood run.

## Context

The controller repository is under OneDrive while the disposable Codex write
root is under `LOCALAPPDATA` or `TEMP`. A linked `git worktree` places its index
and lock files under the controller repository's `.git/worktrees` directory.
Codex `workspace-write` correctly denied that out-of-root write, so the live
executor could produce and test a bounded source diff but could not commit it.
Granting the nested process write access to the controller `.git` directory
would violate the Phase L3 OneDrive and bounded-write-root invariants.

The same run also proved that a reviewed `hooks.json` plus
`--dangerously-bypass-hook-trust` does not enable the hooks feature by itself.
The current CLI requires `features.hooks=true` in the effective configuration.

## Decision

`eliot-governor dogfood prepare-worktree` creates a local `--no-hardlinks`
clone at an explicit safe destination. The clone owns its `.git` directory
inside the sandbox root, has no object-database alternates, and removes its
`origin` remote after checking out the exact 40-character base commit on the
requested branch. The command refuses a dirty source repository, a running
dogfood runtime, an existing or unsafe destination, an invalid branch, or a
non-exact commit.

The command also writes the reviewed project-local lifecycle hooks, excludes
that launch-only file through the clone-local `.git/info/exclude`, and emits a
machine-readable launch contract requiring:

- `features.hooks=true`;
- `sandbox_mode=workspace-write`;
- required ELIOT MCP startup;
- automatic approval only for the governed ELIOT MCP server.

The source repository remains read-only to the nested session. Candidate
acceptance still occurs through the controller after canonical observation and
registered verifier evidence.

## Consequences

- Nested commits no longer require writes to the OneDrive controller `.git`.
- The sandbox has one bounded source-and-Git write root.
- Clone object storage costs more disk space than a linked worktree.
- The first live L3 session cannot be retroactively upgraded with this repair;
  its blocked commit and absent hook spool remain preserved evidence.
- A later live acceptance run must use the emitted launch contract rather than
  reconstructing the flags ad hoc.
