# Repository agent instructions

## Working scope

- Follow the requested scope. Explicit user instructions take priority over repository defaults.
- Use current `main` as the source and documentation authority. Check `git status --short --branch` and `git rev-parse HEAD` before editing.
- Preserve unrelated changes. For parallel work, use isolated worktrees and one writer per file; the root agent handles synchronization and integration.
- Read the nearest `AGENTS.md`, the owning issue/PR when present, and documentation relevant to the change.
- Project navigation: [workflow](WORKFLOW.md), [active workstreams](workstreams/ACTIVE.toml), [architecture contract](docs/ARCHITECTURE_CONTRACT.md).

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

## Verification and delivery

- Run the smallest check that covers the change: `just quick` for documentation/configuration, or the relevant package/edge proof for Rust. Repeat checks only after relevant changes or failures.
- Report what changed, which checks ran, and any failures, skipped checks, or remaining uncertainty. Match completion claims to observed evidence.
- GitHub Actions use `workflow_dispatch` only. Change workflows only when requested; run ordinary checks locally.
- Commit only task files. Keep credentials, local state, build output, `.eliot/`, `.codebase-memory/`, generated reports, and downloaded research out of Git.
