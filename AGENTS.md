# Repository agent instructions

## Current scope: V3 documentation

The owner has frozen V1/V2 as donors and requested a fresh V3 design before
implementation. Start with [V3 navigation](docs/v3/README.md), read
[Architecture](docs/v3/ARCHITECTURE.md) and
[Implementation](docs/v3/IMPLEMENTATION.md), and inspect the relevant evidence in
the [consolidated audit](docs/v3/AUDIT.md). The current V3 revision is a draft, not a claim
of completed code or acceptance of every proposal. Do not resume V2 programmes
or start V3 runtime work from an old issue, manifest, or checklist.

The generated routing block below indexes retained V2 surfaces. Use it when
examining or changing those donor surfaces; read the V3 files directly for a
V3-only documentation change. A legacy receipt does not certify a V3 design.
Preserve existing access controls, required CI, and independent integration.
The unchanged V2 ACTIVE registry still encodes its former programmes as active;
this is a human-directed documentation freeze, not a migration of that registry.

## Working scope

- Follow the requested scope. Explicit user instructions take priority over repository defaults.
- Use current `main` as the source and documentation authority. Check `git status --short --branch` and `git rev-parse HEAD` before editing.
- Preserve unrelated changes. For parallel work, use isolated worktrees and one writer per file; the root agent handles synchronization and integration.
- Read the nearest `AGENTS.md`, the owning issue/PR when present, and documentation relevant to the change.
- Project navigation: [workflow](WORKFLOW.md), [V3 work](docs/v3/README.md), [architecture contract](docs/ARCHITECTURE_CONTRACT.md). [V2 workstream records](workstreams/ACTIVE.toml) and their validators remain unchanged donor infrastructure.

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

- Run the smallest check that covers the change. For V3 prose, review contract/requirement consistency, changed links, and `git diff --check`. The legacy `just quick` includes extensive V2 checks and Cargo work; it is not a default V3 prose check. Runtime work follows the owner's selected development order and relevant required checks. Repeat only after relevant changes or failures.
- Report what changed, which checks ran, and any failures, skipped checks, or remaining uncertainty. Match completion claims to observed evidence.
- GitHub Actions use `workflow_dispatch` only, except `.github/workflows/ci.yml`, the sole automatic compile-only merge check (accepted issue #3004; triggers `pull_request` to `main`, `push` to `main`, manual rerun). Change workflows only when requested; run ordinary checks locally.
- Commit only task files. The requested `docs/v3/AUDIT.md` is a maintained design deliverable. Keep credentials, local state, build output, `.eliot/`, `.codebase-memory/`, generated reports, raw downloaded research, and temporary agent notes out of Git.
