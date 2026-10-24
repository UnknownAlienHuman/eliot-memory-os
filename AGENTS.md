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

## V3 execution discipline

The V2 failure was not a shortage of contracts, registries or work descriptions.
It was failure to convert them into one integrated product path. Apply these
constraints to V3 documentation and later implementation:

- The unit of progress is a connected product edge: shipped caller → owning
  operation → durable result or typed unknown → actual consumer → restart/readback.
  A type, port, fixture, receipt, checklist, report, issue, branch or PR is not
  completion by itself.
- Use [the active analysis registry](docs/v3/ANALYSIS-REGISTRY.md) as the only
  live audit ledger. Do not create another task catalogue, gate, branch manager,
  mission database, report database or agent scheduler. Extend an existing owner
  only when a real product field cannot be represented there.
- Prefer deletion, replacement and direct correction over append-only
  clarification. A new normative document must retire or narrow an existing
  authority; it must not create another equally current source of truth.
- Run cheap deterministic admission and configuration checks before expensive
  setup. Do not download, build, dispatch agents or generate broad evidence when
  a missing credential, stale base, duplicate owner or unsupported route can be
  rejected first.
- Do not start overlapping sibling work while an earlier branch/PR for the same
  semantic owner lacks a terminal disposition. Use `MERGE_READY`, `BLOCKED` with
  an exact owner, `NO_CHANGE`, `SUPERSEDED`, or `RETURNED` with one concrete defect.
- Optimize for merged product behavior and closed blockers, not generated prose,
  LOC, commit count, agent count, issue count or PR count.
- Keep the first implementation vertical and small. Add process machinery only
  after the connected slice demonstrates a missing owner that ordinary code and
  the existing issue/PR path cannot express.

## Working scope

- Follow the requested scope. Explicit user instructions take priority over repository defaults.
- Base work on current `main`. While issue #5324/PR #5325 is open, the files under `docs/v3/` on its branch are the current V3 working authority; retained V2 documents on `main` remain donors.
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
