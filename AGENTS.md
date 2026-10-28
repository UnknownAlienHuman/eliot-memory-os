# Repository agent instructions

## Select the version and task

V3 documentation is the current task. V1/V2 Memory source, architecture shards,
`workstreams/ACTIVE.toml` and their validators are retained donors, not permission
to resume their programmes. This is an agent-work boundary, not a claim that the
legacy machine registry or CI has been migrated.

`main` is the integration base. While issue #5324 / PR #5325 remains open, continue
its V3 documentation on `docs/5324-v3-documentation-audit`; do not create a second
writer branch for the same files. Check the live issue, PR state and head before
editing. After merge, use `main`; a closed or superseded branch is not authority.

Start with [the V3 task map](docs/v3/README.md). Select one eligible stage in the
[existing registry](docs/v3/ANALYSIS-REGISTRY.md#documentation-stages), then read
only the owning sections and the source needed for that decision. Architecture,
Implementation, Cognition, Inference and the audit are not a mandatory reading
stack for every task. Read an adjacent contract when the changed behavior crosses
its boundary. Follow the nearest `AGENTS.md` for any source path being changed.

## Make the change

- Follow the requested scope; explicit user instructions override repository defaults.
- One manager owns one mutating worktree and one writer per file. The root owns
  upstream synchronization; workers do not fetch/pull or change authority refs.
  Preserve unrelated changes. Read-only reviewers need no additional worktree.
- Correct the owning text, not an appended exception. Indexes link to contracts;
  they do not copy their mechanisms, revision numbers or external project status.
- Keep `ANALYSIS-REGISTRY.md` as the only V3 work ledger. Update the existing row
  with the decision, remaining gap and next action; do not add another report,
  scheduler, readiness database or progress journal.
- Add a mechanism only for a named caller, owner, result/unknown and consumer.
  Reuse an existing owner before adding a process, crate, table or framework.
- Stop only the affected decision when a contract conflicts or evidence is missing.
  Record the concrete blocker; unrelated Base work does not wait for inference.

## Verify and deliver

For prose: review requirements, ownership, normal/failure paths, changed links and
`git diff --check`. Run an existing narrow verifier only when its surface changed.
Do not run the V2 `just quick` pipeline as a default V3 prose check.

For separately authorized Rust work: production code first, formatting and minimum
changed-package Clippy after a coherent increment; broad tests follow the assembled
product under the owner's development order. Never describe deferred checks as passed.

Required CI and independent review still apply. Direct V3 reading is not a waiver
of the existing merge evidence check. Record an unavailable reader/check honestly;
never invent a receipt, approval or runtime result. Do not change workflow triggers,
branch protections or product code merely to make this documentation PR green.
The writer/manager does not approve or merge its own result; see [WORKFLOW](WORKFLOW.md).

Commit only task files. Credentials, local state, generated bundles/receipts,
build output, downloads and temporary notes stay out of Git.

## Retained V2 edits only

The following generated block applies only to an explicitly assigned change to
retained V2 surfaces. For V3 documents and their entry-point prose, use the direct,
task-scoped reading rule above. Do not regenerate V3 instructions from the V2 router.

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
