# Start here

## 1. Current task: documentation for a fresh V3

The owner has frozen V1/V2 as donors. Refine V3 documentation before starting its runtime rewrite. Begin with [docs/v3/README.md](docs/v3/README.md), then read [Architecture](docs/v3/ARCHITECTURE.md), [Implementation](docs/v3/IMPLEMENTATION.md), and the relevant evidence in the [consolidated audit](docs/v3/AUDIT.md). Draft proposals are not accepted runtime capabilities.

Existing source, shards, delivery programmes, and validation scripts describe V2. Do not resume its issue factory or import its process topology by default. The unchanged ACTIVE registry still contains V2 `active` values; this documentation revision does not migrate that machine registry or close its issues. The owner's current scope takes precedence for agent work.

## 2. Roles

- **Root/controller:** owns coordinated upstream synchronization and publishes the base identity, timestamp, and result.
- **Writer:** changes only the assigned scope; never merges its own work.
- **Manager:** coordinates a mutating branch in its own worktree; never merges its own managed result.
- **Independent verifier:** checks the actual diff and claims against the issue; is not the writer.
- **Integration owner:** independently validates the candidate and merges only after the required checks; is distinct from its writer/manager.

One scope has one writer. Read-only reviewers can inspect the same tree without creating extra worktrees. Preserve unrelated user/agent changes.

## 3. Start from current main

```text
git status --short --branch
git rev-parse HEAD
```

Use the root-published current-main base. Workers/managers do not fetch or pull independently. Create one issue-numbered branch and one PR for the task, in the form `<kind>/<issue>-<slug>`; see [WORKFLOW](WORKFLOW.md) for valid kinds and branch rules.

## 4. Read sources appropriate to the version

For a V3 contract change, read both V3 design documents and follow the relevant audit claims to their pinned source. Explain the preserved behavior and the proposed mechanism. Do not treat a summarized donor finding or a navigation receipt as personal comprehension.

For retained V2 source, configuration, workflows, tests, or normative fragments, use the existing verified reader before changing those surfaces:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Read every required item and expand substantive descendants where the question requires them. Record the route/read receipts, source hashes, bundle hash, and reading attestation in the work unit or PR. See the [V2 reading protocol](docs/architecture/READING_PROTOCOL.md). This records donor reading; it does not establish a V3 adoption digest.

## 5. Verify the actual change

For the current documentation stage, check semantic consistency, preservation of requirements, source attribution, local Markdown links, and `git diff --check`. Use relevant existing verifiers if their governed surface changed. Do not use the broad V2 `just quick` pipeline as a substitute for reading a V3 design.

For future implementation, follow the owner's sequence: product code, minimum relevant checks/Clippy, then tests after the product is built. Evidence must still support the specific reliability, privacy, learning, and completion claims made. The owning issue and actual affected behavior determine necessary checks; one local PASS does not prove the product.

Required repository CI remains in force. Do not modify or bypass a gate to make this documentation change look verified. Report unavailable, skipped, or failing checks and their scope exactly.

## 6. Integrate the reviewed result

Open a PR to `main` with the issue, base/candidate identity, changed paths, source/read evidence, executed checks, independent review, and remaining questions. The independent integration owner merges after the applicable checks and retires the task branch. The requested consolidated audit belongs in `docs/v3/AUDIT.md`; temporary notes, raw downloads, generated receipts, credentials, and runtime state stay out of Git.

Map: [agent rules](AGENTS.md) · [workflow](WORKFLOW.md) · [version authority](docs/ARCHITECTURE_CONTRACT.md) · [V3 design](docs/v3/README.md) · [V2 source map](docs/PROJECT_MAP.md).
