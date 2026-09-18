# START HERE

Read this file first. It is the shortest route from a cold start to a merged change.
It does not replace `AGENTS.md`, `WORKFLOW.md`, or the normative pair; it points to the authority you need.

## 1. Priority — code first

The product is a draft: write the missing code and land it on `main`. Do not build
ceremony, exhaustive negative matrices, or projections before the capability exists.

## 2. Roles are distinct

- **Controller (root-owned sync only):** performs the coordinated upstream fetch and
  publishes the authority receipt (remote URL, tracked ref, commit SHA, sync result, UTC timestamp).
- **Manager:** works in its own worktree, never runs fetch or pull, and merges its own
  verified PR only after the standing gate passes.
- **Writer:** implements one owning issue inside the claimed scope only, and never merges its own work.
- **Independent verifier:** reviews the diff against the owning issue; never the writer.

## 3. Start from the published authority

```powershell
git status --short --branch
git rev-parse HEAD
```

Confirm `HEAD` equals the base SHA from the published authority receipt and the tree is clean
for your scope. Provision one worktree per mutating branch from that published SHA, then create:

```powershell
git switch -c <kind>/<issue>-<short-slug>
```

Form is `<kind>/<issue>-<slug>` with kind `work`, `fix`, `docs`, `chore`, `refactor`, or `test`.
One issue, one branch, one PR. One mutable path scope has one writer. See `AGENTS.md` and `WORKFLOW.md`
for branch validity and the forbidden sync and ref-mutation list.

## 4. Route docs for every change

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Run routing for every mutation class (code, configuration, tests, workflows, normative prose).
Repeat `--path` for every mutable path family. Open the verified bundle and read every required
item before mutation. Record receipt IDs, matched routes, required handles, fragment paths and hashes,
bundle hash, and attestation in the PR. See `docs/architecture/READING_PROTOCOL.md`.

## 5. Proof is governed by the owning issue

The owning-issue acceptance defines the required proof. Run the smallest proof that can fail on the
changed path while iterating; iteration speed never waives mandatory package, edge, negative, or Product
checks at completion. Keep iteration checks separate from completion gates.

```powershell
cargo metadata --locked --no-deps
cargo check --locked -p <package> --all-targets
cargo test --locked -p <package>
```

Use focused package and edge proofs while iterating; run wider suites only for a matching blast radius.
Report every skipped, failed, simulated, or unavailable check exactly. An honest gap is reported and is
not automatically mergeable; a false claim never merges. See `WORKFLOW.md` and `docs/ARCHITECTURE_CONTRACT.md`.

## 6. Finish

Open a PR to `main` with the authority receipt, read receipt, base and candidate revisions, scope, proof,
and residuals. The writer never merges; the manager merges its verified PR after the gate, then retires
the branch and removes the worktree. See `workstreams/ACTIVE.toml` for programme state.

Map: Architecture `docs/ARCHITECTURE_CONTRACT.md` · source `docs/PROJECT_MAP.md` · scripts `scripts/README.md`.
