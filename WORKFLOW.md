# Development workflow

## Current phase: V3 documentation, V1/V2 donors

The owner selected a fresh V3 implementation after documentation is refined.
[V3 navigation](docs/v3/README.md) and
[architecture authority](docs/ARCHITECTURE_CONTRACT.md) define that version
boundary. Read the V3 Architecture/Implementation and relevant audit evidence
for a V3 design change. The generated routing block below applies to retained
V2 surfaces; it does not turn old physical architecture or delivery waves into
requirements for V3.

This phase permits the requested consolidated audit and documentation changes.
It does not start runtime implementation, migrate data, close old programmes,
or change CI. The V2 ACTIVE registry and validators remain unchanged and still
encode their former programmes as active; this revision does not claim a
machine-enforced freeze. The owner's task scope governs agent work.

The independent writer/verifier/integration roles and required merge checks
below remain applicable. Future product development follows the owner's order:
product code, minimum relevant checks/Clippy, tests after the product is built.
Do not apply a V2 test-first or audit-factory programme to the present prose task.

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


## One authority surface

`main` is the current product source and documentation authority. Issues define
work; branches and worktrees execute it; pull requests integrate it. Reports,
audits, research dumps, local state, and generated evidence are not parallel
sources of truth.

Upstream synchronization is root-owned and controller-only. While online agents
are active, the root controller performs the coordinated upstream fetch
approximately hourly, and also at an explicit integration boundary when needed,
then publishes an authority receipt recording:

- remote URL;
- upstream ref (`refs/heads/main` / `origin/main`);
- commit SHA;
- sync result;
- timestamp (UTC).

Workers and managers never fetch or pull directly, and must not switch,
fast-forward, or update the controller/authority checkout or authority branches.
Issue worktrees and branches are provisioned from the published SHA; ordinary
issue-branch creation remains allowed in isolated worktrees. They verify their
local worktree and base revision against the published authority receipt without
updating refs.

Canonical navigation:

- Architecture authority: `docs/ARCHITECTURE_CONTRACT.md`;
- V3 proposal and current documentation stage: `docs/v3/README.md`;
- historical V2 pair identity: `docs/normative-pair.toml`;
- retained V2 source map: `docs/PROJECT_MAP.md`;
- documentation map: `docs/README.md`;
- retained V2 programme/branch registry: `workstreams/ACTIVE.toml` (not migrated by this revision);
- repository agent rules: `AGENTS.md`.

## Work lifecycle

```text
open issue with owner, causal property, scope, proof, and non-goals
→ root/controller sync and publish authority receipt (remote URL, ref, SHA, result, timestamp)
→ verify local worktree and base commit against authority receipt (no fetch/pull by workers)
→ create a fresh issue-numbered branch from verified base commit
→ claim one mutable path scope
→ read the version-appropriate documentation and exact supporting sources
→ complete the scoped change and run checks appropriate to its actual behavior
→ report concrete anomalies and obtain independent review of the disputed property
→ open PR to main with read receipt, authority receipt, and attestation
→ integrate by squash after current-main and proof checks
→ close issue and retire the branch
```

Normal branch form:

```text
<kind>/<issue-number>-<short-slug>
```

Allowed kinds: `work`, `fix`, `docs`, `chore`, `refactor`, `test`.
Provider-generated names, random adjective names, personal namespaces, and dated
campaign branches are not accepted for new work.

## Branch validity

A standard issue-numbered branch is valid only when:

1. the branch issue is open and describes the current causal change;
2. the branch was created from the verified base commit matching the published
   authority receipt;
3. verified base commit remains an ancestor before further mutation and merge;
4. its PR is open when one exists;
5. the declared mutable path scope has no other writer.

`workstreams/ACTIVE.toml` lists programmes, shared routing inputs, and any rare
explicit exception. It intentionally does not duplicate every ephemeral issue
branch; the issue and PR own that current state. There are no active long-lived
or nonstandard implementation branches.

Do not repair a superseded branch in place. Start a fresh branch and carry only
the reviewed change. A merged, closed, abandoned, or superseded branch is
retired. Branch content never outranks `main`, even when it contains newer dates
or more prose.

## Worktrees and writers

Use one worktree per mutating branch. Record the primary path scope in the issue
or PR. Two agents may read the same files, but they do not mutate the same scope
concurrently. Contract changes land before dependent implementation waves, and
the integration owner revalidates consumers after the contract change.

## Agent operations and audit escalation

Keep agent operations inside their assigned scope and available permissions.
Report a concrete source, change, or failed operation when scope drift,
unsupported completion claims, stale inputs, or session/provider failures occur.
Have an independent reviewer examine the disputed property and repair the
responsible contract or implementation. Do not create a new audit programme for
every routine error, use a diagnostic report as completion authority, or retry
an unauthorized action through another route. Read-only reviewers do not need
additional mutable worktrees. A specific external harness's telemetry API is
not a prerequisite for ordinary repository work.

## Documentation and evidence placement

Keep in Git:

- the current V3 design proposal and retained V2 reference pair;
- the owner-requested consolidated V3 audit and stable decision rationale;
- stable operator/developer documentation;
- ADRs for accepted load-bearing decisions;
- generated projections only when an active consumer and regeneration check
  exist;
- bounded reusable workstream briefs and routing metadata.

Do not keep in the active tree:

- raw historical audit packages, recovery dumps, progress logs, or unrelated one-off reports;
- donor research packages or reverse-engineering dumps;
- copies of documentation owned by Eliot Search or Eliot Research;
- swarm conversations/results;
- local databases, code-graph snapshots, runtime state, or credentials;
- generated documentation bundles or read receipts.

V3 design findings belong in the consolidated audit and corresponding issue/PR.
Temporary investigations need not create another maintained document. Large generated evidence
belongs in CI artifacts or an external content-addressed store. Retired content
remains recoverable from Git history; it is not copied into an `archive/`
directory that agents may mistake for current authority.

## Integration and proof

A PR states:

- owning issue/workstream;
- exact base and candidate revisions;
- published authority receipt reference (remote URL, ref, SHA, result, timestamp);
- changed causal property and path scope;
- documentation route/read receipt, bundle hash, handles, and agent attestation;
- proof executed and proof ceiling;
- affected edges and Product Pulse, or why they are not applicable;
- migration/rollback/removal consequences;
- residual unknowns.

Ordinary PR CI checks current source shape and compilation. The expensive full
workspace test/Clippy/build gate is a separately invoked source-candidate or
release operation, not a tax on every local change. A green check is not product
acceptance: source, build, runtime, store, and Product Proof remain separate
evidence dimensions.

The required automatic check is `.github/workflows/ci.yml` (accepted issue
#3004): it runs the closed `MergeCompile` profile owned by
`scripts/verify.ps1` for every pull request targeting `main` and
diagnostically for every pushed `main` commit. Its proof ceiling is
`MERGE_COMPILE_SOURCE_ONLY`: compile-only with zero test execution and no
lint-cleanliness claim. It never substitutes for manual `Review`,
source-candidate, release, runtime, store, or Product acceptance.
