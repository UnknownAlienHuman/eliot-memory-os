# V3 development guide

Use this page for **where to work, how to check and what to update**. Product rules
remain in the four [owner contracts](../ARCHITECTURE_CONTRACT.md#v3-working-authority);
work status remains in [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md). This is neither a
fifth specification nor another backlog. Read only the section needed by your task.

| Need | Go to |
|---|---|
| Locate a document or source file | [Repository map](#repository-map) |
| Start one implementable assignment | [One bounded task](#one-bounded-task) |
| Choose checks and interpret failure | [Checks](#checks) |
| Update a contract, source or reference | [Change propagation](#change-propagation) |
| Register or refresh the actual task | [Assignment registration](#assignment-registration) |
| Deliver documentation to main | [Documentation integration](#documentation-integration) |

## Repository map

| Location | Role | Use it for |
|---|---|---|
| [START](../../START.md), [AGENTS](../../AGENTS.md), [WORKFLOW](../../WORKFLOW.md) | Entry, agent rules, branch/integration rules | Select the assigned version and writer before editing. |
| [V3 README](README.md#task-routes) | Task-to-section index | Find one owning section; do not read every book. |
| [Architecture](ARCHITECTURE.md) | Purpose, responsibility, invariants | Decide whether a mechanism belongs in Memory at all. |
| [Implementation](IMPLEMENTATION.md) | Runtime, Store, maintenance, implementation order | Find the actual state/effect boundary and its failure handling. |
| [Cognition](COGNITION.md) | Reconstruction, retrieval, revision and learning algorithms | Connect stored data to useful context and later use. |
| [Inference contract](INFERENCE-CONTRACT.md) | Proposed external interface | Verify the other repository before using an advertised method. |
| [ANALYSIS-REGISTRY](ANALYSIS-REGISTRY.md) | Decisions, gaps and next actions | Update the existing finding, not a new progress report. |
| [AUDIT-MAP](AUDIT-MAP.md), [AUDIT](AUDIT.md) | Requirement routes and historical rationale | Resolve one disputed requirement or donor choice. Not the default reading stack. |
| [Store source map](store/README.md) | Location/status of the separately proposed V3 Store package | Inspect the owning source branch; package files are not in the documentation branch. |
| [Crate instructions](../../crates/AGENTS.md#select-the-source-version), [Storage instructions](../../crates/storage/AGENTS.md#v3-store-work), [code navigation](../CODE_NAVIGATION.md#select-v3-or-retained-v2) | Version-aware source entry points | Use the V3 sections for assigned V3 code; retained V2 instructions do not define its topology. |
| Existing `bins/`, `crates/`, `apps/`, `workers/`, `plugin/`, `integrations/` | Retained code; names alone do not establish V3 ownership | Reuse only a selected donor mechanism after tracing its caller and consumer. |
| [PROJECT_MAP](../PROJECT_MAP.md), [ACTIVE.toml](../../workstreams/ACTIVE.toml), `docs/architecture/` | Retained V2 navigation and routing | Only for an explicitly assigned donor/source or tooling change. Not a V3 task queue. |
| [scripts map](../../scripts/README.md), `.github/` | Existing checks and automation | Invoke the narrow check below; do not regenerate V2 surfaces to repair V3 prose. |

For a missing implementation, the owning task selects its code location with the
first caller. Record that real path in the relevant map when it exists. Do not create
empty crates, adapters or modules merely to fill this table.

### Store package files

Resolve the current source PR through [Store ownership](store/README.md). Within
`crates/storage/eliot-v3-store-schema/`, the inspected candidate contains:

| Path | Responsibility | Change together with |
|---|---|---|
| `Cargo.toml` | Package identity and dependencies | Root membership/lock only when the source change requires them. |
| `assets/migrations/0001_base.surql` | Table, field, assertion and index definitions | Writer/reader DTOs, history, catalog and bundle identity. |
| `assets/wrapper.surql` | One transaction and bound schema metadata | Bundle construction and migration readback. |
| `assets/expected_catalog.tsv` | Candidate owned-name manifest | Exact-engine canonical catalog evidence; source lines are not that evidence. |
| `src/lib.rs` | Bundle construction, metadata and validation APIs | Migration/wrapper/catalog and `assets/bundle.sha256`. |
| `src/queries.rs` | Fixed query identities, statements, classes and bounds | Actual bind/decode/operation consumers and `assets/query-corpus.sha256`. |
| `src/bin/inspect.rs` | Embedded asset inspection | Reported identities; it is not a network client or Store readiness probe. |

The first source continuation addresses [R-174 and R-182–R-188](ANALYSIS-REGISTRY.md#store-reconciliation).
Its asset-package scope does not silently expand into a daemon rewrite. Full operation
transactions and network/runtime wiring follow the owning implementation assignment.

## One bounded task

Read [AGENTS](../../AGENTS.md) and select one [task route](README.md#task-routes).
Use the existing issue/PR for an unfinished owner; do not start a competing writer.
In that issue/PR, record only:

```text
Outcome: the concrete changed behavior or corrected document rule.
Owner: contract section and existing R-ID when relevant.
Scope: exact mutable paths; adjacent paths are read-only unless scope changes.
Path: caller -> operation -> saved result/unknown -> reader/consumer.
Checks: commands, expected observations and target environment.
Remaining: next action or exact blocker; no implied runtime PASS.
```

Keep the issue body as the stable assignment. Put changing commits, runs and progress
in the PR or comments; editing a body bound by a catalogue invalidates that binding.
A real scope/disposition change needs [registration refresh](#assignment-registration),
not a copied digest or a second work ledger.

For source work, first trace the current caller and reader. Then implement the
smallest coherent change in the owning module. Use
[Implementation §11](IMPLEMENTATION.md#11-implementation-sequence) for build order,
not the documentation D-stages. An absent dependency blocks only the path that needs it.

Stop the affected change when the required representation, permission, effect identity
or recovery behavior is contradictory. Name the missing decision and its owner in the
existing row. Do not ask a small implementation agent to redesign another repository.
After two unsuccessful repair attempts, record the observed failures in the issue,
recheck the assumption/source and choose a different approach; do not add another layer.

A reviewer receives the exact candidate, scope, owner sections and actual check results.
Ask for concrete contradictions, missing callers/readers or failure paths. A second
self-reading is useful, but is not an independent review or approval.

## Checks

### Checkout and diff

Run in the manager-assigned checkout. Only the root manager refreshes upstream refs.
Verify that `origin/main` below is the agreed base before using it; use its recorded SHA
instead when the task is pinned. Never reset or discard another writer's changes.

```text
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git diff --name-status origin/main
git diff --check origin/main
```

Inspect the full task diff, not only its summary. Stage only the intended paths, then
check the staged diff too; untracked files are not covered by the commands above.

```text
git diff --cached --check
git diff --cached --stat
```

Expected: only task paths, no whitespace diagnostics, no generated state or secrets.
An API-only editor records the remote base/head and exact changed blobs; a partial
local snapshot must never be reported as a full-checkout verification.

### Documentation and navigation

First check meaning: a rule has one owner, its consumer can find it, unresolved design
is named, and implemented behavior is not inferred from prose. Then check local links
from a **complete checkout** with the existing public module's link-only function:

```text
python -c "import sys; from pathlib import Path; sys.path.insert(0, 'scripts'); import docs_shards; print(docs_shards.verify_markdown_links(Path('.')))"
```

This function already exists in [docs_shards.py](../../scripts/docs_shards.py). It checks
local Markdown paths, exact case and heading anchors, including inbound references
from retained documents; generated/build directories are excluded by its existing rule.
It does not contact external URLs, validate semantics or produce merge-read evidence.
A missing path/anchor raises an error; repair the reference or retain the old explicit
anchor. Existing unrelated failures remain named, not hidden by broad exclusions.

For a rename, find references by both filename and old anchor before changing them:

```text
git grep -n -F -e 'OldFile.md' -e '#old-heading' -- '*.md' '*.toml' '*.json'
```

Replace the two search strings with the actual old names. Exit 1 means no matches,
not proof that URLs in external issues or other repositories were checked. Inspect
related open issues/PRs and pinned links separately. Keep historical links historical.

Do not run `docs_shards.py migrate` or regenerate the V2 router/indexes for a V3 prose
edit: they own different surfaces. Full shard/router/conformance checks are selected
only when their actual surface changes or when required by integration.

### Rust source

Write production code first. After a coherent increment, run formatting and minimum
Clippy for the changed package, not the entire retained workspace. For the Store source
checkout **containing that package**, the concrete commands are:

```text
cargo fmt -p eliot-v3-store-schema --check
cargo clippy --locked -p eliot-v3-store-schema --lib --bins -- -D warnings
cargo run --locked -p eliot-v3-store-schema --bin inspect
```

Run each command separately and retain its exit/result. `fmt`/Clippy failures belong to
the changed source. Missing package means wrong checkout or unmerged source, not a reason
to create a placeholder. A required lock update belongs to the dependency change: review
it explicitly, then rerun with `--locked`. Do not remove that flag to hide lock drift.
`inspect` checks embedded assets only; its success is not SQL execution or byte-limit
enforcement. Use the assigned package name for other tasks. An unavailable toolchain is
`NOT_EXECUTED`, not a clean result. Broad tests follow the assembled product.

### Behavior-specific review

Use only the row touched by the change. During documentation work, trace these cases in
the contract; during implementation, connect the checks to the real entrypoint. Record
actual runtime commands when that entrypoint exists, not a fictional CLI in advance.

| Changed boundary | What to inspect or later exercise | Owner |
|---|---|---|
| Capture/spool/restart | Accepted bytes and binding survive direct/staged replay; changed input under the same ID conflicts; excluded bytes never enter spool/logs. | [Implementation §7](IMPLEMENTATION.md#7-core-operations-and-host) |
| Schema/query/codec | Field and aggregate bounds fit encoded request, exact open, history and one-row backup; absent/malformed values stay distinct; every writer has a decoder. | [Implementation §4–6](IMPLEMENTATION.md#4-migration-0001-and-schema-authority) |
| Retrieval/context/open | Scope applies before arm limits; qualifiers belong to the exact revision; empty/partial/unavailable differ; actual host delivery is observed. | [Cognition §6–7](COGNITION.md#6-retrieval-and-context) |
| Revision/jobs | Atomic original result/history; frozen input and current claim match; expiry/unknown never authorizes another uncertain call; later consumer uses the saved revision. | [Implementation §4.7.3](IMPLEMENTATION.md#473-job-state-and-claim-ownership), [Cognition §9](COGNITION.md#9-controller-backed-job-lifecycle) |
| Backup/restore/erase | Coherent cut; bounded lease and candidate custody; current suppression survives rollback; terminal marker is not deletion proof. | [Implementation §8–10](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle) |
| Inference | Actual advertised principal/method/profile, same-ID readback, private result copy and dependency-aware cleanup; missing route leaves Base available. | [Inference contract](INFERENCE-CONTRACT.md#0-authority-and-prerequisites) |

For each executed case retain input identity, entrypoint, observed result/readback and
relevant failure outcome in PR evidence. A model response, hash, compiler result or
upstream test cannot substitute for a missing application operation. Full Windows,
crash, concurrency and load campaigns remain [later qualification](IMPLEMENTATION.md#12-qualification-ceiling).

## Change propagation

Update the owning rule first, its directly affected readers/writers next, then the
existing finding and navigation. Do not update every document for every edit.

| Changed item | Required companion updates | Review question |
|---|---|---|
| Product rule/algorithm | Owning contract; affected adjacent contract; requirement route in AUDIT-MAP when it moves | Does a consumer still receive a contradictory instruction? |
| Field/state/history format | DDL + bind/validation + explicit projections/decoder + history/backup + concrete byte caps | Can every admitted value be read exactly after restart? |
| Fixed query or schema bytes | Owning source assets, catalog expectations and deterministic digests; actual call/result decoder | Are identities recomputed from reviewed bytes, rather than copied to silence a mismatch? |
| Public/external interface | Both real owners, supported version/limits and unavailable behavior; pinned observation in the existing registry | Is this implemented/advertised, or still a proposal? |
| Source path/package | Relevant local source map/README and root membership only when needed; source status in the existing finding | Does the linked file exist in the stated branch? |
| Heading/path | Local inbound links, requirement routes and related live issue links; old anchor when needed | Does an old link reach the same meaning rather than a new unrelated section? |
| Dependency/host version | Exact artifact/API source and affected adapter assumptions; lock/config only in authorized source work | Which relied-on behavior changed? Do not refresh unrelated donors. |
| Finding completion | Existing R-row: decision, evidence scope and next action; PR gets commands/results | Was only design selected, source corrected, or actual behavior executed? |

Keep current instructions in owner sections, not append-only errata. Keep detailed
command output in PR/CI or ignored local evidence. A small new module needs a purpose,
entrypoint and linked contract near its code, not a separate registry or generated book.

## Documentation integration

Documentation may be integrated while product features remain unimplemented and clearly
marked. Do not make all runtime backlog, every historical donor or the full product test
campaign a prerequisite to merging reviewed documentation. Conversely, unresolved
contradictions and false readiness claims must not be hidden by a documentation label.

The integration owner follows [WORKFLOW](../../WORKFLOW.md#verification-and-integration):

1. Freeze the candidate head and base. Perform the preflight below before expensive
   setup or another CI rerun; a body-only repair cannot fix a version/assignment gap.
2. Inspect the complete diff and run applicable prose/link checks. An independent
   reader reviews that same candidate, including the nested instruction chain.
3. Once the actual tooling can represent the task, generate the exact candidate's
   read evidence using the existing reader and [PR format](../../.github/pull_request_template.md).
   Open every required item before attesting; a routed link is not reading.
4. Run the shared verifier with real base/candidate/body and trusted review evidence,
   as the CI caller does. Read current-head CI, including skipped steps. Changed tree,
   base or evidence needs fresh validation; rerunning an old event does not update
   its captured PR body. Do not automatically loop a deterministic failure.
5. Merge only through the allowed repository workflow. Read back `main` and the PR's
   merged state, then update the existing registry/source links and retire the branch.
   A push, an open PR or `mergeable: true` alone is not integration.

### Integration preflight

**Assignment and reading coverage are separate checks.** The legacy verifier reads
[work-unit-cohort.toml](../../.github/work-unit-cohort.toml), not the V3 Markdown ledger.
Inspect the real task's membership without changing that generated lock:

```text
python -c "import sys,tomllib; from pathlib import Path; n=int(sys.argv[1]); d=tomllib.loads(Path('.github/work-unit-cohort.toml').read_text(encoding='utf-8')); rows=[r for r in d.get('row',[]) if r.get('issue')==n]; print({'issue':n,'rows':rows}); sys.exit(0 if len(rows)==1 else 1)" 5324
```

Use the actual owning issue number. Missing/malformed input is an error; a nonempty
matching row is only membership, not acceptance. With a nonempty legacy catalogue,
`_checklist_state` refuses an undeclared issue even when `recorded=true`; changing an
R-row or supplying a plausible digest does not register it. Never borrow an old issue,
delete the catalogue or hand-edit its generated hashes to make the check pass.
For a missing or changed assignment, use [the existing generator](#assignment-registration);
absence of a row does not by itself require modifying the checker.

For reading coverage, inspect the existing reader's required paths on the complete
candidate checkout. This single-path command is a diagnostic, not full-PR evidence:

```text
python scripts/docs_read.py read --path docs/v3/DEVELOPMENT.md --topic "V3 documentation integration" --output .eliot/v3-route-bundle.md --receipt-out .eliot/v3-route-receipt.json
python -c "import json; from pathlib import Path; r=json.loads(Path('.eliot/v3-route-receipt.json').read_text(encoding='utf-8')); print(*(i['path'] for i in r['required']), sep=chr(10))"
```

The existing router selects V3 from the versioned path rules, never from the topic.
`docs/v3/**` and the named V3 Store package use their file owners; shared entry/tooling
paths retain V2 obligations. A mixed change includes both sets under the same combined
byte limit. Inspect `required` against the task route: a route name is not coverage.
An existing edited V3 Markdown file is also read; deleted paths remain in the scope.

Route configuration uses `eliot-doc-route-config-v2`, so an older router rejects it
instead of ignoring version fields. Route/read receipt formats are unchanged. Their
retained V2 pair key is compatibility metadata, not V3 architectural authority.
The reader recomputes the V3/mixed route before accepting its owner-file set.

When an authorized task changes path ownership, update the existing
[route rules](../architecture/route-rules.toml), add a bounded coverage example naming
`expect_required_files`, and regenerate only their existing projection:

```text
python -m py_compile scripts/docs_router_core.py scripts/docs_router.py scripts/docs_read.py
python scripts/docs_router.py self-test
python scripts/docs_read.py self-test
python scripts/docs_router.py sync --root .
python scripts/docs_router.py check --root .
```

Run `check` on the complete checkout; a synthetic fixture pass is not that result.
Review the generated ROUTES diff, pure V2/V3 and mixed paths, deletion, stale bytes,
missing owners and over-limit input. Do not hand-edit ROUTES, raise caps or route a
legacy path as V3 to avoid obligations. Assignment lookup remains a separate check;
a successful read bundle neither registers the task nor supplies independent review.

The concrete repair scope and current observations are in
[the existing D6 finding](ANALYSIS-REGISTRY.md#integration-tooling-follow-up).

### Assignment registration

Only the root/assignment owner changes the catalogue. Use the existing
[`generate-cohort-lock` entrypoint](../../scripts/work_unit_gate/__main__.py), not
an issue-specific verifier exception. This is metadata generation, not product proof.

Prepare one **local** `.eliot/cohort-snapshot.json` for the declared catalogue scope:

| Input | How to obtain and check it |
|---|---|
| `header.repository`, `base_revision` | Observed repository and full `git rev-parse HEAD` before generation. This is the acquisition base, not a claim that every old row was freshly verified. |
| `header.acquired_at`, `acquisition`, `note` | Actual UTC acquisition time, exact sources and limits. Distinguish inherited catalogue rows from live issue reads; preserve their older provenance rather than relabelling it current. |
| `header.complete`, `missing_sections`, coverage/counts | Account for every row in the selected catalogue and the actual descriptor directory. Refuse partial/moved acquisition; do not claim a whole-GitHub inventory. |
| `rows` | Preserve every unrelated existing row. Add/update only the assigned issue with its declared unit, disposition and prerequisites; compute `body_sha256` from the exact API `body` UTF-8 string, without trimming or appending a newline. |
| `numeric_descriptors` | Actual `cohort.discover_numeric_descriptor_files` result, not a desired list. Never filter out an inconvenient real descriptor. Synthetic examples belong in `scripts/testdata/`, not the active directory. |

The closed snapshot row is `{issue, unit, body_sha256, disposition, prerequisites}`.
The generator's exact schema and constraints live in
[`cohort.generate_cohort_lock`](../../scripts/work_unit_gate/cohort.py). An `assigned`
row needs its real executable descriptor. A documentation task blocked on review uses
its explicitly declared `blocked` disposition without inventing a Rust package, test
matrix or executable descriptor; its final-candidate checklist remains required.

For an API JSON response saved as `.eliot/issue.json`, compute the body digest with:

```text
python -c "import json,hashlib; from pathlib import Path; d=json.loads(Path('.eliot/issue.json').read_text(encoding='utf-8-sig')); assert d['number']==5324 and d['state']=='open' and 'pull_request' not in d; print(hashlib.sha256(d['body'].encode('utf-8')).hexdigest())"
```

Use the actual task number and verify the response repository URL before using it.
A metadata digest binds the text; it does not decide its disposition or grant authority.
Then generate to a temporary output. The readback below is for the descriptor-free
documentation catalogue; executable rows instead need their real decoded descriptor
mapping passed to the existing cohort validator, never an invented empty mapping:

```text
python -m scripts.work_unit_gate generate-cohort-lock --snapshot .eliot/cohort-snapshot.json --out .eliot/work-unit-cohort.toml --root . --json
python -c "from scripts.work_unit_gate import cohort; p='.eliot/work-unit-cohort.toml'; lock=cohort.read_cohort_lock(p); rows=cohort.locked_catalogue_rows(p); observed=tuple(sorted(n for n,_ in cohort.discover_numeric_descriptor_files('.github/work-units'))); assert observed==lock.aggregate.numeric_descriptors; print({'rows':len(rows),'numeric_descriptors':observed,'digest':lock.aggregate.sha256})"
```

Require success from **each** command. Read back the issue again: a changed body or
scope requires fresh generation. Review every changed row, preservation of unrelated
rows, descriptor membership and counts. Only then copy the generated bytes to
`.github/work-unit-cohort.toml` and inspect `git diff --check` and the full diff.
Keep snapshots, API responses and temporary outputs out of Git. The retained lock is
the machine catalogue; ANALYSIS-REGISTRY remains the sole V3 work ledger.

Membership fixes only the assignment lookup. The actual PR still needs its own recorded
checklist bound to the final candidate tree, genuine reading evidence and independent
review. A local counterexample using synthetic tree IDs is never that evidence.

### Final-candidate verification

The documented shared command is:

```text
python -m scripts.work_unit_gate doc-read-evidence --base BASE_SHA --candidate CANDIDATE_SHA --pr-body PR_BODY_FILE --approval REVIEWS_JSON --pr-author PR_AUTHOR --pr-head PR_HEAD_SHA
```

Uppercase arguments stand for observed values/files, not literal placeholders to submit.
The command and evidence rules live in
[doc_read_evidence.py](../../scripts/work_unit_gate/doc_read_evidence.py), not this guide.
Do not hand-author an invented receipt or an independent review under the writer's name.

| Failure | Next action, not a workaround |
|---|---|
| `EMPTY_DOCUMENTATION_EVIDENCE` | First check assignment and V3 reading coverage above; then prepare the genuine final-candidate block. A missing block may be only the first failure. |
| `CHECKLIST_REQUIRED_MISSING` or undeclared work issue | Missing/stale assignment: [regenerate the actual binding](#assignment-registration). Registered task: inspect its recorded checklist and final-tree binding. An unrelated issue, stale tree or `recorded=true` alone is not a repair. |
| Reader cannot route/admit this V3 change | Record the exact command/error and affected input in D6. The tooling owner must resolve the version mismatch as a scoped change; do not expand payload caps or weaken the gate here. |
| No independent review | Request a real read-only review of the frozen candidate; report unavailable review honestly. Do not manufacture approval. |
| Provisioning/build environment failure | Identify the failed input/step and its owner; do not blame unexecuted code or mark skipped compilation passed. |
| Remote head moved | Root reconciles the diff and validates the new candidate; never force over the concurrent writer. |

Current integration blockers and their observed head/run belong only to
[the registry](ANALYSIS-REGISTRY.md#integration-blockers), not copied status in this guide.
