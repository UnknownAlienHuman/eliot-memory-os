# Continuation of #5018

Owner order, 2026-10-02: familiarise, re-audit blockers, refine issues, plan work
without overlaps, define stitching/contract ownership, recheck, then start swarm.
Goal: finish product code and production wiring first; product tests follow assembly.

## Start, without waiting for a complete backlog audit

The controller reads README.md, PLAN.tsv and STITCH-PLAN.md. M-KERNEL starts #1943;
M-STORE starts #2691 after the preflight below. Both are implementation assignments,
not permission to mark the whole issue complete. Existing code is retained; the
assignment covers all remaining source obligations, not a separate PR per item.
In parallel, read-only reviewers process RECHECK rows. An unrelated undecided
contract or invalid historical row does not stop these two assignments.

Before issuing writes, the controller must establish the actual machine state:
FIN cleanup and old runners are stopped; no previous writer still owns a claimed
path; current main and open PRs are refreshed once and the authority SHA published.
The checked baseline is b7e9e334569639a6290baeacf82bf44941def506. Revalidate affected
rows if source, issue comments or shared interfaces changed. PR #5021 is an external
writer: re-read its current six-file delta, not just its old head SHA.

## One manager, one worktree, one issue delivery

Each mutating manager uses one isolated worktree and one fresh issue-numbered branch
from the published main SHA. After delivery, retire the issue branch before the next
assignment. Do not reuse lane branches carrying unrelated commits. Only the root
controller synchronises upstream and integrates main. Old issue instructions saying
`main only, no worktrees` and stopped-run lane-branch instructions do not govern
this parallel continuation; current WORKFLOW and this explicit assignment do.

The manager is accountable for the whole claimed scope. Subagents get disjoint files
or read-only questions inside it; they do not create extra worktrees or touch another
manager's paths. Do not count a reviewer as an additional writer. Use actual available
models; a historical quota forecast is not a launch prerequisite.

Claim all write paths together, including tests, manifests and generated outputs.
PLAN path entries ending `/` reserve a subtree; other entries reserve an exact file.
Claims last until explicit integration/transfer/abort, not until a wave number changes.
New shared paths require one controller amendment before mutation. Root Cargo files
and the six #5021 files are not included in either initial implementation scope.
No acquire-one-file-then-wait-for-another cycle; no silent scope expansion.

## Work and evidence

Read the live issue body, all comments, nearest AGENTS and the mandatory routed bundle
for actual mutable paths. Existing declarations are not proof of a production caller.
An existing contract with absent code/caller is implementation, not MISSING-CONTRACT.
An absent measurement/run is not absent code. A closed owner issue or merged PR is
not by itself the release condition for a consumer.

Scoped formatting, minimal Clippy/compile for touched packages and affected consumers,
and diff checks cover delivery. No workspace-wide test campaign in this phase.
Record unexecuted acceptance separately; a named test is not an executed test.
One issue produces one coherent source delivery; any genuine remaining external
obligation stays explicit and does not become a false code-complete claim.

## Maintain one active queue

BLOCK-MAP.tsv owns the checked/recheck disposition; PLAN.tsv contains its READY issue
assignments exactly once. BLOCKERS-AUDIT.tsv records why a historical claim changed;
it is evidence, not a second mutable status authority. STOP-BLOCK-MAP.* is historical.
For every new candidate, check the actual source and discussion, name one owner and
complete write scope, type each real dependency and give its exact release condition;
then promote the whole source assignment into PLAN. Do not import FINISHABLE by regex.

Review the grouped seams in STITCH-PLAN before scheduling their dependent code.
Each historical cycle is a review finding until its item-level edges are established;
internal steps and proof-after-assembly are not cross-issue implementation blockers.
Use the same manager sequentially for shared-owner work, but keep separate issue
branches/deliveries. Never remove a genuine dependency merely to produce a DAG.

After a merge, root updates affected records and consumers, not all 577 issues.
On a real wait, preserve the issue checkpoint, explicitly release/transfer scope,
and take independent ready work. After two identical failures, inspect the cause;
retry only after changed inputs or a different remedy. Do not churn BLOCKED reports.

## Delivery gate and completion

Do not disable the documentation-evidence gate. The local Make-PR2.sh emitter is
outside this repository and has not been changed here. Before first delivery, root
must emit the real v2 read evidence required by scripts/work_unit_gate/doc_read_evidence.py
from the executor's actual receipt and validate one representative PR. A skipped
MergeCompile is not a successful compile. This operational check does not forbid
reading/preparing an otherwise independent assignment.

This revision provides a bounded checked source-work queue and preserves the full
stop inventory. It does not assert a completed 577-issue audit, independent model
review, green CI, or running Windows agents. Root records those facts only after
they occur. Keep #5018 draft until its review/evidence obligations are actually met.
