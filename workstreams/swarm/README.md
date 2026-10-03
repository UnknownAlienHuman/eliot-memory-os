# Swarm continuation: start here

Current work order: [CONTINUATION.md](CONTINUATION.md). Assignments:
[PLAN.tsv](PLAN.tsv). Checked residuals and review queue: [BLOCK-MAP.tsv](BLOCK-MAP.tsv).
Shared-owner boundaries: [STITCH-PLAN.md](STITCH-PLAN.md).

The active map is a bounded continuation queue, **not a claim that all 577 issues
have been re-audited**. Only `READY` implementation rows in PLAN may be dispatched,
after the controller's live preflight. `RECHECK` means investigation, not a product
blocker and not permission to implement. Issues absent from the active map remain
unreviewed; they have not been dropped or declared complete.

The original 577-row stop map is preserved byte-for-byte as
[STOP-BLOCK-MAP.tsv](STOP-BLOCK-MAP.tsv), with its original rendering in
[STOP-BLOCK-MAP.md](STOP-BLOCK-MAP.md). These are read-only historical input.
Their FINISHABLE counts, inferred dependency graph, and OR corrections are not an
execution queue. Do not run the old `blockmap_build.py` over the new active files.
Read the selected issue's old row only, then its live body, all comments and docs.

HANDOFF.md, LANE-HANDOFFS.md, MANAGER-BRIEF.md and RECOMMENDATIONS.md describe the
stopped run. They do not override current AGENTS.md/WORKFLOW.md, the owner's current
order or CONTINUATION.md. No archived branch is merged wholesale. Historical
provider quotas, watchdog/cleanup orders and lane states are not live observations.

These files are non-normative work records under the owner's #5017/#5018 order;
they grant no product capability, change no Architecture contract, and establish
no runtime acceptance. Current source baseline for this revision:
`b7e9e334569639a6290baeacf82bf44941def506`.
