# Swarm continuation — #5018

**Executor:** take the single row issued to you in [PLAN.tsv](PLAN.tsv) and only the
matching [PLAN.md](PLAN.md) card. The card is deliberately operational:

```text
EDIT -> READ ONLY -> START -> MAKE -> DO NOT -> CHECK NOW -> DEFER -> DONE
```

Then read the current Issue/thread, nearest `AGENTS.md` and the complete verified
documentation/source bundle for the exact editable paths. Do not load other cards, the
whole backlog or an old lane. Return the compact handoff specified at the top of
`PLAN.md`; do not commit a diary or duplicate documentation bundle.

**Controller:** use [CONTINUATION.md](CONTINUATION.md) for claims/integration and
[STITCH-PLAN.md](STITCH-PLAN.md) only for the selected assignment's shared seam or PR
disposition. Resolve exact-file overlaps, record one manager/worktree/branch claim and
let unrelated work continue. A `READY` row is not a claim, running session or accepted
result.

The `Not dispatchable yet` section in `PLAN.md` names exact missing owner outputs and
release conditions. Those entries reserve no files and do not stop the four independent
READY cards.

Canonical Architecture/Implementation and accepted owner decisions remain authority.
These files schedule work; they cannot change product contracts or manufacture proof.

[BLOCK-MAP.tsv](BLOCK-MAP.tsv) retains the complete historical inventory.
[REVIEWED.tsv](REVIEWED.tsv) records bounded rechecks; missing means unreviewed.
[BLOCK-MAP.md](BLOCK-MAP.md) explains coverage. `BLOCKERS-AUDIT.tsv` is a finding
index, not another queue. `PRESERVE` prevents repeating an inspected repair without
claiming fresh runtime acceptance.

`HANDOFF.md`, `MANAGER-BRIEF.md`, `LANE-HANDOFFS.md` and `RECOMMENDATIONS.md` remain
historical stop records, not current assignments. Full Issue coverage, genuine reader/
CI evidence and local runner state are not certified by this planning revision.

**Review of 2026-10-03 15:22:** 445 issues reviewed by the lanes; 126 new READY cards in `cards/`, rows in `PLAN.tsv`; waits in `WAIT.tsv`, owner decisions in `ESCALATE.tsv`, seams in `STITCH-20261003.tsv`. See the dated section at the end of `PLAN.md`.

**Review of 2026-10-03 17:13:** 524 issues reviewed by the lanes; 72 new READY cards in `cards/`, rows in `PLAN.tsv`; waits in `WAIT.tsv`, owner decisions in `ESCALATE.tsv`, seams in `STITCH-20261003.tsv`. See the dated section at the end of `PLAN.md`.
