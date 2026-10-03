# Swarm continuation — #5018

**Executor:** take the row issued to you in [PLAN.tsv](PLAN.tsv), read only its
[PLAN.md](PLAN.md) card, then your current Issue/discussion and required verified
documentation/source bundle. Do not load the whole backlog or restart an old lane.
No row is an actual scope claim until the controller records it.

**Controller:** use [CONTINUATION.md](CONTINUATION.md) for claims/integration and
[STITCH-PLAN.md](STITCH-PLAN.md) for the applicable shared seam or PR disposition.
Select independently eligible work; do not wait for an unrelated audit to finish.

Canonical Architecture/Implementation and accepted owner decisions remain authority.
These files schedule work; they cannot change product contracts or manufacture proof.

[BLOCK-MAP.tsv](BLOCK-MAP.tsv) retains the complete historical inventory.
[REVIEWED.tsv](REVIEWED.tsv) records bounded rechecks; missing means unreviewed.
[BLOCK-MAP.md](BLOCK-MAP.md) explains coverage. BLOCKERS-AUDIT.tsv is a finding index,
not another queue. READY is neither claimed/running nor accepted; PRESERVE prevents
repeating a repaired defect without claiming fresh proof.

HANDOFF, MANAGER-BRIEF, LANE-HANDOFFS and RECOMMENDATIONS remain historical stop
records, not current assignments. Full Issue audit, actual reader/CI evidence and
local runner state are not certified by this planning revision.
