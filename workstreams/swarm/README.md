# Swarm handoff (2026-10-02)

Owner order 2026-10-02: "Block map, handoff и brief нужно будет запушить в main тоже." These files record the state of
the ELIOT development swarm at its stop on 2026-10-02 and are the inputs of the continuation sprint (separate PR).

| File | What it is |
|---|---|
| `HANDOFF.md` | Root's handoff: where everything lives, entry points (scripts, loops, restart), lane states at the stop, open problems, decisions waiting for the owner. |
| `LANE-HANDOFFS.md` | Every lane's own HANDOFF line, verbatim. |
| `BLOCK-MAP.md` | Block map of all 577 open issues: summary, OR audit corrections, blockers by reach, per-blocker detail, FINISHABLE / BLOCKED / ALL-DONE tables. |
| `BLOCK-MAP.tsv` | One row per issue: `issue, verdict, finishable, blocked, done, notes, producer, or_audit, or_correction`. |
| `RECOMMENDATIONS.md` | Root's own recommendations (Russian): why the last sprint was slow, how to run the next one. |
| `MANAGER-BRIEF.md` | The swarm operations manual and decision log (Russian). |

These are records of one stop, not architecture authority: `main`'s canonical documentation and the issues outrank
them. The block map was produced by the lanes per the brief quoted in `BLOCK-MAP.md` and audited by OR; ~23% of the
audited rows were overturned, so re-audit before relying on a row (continuation step 2).
