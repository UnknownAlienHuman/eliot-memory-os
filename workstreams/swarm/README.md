# Swarm continuation — #5018

Start with CONTINUATION.md and PLAN.tsv. The live owning issue, its complete
current discussion and canonical documentation define the work; these files
are coordination records, not a replacement specification.

- BLOCK-MAP.tsv retains the complete 577-issue stop inventory. Its historical
  FINISHABLE/BLOCKED/ALL-DONE values are not current dispatch states.
- REVIEWED.tsv records bounded rechecks, their depth and evidence. A missing
  row means not re-audited, never done or automatically ready.
- PLAN.tsv is the sole list of selected source assignments; PLAN.md explains
  their scope. READY is not code-complete, accepted, claimed or running.
- STITCH-PLAN.md records shared-file turns and exact producer/consumer handoffs.
- BLOCKERS-AUDIT.tsv records changed findings, not a competing dispatch queue.

Historical HANDOFF.md, MANAGER-BRIEF.md, LANE-HANDOFFS.md and RECOMMENDATIONS.md
remain stop records. Do not restart old queues or inherit their transient lane
branches, quota forecasts, parked labels or code-complete claims without checking.

The prior 28-row replacement was not a complete blocker map. The full original
TSV is restored at its original path; duplicate STOP-BLOCK-MAP copies are removed.
The old rendered report remains in Git history at main b7e9e334. No issue work is
lost by reducing duplicated reports.

No controller session, Windows runtime, verified reader receipt or green CI is
implied by this planning revision. The full issue-by-issue audit is not complete.
