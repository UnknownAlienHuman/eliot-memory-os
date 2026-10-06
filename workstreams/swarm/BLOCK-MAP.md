# Blocker map: retained inventory and explicit review coverage

BLOCK-MAP.tsv retains the original 577-row stop inventory, blob
f16503f83db9b3ab31a56c9458867623817eddc2. Its FINISHABLE/BLOCKED/ALL-DONE/DISPUTED
values are historical lane judgments, not current dispatch decisions.

The earlier 573-open-issue search was a historical count, not an ID census.
Reconcile actual sets; never infer which rows closed from a difference in totals.
Reopened or newly created issues also belong in the current review population.

## Effective reading

1. Read the current issue and complete discussion. Use the retained row only to
   locate evidence; a number in prose is not automatically a hard dependency.
2. REVIEWED.tsv owns the current bounded finding and review depth. Do not duplicate
   its changing row/state totals manually in Markdown. Missing rows are unreviewed.
3. PLAN.tsv alone selects source assignments. Its dispatch_gate and actual scope
   claim still apply; READY is not claimed, running, code-complete or accepted.

SOURCE_AND_DISCUSSION and SOURCE_SUBSET are bounded inspections, not acceptance.
HISTORICAL rows have no checked source SHA. PRESERVE prevents repeating the inspected
repair; it does not grant current runtime proof or close the parent obligation.
A required owner output can release a consumer before whole-issue test closure.

## Complete coverage, without duplicate authority

Root indexes the union of retained and current open issue IDs. Review relevant
closed prerequisites against their actual source/output evidence, not a closed label.
Read-only queues partition review by issue_number % 4; they do not claim code paths.
Keep raw snapshots and pagination evidence in local/CI artifacts. Bind source SHA,
body/comment identities, missing sections and review depth; parse the corpus rather
than loading every issue into every worker. No complete ID reconciliation is claimed
by this revision. Independent verified assignments do not await unrelated reviews.

The existing assignment oracle is itself under repair in #818 (recheck 5966026795).
Its Valid/READY output cannot replace the explicit preflight: missing inputs can be
called complete, and scope/serialization checks have source-confirmed gaps. Repair
the existing owner; no new scheduler or automatic whole-backlog pause is introduced.
