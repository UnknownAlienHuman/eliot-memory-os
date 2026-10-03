# Blocker map: complete inventory, explicit review coverage

BLOCK-MAP.tsv is the complete retained stop inventory: 577 issue rows, original
blob f16503f83db9b3ab31a56c9458867623817eddc2. The original 455 FINISHABLE, 83 BLOCKED,
36 ALL-DONE and 3 DISPUTED values are historical lane judgments, not a new audit.

A live GitHub issue search returned 573 open issues with incomplete_results=false.
That count is not a reconciled issue-ID inventory and is not 573 source reviews.
The difference from 577 remains a set-reconciliation task; do not silently delete
four rows, assume which four closed, or treat PRs as issues.

## Effective reading

1. Read the issue and all comments on current source. Use the old row only to find
   evidence; do not turn every #number in prose into a hard dependency.
2. Apply REVIEWED.tsv's explicit finding where present. Other rows are not
   re-audited; historical corrections do not automatically become READY either.
3. Only PLAN.tsv selects source assignments. A dependency is released by the
   exact required owner output on current main, not whole-issue test closure.

REVIEWED.tsv has 29 records: 3 READY and 26 RECHECK. SOURCE_AND_DISCUSSION means
bounded source/discussion inspection, not full acceptance. HISTORICAL rows carry
no checked source SHA. #1701's earlier WAIT was not justified by a current missing
output check and is now RECHECK. #2701's residual expands to the full existing audit.

## Coverage without losing the backlog

For full re-audit, use the union of every retained issue ID and the current open
GitHub issue IDs. Classify current closed/superseded records as tracker state only;
closure is not code proof. Four read-only review queues partition that union by
issue_number % 4 = 0, 1, 2, 3. This partitions issue review, NOT source ownership.
No reviewer independently edits the shared map, schemas or code. Root integrates
one issue result at a time, retaining unresolved rows instead of dropping them.

Counts and all-ready claims require exact enumerated ID sets with no missing or
duplicate issue, every comment page, source SHA and review depth. A selected source
assignment need not wait for unrelated review queues to finish. The existing
controller/validator must consume the chosen plan; no new scheduler is introduced.
