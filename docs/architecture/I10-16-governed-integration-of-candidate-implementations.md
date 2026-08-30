## I10.16. Governed integration of candidate implementations

Mutating swarm branches never merge themselves. Each result creates an `IntegrationCandidate`:

```yaml
IntegrationCandidate:
  candidate_id:
  task_and_work_item:
  producer_attempt_and_lineage:
  base_commit_and_state_fence:
  worktree_or_artifact_refs:
  diff_and_changed_path_manifest:
  declared_read_write_effect_sets:
  evidence_and_verification_refs:
  unresolved_conflicts_and_unknowns:
  rollback_or_compensation:
  status: proposed | ready | stale | integrating | accepted | rejected | conflicted | unknown_outcome
```

`IntegrationQueue` is a projection over canonical candidates, dependencies, approvals and the current integration lease. It is not another scheduler or database.

Because worker parallelism can outrun the single integration owner of one mutable target, the projection exposes queue/backlog counter-metrics: candidate age and count, wait-to-first-review, verifier and rebase cost, stale-by-base-drift rate, conflict/rework rate, accepted verified delta per review window, and completed-worker-to-integrated-result ratio. Rising integration pressure narrows fan-out or decomposes contracts/edges before adding workers; it never creates a second integration owner for the same target.

DEFAULT integration discipline:

```text
one active integration owner and lease per target branch/deliverable;
revalidate base, dirty human changes, path/effect set and State Fence;
run required verifier in candidate worktree/environment;
apply through the governed Git/artifact bridge;
never use git reset --hard or destroy unrelated dirty work;
semantic merge conflicts become ConflictSet/Concilium work, not automatic text acceptance;
run post-apply verifier and record OutcomeReceipt;
on failure, execute explicit rollback/compensation and retain candidate/history.
```

Independent candidates may be prepared in parallel; canonical integration is ordered where effects overlap. Base drift marks only dependent candidates stale. Accepting one candidate never erases dissent or evidence from rejected alternatives.

