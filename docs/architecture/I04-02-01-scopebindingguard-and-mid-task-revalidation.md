### I4.2.1. ScopeBindingGuard and mid-task revalidation

A high-ranked existing binding is not trusted forever. `ScopeBindingGuard` revalidates the actual workspace/resource identity at:

```text
Session attach/resume;
first tool/process event for a task;
agent/process launch;
worktree/root/cwd/editor-workspace change;
before a scope-sensitive canonical write or Material effect;
after VCS common-dir/object-store, relocation or generation change.
```

```yaml
ScopeBindingGuardReceipt:
  session_task_and_expected_scope_revision:
  expected_and_observed_workspace_instance:
  repository_lineage_and_generation:
  supporting_conflicting_and_missing_evidence:
  disposition: MATCHED | STALE_BINDING | DIFFERENT_INSTANCE | AMBIGUOUS |
               PROVISIONAL_REBIND | CONFLICTED
  allowed_actions_and_memory_visibility:
  required_question_probe_or_rebind:
  state_fence_and_expiry:
```

A mismatching cwd, open file, process root or worktree does not silently move the task or reuse its memory. Safe observations may be captured under a provisional/quarantined scope with the conflicting lineage preserved; project-specific context, writes and effects remain withheld until an explicit bind/rebind/relocation receipt. `MATCHED` is required again after any generation change that can alter the real target of the task.

