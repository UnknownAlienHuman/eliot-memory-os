## I15.11. Agent worktrees

Material code workers use dedicated Git worktree by default.

```text
base commit recorded;
write set/path policy;
secrets removed;
result is candidate diff/artifact;
verifier runs in same worktree;
application to integration branch is separate governed action;
base drift checked before apply.
```

