## I10.9. Git bridge

Uses typed Git instrument/bridge operations through the shared ProcessExecutor (or an admitted in-process read-only library facade):

```text
status/branch/commit/diff;
worktree create/remove;
apply/check patch;
blame/log/co-change mining;
change manifest;
base drift.
```

No hidden `reset --hard` or destruction of human dirty changes. The bridge executes under the resource's declared execution identity. User-owned roots use a broker-launched scoped Git adapter unless explicit ACL policy admits the service identity; operation receipts preserve SID, root and worktree/environment lease.

