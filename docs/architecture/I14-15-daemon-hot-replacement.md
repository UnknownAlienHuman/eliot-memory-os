## I14.15. Daemon hot replacement

Kernel preserves front door and canonical gateway while replacing `eliotd`. The same durable cutover semantics apply, but daemon semantic proposals and already admitted executions are distinguished.

```text
candidate starts with a new daemon generation and no write/effect authority;
loads projections, catches up the outbox cursor and verifies contract/state compatibility;
Kernel closes new application admission to the old daemon;
old daemon checkpoints current plan/job state and submits its in-flight disposition set;
Kernel commits DaemonCutoverRecord: new route/epoch, old proposal fence,
  exact staged-operation identities already owned by Kernel, unresolved effect scopes;
Kernel publishes the candidate route;
old daemon drains eligible reads and exits;
Sessions rebind through Kernel where the host permits.
```

A `PreparedTransition` already staged by Kernel is Kernel-owned and continues by operation identity even if its proposing daemon exits. An unstaged old-daemon proposal is stale after cutover. A tool/external effect launched by the old daemon follows the I14.14 in-flight rules; an unknown conflicting outcome blocks only its scope. Rollback is another generation transition with a newer epoch, never revival of the old epoch. Lost requests are recovered from submission/receipt state, not recreated semantically.

