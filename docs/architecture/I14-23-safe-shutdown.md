## I14.23. Safe shutdown

```text
stop new normal admissions;
revoke/finish expiring action authority;
request jobs/modules checkpoint/cancel;
drain canonical writes and reconcile pending receipts;
flush audit/outbox/ORS;
quiesce modules in reverse dependency order;
stop store only when no canonical data lease remains;
publish intentional shutdown state to Watchdog/Host.
```

Deadline expiry produces visible incomplete-shutdown recovery state; it does not silently discard pending work.

A wake/attach request racing with shutdown follows I1.5 `DrainCommitRecord`: before linearization it cancels drain; afterward it waits for a fresh activation generation. Suspend/hibernate/logoff closes pre-transition readiness and forces boot/session/generation revalidation. No caller may “rescue” shutdown by reviving an old lease or process handle.

