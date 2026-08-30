## I5.4. Canonical transition

Atomic unit:

```text
semantic event(s);
materialized projection changes;
typed relation changes;
scope revisions;
canonical receipt;
outbox intent;
audit chain fields.
```

Everything commits in one database transaction. Notification never announces a commit before its receipt.

