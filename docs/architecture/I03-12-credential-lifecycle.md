## I3.12. Credential lifecycle

Credentials are stored through Windows Credential Manager/DPAPI-backed secret provider. Registry stores only `SecretRef`.

```text
create/import by authorized Human;
assign to module/route capability;
materialize only in target process;
never expose to agent/context/logs;
rotate on schedule, compromise or recovery;
revoke invalidates dependent Sessions/jobs;
audit access by reference, not value.
```

