## I6.13. Zero-archaeology error contract

Every validation response aggregates all known defects and includes:

```text
stable ErrorCode;
all invalid/missing fields;
record/contract references;
current revision/fence where relevant;
minimal valid example;
safe fallback;
next allowed action;
retry/poll semantics;
operation handle if staged.
```

Raw deserialization errors and one-field-at-a-time loops do not cross the agent boundary.

