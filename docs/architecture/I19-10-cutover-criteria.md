## I19.10. Cutover criteria

```text
one canonical write path;
no active agent knows DB credentials;
new task/capture/read/verify/finish loop works;
restart/resume proof;
backup/restore proof;
old entrypoint produces explicit rejection/redirect;
ControlBoard shows migration gaps;
rollback plan tested.
```

