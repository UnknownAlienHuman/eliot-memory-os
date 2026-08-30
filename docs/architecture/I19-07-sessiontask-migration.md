## I19.7. Session/task migration

Existing active tasks receive:

```text
new scope identity;
current plan revision;
known done/open/killed state;
current diff/artifacts;
unknowns/verifiers;
legacy source marker;
new State Fence and Authority Epoch.
```

No old lease/approval survives automatically.

