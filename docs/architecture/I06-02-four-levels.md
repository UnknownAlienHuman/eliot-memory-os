## I6.2. Four levels

### Primitive

For a read-only, reversible, local, obvious action.

```text
intent;
scope;
expected output;
one stop condition.
```

### Standard

For ordinary development of one Module or work item.

```text
goal and acceptance;
read/write impact;
current State Fence;
expected observable;
verifier;
writeback requirement.
```

### Deep

For Material or Critical, cross-Module, migration, security, or stateful change.

```text
competing options and rationale;
full impact/Ordering Scopes;
authority chain;
invariants and negative memory;
rollback/compensation;
independent observation requirement;
recovery and escalation;
explicit residual unknowns.
```

### Release

For a public installation or release.

```text
compatibility matrix;
migration and rollback;
backup/restore proof;
hot-upgrade proof;
fault/restart proof;
full affected + release suite;
known issues;
artifact provenance/signature.
```

