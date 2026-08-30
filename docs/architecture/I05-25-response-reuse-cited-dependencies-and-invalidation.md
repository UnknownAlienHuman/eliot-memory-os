## I5.25. Response reuse, cited dependencies and invalidation

A rendered answer, packet, report or cached projection is reusable only when ELIOT can name the facts and contracts on which its current meaning depends. Cache identity alone is insufficient.

`ResponseReuseReceipt` binds:

```text
response/artifact identity and renderer/schema revision;
question, WorkScope, Task and visibility scope;
State Fence and Current Epistemic Position revision;
cited facts, evidence, claims, policies, Tool Definitions and verifier contracts;
freshness/supersession/revocation watches;
allowed reuse classes and exact invalidation conditions;
reuse decisions and downstream outcome refs.
```

Rules:

```text
no dependency set → no current-state reuse;
a source, policy, verifier, Tool Definition or scope revision invalidates the dependent response;
invalidated output remains historical evidence but is removed from current influence;
re-rendering from the same stale inputs does not restore validity;
reuse across WorkScope, principal, route or privacy boundary requires an explicit compatible projection;
cache hit never upgrades epistemic status or completion.
```

Dependency invalidation uses the same explicit influence graph as I12.20. Similarity is not a revocation mechanism. When dependency lineage is incomplete, the response is marked `dependency_incomplete` and may be shown only with that limitation or rebuilt from primary evidence.


