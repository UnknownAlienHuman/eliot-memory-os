## I16.17. Instrument Plane observability

Every `InstrumentRun` emits correlated operational events and canonical evidence:

```text
profile/stage/instrument IDs and revisions;
WorkScope/base/candidate/worktree identity;
executable/config/environment identities;
queue, start, first-output, finish and cleanup times;
process tree and resource-limit outcomes;
stdout/stderr bytes, truncation and parser warnings;
facts/unknowns/conflicts and authority/freshness/coverage;
tests discovered/selected/executed/skipped;
target/cache identity and lock wait;
exact rerun and raw evidence handles.
```

Required metrics include:

```text
time_to_first_actionable_failure;
profile overhead excluding tool runtime;
zero-test and inventory-staleness incidents;
parser incompatibility rate;
raw evidence open rate;
negative-result qualification failures;
stale code-intelligence rate;
process cleanup/orphan count;
Cargo lock wait and target-cache effectiveness;
selected-vs-full regression escape;
module-local proof to ProductProof promotion rate.
```

Operational logs never become verifier evidence by themselves. Diagnostic Brief compiles these records so the agent sees the actual failed stage, recurring signature, exact scope and next discriminative action instead of searching raw logs blindly.

