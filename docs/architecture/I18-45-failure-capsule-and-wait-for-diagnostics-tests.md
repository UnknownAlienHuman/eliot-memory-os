## I18.45. Failure Capsule and wait-for diagnostics tests

For every timeout, deadlock, crash, unknown outcome and failed promotion, tests verify that:

```text
one immutable capsule is produced;
raw evidence is referenced, not silently truncated;
process/resource/effect disposition is explicit;
wait-for dependencies identify the blocked owner/resource;
seed/reproduction command reproduces deterministic cases;
retry creates a new attempt lineage;
privacy redaction does not destroy required integrity metadata.
```

The agent-facing Diagnostic Brief is tested against the capsule and may be compact; the capsule itself remains evidence.

