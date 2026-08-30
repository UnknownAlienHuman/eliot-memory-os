## I0.9. Contract maturity

Every concrete contract has one maturity:

```text
SKELETON     — owner and boundary fixed; payload may still evolve;
COMPATIBLE   — wire/state shape versioned and used by at least one real path;
STABLE       — migration, failure and compatibility behavior proven;
REPLACEABLE  — alternative implementation passed equivalence/cutover proof;
RETIRED      — no active producer/consumer; history and migration retained.
```

`SKELETON` is sufficient for early layers only when missing depth is visible and does not cross a Hard Boundary. Agents must not interpret a detailed YAML example as `STABLE` unless the registry says so.

---


