## I19.6. Data migration

```text
create full logical backup/export;
map old records to canonical families preserving IDs/provenance;
mark weak/legacy epistemic status explicitly;
keep raw source/blob;
rebuild derived indexes/capsules/cues;
validate counts/relation endpoints/history;
run dual-read comparison;
cut over to the candidate canonical-store generation through the same fenced route/cutover contract;
retain old DB read-only during rollback window.
```

Unknown legacy semantics become candidates, not invented verified state.

