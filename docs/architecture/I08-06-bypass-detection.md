## I8.6. Bypass detection

Signals include:

```text
process accesses SurrealDB endpoint/credentials outside storage bridge;
process touches the database path outside the active Host-managed SurrealDB process lineage;
unregistered direct canonical export/import;
agent executes known DB CLI/query path;
module writes outside declared effect set;
unknown process changes protected config, Module Catalog, Generation Registry or Capability Registry state;
old generation emits after fencing;
external effect appears without action/receipt lineage.
```

Content may be semantically correct and still be rejected as canonical if it bypassed the write path. Observation of the effect remains evidence. These detections exist only where the active `IntegrationCoverageProfile` names a competent sensor. Missing coverage is reported as a supervision gap; absence of a signal is never treated as proof that bypass did not occur.

